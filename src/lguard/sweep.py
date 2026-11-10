"""Sweeps: walk the disks and scan whatever the index does not already vouch for.

The first sweep is the baseline (everything). After that a sweep is mostly
lstat() calls: unchanged files are answered from the index in microseconds.
"""
from __future__ import annotations

import os
import stat
import time

from .config import Config
from .scanner import Scanner

LOCAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs", "jfs", "reiserfs",
            "fuseblk", "ntfs", "ntfs3", "vfat", "exfat"}


def local_mounts() -> list[str]:
    out = []
    with open("/proc/self/mounts") as f:
        for line in f:
            dev, mnt, fstype, *_ = line.split()
            mnt = mnt.encode().decode("unicode_escape")
            if fstype in LOCAL_FS and not mnt.startswith(("/snap/", "/var/lib/snapd/", "/boot/efi")):
                out.append(mnt)
            elif fstype == "tmpfs" and mnt == "/dev/shm":
                out.append(mnt)
    return sorted(set(out))


def roots(cfg: Config) -> list[str]:
    return cfg.roots or local_mounts()


def walk(top: str, cfg: Config, same_dev: bool = True):
    """Yield regular file paths under `top`, not crossing into other
    filesystems (each one is its own root), skipping excluded subtrees."""
    try:
        top_dev = os.lstat(top).st_dev
    except OSError:
        return
    stack = [top]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                p = e.path
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if cfg.is_excluded(p + "/x"):
                            continue
                        if same_dev and e.stat(follow_symlinks=False).st_dev != top_dev:
                            continue
                        stack.append(p)
                    elif e.is_file(follow_symlinks=False):
                        if not cfg.is_excluded(p):
                            yield p
                except OSError:
                    continue


class Sweep:
    def __init__(self, cfg: Config, scanner: Scanner, progress=None, log=print):
        self.cfg = cfg
        self.scanner = scanner
        self.index = scanner.index
        self.progress = progress or (lambda **kw: None)
        self.log = log
        self.stop = False
        self.stats = {"seen": 0, "scanned": 0, "cached": 0, "findings": 0, "errors": 0, "bytes": 0}
        self.report = False            # write live progress for the app (lguard sweep)
        self.phase = ""
        self.total_bytes = 0
        self.started = time.time()
        self._last_report = 0.0
        self._last_ctl = 0.0

    # ------------------------------------------------------------ progress
    def _used_bytes(self) -> int:
        seen, total = set(), 0
        for r in roots(self.cfg):
            try:
                st, vfs = os.stat(r), os.statvfs(r)
            except OSError:
                continue
            if st.st_dev in seen:
                continue
            seen.add(st.st_dev)
            total += (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize
        return total

    def report_progress(self, current: str = "", force: bool = False, **extra):
        if not self.report:
            return
        now = time.time()
        if not force and now - self._last_report < 3:
            return
        self._last_report = now
        pct = None
        if self.phase in ("media", "drives") and self.total_bytes:
            pct = min(99, int(self.stats["bytes"] * 100 / self.total_bytes))
        self.index.meta_set("sweep_progress", {
            "running": True, "pid": os.getpid(), "phase": self.phase, "started": self.started,
            "updated": now, "current": current, "percent": pct, **self.stats, **extra})

    def finish_progress(self):
        if self.report:
            self.index.meta_set("sweep_progress", {"running": False, "finished": time.time(),
                                                   "started": self.started, **self.stats})

    def check_pause(self):
        """Pause from the app: stop at a file boundary (no lock held) until
        resumed, or until the chosen time when the pause has one."""
        now = time.time()
        if not self.report or now - self._last_ctl < 2:
            return
        self._last_ctl = now
        announced = False
        while not self.stop:
            ctl = self.index.meta_get("sweep_control") or {}
            if not ctl.get("paused"):
                if announced:
                    self.index.event("sweep_resume", "by user")
                return
            ra = ctl.get("resume_at")
            if ra and time.time() >= ra:
                self.index.meta_set("sweep_control", {"paused": False})
                self.index.event("sweep_resume", "automatic")
                return
            if not announced:
                self.index.event("sweep_pause", f"until {time.strftime('%H:%M', time.localtime(ra))}" if ra else "until resumed")
                announced = True
            self.report_progress(force=True, paused=True, resume_at=ra)
            time.sleep(3)

    def _scan(self, path, force=False):
        self.check_pause()
        try:
            size = os.lstat(path).st_size
        except OSError:
            size = 0
        self.report_progress(path)
        r = self.scanner.scan(path, force=force)
        self.stats["seen"] += 1
        self.stats["bytes"] += size
        if r.cached:
            self.stats["cached"] += 1
        elif r.verdict != "skipped":
            self.stats["scanned"] += 1
        if r.verdict in ("infected", "suspicious", "warning"):
            self.stats["findings"] += 1
        if r.verdict == "error":
            self.stats["errors"] += 1
        if self.stats["seen"] % 500 == 0:
            self.index.commit()
            self.progress(path=path, **self.stats)
        return r

    def run_paths(self, tops: list[str], force=False):
        for top in tops:
            if self.stop:
                break
            if os.path.isfile(top):
                self._scan(top, force)
                continue
            for p in walk(top, self.cfg, same_dev=not self.cfg.is_priority(top)):
                if self.stop:
                    break
                self._scan(p, force)
        self.index.commit()

    def full(self, only_priority=False, deep=False):
        """Priority folders first, then every root; then maintenance."""
        t0 = time.time()
        self.index.event("sweep_start", "priority" if only_priority else "full")
        self.total_bytes = self._used_bytes()
        self.phase = "media"
        self.report_progress(force=True)
        try:
            self.run_paths(list(self.cfg.all_priority_paths))
            if not only_priority:
                self.phase = "drives"
                self.run_paths(roots(self.cfg))
                # deep: "Full disk scan" from the app - every file read again now
                self.maintenance(verify_budget=(1 << 62) if deep else None)
        finally:
            self.finish_progress()
        self.index.meta_set("last_priority_sweep" if only_priority else "last_sweep", time.time())
        self.index.event("sweep_end", f"{self.stats} in {int(time.time() - t0)}s")
        self.index.commit()
        return self.stats

    def maintenance(self, verify_budget: int | None = None):
        """One decrypting pass over the inventory, then:
          - prune rows of files that are gone,
          - retro-hunt: risky files seen recently get newer signatures,
          - deep verification: re-hash the files verified longest ago
            (priority folders and risky types first) within a byte budget;
            content that changed under an unchanged identity is tampering,
          - refresh the verdict counters shown by status and the GUI."""
        cfg = self.cfg
        dbver = self.scanner.db_version
        since = time.time() - cfg.sweep_retro_days * 86400
        counts = {"files": 0, "clean": 0, "infected": 0, "suspicious": 0, "warning": 0,
                  "error": 0, "skipped": 0, "bytes": 0}
        kinds: dict[str, int] = {}
        gone, retro, verify = [], [], []
        for row in self.index.iter_files():
            if self.stop:
                return
            try:
                st = os.lstat(row.path)
                if not stat.S_ISREG(st.st_mode):
                    gone.append(row.path)
                    continue
            except FileNotFoundError:
                gone.append(row.path)
                continue
            except OSError:
                continue
            counts["files"] += 1
            counts[row.verdict] = counts.get(row.verdict, 0) + 1
            counts["bytes"] += row.size
            kinds[row.kind or "unknown"] = kinds.get(row.kind or "unknown", 0) + 1
            if row.risky and row.db_version < dbver and (row.scanned_at >= since or cfg.is_priority(row.path)):
                retro.append(row.path)
            if row.verdict == "clean" and row.size:
                urgency = (0 if cfg.is_priority(row.path) else 1 if row.risky else 2)
                verify.append((urgency, row.verified_at or 0, row.path, row.size, row.digest))
        for p in gone:
            self.index.forget(p)
        self.index.meta_set("counts", {**counts, "kinds": kinds, "at": time.time()})
        self.index.commit()
        cutoff = time.time() - cfg.verify_cycle_days * 86400
        recent = sum(1 for c in verify if (c[1] or 0) >= cutoff)
        self.index.meta_set("verify_progress", {"percent": int(recent * 100 / max(1, len(verify))), "at": time.time()})
        if retro:
            self.index.event("retro_hunt", f"{len(retro)} files, signatures {dbver}")
        self.phase = "signatures"
        for p in retro:
            if self.stop:
                return
            self._scan(p, force=True)
        self.index.commit()
        self.deep_verify(verify, cfg.verify_budget_bytes if verify_budget is None else verify_budget)

    def deep_verify(self, candidates, budget: int):
        from .index import identity_of
        from .scanner import _digest
        cutoff = time.time() - self.cfg.verify_cycle_days * 86400
        # files never verified or verified before the cycle cutoff first,
        # within that: priority folders, then risky types, then oldest
        candidates.sort(key=lambda c: (c[1] >= cutoff, c[0], c[1]))
        used, n, mism = 0, 0, 0
        self.phase = "fulldisk"
        goal = min(budget, sum(c[3] for c in candidates)) or 1
        for urgency, verified_at, path, size, digest in candidates:
            if self.stop or used >= budget:
                break
            self.check_pause()
            self.report_progress(path, percent_budget=min(99, int(used * 100 / goal)))
            row = self.index.get(path)
            if not row:
                continue
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
            except OSError:
                continue
            try:
                st = os.fstat(fd)
                if identity_of(st) != row.identity():
                    self._scan(path)             # changed normally: plain rescan
                    continue
                now_digest = _digest(fd, st.st_size)
            finally:
                os.close(fd)
            used += size
            n += 1
            if now_digest != row.digest:
                mism += 1
                self.index.event("tamper_content",
                                 f"{path}: content changed but size/mtime/ctime/inode did not")
                self.scanner.tamper_alarm(path, "content changed under an unchanged identity")
                self._scan(path, force=True)
            else:
                row.verified_at = time.time()
                self.index.put(row)
            if n % 200 == 0:
                self.index.commit()
        self.index.commit()
        self.index.event("deep_verify", f"{n} files, {used // (1024 ** 2)} MiB, {mism} mismatches")
        total = len(candidates)
        recent = sum(1 for c in candidates if (c[1] or 0) >= cutoff) + n
        self.index.meta_set("verify_progress", {"percent": min(100, int(recent * 100 / max(1, total))),
                                                "at": time.time()})
        self.verified = (n, used, mism)
