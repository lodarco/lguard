"""Sweeps: walk the disks and scan whatever the index does not already vouch for.

The first sweep is the baseline (everything). After that a sweep is mostly
lstat() calls: unchanged files are answered from the index in microseconds.
"""
from __future__ import annotations

import os
import re
import stat
import time

from . import index as index_mod
from .config import Config
from .scanner import Result, Scanner

# What holds no files of anyone's: kernel interfaces, and overlay/squashfs
# views of files that are checked where they really are. Everything else is
# watched - a list of "known good" filesystems would leave out the next new
# one, and with it whatever is stored there.
PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "pstore", "bpf", "tracefs", "debugfs",
    "securityfs", "configfs", "fusectl", "mqueue", "hugetlbfs", "autofs", "binfmt_misc", "efivarfs",
    "rpc_pipefs", "nfsd", "selinuxfs", "ramfs", "nsfs", "squashfs", "overlay", "fuse.portal",
    "fuse.gvfsd-fuse", "fuse.snapfuse", "fuse.lxcfs", "erofs",
}
NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "afs", "ncpfs",
              "fuse.sshfs", "fuse.rclone", "fuse.davfs", "davfs", "fuse.s3fs", "fuse.glusterfs"}
SKIP_MOUNTS = ("/snap/", "/var/lib/snapd/", "/boot/efi", "/proc", "/sys", "/var/lib/docker/", "/var/lib/containers/",
               "/tmp/.mount_")             # an AppImage showing its own (read-only) content while it runs


def parse_mounts(text: str) -> list[tuple[str, str]]:
    """[(mount point, filesystem type)] from the text of /proc/self/mounts."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        # the kernel writes space, tab, newline and backslash as \ooo
        out.append((re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), parts[1]), parts[2]))
    return out


def mounts(watch_network: bool = False, table: list[tuple[str, str]] | None = None,
           dev_of=None) -> tuple[list[str], list[tuple[str, str]]]:
    """(mount points to watch and walk, [(mount point, why not)] for the rest
    that could hold files)."""
    if table is None:
        with open("/proc/self/mounts") as f:
            table = parse_mounts(f.read())
    if dev_of is None:
        def dev_of(path):
            st = os.stat(path)
            # Not a folder, or a folder nobody may enter (mode 000): that is
            # how a sandbox hides a place from a service, not a disk.
            return st.st_dev if stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) else None
    watched, left, seen = [], [], set()
    # Shortest first: a filesystem that shows up a second time further down
    # (a bind mount, as systemd makes for a sandboxed service) is the same
    # files again.
    for mnt, fstype in sorted(set(table), key=lambda e: (len(e[0]), e[0])):
        if fstype in PSEUDO_FS or mnt.startswith(SKIP_MOUNTS):
            continue
        # tmpfs below /run is the system's own state - except the users' folders there
        if fstype == "tmpfs" and (mnt == "/run" or mnt.startswith("/run/")) and not mnt.startswith("/run/user/"):
            continue
        if fstype in NETWORK_FS and not watch_network:
            left.append((mnt, f"network share ({fstype}); set watch_network = true to include it"))
            continue
        try:
            dev = dev_of(mnt)
        except OSError:
            continue
        if dev is None or dev in seen:       # not a folder, or these files are covered already
            continue
        seen.add(dev)
        watched.append(mnt)
    return sorted(set(watched)), sorted(set(left))


def local_mounts(watch_network: bool = False) -> list[str]:
    return mounts(watch_network)[0]


def roots(cfg: Config) -> list[str]:
    return cfg.roots or local_mounts(cfg.watch_network)


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
        try:
            r = self.scanner.scan(path, force=force)
        except Exception as e:
            if index_mod.is_damage(e):
                raise                            # the inventory itself: nothing here can go on
            self.log(f"check failed: {path}: {e}")
            r = Result(path, "error", detail=str(e))
        self.stats["seen"] += 1
        self.stats["bytes"] += size
        self._count(r)
        if self.stats["seen"] % 500 == 0:
            self.index.commit()
            self.progress(path=path, **self.stats)
        return r

    def _count(self, r):
        if r.cached:
            self.stats["cached"] += 1
        elif r.verdict != "skipped":
            self.stats["scanned"] += 1
        if r.verdict in ("infected", "suspicious") or (r.verdict == "warning" and r.action):
            self.stats["findings"] += 1
        if r.verdict == "error":
            self.stats["errors"] += 1

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
        if self.stop:
            # Stopped half-way (an update, a shutdown): not a finished check.
            self.index.event("sweep_stopped", "priority" if only_priority else "full")
            self.index.commit()
            return self.stats
        self.index.meta_set("last_priority_sweep" if only_priority else "last_sweep", time.time())
        self.index.event("sweep_end", f"{self.stats} in {int(time.time() - t0)}s")
        self.index.commit()
        return self.stats

    def maintenance(self, verify_budget: int | None = None):
        """One decrypting pass over the inventory, then:
          - prune rows of files that are gone,
          - refresh the verdict counters shown by status and the GUI,
          - full disk scan slice: read again the files checked longest ago
            (category folders and risky types first) within a byte budget."""
        cfg = self.cfg
        counts = {"files": 0, "clean": 0, "infected": 0, "suspicious": 0, "warning": 0,
                  "partial": 0, "error": 0, "skipped": 0, "bytes": 0}
        kinds: dict[str, int] = {}
        gone, verify = [], []
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
            if row.verdict in ("clean", "partial") and row.size:
                urgency = (0 if cfg.is_priority(row.path) else 1 if row.risky else 2)
                verify.append((urgency, row.verified_at or 0, row.path, row.size))
        for p in gone:
            self.index.forget(p)
        self.index.meta_set("counts", {**counts, "kinds": kinds, "at": time.time()})
        self.index.commit()
        cutoff = time.time() - cfg.verify_cycle_days * 86400
        recent = sum(1 for c in verify if (c[1] or 0) >= cutoff)
        self.index.meta_set("verify_progress", {"percent": int(recent * 100 / max(1, len(verify))), "at": time.time()})
        self.deep_verify(verify, cfg.verify_budget_bytes if verify_budget is None else verify_budget)

    def deep_verify(self, candidates, budget: int):
        """Full disk scan: every chosen file is read again from the first
        byte to the last. Its SHA-256 must still be the one in the inventory
        (content changed under an unchanged identity = tampering), and the
        content is checked by the engine again unless this very content was
        already checked with the current signatures."""
        from .index import identity_of
        from .scanner import _digest, mostly_holes
        cutoff = time.time() - self.cfg.verify_cycle_days * 86400
        # files never verified or verified before the cycle cutoff first,
        # within that: category folders, then risky types, then oldest
        candidates.sort(key=lambda c: (c[1] >= cutoff, c[0], c[1]))
        used, n, mism = 0, 0, 0
        self.phase = "fulldisk"
        goal = min(budget, sum(c[3] for c in candidates)) or 1
        dbver = self.scanner.db_version
        for urgency, verified_at, path, size in candidates:
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
            changed = False
            try:
                st = os.fstat(fd)
                if identity_of(st) != row.identity():
                    self._scan(path)             # changed normally: plain rescan
                    continue
                if row.digest is None or mostly_holes(st):
                    continue                     # never read through (see scanner): nothing to compare
                now_digest = _digest(fd, st.st_size, self.cfg.hash_max)
                if now_digest is None:
                    continue                     # too slow to read today
                changed = now_digest != row.digest
                if not changed:
                    self._count(self.scanner._scan_open(path, fd, st, dbver, None, row=row,
                                                        digest=now_digest, current_only=True))
            except Exception as e:
                if index_mod.is_damage(e):
                    raise
                self.log(f"full disk scan: {path}: {e}")
                continue
            finally:
                os.close(fd)
            used += size
            n += 1
            if changed:
                mism += 1
                self.index.event("tamper_content",
                                 f"{path}: content changed but size/mtime/ctime/inode did not")
                self.scanner.tamper_alarm(path, "content changed under an unchanged identity")
                self._scan(path, force=True)
            if n % 200 == 0:
                self.index.commit()
        self.index.commit()
        self.index.event("deep_verify", f"{n} files, {used // (1024 ** 2)} MiB, {mism} mismatches")
        total = len(candidates)
        recent = sum(1 for c in candidates if (c[1] or 0) >= cutoff) + n
        self.index.meta_set("verify_progress", {"percent": min(100, int(recent * 100 / max(1, total))),
                                                "at": time.time()})
        self.verified = (n, used, mism)
