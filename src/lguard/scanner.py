"""Scan one file: index check, content type, hash, heuristics, clamd, action."""
from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass

from . import filetype, quarantine
from .clamd import Clamd, ClamdError
from .config import Config
from .i18n import t
from .index import FileRow, Index, identity_of
from .notify import notify

BAD = ("infected", "suspicious")


@dataclass
class Result:
    path: str
    verdict: str            # clean | infected | suspicious | warning | error | skipped
    signature: str | None = None
    cached: bool = False
    action: str | None = None   # quarantined | reported | None
    detail: str | None = None


def _digest(fd: int, size: int, hash_max: int = 0) -> str:
    """SHA-256 of the whole content, byte by byte. hash_max > 0 allows a
    cheaper fingerprint for files above it (off by default)."""
    h = hashlib.sha256()
    if not hash_max or size <= hash_max:
        off = 0
        while True:
            buf = os.pread(fd, 1 << 20, off)
            if not buf:
                break
            h.update(buf)
            off += len(buf)
        return h.hexdigest()
    # Fingerprint for very big files (videos): size + first and last MiB.
    h.update(str(size).encode())
    h.update(os.pread(fd, 1 << 20, 0))
    h.update(os.pread(fd, 1 << 20, max(0, size - (1 << 20))))
    return "fp:" + h.hexdigest()


class Scanner:
    def __init__(self, cfg: Config, index: Index, clamd: Clamd | None = None, log=print):
        self.cfg = cfg
        self.index = index
        self.clamd = clamd or Clamd(cfg.clamd_socket)
        self.log = log
        self._dbver = 0
        self._dbver_at = 0.0
        self.on_finding = None   # callback(Result) for the daemon / GUI
        index.on_tamper = lambda table, detail: (
            index.event("tamper_record", f"{table}: {detail}"), self.tamper_alarm(table, detail))

    @property
    def db_version(self) -> int:
        if time.time() - self._dbver_at > 600:
            try:
                _, self._dbver = self.clamd.version()
            except (ClamdError, OSError):
                pass
            self._dbver_at = time.time()
        return self._dbver

    def tamper_alarm(self, what: str, why: str):
        """The inventory or a file was changed behind Lguard's back."""
        now = time.time()
        if now - getattr(self, "_last_tamper", 0) < 600:   # one alarm per 10 min
            return
        self._last_tamper = now
        notify(self.cfg, t("tamper_title"), t("tamper_body", what=what, why=why), "urgent")

    def invalidate_db_version(self):
        self._dbver_at = 0.0

    def scan(self, path: str, force: bool = False, process: str | None = None) -> Result:
        cfg = self.cfg
        if cfg.is_excluded(path):
            return Result(path, "skipped", detail="excluded")
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            self.index.forget(path)
            return Result(path, "skipped", detail="gone")
        except OSError as e:
            return Result(path, "error", detail=str(e))
        if not stat.S_ISREG(st.st_mode):
            return Result(path, "skipped", detail="not a regular file")

        dbver = self.db_version
        row = self.index.get(path)
        same = row is not None and row.identity() == identity_of(st)
        if same and not force:
            fresh = not row.risky or row.db_version >= dbver
            if row.verdict in BAD or (row.verdict in ("clean", "warning") and fresh):
                self.index.bump(cached=1)
                return Result(path, row.verdict, row.signature, cached=True)

        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
        except PermissionError:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as e:
            return Result(path, "error", detail=str(e))
        try:
            fst = os.fstat(fd)
            if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(fst.st_mode):
                return Result(path, "skipped", detail="changed while opening")
            st = fst
            return self._scan_open(path, fd, st, dbver, process)
        finally:
            os.close(fd)

    def _scan_open(self, path, fd, st, dbver, process) -> Result:
        cfg = self.cfg
        head = os.pread(fd, filetype.HEAD, 0)
        kind = filetype.kind(head)
        if kind in ("unknown", "text") and st.st_size > 0x8006 and filetype.is_iso(fd):
            kind = "iso"
        ext = filetype.ext_of(path)
        risky = filetype.is_risky(kind, ext)
        digest = _digest(fd, st.st_size, cfg.hash_max) if st.st_size else None

        verdict, signature, cached = "clean", None, False
        if st.st_size == 0:
            pass
        elif self.index.is_allowed(digest):
            signature = "allowed"
        else:
            # 1) content already known?
            hv = self.index.hash_verdict(digest) if digest else None
            if hv and (hv["db_version"] >= dbver or not risky) and hv["verdict"] != "error":
                verdict, signature, cached = hv["verdict"], hv["signature"], True
            else:
                try:
                    if st.st_size <= cfg.full_scan_max:
                        r = self.clamd.scan_fd(fd)
                    else:
                        r = self.clamd.scan_partial(fd, st.st_size, cfg.partial_chunk)
                    verdict = "infected" if r.infected else "clean"
                    signature = r.signature
                    if digest:
                        self.index.put_hash(digest, verdict, signature, dbver)
                except (ClamdError, OSError) as e:
                    verdict, signature = "error", None
                    self.log(f"clamd error on {path}: {e}")
            # 2) torrent / media-folder heuristics (path dependent, never cached by hash)
            # (also when clamd failed: these need no signatures)
            if verdict in ("clean", "error") and cfg.is_priority(path):
                hv2 = filetype.torrent_verdict(path, kind, fd)
                if hv2:
                    verdict, signature = hv2

        if cached:
            self.index.bump(cached=1)
        else:
            self.index.bump(scanned=1, nbytes=st.st_size)

        res = Result(path, verdict, signature, cached=cached,
                     detail="content already known (re-hashed, same SHA-256)" if cached else None)
        if verdict in BAD or verdict == "warning":
            self._act(res, fd, st, digest, process)
        if res.action != "quarantined":
            now = time.time()
            self.index.put(FileRow(path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                                   st.st_ctime_ns, digest, kind, int(risky), verdict, signature,
                                   dbver, now, verified_at=now))
        else:
            self.index.forget(path)
        return res

    def _act(self, res: Result, fd, st, digest, process):
        cfg = self.cfg
        sig = res.signature or "?"
        level = res.verdict
        if res.verdict in BAD and cfg.may_quarantine(res.path):
            try:
                qid = quarantine.quarantine(cfg, res.path, fd, st, digest, sig, self.log)
                res.action = "quarantined"
                self.index.add_finding(res.path, digest, level, sig, "quarantined", qid, process)
                notify(cfg, t(f"{level}_title"), t("quarantined", sig=sig, path=res.path), "high")
            except Exception as e:
                res.action = "reported"
                res.detail = f"quarantine failed: {e}"
                self.index.add_finding(res.path, digest, level, sig, "reported", None, process, res.detail)
                notify(cfg, t(f"{level}_title"), t("quarantine_failed", sig=sig, path=res.path, err=e), "urgent")
        else:
            if res.verdict in BAD:
                level = "critical"
            res.action = "reported"
            self.index.add_finding(res.path, digest, level, sig, "reported", None, process)
            prio = {"critical": "urgent", "warning": "default"}.get(level, "high")
            notify(cfg, t(f"{level}_title"), t("reported", sig=sig, path=res.path), prio)
        self.index.commit()
        if self.on_finding:
            try:
                self.on_finding(res)
            except Exception:
                pass
