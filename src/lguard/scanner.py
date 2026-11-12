"""Scan one file: index check, content type, hash, heuristics, clamd, action."""
from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass

from . import authenticode, filetype, quarantine
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
    action: str | None = None   # quarantined | held | reported | None
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

    def scan(self, path: str, force: bool = False, process: str | None = None,
             fresh: bool = False, started: bool = False) -> Result:
        """fresh = the file was written or moved into place just now (a
        real-time event); started = it is being run as a program. Either
        way a detection is quarantined at once, however old the file is."""
        cfg = self.cfg
        event = "started" if started else "fresh" if fresh else ""
        if cfg.is_excluded(path):
            return Result(path, "skipped", detail="excluded")
        soft = cfg.is_soft_excluded(path)
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
            # New signatures are tried on risky files while they are new (a
            # fresh threat is usually recognised days after it appears) and
            # always in the category folders. Everything else is re-checked
            # in rotation by the full disk scan.
            born = row.first_seen or row.scanned_at or 0
            recent = time.time() - born < cfg.sweep_retro_days * 86400
            stale = row.risky and row.db_version < dbver and (recent or cfg.is_priority(path))
            if started and row.verdict in BAD:
                pass                                 # left in place earlier; not any more
            elif row.verdict in BAD or (row.verdict in ("clean", "warning", "partial") and not stale):
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
            if soft and not filetype.is_program(os.pread(fd, 8, 0)):
                return Result(path, "skipped", detail="cache or log data")
            return self._scan_open(path, fd, fst, dbver, process, row=row, event=event)
        finally:
            os.close(fd)

    def _scan_open(self, path, fd, st, dbver, process, row=None, digest=None, current_only=False,
                   event="") -> Result:
        """Scan the open file. `digest` is passed when the caller has just
        hashed it; current_only = accept a remembered verdict for this
        content only if it was made with the current signatures (full disk
        scan)."""
        cfg = self.cfg
        head = os.pread(fd, filetype.HEAD, 0)
        kind = filetype.kind(head)
        if kind in ("unknown", "text") and st.st_size > 0x8006 and filetype.is_iso(fd):
            kind = "iso"
        ext = filetype.ext_of(path)
        risky = filetype.is_risky(kind, ext)
        if digest is None and st.st_size:
            digest = _digest(fd, st.st_size, cfg.hash_max)

        verdict, signature, cached = "clean", None, False
        if st.st_size == 0:
            pass
        elif self.index.is_allowed(digest):
            signature = "allowed"
        else:
            # 1) content already known?
            hv = self.index.hash_verdict(digest) if digest else None
            usable = hv and hv["verdict"] != "error" and (
                hv["db_version"] >= dbver or (not current_only and not risky))
            if usable:
                verdict, signature, cached = hv["verdict"], hv["signature"], True
            else:
                try:
                    media = kind in filetype.MEDIA_KINDS
                    whole = st.st_size <= cfg.full_scan_max and not (media and st.st_size > cfg.media_partial_min)
                    if whole:
                        r = self.clamd.scan_fd(fd)
                    else:
                        r = self.clamd.scan_partial(fd, st.st_size, cfg.partial_chunk)
                    if r.infected:
                        verdict, signature = "infected", r.signature
                    elif r.limited or (not whole and not media):
                        # too big or too deep for the engine: say so, never "clean"
                        verdict, signature = "partial", r.signature or "Lguard.Limits.TooLarge"
                    else:
                        verdict, signature = "clean", r.signature
                    if digest:
                        self.index.put_hash(digest, verdict, signature, dbver)
                except (ClamdError, OSError) as e:
                    verdict, signature = "error", None
                    self.log(f"clamd error on {path}: {e}")
            # 2) fake-media heuristics in the category folders (path
            # dependent, never cached by hash; also when the engine failed:
            # these need no signatures)
            if verdict in ("clean", "partial", "error") and cfg.is_priority(path):
                hv2 = filetype.media_verdict(path, kind, fd, cfg.mode_of(path))
                if hv2:
                    verdict, signature = hv2

        if cached:
            self.index.bump(cached=1)
        else:
            self.index.bump(scanned=1, nbytes=st.st_size)

        res = Result(path, verdict, signature, cached=cached,
                     detail="content already known (re-hashed, same SHA-256)" if cached else None)
        if verdict in BAD or verdict == "warning":
            known = row is not None and row.verdict == verdict and row.signature == signature
            if not (known and verdict == "warning"):      # a standing warning is reported once
                self._act(res, fd, st, digest, process, event)
        if res.action != "quarantined":
            now = time.time()
            born = (row.first_seen or row.scanned_at) if row is not None else now
            self.index.put(FileRow(path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                                   st.st_ctime_ns, digest, kind, int(risky), verdict, signature,
                                   dbver, now, verified_at=now, first_seen=born or now))
        else:
            self.index.forget(path)
        return res

    @staticmethod
    def _unchanged_days(st) -> int:
        """Whole days since content or attributes last changed (the later
        of the two: a file's own date can be set to anything)."""
        return int((time.time() - max(st.st_mtime, st.st_ctime)) // 86400)

    def _hold_days(self, res: Result, st, digest, event: str, sig, held: dict) -> int:
        """Days the detected file has been unchanged, when that is long
        enough to leave it where it is and ask; else 0 (quarantine now)."""
        cfg = self.cfg
        if not cfg.hold_old_days or event == "started" or cfg.is_priority(res.path):
            return 0
        if (res.signature or "").startswith("Lguard.") or self.index.is_condemned(digest):
            return 0
        if sig is not None and not sig.intact:       # altered after it was signed
            return 0
        days = self._unchanged_days(st)
        if any(h.get("digest") == digest for h in held.values()):
            return max(days, 1)                      # a copy of what is already waiting for a decision
        return days if days >= cfg.hold_old_days and not event else 0

    def _act(self, res: Result, fd, st, digest, process, event: str = ""):
        cfg = self.cfg
        sig = res.signature or "?"
        level = res.verdict
        signed = authenticode.check(fd, st.st_size) if res.verdict in BAD else None
        note = ""
        if signed is not None:
            res.detail = signed.describe()
            note = "\n" + (t("signed_ok", who=f" ({signed.signer})" if signed.signer else "")
                           if signed.intact else t("signed_broken"))
        held = self.index.held() if res.verdict in BAD else {}
        held_days = self._hold_days(res, st, digest, event, signed, held) if (
            res.verdict in BAD and cfg.may_quarantine(res.path)) else 0
        if held_days:
            res.action = "held"
            if (held.get(res.path) or {}).get("digest") != digest:
                known = any(h.get("digest") == digest for h in held.values())
                self.index.hold(res.path, digest, sig)
                self.index.add_finding(res.path, digest, level, sig, "held", None, process, res.detail)
                if not known:                        # one alert per content, not one per copy
                    notify(cfg, t("held_title"), t("held", sig=sig, path=res.path, days=held_days) + note,
                           "high", covered=bool(self.on_finding))
        elif res.verdict in BAD and cfg.may_quarantine(res.path):
            try:
                qid = quarantine.quarantine(cfg, res.path, fd, st, digest, sig, self.log)
                res.action = "quarantined"
                self.index.unhold(res.path)
                self.index.add_finding(res.path, digest, level, sig, "quarantined", qid, process, res.detail)
                notify(cfg, t(f"{level}_title"), t("quarantined", sig=sig, path=res.path) + note, "high",
                       covered=bool(self.on_finding))
            except Exception as e:
                res.action = "reported"
                res.detail = f"quarantine failed: {e}"
                self.index.add_finding(res.path, digest, level, sig, "reported", None, process, res.detail)
                notify(cfg, t(f"{level}_title"), t("quarantine_failed", sig=sig, path=res.path, err=e), "urgent")
        else:
            if res.verdict in BAD:
                level = "critical"
            res.action = "reported"
            self.index.add_finding(res.path, digest, level, sig, "reported", None, process, res.detail)
            prio = {"critical": "urgent", "warning": "default"}.get(level, "high")
            notify(cfg, t(f"{level}_title"), t("reported", sig=sig, path=res.path) + note, prio,
                   covered=bool(self.on_finding))
        self.index.commit()
        if self.on_finding:
            try:
                self.on_finding(res)
            except Exception:
                pass
