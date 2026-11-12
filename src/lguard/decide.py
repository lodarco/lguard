"""The user's decision on detected content, applied to every copy of it.

The same file usually sits in several places (a backup disk, a sync folder,
a trash bin). Trusting or removing one copy settles all of them: the ones in
quarantine and the ones that were left in place waiting for a decision.
"""
from __future__ import annotations

import os
import stat

from . import quarantine
from .config import Config
from .index import Index
from .scanner import _digest


def held_items(idx: Index) -> list[dict]:
    """Detections left in place, newest first."""
    out = [{"path": p, **h} for p, h in idx.held().items()]
    return sorted(out, key=lambda h: h.get("ts") or 0, reverse=True)


def prune_held(idx: Index) -> int:
    """Forget held files that are gone or no longer the same content."""
    n = 0
    for path, h in list(idx.held().items()):
        row = idx.get(path)
        if not os.path.lexists(path) or (row is not None and row.digest != h.get("digest")):
            idx.unhold(path)
            idx.finding_decided(path, h.get("digest"), "gone")
            n += 1
    if n:
        idx.commit()
    return n


def _move(cfg: Config, idx: Index, path: str, digest: str, signature: str, log) -> str | None:
    """Quarantine `path` if it still holds exactly `digest`."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or _digest(fd, st.st_size, cfg.hash_max) != digest:
            return None
        qid = quarantine.quarantine(cfg, path, fd, st, digest, signature or "?", log)
        idx.forget(path)
        return qid
    except (OSError, quarantine.QuarantineError) as e:
        log(f"could not quarantine {path}: {e}")
        return None
    finally:
        os.close(fd)


def trust(cfg: Config, idx: Index, digest: str, signature: str | None, note: str, log=print) -> dict:
    """Never flag this content again; put every quarantined copy back."""
    idx.pardon(digest)
    idx.allow(digest, signature, note)
    restored, kept = [], []
    for e in quarantine.entries(cfg):
        if e.get("digest") == digest:
            try:
                restored.append(quarantine.restore(cfg, e["id"], log))
                idx.finding_action(e["id"], "restored+trusted")
            except (OSError, quarantine.QuarantineError) as err:
                log(f"could not restore {e['path']}: {err}")
    for path, h in list(idx.held().items()):
        if h.get("digest") == digest:
            idx.unhold(path)
            idx.forget(path)                         # judged again (as trusted) at the next check
            idx.finding_decided(path, digest, "trusted")
            kept.append(path)
    idx.commit()
    return {"restored": restored, "kept": kept}


def isolate(cfg: Config, idx: Index, digest: str, log=print, final: str = "quarantined") -> list[str]:
    """Move every copy that was left in place into quarantine."""
    moved = []
    for path, h in list(idx.held().items()):
        if h.get("digest") != digest:
            continue
        qid = _move(cfg, idx, path, digest, h.get("signature"), log)
        idx.unhold(path)
        idx.finding_decided(path, digest, final if qid else "gone", qid)
        if qid:
            moved.append(qid)
    idx.commit()
    return moved


def remove(cfg: Config, idx: Index, digest: str, log=print) -> dict:
    """This content is a threat: delete every copy for good, and quarantine
    any copy that turns up later without asking."""
    idx.condemn(digest)
    isolate(cfg, idx, digest, log)
    n = 0
    for e in quarantine.entries(cfg):
        if e.get("digest") == digest:
            quarantine.delete(cfg, e["id"])
            idx.finding_action(e["id"], "deleted")
            n += 1
    idx.commit()
    return {"deleted": n}
