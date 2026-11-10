"""Quarantine: take a detected file out of reach, keep it restorable.

The file is moved (renamed when on the same filesystem, else copied and the
original unlinked) to <quarantine_dir>/<id>.bin, root-only, without execute
bits. <id>.json keeps everything needed to put it back exactly as it was.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import subprocess
import time
import uuid

from .config import Config


class QuarantineError(Exception):
    pass


def _meta_path(qdir: str, qid: str) -> str:
    return os.path.join(qdir, qid + ".json")


def _bin_path(qdir: str, qid: str) -> str:
    return os.path.join(qdir, qid + ".bin")


def _run_hooks(cfg: Config, path: str, log):
    for prefix, cmd in cfg.post_quarantine_hooks.items():
        if path.startswith(prefix.rstrip("/") + "/"):
            rel = path[len(prefix.rstrip("/")) + 1:]
            full = (cmd.replace("{path}", shlex.quote(path))
                       .replace("{relpath}", shlex.quote(rel))
                       .replace("{reldir}", shlex.quote(os.path.dirname(rel))))
            try:
                subprocess.run(full, shell=True, timeout=600, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:  # a failing hook must never undo the quarantine
                log(f"hook failed for {path}: {e}")


def quarantine(cfg: Config, path: str, fd: int, st: os.stat_result, digest: str | None,
               signature: str, log=print) -> str:
    """Move `path` (open as `fd`, identity `st`) into quarantine. Returns the id."""
    qdir = cfg.quarantine_dir
    os.makedirs(qdir, mode=0o700, exist_ok=True)
    os.chmod(qdir, 0o700)

    # The path must still be the very file we scanned.
    cur = os.lstat(path)
    if (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
        raise QuarantineError("file was replaced while being scanned")

    # Defuse first: whatever happens next, it can no longer be executed.
    try:
        os.fchmod(fd, stat.S_IMODE(st.st_mode) & ~0o7111)
    except OSError:
        pass

    qid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
    dest = _bin_path(qdir, qid)
    meta = {
        "id": qid, "path": path, "uid": st.st_uid, "gid": st.st_gid,
        "mode": stat.S_IMODE(st.st_mode), "size": st.st_size,
        "mtime_ns": st.st_mtime_ns, "digest": digest, "signature": signature,
        "quarantined_at": time.time(),
    }
    qdev = os.stat(qdir).st_dev
    if qdev == st.st_dev:
        os.rename(path, dest)
    else:
        with open(dest, "wb") as out:
            os.lseek(fd, 0, os.SEEK_SET)
            while True:
                buf = os.read(fd, 1 << 20)
                if not buf:
                    break
                out.write(buf)
            out.flush()
            os.fsync(out.fileno())
        if os.path.getsize(dest) != st.st_size:
            os.unlink(dest)
            raise QuarantineError("copy into quarantine was incomplete")
        cur = os.lstat(path)
        if (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
            os.unlink(dest)
            raise QuarantineError("file was replaced during the copy")
        os.unlink(path)
    os.chown(dest, 0, 0)
    os.chmod(dest, 0o400)
    with open(_meta_path(qdir, qid), "w") as f:
        json.dump(meta, f, indent=1)
    os.chmod(_meta_path(qdir, qid), 0o600)
    _run_hooks(cfg, path, log)
    return qid


def entries(cfg: Config) -> list[dict]:
    qdir = cfg.quarantine_dir
    out = []
    if not os.path.isdir(qdir):
        return out
    for name in sorted(os.listdir(qdir), reverse=True):
        if name.endswith(".json"):
            try:
                with open(os.path.join(qdir, name)) as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                continue
    return out


def restore(cfg: Config, qid: str, log=print) -> str:
    """Put a quarantined file back. Never overwrites: if the original path is
    taken again, it is restored next to it with a .restored suffix."""
    qdir = cfg.quarantine_dir
    with open(_meta_path(qdir, qid)) as f:
        meta = json.load(f)
    target = meta["path"]
    if os.path.lexists(target):
        target = target + ".restored"
    os.makedirs(os.path.dirname(target), exist_ok=True)
    src = _bin_path(qdir, qid)
    try:
        os.rename(src, target)
    except OSError:
        shutil.copyfile(src, target)
        os.unlink(src)
    os.chown(target, meta["uid"], meta["gid"])
    os.chmod(target, meta["mode"])
    os.utime(target, ns=(meta["mtime_ns"], meta["mtime_ns"]))
    os.unlink(_meta_path(qdir, qid))
    _run_hooks(cfg, meta["path"], log)
    return target


def delete(cfg: Config, qid: str):
    qdir = cfg.quarantine_dir
    for p in (_bin_path(qdir, qid), _meta_path(qdir, qid)):
        if os.path.exists(p):
            os.unlink(p)
