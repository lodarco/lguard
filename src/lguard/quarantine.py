"""Quarantine: take a detected file out of reach, keep it restorable.

The file is moved (renamed when on the same filesystem, else copied and the
original unlinked) to <quarantine_dir>/<id>.bin, root-only, without execute
bits. <id>.json keeps everything needed to put it back exactly as it was.

Lguard does this as root inside folders that belong to ordinary users, so
nothing here trusts a path: the folder is opened one component at a time
without following symbolic links, and every step then works relative to that
open folder and on open file descriptors. A user who swaps a folder for a
link to /etc while a file is being quarantined or restored gets an error,
not root's hand on a system file.
"""
from __future__ import annotations

import errno
import json
import os
import shlex
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


def open_dir(path: str, create_owner: tuple[int, int] | None = None) -> int:
    """Open the directory `path` (absolute) without following a symbolic link
    in any component. With create_owner, missing folders are created and
    given to that (uid, gid). Returns an O_PATH descriptor."""
    if not path.startswith("/"):
        raise QuarantineError(f"not an absolute path: {path}")
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise QuarantineError(f"'..' in path: {path}")
            try:
                nfd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if create_owner is None:
                    raise
                os.mkdir(part, 0o755, dir_fd=fd)
                os.chown(part, create_owner[0], create_owner[1], dir_fd=fd, follow_symlinks=False)
                nfd = os.open(part, flags, dir_fd=fd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise QuarantineError(f"{path}: {part!r} is a link or not a folder") from e
                raise
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _same(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def quarantine(cfg: Config, path: str, fd: int, st: os.stat_result, digest: str | None,
               signature: str, log=print) -> str:
    """Move the file open as `fd` (identity `st`) into quarantine. Returns the id."""
    qdir = cfg.quarantine_dir
    os.makedirs(qdir, mode=0o700, exist_ok=True)
    os.chmod(qdir, 0o700)

    # Where the scanned file really is now, according to the kernel - not
    # according to a path that may have been re-pointed since.
    real = os.readlink(f"/proc/self/fd/{fd}")
    if not real.startswith("/") or real.endswith(" (deleted)"):
        raise QuarantineError("file is gone")
    if not cfg.may_quarantine(real):
        raise QuarantineError(f"file is in a protected location ({real})")
    dname, base = os.path.split(real)
    dfd = open_dir(dname)
    try:
        cur = os.stat(base, dir_fd=dfd, follow_symlinks=False)
        if not _same(cur, st):
            raise QuarantineError("file was replaced while being scanned")

        # Defuse first: whatever happens next, it can no longer be executed.
        try:
            os.fchmod(fd, stat.S_IMODE(st.st_mode) & ~0o7111)
        except OSError:
            pass

        qid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        dest = _bin_path(qdir, qid)
        meta = {
            "id": qid, "path": real, "uid": st.st_uid, "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode), "size": st.st_size,
            "mtime_ns": st.st_mtime_ns, "digest": digest, "signature": signature,
            "quarantined_at": time.time(),
        }
        if os.stat(qdir).st_dev == st.st_dev:
            os.rename(base, dest, src_dir_fd=dfd)
            if not _same(os.lstat(dest), st):          # the name was swapped at the last moment
                os.rename(dest, base, dst_dir_fd=dfd)
                raise QuarantineError("file was replaced while being moved")
        else:
            out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                off = 0
                while True:
                    buf = os.pread(fd, 1 << 20, off)
                    if not buf:
                        break
                    os.write(out, buf)
                    off += len(buf)
                os.fsync(out)
            finally:
                os.close(out)
            if off != os.fstat(fd).st_size:
                os.unlink(dest)
                raise QuarantineError("copy into quarantine was incomplete")
            cur = os.stat(base, dir_fd=dfd, follow_symlinks=False)
            if not _same(cur, st):
                os.unlink(dest)
                raise QuarantineError("file was replaced during the copy")
            os.unlink(base, dir_fd=dfd)
    finally:
        os.close(dfd)
    if os.geteuid() == 0:
        os.chown(dest, 0, 0)
    os.chmod(dest, 0o400)
    with open(_meta_path(qdir, qid), "w") as f:
        json.dump(meta, f, indent=1)
    os.chmod(_meta_path(qdir, qid), 0o600)
    _run_hooks(cfg, real, log)
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


def _valid_id(qid: str) -> str:
    if not qid or "/" in qid or qid.startswith("."):
        raise QuarantineError("bad quarantine id")
    return qid


def restore(cfg: Config, qid: str, log=print) -> str:
    """Put a quarantined file back. Never overwrites: if the original name is
    taken again, it is restored next to it with a .restored suffix."""
    qdir = cfg.quarantine_dir
    with open(_meta_path(qdir, _valid_id(qid))) as f:
        meta = json.load(f)
    dname, base = os.path.split(meta["path"])
    uid, gid = int(meta["uid"]), int(meta["gid"])
    dfd = open_dir(dname, create_owner=(uid, gid))
    src = _bin_path(qdir, qid)
    sfd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        def taken(name):
            try:
                os.stat(name, dir_fd=dfd, follow_symlinks=False)
                return True
            except FileNotFoundError:
                return False
        name, n = base, 0
        while taken(name):
            n += 1
            name = base + ".restored" + (str(n) if n > 1 else "")
        # Owner, mode and time are set on the open file while it is still in
        # quarantine - never afterwards by name in the user's folder.
        os.fchown(sfd, uid, gid)
        os.fchmod(sfd, int(meta["mode"]) & 0o1777)       # never restores setuid/setgid
        os.utime(sfd, ns=(meta["mtime_ns"], meta["mtime_ns"]))
        try:
            os.rename(src, name, dst_dir_fd=dfd)
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            try:
                off = 0
                while True:
                    buf = os.pread(sfd, 1 << 20, off)
                    if not buf:
                        break
                    os.write(out, buf)
                    off += len(buf)
                os.fchown(out, uid, gid)
                os.fchmod(out, int(meta["mode"]) & 0o1777)
                os.utime(out, ns=(meta["mtime_ns"], meta["mtime_ns"]))
                os.fsync(out)
            finally:
                os.close(out)
            os.unlink(src)
    finally:
        os.close(sfd)
        os.close(dfd)
    os.unlink(_meta_path(qdir, qid))
    target = os.path.join(dname, name)
    _run_hooks(cfg, meta["path"], log)
    return target


def delete(cfg: Config, qid: str):
    qdir = cfg.quarantine_dir
    for p in (_bin_path(qdir, _valid_id(qid)), _meta_path(qdir, qid)):
        if os.path.exists(p):
            os.unlink(p)
