"""fanotify through ctypes (no third-party modules).

Two listeners:

Fanotify   marks whole filesystems for FAN_CLOSE_WRITE: the kernel reports
           every file that was open for writing and has just been closed, on
           the entire filesystem, without per-directory watches (inotify
           would need millions).
DirEvents  (Linux 5.9+) reports names that appear by rename and names that
           disappear: a download moved into place when it finishes gives no
           close-write event, and ransomware deletes the originals. On older
           kernels it is simply not available and the daemon falls back to
           re-checking folders.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import struct

FAN_CLOEXEC = 0x01
FAN_NONBLOCK = 0x02
FAN_CLASS_NOTIF = 0x00
FAN_UNLIMITED_QUEUE = 0x10

FAN_MARK_ADD = 0x01
FAN_MARK_MOUNT = 0x10
FAN_MARK_FILESYSTEM = 0x100

FAN_CLOSE_WRITE = 0x08
FAN_MOVED_FROM = 0x40
FAN_MOVED_TO = 0x80
FAN_DELETE = 0x200
FAN_ONDIR = 0x40000000
FAN_REPORT_DFID_NAME = 0x400 | 0x800        # FAN_REPORT_DIR_FID | FAN_REPORT_NAME
FAN_EVENT_INFO_TYPE_DFID_NAME = 2
O_PATH = 0o10000000
FAN_Q_OVERFLOW = 0x4000
FAN_NOFD = -1
AT_FDCWD = -100

_META = struct.Struct("=IBBHQii")   # event_len, vers, reserved, metadata_len, mask, fd, pid

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
_libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
_libc.open_by_handle_at.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]


class Fanotify:
    def __init__(self, unlimited_queue: bool = True):
        flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | (FAN_UNLIMITED_QUEUE if unlimited_queue else 0)
        event_flags = os.O_RDONLY | os.O_LARGEFILE | os.O_CLOEXEC | os.O_NOATIME
        fd = _libc.fanotify_init(flags, event_flags)
        if fd < 0:
            e = ctypes.get_errno()
            raise OSError(e, f"fanotify_init: {os.strerror(e)}")
        self.fd = fd

    def mark(self, path: str) -> str:
        """Watch the filesystem containing `path` (falls back to the mount
        for filesystems that refuse filesystem marks, e.g. FUSE)."""
        for how, flag in (("filesystem", FAN_MARK_FILESYSTEM), ("mount", FAN_MARK_MOUNT)):
            r = _libc.fanotify_mark(self.fd, FAN_MARK_ADD | flag, FAN_CLOSE_WRITE, AT_FDCWD, path.encode())
            if r == 0:
                return how
            e = ctypes.get_errno()
            if e not in (errno.EINVAL, errno.EXDEV, errno.ENODEV, errno.EOPNOTSUPP):
                raise OSError(e, f"fanotify_mark {path}: {os.strerror(e)}")
        raise OSError(errno.EOPNOTSUPP, f"fanotify cannot watch {path}")

    def read(self):
        """Yield (path | None, pid, overflow, first bytes) for each event;
        closes event fds."""
        buf = os.read(self.fd, 256 * 1024)
        off = 0
        while off + _META.size <= len(buf):
            event_len, vers, _r, mlen, mask, fd, pid = _META.unpack_from(buf, off)
            if event_len < _META.size:
                break
            off += event_len
            if mask & FAN_Q_OVERFLOW:
                yield None, 0, True, b""
                continue
            if fd < 0:
                continue
            magic = b""
            try:
                path = os.readlink(f"/proc/self/fd/{fd}")
                magic = os.pread(fd, 8, 0)      # costs nothing: the file is already open
            except OSError:
                path = None
            finally:
                os.close(fd)
            if path and not path.endswith(" (deleted)"):
                yield path, pid, False, magic

    def close(self):
        os.close(self.fd)


class DirEvents:
    """Names moved into place, moved away or deleted, on whole filesystems.

    Events arrive as (folder handle, name) instead of an open descriptor; the
    handle is turned back into a path with open_by_handle_at()."""

    def __init__(self):
        flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_REPORT_DFID_NAME
        fd = _libc.fanotify_init(flags, os.O_RDONLY)
        if fd < 0:
            e = ctypes.get_errno()
            raise OSError(e, f"fanotify_init (names): {os.strerror(e)}")     # EINVAL before Linux 5.9
        self.fd = fd
        # Nothing here keeps a folder open between events: an open folder
        # would make its disk impossible to unmount (USB sticks).
        self.roots: list[str] = []
        self._by_fsid: dict[bytes, str] = {}

    def mark(self, path: str):
        mask = FAN_MOVED_TO | FAN_MOVED_FROM | FAN_DELETE | FAN_ONDIR
        r = _libc.fanotify_mark(self.fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, path.encode())
        if r != 0:
            e = ctypes.get_errno()
            raise OSError(e, f"fanotify_mark (names) {path}: {os.strerror(e)}")
        if path not in self.roots:
            self.roots.append(path)

    def unmark(self, path: str):
        if path in self.roots:
            self.roots.remove(path)
        self._by_fsid = {k: v for k, v in self._by_fsid.items() if v != path}

    def _dir_path(self, fsid: bytes, handle: bytes, fds: dict) -> str | None:
        known = self._by_fsid.get(fsid)
        for root in ([known] if known else list(self.roots)):
            if root not in fds:
                try:
                    fds[root] = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                except OSError:
                    continue
            fd = _libc.open_by_handle_at(fds[root], handle, O_PATH | os.O_CLOEXEC)
            if fd < 0:
                continue
            try:
                self._by_fsid[fsid] = root
                return os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                return None
            finally:
                os.close(fd)
        return None

    def read(self):
        """Read one batch of events. Returns a list of (what, path, pid,
        is_dir): what is "moved_to", "moved_from" or "delete";
        (None, None, 0, False) on queue overflow."""
        fds: dict[str, int] = {}
        try:
            return list(self._read(fds))
        finally:
            for fd in fds.values():
                os.close(fd)

    def _read(self, fds):
        buf = os.read(self.fd, 256 * 1024)
        off = 0
        while off + _META.size <= len(buf):
            event_len, vers, _r, mlen, mask, fd, pid = _META.unpack_from(buf, off)
            if event_len < _META.size:
                break
            end = off + event_len
            info = off + mlen
            off = end
            if mask & FAN_Q_OVERFLOW:
                yield None, None, 0, False
                continue
            while info + 4 <= end:
                itype, _pad, ilen = struct.unpack_from("=BBH", buf, info)
                if ilen < 4:
                    break
                if itype == FAN_EVENT_INFO_TYPE_DFID_NAME:
                    fsid = bytes(buf[info + 4:info + 12])
                    hbytes, _htype = struct.unpack_from("=Ii", buf, info + 12)
                    hend = info + 20 + hbytes
                    handle = bytes(buf[info + 12:hend])
                    name = bytes(buf[hend:info + ilen]).split(b"\0", 1)[0]
                    d = self._dir_path(fsid, handle, fds)
                    if d and name and not d.endswith(" (deleted)"):
                        path = os.path.join(d, name.decode("utf-8", "surrogateescape"))
                        what = ("moved_to" if mask & FAN_MOVED_TO else
                                "moved_from" if mask & FAN_MOVED_FROM else "delete")
                        yield what, path, pid, bool(mask & FAN_ONDIR)
                info += ilen

    def close(self):
        os.close(self.fd)
