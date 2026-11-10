"""fanotify through ctypes (no third-party modules).

Marks whole filesystems for FAN_CLOSE_WRITE: the kernel reports every file
that was open for writing and has just been closed, on the entire
filesystem, without per-directory watches (inotify would need millions).
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
FAN_Q_OVERFLOW = 0x4000
FAN_NOFD = -1
AT_FDCWD = -100

_META = struct.Struct("=IBBHQii")   # event_len, vers, reserved, metadata_len, mask, fd, pid

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
_libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]


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
        """Yield (path | None, pid, overflow) for each event; closes event fds."""
        buf = os.read(self.fd, 256 * 1024)
        off = 0
        while off + _META.size <= len(buf):
            event_len, vers, _r, mlen, mask, fd, pid = _META.unpack_from(buf, off)
            if event_len < _META.size:
                break
            off += event_len
            if mask & FAN_Q_OVERFLOW:
                yield None, 0, True
                continue
            if fd < 0:
                continue
            try:
                path = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                path = None
            finally:
                os.close(fd)
            if path and not path.endswith(" (deleted)"):
                yield path, pid, False

    def close(self):
        os.close(self.fd)
