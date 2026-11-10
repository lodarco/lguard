"""Minimal clamd client.

Files are handed over as an open file descriptor (FILDES), so clamd, which
runs as the unprivileged `clamav` user, never needs read access to the file
itself, and the file cannot be swapped between our check and the scan.
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass


class ClamdError(Exception):
    pass


@dataclass
class ClamResult:
    infected: bool
    signature: str | None
    raw: str


def _recv_all(sock: socket.socket) -> str:
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        if data.endswith(b"\0"):
            break
    return b"".join(chunks).rstrip(b"\0").decode("utf-8", "replace")


def _parse(reply: str) -> ClamResult:
    # "fd[10]: OK" | "stream: Eicar-Test-Signature FOUND" | "...: <msg> ERROR"
    body = reply.split(": ", 1)[1] if ": " in reply else reply
    if body.endswith(" FOUND"):
        return ClamResult(True, body[: -len(" FOUND")], reply)
    if body == "OK":
        return ClamResult(False, None, reply)
    raise ClamdError(reply)


class Clamd:
    def __init__(self, socket_path: str, timeout: float = 300.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path)
        except OSError as e:
            s.close()
            raise ClamdError(f"clamd unreachable at {self.socket_path}: {e}") from e
        return s

    def command(self, cmd: str) -> str:
        with self._connect() as s:
            s.sendall(b"z" + cmd.encode() + b"\0")
            return _recv_all(s)

    def ping(self) -> bool:
        try:
            return self.command("PING") == "PONG"
        except (ClamdError, OSError):
            return False

    def version(self) -> tuple[str, int]:
        """('ClamAV 1.5.4', 28179) - the number is the signature database version.

        Some distributions ship clamd with EnableVersionCommand false; then
        the version is read from the header of the daily database instead."""
        try:
            reply = self.command("VERSION")
        except (ClamdError, OSError):
            reply = ""
        parts = reply.split("/")
        if reply.startswith("ClamAV") and len(parts) > 1 and parts[1].isdigit():
            return parts[0], int(parts[1])
        return engine_version(), database_version()


    def reload(self) -> str:
        return self.command("RELOAD")

    def scan_fd(self, fd: int) -> ClamResult:
        with self._connect() as s:
            # The command first, then the descriptor in its own message with a
            # one-byte payload (what clamdscan does); both in one message is a
            # protocol error.
            s.sendall(b"zFILDES\0")
            socket.send_fds(s, [b"\0"], [fd])
            return _parse(_recv_all(s))

    def scan_stream(self, chunks) -> ClamResult:
        """Scan bytes that are not a whole file (head + tail of a big video)."""
        with self._connect() as s:
            s.sendall(b"zINSTREAM\0")
            for chunk in chunks:
                for i in range(0, len(chunk), 1 << 20):
                    part = chunk[i:i + (1 << 20)]
                    s.sendall(struct.pack("!L", len(part)) + part)
            s.sendall(struct.pack("!L", 0))
            return _parse(_recv_all(s))

    def scan_partial(self, fd: int, size: int, chunk: int) -> ClamResult:
        def parts():
            yield os.pread(fd, chunk, 0)
            if size > chunk:
                start = max(chunk, size - chunk)
                yield os.pread(fd, size - start, start)
        return self.scan_stream(parts())


def database_version(db_dir: str = "/var/lib/clamav") -> int:
    """Version of the daily signature database, from its file header
    ("ClamAV-VDB:<date>:<version>:...")."""
    best = 0
    for name in ("daily.cld", "daily.cvd"):
        try:
            with open(os.path.join(db_dir, name), "rb") as f:
                head = f.read(512).decode("ascii", "replace")
            fields = head.split(":")
            if fields[0] == "ClamAV-VDB" and fields[2].isdigit():
                best = max(best, int(fields[2]))
        except (OSError, IndexError):
            continue
    return best


def engine_version() -> str:
    import subprocess
    try:
        out = subprocess.run(["clamd", "--version"], capture_output=True, text=True, timeout=10).stdout
        return out.split("/")[0].strip() or "ClamAV"
    except Exception:
        return "ClamAV"
