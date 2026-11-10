"""Shared test fixtures: a throw-away state folder, a real encrypted
inventory and a stand-in for the scan engine."""
import os
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ.setdefault("LGUARD_STATE", tempfile.mkdtemp(prefix="lguard-state-"))

from lguard import config, vault                      # noqa: E402
from lguard.clamd import ClamResult                   # noqa: E402
from lguard.index import Index                        # noqa: E402

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class FakeClamd:
    """Flags EICAR, reports a limit for content starting with b"TOOBIG"."""

    def __init__(self):
        self.dbver = 100
        self.scans = 0

    def version(self):
        return "ClamAV test", self.dbver

    def ping(self):
        return True

    def _judge(self, data):
        self.scans += 1
        if EICAR in data:
            return ClamResult(True, "Eicar-Test-Signature", "")
        if data.startswith(b"TOOBIG"):
            return ClamResult(False, "Heuristics.Limits.Exceeded.MaxFileSize", "", limited=True)
        return ClamResult(False, None, "")

    def scan_fd(self, fd):
        return self._judge(os.pread(fd, 1 << 20, 0))

    def scan_partial(self, fd, size, chunk):
        return self._judge(os.pread(fd, 1 << 20, 0))


def sandbox():
    """(folder, config, inventory) for one test."""
    top = tempfile.mkdtemp(prefix="lguard-test-")
    cfg = config.Config()
    cfg.quarantine_dir = os.path.join(top, "quarantine")
    cfg.never_quarantine = []
    cfg.desktop_notify = False
    cfg.data_paths = [os.path.join(top, "home")]
    os.makedirs(os.path.join(top, "home"))
    idx = Index(os.path.join(top, "index.db"), vault.Vault(os.urandom(32)))
    return top, cfg, idx


def write(path, data=b"hello\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def read(path):
    with open(path, "rb") as f:
        return f.read()
