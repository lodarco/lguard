"""Shared test fixtures: a throw-away state folder, a real encrypted
inventory and a stand-in for the scan engine."""
import atexit
import os
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
_made = []                 # every folder these tests create is removed again
atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _made])
if "LGUARD_STATE" not in os.environ:
    os.environ["LGUARD_STATE"] = tempfile.mkdtemp(prefix="lguard-state-")
    _made.append(os.environ["LGUARD_STATE"])

from lguard import config, vault                      # noqa: E402
from lguard.clamd import ClamResult                   # noqa: E402
from lguard.index import Index                        # noqa: E402

# A stand-in "threat" that only the fake engine below knows. Deliberately not
# the EICAR test file: these tests write into /tmp, and a real antivirus on
# the machine running them (Lguard itself, for one) would rightly react.
THREAT = b"LGUARD-UNIT-TEST-THREAT (harmless marker, not a virus)"


class FakeClamd:
    """Flags THREAT, reports a limit for content starting with b"TOOBIG"."""

    def __init__(self):
        self.dbver = 100
        self.scans = 0

    def version(self):
        return "ClamAV test", self.dbver

    def ping(self):
        return True

    def _judge(self, data):
        self.scans += 1
        if THREAT in data:
            return ClamResult(True, "Test.Threat", "")
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
    _made.append(top)
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


def tmpdir():
    d = tempfile.mkdtemp(prefix="lguard-test-")
    _made.append(d)
    return d
