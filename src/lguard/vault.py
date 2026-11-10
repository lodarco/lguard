"""Keys and authenticated encryption for the Lguard inventory.

Master key: 32 random bytes created once (`lguard init`), sealed with
systemd-creds (bound to the TPM 2.0 chip when the machine has one, plus the
host secret), so it never lies on disk in the clear and a copied disk or
database is useless elsewhere. lguardd receives it via LoadCredentialEncrypted=
and holds it only in memory.

From the master key three subkeys are derived (HKDF-SHA256):
  enc   - AES-256-GCM for every stored record
  idx   - HMAC "blind index": record ids are HMAC(idx, path|digest|...), so
          lookups work without storing paths or hashes in the clear
  chain - HMAC for the append-only history (ledger) hash chain
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import config as config_mod

CRED_NAME = "lguard-master"
ANCHOR_NAME = "lguard-anchor"


class VaultError(Exception):
    pass


class TamperError(VaultError):
    """A stored record failed authentication."""


def _paths():
    sd = config_mod.STATE_DIR
    return (os.path.join(sd, "master.cred"), os.path.join(sd, "master.key"),
            os.path.join(sd, "anchor.cred"))


def have_systemd_creds() -> bool:
    if not shutil.which("systemd-creds"):
        return False
    try:
        r = subprocess.run(["systemd-creds", "--version"], capture_output=True, text=True, timeout=10)
        ver = int(r.stdout.split()[1])
        return ver >= 250
    except Exception:
        return False


def _seal(name: str, data: bytes, out_path: str):
    tmp = out_path + ".tmp"
    subprocess.run(["systemd-creds", "encrypt", "--with-key=auto", f"--name={name}", "-", tmp],
                   input=data, check=True, capture_output=True, timeout=60)
    os.chmod(tmp, 0o600)
    os.replace(tmp, out_path)


def _unseal(name: str, path: str) -> bytes:
    r = subprocess.run(["systemd-creds", "decrypt", f"--name={name}", path, "-"],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        raise VaultError(f"cannot unseal {path}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def init_master_key() -> str:
    """Create and seal a new master key. Refuses to overwrite an existing one."""
    cred, plain, _ = _paths()
    if os.path.exists(cred) or os.path.exists(plain):
        raise VaultError("a master key already exists")
    os.makedirs(config_mod.STATE_DIR, mode=0o700, exist_ok=True)
    key = os.urandom(32)
    if have_systemd_creds():
        _seal(CRED_NAME, key, cred)
        return "systemd-creds (TPM2 if present)"
    fd = os.open(plain, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return "plain file (no systemd-creds): weaker"


def load_master_key() -> bytes:
    # 1) handed over by systemd (LoadCredentialEncrypted=) - the normal case
    cdir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cdir and os.path.exists(os.path.join(cdir, CRED_NAME)):
        with open(os.path.join(cdir, CRED_NAME), "rb") as f:
            key = f.read()
    else:
        test_key = os.environ.get("LGUARD_KEY_FILE")       # tests only
        cred, plain, _ = _paths()
        if test_key:
            with open(test_key, "rb") as f:
                key = f.read()
        elif os.path.exists(cred):
            key = _unseal(CRED_NAME, cred)
        elif os.path.exists(plain):
            with open(plain, "rb") as f:
                key = f.read()
        else:
            raise VaultError("no master key: run `lguard init` first")
    if len(key) != 32:
        raise VaultError("master key has the wrong length")
    return key


def key_storage() -> str:
    cred, plain, _ = _paths()
    if os.path.exists(cred):
        return "sealed (systemd-creds)"
    if os.path.exists(plain):
        return "plain file"
    return "missing"


class Vault:
    def __init__(self, master: bytes):
        def sub(label: bytes) -> bytes:
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"lguard-v1",
                        info=label).derive(master)
        self._aead = AESGCM(sub(b"enc"))
        self._idx = sub(b"idx")
        self._chain = sub(b"chain")

    # blind index ---------------------------------------------------------
    def rid(self, table: str, key: str) -> bytes:
        return hmac.new(self._idx, f"{table}\0{key}".encode("utf-8", "surrogateescape"),
                        hashlib.sha256).digest()[:20]

    # records ---------------------------------------------------------------
    def seal(self, table: str, rid: bytes, obj) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogateescape")
        return nonce, self._aead.encrypt(nonce, data, table.encode() + b"\0" + rid)

    def open(self, table: str, rid: bytes, nonce: bytes, ct: bytes):
        try:
            data = self._aead.decrypt(nonce, ct, table.encode() + b"\0" + rid)
        except Exception as e:
            raise TamperError(f"{table} record failed authentication") from e
        return json.loads(data.decode("utf-8", "surrogateescape"))

    # ledger chain --------------------------------------------------------
    def chain(self, prev: bytes, seq: int, ts: float, nonce: bytes, ct: bytes) -> bytes:
        m = hmac.new(self._chain, prev, hashlib.sha256)
        m.update(seq.to_bytes(8, "big"))
        m.update(repr(ts).encode())
        m.update(nonce)
        m.update(ct)
        return m.digest()


# rollback anchor -----------------------------------------------------------
def write_anchor(seq: int, head: bytes):
    _, _, anchor = _paths()
    data = json.dumps({"seq": seq, "head": head.hex()}).encode()
    if have_systemd_creds() and os.geteuid() == 0:
        _seal(ANCHOR_NAME, data, anchor)
    # without systemd-creds there is no anchor: documented limitation


def read_anchor():
    _, _, anchor = _paths()
    if not os.path.exists(anchor):
        return None
    d = json.loads(_unseal(ANCHOR_NAME, anchor))
    return d["seq"], bytes.fromhex(d["head"])
