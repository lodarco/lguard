"""Publisher signature of a Windows program (Authenticode), read-only.

Answers one question about a detected file: does it carry a signature, and
is the content still exactly what was signed? A virus that writes itself
into a program breaks that; an untouched installer keeps it.

What this does NOT do is decide who is trustworthy: the certificate chain is
not checked, and anybody can sign a file with a certificate they made
themselves. So an intact signature is shown to the user as evidence and
never keeps a new file out of quarantine; a broken one counts against the
file.

Standard library only.
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

MAX_SIZE = 512 * 1024 * 1024
MAX_CERT = 1024 * 1024
_HASHES = {20: "sha1", 32: "sha256", 48: "sha384", 64: "sha512"}
_OID_CN = bytes.fromhex("550403")
_OID_O = bytes.fromhex("55040a")


@dataclass
class Signature:
    intact: bool                 # the signed digest equals the content now
    signer: str | None = None    # name stated in the signing certificate
    self_signed: bool = False

    def describe(self) -> str:
        who = f' by "{self.signer}"' if self.signer else ""
        if not self.intact:
            return f"signed{who}, but the content was changed after signing"
        own = ", self-signed" if self.self_signed else ""
        return f"signed{who}{own}, unchanged since signing (publisher not verified)"


# ------------------------------------------------------------------- DER
def _tlv(buf: bytes, off: int):
    """(tag, start of value, end of value) of the element at `off`."""
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7f
        if not 1 <= k <= 4:
            raise ValueError("bad length")
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    if off + n > len(buf):
        raise ValueError("element runs past the end")
    return tag, off, off + n


def _children(buf: bytes, start: int, end: int):
    out = []
    while start < end:
        tag, s, e = _tlv(buf, start)
        out.append((tag, s, e, start))
        start = e
    return out


def _name_text(buf: bytes, start: int, end: int) -> str | None:
    """Common name, else organisation, of an X.509 Name."""
    found = {}
    for _t, s, e, _o in _children(buf, start, end):            # RDN sets
        for _t2, s2, e2, _o2 in _children(buf, s, e):          # attribute sequences
            kids = _children(buf, s2, e2)
            if len(kids) == 2 and kids[0][0] == 0x06:
                oid = buf[kids[0][1]:kids[0][2]]
                raw = buf[kids[1][1]:kids[1][2]]
                text = raw.decode("utf-16-be" if kids[1][0] == 0x1e else "utf-8", "replace")
                found.setdefault(oid, text)
    text = found.get(_OID_CN) or found.get(_OID_O)
    return "".join(ch for ch in text if ch.isprintable())[:80] if text else None


def _parse(p7: bytes):
    """(signed digest, signer name, self-signed) from a PKCS#7 SignedData."""
    _t, s, e = _tlv(p7, 0)                                     # ContentInfo
    kids = _children(p7, s, e)
    _t, s, e = _tlv(p7, kids[1][1])                            # [0] -> SignedData
    sd = _children(p7, s, e)
    # SpcIndirectDataContent: { data, messageDigest { algorithm, digest } }
    ci = _children(p7, sd[2][1], sd[2][2])
    _t, s, e = _tlv(p7, ci[1][1])
    spc = _children(p7, s, e)
    md = _children(p7, spc[1][1], spc[1][2])
    if md[1][0] != 0x04:
        raise ValueError("no digest")
    digest = p7[md[1][1]:md[1][2]]

    certs = next((c for c in sd[3:] if c[0] == 0xa0), None)
    infos = sd[-1]
    signer, self_signed = None, False
    try:
        si = _children(p7, *_tlv(p7, infos[1])[1:])            # first SignerInfo
        ias = _children(p7, si[1][1], si[1][2])                # issuer, serial
        issuer = p7[ias[0][3]:ias[0][2]]
        serial = p7[ias[1][1]:ias[1][2]]
        for _t, cs, ce, _o in _children(p7, certs[1], certs[2]) if certs else []:
            tbs = _children(p7, *_tlv(p7, cs)[1:])
            f = tbs[1:] if tbs[0][0] == 0xa0 else tbs          # skip the version
            if p7[f[0][1]:f[0][2]] == serial and p7[f[2][3]:f[2][2]] == issuer:
                signer = _name_text(p7, f[4][1], f[4][2])
                self_signed = p7[f[4][3]:f[4][2]] == issuer
                break
    except (IndexError, ValueError, TypeError):
        pass
    return digest, signer, self_signed


# -------------------------------------------------------------------- PE
def check(fd: int, size: int) -> Signature | None:
    """None when the file is not a signed Windows program (or cannot be
    read as one); otherwise whether its signature still matches."""
    try:
        if size < 0x100 or size > MAX_SIZE:
            return None
        head = os.pread(fd, 4096, 0)
        if head[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", head, 0x3c)[0]
        if pe + 24 + 240 > len(head) or head[pe:pe + 4] != b"PE\0\0":
            return None
        opt = pe + 24
        magic = struct.unpack_from("<H", head, opt)[0]
        if magic not in (0x10b, 0x20b):
            return None
        dd = opt + (96 if magic == 0x10b else 112)
        if struct.unpack_from("<I", head, dd - 4)[0] < 5:      # no certificate table entry
            return None
        cert_off, cert_len = struct.unpack_from("<II", head, dd + 8 * 4)
        if not cert_off or cert_len < 16 or cert_len > MAX_CERT or cert_off + cert_len > size:
            return None
        table = os.pread(fd, cert_len, cert_off)
        length, _rev, kind = struct.unpack_from("<IHH", table, 0)
        if kind != 2 or length < 16 or length > len(table):    # 2 = PKCS#7 SignedData
            return None
        try:
            digest, signer, self_signed = _parse(table[8:length])
        except (IndexError, ValueError, TypeError):
            return None
        alg = _HASHES.get(len(digest))
        if not alg:
            return None

        # The signed digest covers the file without its checksum field, the
        # pointer to the certificate table and the table itself.
        h = hashlib.new(alg)
        skip = [(opt + 64, opt + 68), (dd + 8 * 4, dd + 8 * 5), (cert_off, cert_off + cert_len)]
        pos = 0
        for a, b in skip + [(size, size)]:
            while pos < a:
                buf = os.pread(fd, min(1 << 20, a - pos), pos)
                if not buf:
                    return None
                h.update(buf)
                pos += len(buf)
            pos = max(pos, b)
        return Signature(h.digest() == digest, signer, self_signed)
    except (OSError, struct.error):
        return None
