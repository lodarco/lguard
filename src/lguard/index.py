"""The encrypted, authenticated scan inventory.

Nothing in the database is readable or forgeable without the master key:

  files     id = HMAC(path)      payload: path, identity, sha256, verdict ...
  hashes    id = HMAC(sha256)    payload: verdict per content
  allow     id = HMAC(sha256)    payload: user-approved false positives
  meta      id = HMAC(name)      payload: settings / state
  daily     id = HMAC(day)       payload: counters for the graphs
  ledger    seq, ts, payload, chain = HMAC(prev chain, seq, ts, payload)

Every payload is AES-256-GCM with (table, id) as associated data, so a record
cannot be edited, nor moved to another id (a "clean" row copied onto a virus'
path fails authentication). A record that fails is treated as absent - the
file is simply scanned again - and is reported as tampering.

A file counts as unchanged only if (dev, inode, size, mtime, ctime) all
match; ctime cannot be set back by a user.
"""
from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import asdict, dataclass, fields

from .vault import TamperError, Vault

SCHEMA = """
CREATE TABLE IF NOT EXISTS files  (id BLOB PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hashes (id BLOB PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS allow  (id BLOB PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta   (id BLOB PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS daily  (id BLOB PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ledger (
    seq   INTEGER PRIMARY KEY,
    ts    REAL NOT NULL,
    nonce BLOB NOT NULL,
    ct    BLOB NOT NULL,
    chain BLOB NOT NULL
);
"""

GENESIS = b"\0" * 32


@dataclass
class FileRow:
    path: str
    dev: int
    ino: int
    size: int
    mtime_ns: int
    ctime_ns: int
    digest: str | None
    kind: str | None
    risky: int
    verdict: str            # clean | infected | suspicious | warning | error | skipped
    signature: str | None
    db_version: int
    scanned_at: float
    verified_at: float = 0.0   # last time the content was read again and re-checked
    first_seen: float = 0.0    # when this path first entered the inventory

    def identity(self):
        return (self.dev, self.ino, self.size, self.mtime_ns, self.ctime_ns)


_FILE_FIELDS = [f.name for f in fields(FileRow)]


def identity_of(st: os.stat_result):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class Index:
    def __init__(self, path: str, vault: Vault, readonly: bool = False):
        self.path = path
        self.v = vault
        self.tamper_count = 0
        self.on_tamper = None          # callback(table, detail)
        self.readonly = readonly
        self._counters: dict[str, dict] = {}      # day -> counters not yet written
        if readonly:
            self.db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=60,
                                      isolation_level=None)
        else:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            new = not os.path.exists(path)
            self.db = sqlite3.connect(path, timeout=60, isolation_level=None)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)
            if new:
                os.chmod(path, 0o600)
        # A record stored as text instead of bytes (someone edited the file)
        # must fail authentication like any other forgery, not raise.
        self.db.text_factory = bytes

    def close(self):
        self.commit()
        self.db.close()

    # --- low level -------------------------------------------------------
    def _begin(self):
        if not self.db.in_transaction:
            self.db.execute("BEGIN")

    def commit(self):
        if self.db.in_transaction:
            self.db.execute("COMMIT")
        if self._counters:
            self.flush_counters()

    def _tamper(self, table: str, detail: str):
        self.tamper_count += 1
        if self.on_tamper:
            try:
                self.on_tamper(table, detail)
            except Exception:
                pass

    def _get(self, table: str, key: str):
        rid = self.v.rid(table, key)
        r = self.db.execute(f"SELECT nonce, ct FROM {table} WHERE id=?", (rid,)).fetchone()
        if not r:
            return None
        try:
            return self.v.open(table, rid, bytes(r[0]), bytes(r[1]))
        except (TamperError, TypeError, ValueError):
            self._tamper(table, f"record for {key!r} failed authentication")
            return None

    def _put(self, table: str, key: str, obj):
        # Autocommit: one short write, never a lock held across slow work
        # (hashing a 4 GB film takes seconds; another process must not wait).
        rid = self.v.rid(table, key)
        nonce, ct = self.v.seal(table, rid, obj)
        self.db.execute(f"INSERT OR REPLACE INTO {table}(id, nonce, ct) VALUES (?,?,?)", (rid, nonce, ct))

    def _del(self, table: str, key: str):
        self.db.execute(f"DELETE FROM {table} WHERE id=?", (self.v.rid(table, key),))

    def _iter(self, table: str):
        """Decrypt every record of a table (sweeps, verify, GUI lists)."""
        for rid, nonce, ct in self.db.execute(f"SELECT id, nonce, ct FROM {table}"):
            try:
                yield self.v.open(table, bytes(rid), bytes(nonce), bytes(ct))
            except (TamperError, TypeError, ValueError):
                self._tamper(table, f"record {bytes(rid).hex()[:12]} failed authentication")

    # --- files -----------------------------------------------------------
    def get(self, path: str) -> FileRow | None:
        d = self._get("files", path)
        if d is None:
            return None
        if d.get("path") != path:            # can only happen with a forged id
            self._tamper("files", f"record under {path!r} belongs to {d.get('path')!r}")
            return None
        return FileRow(**{k: d.get(k) for k in _FILE_FIELDS})

    def put(self, row: FileRow):
        self._put("files", row.path, asdict(row))

    def forget(self, path: str):
        self._del("files", path)

    def iter_files(self):
        for d in self._iter("files"):
            yield FileRow(**{k: d.get(k) for k in _FILE_FIELDS})

    def file_count(self) -> int:
        return self.db.execute("SELECT count(*) FROM files").fetchone()[0]

    # --- hashes / allowlist ----------------------------------------------
    def hash_verdict(self, digest: str):
        return self._get("hashes", digest)

    def put_hash(self, digest: str, verdict: str, signature: str | None, db_version: int):
        self._put("hashes", digest, {"verdict": verdict, "signature": signature,
                                     "db_version": db_version, "scanned_at": time.time()})

    def is_allowed(self, digest: str | None) -> bool:
        return bool(digest) and self._get("allow", digest) is not None

    def allow(self, digest: str, signature: str | None, note: str = ""):
        self._put("allow", digest, {"digest": digest, "signature": signature, "note": note, "ts": time.time()})
        self.ledger("allow", {"digest": digest, "signature": signature, "note": note})

    def unallow(self, digest: str, note: str = ""):
        """Take back "trust": the content is scanned and judged again."""
        self._del("allow", digest)
        self._del("hashes", digest)
        self.ledger("unallow", {"digest": digest, "note": note})

    def allowlist(self) -> list[dict]:
        """Content the user trusted and has not taken back, newest first."""
        out: dict[str, dict] = {}
        for e in reversed(self.ledger_entries(kinds={"allow", "unallow"})):     # oldest first
            if e["kind"] == "allow":
                out[e["digest"]] = {"digest": e["digest"], "signature": e.get("signature"),
                                    "note": e.get("note"), "ts": e["ts"]}
            else:
                out.pop(e["digest"], None)
        return sorted((v for d, v in out.items() if self.is_allowed(d)), key=lambda v: v["ts"], reverse=True)

    # --- meta ------------------------------------------------------------
    def meta_get(self, key: str, default=None):
        d = self._get("meta", key)
        return default if d is None else d["v"]

    def meta_set(self, key: str, value):
        self._put("meta", key, {"k": key, "v": value})

    # --- daily counters (graphs) -----------------------------------------
    def bump(self, scanned=0, cached=0, nbytes=0, findings=0):
        """Per-day counters. Kept in memory and written with the next
        commit(): one small write every few seconds, not one per file."""
        d = self._counters.setdefault(time.strftime("%Y-%m-%d"),
                                      {"scanned": 0, "cached": 0, "bytes": 0, "findings": 0})
        d["scanned"] += scanned
        d["cached"] += cached
        d["bytes"] += nbytes
        d["findings"] += findings

    def flush_counters(self):
        """Several processes add to the same day, so the read-modify-write
        runs in one short IMMEDIATE transaction."""
        pending, self._counters = self._counters, {}
        if self.readonly:
            return
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for day, add in pending.items():
                d = self._get("daily", day) or {"day": day, "scanned": 0, "cached": 0, "bytes": 0, "findings": 0}
                for k, v in add.items():
                    d[k] = d.get(k, 0) + v
                self._put("daily", day, d)
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            for day, add in pending.items():         # keep them for the next try
                cur = self._counters.setdefault(day, {"scanned": 0, "cached": 0, "bytes": 0, "findings": 0})
                for k, v in add.items():
                    cur[k] += v
            raise

    def daily(self, days: int = 30):
        rows = sorted(self._iter("daily"), key=lambda d: d["day"], reverse=True)
        return rows[:days]

    # --- ledger (append-only, hash-chained history) ----------------------
    def ledger(self, kind: str, data: dict) -> int:
        """Append one history record. Runs in its own IMMEDIATE transaction so
        two processes can never fork the chain."""
        self.commit()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            last = self.db.execute("SELECT seq, chain FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
            ts = time.time()
            rid = seq.to_bytes(8, "big")
            nonce, ct = self.v.seal("ledger", rid, {"kind": kind, **data})
            chain = self.v.chain(prev, seq, ts, nonce, ct)
            self.db.execute("INSERT INTO ledger(seq, ts, nonce, ct, chain) VALUES (?,?,?,?,?)",
                            (seq, ts, nonce, ct, chain))
            self.db.execute("COMMIT")
            return seq
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def ledger_head(self):
        r = self.db.execute("SELECT seq, chain FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return (r[0], r[1]) if r else (0, GENESIS)

    def ledger_entries(self, limit: int | None = None, kinds: set | None = None):
        q = "SELECT seq, ts, nonce, ct FROM ledger ORDER BY seq DESC"
        out = []
        for seq, ts, nonce, ct in self.db.execute(q):
            try:
                d = self.v.open("ledger", seq.to_bytes(8, "big"), bytes(nonce), bytes(ct))
            except (TamperError, TypeError, ValueError, AttributeError):
                self._tamper("ledger", f"entry {seq} failed authentication")
                continue
            if kinds and d.get("kind") not in kinds:
                continue
            d["seq"], d["ts"] = seq, ts
            out.append(d)
            if limit and len(out) >= limit:
                break
        return out

    def verify_ledger(self) -> list[str]:
        """Walk the whole chain. Returns a list of problems (empty = intact)."""
        problems = []
        prev, expect = GENESIS, 1
        for seq, ts, nonce, ct, chain in self.db.execute(
                "SELECT seq, ts, nonce, ct, chain FROM ledger ORDER BY seq"):
            if seq != expect:
                problems.append(f"gap: expected entry {expect}, found {seq}")
            try:
                calc = self.v.chain(bytes(prev), seq, ts, bytes(nonce), bytes(ct))
            except (TypeError, ValueError, AttributeError):
                calc = None
            if calc != chain:
                problems.append(f"entry {seq}: chain mismatch (edited, inserted or reordered)")
            try:
                self.v.open("ledger", seq.to_bytes(8, "big"), bytes(nonce), bytes(ct))
            except (TamperError, TypeError, ValueError, AttributeError):
                problems.append(f"entry {seq}: content failed authentication")
            prev, expect = chain, seq + 1
        return problems

    # --- findings / events on top of the ledger --------------------------
    def add_finding(self, path, digest, level, signature, action, quarantine_id=None,
                    process=None, detail=None) -> int:
        self.bump(findings=1)
        self.commit()
        return self.ledger("finding", {"path": path, "digest": digest, "level": level,
                                       "signature": signature, "action": action,
                                       "quarantine_id": quarantine_id, "process": process,
                                       "detail": detail})

    def finding_action(self, quarantine_id: str, action: str):
        self.ledger("finding_update", {"quarantine_id": quarantine_id, "action": action})

    def findings(self, limit: int = 200):
        entries = self.ledger_entries(kinds={"finding", "finding_update"})
        updates = {}
        for e in reversed(entries):              # oldest first
            if e["kind"] == "finding_update":
                updates[e["quarantine_id"]] = e["action"]
        out = []
        for e in entries:
            if e["kind"] != "finding":
                continue
            if e.get("quarantine_id") in updates:
                e["action"] = updates[e["quarantine_id"]]
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def event(self, kind: str, detail: str = ""):
        self.ledger("event", {"event": kind, "detail": detail})

    def events(self, limit: int = 200):
        return self.ledger_entries(limit=limit, kinds={"event"})
