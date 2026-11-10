"""Local API between lguardd (root) and the desktop app (the user).

Unix socket /run/lguard/api.sock, one JSON object per line:
  -> {"id": 1, "method": "status", "params": {}}
  <- {"id": 1, "result": {...}}            or {"id": 1, "error": "..."}
  -> {"id": 2, "method": "subscribe"}       then a stream of {"event": ...}

Who is calling is taken from the kernel (SO_PEERCRED), never from the
request. Reading status is allowed to the active local user (polkit action
io.github.lodarco.lguard.view); everything that changes something (restore,
delete, trust, unfreeze, freeze) needs io.github.lodarco.lguard.manage, which asks
for an administrator password through the desktop's polkit agent.
"""
from __future__ import annotations

import json
import os
import queue
import socket
import struct
import subprocess
import threading
import time

from . import config as config_mod
from . import detect, quarantine, vault
from .clamd import Clamd
from .config import Config
from .freeze import freeze, unfreeze
from .index import Index

SOCKET_PATH = os.environ.get("LGUARD_API_SOCKET", "/run/lguard/api.sock")
VIEW = "io.github.lodarco.lguard.view"
MANAGE = "io.github.lodarco.lguard.manage"
READ_METHODS = {"status", "findings", "events", "daily", "category", "quarantine", "subscribe", "ping",
                "start_sweep", "pause_sweep", "resume_sweep", "get_folders"}


def _peer(conn: socket.socket):
    data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", data)          # pid, uid, gid


def _start_time(pid: int) -> str:
    with open(f"/proc/{pid}/stat") as f:
        rest = f.read().rsplit(")", 1)[1].split()
    return rest[19]                            # field 22: starttime


def authorized(action: str, pid: int, uid: int, interactive: bool) -> bool:
    if uid == 0:
        return True
    cmd = ["pkcheck", "--action-id", action, "--process", f"{pid},{_start_time(pid)},{uid}"]
    if interactive:
        cmd.append("--allow-user-interaction")
    try:
        return subprocess.run(cmd, capture_output=True, timeout=300).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class Api:
    def __init__(self, cfg: Config, v: vault.Vault, index_path: str, daemon=None, log=print):
        self.cfg = cfg
        self.vault = v
        self.index_path = index_path
        self.daemon = daemon
        self.log = log
        self.subscribers: list[queue.Queue] = []
        self.lock = threading.Lock()

    # ---------------------------------------------------------- events out
    def publish(self, event: dict):
        event = {"event": event.get("event", "update"), "ts": time.time(), **event}
        with self.lock:
            for q in list(self.subscribers):
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass

    # ---------------------------------------------------------- server
    def serve(self, stop: threading.Event):
        os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
        os.chmod(os.path.dirname(SOCKET_PATH), 0o755)
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o666)            # who may do what is decided per call
        srv.listen(16)
        srv.settimeout(1.0)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._client, args=(conn, stop), daemon=True).start()
        srv.close()

    def _client(self, conn: socket.socket, stop: threading.Event):
        try:
            pid, uid, _gid = _peer(conn)
        except OSError:
            conn.close()
            return
        f = conn.makefile("rwb", buffering=0)
        idx = Index(self.index_path, self.vault, readonly=True)
        try:
            for line in f:
                try:
                    req = json.loads(line)
                    rid, method, params = req.get("id"), req.get("method", ""), req.get("params") or {}
                except (ValueError, AttributeError):
                    break
                need = VIEW if method in READ_METHODS else MANAGE
                if not authorized(need, pid, uid, interactive=need == MANAGE):
                    self._send(f, {"id": rid, "error": "not authorized"})
                    continue
                if method == "subscribe":
                    self._stream(f, stop)
                    return
                try:
                    result = getattr(self, "m_" + method)(idx, uid=uid, **params)
                    self._send(f, {"id": rid, "result": result})
                except AttributeError:
                    self._send(f, {"id": rid, "error": f"unknown method {method}"})
                except Exception as e:
                    self._send(f, {"id": rid, "error": str(e)})
        except (OSError, ValueError):
            pass
        finally:
            idx.close()
            conn.close()

    @staticmethod
    def _send(f, obj):
        f.write(json.dumps(obj, default=str).encode() + b"\n")

    def _stream(self, f, stop):
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self.lock:
            self.subscribers.append(q)
        try:
            self._send(f, {"event": "subscribed"})
            while not stop.is_set():
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    ev = {"event": "heartbeat", "ts": time.time()}
                self._send(f, ev)
        except OSError:
            pass
        finally:
            with self.lock:
                self.subscribers.remove(q)

    # ---------------------------------------------------------- read methods
    def m_ping(self, idx, uid):
        return "pong"

    def m_status(self, idx, uid):
        try:
            eng, db = Clamd(self.cfg.clamd_socket).version()
            engine_ok = Clamd(self.cfg.clamd_socket).ping()
        except Exception:
            eng, db, engine_ok = "?", 0, False
        counts = idx.meta_get("counts") or {}
        d = self.daemon
        seq, head = idx.ledger_head()
        return {
            "engine": eng, "signatures": db, "engine_ok": engine_ok,
            "realtime": bool(d) and not d.stop.is_set(),
            "watched": d.watched if d else [],
            "files": idx.file_count(), "counts": counts,
            "last_sweep": idx.meta_get("last_sweep"),
            "frozen": idx.meta_get("frozen", "no"),
            "quarantine": len(quarantine.entries(self.cfg)),
            "key": vault.key_storage(),
            "history": {"entries": seq, "head": head.hex()[:16]},
            "categories": {k: v for k, v in self.cfg.categories.items()},
            "verify": idx.meta_get("verify_progress") or {},
            "queue": (len(d.work) + len(d.pending)) if d else 0,
            "current": list(d.current.values()) if d else [],
            "sweep": self._sweep_progress(idx),
            "sweep_control": idx.meta_get("sweep_control") or {},
            "stats": dict(d.stats) if d else {},
        }

    @staticmethod
    def _sweep_progress(idx):
        p = idx.meta_get("sweep_progress") or {}
        if p.get("running"):
            try:
                os.kill(int(p.get("pid", 0)), 0)
            except (OSError, ValueError):
                p["running"] = False        # the process died without saying so
        return p

    def m_start_sweep(self, idx, uid, full: bool = False):
        """"Scan now": quick check of everything that changed (first time: all),
        or full=True: the full disk scan - every file read and checked again."""
        unit = "lguard-fullscan.service" if full else "lguard-sweep.service"
        w = self._write_index()
        try:
            w.meta_set("sweep_control", {"paused": False})
        finally:
            w.close()
        r = subprocess.run(["systemctl", "start", "--no-block", unit], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "could not start the scan")
        self.publish({"event": "sweep_started", "full": full})
        return {"started": unit}

    def m_pause_sweep(self, idx, uid, minutes: int | None = None):
        """Pause the running scan; with minutes, it resumes by itself then."""
        resume_at = time.time() + int(minutes) * 60 if minutes else None
        w = self._write_index()
        try:
            w.meta_set("sweep_control", {"paused": True, "resume_at": resume_at, "by": uid})
        finally:
            w.close()
        self.publish({"event": "sweep_paused", "resume_at": resume_at})
        return {"paused": True, "resume_at": resume_at}

    def m_resume_sweep(self, idx, uid):
        w = self._write_index()
        try:
            w.meta_set("sweep_control", {"paused": False})
        finally:
            w.close()
        self.publish({"event": "sweep_resumed"})
        return {"paused": False}

    # ---------------------------------------------------------- folders
    def m_get_folders(self, idx, uid):
        c = self.cfg
        return {"categories": c.categories, "priority_paths": c.priority_paths,
                "extra_excludes": c.extra_excludes, "report_only": c.report_only,
                "detected": detect.suggestions(),
                "app_file": os.path.join(config_mod.dropin_dir(config_mod.CONFIG_PATH), config_mod.APP_DROPIN)}

    def m_set_folders(self, idx, uid, categories: dict, priority_paths: list, extra_excludes: list,
                      report_only: list):
        """Save folders from the app (lguard.d/50-app.toml) and apply them at once."""
        def clean(paths):
            out = []
            for p in paths or []:
                p = str(p).strip()
                if not p:
                    continue
                if not os.path.isabs(p) or "\0" in p or "\n" in p:
                    raise ValueError(f"not an absolute path: {p!r}")
                p = os.path.normpath(p)
                if p not in out:
                    out.append(p)
            return out
        cats = {}
        for name, paths in (categories or {}).items():
            name = str(name).strip()
            if not name or len(name) > 40 or any(ch in name for ch in "\"\n[]="):
                raise ValueError(f"bad category name: {name!r}")
            cats[name] = clean(paths)
        excludes = []
        for p in clean(extra_excludes):
            excludes.append(p if any(ch in p for ch in "*?") else p.rstrip("/") + "/*")
        out = config_mod.write_app_settings({"categories": cats, "priority_paths": clean(priority_paths),
                                             "extra_excludes": excludes, "report_only": clean(report_only)},
                                            config_mod.CONFIG_PATH)
        self.reload_config()
        w = self._write_index()
        try:
            w.event("folders_changed", f"uid {uid}: {out}")
        finally:
            w.close()
        self.publish({"event": "folders_changed"})
        return self.m_get_folders(idx, uid)

    def reload_config(self):
        """Apply changed settings in place (everyone holds the same Config object)."""
        new = config_mod.load(config_mod.CONFIG_PATH)
        for attr in ("categories", "priority_paths", "extra_excludes", "report_only", "never_quarantine",
                     "data_paths", "notify_command", "freeze_commands", "unfreeze_commands"):
            setattr(self.cfg, attr, getattr(new, attr))

    def m_daily(self, idx, uid, days: int = 14):
        return idx.daily(days)

    def m_findings(self, idx, uid, limit: int = 200):
        return idx.findings(limit)

    def m_events(self, idx, uid, limit: int = 100):
        return idx.events(limit)

    def m_quarantine(self, idx, uid):
        return quarantine.entries(self.cfg)

    def m_category(self, idx, uid, name: str):
        """Downloads/libraries of one media category: top-level folders with
        size, newest change and what was found in them."""
        paths = self.cfg.categories.get(name, [])
        bad: dict[str, list] = {}
        for f in idx.findings(1000):
            bad.setdefault(f["path"], []).append(f)
        items = []
        for top in paths:
            try:
                entries = list(os.scandir(top))
            except OSError:
                continue
            for e in entries:
                n, size, newest, found = 0, 0, 0.0, []
                walk = [e.path] if e.is_dir(follow_symlinks=False) else []
                if e.is_file(follow_symlinks=False):
                    st = e.stat(follow_symlinks=False)
                    n, size, newest = 1, st.st_size, st.st_mtime
                while walk:
                    d = walk.pop()
                    try:
                        for x in os.scandir(d):
                            if x.is_dir(follow_symlinks=False):
                                walk.append(x.path)
                            elif x.is_file(follow_symlinks=False):
                                st = x.stat(follow_symlinks=False)
                                n += 1
                                size += st.st_size
                                newest = max(newest, st.st_mtime)
                    except OSError:
                        pass
                prefix = e.path.rstrip("/") + "/"
                for p, fs in bad.items():
                    if p == e.path or p.startswith(prefix):
                        found += fs
                items.append({"name": e.name, "path": e.path, "files": n, "bytes": size,
                              "changed": newest, "findings": found})
        items.sort(key=lambda i: i["changed"], reverse=True)
        return {"name": name, "paths": paths, "items": items[:200]}

    # ---------------------------------------------------------- manage methods
    def _write_index(self) -> Index:
        return Index(self.index_path, self.vault)

    def m_restore(self, idx, uid, qid: str, trust: bool = False):
        w = self._write_index()
        try:
            meta = next((e for e in quarantine.entries(self.cfg) if e["id"] == qid), None)
            if not meta:
                raise ValueError("no such quarantine entry")
            if trust and meta.get("digest"):
                w.allow(meta["digest"], meta.get("signature"), f"restored {meta['path']} (uid {uid})")
            target = quarantine.restore(self.cfg, qid)
            w.finding_action(qid, "restored+trusted" if trust else "restored")
        finally:
            w.close()
        self.publish({"event": "quarantine_changed"})
        return {"restored_to": target}

    def m_delete(self, idx, uid, qid: str):
        w = self._write_index()
        try:
            quarantine.delete(self.cfg, qid)
            w.finding_action(qid, "deleted")
        finally:
            w.close()
        self.publish({"event": "quarantine_changed"})
        return {"deleted": qid}

    def m_unfreeze(self, idx, uid):
        w = self._write_index()
        try:
            res = unfreeze(self.cfg, w)
        finally:
            w.close()
        self.publish({"event": "frozen_changed", "frozen": False})
        return res

    def m_freeze(self, idx, uid):
        w = self._write_index()
        try:
            ok = freeze(self.cfg, w, f"manual (uid {uid})")
        finally:
            w.close()
        self.publish({"event": "frozen_changed", "frozen": ok})
        return ok

    def m_scan(self, idx, uid, path: str):
        """Queue a file or folder for scanning (it runs in the daemon)."""
        if not self.daemon:
            raise RuntimeError("real-time protection is not running")
        path = os.path.realpath(path)
        self.daemon.enqueue_tree(path)
        return {"queued": path}
