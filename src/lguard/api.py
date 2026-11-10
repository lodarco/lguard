"""Local API between lguardd (root) and the desktop app (the user).

Unix socket /run/lguard/api.sock, one JSON object per line:
  -> {"id": 1, "method": "status", "params": {}}
  <- {"id": 1, "result": {...}}            or {"id": 1, "error": "..."}
  -> {"id": 2, "method": "subscribe"}       then a stream of {"event": ...}

Who is calling is taken from the kernel (SO_PEERCRED), never from the
request. Reading status, starting a scan and a short pause are allowed to the
active local user (polkit action io.github.lodarco.lguard.view); everything
that weakens protection or changes something (restore, delete, trust,
unfreeze, folders, a long pause) needs io.github.lodarco.lguard.manage, which
asks for an administrator password through the desktop's polkit agent.

The socket is open to every local account, so before a caller is known to be
allowed it gets very little: a request line is at most 64 KiB, connections
are limited in total and per user, and the inventory is opened only for an
authorised request.
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

from . import __version__
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
                "start_sweep", "resume_sweep", "get_folders", "scan", "trusted"}
MAX_LINE = 64 * 1024
MAX_CONNECTIONS = 64
MAX_PER_USER = 16
MAX_PAUSE_MIN = 24 * 60


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
        self.subscribers: list[tuple[queue.Queue, int]] = []      # (queue, uid)
        self.lock = threading.Lock()
        self.connections: dict[int, int] = {}                     # uid -> open connections

    def subscriber_uids(self) -> set:
        """Users whose app is connected right now."""
        with self.lock:
            return {uid for _q, uid in self.subscribers}

    def need(self, method: str, params: dict) -> str:
        if method == "pause_sweep":
            try:
                minutes = int(params.get("minutes") or 0)
            except (TypeError, ValueError):
                minutes = 0
            return VIEW if 0 < minutes <= self.cfg.pause_free_minutes else MANAGE
        return VIEW if method in READ_METHODS else MANAGE

    # ---------------------------------------------------------- events out
    def publish(self, event: dict):
        event = {"event": event.get("event", "update"), "ts": time.time(), **event}
        with self.lock:
            for q, _uid in list(self.subscribers):
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
        srv.listen(64)
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
        with self.lock:
            total = sum(self.connections.values())
            mine = self.connections.get(uid, 0)
            if uid != 0 and (total >= MAX_CONNECTIONS or mine >= MAX_PER_USER):
                conn.close()
                return
            self.connections[uid] = mine + 1
        idx = None
        view_ok_until = 0.0
        try:
            conn.settimeout(30)                       # a caller that says nothing is dropped
            f = conn.makefile("rb")
            while True:
                line = f.readline(MAX_LINE + 1)
                if not line or len(line) > MAX_LINE:
                    break
                try:
                    req = json.loads(line)
                    rid, method, params = req.get("id"), str(req.get("method", "")), req.get("params") or {}
                    if not isinstance(params, dict):
                        raise ValueError
                except (ValueError, AttributeError):
                    break
                need = self.need(method, params)
                if need == VIEW and time.time() < view_ok_until:
                    ok = True
                else:
                    conn.settimeout(600)              # the password dialog may be open
                    ok = authorized(need, pid, uid, interactive=need == MANAGE)
                    if ok and need == VIEW:
                        view_ok_until = time.time() + 60
                if not ok:
                    self._send(conn, {"id": rid, "error": "not authorized"})
                    continue
                conn.settimeout(600)
                if method == "subscribe":
                    self._stream(conn, stop, uid)
                    return
                handler = getattr(self, "m_" + method, None) if method.isidentifier() else None
                if handler is None:
                    self._send(conn, {"id": rid, "error": f"unknown method {method}"})
                    continue
                if idx is None:
                    idx = Index(self.index_path, self.vault, readonly=True)
                params.pop("idx", None)
                params.pop("uid", None)
                try:
                    self._send(conn, {"id": rid, "result": handler(idx, uid=uid, **params)})
                except Exception as e:
                    self._send(conn, {"id": rid, "error": str(e)})
        except (OSError, ValueError):
            pass
        finally:
            if idx is not None:
                idx.close()
            conn.close()
            with self.lock:
                left = self.connections.get(uid, 1) - 1
                if left > 0:
                    self.connections[uid] = left
                else:
                    self.connections.pop(uid, None)

    @staticmethod
    def _send(conn, obj):
        conn.sendall(json.dumps(obj, default=str).encode() + b"\n")

    def _stream(self, conn, stop, uid):
        q: queue.Queue = queue.Queue(maxsize=1000)
        entry = (q, uid)
        with self.lock:
            self.subscribers.append(entry)
        try:
            self._send(conn, {"event": "subscribed"})
            while not stop.is_set():
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    ev = {"event": "heartbeat", "ts": time.time()}
                self._send(conn, ev)
        except OSError:
            pass
        finally:
            with self.lock:
                self.subscribers.remove(entry)

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
            "version": __version__,
            "scans": self.scans_active(),
            "stopped": idx.meta_get("stopped") or [],
            "rename_events": bool(d and d.names is not None),
            "category_modes": {k: self.cfg.mode_of(v[0]) if v else "downloads"
                               for k, v in self.cfg.categories.items()},
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

    def scans_active(self) -> dict:
        """Which scans are running or waiting their turn (asked at most
        every two seconds)."""
        now = time.time()
        cached = getattr(self, "_scans", None)
        if cached and now - cached[0] < 2:
            return cached[1]
        try:
            out = subprocess.run(["systemctl", "is-active", "lguard-sweep.service", "lguard-fullscan.service"],
                                 capture_output=True, text=True, timeout=10).stdout.split()
        except (OSError, subprocess.TimeoutExpired):
            out = []
        out += ["unknown"] * 2
        res = {"quick": out[0] in ("active", "activating"), "full": out[1] in ("active", "activating")}
        self._scans = (now, res)
        return res

    def m_start_sweep(self, idx, uid, full: bool = False):
        """"Scan now": quick check of everything that changed (first time: all),
        or full=True: the full disk scan - every file read and checked again."""
        unit = "lguard-fullscan.service" if full else "lguard-sweep.service"
        self._scans = None
        active = self.scans_active()
        # never the same scan twice; and a quick check while the full disk
        # scan runs would have nothing left to do
        if active["full"] or (active["quick"] and not full):
            return {"started": unit, "already": True}
        self._scans = None
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
        """Pause the running scan. It always resumes by itself: at the chosen
        time, or after a day at the latest. (A pause longer than
        pause_free_minutes needed the administrator password to get here.)"""
        try:
            minutes = int(minutes or 0)
        except (TypeError, ValueError):
            minutes = 0
        minutes = min(minutes, MAX_PAUSE_MIN) if minutes > 0 else MAX_PAUSE_MIN
        resume_at = time.time() + minutes * 60
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
        return {"categories": c.categories,
                "category_modes": {k: c.mode_of(v[0]) if v else c.category_modes.get(k) or
                                   ("media" if k.lower() in ("plex", "jellyfin", "emby", "kodi") else "downloads")
                                   for k, v in c.categories.items()},
                "priority_paths": c.priority_paths,
                "extra_excludes": c.extra_excludes, "report_only": c.report_only,
                "data_paths": c.data_paths,
                "detected": detect.suggestions(),
                "app_file": os.path.join(config_mod.dropin_dir(config_mod.CONFIG_PATH), config_mod.APP_DROPIN)}

    def m_set_folders(self, idx, uid, categories: dict, priority_paths: list, extra_excludes: list,
                      report_only: list, category_modes: dict | None = None, data_paths: list | None = None):
        """Save folders from the app (lguard.d/50-app.toml) and apply them at once."""
        def clean(paths):
            out = []
            for p in paths or []:
                p = str(p).strip()
                if not p:
                    continue
                if not os.path.isabs(p) or any(ord(ch) < 32 or ord(ch) == 127 for ch in p):
                    raise ValueError(f"not a usable absolute path: {p!r}")
                p = os.path.normpath(p)
                if p not in out:
                    out.append(p)
            return out

        def clean_name(name):
            name = str(name).strip()
            if not name or len(name) > 40 or any(ch in name for ch in "\"[]=") \
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
                raise ValueError(f"bad category name: {name!r}")
            return name
        cats = {clean_name(name): clean(paths) for name, paths in (categories or {}).items()}
        modes = {}
        for name, mode in (category_modes or {}).items():
            if mode not in ("media", "downloads"):
                raise ValueError(f"bad mode for {name!r}: {mode!r}")
            if clean_name(name) in cats:
                modes[clean_name(name)] = mode
        excludes = []
        for p in clean(extra_excludes):
            excludes.append(p if any(ch in p for ch in "*?") else p.rstrip("/") + "/*")
        values = {"categories": cats, "category_modes": modes, "priority_paths": clean(priority_paths),
                  "extra_excludes": excludes, "report_only": clean(report_only)}
        if data_paths is not None:
            values["data_paths"] = clean(data_paths)
            if not values["data_paths"]:
                raise ValueError("the ransomware shield needs at least one folder to protect")
        out = config_mod.write_app_settings(values, config_mod.CONFIG_PATH)
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
        for attr in ("categories", "category_modes", "priority_paths", "extra_excludes", "report_only",
                     "never_quarantine", "data_paths", "notify_command", "freeze_commands", "unfreeze_commands"):
            setattr(self.cfg, attr, getattr(new, attr))

    def m_daily(self, idx, uid, days: int = 14):
        return idx.daily(days)

    def m_findings(self, idx, uid, limit: int = 200):
        return idx.findings(limit)

    def m_events(self, idx, uid, limit: int = 100):
        return idx.events(limit)

    def m_quarantine(self, idx, uid):
        return quarantine.entries(self.cfg)

    def m_trusted(self, idx, uid):
        """Content the user chose to trust (restore & trust)."""
        return idx.allowlist()

    def m_untrust(self, idx, uid, digest: str):
        w = self._write_index()
        try:
            w.unallow(str(digest), f"uid {uid}")
        finally:
            w.close()
        self.publish({"event": "quarantine_changed"})
        return {"untrusted": digest}

    def m_resume_process(self, idx, uid):
        """Let the program(s) suspended by a ransomware alarm continue."""
        from .ransom import resume_stopped
        w = self._write_index()
        try:
            done = resume_stopped(w)
        finally:
            w.close()
        self.publish({"event": "frozen_changed"})
        return {"resumed": done}

    def m_category(self, idx, uid, name: str):
        """Downloads/libraries of one media category: top-level folders with
        size, newest change and what was found in them."""
        if name == "torrents":
            name = "downloads"
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
        return {"name": name, "paths": paths, "items": items[:200],
                "mode": self.cfg.mode_of(paths[0]) if paths else "downloads"}

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
        path = os.path.realpath(str(path))
        if not os.path.exists(path):
            raise ValueError(f"no such file or folder: {path}")
        threading.Thread(target=self.daemon.enqueue_tree, args=(path,), daemon=True).start()
        return {"queued": path}
