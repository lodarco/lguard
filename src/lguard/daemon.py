"""lguardd: real-time protection.

  written files ─┐
  (close-write)  ├─► debounce (path quiet for N s) ──► priority queue ──► scan workers
  files moved    │                                       (category folders first)
  into place ────┘
  written / deleted / moved away ──► ransomware detector (at once, cheap head read)

Runs as root under systemd. Sweeps are separate timer units; the daemon
handles what changes while it runs. Filesystems mounted later (a USB stick)
are picked up within seconds. On kernels without rename events (before 5.9)
the category folders are polled and a folder where a download just finished
is looked at again.
"""
from __future__ import annotations

import heapq
import os
import queue
import select
import signal
import subprocess
import sys
import threading
import time
import traceback

from . import config as config_mod
from .clamd import Clamd
from .api import Api
from .fanotify import DirEvents, Fanotify
from .i18n import set_language, t
from . import index as index_mod
from .index import Index
from . import filetype, vault
from . import notify as notify_mod
from .notify import notify
from .ransom import RansomDetector
from .scanner import Scanner
from .sweep import Sweep, roots

INDEX_PATH = os.path.join(config_mod.STATE_DIR, "index.db")
# The inventory and SQLite's two side files: see Fanotify.protect().
INDEX_FILES = (INDEX_PATH, INDEX_PATH + "-wal", INDEX_PATH + "-shm")
SELF_ALERT_FILE = os.path.join(config_mod.STATE_DIR, "self-alert")


def log(msg: str):
    print(notify_mod.safe(msg), flush=True)


def self_alert(cfg, body: str, every_s: int = 1800):
    """Tell the user that Lguard itself is in trouble - but not on every
    restart of a service that keeps failing."""
    try:
        if time.time() - os.stat(SELF_ALERT_FILE).st_mtime < every_s:
            return
    except OSError:
        pass
    try:
        with open(SELF_ALERT_FILE, "w") as f:
            f.write(notify_mod.safe(body)[:500] + "\n")
    except OSError:
        pass
    try:
        notify(cfg, t("self_title"), body, "urgent")
    except Exception as e:
        log(f"could not send the alert: {e}")


def _proc_name(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        # A process may call itself anything, including bytes that are no text.
        with open(f"/proc/{pid}/comm", "rb") as f:
            return f.read().decode("utf-8", "replace").strip() or f"pid {pid}"
    except Exception:
        return f"pid {pid}"


class Daemon:
    def __init__(self, cfg, v: "vault.Vault"):
        self.cfg = cfg
        self.vault = v
        self.stop = threading.Event()
        self.pending: dict[str, tuple[float, str]] = {}      # path -> (last event, process)
        self.pending_lock = threading.Lock()
        self.work: list = []                                  # heap of (prio, ts, path, proc, event)
        self.held: set[str] = set()                           # detections left in place (see scanner)
        self.work_cv = threading.Condition()
        self.ransom_q: queue.Queue = queue.Queue(maxsize=100000)
        self.own_pids = {os.getpid()}
        self.stats = {"events": 0, "queued": 0, "scanned": 0, "overflows": 0}
        self.watched: list[str] = []
        self.current: dict[int, str] = {}
        self.api = Api(cfg, v, INDEX_PATH, daemon=self, log=log)
        notify_mod.skip_uids = self.api.subscriber_uids
        self.clamd_down_since = 0.0
        self.names: DirEvents | None = None                   # rename/delete events (Linux 5.9+)
        self.recheck: dict[str, float] = {}                   # folder -> look again until
        self.threads: list[threading.Thread] = []             # all of them must stay alive
        self.fatal: str | None = None                         # why the service must restart itself

    # ---------------------------------------------------------- self-checks
    def fail(self, why: str):
        """Something this service cannot repair while running: stop, so that
        systemd starts it again (a restart also rebuilds a damaged inventory)."""
        if self.fatal is None:
            self.fatal = why
            log(f"FATAL: {why}")

    def note_error(self, e: BaseException):
        """Called wherever the inventory is used and an error is caught."""
        if index_mod.is_damage(e):
            index_mod.mark_broken(INDEX_PATH, str(e))
            self.fail(f"inventory damaged: {e}")

    def deep_check(self):
        try:
            why = index_mod.looks_sound(INDEX_PATH, deep=True)
        except Exception as e:
            log(f"inventory check: {e}")
            return
        if why:
            index_mod.mark_broken(INDEX_PATH, why)
            self.fail(f"inventory damaged: {why}")

    def _thread(self, target, name: str, args=()) -> threading.Thread:
        """A thread that reports its own death instead of vanishing."""
        def body():
            try:
                target(*args)
            except BaseException as e:           # noqa: B036 - nothing may pass silently here
                log(f"thread {name} died: {e!r}\n{traceback.format_exc()}")
                self.note_error(e)
            if not self.stop.is_set():
                self.fail(f"{name} stopped")
        th = threading.Thread(target=body, name=name, daemon=True)
        self.threads.append(th)
        return th

    def healthy(self) -> bool:
        return self.fatal is None and all(th.is_alive() for th in self.threads)

    # ---------------------------------------------------------------- reader
    def _watch(self, fan: Fanotify, announce: bool = True):
        """Mark every local filesystem not marked yet; forget the ones that
        went away. Returns the newly watched mount points."""
        now = roots(self.cfg)
        new = []
        for r in now:
            if r in self.watched:
                continue
            try:
                how = fan.mark(r)
            except OSError as e:
                if announce:
                    log(f"cannot watch {r}: {e}")
                continue
            self.watched.append(r)
            new.append(r)
            names = ""
            if self.names is not None:
                try:
                    self.names.mark(r)
                    names = ", renames and deletes"
                except OSError as e:
                    names = f", no rename events here ({e.strerror})"
            log(f"watching {r} ({how}{names})")
        for r in [r for r in self.watched if r not in now]:
            self.watched.remove(r)
            if self.names is not None:
                self.names.unmark(r)
            log(f"no longer mounted: {r}")
        return new

    def _queue(self, path: str, proc: str):
        with self.pending_lock:
            if len(self.pending) > 500_000 and path not in self.pending:
                self.stats["overflows"] += 1          # a sweep will catch up
                return
            self.pending[path] = (time.time(), proc)

    def reader(self):
        fan = Fanotify()
        fan.protect(INDEX_FILES)              # before any filesystem is marked
        try:
            self.names = DirEvents()
        except OSError as e:
            log(f"rename events not available on this kernel ({e.strerror}): category folders are polled instead")
        self._watch(fan)
        if self.names is not None:
            self._thread(self.names_reader, "names").start()
        poll = select.poll()
        poll.register(fan.fd, select.POLLIN)
        cfg = self.cfg
        last_mounts = time.time()
        while not self.stop.is_set():
            if time.time() - last_mounts > 5:
                last_mounts = time.time()
                fan.protect(INDEX_FILES)
                if len(fan.kept) > 32:
                    # Should not happen (the kernel filters them); if it does,
                    # a restart is cheaper than a pile of open descriptors.
                    self.fail("events on the inventory keep arriving")
                try:
                    if self._watch(fan, announce=False):
                        self.start_sweep("new disk")      # what is already on it
                except OSError:
                    pass
            if not poll.poll(1000):
                continue
            for path, pid, overflow, magic, what in fan.read():
                if overflow:
                    self.stats["overflows"] += 1
                    log("fanotify queue overflow: a sweep will catch up")
                    continue
                if pid in self.own_pids:
                    continue
                if "start" in what and path in self.held:
                    # a file with a detection that was left in place is being run
                    log(f"started while waiting for a decision: {path} (by {_proc_name(pid)})")
                    with self.work_cv:
                        heapq.heappush(self.work, (-1, time.time(), path, _proc_name(pid), "started"))
                        self.work_cv.notify()
                if "write" not in what:
                    continue
                self.stats["events"] += 1
                if not cfg.is_watched(path):
                    continue
                if cfg.is_excluded(path):
                    if self.names is None and cfg.is_incomplete(path):
                        # no rename events: the finished download will show
                        # up in this folder under its real name
                        self.recheck[os.path.dirname(path)] = time.time() + 900
                    continue
                if cfg.is_soft_excluded(path) and not filetype.is_program(magic):
                    continue                              # cache/log data; programs are never exempt
                proc = _proc_name(pid)
                self._queue(path, proc)
                if cfg.is_data(path):
                    try:
                        self.ransom_q.put_nowait((path, proc, pid, "write"))
                    except queue.Full:
                        pass
        fan.close()

    def names_reader(self):
        """Files (and folders) renamed into place are scanned like written
        ones; documents that disappear are reported to the ransomware
        detector."""
        cfg = self.cfg
        poll = select.poll()
        poll.register(self.names.fd, select.POLLIN)
        while not self.stop.is_set():
            if not poll.poll(1000):
                continue
            try:
                events = list(self.names.read())
            except OSError as e:
                log(f"rename events: {e}")
                continue
            for what, path, pid, is_dir in events:
                if path is None:
                    self.stats["overflows"] += 1
                    continue
                if pid in self.own_pids or not cfg.is_watched(path):
                    continue
                if what == "moved_to":
                    if cfg.is_excluded(path if not is_dir else path + "/x"):
                        continue
                    self.stats["events"] += 1
                    if is_dir:
                        if cfg.is_soft_excluded(path + "/x"):
                            continue
                        threading.Thread(target=self.enqueue_tree, args=(path, _proc_name(pid), 1),
                                         daemon=True).start()
                    else:
                        proc = _proc_name(pid)
                        self._queue(path, proc)
                        if cfg.is_data(path):
                            try:
                                self.ransom_q.put_nowait((path, proc, pid, "write"))
                            except queue.Full:
                                pass
                elif not is_dir and cfg.is_data(path) and filetype.promises_format(path):
                    try:
                        self.ransom_q.put_nowait((path, _proc_name(pid), pid, what))
                    except queue.Full:
                        pass

    def start_sweep(self, why: str):
        """Ask systemd for a quick check (it does nothing if one is running)."""
        try:
            subprocess.run(["systemctl", "start", "--no-block", "lguard-sweep.service"],
                           capture_output=True, timeout=30)
            log(f"quick check requested: {why}")
        except (OSError, subprocess.TimeoutExpired) as e:
            log(f"could not start a quick check ({why}): {e}")

    # -------------------------------------------------------------- debounce
    def refresh_held(self):
        """Files with a detection that were left in place (also by the
        nightly check, which is another process); the ones that are gone
        are dropped from the list."""
        from . import decide
        try:
            idx = Index(INDEX_PATH, self.vault)
            try:
                decide.prune_held(idx)
                self.held = set(idx.held())
            finally:
                idx.close()
        except Exception as e:
            log(f"held files: {e}")
            self.note_error(e)

    def debouncer(self):
        cfg = self.cfg
        last_poll = 0.0
        last_held = 0.0
        while not self.stop.wait(1.0):
            now = time.time()
            if now - last_held > 60:
                last_held = now
                self.refresh_held()
            ready = []
            with self.pending_lock:
                for p, (ts, proc) in list(self.pending.items()):
                    quiet = cfg.debounce_s / 4 if cfg.is_priority(p) else cfg.debounce_s
                    if now - ts >= quiet:
                        ready.append((p, proc))
                        del self.pending[p]
            if ready:
                with self.work_cv:
                    for p, proc in ready:
                        prio = 0 if cfg.is_priority(p) else 1
                        heapq.heappush(self.work, (prio, now, p, proc, "fresh"))
                        self.stats["queued"] += 1
                    self.work_cv.notify_all()
            # Without rename events: poll the category folders, and look
            # again at folders where a download was being written.
            if self.names is None:
                if cfg.all_priority_paths and now - last_poll > 300:
                    last_poll = now
                    threading.Thread(target=self.poll_priority, daemon=True).start()
                for d, until in list(self.recheck.items()):
                    if now > until:
                        del self.recheck[d]
                        continue
                    try:
                        with os.scandir(d) as it:
                            for e in it:
                                if (e.is_file(follow_symlinks=False) and not cfg.is_excluded(e.path)
                                        and now - e.stat(follow_symlinks=False).st_ctime < 60):
                                    self._queue(e.path, "download")
                    except OSError:
                        del self.recheck[d]
            elif cfg.all_priority_paths and now - last_poll > 3600:
                last_poll = now                     # network and FUSE folders give no events at all
                threading.Thread(target=self.poll_priority, daemon=True).start()

    def enqueue_tree(self, top: str, proc: str = "user request", prio: int = 0, limit: int = 200_000):
        """Scan a file or a whole folder now (the app's "Scan a folder", or a
        folder that was just moved into place)."""
        from .sweep import walk
        files = [top] if os.path.isfile(top) else walk(top, self.cfg, same_dev=False)
        now = time.time()
        n = 0
        event = "" if proc == "user request" else "fresh"     # a folder that just arrived is new
        for p in files:
            with self.work_cv:
                heapq.heappush(self.work, (prio, now, p, proc, event))
                self.work_cv.notify()
            n += 1
            if n >= limit:
                log(f"{top}: more than {limit} files, the rest is left to the next check")
                break

    def poll_priority(self):
        if not Clamd(self.cfg.clamd_socket).ping():
            return                      # engine still loading: next poll in 5 min
        idx = Index(INDEX_PATH, self.vault)
        try:
            sw = Sweep(self.cfg, Scanner(self.cfg, idx, log=log), log=log)
            sw.run_paths(list(self.cfg.all_priority_paths))
            if sw.stats["scanned"]:
                log(f"priority poll: {sw.stats}")
        except Exception as e:
            log(f"priority poll failed: {e}")
            self.note_error(e)
        finally:
            idx.close()

    # --------------------------------------------------------------- workers
    def worker(self, n: int):
        idx = Index(INDEX_PATH, self.vault)
        clamd = Clamd(self.cfg.clamd_socket)
        sc = Scanner(self.cfg, idx, clamd, log=log)
        def found(r):
            if r.action == "held":
                self.held.add(r.path)
            self.api.publish({
                "event": "finding", "verdict": r.verdict, "signature": r.signature,
                "action": r.action, "path": r.path, "category": self.cfg.category_of(r.path)})
        sc.on_finding = found
        last_commit = time.time()
        while not self.stop.is_set():
            with self.work_cv:
                while not self.work and not self.stop.is_set():
                    self.work_cv.wait(5)
                    if time.time() - last_commit > 5:
                        idx.commit()
                        last_commit = time.time()
                if self.stop.is_set():
                    break
                prio, ts, path, proc, event = heapq.heappop(self.work)
            if not clamd.ping():
                self._clamd_down(path, prio, proc, event)
                continue
            self.clamd_down_since = 0.0
            try:
                self.current[n] = path
                r = sc.scan(path, process=proc, fresh=event == "fresh", started=event == "started")
                self.current.pop(n, None)
                self.stats["scanned"] += 1
                if r.verdict in ("infected", "suspicious", "warning"):
                    log(f"{r.verdict}: {r.signature} {r.action} {path} (by {proc})")
            except Exception as e:
                self.current.pop(n, None)
                log(f"scan failed {path}: {e}")
                self.note_error(e)
            if time.time() - last_commit > 5:
                idx.commit()
                last_commit = time.time()
        idx.commit()
        idx.close()

    def _clamd_down(self, path, prio, proc, event=""):
        now = time.time()
        if not self.clamd_down_since:
            self.clamd_down_since = now
        elif now - self.clamd_down_since > 300 and self.clamd_down_since > 0:
            notify(self.cfg, t("clamd_down_title"), t("clamd_down_body"), "high")
            self.clamd_down_since = -1.0      # notified; reset when clamd is back
        with self.work_cv:
            heapq.heappush(self.work, (prio, now, path, proc, event))
        self.stop.wait(10)

    # -------------------------------------------------------------- ransom
    def ransom(self):
        idx = Index(INDEX_PATH, self.vault)
        det = RansomDetector(self.cfg, idx, log=log)
        det.on_alarm = lambda body: self.api.publish({"event": "ransom_alarm", "body": body})
        last_commit = time.time()
        while not self.stop.is_set():
            try:
                path, proc, pid, what = self.ransom_q.get(timeout=2)
            except queue.Empty:
                path = None
            if path:
                try:
                    det.feed(path, proc, pid, what)
                except Exception as e:
                    log(f"ransom detector error {path}: {e}")
                    self.note_error(e)
            if time.time() - last_commit > 5:
                idx.commit()
                last_commit = time.time()
        idx.commit()
        idx.close()

    # ------------------------------------------------------------------ run
    def check_anchor(self, idx: Index):
        """A database older than the sealed anchor = someone restored an old copy."""
        try:
            anchor = vault.read_anchor()
        except vault.VaultError as e:
            log(f"anchor unreadable: {e}")
            return
        if not anchor:
            return
        aseq, ahead = anchor
        seq, _ = idx.ledger_head()
        r = idx.db.execute("SELECT chain FROM ledger WHERE seq=?", (aseq,)).fetchone()
        if seq < aseq or (aseq and (not r or r[0] != ahead)):
            msg = f"inventory history ({seq}) does not contain the sealed anchor ({aseq})"
            log("ROLLBACK: " + msg)
            idx.event("tamper_rollback", msg)
            notify(self.cfg, t("tamper_title"), t("tamper_body", what="index.db", why=msg), "urgent")
            # an untrusted inventory is worthless: forget it, everything is rescanned
            idx.db.execute("DELETE FROM files")
            idx.db.execute("DELETE FROM hashes")
            idx.commit()
            return True
        return False

    def anchorer(self):
        idx = Index(INDEX_PATH, self.vault)
        last = None
        while True:
            stopping = self.stop.wait(300)
            head = idx.ledger_head()
            if head != last:
                try:
                    vault.write_anchor(*head)
                    last = head
                except Exception as e:
                    log(f"anchor write failed: {e}")
            if stopping:
                break
        idx.close()

    def open_inventory(self):
        """The inventory, rebuilt first if an earlier run found it damaged or
        it does not open. Returns (index, reason for a full check or None)."""
        why = None
        try:
            with open(index_mod.broken_marker(INDEX_PATH)) as f:
                why = f.read().strip() or "marked as damaged"
        except OSError:
            why = index_mod.looks_sound(INDEX_PATH)
        if why is None:
            return Index(INDEX_PATH, self.vault), None
        log(f"inventory damaged ({why}): starting a new one")
        kept = index_mod.rebuild(INDEX_PATH, self.vault, why)
        idx = Index(INDEX_PATH, self.vault)
        try:
            vault.write_anchor(*idx.ledger_head())     # the new history is the one that counts
        except Exception as e:
            log(f"anchor write failed: {e}")
        log(f"inventory rebuilt, kept {kept}")
        self_alert(self.cfg, t("db_rebuilt_body", why=why[:200], decisions=kept["allow"] + kept["meta"],
                               history=kept["ledger"]), every_s=0)
        return idx, "inventory was rebuilt"

    def run(self, workers: int = 2):
        idx, rebuilt = self.open_inventory()
        catch_up = "inventory was rolled back" if self.check_anchor(idx) else rebuilt
        clean = idx.meta_get("clean_shutdown", True)
        if not clean:
            idx.event("gap", "previous run did not stop cleanly: a sweep will catch up")
            catch_up = catch_up or "previous run did not stop cleanly"
        idx.meta_set("clean_shutdown", False)
        idx.event("daemon_start", f"roots={roots(self.cfg)} priority={self.cfg.all_priority_paths}")
        idx.commit()
        threads = [self._thread(self.reader, "reader"),
                   self._thread(self.debouncer, "debounce"),
                   self._thread(self.ransom, "ransom"),
                   self._thread(self.anchorer, "anchor"),
                   self._thread(self.api.serve, "api", (self.stop,))]
        threads += [self._thread(self.worker, f"scan{i}", (i,)) for i in range(workers)]
        for th in threads:
            th.start()
        # Once per start, beside the work: every page of the inventory is
        # read. Damage left by an earlier version is found here, right after
        # the update, not at the first file that happens to touch it.
        threading.Thread(target=self.deep_check, name="selfcheck", daemon=True).start()
        if catch_up:
            self.start_sweep(catch_up)        # what changed while nobody was watching

        def _stop(*_):
            self.stop.set()
            with self.work_cv:
                self.work_cv.notify_all()
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        last = time.time()
        while not self.stop.wait(1):
            if self.fatal:
                # A part of the service is gone or the inventory is damaged:
                # say so and let systemd start a whole new service.
                self_alert(self.cfg, t("self_restart_body", what=self.fatal[:300]))
                _stop()
                break
            if time.time() - last > 600:
                last = time.time()
                log(f"stats {self.stats} pending={len(self.pending)} queue={len(self.work)}")
        for th in list(self.threads):
            th.join(timeout=15)
        try:
            idx.event("daemon_stop", self.fatal or str(self.stats))
            idx.meta_set("clean_shutdown", self.fatal is None)
            idx.commit()
            vault.write_anchor(*idx.ledger_head())
            idx.close()
        except Exception as e:
            log(f"could not close the inventory: {e}")
            self.note_error(e)
        log("stopped")
        if self.fatal:
            sys.exit(1)


def main():
    if os.geteuid() != 0:
        sys.exit("lguardd must run as root")
    for stream in (sys.stdout, sys.stderr):          # file names need not be valid UTF-8
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    cfg = config_mod.load(sys.argv[1] if len(sys.argv) > 1 else config_mod.CONFIG_PATH)
    set_language(cfg.language)
    try:
        v = vault.Vault(vault.load_master_key())
    except vault.VaultError as e:
        sys.exit(f"lguardd: {e}")
    try:
        Daemon(cfg, v).run()
    except SystemExit:
        raise
    except BaseException as e:
        # Not starting at all is the one failure nobody would notice.
        log(f"lguardd could not run: {e!r}\n{traceback.format_exc()}")
        if index_mod.is_damage(e):
            index_mod.mark_broken(INDEX_PATH, str(e))
        self_alert(cfg, t("self_restart_body", what=f"{type(e).__name__}: {e}"[:300]))
        sys.exit(1)


if __name__ == "__main__":
    main()
