"""Ransomware detector.

Three signals, each counted over a sliding window:
  1. files in user data whose name promises a format (docx, pdf, jpg ...) but
     whose content is random-looking: encrypted in place (also when only the
     beginning was encrypted, or an extra extension was appended);
  2. one program rewriting a large number of *existing* files with
     random-looking content;
  3. one program deleting (or moving away) known documents while it writes
     random-looking files: encrypt to a new name, delete the original.
Any one past its threshold raises the alarm: urgent notification, backups
and sync are frozen (if configured) and, by default, a program that does not
belong to the operating system is suspended until the user decides.
"""
from __future__ import annotations

import collections
import fnmatch
import os
import signal
import time

from . import filetype
from .config import SYSTEM_DIRS, Config
from .freeze import freeze, is_frozen
from .i18n import t
from .index import Index
from .notify import notify

COOLDOWN_S = 1800


def _start_time(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def is_system_program(proc: str) -> bool:
    """Installed by the operating system (as opposed to started out of a
    home, download or temporary folder)."""
    return bool(proc) and proc.startswith(SYSTEM_DIRS) and not proc.endswith(" (deleted)")


def resume_stopped(index: Index) -> list[str]:
    """Let the programs suspended by an alarm continue."""
    done = []
    for p in index.meta_get("stopped") or []:
        if _start_time(p["pid"]) == p.get("start"):          # still the same process
            try:
                os.kill(p["pid"], signal.SIGCONT)
                done.append(f"{p['proc']} (pid {p['pid']})")
            except OSError:
                pass
    index.meta_set("stopped", [])
    if done:
        index.event("process_resumed", "; ".join(done))
    index.commit()
    return done


class RansomDetector:
    def __init__(self, cfg: Config, index: Index, log=print):
        self.cfg = cfg
        self.index = index
        self.log = log
        self.suspects: collections.deque = collections.deque()       # (ts, path, proc)
        self.rewrites: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.created: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.gone: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.pids: dict[str, set] = collections.defaultdict(set)
        self.last_alarm = 0.0
        self.last_tidy = time.time()
        self.on_alarm = None

    def _ignored(self, proc: str) -> bool:
        return is_system_program(proc) and any(fnmatch.fnmatchcase(proc, p) for p in self.cfg.ransom_ignore_exe)

    def _trim(self, q: collections.deque, now: float, window: float) -> int:
        while q and q[0] < now - window:
            q.popleft()
        return len(q)

    def _tidy(self, now: float):
        """Forget programs that have been quiet for a window."""
        self.last_tidy = now
        w = self.cfg.ransom_rewrite_window_s
        for table in (self.rewrites, self.created, self.gone):
            for proc in [p for p, q in table.items() if not self._trim(q, now, w)]:
                del table[proc]
        live = set(self.rewrites) | set(self.created) | set(self.gone) | {p for _, _, p in self.suspects}
        for proc in [p for p in self.pids if p not in live]:
            del self.pids[proc]

    # ------------------------------------------------------------------ feed
    def feed(self, path: str, proc: str, pid: int = 0, what: str = "write"):
        cfg = self.cfg
        if not cfg.is_data(path) or cfg.is_excluded(path) or cfg.is_soft_excluded(path):
            return
        now = time.time()
        if now - self.last_tidy > 300:
            self._tidy(now)
        if pid:
            self.pids[proc].add(pid)
        if what != "write":
            self._gone(path, proc, now)
            return
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
        except OSError:
            return
        try:
            head = os.pread(fd, filetype.HEAD, 0)
        finally:
            os.close(fd)

        if filetype.looks_encrypted(path, head):
            self.suspects.append((now, path, proc))
            self.index.event("ransom_suspect", f"{proc}: {path}")
        while self.suspects and self.suspects[0][0] < now - cfg.ransom_window_s:
            self.suspects.popleft()
        if len(self.suspects) >= cfg.ransom_suspect_files:
            procs = collections.Counter(p for _, _, p in self.suspects).most_common(1)[0][0]
            self._alarm(t("ransom_body", n=len(self.suspects), mins=cfg.ransom_window_s // 60,
                          path=self.suspects[-1][1], proc=procs, frozen="{frozen}"), procs)
            return

        # Random-looking content from one program. Plain rewrites do not
        # count: unpacking archives, git checkouts, builds and package
        # installs rewrite thousands of files with ordinary content.
        if not proc or self._ignored(proc) or not filetype.looks_random(head):
            return
        w = cfg.ransom_rewrite_window_s
        if self.index.get(path) is not None:            # an existing file, rewritten
            q = self.rewrites[proc]
            q.append(now)
            if self._trim(q, now, w) >= cfg.ransom_rewrite_files:
                self._alarm(t("rewrite_body", proc=proc, n=len(q), mins=w // 60, frozen="{frozen}"), proc)
                q.clear()
                return
        else:                                           # a new file
            self.created[proc].append(now)
        self._combo(proc, now)

    def _gone(self, path: str, proc: str, now: float):
        """A name disappeared (deleted or moved away)."""
        if not proc or self._ignored(proc) or not filetype.promises_format(path):
            return
        if self.index.get(path) is None:                 # not a file we knew
            return
        self.gone[proc].append(now)
        self._combo(proc, now)

    def _combo(self, proc: str, now: float):
        cfg = self.cfg
        w = cfg.ransom_rewrite_window_s
        n_gone = self._trim(self.gone[proc], now, w) if proc in self.gone else 0
        n_new = ((self._trim(self.created[proc], now, w) if proc in self.created else 0)
                 + (self._trim(self.rewrites[proc], now, w) if proc in self.rewrites else 0))
        if n_gone >= cfg.ransom_combo_files and n_new >= cfg.ransom_combo_files:
            self._alarm(t("combo_body", proc=proc, gone=n_gone, new=n_new, mins=w // 60, frozen="{frozen}"), proc)
            self.gone[proc].clear()
            self.created[proc].clear()

    # ----------------------------------------------------------------- alarm
    def _stop(self, proc: str) -> list[int]:
        """Suspend the program (reversible). Never init, never ourselves."""
        mode = self.cfg.ransom_stop_process
        if mode == "never" or (mode != "always" and is_system_program(proc)):
            return []
        stopped = self.index.meta_get("stopped") or []
        done = []
        for pid in sorted(self.pids.get(proc, ())):
            if pid <= 1 or pid == os.getpid() or pid == os.getppid():
                continue
            try:
                if os.readlink(f"/proc/{pid}/exe") != proc:
                    continue                             # the pid belongs to something else now
                start = _start_time(pid)
                os.kill(pid, signal.SIGSTOP)
            except OSError:
                continue
            done.append(pid)
            stopped.append({"pid": pid, "proc": proc, "start": start, "ts": time.time()})
        if done:
            self.index.meta_set("stopped", stopped)
            self.index.event("process_stopped", f"{proc}: pid {', '.join(map(str, done))}")
        return done

    def _alarm(self, body: str, proc: str):
        now = time.time()
        frozen = is_frozen(self.index)
        # One alarm per attack, not one per file - but if the user has
        # unfrozen and the attack goes on, it counts as a new one.
        if now - self.last_alarm < COOLDOWN_S and (frozen or not self.cfg.freeze_commands):
            return
        self.last_alarm = now
        stopped = self._stop(proc)
        frozen = frozen or freeze(self.cfg, self.index, f"ransomware alarm ({proc})", self.log)
        body = body.replace("{frozen}", t("frozen") if frozen else t("not_frozen"))
        if stopped:
            body += "\n" + t("stopped", pids=", ".join(map(str, stopped)))
        self.index.event("ransom_alarm", body)
        self.index.commit()
        notify(self.cfg, t("ransom_title"), body, "urgent", covered=bool(self.on_alarm))
        if self.on_alarm:
            self.on_alarm(body)
        self.suspects.clear()
