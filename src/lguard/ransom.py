"""Ransomware detector.

Two signals, both counted over a sliding window:
  1. files in user data whose name promises a format (docx, pdf, jpg ...) but
     whose content is random-looking: encrypted in place;
  2. one process rewriting a large number of *existing* files.
Either one past its threshold raises the alarm: urgent notification and,
if configured, backups/sync are frozen.
"""
from __future__ import annotations

import collections
import fnmatch
import os
import time

from . import filetype
from .config import Config
from .freeze import freeze, is_frozen
from .i18n import t
from .index import Index
from .notify import notify

COOLDOWN_S = 1800


class RansomDetector:
    def __init__(self, cfg: Config, index: Index, log=print):
        self.cfg = cfg
        self.index = index
        self.log = log
        self.suspects: collections.deque = collections.deque()       # (ts, path, proc)
        self.rewrites: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.last_alarm = 0.0
        self.on_alarm = None

    def _ignored(self, proc: str) -> bool:
        return any(fnmatch.fnmatchcase(proc or "", p) for p in self.cfg.ransom_ignore_exe)

    def feed(self, path: str, proc: str):
        cfg = self.cfg
        if not cfg.is_data(path) or cfg.is_excluded(path):
            return
        now = time.time()
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

        # An existing file (one we had indexed) being rewritten.
        if proc and not self._ignored(proc) and self.index.get(path) is not None:
            q = self.rewrites[proc]
            q.append(now)
            while q and q[0] < now - cfg.ransom_rewrite_window_s:
                q.popleft()
            if len(q) >= cfg.ransom_rewrite_files:
                self._alarm(t("rewrite_body", proc=proc, n=len(q), mins=cfg.ransom_rewrite_window_s // 60,
                              frozen="{frozen}"), proc)
                q.clear()

    def _alarm(self, body: str, proc: str):
        now = time.time()
        if now - self.last_alarm < COOLDOWN_S:
            return
        self.last_alarm = now
        self.index.event("ransom_alarm", body)
        frozen = is_frozen(self.index) or freeze(self.cfg, self.index, f"ransomware alarm ({proc})", self.log)
        body = body.replace("{frozen}", t("frozen") if frozen else t("not_frozen"))
        self.index.commit()
        notify(self.cfg, t("ransom_title"), body, "urgent")
        if self.on_alarm:
            self.on_alarm(body)
        self.suspects.clear()
