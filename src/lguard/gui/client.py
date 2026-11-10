"""Talking to lguardd from the app: requests in worker threads, the event
stream in its own thread, results delivered to the UI thread as Qt signals."""
from __future__ import annotations

import itertools
import json
import os
import socket
import threading

from PySide6.QtCore import QObject, Signal

SOCKET_PATH = os.environ.get("LGUARD_API_SOCKET", "/run/lguard/api.sock")


class ApiError(Exception):
    pass


def call(method: str, timeout: float = 30.0, **params):
    """Blocking request (use from a worker thread)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCKET_PATH)
    except OSError as e:
        s.close()
        raise ApiError(f"Lguard service is not reachable ({e})") from e
    with s:
        f = s.makefile("rwb", buffering=0)
        f.write(json.dumps({"id": 1, "method": method, "params": params}).encode() + b"\n")
        line = f.readline()
    if not line:
        raise ApiError("no answer from the Lguard service")
    reply = json.loads(line)
    if "error" in reply:
        raise ApiError(reply["error"])
    return reply["result"]


class Client(QObject):
    """result(tag, data) / failed(tag, message) / event(dict) / online(bool)"""
    result = Signal(str, object)
    failed = Signal(str, str)
    event = Signal(dict)
    online = Signal(bool)

    def __init__(self, demo=None):
        super().__init__()
        self.demo = demo                 # lguard.gui.demo.Demo for screenshots/dev
        self._stop = threading.Event()
        self._seq = itertools.count()

    def request(self, tag: str, method: str, timeout: float = 30.0, **params):
        def run():
            try:
                data = self.demo.call(method, **params) if self.demo else call(method, timeout, **params)
                self.result.emit(tag, data)
            except Exception as e:
                self.failed.emit(tag, str(e))
        threading.Thread(target=run, daemon=True, name=f"api-{tag}").start()

    def start_events(self):
        if self.demo:
            self.online.emit(True)
            return
        threading.Thread(target=self._events, daemon=True, name="api-events").start()

    def stop(self):
        self._stop.set()

    def _events(self):
        while not self._stop.is_set():
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(40)
                s.connect(SOCKET_PATH)
                f = s.makefile("rwb", buffering=0)
                f.write(b'{"id":1,"method":"subscribe"}\n')
                self.online.emit(True)
                for line in f:
                    if self._stop.is_set():
                        break
                    ev = json.loads(line)
                    if ev.get("event") not in ("heartbeat", "subscribed"):
                        self.event.emit(ev)
                s.close()
            except (OSError, ValueError):
                pass
            self.online.emit(False)
            self._stop.wait(5)
