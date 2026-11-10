import json
import os
import socket
import tempfile
import threading
import time
import unittest

import util
from lguard import api as api_mod


class Policy(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()
        self.api = api_mod.Api(self.cfg, self.idx.v, self.idx.path)

    def tearDown(self):
        self.idx.close()

    def test_what_needs_the_administrator(self):
        need = self.api.need
        for m in ("status", "findings", "start_sweep", "resume_sweep", "scan", "trusted"):
            self.assertEqual(need(m, {}), api_mod.VIEW, m)
        for m in ("restore", "delete", "unfreeze", "set_folders", "untrust", "resume_process", "no_such"):
            self.assertEqual(need(m, {}), api_mod.MANAGE, m)

    def test_only_a_short_pause_is_free(self):
        need = self.api.need
        self.assertEqual(need("pause_sweep", {"minutes": 60}), api_mod.VIEW)
        self.assertEqual(need("pause_sweep", {"minutes": 180}), api_mod.VIEW)
        for params in ({}, {"minutes": None}, {"minutes": 181}, {"minutes": -5}, {"minutes": "x"}, {"minutes": 10 ** 9}):
            self.assertEqual(need("pause_sweep", params), api_mod.MANAGE, params)

    def test_no_pause_lasts_longer_than_a_day(self):
        for minutes in (None, 0, 10 ** 9):
            r = self.api.m_pause_sweep(self.idx, 1000, minutes)
            self.assertLessEqual(r["resume_at"], time.time() + 86400 + 5)
        self.assertLessEqual(self.api.m_pause_sweep(self.idx, 1000, 30)["resume_at"], time.time() + 1805)

    def test_a_running_scan_is_not_started_twice(self):
        started = []
        real = api_mod.subprocess.run

        def fake(cmd, **kw):
            if cmd[:2] == ["systemctl", "start"]:
                started.append(cmd[-1])
            class R:
                returncode, stdout, stderr = 0, self.state, ""
            return R()
        api_mod.subprocess.run = fake
        try:
            self.state = "inactive\ninactive\n"
            self.assertNotIn("already", self.api.m_start_sweep(self.idx, 1000, full=False))
            self.state = "activating\ninactive\n"                 # quick check running
            self.assertTrue(self.api.m_start_sweep(self.idx, 1000, full=False)["already"])
            self.assertNotIn("already", self.api.m_start_sweep(self.idx, 1000, full=True))   # full may queue
            self.state = "inactive\nactivating\n"                 # full disk scan running
            self.assertTrue(self.api.m_start_sweep(self.idx, 1000, full=True)["already"])
            self.assertTrue(self.api.m_start_sweep(self.idx, 1000, full=False)["already"])
            self.assertEqual(started, ["lguard-sweep.service", "lguard-fullscan.service"])
        finally:
            api_mod.subprocess.run = real

    def test_password_holds_five_minutes_for_the_same_program_only(self):
        asked = []
        real_auth, real_start = api_mod.authorized, api_mod._start_time
        api_mod.authorized = lambda action, pid, uid, interactive: asked.append((action, pid)) or True
        api_mod._start_time = lambda pid: f"start-of-{pid}"
        try:
            for _ in range(3):
                self.assertTrue(self.api.authorize(api_mod.MANAGE, 500, 1000))
            self.assertEqual(len(asked), 1)                       # asked once, kept for the next ones
            self.assertTrue(self.api.authorize(api_mod.MANAGE, 501, 1000))
            self.assertEqual(len(asked), 2)                       # another program of the same user: asked
            api_mod._start_time = lambda pid: "a-later-process-with-the-same-pid"
            self.api.authorize(api_mod.MANAGE, 500, 1000)
            self.assertEqual(len(asked), 3)                       # pid reused: asked
            self.api.manage_ok = {k: 0 for k in self.api.manage_ok}
            self.api.authorize(api_mod.MANAGE, 500, 1000)
            self.assertEqual(len(asked), 4)                       # time is up: asked
            api_mod.authorized = lambda *a, **k: False
            self.api.manage_ok = {}
            self.assertFalse(self.api.authorize(api_mod.MANAGE, 500, 1000))
            self.assertEqual(self.api.manage_ok, {})              # a refusal is never remembered
        finally:
            api_mod.authorized, api_mod._start_time = real_auth, real_start

    def test_folders_reject_what_would_break_the_config(self):
        for bad in ("relative/path", "/srv/a\rb", "/srv/a\x00b"):
            with self.assertRaises(ValueError):
                self.api.m_set_folders(self.idx, 1000, {"x": [bad]}, [], [], [])
        with self.assertRaises(ValueError):
            self.api.m_set_folders(self.idx, 1000, {"bad[name]": []}, [], [], [])
        with self.assertRaises(ValueError):
            self.api.m_set_folders(self.idx, 1000, {"x": []}, [], [], [], category_modes={"x": "weird"})


class Server(unittest.TestCase):
    """The socket is open to every local account: what an unknown caller gets."""

    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()
        self.sock = os.path.join(util.tmpdir(), "api.sock")
        self._old = api_mod.SOCKET_PATH, api_mod.authorized
        api_mod.SOCKET_PATH = self.sock
        self.allowed = True
        api_mod.authorized = lambda action, pid, uid, interactive: self.allowed and action == api_mod.VIEW
        self.api = api_mod.Api(self.cfg, self.idx.v, self.idx.path)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.api.serve, args=(self.stop,), daemon=True)
        self.thread.start()
        for _ in range(100):
            if os.path.exists(self.sock):
                break
            time.sleep(0.02)

    def tearDown(self):
        self.stop.set()
        self.thread.join(3)
        api_mod.SOCKET_PATH, api_mod.authorized = self._old
        self.idx.close()

    def ask(self, payload: bytes):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(self.sock)
            s.sendall(payload)
            try:
                return s.makefile("rb").readline()
            except OSError:
                return b""

    def test_ping(self):
        self.assertEqual(json.loads(self.ask(b'{"id":1,"method":"ping"}\n'))["result"], "pong")

    def test_manage_methods_are_refused(self):
        r = json.loads(self.ask(b'{"id":1,"method":"unfreeze"}\n'))
        self.assertEqual(r["error"], "not authorized")

    def test_caller_cannot_pass_its_own_identity(self):
        r = json.loads(self.ask(b'{"id":1,"method":"ping","params":{"uid":0,"idx":1}}\n'))
        self.assertEqual(r["result"], "pong")

    def test_unknown_and_odd_method_names(self):
        self.allowed = True
        api_mod.authorized = lambda *a, **k: True
        for name in ("nope", "_send", "status.__class__", ""):
            r = json.loads(self.ask(json.dumps({"id": 1, "method": name}).encode() + b"\n"))
            self.assertIn("unknown method", r["error"], name)

    def test_oversized_request_is_dropped(self):
        self.assertEqual(self.ask(b'{"id":1,"method":"ping","params":{"x":"' + b"A" * 200_000 + b'"}}\n'), b"")
        self.assertEqual(json.loads(self.ask(b'{"id":1,"method":"ping"}\n'))["result"], "pong")   # still alive

    def test_connection_limit_per_user(self):
        if os.geteuid() == 0:
            self.skipTest("root is exempt")
        held = []
        try:
            for _ in range(api_mod.MAX_PER_USER + 6):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect(self.sock)
                held.append(s)
                time.sleep(0.02)
            time.sleep(0.5)
            self.assertLessEqual(sum(self.api.connections.values()), api_mod.MAX_PER_USER)
        finally:
            for s in held:
                s.close()
        time.sleep(0.3)
        self.assertEqual(json.loads(self.ask(b'{"id":1,"method":"ping"}\n'))["result"], "pong")


if __name__ == "__main__":
    unittest.main()
