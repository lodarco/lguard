"""Lguard looking after itself: its own inventory must survive, a damaged
one is replaced without losing the user's decisions, and odd files (holes,
names that are not text) must not stop the service."""
import os
import select
import sqlite3
import subprocess
import sys
import threading
import time
import unittest

import util
from util import FakeClamd, sandbox, tmpdir, write

from lguard import config, daemon, index as index_mod, notify, scanner as scanner_mod
from lguard.fanotify import Fanotify
from lguard.index import FileRow, Index
from lguard.scanner import Scanner, _digest
from lguard.sweep import Sweep

OTHER = ("import sqlite3, sys; c = sqlite3.connect(sys.argv[1], isolation_level=None); "
         "c.execute('INSERT INTO t VALUES (2)'); c.close()")


class OwnInventory(unittest.TestCase):
    """The fault that damaged the inventory: an event on its files arrives as
    a descriptor, closing it drops SQLite's locks, and the next process that
    closes the inventory deletes its log under the service."""

    def _session(self, protect: bool):
        d = tmpdir()
        p = os.path.join(d, "index.db")
        files = (p, p + "-wal", p + "-shm")
        a = sqlite3.connect(p, isolation_level=None)
        a.execute("PRAGMA journal_mode=WAL")
        a.execute("CREATE TABLE t(x)")
        a.execute("INSERT INTO t VALUES (1)")
        try:
            fan = Fanotify()
        except OSError as e:
            a.close()
            self.skipTest(f"no fanotify here ({e})")
        if protect:
            fan.protect(files)
        fan.mark(d)
        stop = threading.Event()
        seen = []

        def reader():
            poll = select.poll()
            poll.register(fan.fd, select.POLLIN)
            while not stop.is_set():
                if poll.poll(100):
                    seen.extend(path for path, *_rest in fan.read() if path and path.startswith(d))

        th = threading.Thread(target=reader, daemon=True)
        th.start()
        try:
            for _ in range(2):                       # two other processes come and go
                subprocess.run([sys.executable, "-c", OTHER, p], check=True)
                time.sleep(0.7)
        finally:
            stop.set()
            th.join(5)
        left = [os.path.exists(f) for f in files]
        rows = a.execute("SELECT count(*) FROM t").fetchone()[0]
        kept = len(fan.kept)
        a.close()
        for fd in fan.kept:
            os.close(fd)
        fan.close()
        return left, rows, seen, kept

    @unittest.skipUnless(os.geteuid() == 0, "needs root (fanotify)")
    def test_without_protection_the_log_is_deleted_under_the_open_inventory(self):
        left, _rows, seen, _kept = self._session(protect=False)
        self.assertTrue(any(s.endswith("index.db-wal") or s.endswith("index.db-shm") or s.endswith("index.db")
                            for s in seen), "the events on the inventory files should have arrived")
        self.assertEqual(left, [True, False, False])

    @unittest.skipUnless(os.geteuid() == 0, "needs root (fanotify)")
    def test_protected_inventory_keeps_its_log_and_every_row(self):
        left, rows, seen, kept = self._session(protect=True)
        self.assertEqual(left, [True, True, True])
        self.assertEqual(rows, 3)
        self.assertEqual([s for s in seen if "index.db" in s], [])     # the kernel filtered them
        self.assertEqual(kept, 0)

    def test_an_event_that_arrives_anyway_is_recognised(self):
        fan = Fanotify.__new__(Fanotify)
        fan._protected_paths, fan._protected_inodes = {"/x/index.db"}, set()
        d = tmpdir()
        f = write(os.path.join(d, "index.db-wal"))
        fan._protected_inodes.add((os.stat(f).st_dev, os.stat(f).st_ino))
        self.assertTrue(fan.is_protected("/x/index.db", None))
        self.assertTrue(fan.is_protected("/somewhere/else", os.stat(f)))       # same file under another name
        self.assertFalse(fan.is_protected("/x/other", os.stat(write(os.path.join(d, "other")))))

    def test_own_state_is_excluded_whatever_the_settings_say(self):
        cfg = config.Config()
        cfg.excludes, cfg.extra_excludes = [], []
        self.assertTrue(cfg.is_excluded(os.path.join(config.STATE_DIR, "index.db-shm")))


class Rebuild(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = sandbox()
        self.path = os.path.join(self.top, "index.db")
        self.vault = self.idx.v

    def _fill(self, files=0):
        idx = self.idx
        idx.allow("a" * 64, "Test.Threat", "mine")
        idx.hold("/home/alex/old.exe", "b" * 64, "Test.Old")
        idx.condemn("c" * 64)
        idx.meta_set("frozen", "yes")
        idx.meta_set("sweep_progress", {"running": True})
        idx.event("something", "happened")
        for i in range(files):
            idx.put(FileRow(f"/srv/media/file{i}", 1, i, 10, 1, 1, "d" * 64, "text", 0, "clean", None, 1, 1.0))
        idx.commit()
        head = idx.ledger_head()
        idx.close()
        return head

    def test_decisions_and_history_survive_the_file_list_does_not(self):
        head = self._fill(files=50)
        self.assertIsNone(index_mod.looks_sound(self.path, deep=True))
        kept = index_mod.rebuild(self.path, self.vault, "test")
        new = Index(self.path, self.vault)
        self.assertEqual(kept["allow"], 1)
        self.assertTrue(new.is_allowed("a" * 64))
        self.assertIn("/home/alex/old.exe", new.held())
        self.assertTrue(new.is_condemned("c" * 64))
        self.assertEqual(new.meta_get("frozen"), "yes")
        self.assertIsNone(new.meta_get("sweep_progress"))          # state of a check that no longer applies
        self.assertEqual(new.file_count(), 0)
        self.assertEqual(new.verify_ledger(), [])
        self.assertEqual(new.ledger_head()[0], head[0] + 1)         # the old history plus "inventory_rebuilt"
        self.assertEqual(new.events(1)[0]["event"], "inventory_rebuilt")
        self.assertTrue(os.path.exists(self.path + ".damaged"))
        new.close()

    def test_a_file_that_is_no_inventory_at_all_is_replaced(self):
        self.idx.close()
        for suffix in ("-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                os.unlink(self.path + suffix)
        with open(self.path, "wb") as f:
            f.write(os.urandom(64 * 1024))
        self.assertIsNotNone(index_mod.looks_sound(self.path))
        kept = index_mod.rebuild(self.path, self.vault, "garbage")
        self.assertEqual(kept, {"allow": 0, "daily": 0, "ledger": 0, "meta": 0})
        new = Index(self.path, self.vault)
        new.allow("e" * 64, None)
        self.assertTrue(new.is_allowed("e" * 64))
        new.close()

    def test_damage_inside_the_file_is_found_and_survived(self):
        self._fill(files=4000)
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.close()
        size = os.path.getsize(self.path)
        with open(self.path, "r+b") as f:                # a stretch in the middle is overwritten
            f.seek(size // 2)
            f.write(os.urandom(size // 4))
        self.assertIsNotNone(index_mod.looks_sound(self.path, deep=True))
        index_mod.rebuild(self.path, self.vault, "middle overwritten")
        new = Index(self.path, self.vault)
        self.assertEqual(new.file_count(), 0)
        self.assertEqual(new.verify_ledger(), [])
        new.put(FileRow("/srv/media/again", 1, 1, 10, 1, 1, None, "text", 0, "clean", None, 1, 1.0))
        self.assertIsNotNone(new.get("/srv/media/again"))
        new.close()

    def test_which_errors_mean_damage(self):
        try:
            with open(self.path + "x", "wb") as f:
                f.write(b"not a database, just text " * 400)
            sqlite3.connect(self.path + "x").execute("SELECT * FROM t")
        except sqlite3.DatabaseError as e:
            self.assertTrue(index_mod.is_damage(e))
        try:
            self.idx.db.execute("SELECT * FROM no_such_table")
        except sqlite3.DatabaseError as e:
            self.assertFalse(index_mod.is_damage(e))
        self.assertFalse(index_mod.is_damage(ValueError("x")))
        self.idx.close()

    def test_the_marker_makes_the_service_rebuild_at_start(self):
        self._fill()
        index_mod.mark_broken(self.path, "seen at run time")
        d = daemon.Daemon.__new__(daemon.Daemon)
        d.cfg, d.vault = self.cfg, self.vault
        sent = []
        old = (daemon.INDEX_PATH, daemon.self_alert, daemon.vault.write_anchor)
        daemon.INDEX_PATH = self.path
        daemon.self_alert = lambda cfg, body, every_s=1800: sent.append(body)
        daemon.vault.write_anchor = lambda *a: None
        try:
            idx, why = d.open_inventory()
        finally:
            daemon.INDEX_PATH, daemon.self_alert, daemon.vault.write_anchor = old
        self.assertEqual(why, "inventory was rebuilt")
        self.assertEqual(len(sent), 1)
        self.assertTrue(idx.is_allowed("a" * 64))
        self.assertFalse(os.path.exists(index_mod.broken_marker(self.path)))
        idx.close()


class OddFiles(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = sandbox()
        self.clamd = FakeClamd()
        self.sc = Scanner(self.cfg, self.idx, self.clamd, log=lambda m: None)

    def tearDown(self):
        self.idx.close()

    def test_a_file_made_of_holes_is_not_read_through_and_never_clean(self):
        old = scanner_mod.SPARSE_MIN
        scanner_mod.SPARSE_MIN = 1 << 20
        try:
            p = os.path.join(self.top, "home", "huge.img")
            with open(p, "wb") as f:
                f.truncate(1 << 40)                  # a terabyte that takes no room
            t0 = time.time()
            r = self.sc.scan(p)
            self.assertLess(time.time() - t0, 5)
            self.assertEqual((r.verdict, r.signature), ("partial", "Lguard.Limits.Sparse"))
            self.assertIsNone(self.idx.get(p).digest)
            # the full disk scan leaves it alone as well
            Sweep(self.cfg, self.sc, log=lambda m: None).maintenance(verify_budget=1 << 62)
        finally:
            scanner_mod.SPARSE_MIN = old

    def test_a_threat_at_the_start_of_such_a_file_is_still_found(self):
        old = scanner_mod.SPARSE_MIN
        scanner_mod.SPARSE_MIN = 1 << 20
        try:
            p = os.path.join(self.top, "home", "huge.bin")
            with open(p, "wb") as f:
                f.write(util.THREAT)
                f.truncate(1 << 40)
            self.assertEqual(self.sc.scan(p).verdict, "infected")
        finally:
            scanner_mod.SPARSE_MIN = old

    def test_hashing_gives_up_when_it_takes_too_long(self):
        p = os.path.join(self.top, "slow.bin")
        with open(p, "wb") as f:
            f.truncate(300 << 20)
        fd = os.open(p, os.O_RDONLY)
        try:
            self.assertIsNone(_digest(fd, 300 << 20, budget_s=-1))
            self.assertEqual(len(_digest(fd, 300 << 20)), 64)
        finally:
            os.close(fd)

    def test_a_name_that_is_not_text_reaches_log_and_alert(self):
        name = os.fsdecode(b"/home/alex/bad-\xff\xfe-name.exe")
        self.assertEqual(notify.safe(name), "/home/alex/bad-\\xff\\xfe-name.exe")
        notify.safe(name).encode("utf-8")                       # can be written anywhere
        self.assertEqual(notify.safe("lone \ud800 half"), "lone \\ud800 half")
        written = []
        real = notify.syslog.syslog
        notify.syslog.syslog = lambda prio, text: written.append(text)   # not into this machine's journal
        try:
            notify.notify(self.cfg, "Test", name, "high")       # must not raise
        finally:
            notify.syslog.syslog = real
        self.assertEqual(written, ["Test: /home/alex/bad-\\xff\\xfe-name.exe"])
        daemon.log(f"test: {name}")

    def test_a_threat_under_such_a_name_is_quarantined_and_told(self):
        p = os.fsdecode(os.path.join(os.fsencode(self.top), b"home", b"x-\xff.exe"))
        with open(p, "wb") as f:
            f.write(util.THREAT)
        told = []
        self.sc.on_finding = lambda r: told.append(r.action)
        r = self.sc.scan(p, fresh=True)
        self.assertEqual((r.verdict, r.action), ("infected", "quarantined"))
        self.assertEqual(told, ["quarantined"])

    def test_one_file_that_cannot_be_checked_does_not_end_the_whole_check(self):
        folder = os.path.join(self.top, "home", "docs")
        for n in ("a.txt", "b.txt", "c.txt"):
            write(os.path.join(folder, n), n.encode())
        real = self.sc.scan

        def scan(path, **kw):
            if path.endswith("b.txt"):
                raise UnicodeEncodeError("utf-8", "x", 0, 1, "made up")
            return real(path, **kw)
        self.sc.scan = scan
        sw = Sweep(self.cfg, self.sc, log=lambda m: None)
        sw.run_paths([folder])
        self.assertEqual((sw.stats["seen"], sw.stats["errors"]), (3, 1))

    def test_a_damaged_inventory_does_end_it(self):
        def scan(path, **kw):
            raise sqlite3.DatabaseError("database disk image is malformed")
        self.sc.scan = scan
        write(os.path.join(self.top, "home", "a.txt"))
        with self.assertRaises(sqlite3.DatabaseError):
            Sweep(self.cfg, self.sc, log=lambda m: None).run_paths([os.path.join(self.top, "home")])

    def test_a_process_can_have_any_name(self):
        self.assertEqual(daemon._proc_name(2 ** 22 + 12345), f"pid {2 ** 22 + 12345}")
        self.assertIsInstance(daemon._proc_name(os.getpid()), str)


class Supervision(unittest.TestCase):
    def test_a_thread_that_ends_makes_the_service_restart_itself(self):
        d = daemon.Daemon.__new__(daemon.Daemon)
        d.stop, d.threads, d.fatal = threading.Event(), [], None
        ok = d._thread(lambda: d.stop.wait(30), "steady")
        bad = d._thread(lambda: 1 / 0, "reader")
        ok.start()
        bad.start()
        bad.join(5)
        self.assertEqual(d.fatal, "reader stopped")
        self.assertFalse(d.healthy())
        d.stop.set()
        ok.join(5)

    def test_damage_met_at_run_time_leaves_the_marker_and_asks_for_a_restart(self):
        top = tmpdir()
        old = daemon.INDEX_PATH
        daemon.INDEX_PATH = os.path.join(top, "index.db")
        try:
            d = daemon.Daemon.__new__(daemon.Daemon)
            d.fatal = None
            d.note_error(ValueError("something else"))
            self.assertIsNone(d.fatal)
            d.note_error(sqlite3.DatabaseError("database disk image is malformed"))
            self.assertIn("inventory damaged", d.fatal)
            self.assertTrue(os.path.exists(index_mod.broken_marker(daemon.INDEX_PATH)))
        finally:
            daemon.INDEX_PATH = old


class DeepCheck(unittest.TestCase):
    def test_damage_left_by_an_earlier_version_is_found_after_start(self):
        top, cfg, idx = sandbox()
        path = os.path.join(top, "index.db")
        for i in range(4000):
            idx.put(FileRow(f"/srv/media/file{i}", 1, i, 10, 1, 1, "d" * 64, "text", 0, "clean", None, 1, 1.0))
        idx.commit()
        idx.close()
        db = sqlite3.connect(path)
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.close()
        old = daemon.INDEX_PATH
        daemon.INDEX_PATH = path
        try:
            d = daemon.Daemon.__new__(daemon.Daemon)
            d.fatal = None
            d.deep_check()
            self.assertIsNone(d.fatal)                       # a sound inventory is left alone
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                f.seek(size // 2)
                f.write(os.urandom(size // 4))
            d.deep_check()
            self.assertIn("inventory damaged", d.fatal)
            self.assertTrue(os.path.exists(index_mod.broken_marker(path)))
        finally:
            daemon.INDEX_PATH = old


if __name__ == "__main__":
    unittest.main()
