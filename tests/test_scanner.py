import os
import time
import unittest

import util
from lguard import quarantine
from lguard.scanner import Scanner
from lguard.sweep import Sweep


class Scanning(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()
        self.clamd = util.FakeClamd()
        self.sc = Scanner(self.cfg, self.idx, self.clamd, log=lambda m: None)
        self.home = os.path.join(self.top, "home")

    def tearDown(self):
        self.idx.close()

    def test_unchanged_file_is_answered_from_the_inventory(self):
        p = util.write(os.path.join(self.home, "a.txt"))
        self.assertFalse(self.sc.scan(p).cached)
        r = self.sc.scan(p)
        self.assertTrue(r.cached)
        self.assertEqual(self.clamd.scans, 1)
        util.write(p, b"changed\n")
        self.assertFalse(self.sc.scan(p).cached)

    def test_threat_is_quarantined_and_logged(self):
        p = util.write(os.path.join(self.home, "eicar.com"), util.EICAR)
        r = self.sc.scan(p)
        self.assertEqual((r.verdict, r.action), ("infected", "quarantined"))
        self.assertFalse(os.path.exists(p))
        self.assertEqual(len(quarantine.entries(self.cfg)), 1)
        self.assertEqual(self.idx.findings()[0]["signature"], "Eicar-Test-Signature")

    def test_same_content_elsewhere_is_not_scanned_twice(self):
        a = util.write(os.path.join(self.home, "a.jpg"), b"\xff\xd8\xff" + b"photo" * 100)
        b = util.write(os.path.join(self.home, "copy", "a.jpg"), b"\xff\xd8\xff" + b"photo" * 100)
        self.sc.scan(a)
        self.assertTrue(self.sc.scan(b).cached)
        self.assertEqual(self.clamd.scans, 1)

    def test_cache_data_is_skipped_but_a_program_in_a_cache_is_not(self):
        data = util.write(os.path.join(self.home, "u", ".cache", "thumb.bin"), util.EICAR)
        prog = util.write(os.path.join(self.home, "u", ".cache", "updater"), b"\x7fELF" + util.EICAR)
        self.assertEqual(self.sc.scan(data).verdict, "skipped")
        self.assertEqual(self.sc.scan(prog).verdict, "infected")

    def test_engine_limit_is_never_recorded_as_clean(self):
        p = util.write(os.path.join(self.home, "huge.zip"), b"TOOBIG" + b"x" * 100)
        r = self.sc.scan(p)
        self.assertEqual(r.verdict, "partial")
        self.assertEqual(self.idx.get(p).verdict, "partial")
        self.assertIsNone(r.action)

    def test_big_non_media_file_is_partial_big_video_is_clean(self):
        self.cfg.full_scan_max = 1000
        self.cfg.media_partial_min = 1000
        blob = util.write(os.path.join(self.home, "installer.run"), b"\x7fELF" + b"x" * 5000)
        film = util.write(os.path.join(self.home, "film.mkv"), b"\x1a\x45\xdf\xa3" + b"x" * 5000)
        self.assertEqual(self.sc.scan(blob).verdict, "partial")
        self.assertEqual(self.sc.scan(film).verdict, "clean")

    def test_category_modes(self):
        dl, lib = os.path.join(self.top, "dl"), os.path.join(self.top, "plex")
        self.cfg.categories = {"downloads": [dl], "plex": [lib]}
        self.assertEqual(self.sc.scan(util.write(os.path.join(dl, "setup.exe"), b"MZ" + b"1" * 50)).verdict, "clean")
        self.assertEqual(self.sc.scan(util.write(os.path.join(dl, "Film.mp4.exe"), b"MZ" + b"2" * 50)).action, "quarantined")
        self.assertEqual(self.sc.scan(util.write(os.path.join(lib, "codec.exe"), b"MZ" + b"3" * 50)).action, "quarantined")
        r = self.sc.scan(util.write(os.path.join(lib, "disc.iso"), b"4" * 50))
        self.assertEqual((r.verdict, r.action), ("warning", "reported"))
        self.assertTrue(os.path.exists(os.path.join(lib, "disc.iso")))

    def test_new_signatures_reach_new_risky_files_only(self):
        fresh = util.write(os.path.join(self.home, "tool.sh"), b"#!/bin/sh\necho 1\n")
        old = util.write(os.path.join(self.home, "old.sh"), b"#!/bin/sh\necho 2\n")
        photo = util.write(os.path.join(self.home, "p.jpg"), b"\xff\xd8\xff" + b"3" * 50)
        for p in (fresh, old, photo):
            self.sc.scan(p)
        row = self.idx.get(old)
        row.first_seen = time.time() - 90 * 86400
        self.idx.put(row)
        self.clamd.dbver += 1
        self.sc.invalidate_db_version()
        self.assertFalse(self.sc.scan(fresh).cached)      # new and risky: checked again
        self.assertTrue(self.sc.scan(old).cached)         # old: left to the full disk scan
        self.assertTrue(self.sc.scan(photo).cached)

    def test_full_disk_scan_runs_the_engine_again(self):
        p = util.write(os.path.join(self.home, "p.jpg"), b"\xff\xd8\xff" + b"photo" * 100)
        self.sc.scan(p)
        self.assertEqual(self.clamd.scans, 1)
        sw = Sweep(self.cfg, self.sc, log=lambda m: None)
        sw.maintenance(verify_budget=1 << 40)             # same signatures: content already vouched for
        self.assertEqual(self.clamd.scans, 1)
        self.clamd.dbver += 1
        self.sc.invalidate_db_version()
        sw.maintenance(verify_budget=1 << 40)             # new signatures: every content checked again
        self.assertEqual(self.clamd.scans, 2)
        self.assertEqual(self.idx.get(p).db_version, self.clamd.dbver)

    def test_full_disk_scan_finds_what_new_signatures_know(self):
        p = util.write(os.path.join(self.home, "doc.jpg"), b"\xff\xd8\xff" + util.EICAR)
        real, self.clamd._judge = self.clamd._judge, lambda data: util.ClamResult(False, None, "")
        self.assertEqual(self.sc.scan(p).verdict, "clean")        # not known yet
        self.clamd._judge = real
        self.clamd.dbver += 1
        self.sc.invalidate_db_version()
        self.assertTrue(self.sc.scan(p).cached)                   # a photo is not re-checked at once...
        Sweep(self.cfg, self.sc, log=lambda m: None).maintenance(verify_budget=1 << 40)
        self.assertFalse(os.path.exists(p))                       # ...but the full disk scan gets it

    def test_content_changed_behind_the_inventory_is_tampering(self):
        p = util.write(os.path.join(self.home, "a.txt"), b"one two three\n")
        self.sc.scan(p)
        row = self.idx.get(p)
        row.digest = "0" * 64
        self.idx.put(row)
        sw = Sweep(self.cfg, self.sc, log=lambda m: None)
        sw.maintenance(verify_budget=1 << 40)
        self.assertEqual(sw.verified[2], 1)
        self.assertTrue(any(e["event"] == "tamper_content" for e in self.idx.events()))


if __name__ == "__main__":
    unittest.main()
