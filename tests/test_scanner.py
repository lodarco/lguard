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
        p = util.write(os.path.join(self.home, "threat.bin"), util.THREAT)
        r = self.sc.scan(p)
        self.assertEqual((r.verdict, r.action), ("infected", "quarantined"))
        self.assertFalse(os.path.exists(p))
        self.assertEqual(len(quarantine.entries(self.cfg)), 1)
        self.assertEqual(self.idx.findings()[0]["signature"], "Test.Threat")

    def test_same_content_elsewhere_is_not_scanned_twice(self):
        a = util.write(os.path.join(self.home, "a.jpg"), b"\xff\xd8\xff" + b"photo" * 100)
        b = util.write(os.path.join(self.home, "copy", "a.jpg"), b"\xff\xd8\xff" + b"photo" * 100)
        self.sc.scan(a)
        self.assertTrue(self.sc.scan(b).cached)
        self.assertEqual(self.clamd.scans, 1)

    def test_cache_data_is_skipped_but_a_program_in_a_cache_is_not(self):
        data = util.write(os.path.join(self.home, "u", ".cache", "thumb.bin"), util.THREAT)
        prog = util.write(os.path.join(self.home, "u", ".cache", "updater"), b"\x7fELF" + util.THREAT)
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
        # a film that holds together as one: header, then the Segment
        mkv = b"\x1a\x45\xdf\xa3" + b"\x84" + b"\x42\x82\x81w" + b"\x18\x53\x80\x67" + b"\x01" + b"\xff" * 7
        film = util.write(os.path.join(self.home, "film.mkv"), mkv + b"x" * 5000)
        self.assertEqual(self.sc.scan(blob).verdict, "partial")
        self.assertEqual(self.sc.scan(film).verdict, "clean")

    def test_a_big_file_that_merely_starts_like_a_film_is_not_called_clean(self):
        self.cfg.full_scan_max = 1000
        self.cfg.media_partial_min = 1000
        for name, start in (("a.mkv", b"\x1a\x45\xdf\xa3"), ("b.mp4", b"\x00\x00\x00\x18ftypisom"), ("c.mp3", b"\xff\xfb"),
                            ("d.avi", b"RIFF\x10\x00\x00\x00AVI ")):
            fake = util.write(os.path.join(self.home, name), start + b"x" * 5000)
            self.assertEqual(self.sc.scan(fake).verdict, "partial", name)

    def test_what_a_real_film_file_looks_like(self):
        from lguard import filetype

        def ok(data, kind):
            p = util.write(os.path.join(self.home, "probe.bin"), data)
            fd = os.open(p, os.O_RDONLY)
            try:
                return filetype.media_structure_ok(fd, len(data), kind)
            finally:
                os.close(fd)
        ftyp = b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00"
        self.assertTrue(ok(ftyp + (1008).to_bytes(4, "big") + b"mdat" + b"x" * 1000, "mp4"))
        self.assertTrue(ok(ftyp + b"\x00\x00\x00\x00mdat" + b"x" * 1000, "mp4"))             # last box "to the end"
        self.assertFalse(ok(ftyp + (500).to_bytes(4, "big") + b"mdat" + b"x" * 1000, "mp4"))   # boxes do not add up
        self.assertFalse(ok(ftyp + b"x" * 1000, "mp4"))
        self.assertTrue(ok(b"RIFF" + (1004).to_bytes(4, "little") + b"AVI " + b"x" * 1000, "avi"))
        self.assertFalse(ok(b"RIFF" + (100).to_bytes(4, "little") + b"AVI " + b"x" * 1000, "avi"))
        self.assertTrue(ok((b"\x47" + b"x" * 187) * 200, "mpeg-ts"))
        self.assertFalse(ok(b"\x47" + b"x" * 187 + b"y" * 188 * 199, "mpeg-ts"))
        self.assertFalse(ok(b"\xff\xfb" + b"x" * 1000, "mpeg-audio"))                          # nothing cheap to check

    def test_a_verdict_is_not_remembered_for_content_that_changed_while_it_was_checked(self):
        p = util.write(os.path.join(self.home, "swap.bin"), b"\x7fELF" + b"first content")
        real = self.clamd.scan_fd

        def swap(fd):
            r = real(fd)
            with open(p, "wb") as f:                 # someone rewrites the file while the engine reads it
                f.write(b"\x7fELF" + b"second, harmless content")
            return r
        self.clamd.scan_fd = swap
        import hashlib
        first = hashlib.sha256(b"\x7fELF" + b"first content").hexdigest()
        r = self.sc.scan(p)
        self.clamd.scan_fd = real
        self.assertEqual(r.verdict, "error")                     # checked again later, not called clean
        self.assertIsNone(self.idx.hash_verdict(first))
        self.assertEqual(self.sc.scan(p).verdict, "clean")

    def test_a_download_name_does_not_hide_a_file_for_good(self):
        import time
        p = util.write(os.path.join(self.home, "payload.part"), util.THREAT)
        self.assertEqual(self.sc.scan(p).detail, "download in progress")
        old = time.time() - 2 * 3600
        os.utime(p, (old, old))
        self.assertEqual(self.sc.scan(p).verdict, "infected")

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
        p = util.write(os.path.join(self.home, "doc.jpg"), b"\xff\xd8\xff" + util.THREAT)
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
