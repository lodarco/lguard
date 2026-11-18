"""Limits on what anyone can make the guard store, send or read."""
import os
import time
import unittest

import util
from util import sandbox, tmpdir, write

from lguard import clamd, detect, filetype, notify, quarantine
from lguard.ransom import FREEZES_PER_USER_PER_DAY, RansomDetector


class Alerts(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = sandbox()
        self.cfg.alert_burst = 3
        self.cfg.notify_command = ["/bin/true", "{title}", "{message}"]
        self.sent = []
        self._run, notify.subprocess.run = notify.subprocess.run, lambda args, **kw: self.sent.append(args)
        self._log, notify.syslog.syslog = notify.syslog.syslog, lambda *a: None
        notify._sent.clear()
        notify._held_back = 0

    def tearDown(self):
        notify.subprocess.run, notify.syslog.syslog = self._run, self._log
        notify._sent.clear()
        notify._held_back = 0
        self.idx.close()

    def test_a_flood_is_cut_off_and_then_summed_up(self):
        for i in range(10):
            notify.notify(self.cfg, "Threat found", f"file {i}", "high")
        self.assertEqual(len(self.sent), 3)
        notify.notify(self.cfg, "RANSOMWARE ALARM", "x", "urgent")           # what matters most always goes out
        self.assertEqual(len(self.sent), 4)
        self.assertIn("7 more alerts", self.sent[-1][2])                      # and says what was held back
        notify._sent.clear()                                                  # ten minutes later
        notify.notify(self.cfg, "Threat found", "next", "high")
        self.assertEqual(self.sent[-1][2], "next")


class Mounts(unittest.TestCase):
    TABLE = """/dev/sda2 / ext4 rw 0 0
proc /proc proc rw 0 0
tmpfs /run tmpfs rw 0 0
tmpfs /run/user/1000 tmpfs rw 0 0
tmpfs /run/lock tmpfs rw 0 0
tmpfs /tmp tmpfs rw 0 0
tmpfs /dev/shm tmpfs rw 0 0
/dev/sdb1 /mnt/pool fuse.mergerfs rw 0 0
/dev/sdc1 /mnt/My\\040Disk exfat rw 0 0
/dev/loop3 /snap/core/1 squashfs ro 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0
nas:/vol /mnt/nas nfs4 rw 0 0
/dev/sda2 /usr/lib/modules ext4 ro 0 0
tmpfs /dev/kmsg tmpfs ro 0 0
App.AppImage /tmp/.mount_AppXyz fuse.App.AppImage ro 0 0
/dev/sdd1 /mnt/new bcachefs rw 0 0
"""

    def test_everything_that_can_hold_files_is_watched_once(self):
        from lguard import sweep
        table = sweep.parse_mounts(self.TABLE)
        devs = {"/": 1, "/usr/lib/modules": 1, "/run/user/1000": 2, "/tmp": 3, "/dev/shm": 4, "/mnt/pool": 5,
                "/mnt/My Disk": 6, "/mnt/nas": 7, "/dev/kmsg": None, "/mnt/new": 8}
        watched, left = sweep.mounts(False, table, lambda p: devs[p])
        self.assertEqual(watched, ["/", "/dev/shm", "/mnt/My Disk", "/mnt/new", "/mnt/pool", "/run/user/1000", "/tmp"])
        self.assertEqual([m for m, _why in left], ["/mnt/nas"])
        watched, left = sweep.mounts(True, table, lambda p: devs[p])
        self.assertIn("/mnt/nas", watched)
        self.assertEqual(left, [])


class Engine(unittest.TestCase):
    def test_an_archive_locked_with_a_password_is_not_a_threat_and_not_clean(self):
        r = clamd._parse("fd[9]: Heuristics.Encrypted.Zip FOUND")
        self.assertEqual((r.infected, r.limited), (False, True))
        self.assertTrue(clamd._parse("fd[9]: Win.Test.EICAR_HDB-1 FOUND").infected)


class Quarantine(unittest.TestCase):
    def test_the_store_knows_how_much_it_holds(self):
        d = tmpdir()
        write(os.path.join(d, "a.bin"), b"x" * 100_000)
        write(os.path.join(d, "a.json"), b"{}")
        self.assertGreaterEqual(quarantine.store_size(d), 100_000)
        self.assertEqual(quarantine.store_size(os.path.join(d, "missing")), 0)


class UsersSettings(unittest.TestCase):
    def test_only_a_plain_small_file_is_read(self):
        d = tmpdir()
        real = write(os.path.join(d, "conf"), b"Session\\DefaultSavePath=/srv/dl\n" + b"x" * 3_000_000)
        self.assertEqual(len(detect._read(real)), 1 << 20)                    # no more than a megabyte
        os.symlink("/etc/shadow", os.path.join(d, "link"))
        self.assertEqual(detect._read(os.path.join(d, "link")), "")           # a link is not followed
        os.mkfifo(os.path.join(d, "pipe"))
        t0 = time.time()
        self.assertEqual(detect._read(os.path.join(d, "pipe")), "")           # a pipe is not waited for
        self.assertLess(time.time() - t0, 2)
        self.assertEqual(detect._read(os.path.join(d, "none")), "")


class EncryptedLooking(unittest.TestCase):
    def test_extra_extensions_and_ciphertext_written_as_text(self):
        rnd = os.urandom(70000)
        self.assertTrue(filetype.looks_encrypted("/h/report.docx", rnd))
        self.assertTrue(filetype.looks_encrypted("/h/report.docx.locked", rnd))
        self.assertTrue(filetype.looks_encrypted("/h/report.docx.id-4711.locked", rnd))
        self.assertFalse(filetype.looks_encrypted("/h/unknown.blob", rnd))
        import base64
        armoured = base64.encodebytes(rnd)
        self.assertTrue(filetype.looks_encrypted("/h/photo.jpg", armoured))
        self.assertFalse(filetype.looks_encrypted("/h/notes.txt", armoured))  # text is allowed to be text
        self.assertFalse(filetype.looks_encrypted("/h/photo.jpg", b"\xff\xd8\xff\xe0" + rnd))


class Packed(unittest.TestCase):
    def test_compressed_and_encoded_files_are_not_taken_for_encrypted_ones(self):
        import base64, bz2, lzma, zlib
        text = ("lorem ipsum dolor sit amet %d " * 4000).encode()
        packed = {
            "/h/go/src/testdata/e.txt.bz2": bz2.compress(text),
            "/h/go/src/jsontest/twitter.json.zst": b"\x28\xb5\x2f\xfd" + os.urandom(70000),
            "/h/go/src/testdata/data.json.xz": lzma.compress(text),
            "/h/go/src/gzip/testdata/issue.gz.base64": base64.encodebytes(os.urandom(70000)),
            "/h/backup/report.docx.gz": b"\x1f\x8b\x08" + os.urandom(70000),
            "/h/backup/photo.jpg.7z": b"7z\xbc\xaf\x27\x1c" + os.urandom(70000),
        }
        for path, content in packed.items():
            self.assertFalse(filetype.looks_encrypted(path, content[:65536]), path)
        # ... while ransomware's own extensions still are
        self.assertTrue(filetype.looks_encrypted("/h/report.docx.locked", os.urandom(70000)))
        self.assertTrue(filetype.looks_encrypted("/h/photo.jpg.encrypted", os.urandom(70000)))

    def test_electron_app_caches_are_soft(self):
        from lguard import config
        c = config.Config()
        for p in ("/home/u/.config/SomeApp/Cache/Cache_Data/f_000123", "/home/u/.config/SomeApp/IndexedDB/https_x/1.blob",
                  "/home/u/.config/SomeApp/blob_storage/abc/1"):
            self.assertTrue(c.is_soft_excluded(p), p)
        self.assertFalse(c.is_soft_excluded("/home/u/Documents/Cache.docx"))


class Ransom(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = sandbox()
        self.cfg.ransom_suspect_files = 3
        self.cfg.ransom_stop_process = "never"
        self.cfg.freeze_commands = ["true"]
        self.cfg.unfreeze_commands = ["true"]
        self.bodies = []
        import lguard.ransom as mod
        self.mod = mod
        self._notify, mod.notify = mod.notify, lambda cfg, title, body, *a, **k: self.bodies.append(body)
        self.frozen = []
        self._freeze, mod.freeze = mod.freeze, lambda cfg, idx, why, log: (self.frozen.append(why), True)[1]
        self._is, mod.is_frozen = mod.is_frozen, lambda idx: False
        self.det = RansomDetector(self.cfg, self.idx, log=lambda m: None)
        self.det.uid_of["/home/x/tool"] = 1000

    def tearDown(self):
        self.mod.notify, self.mod.freeze, self.mod.is_frozen = self._notify, self._freeze, self._is
        self.idx.close()

    def _attack(self, n):
        for i in range(self.cfg.ransom_suspect_files):
            p = write(os.path.join(self.top, "home", f"doc{n}-{i}.docx"), os.urandom(70000))
            self.det.feed(p, "/home/x/tool", 0)
        self.det.last_alarm = 0                       # as if the half hour had passed and the user had unfrozen

    def test_the_alarm_names_the_user_and_one_user_cannot_freeze_the_backups_all_day(self):
        for n in range(FREEZES_PER_USER_PER_DAY + 2):
            self._attack(n)
        self.assertEqual(len(self.bodies), FREEZES_PER_USER_PER_DAY + 2)        # every alarm is still raised
        self.assertEqual(len(self.frozen), FREEZES_PER_USER_PER_DAY)            # the freeze is not repeated for ever
        self.assertIn("User:", self.bodies[0])
        self.assertIn("NOT frozen again", self.bodies[-1])

    def _split(self, writer, deleter, n=40):
        from lguard.index import FileRow
        for i in range(n):
            known = os.path.join(self.top, "home", f"old{i}.json")
            self.idx.put(FileRow(known, 1, i, 10, 1, 1, "d" * 64, "text", 0, "clean", None, 1, 1.0))
            self.det.feed(known, deleter, 0, "delete")
            new = write(os.path.join(self.top, "home", f"cache{i}"), os.urandom(70000))
            self.det.feed(new, writer, 0)

    def test_two_programs_of_one_user_doing_ordinary_things_are_not_an_attack(self):
        # A launcher clears its runtime folder (hundreds of small files go)
        # while the game it starts fills its shader cache (dense new files).
        self.cfg.ransom_combo_files = 30
        self.det.uid_of["/home/x/launcher"] = self.det.uid_of["/home/x/game"] = 1000
        self._split(writer="/home/x/game", deleter="/home/x/launcher")
        self.assertEqual(self.bodies, [])
        self.assertEqual(self.frozen, [])

    def test_one_program_doing_both_is(self):
        self.cfg.ransom_combo_files = 30
        self._split(writer="/home/x/tool", deleter="/home/x/tool")
        self.assertEqual(len(self.bodies), 1)


if __name__ == "__main__":
    unittest.main()
