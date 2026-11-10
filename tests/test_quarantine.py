import os
import unittest

import util
from lguard import quarantine as q


class Quarantine(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()
        self.dir = os.path.join(self.top, "home", "u", "docs")
        self.path = util.write(os.path.join(self.dir, "evil"), b"X" * 10)
        os.chmod(self.path, 0o755)

    def tearDown(self):
        self.idx.close()

    def put(self, path=None):
        path = path or self.path
        fd = os.open(path, os.O_RDONLY)
        try:
            return q.quarantine(self.cfg, path, fd, os.fstat(fd), "digest", "Sig")
        finally:
            os.close(fd)

    def test_round_trip_keeps_mode_and_never_overwrites(self):
        qid = self.put()
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(os.stat(os.path.join(self.cfg.quarantine_dir, qid + ".bin")).st_mode & 0o777, 0o400)
        util.write(self.path, b"new file with the old name")
        target = q.restore(self.cfg, qid)
        self.assertEqual(target, self.path + ".restored")
        self.assertEqual(util.read(target), b"X" * 10)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)
        self.assertEqual(util.read(self.path), b"new file with the old name")
        self.assertEqual(q.entries(self.cfg), [])

    def test_restore_refuses_a_folder_swapped_for_a_link(self):
        qid = self.put()
        elsewhere = os.path.join(self.top, "etc")
        os.makedirs(elsewhere)
        os.rename(self.dir, self.dir + ".real")
        os.symlink(elsewhere, self.dir)
        with self.assertRaises(q.QuarantineError):
            q.restore(self.cfg, qid)
        self.assertEqual(os.listdir(elsewhere), [])
        self.assertEqual(len(q.entries(self.cfg)), 1)          # still safely in quarantine

    def test_quarantine_follows_the_file_not_the_name(self):
        fd = os.open(self.path, os.O_RDONLY)
        st = os.fstat(fd)
        os.rename(self.path, self.path + ".moved")
        util.write(self.path, b"an innocent file put under the old name")
        try:
            q.quarantine(self.cfg, self.path, fd, st, None, "Sig")
        finally:
            os.close(fd)
        self.assertTrue(os.path.exists(self.path))              # the innocent one stays
        self.assertFalse(os.path.exists(self.path + ".moved"))  # the scanned one went

    def test_protected_location_is_judged_by_the_real_path(self):
        self.cfg.never_quarantine = [self.dir + "/*"]
        link = os.path.join(self.top, "home", "u", "shortcut")
        os.symlink(self.dir, link)
        with self.assertRaises(q.QuarantineError):
            self.put(os.path.join(link, "evil"))
        self.assertTrue(os.path.exists(self.path))

    def test_ids_cannot_leave_the_quarantine_folder(self):
        for bad in ("../../etc/passwd", "", ".hidden", "a/b"):
            with self.assertRaises(q.QuarantineError):
                q.restore(self.cfg, bad)
            with self.assertRaises(q.QuarantineError):
                q.delete(self.cfg, bad)

    def test_open_dir_rejects_links_and_dotdot(self):
        os.symlink(self.dir, os.path.join(self.top, "link"))
        for bad in (os.path.join(self.top, "link"), os.path.join(self.dir, "..", "docs"), "relative/path"):
            with self.assertRaises(q.QuarantineError):
                os.close(q.open_dir(bad))


if __name__ == "__main__":
    unittest.main()
