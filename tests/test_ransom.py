import os
import unittest

import util
from lguard import ransom
from lguard.index import FileRow
from lguard.ransom import RansomDetector


class Shield(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()
        self.cfg.ransom_stop_process = "never"
        self.home = os.path.join(self.top, "home")
        self.det = RansomDetector(self.cfg, self.idx, log=lambda m: None)
        self.alarms = []
        self.det.on_alarm = self.alarms.append

    def tearDown(self):
        self.idx.close()

    def known(self, path):
        """Put a file into the inventory as if it had been scanned."""
        self.idx.put(FileRow(path, 1, 2, 3, 4, 5, "d" * 64, "zip", 0, "clean", None, 1, 1.0))

    def test_documents_turning_into_noise(self):
        for i in range(self.cfg.ransom_suspect_files):
            p = util.write(os.path.join(self.home, f"report{i}.docx"), os.urandom(8192))
            self.det.feed(p, "/tmp/x/evil", 4242)
        self.assertEqual(len(self.alarms), 1)

    def test_ordinary_work_raises_nothing(self):
        for i in range(400):                      # unpacking, building: many files, ordinary content
            p = util.write(os.path.join(self.home, "src", f"f{i}.c"), b"int main(void) { return 0; }\n" * 200)
            self.known(p)
            self.det.feed(p, "/usr/bin/tar", 99)
        for i in range(100):                      # deleting photos is not an attack
            self.det.feed(os.path.join(self.home, f"p{i}.jpg"), "/usr/bin/rm", 98, "delete")
        self.assertEqual(self.alarms, [])

    def test_encrypt_to_new_name_and_delete_the_original(self):
        n = self.cfg.ransom_combo_files
        for i in range(n):
            orig = os.path.join(self.home, f"photo{i}.jpg")
            self.known(orig)
            new = util.write(os.path.join(self.home, f"{i:08x}.lockbit"), os.urandom(8192))
            self.det.feed(new, "/home/u/.local/x", 77)
            self.det.feed(orig, "/home/u/.local/x", 77, "delete")
        self.assertEqual(len(self.alarms), 1)

    def test_a_program_named_like_a_trusted_one_is_not_trusted(self):
        self.assertTrue(self.det._ignored("/usr/bin/rsync"))
        self.assertFalse(self.det._ignored("/tmp/.x/rsync"))
        self.assertFalse(self.det._ignored("/dev/shm/ffmpeg-helper"))
        self.assertFalse(self.det._ignored("/usr/bin/rsync (deleted)"))

    def test_stop_policy(self):
        self.assertTrue(ransom.is_system_program("/usr/bin/tar"))
        self.assertFalse(ransom.is_system_program("/home/u/Downloads/tool"))
        self.cfg.ransom_stop_process = "untrusted"
        self.det.pids["/usr/bin/tar"].add(os.getpid())
        self.assertEqual(self.det._stop("/usr/bin/tar"), [])          # a system tool is never suspended
        self.assertEqual(self.det._stop("/no/such/program"), [])      # nor a pid that is something else now

    def test_alarm_repeats_if_the_user_unfroze_and_it_goes_on(self):
        self.cfg.freeze_commands = ["true"]
        self.cfg.unfreeze_commands = ["true"]
        self.det._alarm("first {frozen}", "/tmp/evil")
        self.det._alarm("again while frozen {frozen}", "/tmp/evil")
        self.assertEqual(len(self.alarms), 1)
        from lguard.freeze import unfreeze
        unfreeze(self.cfg, self.idx, log=lambda m: None)
        self.det._alarm("still going {frozen}", "/tmp/evil")
        self.assertEqual(len(self.alarms), 2)


if __name__ == "__main__":
    unittest.main()
