import os
import tempfile
import unittest

import util
from lguard import config


class Excludes(unittest.TestCase):
    def test_caches_are_soft_not_blind(self):
        c = config.Config()
        for p in ("/home/u/.cache/update/miner", "/home/u/p/__pycache__/x.so", "/home/u/.git/objects/ab/cd",
                  "/var/cache/evil", "/home/u/db-journal"):
            self.assertFalse(c.is_excluded(p), p)
            self.assertTrue(c.is_soft_excluded(p), p)

    def test_hard_excludes(self):
        c = config.Config()
        for p in ("/proc/1/mem", "/var/lib/lguard/index.db", "/run/systemd/x", "/var/lib/docker/overlay2/a/b"):
            self.assertTrue(c.is_excluded(p), p)
        self.assertFalse(c.is_excluded("/home/u/Downloads/setup.exe"))

    def test_no_exclusion_can_be_picked_by_naming_a_file_or_folder(self):
        c = config.Config()
        for p in ("/home/u/Downloads/setup.exe.part", "/home/u/Downloads/Unconfirmed 12.crdownload", "/home/u/x.!qB",
                  "/home/u/anything/.local/share/containers/payload", "/tmp/.mount_fake/payload",
                  "/run/user/1000/payload", "/run/media/u/STICK/payload"):
            self.assertFalse(c.is_excluded(p), p)
        # the users' own corners are "soft": their data is skipped, a program there is not
        for p in ("/home/u/anything/.local/share/containers/payload", "/tmp/.mount_fake/payload", "/run/user/1000/payload"):
            self.assertTrue(c.is_soft_excluded(p), p)

    def test_a_download_is_left_alone_only_while_it_is_being_written(self):
        import time
        c = config.Config()
        self.assertTrue(c.is_incomplete("/x/a.part"))
        self.assertTrue(c.is_downloading("/x/a.part", time.time() - 60))
        self.assertFalse(c.is_downloading("/x/a.part", time.time() - 2 * 3600))     # kept the name, stopped changing
        self.assertFalse(c.is_downloading("/x/a.iso", time.time()))

    def test_other_disks_count_as_data_unless_the_user_said_where_the_data_is(self):
        c = config.Config()
        c.data_mounts = ["/mnt/photos"]
        c.categories = {"downloads": ["/mnt/photos/incoming"]}
        self.assertTrue(c.is_data("/home/u/a.docx"))
        self.assertTrue(c.is_data("/mnt/photos/2024/a.jpg"))
        self.assertFalse(c.is_data("/mnt/photos/incoming/film.mkv"))                # half-written downloads look encrypted
        self.assertFalse(c.is_data("/srv/x"))


class Categories(unittest.TestCase):
    def test_modes(self):
        c = config.Config()
        c.categories = {"downloads": ["/srv/dl"], "plex": ["/srv/plex"], "Work": ["/srv/work"], "Films": ["/srv/films"]}
        c.category_modes = {"Films": "media"}
        self.assertEqual(c.mode_of("/srv/dl/a.exe"), "downloads")
        self.assertEqual(c.mode_of("/srv/plex/a.exe"), "media")
        self.assertEqual(c.mode_of("/srv/work/a.exe"), "downloads")
        self.assertEqual(c.mode_of("/srv/films/a.exe"), "media")

    def test_old_name_is_still_read(self):
        d = util.tmpdir()
        main = os.path.join(d, "lguard.toml")
        with open(main, "w") as f:
            f.write('categories = { torrents = ["/srv/t"], plex = ["/srv/p"] }\n')
        c = config.load(main)
        self.assertEqual(c.categories, {"plex": ["/srv/p"], "downloads": ["/srv/t"]})


class AppSettings(unittest.TestCase):
    def setUp(self):
        self.dir = util.tmpdir()
        self.main = os.path.join(self.dir, "lguard.toml")
        open(self.main, "w").close()

    def test_round_trip(self):
        config.write_app_settings({"categories": {"downloads": ['/srv/a "b"', "/srv/c\\d"], "Work": []},
                                   "category_modes": {"Work": "media"}, "priority_paths": [],
                                   "extra_excludes": ["/x/*"], "report_only": ["/games"],
                                   "data_paths": ["/home", "/srv/docs"]}, self.main)
        c = config.load(self.main)
        self.assertEqual(c.categories["downloads"], ['/srv/a "b"', "/srv/c\\d"])
        self.assertEqual(c.category_modes, {"Work": "media"})
        self.assertEqual(c.data_paths, ["/home", "/srv/docs"])
        self.assertIn("/games/*", c.never_quarantine)

    def test_control_characters_never_reach_the_file(self):
        for bad in ("/srv/a\rb", "/srv/a\nb", "/srv/a\x01b"):
            with self.assertRaises(ValueError):
                config.write_app_settings({"categories": {"x": [bad]}}, self.main)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "lguard.d", config.APP_DROPIN)))
        config.load(self.main)            # still loads


if __name__ == "__main__":
    unittest.main()
