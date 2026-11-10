import os
import tempfile
import unittest

import util  # noqa: F401
from lguard import filetype as ft


def verdict(name, data, mode):
    d = tempfile.mkdtemp()
    p = util.write(os.path.join(d, name), data)
    fd = os.open(p, os.O_RDONLY)
    try:
        return ft.media_verdict(p, ft.kind(data[:ft.HEAD]), fd, mode)
    finally:
        os.close(fd)


class MediaRules(unittest.TestCase):
    def test_pretending_names_are_caught_everywhere(self):
        for mode in ("media", "downloads"):
            self.assertEqual(verdict("Movie.mp4.exe", b"MZ", mode), ("suspicious", "Lguard.Media.DoubleExtension"))
            self.assertEqual(verdict("film.mkv", b"MZ" + bytes(64), mode)[0], "suspicious")
            self.assertEqual(verdict("film.mkv", b"PK\x03\x04" + bytes(64), mode)[0], "suspicious")

    def test_downloads_may_hold_programs_and_images(self):
        iso = bytearray(0x9000)
        iso[0x8001:0x8006] = b"CD001"
        for name, data in (("ubuntu.iso", bytes(iso)), ("setup.exe", b"MZ" + bytes(64)), ("game.bin", os.urandom(4096)),
                           ("install.sh", b"#!/bin/sh\n"), ("lib.dll", b"MZ" + bytes(8)), ("link.url", b"[InternetShortcut]\n")):
            self.assertIsNone(verdict(name, data, "downloads"), name)

    def test_media_library_takes_programs_away(self):
        self.assertEqual(verdict("codec.exe", b"MZ" + bytes(64), "media")[0], "suspicious")
        self.assertEqual(verdict("run.sh", b"#!/bin/sh\n", "media")[0], "suspicious")
        self.assertEqual(verdict("disc.iso", b"x" * 100, "media"), ("warning", "Lguard.Media.DiskImage"))
        self.assertEqual(verdict("data.bin", os.urandom(4096), "media")[0], "warning")

    def test_real_media_and_typescript_are_left_alone(self):
        for mode in ("media", "downloads"):
            self.assertIsNone(verdict("film.mkv", b"\x1a\x45\xdf\xa3" + os.urandom(4096), mode))
            self.assertIsNone(verdict("subs.srt", b"1\n00:00:01 --> 00:00:02\nhi\n", mode))
            self.assertIsNone(verdict("component.ts", b"export const x: number = 1;\n" * 40, mode))


class Ransomware(unittest.TestCase):
    def test_encrypted_documents(self):
        enc = os.urandom(65536)
        self.assertTrue(ft.looks_encrypted("/h/report.docx", enc))
        self.assertTrue(ft.looks_encrypted("/h/report.docx.locked", enc))
        self.assertTrue(ft.looks_encrypted("/h/photo.cr2", enc))
        self.assertFalse(ft.looks_encrypted("/h/blob.xyz", enc))            # no promise, no verdict

    def test_only_the_beginning_encrypted(self):
        part = os.urandom(4096) + b"A plain text document body. " * 2200
        self.assertTrue(ft.looks_encrypted("/h/notes.txt", part[:65536]))

    def test_real_files_are_not_suspects(self):
        self.assertFalse(ft.looks_encrypted("/h/a.jpg", b"\xff\xd8\xff\xe0" + os.urandom(65532)))
        self.assertFalse(ft.looks_encrypted("/h/a.txt", b"plain text\n" * 6000))
        self.assertFalse(ft.looks_random(b"\x1f\x8b" + os.urandom(65534)))   # gzip is dense by nature
        self.assertFalse(ft.looks_random(b"int main(void) { return 0; }\n" * 3000))
        self.assertTrue(ft.looks_random(os.urandom(65536)))

    def test_promises_format(self):
        self.assertTrue(ft.promises_format("/h/a.DOCX"))
        self.assertFalse(ft.promises_format("/h/a.pak"))


class Kinds(unittest.TestCase):
    def test_programs(self):
        for magic in (b"\x7fELF", b"MZ\x90\x00", b"#!/bin/sh", b"\xca\xfe\xba\xbe"):
            self.assertTrue(ft.is_program(magic))
        self.assertFalse(ft.is_program(b"\x89PNG"))

    def test_risky_types_get_new_signatures(self):
        for kind, ext in (("text", "html"), ("rtf", "rtf"), ("text", "svg"), ("unknown", ""), ("onenote", "one"),
                          ("pe", "exe"), ("zip", "docx")):
            self.assertTrue(ft.is_risky(kind, ext), (kind, ext))
        self.assertFalse(ft.is_risky("jpeg", "jpg"))
        self.assertFalse(ft.is_risky("text", "txt"))


if __name__ == "__main__":
    unittest.main()
