import hashlib
import os
import struct
import unittest

import util
from lguard import authenticode, decide, quarantine
from lguard.scanner import Scanner
from lguard.sweep import Sweep


def der(tag, *parts):
    body = b"".join(parts)
    n = len(body)
    size = bytes([n]) if n < 128 else bytes([0x80 | len(n.to_bytes(4, "big").lstrip(b"\0"))]) + n.to_bytes(4, "big").lstrip(b"\0")
    return bytes([tag]) + size + body


def name(cn):
    return der(0x30, der(0x31, der(0x30, der(0x06, bytes.fromhex("550403")), der(0x0c, cn.encode()))))


def signed_program(body=b"program code " * 40, signer="Example Software Ltd", self_signed=False):
    """A minimal 64-bit Windows program carrying a publisher signature over
    its content (the signature block is shaped like a real one; the keys are
    not, nothing here checks them)."""
    pe = 0x80
    head = bytearray(0x200)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3c, pe)
    head[pe:pe + 4] = b"PE\0\0"
    opt = pe + 24
    struct.pack_into("<H", head, opt, 0x20b)
    dd = opt + 112
    struct.pack_into("<I", head, dd - 4, 16)
    content = bytes(head) + body
    content += b"\0" * (-len(content) % 8)
    cert_off = len(content)

    def blob(digest):
        issuer = name(signer if self_signed else "Example Signing CA")
        serial = der(0x02, b"\x01\x23")
        cert = der(0x30, der(0x30, der(0xa0, der(0x02, b"\x02")), serial, der(0x30), issuer, der(0x30),
                             name(signer), der(0x30)), der(0x30), der(0x03, b"\0"))
        spc = der(0x30, der(0x30, der(0x06, b"\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x0f")),
                  der(0x30, der(0x30, der(0x06, b"\x60\x86\x48\x01\x65\x03\x04\x02\x01")), der(0x04, digest)))
        signer_info = der(0x30, der(0x02, b"\x01"), der(0x30, issuer, serial), der(0x30), der(0x30), der(0x04, b"sig"))
        sd = der(0x30, der(0x02, b"\x01"), der(0x31), der(0x30, der(0x06, b"\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04"),
                                                         der(0xa0, spc)), der(0xa0, cert), der(0x31, signer_info))
        p7 = der(0x30, der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"), der(0xa0, sd))
        p7 += b"\0" * (-(len(p7) + 8) % 8)
        return struct.pack("<IHH", len(p7) + 8, 0x200, 2) + p7

    table_len = len(blob(b"\0" * 32))
    buf = bytearray(content)
    struct.pack_into("<II", buf, dd + 8 * 4, cert_off, table_len)
    h = hashlib.sha256()
    h.update(buf[:opt + 64])
    h.update(buf[opt + 68:dd + 8 * 4])
    h.update(buf[dd + 8 * 5:])
    return bytes(buf) + blob(h.digest())


def check(data):
    path = util.write(os.path.join(util.tmpdir(), "p.exe"), data)
    fd = os.open(path, os.O_RDONLY)
    try:
        return authenticode.check(fd, len(data))
    finally:
        os.close(fd)


class PublisherSignature(unittest.TestCase):
    def test_untouched_signed_program_is_intact(self):
        s = check(signed_program())
        self.assertTrue(s.intact)
        self.assertEqual(s.signer, "Example Software Ltd")
        self.assertFalse(s.self_signed)

    def test_one_changed_byte_breaks_it(self):
        data = bytearray(signed_program())
        data[0x210] ^= 1
        self.assertFalse(check(bytes(data)).intact)

    def test_self_signed_is_said_so(self):
        s = check(signed_program(self_signed=True))
        self.assertTrue(s.intact and s.self_signed)
        self.assertIn("self-signed", s.describe())

    def test_unsigned_and_other_files_have_none(self):
        self.assertIsNone(check(b"MZ" + b"\0" * 600))
        self.assertIsNone(check(b"\x7fELF" + b"\0" * 600))
        self.assertIsNone(check(b"hello"))

    def test_garbage_in_the_signature_block_is_not_an_error(self):
        data = bytearray(signed_program())
        cert = len(data) - 60
        data[cert:cert + 40] = b"\xff" * 40
        got = check(bytes(data))                         # must not raise
        self.assertTrue(got is None or not got.intact or got.signer is None)
        for cut in range(0x200, len(data), 7):           # nor on any truncated file
            check(bytes(data[:cut]))


class OldFiles(unittest.TestCase):
    """A detection in a file that has not changed for a long time is left in
    place for the user; anything new is quarantined as before."""

    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()
        self.clamd = util.FakeClamd()
        self.sc = Scanner(self.cfg, self.idx, self.clamd, log=lambda m: None)
        self.sc._unchanged_days = lambda st: 400
        self.home = os.path.join(self.top, "home")

    def tearDown(self):
        self.idx.close()

    def threat(self, name, extra=b""):
        return util.write(os.path.join(self.home, name), util.THREAT + extra)

    def test_old_file_met_by_a_background_check_stays(self):
        p = self.threat("old/tool.bin")
        r = self.sc.scan(p)
        self.assertEqual((r.verdict, r.action), ("infected", "held"))
        self.assertTrue(os.path.exists(p))
        self.assertEqual(quarantine.entries(self.cfg), [])
        f = self.idx.findings()[0]
        self.assertEqual((f["action"], f["level"]), ("held", "infected"))
        self.assertIn(p, self.idx.held())
        self.assertEqual(self.sc.scan(p).verdict, "infected")           # and is not reported twice
        self.assertEqual(len(self.idx.findings()), 1)

    def test_recently_changed_file_is_quarantined(self):
        self.sc._unchanged_days = lambda st: 3
        self.assertEqual(self.sc.scan(self.threat("new.bin")).action, "quarantined")

    def test_file_that_just_arrived_is_quarantined_whatever_its_date(self):
        self.assertEqual(self.sc.scan(self.threat("dl.bin"), fresh=True).action, "quarantined")

    def test_category_folder_is_always_quarantined(self):
        dl = os.path.join(self.top, "dl")
        self.cfg.categories = {"downloads": [dl]}
        p = util.write(os.path.join(dl, "x.bin"), util.THREAT)
        self.assertEqual(self.sc.scan(p).action, "quarantined")

    def test_setting_zero_turns_it_off(self):
        self.cfg.hold_old_days = 0
        self.assertEqual(self.sc.scan(self.threat("a.bin")).action, "quarantined")

    def test_started_program_is_quarantined_even_after_it_was_left(self):
        p = self.threat("old/run.bin")
        self.assertEqual(self.sc.scan(p).action, "held")
        self.assertEqual(self.sc.scan(p).action, None)                  # an ordinary re-check changes nothing
        r = self.sc.scan(p, started=True)
        self.assertEqual(r.action, "quarantined")
        self.assertFalse(os.path.exists(p))
        self.assertEqual(self.idx.held(), {})

    def test_program_changed_after_signing_is_quarantined(self):
        good = signed_program(body=util.THREAT + b"x" * 300)
        bad = bytearray(good)
        bad[0x240] ^= 1
        kept = util.write(os.path.join(self.home, "old/setup.exe"), good)
        hit = util.write(os.path.join(self.home, "old/infected.exe"), bytes(bad))
        r = self.sc.scan(kept)
        self.assertEqual(r.action, "held")
        self.assertIn("unchanged since signing", r.detail)
        self.assertIn("Example Software Ltd", self.idx.findings()[0]["detail"])
        r = self.sc.scan(hit)
        self.assertEqual(r.action, "quarantined")
        self.assertIn("changed after signing", r.detail)

    def test_copy_of_waiting_content_waits_too_without_a_second_alert(self):
        alerts = []
        import lguard.scanner as mod
        real, mod.notify = mod.notify, lambda cfg, title, msg, *a, **k: alerts.append(title)
        try:
            self.sc.scan(self.threat("old/a.bin"))
            r = self.sc.scan(self.threat("copy/a.bin"), fresh=True)     # e.g. moved to a trash folder
        finally:
            mod.notify = real
        self.assertEqual(r.action, "held")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(self.idx.held()), 2)

    def test_full_disk_scan_holds_too(self):
        p = util.write(os.path.join(self.home, "doc.jpg"), b"\xff\xd8\xff" + util.THREAT)
        real, self.clamd._judge = self.clamd._judge, lambda data: util.ClamResult(False, None, "")
        self.sc.scan(p)
        self.clamd._judge = real
        self.clamd.dbver += 1
        self.sc.invalidate_db_version()
        Sweep(self.cfg, self.sc, log=lambda m: None).maintenance(verify_budget=1 << 40)
        self.assertTrue(os.path.exists(p))
        self.assertIn(p, self.idx.held())


class Decisions(unittest.TestCase):
    """One decision settles every copy of the same content."""

    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()
        self.sc = Scanner(self.cfg, self.idx, util.FakeClamd(), log=lambda m: None)
        self.sc._unchanged_days = lambda st: 400
        self.home = os.path.join(self.top, "home")
        self.a = util.write(os.path.join(self.home, "disk1/tool.bin"), util.THREAT)
        self.b = util.write(os.path.join(self.home, "disk2/tool.bin"), util.THREAT)
        self.c = util.write(os.path.join(self.home, "new/tool.bin"), util.THREAT)
        self.other = util.write(os.path.join(self.home, "disk1/other.bin"), util.THREAT + b"!")
        self.sc._unchanged_days = lambda st: 0
        self.assertEqual(self.sc.scan(self.c).action, "quarantined")    # one copy went to quarantine
        self.sc._unchanged_days = lambda st: 400
        for p in (self.a, self.b, self.other):
            self.assertEqual(self.sc.scan(p).action, "held")
        self.digest = self.idx.held()[self.a]["digest"]

    def tearDown(self):
        self.idx.close()

    def actions(self):
        return {f["path"]: f["action"] for f in self.idx.findings()}

    def test_trust_keeps_and_restores_every_copy(self):
        done = decide.trust(self.cfg, self.idx, self.digest, "Test.Threat", "test", log=lambda m: None)
        self.assertEqual(done["restored"], [self.c])
        self.assertEqual(sorted(done["kept"]), [self.a, self.b])
        self.assertTrue(all(os.path.exists(p) for p in (self.a, self.b, self.c)))
        self.assertEqual(list(self.idx.held()), [self.other])           # different content: still waiting
        got = self.actions()
        self.assertEqual((got[self.a], got[self.b], got[self.c], got[self.other]),
                         ("trusted", "trusted", "restored+trusted", "held"))
        for p in (self.a, self.b, self.c):
            self.assertEqual(self.sc.scan(p).verdict, "clean")

    def test_remove_deletes_every_copy_and_later_ones_go_at_once(self):
        done = decide.remove(self.cfg, self.idx, self.digest, log=lambda m: None)
        self.assertEqual(done["deleted"], 3)
        self.assertFalse(any(os.path.exists(p) for p in (self.a, self.b, self.c)))
        self.assertEqual(quarantine.entries(self.cfg), [])
        self.assertTrue(os.path.exists(self.other))
        got = self.actions()
        self.assertEqual((got[self.a], got[self.b], got[self.c]), ("deleted",) * 3)
        again = util.write(os.path.join(self.home, "disk3/tool.bin"), util.THREAT)
        self.assertEqual(self.sc.scan(again).action, "quarantined")     # old or not

    def test_isolate_moves_the_waiting_copies_and_they_can_come_back(self):
        moved = decide.isolate(self.cfg, self.idx, self.digest, log=lambda m: None)
        self.assertEqual(len(moved), 2)
        self.assertFalse(os.path.exists(self.a) or os.path.exists(self.b))
        self.assertEqual(len(quarantine.entries(self.cfg)), 3)
        self.assertEqual(self.actions()[self.a], "quarantined")
        quarantine.restore(self.cfg, moved[0])
        self.assertTrue(os.path.exists(self.a) or os.path.exists(self.b))

    def test_file_replaced_since_is_not_touched(self):
        util.write(self.a, b"something else now\n")
        decide.remove(self.cfg, self.idx, self.digest, log=lambda m: None)
        self.assertEqual(util.read(self.a), b"something else now\n")
        self.assertEqual(self.actions()[self.a], "gone")

    def test_vanished_files_leave_the_waiting_list(self):
        os.unlink(self.b)
        self.assertEqual(decide.prune_held(self.idx), 1)
        self.assertEqual(sorted(self.idx.held()), sorted([self.a, self.other]))


if __name__ == "__main__":
    unittest.main()
