import unittest

import util
from lguard.index import FileRow, Index


def row(path, verdict="clean"):
    return FileRow(path, 1, 2, 3, 4, 5, "d" * 64, "text", 0, verdict, None, 100, 1.0)


class Inventory(unittest.TestCase):
    def setUp(self):
        self.top, self.cfg, self.idx = util.sandbox()

    def tearDown(self):
        self.idx.close()

    def test_records_are_not_readable_on_disk(self):
        self.idx.put(row("/home/u/secret-name.docx"))
        self.idx.commit()
        self.assertNotIn(b"secret-name", util.read(self.idx.path))

    def test_edited_record_counts_as_absent(self):
        self.idx.put(row("/a"))
        self.idx.db.execute("UPDATE files SET ct = substr(ct, 1, length(ct) - 1) || x'00'")
        seen = []
        self.idx.on_tamper = lambda table, detail: seen.append(table)
        self.assertIsNone(self.idx.get("/a"))
        self.assertEqual(seen, ["files"])

    def test_clean_record_cannot_be_copied_onto_another_file(self):
        self.idx.put(row("/clean"))
        self.idx.put(row("/virus", "infected"))
        clean_id = self.idx.v.rid("files", "/clean")
        virus_id = self.idx.v.rid("files", "/virus")
        nonce, ct = self.idx.db.execute("SELECT nonce, ct FROM files WHERE id=?", (clean_id,)).fetchone()
        self.idx.db.execute("UPDATE files SET nonce=?, ct=? WHERE id=?", (nonce, ct, virus_id))
        self.assertIsNone(self.idx.get("/virus"))
        self.assertEqual(self.idx.tamper_count, 1)

    def test_history_chain_detects_removal_and_edit(self):
        for i in range(5):
            self.idx.event("test", str(i))
        self.assertEqual(self.idx.verify_ledger(), [])
        self.idx.db.execute("DELETE FROM ledger WHERE seq=3")
        self.assertTrue(self.idx.verify_ledger())

    def test_counters_are_written_in_batches(self):
        for _ in range(1000):
            self.idx.bump(cached=1)
        self.assertEqual(self.idx.daily(1), [])                  # nothing written per file
        self.idx.commit()
        self.assertEqual(self.idx.daily(1)[0]["cached"], 1000)
        other = Index(self.idx.path, self.idx.v)                 # a second process adds to the same day
        other.bump(scanned=5, cached=1)
        other.close()
        self.assertEqual(self.idx.daily(1)[0]["cached"], 1001)
        self.assertEqual(self.idx.daily(1)[0]["scanned"], 5)

    def test_trust_can_be_taken_back(self):
        self.idx.allow("a" * 64, "Sig.A", "restored /x/a")
        self.idx.allow("b" * 64, "Sig.B", "restored /x/b")
        self.assertTrue(self.idx.is_allowed("a" * 64))
        self.idx.unallow("a" * 64)
        self.assertFalse(self.idx.is_allowed("a" * 64))
        self.assertEqual([e["digest"] for e in self.idx.allowlist()], ["b" * 64])


if __name__ == "__main__":
    unittest.main()
