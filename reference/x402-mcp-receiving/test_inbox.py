"""Actual local VATE Inbox integration; requires the existing repository venv."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

import receive
from fixture_data import CASE_IDS, fixture
from inbox_connection import NATIVE_KIND, retain

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "reference/recipient-inbox"))
from recipient_inbox import Engine, Inbox


class InboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Engine(ROOT)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "inbox.sqlite3"
        self.inbox = Inbox(self.db, self.engine, create=True)

    def tearDown(self):
        self.inbox.close()
        self.temp.cleanup()

    def test_result_and_originals_survive_database_reopen(self):
        inputs = fixture(CASE_IDS[3])
        retained = retain(self.inbox, **inputs)
        self.inbox.close()
        self.inbox = Inbox(self.db, self.engine, create=False)
        for name, raw in inputs.items():
            self.assertEqual(self.inbox.get(retained["originals"][name]), raw)
        report = json.loads(self.inbox.get(retained["originals"]["inspection"]))
        self.assertEqual(report, receive.assess(**inputs))
        self.assertEqual(report["observations"]["result_carrier"], "exception.result")

    def test_identical_delivery_is_idempotent(self):
        inputs = fixture(CASE_IDS[0])
        first, second = retain(self.inbox, **inputs), retain(self.inbox, **inputs)
        self.assertFalse(first["registration"]["duplicate"])
        self.assertTrue(second["registration"]["duplicate"])
        self.assertEqual(first["registration"]["sequence"], second["registration"]["sequence"])
        self.assertEqual(self.inbox.db.execute("SELECT count(*) FROM deliveries").fetchone()[0], 1)

    def test_revised_capture_does_not_replace_original_or_report(self):
        inputs = fixture(CASE_IDS[0])
        first = retain(self.inbox, **inputs)
        report_bytes = self.inbox.get(first["originals"]["inspection"])
        newer = dict(inputs)
        c = json.loads(newer["capture"])
        c["local_observations"]["client_recovered"] = True
        newer["capture"] = receive.encoded(c)
        s = json.loads(newer["selection"])
        s["capture_sha256"] = receive.sha(newer["capture"])
        newer["selection"] = receive.encoded(s)
        second = retain(self.inbox, **newer)
        self.assertNotEqual(first["delivery"]["entry_id"], second["delivery"]["entry_id"])
        self.assertEqual(first["delivery"]["source_namespace"], second["delivery"]["source_namespace"])
        self.assertEqual(self.inbox.get(first["originals"]["capture"]), inputs["capture"])
        self.assertEqual(self.inbox.get(first["originals"]["inspection"]), report_bytes)
        self.assertEqual(self.inbox.get(second["originals"]["capture"]), newer["capture"])

    def test_unknown_kind_is_not_fabricated_vate_receipt(self):
        result = retain(self.inbox, **fixture(CASE_IDS[1]))
        self.assertEqual(result["delivery"]["native_input_kind"], NATIVE_KIND)
        self.assertEqual(set(result["originals"]), {"request", "capture", "selection", "inspection"})
        self.assertIsNone(result["delivery"]["received_at"])
        self.assertEqual(self.inbox.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
        self.assertFalse(result["is_execution_ticket"])

    def test_invalid_json_is_rejected_before_storage(self):
        inputs = fixture(CASE_IDS[0])
        inputs["capture"] = b"not JSON"
        with self.assertRaises(receive.InputError):
            retain(self.inbox, **inputs)
        self.assertEqual(self.inbox.db.execute("SELECT count(*) FROM objects").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
