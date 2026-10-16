"""File-set operation receipts through durable intake and revised cutoffs."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from recipient_inbox import Engine, Inbox, encoded
from scenario_inputs import ROOT, LATE, coverage, delivery, next_plan, plan_for, timings
from run_trial import compare_replay

sys.path.insert(0, str(ROOT / "reference/runtime-support"))
from file_set_fixture import capture_cases, operation_context, receipt_pair, tree_hashes


class FileSetInboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="vate-file-set-intake-originals-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.captures = Path(cls.temp.name) / "captures"
        cls.native_reports = capture_cases(ROOT, cls.captures)
        cls.originals = tree_hashes(cls.captures)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="vate-file-set-intake-")
        self.addCleanup(self.work.cleanup)
        self.folder = Path(self.work.name)
        self.box = Inbox(self.folder / "inbox.sqlite3", Engine(ROOT), create=True)
        self.addCleanup(lambda: self.box.close())
        self.received_originals = []
        self.plan = plan_for(self.box)
        basis = self.box.put(b"Synthetic finite receiver requirements and arrival assertions for file-set receipts.\n", "text/plain")
        self.plan.update(collection_basis_ref=basis, selection_basis_ref=basis, revision_basis_ref=basis,
                         native_policy_refs={"s3": None, "signature": None})
        self.plan["review_set"].update(review_set_id="file-set-operations", population_basis_refs=[basis])
        self.pairs = dict(zip(("A", "B"), (receipt_pair(self.captures / name)
                          for name in ("allow", "response-loss-reconciled"))))
        for row in self.plan["review_set"]["requirements"]:
            row["subject"]["native_context"] = operation_context(self.pairs[row["requirement_id"]][0])
            row["basis_refs"] = [basis]
        self.addCleanup(lambda: self.assertEqual(tree_hashes(self.captures), self.originals))

    def receive(self, event, entry, originals, **kwargs):
        raw = delivery(self.box, self.plan, event, originals, entry_id=entry, **kwargs)
        self.box.receive(raw)
        self.received_originals.extend((ref, originals[name])
                                       for name, ref in json.loads(raw)["originals"].items())

    def assert_originals_retained(self):
        for ref, raw in self.received_originals:
            self.assertEqual(self.box.get(ref), raw)

    def finish(self, prepared):
        state = self.box.run(prepared["run_id"])
        self.assertEqual(state["status"], "completed", state)
        report = json.loads(self.box.get(state["report_ref"]))
        self.assertIs(report["invocation_errors"], False)
        return state, report

    def assess(self, plan):
        return self.finish(self.box.prepare(encoded(plan)))

    def replay(self, state, label):
        folder = self.folder / label
        self.box.export(state["run_id"], folder)
        output = self.folder / (label + "-replayed.json")
        result = subprocess.run([sys.executable, "-B", str(ROOT / "reference/required-records/required_records.py"),
            "--selection", str(folder / "selection.json"), "--base", "inbox=" + str(folder),
            "--source-root", str(ROOT), "--output", str(output)], capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        compare_replay(json.loads((folder / "report.json").read_bytes()), json.loads(output.read_bytes()))

    def test_frozen_snapshot_old_cutoff_late_reassessment_and_export_keep_original_history(self):
        for name, (admission, _) in self.pairs.items():
            self.receive(name + "-admission", name, {"admission": admission})
        prepared = self.box.prepare(encoded(self.plan))
        for name, (_, post) in self.pairs.items():
            self.receive(name + "-post", name, {"post": post}, received=LATE)
        first, report1 = self.finish(prepared)
        self.assertEqual(coverage(report1), {"A": "missing", "B": "missing"})
        self.assertEqual(first["max_delivery_sequence"], 2)
        old_raw = self.box.get(first["report_ref"])
        self.box.close()
        self.box = Inbox(self.folder / "inbox.sqlite3", Engine(ROOT))
        second, report2 = self.assess(self.plan)
        self.assertEqual(coverage(report2), {"A": "missing", "B": "missing"})
        for row in report2["requirements"]:
            self.assertTrue(all(c["reason"] == "AFTER_CUTOFF" for c in row["candidates"]))
        third, report3 = self.assess(next_plan(self.plan))
        self.assertEqual(coverage(report3), {"A": "present", "B": "present"})
        self.assertEqual(timings(report3), {"A": "late", "B": "late"})
        self.assertEqual(third["revision"], 3)
        self.assertEqual(third["previous_id"], second["run_id"])
        self.assertEqual(report3["previous"]["previous_report_ref"], second["report_ref"])
        self.assertEqual([c["result"]["native_result"]["record_linkage"] for c in report3["native_calls"]],
                         ["matched", "matched"])
        self.assertEqual(self.box.get(first["report_ref"]), old_raw)
        self.assert_originals_retained()
        self.assertIn("actual_execution", report3["not_checked"])
        self.assertIn("current_permission_to_execute", report3["not_checked"])
        self.assertEqual(self.box.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.replay(first, "first-export")
        self.replay(third, "latest-export")

    def test_unknown_arrival_stays_unresolved_despite_native_issued_time(self):
        admission, post = self.pairs["A"]
        self.receive("unknown-time", "A", {"admission": admission, "post": post}, received=None)
        _, report = self.assess(self.plan)
        self.assertEqual(coverage(report), {"A": "unresolved", "B": "missing"})
        self.assertEqual(timings(report)["A"], "unknown")

    def test_attenuated_operation_survives_storage_and_export(self):
        admission, post = receipt_pair(self.captures / "attenuate")
        row = self.plan["review_set"]["requirements"][0]
        row["subject"]["native_context"] = operation_context(admission)
        admission_row = deepcopy(row)
        admission_row.update(requirement_id="A-admission", record_kind="admission")
        self.plan["review_set"]["requirements"] = [admission_row, row]
        self.receive("attenuated", "A", {"admission": admission, "post": post})
        state, report = self.assess(self.plan)
        self.assertEqual(coverage(report), {"A-admission": "present", "A": "present"})
        self.assertEqual(report["native_calls"][0]["result"]["native_result"]["record_linkage"], "matched")
        self.assert_originals_retained()
        self.replay(state, "attenuated-export")

    def test_other_operations_post_remains_mismatch_and_does_not_complete_A(self):
        self.receive("cross-operation", "A", {"admission": self.pairs["A"][0], "post": self.pairs["B"][1]})
        _, report = self.assess(self.plan)
        self.assertEqual(coverage(report), {"A": "missing", "B": "present"})
        self.assertEqual(report["native_calls"][0]["result"]["native_result"]["record_linkage"], "mismatch")

    def test_missing_receipt_after_response_loss_does_not_authorize_another_execution(self):
        admission, post = receipt_pair(self.captures / "response-loss")
        self.assertIsNone(post)
        self.plan["review_set"]["requirements"] = self.plan["review_set"]["requirements"][:1]
        self.plan["review_set"]["requirements"][0]["subject"]["native_context"] = operation_context(admission)
        self.receive("indeterminate", "A", {"admission": admission})
        _, report = self.assess(self.plan)
        self.assertEqual(coverage(report), {"A": "missing"})
        self.assertIn("current_permission_to_execute", report["not_checked"])
        self.assertEqual(self.native_reports["response-loss"]["provider_execution_count"], 1)
        gate = json.loads((self.captures / "response-loss/adapter/gate-2.json").read_bytes())
        self.assertFalse(gate["handoff"])
        self.assertEqual(gate["reason"], "OPERATION_INDETERMINATE")

    def test_unsupported_file_set_attempt_rejects_prepare_without_mutating_history(self):
        self.receive("admission", "A", {"admission": self.pairs["A"][0]})
        before = {table: self.box.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                  for table in ("objects", "deliveries", "runs", "heads")}
        row = self.plan["review_set"]["requirements"][0]
        row["subject"].update(kind="attempt", attempt_id="named-file-set-attempt")
        row["binding_profile"] = "vate_s3_attempt_context"
        with self.assertRaisesRegex(ValueError, "unsupported attempt requirement"):
            self.box.prepare(encoded(self.plan))
        for table, count in before.items():
            self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0], count)


if __name__ == "__main__":
    unittest.main()
