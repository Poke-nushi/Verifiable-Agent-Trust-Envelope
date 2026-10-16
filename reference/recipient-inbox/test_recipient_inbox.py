"""Persistence and integration regressions, using unchanged native evaluators."""
from copy import deepcopy
import errno
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from recipient_inbox import Engine, Inbox, InboxError, MIB, SNAPSHOT_HEADER_RESERVE, READ_METADATA_RESERVE, encoded, read_file, sha
from scenario_inputs import ROOT, HERE, BUNDLE, NAMESPACE, LATE, plan_for, delivery, next_plan, signature_fixture, coverage, timings

# Let the real evaluator's 90-second limit and runtime checks finish before
# the test harness terminates their parent process on a slow platform.
TEST_PROCESS_TIMEOUT = 180


class InboxCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vate-inbox-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.engine = Engine(ROOT)
        self.box = Inbox(self.folder / "inbox.sqlite3", self.engine, create=True)
        self.addCleanup(lambda: self.box.close())
        self.plan = plan_for(self.box)
        self.admission, self.post = (BUNDLE / "admission.json").read_bytes(), (BUNDLE / "post.json").read_bytes()

    def receive(self, event="delivery-1", *, originals=None, **kwargs):
        raw = delivery(self.box, self.plan, event, {"admission": self.admission, "post": self.post}
                       if originals is None else originals, **kwargs)
        return self.box.receive(raw)

    def assess(self, plan=None):
        prepared = self.box.prepare(encoded(plan or self.plan))
        state = self.box.run(prepared["run_id"])
        self.assertEqual(state["status"], "completed", state)
        return state, json.loads(self.box.get(state["report_ref"]))

    def command(self, *args):
        return [sys.executable, "-B", str(HERE / "recipient_inbox.py"), "--db", str(self.box.path),
                "--source-root", str(ROOT), *args]

    def child(self, code, *args):
        result = subprocess.run([sys.executable, "-B", "-c", "import sys;sys.path.insert(0,sys.argv[1]);" + code,
                                 str(HERE), str(ROOT), str(self.box.path), *map(str, args)],
                                capture_output=True, timeout=TEST_PROCESS_TIMEOUT)
        return result

class InboxTests(InboxCase):
    def test_incomplete_then_late_after_reopen_preserves_previous_bytes(self):
        self.receive(originals={"admission": self.admission})
        first, report1 = self.assess()
        self.assertEqual(coverage(report1), {"A": "missing", "B": "missing"})
        before = self.box.get(first["report_ref"])
        self.box.close(); self.box = Inbox(self.folder / "inbox.sqlite3", Engine(ROOT))
        self.receive("late", originals={"post": self.post}, received=LATE)
        second, report2 = self.assess(next_plan(self.plan))
        self.assertEqual(coverage(report2), {"A": "present", "B": "missing"})
        self.assertEqual(timings(report2)["A"], "late")
        self.assertEqual(second["revision"], 2)
        self.assertEqual(second["previous_id"], first["run_id"])
        self.assertEqual(self.box.get(first["report_ref"]), before)
        self.assertEqual(report2["previous"]["previous_report_ref"], first["report_ref"])
        self.assertEqual(report1["entries"][0]["originals"]["post"],
                         {"event": None, "raw_identity": None, "state": "absent"})

    def test_prepared_snapshot_does_not_absorb_later_arrival(self):
        self.receive(originals={"admission": self.admission})
        prepared = self.box.prepare(encoded(self.plan))
        self.receive("late", originals={"post": self.post}, received=LATE)
        state = self.box.run(prepared["run_id"])
        self.assertEqual(coverage(json.loads(self.box.get(state["report_ref"])))["A"], "missing")
        self.assertEqual(state["max_delivery_sequence"], 1)

    def test_late_original_never_completes_the_earlier_cutoff(self):
        self.receive(originals={"admission": self.admission})
        self.assess()
        self.receive("late", originals={"post": self.post}, received=LATE)
        state, report = self.assess(next_plan(self.plan, later=False))
        self.assertEqual(state["revision"], 2)
        self.assertEqual(coverage(report)["A"], "missing")
        self.assertIn("after", encoded(report).decode())

    def test_partial_inventory_does_not_become_complete_from_storage(self):
        self.receive()
        self.plan["inventory_state"] = "partial"
        _, report = self.assess()
        self.assertEqual(coverage(report), {"A": "unresolved", "B": "unresolved"})

    def test_unknown_arrival_is_not_backfilled_from_receipt(self):
        self.receive(received=None)
        _, report = self.assess()
        self.assertEqual(coverage(report)["A"], "unresolved")
        self.assertEqual(timings(report)["A"], "unknown")

    def test_malformed_original_is_retained_and_remains_unresolved(self):
        self.receive(originals={"admission": self.admission, "post": b"{broken"})
        _, report = self.assess()
        self.assertEqual(coverage(report)["A"], "unresolved")
        self.assertEqual(self.box.get(self.box.put(b"{broken")), b"{broken")

    def test_duplicate_event_is_idempotent_but_reused_id_is_rejected(self):
        raw = delivery(self.box, self.plan, "same", {"post": self.post})
        one, two = self.box.receive(raw), self.box.receive(raw)
        self.assertFalse(one["duplicate"]); self.assertTrue(two["duplicate"])
        self.assertEqual(one["sequence"], two["sequence"])
        changed = json.loads(raw); changed["received_at"] = LATE
        with self.assertRaisesRegex(InboxError, "event ID"):
            self.box.receive(encoded(changed))
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 1)

    def test_slot_conflict_rolls_back_the_entire_delivery(self):
        self.receive(originals={"admission": self.admission})
        # Insert the new proof before a conflict is detected on another proof slot.
        self.receive("proof-1", originals={}, proofs={"post": b"first proof"})
        raw = delivery(self.box, self.plan, "conflicting", {}, proofs={"admission": b"new proof", "post": b"changed proof"})
        with self.assertRaisesRegex(InboxError, "never replace"):
            self.box.receive(raw)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 2)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM slots WHERE role='detached_proofs'").fetchone()[0], 1)

    def test_entry_kind_cannot_change(self):
        self.receive()
        with self.assertRaisesRegex(InboxError, "input kind"):
            self.receive("different-kind", originals={"post.json": self.post}, kind="s3_bundle")

    def test_competing_original_is_visible_with_a_new_entry(self):
        self.receive()
        self.receive("different-post", entry_id="A-variant", originals={"admission": self.admission, "post": self.post + b"\n"})
        _, report = self.assess()
        self.assertEqual(coverage(report)["A"], "unresolved")
        row = next(row for row in report["requirements"] if row["requirement_id"] == "A")
        self.assertIn("AMBIGUOUS_ORIGINALS", row["reasons"])

    def test_unknown_input_kind_remains_an_unknown_candidate(self):
        self.receive()
        self.receive("unknown", entry_id="unknown", originals={"unknown": b"native opaque bytes"}, kind="unmapped")
        _, report = self.assess()
        self.assertEqual(coverage(report)["A"], "unresolved")

    def test_cumulative_unknown_slots_rejects_nineteenth_without_poisoning_entry(self):
        original = delivery(self.box, self.plan, "eighteen", {f"part-{i}": b"opaque" for i in range(18)}, kind="unmapped")
        self.box.receive(original)
        with self.assertRaises(InboxError) as caught:
            self.receive("nineteenth", originals={"part-18": b"opaque"}, kind="unmapped")
        self.assertEqual(caught.exception.code, "SLOT_LIMIT")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM slots").fetchone()[0], 18)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 1)
        self.assertTrue(self.box.receive(original)["duplicate"])
        _, report = self.assess()
        self.assertEqual(coverage(report)["A"], "unresolved")

    def test_namespace_entry_limit_is_atomic_and_does_not_block_other_namespaces(self):
        first = None
        for index in range(256):
            raw = delivery(self.box, self.plan, f"event-{index}", {"opaque": b"opaque"},
                           kind="unmapped", entry_id=f"entry-{index}")
            self.box.receive(raw)
            first = first or raw
        with self.assertRaises(InboxError) as caught:
            self.receive("overflow", entry_id="overflow", originals={"opaque": b"opaque"}, kind="unmapped")
        self.assertEqual(caught.exception.code, "ENTRY_LIMIT")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 256)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 256)
        self.assertTrue(self.box.receive(first)["duplicate"])
        self.receive("another-namespace", namespace="other", originals={"opaque": b"opaque"}, kind="unmapped")
        _, report = self.assess()
        self.assertEqual(len(report["entries"]), 256)

    def test_snapshot_capacity_rejects_delivery_atomically_and_preserves_last_valid_state(self):
        originals = {f"part-{index}": b"opaque" for index in range(18)}
        accepted = []
        for index in range(100):
            raw = delivery(self.box, self.plan, f"event-{index}", originals, kind="unmapped", entry_id=f"entry-{index}")
            before = {table: self.box.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                      for table in ("objects", "slots", "entries", "deliveries")}
            try:
                self.box.receive(raw)
            except InboxError as exc:
                self.assertEqual(exc.code, "SNAPSHOT_CAPACITY")
                for table, count in before.items():
                    self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0], count)
                break
            accepted.append(raw)
        else:
            self.fail("100 18-slot entries should exceed the existing metadata budget")
        self.assertGreater(len(accepted), 1)
        self.assertTrue(self.box.receive(accepted[-1])["duplicate"])
        entries, _, _ = self.box._snapshot(NAMESPACE)
        self.assertLessEqual(len(encoded(entries)), MIB - SNAPSHOT_HEADER_RESERVE)
        prepared = self.box.prepare(encoded(self.plan))
        _, job = self.box._run(prepared["run_id"])
        self.assertLessEqual(job["snapshot_ref"]["byte_length"], MIB)
        completed = self.box.run(prepared["run_id"])
        self.assertEqual(completed["status"], "completed", completed)
        report = json.loads(self.box.get(completed["report_ref"]))
        self.assertEqual(len(report["entries"]), len(accepted))

    def test_native_call_capacity_rejects_new_entries_but_keeps_prior_inputs(self):
        first = None
        for index in range(32):
            raw = delivery(self.box, self.plan, f"receipt-{index}", {"admission": self.admission}, entry_id=f"E{index}")
            self.box.receive(raw)
            first = first or raw
        with self.assertRaises(InboxError) as caught:
            self.receive("over-native-budget", entry_id="overflow", originals={"admission": self.admission})
        self.assertEqual(caught.exception.code, "NATIVE_CAPACITY")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 32)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 32)
        self.assertTrue(self.box.receive(first)["duplicate"])
        self.receive("late-slot", entry_id="E0", originals={"post": self.post}, received=LATE)
        _, report = self.assess(next_plan(self.plan))
        self.assertEqual(len(report["entries"]), 32)

    def test_prepare_rejects_legacy_namespace_that_exceeds_native_capacity(self):
        # Emulate the earlier receive contract, which did not enforce capacity.
        with patch.object(self.box, "_check_capacity"):
            for index in range(65):
                self.receive(f"legacy-{index}", entry_id=f"E{index}",
                             originals={"admission": self.admission + b"\n" * index})
        before = self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        with self.assertRaises(InboxError) as caught:
            self.box.prepare(encoded(self.plan))
        self.assertEqual(caught.exception.code, "NATIVE_CAPACITY")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 0)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0], before)

    def test_s3_capacity_reserves_three_native_calls_per_entry(self):
        for index in range(21):
            self.receive(f"s3-{index}", entry_id=f"E{index}", kind="s3_bundle",
                         originals={"admission.json": self.admission})
        with self.assertRaises(InboxError) as caught:
            self.receive("s3-overflow", entry_id="overflow", kind="s3_bundle",
                         originals={"admission.json": self.admission})
        self.assertEqual(caught.exception.code, "NATIVE_CAPACITY")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 21)

    def test_oversized_original_batch_is_refused_without_poisoning_the_namespace(self):
        raw = delivery(self.box, self.plan, "large", {f"part-{i}": bytes([65 + i]) * MIB for i in range(17)},
                       kind="unmapped")
        before = {table: self.box.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                  for table in ("objects", "entries", "slots", "deliveries")}
        with self.assertRaises(InboxError) as caught:
            self.box.receive(raw)
        self.assertEqual(caught.exception.code, "READ_CAPACITY")
        for table, count in before.items():
            self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0], count)
        self.receive()
        self.plan["inventory_state"] = "partial"  # Caller records that intake was incomplete.
        _, report = self.assess()
        self.assertEqual(coverage(report), {"A": "unresolved", "B": "unresolved"})

    def test_read_capacity_counts_full_references_including_after_and_unknown_arrivals(self):
        payload = b"x" * MIB
        self.receive(originals={f"p{i}": payload for i in range(18)}, kind="unmapped")
        # Equal full references share Reader's cache even across slots. Equal bytes
        # with different media types do not, regardless of asserted arrival time.
        for received in (LATE, None):
            with self.subTest(received=received):
                raw = json.loads(delivery(self.box, self.plan, "aliases", {f"p{i}": payload for i in range(12)},
                                         entry_id="aliases", kind="unmapped", received=received))
                for index, ref in enumerate(raw["originals"].values()):
                    ref["media_type"] = f"application/x-alias-{index}"
                with self.assertRaises(InboxError) as caught:
                    self.box.receive(encoded(raw))
                self.assertEqual(caught.exception.code, "READ_CAPACITY")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 1)
        _, report = self.assess()
        self.assertFalse(report["invocation_errors"])

    def test_read_capacity_boundary_preserves_last_accepted_bytes(self):
        maximum = self.box.v.DEFAULT_LIMITS["bytes"] - READ_METADATA_RESERVE
        originals = {f"p{i}": bytes([65 + i]) * MIB for i in range(11)}
        originals["p11"] = b"z" * (maximum - 11 * MIB - self.plan["collection_basis_ref"]["byte_length"] - 1)
        self.receive(originals=originals, kind="unmapped")  # Capacity minus one byte.
        self.receive("at-bound", originals={"p12": b"!"}, kind="unmapped")
        with self.assertRaises(InboxError) as caught:
            self.receive("over-bound", originals={"p13": b"?"}, kind="unmapped")
        self.assertEqual(caught.exception.code, "READ_CAPACITY")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM slots").fetchone()[0], 13)
        self.plan["inventory_state"] = "partial"
        _, report = self.assess()
        self.assertGreater(report["usage"]["bytes_read"], maximum)
        self.assertLessEqual(report["usage"]["bytes_read"], self.box.v.DEFAULT_LIMITS["bytes"])

    def test_prepare_rejects_legacy_namespace_over_the_read_budget(self):
        with patch.object(self.box, "_check_capacity"):
            self.receive(originals={f"p{i}": bytes([65 + i]) * MIB for i in range(17)}, kind="unmapped")
        with self.assertRaises(InboxError) as caught:
            self.box.prepare(encoded(self.plan))
        self.assertEqual(caught.exception.code, "READ_CAPACITY")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 0)

    def test_prepare_counts_plan_basis_bytes_and_rolls_back_without_advancing_history(self):
        self.receive()
        first, _ = self.assess()
        plan = next_plan(self.plan)
        plan["review_set"]["population_basis_refs"] = [self.box.put(bytes([65 + i]) * MIB) for i in range(16)]
        before = self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        with self.assertRaises(InboxError) as caught:
            self.box.prepare(encoded(plan))
        self.assertEqual(caught.exception.code, "READ_CAPACITY")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0], before)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
        self.assertEqual(self.box.status(first["run_id"])["head"], first["run_id"])
        second, _ = self.assess(next_plan(self.plan))
        self.assertEqual(second["previous_id"], first["run_id"])

    def test_previous_report_uses_separate_history_byte_budget(self):
        self.receive()
        first, _ = self.assess()
        row, _ = self.box._run(first["run_id"])
        result = self.box._json(json.loads(row["result_ref"]))
        # Synthetic larger valid JSON report, preserving the prior binding fields.
        result["report_ref"] = self.box.put(self.box.get(first["report_ref"]) + b" " * (17 * MIB))
        ref = self.box.put(encoded(result))
        self.box.db.execute("UPDATE runs SET result_ref=? WHERE run_id=?", (encoded(ref).decode(), first["run_id"]))
        second, report = self.assess(next_plan(self.plan))
        self.assertEqual(second["previous_id"], first["run_id"])
        self.assertGreater(report["usage"]["history_bytes_read"], 16 * MIB)
        self.assertLess(report["usage"]["bytes_read"], MIB)

    def test_sqlite_automatic_rollback_preserves_original_error(self):
        raw = delivery(self.box, self.plan, "rolled-back", {"post": self.post})
        self.box.db.execute("CREATE TEMP TRIGGER force_rollback BEFORE INSERT ON slots "
                            "BEGIN SELECT RAISE(ROLLBACK, 'synthetic storage failure'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "synthetic storage failure"):
            self.box.receive(raw)
        self.assertFalse(self.box.db.in_transaction)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 0)
        self.box.db.execute("DROP TRIGGER force_rollback")
        self.assertFalse(self.box.receive(raw)["duplicate"])

    def test_report_is_retained_when_evaluator_log_exceeds_bound(self):
        self.receive()
        root_copy = self.folder / "noisy-source"
        for name in self.engine.identity["sources"]:
            target = root_copy / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        changed = root_copy / "reference/required-records/required_records.py"
        original = changed.read_text()
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                changed.write_text(original.replace("if __name__ == '__main__':",
                    "if __name__ == '__main__':\n    sys." + stream + ".write('x' * (1024 * 1024 + 1))"))
                box = Inbox(self.box.path, Engine(root_copy))
                try:
                    prepared = box.prepare(encoded(self.plan))
                    state = box.run(prepared["run_id"])
                    self.assertEqual(state["status"], "assessment_error")
                    self.assertIsNone(state["head"])
                    self.assertTrue(state["report_ref"])
                    report = json.loads(box.get(state["report_ref"]))
                    self.assertEqual(coverage(report), {"A": "present", "B": "missing"})
                    self.assertTrue(any(error["code"] == "OUTPUT_ERROR" and error["detail"].startswith(stream + ":")
                                        for error in state["errors"]))
                finally:
                    box.close()

    def test_evaluator_start_failure_is_saved_without_advancing_history(self):
        self.receive()
        prepared = self.box.prepare(encoded(self.plan))
        real_popen = subprocess.Popen
        def launch(command, **kwargs):
            if any(str(arg).endswith("/required_records.py") for arg in command):
                raise OSError(errno.EAGAIN, "synthetic process capacity failure")
            return real_popen(command, **kwargs)
        with patch("recipient_inbox.subprocess.Popen", side_effect=launch):
            state = self.box.run(prepared["run_id"])
        self.assertEqual(state["status"], "assessment_error")
        self.assertIsNone(state["head"])
        self.assertTrue(any(error["code"] == "EVALUATOR_START" for error in state["errors"]))
        self.assertTrue(self.box._run(prepared["run_id"])[0]["result_ref"])

    def test_invalid_manifest_after_evaluation_still_saves_report_and_error(self):
        self.receive()
        source = self.folder / "changing-source"
        for name in self.engine.identity["sources"]:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        box = Inbox(self.box.path, Engine(source))
        self.addCleanup(box.close)
        manifest = source / "reference/required-records/NATIVE-SOURCES.json"
        original_manifest = manifest.read_bytes()
        real_popen = subprocess.Popen
        class CompletedThenChanged:
            def __init__(self, process): self.process, self.pid = process, process.pid
            def poll(self): return self.process.poll()
            def wait(self, timeout=None):
                result = self.process.wait(timeout=timeout)
                manifest.write_bytes(malformed)
                return result
        def launch(command, **kwargs):
            process = real_popen(command, **kwargs)
            return CompletedThenChanged(process) if any(str(arg).endswith("/required_records.py") for arg in command) else process
        for malformed in (b"{broken", b"null", b"[{}]", b"42", b'"text"'):
            with self.subTest(manifest=malformed):
                manifest.write_bytes(original_manifest)
                prepared = box.prepare(encoded(self.plan))
                with patch("recipient_inbox.subprocess.Popen", side_effect=launch):
                    state = box.run(prepared["run_id"])
                self.assertEqual(state["status"], "assessment_error")
                self.assertIsNone(state["head"])
                self.assertTrue(state["report_ref"])
                self.assertTrue(any(error["code"] == "SOURCE_CHANGED" for error in state["errors"]))
                self.assertEqual(coverage(json.loads(box.get(state["report_ref"])))["A"], "present")

    def test_report_runtime_or_source_mismatch_is_preserved_but_not_adopted(self):
        self.receive()
        real_popen = subprocess.Popen
        for field in ("python", "native_sources"):
            with self.subTest(field=field):
                prepared = self.box.prepare(encoded(self.plan))
                class MismatchedReport:
                    def __init__(self, process, output):
                        self.process, self.pid, self.output = process, process.pid, Path(output)
                    def poll(self): return self.process.poll()
                    def wait(self, timeout=None):
                        result = self.process.wait(timeout=timeout)
                        report = json.loads(self.output.read_bytes())
                        report["source_identity"][field] = "DIFFERENT-IDENTITY"
                        self.output.write_bytes(encoded(report))
                        return result
                def launch(command, **kwargs):
                    process = real_popen(command, **kwargs)
                    if any(str(arg).endswith("/required_records.py") for arg in command):
                        return MismatchedReport(process, command[command.index("--output") + 1])
                    return process
                with patch("recipient_inbox.subprocess.Popen", side_effect=launch):
                    state = self.box.run(prepared["run_id"])
                self.assertEqual(state["status"], "assessment_error")
                self.assertIsNone(state["head"])
                self.assertTrue(state["report_ref"])
                self.assertTrue(any(error["code"] == "REPORT_SOURCE_BINDING" for error in state["errors"]))
                self.assertEqual(json.loads(self.box.get(state["report_ref"]))["source_identity"][field], "DIFFERENT-IDENTITY")

    def test_python_binary_change_rejects_old_prepared_job_even_with_same_version_label(self):
        binary = self.folder / "interpreter-fixture"
        binary.write_bytes(b"synthetic interpreter build A")
        selected = self.folder / "selected-python"
        selected.symlink_to(binary)
        runtime = {"python": sys.version, "interpreter": str(selected),
                   "jsonschema_version": self.engine.identity["jsonschema_version"]}
        # Only runtime probing is simulated; the selected path/bytes are real
        # temporary files. No installed interpreter or environment is changed.
        with patch("recipient_inbox.sys.executable", str(selected)), patch("recipient_inbox.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, encoded(runtime), b"")):
            old_engine = Engine(ROOT)
            box = Inbox(self.box.path, old_engine)
            self.addCleanup(box.close)
            prepared = box.prepare(encoded(self.plan))
            binary.write_bytes(b"synthetic interpreter build B")
            with self.assertRaisesRegex(InboxError, "source/runtime selection changed"):
                old_engine.check()
            box.engine = Engine(ROOT)
            with self.assertRaisesRegex(InboxError, "same evaluator/runtime"):
                box.run(prepared["run_id"])
            new_job = box.prepare(encoded(self.plan))
            self.assertNotEqual(new_job["run_id"], prepared["run_id"])

    def test_interrupt_during_evaluation_keeps_fixed_input_resumable(self):
        self.receive()
        prepared = self.box.prepare(encoded(self.plan))
        real_popen = subprocess.Popen
        class Interrupted:
            def __init__(self, process): self.process, self.pid, self.first = process, process.pid, True
            def poll(self): return self.process.poll()
            def wait(self, timeout=None):
                if self.first:
                    self.first = False
                    raise KeyboardInterrupt()
                return self.process.wait(timeout=timeout)
        def launch(command, **kwargs):
            process = real_popen(command, **kwargs)
            return Interrupted(process) if any(str(arg).endswith("/required_records.py") for arg in command) else process
        with patch("recipient_inbox.subprocess.Popen", side_effect=launch), self.assertRaises(KeyboardInterrupt):
            self.box.run(prepared["run_id"])
        self.assertEqual(self.box.status(prepared["run_id"])["status"], "prepared")
        self.assertEqual(self.box.run(prepared["run_id"])["status"], "completed")

    def test_utf8_plan_cannot_expand_into_oversized_prepared_review(self):
        self.receive()
        first, _ = self.assess()
        plan = next_plan(self.plan)
        basis = deepcopy(plan["collection_basis_ref"])
        basis["media_type"] = "\u0080" * 128
        template = deepcopy(plan["review_set"]["requirements"][0])
        rows = []
        for index in range(80):
            row = deepcopy(template)
            row["requirement_id"] = f"extra-{index}"
            row["subject"]["operation_id"] = f"extra-{index}"
            row["subject"]["native_context"]["transaction_id"] = f"extra-{index}"
            row["basis_refs"] = [basis] * 16
            rows.append(row)
        plan["review_set"]["requirements"].extend(rows)
        raw = json.dumps(plan, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertLess(len(raw), MIB)
        self.assertGreater(len(encoded(plan["review_set"])), MIB)
        before = self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        with self.assertRaises(InboxError) as caught:
            self.box.prepare(raw)
        self.assertEqual(caught.exception.code, "METADATA_BOUND")
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0], before)
        self.assertEqual(self.box.status(first["run_id"])["head"], first["run_id"])

    def test_runtime_identity_ignores_caller_only_package_metadata(self):
        overlay = self.folder / "overlay"
        dist = overlay / "jsonschema-99.0.0.dist-info"
        dist.mkdir(parents=True)
        (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: jsonschema\nVersion: 99.0.0\n")
        sys.path.insert(0, str(overlay))
        try:
            import importlib.metadata
            self.assertEqual(importlib.metadata.version("jsonschema"), "99.0.0")
            current = Engine(ROOT)
            self.assertEqual(current.identity["jsonschema_version"], self.engine.identity["jsonschema_version"])
            self.assertNotEqual(current.identity["jsonschema_version"], "99.0.0")
            self.engine.check()
        finally:
            sys.path.remove(str(overlay))

    def test_other_namespace_is_not_selected(self):
        self.receive()
        self.receive("other", entry_id="unknown", originals={"unknown": b"opaque"}, kind="unmapped", namespace="other-receiver")
        _, report = self.assess()
        self.assertEqual(coverage(report), {"A": "present", "B": "missing"})

    def test_completed_run_is_not_evaluated_or_overwritten_again(self):
        self.receive()
        first, _ = self.assess()
        original = self.box.get(first["report_ref"])
        self.assertEqual(self.box.run(first["run_id"]), first)
        self.assertEqual(self.box.get(first["report_ref"]), original)

    def test_prepared_job_survives_abrupt_process_exit_and_resumes_in_cli(self):
        self.receive(originals={"admission": self.admission})
        plan_path = self.folder / "plan.json"; plan_path.write_bytes(encoded(self.plan))
        result = self.child("from recipient_inbox import *; "
                            "box=Inbox(sys.argv[3],Engine(sys.argv[2])); "
                            "job=box.prepare(Path(sys.argv[4]).read_bytes()); "
                            "print(json.dumps(job),flush=True); os._exit(73)", plan_path)
        self.assertEqual(result.returncode, 73, result.stderr.decode())
        prepared = json.loads(result.stdout)
        resumed = subprocess.run(self.command("run", prepared["run_id"]), capture_output=True, timeout=TEST_PROCESS_TIMEOUT)
        self.assertEqual(resumed.returncode, 0, resumed.stdout.decode() + resumed.stderr.decode())
        state = json.loads(resumed.stdout)
        self.assertEqual(state["status"], "completed")
        self.assertEqual(coverage(json.loads(self.box.get(state["report_ref"])))["A"], "missing")

    def test_abrupt_exit_during_receive_does_not_leave_partial_delivery(self):
        raw = delivery(self.box, self.plan, "interrupted", {"post": self.post})
        payload = self.folder / "delivery.json"; payload.write_bytes(raw)
        code = ("from recipient_inbox import *; box=Inbox(sys.argv[3],Engine(sys.argv[2])); "
                "box.db.create_function('stop_now',0,lambda:os._exit(74)); "
                "box.db.execute('CREATE TEMP TRIGGER interrupt_slot BEFORE INSERT ON slots BEGIN SELECT stop_now(); END'); "
                "box.receive(Path(sys.argv[4]).read_bytes())")
        result = self.child(code, payload)
        self.assertEqual(result.returncode, 74, result.stderr.decode())
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 0)
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 0)
        self.assertEqual(self.box.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertFalse(self.box.receive(raw)["duplicate"])

    def test_parallel_evaluations_preserve_both_results_and_only_one_history_head(self):
        self.receive()
        ids = [self.box.prepare(encoded(self.plan))["run_id"] for _ in range(2)]
        processes = [subprocess.Popen(self.command("run", run_id), stdout=subprocess.PIPE, stderr=subprocess.PIPE) for run_id in ids]
        states = []
        try:
            for process in processes:
                stdout, stderr = process.communicate(timeout=TEST_PROCESS_TIMEOUT)
                self.assertIn(process.returncode, (0, 64), stderr.decode())
                states.append(json.loads(stdout))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.wait()
        self.assertEqual(sorted(s["status"] for s in states), ["completed", "stale_history"])
        self.assertTrue(all(s["report_ref"] for s in states))
        accepted = next(s for s in states if s["status"] == "completed")
        self.assertTrue(all(self.box.status(run_id)["head"] == accepted["run_id"] for run_id in ids))

    def test_crash_during_result_commit_rolls_back_report_and_head_together(self):
        self.receive()
        prepared = self.box.prepare(encoded(self.plan))
        before = self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        code = ("from recipient_inbox import *; box=Inbox(sys.argv[3],Engine(sys.argv[2])); "
                "box.db.create_function('stop_now',0,lambda:os._exit(75)); "
                "box.db.execute('CREATE TEMP TRIGGER interrupt_commit BEFORE INSERT ON heads BEGIN SELECT stop_now(); END'); "
                "box.run(sys.argv[4])")
        result = self.child(code, prepared["run_id"])
        self.assertEqual(result.returncode, 75, result.stderr.decode())
        self.assertEqual(self.box.status(prepared["run_id"])["status"], "prepared")
        self.assertIsNone(self.box.status(prepared["run_id"])["head"])
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0], before)
        self.assertEqual(self.box.run(prepared["run_id"])["status"], "completed")

    def test_same_prepared_run_can_be_retried_concurrently_without_replacing_result(self):
        self.receive()
        run_id = self.box.prepare(encoded(self.plan))["run_id"]
        processes = [subprocess.Popen(self.command("run", run_id), stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        states = []
        try:
            for process in processes:
                stdout, stderr = process.communicate(timeout=TEST_PROCESS_TIMEOUT)
                self.assertEqual(process.returncode, 0, stderr.decode())
                states.append(json.loads(stdout))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.wait()
        self.assertEqual(states[0], states[1])
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)

    def test_source_change_prevents_resume_of_old_prepared_input(self):
        root_copy = self.folder / "source"
        for name in self.engine.identity["sources"]:
            target = root_copy / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        copied_engine = Engine(root_copy)
        box = Inbox(self.box.path, copied_engine)
        try:
            prepared = box.prepare(encoded(self.plan))
            changed = root_copy / "reference/required-records/required_records.py"
            changed.write_bytes(changed.read_bytes() + b"\n# synthetic wrapper source update\n")
            box.close(); box = Inbox(self.box.path, Engine(root_copy))
            with self.assertRaisesRegex(InboxError, "same evaluator/runtime"):
                box.run(prepared["run_id"])
            self.assertEqual(box.status(prepared["run_id"])["status"], "prepared")
            new_job = box.prepare(encoded(self.plan))
            completed = box.run(new_job["run_id"])
            self.assertEqual(completed["status"], "completed", completed)
            before = box._run(prepared["run_id"])[1]["engine_identity"]
            after = box._run(new_job["run_id"])[1]["engine_identity"]
            self.assertNotEqual(before["sources"]["reference/required-records/required_records.py"],
                                after["sources"]["reference/required-records/required_records.py"])
        finally:
            box.close()

    def test_corrupted_object_is_detected_before_export(self):
        self.receive()
        state, _ = self.assess()
        ref = self.box.put(self.post)
        self.box.db.execute("UPDATE objects SET raw=? WHERE digest=?", (b"tampered", ref["digest"]["value"]))
        with self.assertRaisesRegex(InboxError, "raw-byte identity"):
            self.box.get(ref)
        destination = self.folder / "export"
        with self.assertRaisesRegex(InboxError, "raw-byte identity"):
            self.box.export(state["run_id"], destination)
        self.assertFalse(destination.exists())

    def test_revision_uses_existing_validator_for_removal_and_cutoff_regression(self):
        self.receive(); self.assess()
        changed = next_plan(self.plan)
        changed["review_set"]["requirements"].pop()
        with self.assertRaisesRegex(self.box.v.Problem, "removed prior requirement"):
            self.box.prepare(encoded(changed))
        changed = next_plan(self.plan)
        changed["assessment_cutoff"] = "2026-10-20T11:00:00Z"
        with self.assertRaisesRegex(self.box.v.Problem, "cutoff regressed"):
            self.box.prepare(encoded(changed))
        self.assertEqual(self.box.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)

    def test_future_receipt_assertion_does_not_get_silently_omitted(self):
        self.receive(received="2026-10-20T18:00:00Z")
        with self.assertRaisesRegex(InboxError, "precedes"):
            self.box.prepare(encoded(self.plan))

    def test_export_replays_full_report_and_preserves_previous_history(self):
        self.receive(originals={"admission": self.admission}); first, _ = self.assess()
        self.receive("late", originals={"post": self.post}, received=LATE)
        state, report = self.assess(next_plan(self.plan))
        destination = self.folder / "export"
        self.box.export(state["run_id"], destination)
        self.assertEqual((destination / "report.json").read_bytes(), self.box.get(state["report_ref"]))
        self.assertEqual((destination / first["report_ref"]["path"]).read_bytes(), self.box.get(first["report_ref"]))
        manifest = json.loads((destination / "MANIFEST.json").read_bytes())
        for name, identity in manifest["files"].items():
            raw = (destination / name).read_bytes()
            self.assertEqual({"raw_sha256": sha(raw), "byte_length": len(raw)}, identity)
        output = self.folder / "replayed.json"
        result = subprocess.run([sys.executable, "-B", str(ROOT / "reference/required-records/required_records.py"),
            "--selection", str(destination / "selection.json"), "--base", "inbox=" + str(destination),
            "--source-root", str(ROOT), "--output", str(output)], capture_output=True, timeout=TEST_PROCESS_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        replayed = json.loads(output.read_bytes())
        report["usage"].pop("elapsed_milliseconds"); replayed["usage"].pop("elapsed_milliseconds")
        self.assertEqual(report, replayed)
        with self.assertRaises(FileExistsError):
            self.box.export(state["run_id"], destination)

    def test_non_store_reference_is_rejected(self):
        ref = self.box.put(b"bytes"); ref["path_base"] = "repository"
        with self.assertRaisesRegex(InboxError, "this inbox"):
            self.box.get(ref)

    def test_database_and_input_symlinks_are_rejected(self):
        link = self.folder / "link.sqlite3"; link.symlink_to(self.box.path)
        with self.assertRaisesRegex(InboxError, "regular file"):
            Inbox(link, self.engine)
        file = self.folder / "plain"; file.write_bytes(b"plain")
        link = self.folder / "link"; link.symlink_to(file)
        with self.assertRaises(OSError):
            read_file(link)

    def test_fifo_read_does_not_block(self):
        fifo = self.folder / "pipe"; os.mkfifo(fifo)
        with self.assertRaisesRegex(InboxError, "regular file"):
            read_file(fifo)

    def test_s3_attempt_gains_binding_only_after_all_support_arrives(self):
        sys.path.insert(0, str(ROOT / "reference/runtime-support"))
        from synthetic_s3 import synthetic_current_instance
        instance = synthetic_current_instance(ROOT, self.folder / "synthetic-current-s3")
        bundle = instance / "bundles/supported"
        self.plan["native_policy_refs"]["s3"] = self.box.put((instance / "receiver-policy.json").read_bytes())
        attempt = json.loads((bundle / "attempt.json").read_bytes())["attempt_id"]
        self.plan["review_set"]["requirements"] = self.plan["review_set"]["requirements"][:1]
        row = self.plan["review_set"]["requirements"][0]
        row["subject"].update(kind="attempt", attempt_id=attempt)
        row["binding_profile"] = "vate_s3_attempt_context"
        row["requested_native_checks"].append("s3_observation_binding")
        originals = {name: (bundle / name).read_bytes() for name in self.box.v.MEMBERS if name != "get-body.bin"}
        self.receive(originals=originals, kind="s3_bundle")
        prepared = self.box.prepare(encoded(self.plan)); first = self.box.run(prepared["run_id"])
        report1 = json.loads(self.box.get(first["report_ref"]))
        self.assertEqual(coverage(report1)["A"], "unresolved")
        self.receive("late-body", originals={"get-body.bin": (bundle / "get-body.bin").read_bytes()}, received=LATE, kind="s3_bundle")
        # If incomplete native execution is an invocation error, the next run starts the accepted history.
        _, report2 = self.assess(next_plan(self.plan))
        self.assertEqual(coverage(report2)["A"], "present")
        self.assertIn(b'"retry_authorized":false', encoded(report2))
        self.assertEqual(self.box.get(first["report_ref"]), encoded(report1) + b"\n")

    def test_replay_comparator_does_not_ignore_meaning_or_wrong_size_counter(self):
        from run_trial import compare_replay
        self.receive()
        _, report = self.assess()
        changed = deepcopy(report); changed["usage"]["elapsed_milliseconds"] += 1
        compare_replay(report, changed)
        changed["requirements"][0]["record_coverage"] = "missing"
        with self.assertRaisesRegex(AssertionError, "differs beyond"):
            compare_replay(report, changed)
        changed = deepcopy(report); changed["usage"]["native_result_bytes"] += 1
        with self.assertRaisesRegex(AssertionError, "size counter"):
            compare_replay(report, changed)


class SignatureIntegrationTests(InboxCase):
    # Only these integration tests need the already installed OpenSSL executable.
    def setUp(self):
        super().setUp()
        openssl = os.environ.get("VATE_TRIAL_OPENSSL")
        if not openssl:
            self.skipTest("select installed OpenSSL with VATE_TRIAL_OPENSSL")
        self.sig = signature_fixture(openssl)
        self.box.close()
        self.box = Inbox(self.folder / "inbox.sqlite3", Engine(ROOT, openssl, self.sig.binary_sha256))
        self.plan["native_policy_refs"]["signature"] = self.box.put(encoded(self.sig.policy))
        self.plan["review_set"]["requirements"][0]["requested_native_checks"].append("signatures_and_issuer_authority")

    def test_signed_late_record_then_authority_policy_update_preserves_three_results(self):
        self.receive(originals={"admission": self.admission}, proofs={"admission": self.sig.admission_proof})
        first, _ = self.assess()
        self.receive("late-signed", originals={"post": self.post}, proofs={"post": self.sig.post_proof}, received=LATE)
        second, report = self.assess(next_plan(self.plan))
        result = next(c["result"] for c in report["native_calls"] if "signatures" in c["result"])
        self.assertEqual(coverage(report)["A"], "present")
        self.assertEqual(result["signatures"]["post_execution"]["status"], "verified")
        self.assertEqual(result["issuer_authority"]["post_execution"]["status"], "authorized_under_policy")
        self.assertEqual(result["receipt_assessment"]["native_result"]["record_linkage"], "matched")
        policy = deepcopy(self.sig.policy); policy["grants"] = []
        changed = next_plan(self.plan); changed["native_policy_refs"]["signature"] = self.box.put(encoded(policy))
        third, report3 = self.assess(changed)
        result3 = next(c["result"] for c in report3["native_calls"] if "signatures" in c["result"])
        self.assertEqual(third["revision"], 3)
        self.assertEqual(coverage(report3)["A"], "present")
        self.assertEqual(result3["signatures"]["post_execution"]["status"], "verified")
        self.assertEqual(result3["issuer_authority"]["post_execution"]["status"], "denied")
        self.assertEqual(result3["receipt_assessment"]["requested_checks"]["unsupported"], ["signatures_and_issuer_authority"])
        self.assertEqual(self.box.get(second["report_ref"]), encoded(report) + b"\n")

    def test_policy_execution_error_is_saved_and_does_not_advance_head(self):
        self.receive(proofs={"admission": self.sig.admission_proof, "post": self.sig.post_proof})
        first, _ = self.assess()
        changed = next_plan(self.plan); changed["native_policy_refs"]["signature"] = self.box.put(b"{}")
        job = self.box.prepare(encoded(changed)); state = self.box.run(job["run_id"])
        self.assertEqual(state["status"], "assessment_error")
        self.assertEqual(state["head"], first["run_id"])
        self.assertTrue(state["report_ref"])
        report = json.loads(self.box.get(state["report_ref"]))
        self.assertTrue(report["invocation_errors"])
        self.assertEqual(coverage(report)["A"], "present")


if __name__ == "__main__":
    unittest.main()
