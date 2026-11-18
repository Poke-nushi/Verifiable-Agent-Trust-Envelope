"""Real Inbox/native replay, source retention, failure, and no-execution tests."""
from pathlib import Path
import builtins
import fcntl
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import bridge
import receive_handoff
from bridge import Receiver, InboxError, encode, decode, sha, unb64, b64, replay_export
from demo_connection import capture, choose, EARLY, LATE, FIRST_CUTOFF, FINAL_CUTOFF, ASSESSED
from fixture import Case, Keys


class ConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="vate-handoff-inbox-inputs-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.inputs = Path(cls.temp.name) / "inputs"
        capture(cls.inputs)
        cls.input_hashes = cls.hashes(cls.inputs)

    @staticmethod
    def hashes(folder):
        return {str(p.relative_to(folder)): sha(p.read_bytes()) for p in folder.rglob("*") if p.is_file()}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vate-handoff-inbox-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.receivers = []
        self.addCleanup(lambda: [r.close() for r in self.receivers])
        self.addCleanup(lambda: self.assertEqual(self.hashes(self.inputs), self.input_hashes))

    def receiver(self, name="b-after-unaccepted-a", *, label="test"):
        folder = self.inputs / name
        selected = choose(folder, "runtime-b" if name == "b-after-unaccepted-a" else "runtime-a")
        result = Receiver(self.work / (label + ".sqlite3"), selected, create=True)
        self.receivers.append(result)
        return result, folder

    def receive(self, r, folder, part="before-handoff.json", event="early", at=EARLY):
        result = r.receive(event, (folder / part).read_bytes(), at)
        self.assertEqual(result["status"], "assessed", result)
        self.assertFalse(result["is_execution_ticket"])
        return result

    def finish(self, r, *, cutoff=FINAL_CUTOFF):
        result = r.run(r.prepare(cutoff, ASSESSED)["run_id"])
        if result["inbox"]["status"] != "completed":
            report = decode(r.box.get(result["inbox"]["report_ref"])) if result["inbox"]["report_ref"] else {}
            self.fail(encode({"inbox": result["inbox"], "diagnostics": report.get("diagnostics"),
                "usage": report.get("usage"), "native_errors": [c["result"] for c in report.get("native_calls", [])
                    if c["result"].get("invocation", {}).get("status") != "returned"]}).decode())
        self.assertFalse(result["is_execution_ticket"])
        return result

    def test_unknown_then_B_completion_preserves_frozen_report_and_all_originals(self):
        r, f = self.receiver()
        first = self.receive(r, f)
        prepared = r.prepare(FIRST_CUTOFF, ASSESSED)
        self.receive(r, f, "bundle.json", "later", LATE)
        old = r.run(prepared["run_id"])
        self.assertEqual(old["handoff"]["effect_state"], "unresolved")
        self.assertIsNone(old["handoff"]["accepted"])
        self.assertEqual(old["handoff"]["acceptance_count"], 0)
        self.assertEqual(old["record_coverage"], {"expected-post": "missing"})
        old_raw = r.box.get(old["inbox"]["report_ref"])
        new = self.finish(r)
        self.assertEqual(new["handoff"]["effect_state"], "completed")
        self.assertEqual(new["handoff"]["accepted"]["runtime"], "runtime-b")
        self.assertEqual(new["record_coverage"], {"expected-post": "present"})
        self.assertEqual(len(new["handoff"]["unknown"]), len(old["handoff"]["unknown"]))
        self.assertEqual(new["inbox"]["previous_id"], old["inbox"]["run_id"])
        self.assertEqual(r.box.get(old["inbox"]["report_ref"]), old_raw)
        self.assertEqual(unb64(decode(r.box.get(first["capsule_ref"]))["bundle_b64"]),
                         (f / "before-handoff.json").read_bytes())
        r.export(new["inbox"]["run_id"], self.work / "export")
        self.assertEqual(replay_export(r.selected_raw, self.work / "export")["capsules_reassessed"], 2)
        repeated = r.run(prepared["run_id"])
        self.assertEqual(repeated["handoff"], old["handoff"])
        self.assertEqual(repeated["inbox"]["report_ref"], old["inbox"]["report_ref"])
        self.assertEqual(repeated["inbox"]["head"], new["inbox"]["run_id"])

    def test_A_native_keeps_original_admission_after_handoff(self):
        r, f = self.receiver("a-completed-response-lost")
        self.receive(r, f, "bundle.json")
        result = self.finish(r)
        self.assertEqual(result["handoff"]["accepted"]["runtime"], "runtime-a")
        self.assertEqual(result["handoff"]["runtime"], "runtime-b")
        self.assertEqual(result["record_coverage"], {"expected-post": "present"})
        report = decode(r.box.get(result["inbox"]["report_ref"]))
        linked = [x["result"]["native_result"]["record_linkage"] for x in report["native_calls"]]
        self.assertIn("matched", linked)
        self.assertIn("current_permission_to_execute", report["not_checked"])

    def test_zero_partial_and_expired_results_remain_distinct(self):
        for name in ("accepted-zero-effects", "accepted-partial-effects", "effect-completed-outside-admission"):
            with self.subTest(name=name):
                r, f = self.receiver(name, label=name)
                self.receive(r, f, "bundle.json")
                result = self.finish(r)
                if name.startswith("accepted-"):
                    self.assertEqual(result["handoff"]["effect_state"], "unresolved")
                    self.assertEqual(result["record_coverage"]["expected-post"], "missing")
                    self.assertIsNone(result["handoff"]["post_execution_receipt"])
                else:
                    self.assertEqual(result["handoff"]["effect_state"], "completed")
                    self.assertEqual(result["handoff"]["linkage"]["outcome"], "failed")
                    self.assertIn("POST_EXEC_ADMISSION_EXPIRED", result["handoff"]["linkage"]["reason_codes"])

    def test_later_observation_does_not_manufacture_competing_native_receipt(self):
        r, f = self.receiver("completed-then-observed-later")
        self.receive(r, f)
        self.receive(r, f, "bundle.json", "later", LATE)
        result = self.finish(r)
        self.assertEqual(result["record_coverage"]["expected-post"], "present")
        report = decode(r.box.get(result["inbox"]["report_ref"]))
        self.assertEqual(report["requirements"][0]["unique_candidates"], 1)
        posts = [unb64(c["evaluation"]["projection"][0]["post_b64"])
                 for _, c in r.capsules() if c["evaluation"]["projection"][0]["post_b64"]]
        self.assertTrue(posts)
        self.assertEqual(len(set(posts)), 1)

    def test_malformed_records_are_retained_without_receipt_projection(self):
        r, f = self.receiver()
        before = self.receive(r, f)
        original = decode((f / "bundle.json").read_bytes())
        for index, value in enumerate(([None], [{}], "bad")):
            raw = encode({**original, "records": value})
            result = r.receive("bad-" + str(index), raw, LATE)
            self.assertEqual(result["status"], "unassessable")
            capsule = decode(r.box.get(result["capsule_ref"]))
            self.assertEqual(unb64(capsule["bundle_b64"]), raw)
            self.assertEqual(capsule["evaluation"]["projection"], [])
            self.assertIsNone(result["effect_state"])
        final = self.finish(r)
        self.assertEqual(final["handoff"]["bundle_sha256"],
                         decode(r.box.get(before["capsule_ref"]))["evaluation"]["handoff"]["bundle_sha256"])
        self.assertEqual(final["record_coverage"]["expected-post"], "missing")

    def test_wrong_context_and_tampered_history_are_rejected(self):
        r, f = self.receiver()
        wrong = (self.inputs / "accepted-zero-effects/bundle.json").read_bytes()
        self.assertEqual(r.receive("wrong", wrong, EARLY)["status"], "unassessable")
        value = decode((f / "bundle.json").read_bytes())
        value["records"][0]["sha256"] = "0" * 64
        self.assertEqual(r.receive("tamper", encode(value), EARLY)["status"], "unassessable")
        self.assertEqual(r.box.db.execute("SELECT count(*) FROM entries WHERE namespace=?", (r.s["namespace"],)).fetchone()[0], 0)

    def test_regressed_snapshot_cannot_replace_later_evidence(self):
        r, f = self.receiver()
        self.receive(r, f, "bundle.json", "final", EARLY)
        bad = r.receive("old", (f / "before-handoff.json").read_bytes(), LATE)
        self.assertEqual(bad["reason"], "HISTORY_NOT_EXTENSION")
        self.assertEqual(self.finish(r)["handoff"]["effect_state"], "completed")

    def test_duplicate_idempotence_and_conflicting_event(self):
        r, f = self.receiver()
        result = self.receive(r, f)
        before = r.box.db.execute("SELECT count(*) FROM deliveries").fetchone()[0]
        duplicate = self.receive(r, f)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["capsule_ref"], result["capsule_ref"])
        self.assertEqual(r.box.db.execute("SELECT count(*) FROM deliveries").fetchone()[0], before)
        with self.assertRaisesRegex(InboxError, "EVENT_ID_CONFLICT"):
            r.receive("early", (f / "bundle.json").read_bytes(), EARLY)

    def test_interrupted_storage_resumes_without_another_source_event(self):
        r, f = self.receiver()
        real = r.box.receive
        def fail_projection(raw):
            if decode(raw)["native_input_kind"] == "receipt_pair":
                raise OSError("synthetic storage interruption")
            return real(raw)
        with patch.object(r.box, "receive", side_effect=fail_projection):
            with self.assertRaises(OSError):
                r.receive("early", (f / "before-handoff.json").read_bytes(), EARLY)
        self.assertEqual(len(r.capsules()), 1)
        self.assertTrue(self.receive(r, f)["duplicate"])
        self.assertEqual(len(r.capsules()), 1)
        self.assertEqual(self.finish(r)["handoff"]["effect_state"], "unresolved")

    def test_busy_and_io_failures_are_not_unexecuted_verdicts(self):
        r, f = self.receiver()
        with r.lock():
            with self.assertRaises(BlockingIOError):
                r.receive("busy", (f / "bundle.json").read_bytes(), EARLY)
        with patch.object(bridge, "evaluate", side_effect=OSError("synthetic read error")):
            with self.assertRaises(OSError):
                r.receive("io", (f / "bundle.json").read_bytes(), EARLY)
        self.assertEqual(r.capsules(), [])

    def test_unknown_arrival_and_old_cutoff_do_not_include_future_results(self):
        r, f = self.receiver()
        self.receive(r, f)
        self.receive(r, f, "bundle.json", "later", LATE)
        old = self.finish(r, cutoff=FIRST_CUTOFF)
        self.assertEqual(old["handoff"]["effect_state"], "unresolved")
        self.assertEqual(old["record_coverage"]["expected-post"], "missing")
        r2, f2 = self.receiver(label="unknown-arrival")
        self.receive(r2, f2, "bundle.json", "unknown-time", None)
        result = self.finish(r2)
        self.assertIsNone(result["handoff"])
        self.assertEqual(result["record_coverage"]["expected-post"], "unresolved")

    def test_missing_actual_times_keeps_native_without_inventing_post(self):
        keydir = self.work / "keys"
        keydir.mkdir()
        def interrupt(point):
            if point == "after_file_2":
                raise RuntimeError("synthetic interrupted observation")
        case = Case(self.work / "provider", Keys(keydir), hook=interrupt)
        case.submit()
        case.reopen()
        with case.provider.connection(write=True) as db:
            state, records = case.provider.load(db)
            op = state["operations"]["operation-one"]
            ticket = op["tickets"][op["accepted"]["attempt_id"]]
            native = {k: ticket[k] for k in ("attempt_id", "runtime", "admission_sha256", "input_sha256")}
            native.update(started_at=None, finished_at=None, outputs=case.provider.inventory(case.operation))
            case.provider.append(db, state, records, "native", "operation-one", native, case.clock())
            db.commit()
        (self.work / "context.json").write_bytes(case.context_raw)
        (self.work / "operation.json").write_bytes(encode(case.operation))
        r = Receiver(self.work / "missing-time.sqlite3", choose(self.work, "runtime-a"), create=True)
        self.receivers.append(r)
        r.receive("actual-time-missing", case.provider.export("operation-one"), EARLY)
        result = self.finish(r)
        self.assertEqual(result["handoff"]["effect_state"], "completed")
        self.assertEqual(result["handoff"]["linkage"]["outcome"], "unassessable")
        self.assertIsNone(result["handoff"]["post_execution_receipt"])
        self.assertEqual(result["record_coverage"]["expected-post"], "missing")

    def test_unknown_arrival_cannot_gain_cutoff_membership_in_export(self):
        r, folder = self.receiver("a-completed-response-lost")
        self.receive(r, folder, "bundle.json", at=None)
        final = self.finish(r)
        self.assertEqual(final["record_coverage"], {"expected-post": "unresolved"})
        self.assertIsNone(final["handoff"])
        original = self.work / "unknown-export"
        r.export(final["inbox"]["run_id"], original)
        before = self.hashes(original)
        report_raw = r.box.get(final["inbox"]["report_ref"])
        self.assertTrue(replay_export(r.selected_raw, original)["required_records_replayed"])
        for membership, coverage in (("included", "present"), ("after", "missing")):
            with self.subTest(membership=membership):
                export = self.work / membership
                shutil.copytree(original, export)
                manifest = decode((export / "MANIFEST.json").read_bytes())
                frozen = decode((export / "selection.json").read_bytes())
                snapshot = decode((export / frozen["submission_snapshot_ref"]["path"]).read_bytes())
                changed = 0
                for entry in snapshot["entries"]:
                    for record in entry["originals"].values():
                        if record is not None:
                            self.assertIsNone(record["received_at"])
                            self.assertEqual(record["cutoff_membership"], "unknown")
                            record["cutoff_membership"] = membership
                            changed += 1
                self.assertEqual(changed, 3)
                def store(name, raw):
                    (export / name).write_bytes(raw)
                    manifest["files"][name] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
                raw = encode(snapshot)
                frozen["submission_snapshot_ref"] = bridge.raw_ref(raw)
                store(frozen["submission_snapshot_ref"]["path"], raw)
                store("selection.json", encode(frozen))
                # Generate a matching report with the generic evaluator: it may
                # accept independent membership assertions; this bridge may not.
                output = self.work / (membership + "-report.json")
                done = subprocess.run([sys.executable, "-E", "-s", "-B",
                    str(bridge.ROOT / "reference/required-records/required_records.py"),
                    "--selection", str(export / "selection.json"), "--base", "inbox=" + str(export),
                    "--source-root", str(bridge.ROOT), "--output", str(output)],
                    capture_output=True, timeout=120)
                self.assertEqual(done.returncode, 0, done.stderr.decode() + done.stdout.decode())
                self.assertEqual(decode(output.read_bytes())["requirements"][0]["record_coverage"], coverage)
                store("report.json", output.read_bytes())
                (export / "MANIFEST.json").write_bytes(encode(manifest))
                with self.assertRaisesRegex(InboxError, "PROJECTION_CUTOFF_MEMBERSHIP"):
                    replay_export(r.selected_raw, export)
        self.assertEqual(self.hashes(original), before)
        self.assertEqual(r.box.get(final["inbox"]["report_ref"]), report_raw)

    def test_known_arrival_cutoff_boundary_replays(self):
        for index, (arrival, expected) in enumerate(((EARLY, "present"), (FIRST_CUTOFF, "present"), (LATE, "missing"))):
            with self.subTest(arrival=arrival):
                r, folder = self.receiver("a-completed-response-lost", label="boundary-" + str(index))
                self.receive(r, folder, "bundle.json", at=arrival)
                final = self.finish(r, cutoff=FIRST_CUTOFF)
                self.assertEqual(final["record_coverage"]["expected-post"], expected)
                self.assertEqual(final["handoff"] is None, expected == "missing")
                export = self.work / ("boundary-" + arrival)
                r.export(final["inbox"]["run_id"], export)
                self.assertTrue(replay_export(r.selected_raw, export)["required_records_replayed"])

    def test_replay_normalizes_runtime_measurements_only(self):
        r, folder = self.receiver("a-completed-response-lost")
        self.receive(r, folder, "bundle.json")
        final = self.finish(r)
        raw = r.box.get(final["inbox"]["report_ref"])
        old = decode(raw)
        # Receipt-pair reports do not use a temporary bundle path. Add that
        # generic report field only for this comparison-contract unit probe;
        # the export/replay tests exercise unmodified real evaluator reports.
        old["native_calls"][0]["result"]["inputs"]["bundle"] = {"selected_path": "/old/tmp/bundle.json"}
        old["usage"]["native_result_bytes"] = sum(len(bridge.encoded(c["result"])) for c in old["native_calls"])
        new = decode(encode(old))
        new["usage"]["elapsed_milliseconds"] += 123
        paths = 0
        for call in new["native_calls"]:
            bundle = call["result"].get("inputs", {}).get("bundle")
            if isinstance(bundle, dict) and "selected_path" in bundle:
                bundle["selected_path"] = "/a/different/temporary/snapshot/path/bundle.json"
                paths += 1
        self.assertGreater(paths, 0)
        new["usage"]["native_result_bytes"] = sum(len(bridge.encoded(c["result"])) for c in new["native_calls"])
        def reversed_members(value):
            if isinstance(value, dict):
                return {key: reversed_members(item) for key, item in reversed(list(value.items()))}
            if isinstance(value, list):
                return [reversed_members(item) for item in value]
            return value
        new = reversed_members(new)
        old_bytes, new_bytes = encode(old), encode(new)
        differences = bridge.compare_replay(old, new)
        self.assertEqual(len(differences), paths + 2)
        self.assertEqual((encode(old), encode(new)), (old_bytes, new_bytes))
        mutations = (
            lambda x: x.update(assessment_cutoff=EARLY),
            lambda x: x["requirements"][0].update(record_coverage="missing"),
            lambda x: x["requirements"][0]["reasons"].append("unexpected_reason"),
            lambda x: x["selection_identity"].update(raw_sha256="0" * 64),
            lambda x: x["usage"].update(native_result_bytes=x["usage"]["native_result_bytes"] + 1),
            lambda x: x["usage"].update(elapsed_milliseconds=-1),
            lambda x: x["usage"].update(elapsed_milliseconds=False),
            lambda x: x.update(invocation_errors=int(x["invocation_errors"])),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                different = decode(new_bytes)
                mutate(different)
                preserved = encode(different)
                with self.assertRaisesRegex(InboxError, "REPLAY_REPORT_MISMATCH"):
                    bridge.compare_replay(old, different)
                with self.assertRaisesRegex(InboxError, "REPLAY_REPORT_MISMATCH"):
                    bridge.compare_replay(different, old)
                self.assertEqual((encode(old), encode(different)), (old_bytes, preserved))
        self.assertEqual(r.box.get(final["inbox"]["report_ref"]), raw)

    def test_cli_replay_rejects_report_type_changes(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                r, folder = self.receiver("a-completed-response-lost", label="types-" + str(empty))
                if not empty:
                    self.receive(r, folder, "bundle.json")
                final = self.finish(r)
                original_report = r.box.get(final["inbox"]["report_ref"])
                original = self.work / ("types-original-" + str(empty))
                r.export(final["inbox"]["run_id"], original)
                original_hashes = self.hashes(original)
                selected = self.work / ("types-selection-" + str(empty) + ".json")
                selected.write_bytes(r.selected_raw)
                command = [sys.executable, "-E", "-s", "-B", str(bridge.HERE / "receive_handoff.py"),
                           "--selection", str(selected), "replay"]
                control = subprocess.run(command + [str(original)], capture_output=True, timeout=120)
                self.assertEqual(control.returncode, 0, control.stderr.decode())
                self.assertTrue(decode(control.stdout)["required_records_replayed"])
                self.assertIs(decode(control.stdout)["is_execution_ticket"], False)
                fields = ("invocation_errors", "native_result_bytes") if empty else ("invocation_errors",)
                for field in fields:
                    with self.subTest(field=field):
                        export = self.work / ("types-mutated-" + str(empty) + "-" + field)
                        shutil.copytree(original, export)
                        report = decode((export / "report.json").read_bytes())
                        if field == "invocation_errors":
                            self.assertIs(report[field], False)
                            report[field] = 0
                        else:
                            self.assertEqual(report["native_calls"], [])
                            self.assertIs(type(report["usage"][field]), int)
                            self.assertEqual(report["usage"][field], 0)
                            report["usage"][field] = False
                            fresh = decode(original_report)
                            for left, right in ((report, fresh), (fresh, report)):
                                with self.assertRaisesRegex(InboxError, "REPLAY_REPORT_MISMATCH"):
                                    bridge.compare_replay(left, right)
                        raw = encode(report)
                        (export / "report.json").write_bytes(raw)
                        manifest = decode((export / "MANIFEST.json").read_bytes())
                        manifest["files"]["report.json"] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
                        (export / "MANIFEST.json").write_bytes(encode(manifest))
                        before = self.hashes(export)
                        done = subprocess.run(command + [str(export)], capture_output=True, timeout=120)
                        self.assertEqual(done.returncode, 3, done.stderr.decode() + done.stdout.decode())
                        self.assertEqual(decode(done.stdout), {"status": "operation_error",
                            "reason": "REPLAY_REPORT_MISMATCH", "is_execution_ticket": False})
                        self.assertEqual(done.stderr, b"")
                        self.assertEqual(self.hashes(export), before)
                self.assertEqual(self.hashes(original), original_hashes)
                self.assertEqual(r.box.get(final["inbox"]["report_ref"]), original_report)

    def test_replay_reference_shapes_are_structured_errors(self):
        r, _ = self.receiver(label="reference-shapes")
        final = self.finish(r)
        saved_report = r.box.get(final["inbox"]["report_ref"])
        original = self.work / "reference-original"
        r.export(final["inbox"]["run_id"], original)
        original_hashes = self.hashes(original)
        selected = self.work / "reference-selection.json"
        selected.write_bytes(r.selected_raw)
        command = [sys.executable, "-E", "-s", "-B", str(bridge.HERE / "receive_handoff.py"),
                   "--selection", str(selected), "replay"]
        mutations = [("digest", value) for value in (None, [], "bad", 0, False)]
        mutations += [("digest.value", value) for value in (None, [], {}, 0, False, "", "A" * 64)]
        mutations += [("byte_length", value) for value in (None, False, -1)]
        mutations += [("media_type", value) for value in (None, [], False)]
        for field in ("selection_basis_ref", "review_set_ref", "submission_snapshot_ref"):
            for index, (key, value) in enumerate(mutations):
                export = self.work / (field + "-" + str(index))
                shutil.copytree(original, export)
                frozen = decode((export / "selection.json").read_bytes())
                if key == "digest.value":
                    frozen[field]["digest"]["value"] = value
                else:
                    frozen[field][key] = value
                raw = encode(frozen)
                (export / "selection.json").write_bytes(raw)
                manifest = decode((export / "MANIFEST.json").read_bytes())
                manifest["files"]["selection.json"] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
                (export / "MANIFEST.json").write_bytes(encode(manifest))
                before = self.hashes(export)
                with self.subTest(field=field, key=key, value=value, entry="api"):
                    with self.assertRaisesRegex(InboxError, "EXPORT_REFERENCE"):
                        replay_export(r.selected_raw, export)
                    self.assertEqual(self.hashes(export), before)
                if key == "digest" and value in (None, []):
                    with self.subTest(field=field, key=key, value=value, entry="cli"):
                        done = subprocess.run(command + [str(export)], capture_output=True, timeout=120)
                        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
                        self.assertEqual(decode(done.stdout), {"status": "operation_error",
                            "reason": "EXPORT_REFERENCE", "is_execution_ticket": False})
                        self.assertEqual(done.stderr, b"")
                        self.assertEqual(self.hashes(export), before)
        self.assertTrue(replay_export(r.selected_raw, original)["required_records_replayed"])
        self.assertEqual(self.hashes(original), original_hashes)
        self.assertEqual(r.box.get(final["inbox"]["report_ref"]), saved_report)

    def test_replay_report_container_shapes_are_structured_errors(self):
        r, folder = self.receiver("a-completed-response-lost", label="report-shapes")
        self.receive(r, folder, "bundle.json")
        final = self.finish(r)
        saved_report = r.box.get(final["inbox"]["report_ref"])
        valid = decode(saved_report)
        mutations = []
        for value in (None, [], False, 0, "bad"):
            mutations += [("usage", value), ("native_calls", value), ("result", value), ("inputs", value)]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                changed = decode(saved_report)
                if field in ("usage", "native_calls"):
                    changed[field] = value
                elif field == "result":
                    changed["native_calls"][0]["result"] = value
                else:
                    changed["native_calls"][0]["result"]["inputs"] = value
                if field in ("result", "inputs"):
                    changed["usage"]["native_result_bytes"] = sum(
                        len(bridge.encoded(call["result"])) for call in changed["native_calls"])
                before = encode(changed)
                for left, right in ((changed, valid), (valid, changed)):
                    with self.assertRaisesRegex(InboxError, "REPLAY_REPORT_MISMATCH"):
                        bridge.compare_replay(left, right)
                self.assertEqual(encode(changed), before)
        original = self.work / "report-original"
        r.export(final["inbox"]["run_id"], original)
        saved = self.hashes(original)
        selected = self.work / "report-selection.json"
        selected.write_bytes(r.selected_raw)
        for field in ("result", "inputs"):
            export = self.work / ("report-" + field)
            shutil.copytree(original, export)
            changed = decode(saved_report)
            call = changed["native_calls"][0]
            (call if field == "result" else call["result"])[field] = None
            changed["usage"]["native_result_bytes"] = sum(
                len(bridge.encoded(c["result"])) for c in changed["native_calls"])
            raw = encode(changed)
            (export / "report.json").write_bytes(raw)
            manifest = decode((export / "MANIFEST.json").read_bytes())
            manifest["files"]["report.json"] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
            (export / "MANIFEST.json").write_bytes(encode(manifest))
            before = self.hashes(export)
            with self.subTest(field=field, entry="cli"):
                done = subprocess.run([sys.executable, "-E", "-s", "-B", str(bridge.HERE / "receive_handoff.py"),
                    "--selection", str(selected), "replay", str(export)], capture_output=True, timeout=120)
                self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
                self.assertEqual(decode(done.stdout), {"status": "operation_error",
                    "reason": "REPLAY_REPORT_MISMATCH", "is_execution_ticket": False})
                self.assertEqual(done.stderr, b"")
                self.assertEqual(self.hashes(export), before)
        self.assertTrue(replay_export(r.selected_raw, original)["required_records_replayed"])
        self.assertEqual(self.hashes(original), saved)
        self.assertEqual(r.box.get(final["inbox"]["report_ref"]), saved_report)

    def test_cli_replay_manifest_shapes_are_structured_errors(self):
        r, folder = self.receiver("a-completed-response-lost")
        self.receive(r, folder, "bundle.json")
        final = self.finish(r)
        original_report = r.box.get(final["inbox"]["report_ref"])
        original = self.work / "manifest-original"
        r.export(final["inbox"]["run_id"], original)
        original_hashes = self.hashes(original)
        selected = self.work / "manifest-selection.json"
        selected.write_bytes(r.selected_raw)
        command = [sys.executable, "-E", "-s", "-B", str(bridge.HERE / "receive_handoff.py"),
                   "--selection", str(selected), "replay"]
        for index, manifest in enumerate(([], None, "invalid", False, 0, {}, {"files": []})):
            with self.subTest(manifest=manifest):
                export = self.work / ("manifest-invalid-" + str(index))
                shutil.copytree(original, export)
                (export / "MANIFEST.json").write_bytes(encode(manifest))
                before = self.hashes(export)
                done = subprocess.run(command + [str(export)], capture_output=True, timeout=120)
                self.assertEqual(done.returncode, 3, done.stderr.decode() + done.stdout.decode())
                self.assertEqual(decode(done.stdout), {"status": "operation_error", "reason": "EXPORT_MANIFEST",
                                                      "is_execution_ticket": False})
                self.assertEqual(done.stderr, b"")
                self.assertEqual(self.hashes(export), before)
        control = subprocess.run(command + [str(original)], capture_output=True, timeout=120)
        self.assertEqual(control.returncode, 0, control.stderr.decode())
        self.assertEqual(decode(control.stdout), {"capsules_reassessed": 1,
            "required_records_replayed": True, "is_execution_ticket": False})
        self.assertEqual(control.stderr, b"")
        self.assertEqual(self.hashes(original), original_hashes)
        self.assertEqual(r.box.get(final["inbox"]["report_ref"]), original_report)

    def test_cli_replay_requires_all_control_file_membership(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                r, folder = self.receiver("a-completed-response-lost", label="membership-" + str(empty))
                if not empty:
                    self.receive(r, folder, "bundle.json")
                final = self.finish(r)
                original_report = r.box.get(final["inbox"]["report_ref"])
                original = self.work / ("membership-original-" + str(empty))
                r.export(final["inbox"]["run_id"], original)
                moved = self.work / ("membership moved evidence " + str(empty))
                original.rename(moved)
                saved = self.hashes(moved)
                selected = self.work / ("membership-selection-" + str(empty) + ".json")
                selected.write_bytes(r.selected_raw)
                command = [sys.executable, "-E", "-s", "-B", str(bridge.HERE / "receive_handoff.py"),
                           "--selection", str(selected), "replay"]
                control = subprocess.run(command + [str(moved)], capture_output=True, timeout=120)
                self.assertEqual(control.returncode, 0, control.stdout + control.stderr)
                self.assertEqual(decode(control.stdout), {"capsules_reassessed": 0 if empty else 1,
                    "required_records_replayed": True, "is_execution_ticket": False})
                cases = [("changed-report-listed", None, False, True, "EXPORT_HASH"),
                         ("changed-report-unlisted", "report.json", False, True, "EXPORT_MEMBERSHIP")]
                cases += [(name + "-" + str(remove), name, remove, False, "EXPORT_MEMBERSHIP")
                          for name in ("selection.json", "report.json", "runs.json") for remove in (False, True)]
                for label, missing, remove, change_report, reason in cases:
                    with self.subTest(case=label):
                        export = self.work / ("membership-" + str(empty) + "-" + label)
                        shutil.copytree(moved, export)
                        if change_report:
                            report = decode((export / "report.json").read_bytes())
                            report["usage"]["elapsed_milliseconds"] += 100000
                            (export / "report.json").write_bytes(encode(report))
                        if missing is not None:
                            manifest = decode((export / "MANIFEST.json").read_bytes())
                            del manifest["files"][missing]
                            (export / "MANIFEST.json").write_bytes(encode(manifest))
                            if remove:
                                (export / missing).unlink()
                        before = self.hashes(export)
                        done = subprocess.run(command + [str(export)], capture_output=True, timeout=120)
                        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
                        self.assertEqual(decode(done.stdout), {"status": "operation_error", "reason": reason,
                                                              "is_execution_ticket": False})
                        self.assertEqual(done.stderr, b"")
                        self.assertEqual(self.hashes(export), before)
                self.assertEqual(self.hashes(moved), saved)
                self.assertEqual(r.box.get(final["inbox"]["report_ref"]), original_report)

    def test_replay_manifest_contract_and_entry_metadata(self):
        r, _ = self.receiver(label="manifest-metadata")
        final = self.finish(r)
        original_report = r.box.get(final["inbox"]["report_ref"])
        original = self.work / "manifest-metadata-original"
        r.export(final["inbox"]["run_id"], original)
        original_hashes = self.hashes(original)
        manifest = decode((original / "MANIFEST.json").read_bytes())
        # Empty diagnostic output is a legitimate stored object. False and 0.0
        # compare equal to its length in Python, but are not integer metadata.
        empty_name = next(name for name, item in manifest["files"].items() if item["byte_length"] == 0)
        mutations = [({"missing_contract": True}, "EXPORT_MANIFEST")]
        mutations += [({"contract": value}, "EXPORT_MANIFEST") for value in (None, False, 0, "other", [])]
        mutations += [({"entry": value}, "EXPORT_MANIFEST_ENTRY") for value in (None, [], False, 0, "bad")]
        mutations += [({"missing_field": key}, "EXPORT_MANIFEST_ENTRY") for key in ("raw_sha256", "byte_length")]
        mutations += [({"field": "raw_sha256", "value": value}, "EXPORT_MANIFEST_ENTRY")
                      for value in (None, False, 0, [], "", "a" * 63, "A" * 64, "a" * 64 + "\n")]
        mutations += [({"field": "byte_length", "value": value}, "EXPORT_MANIFEST_ENTRY")
                      for value in (None, False, True, "0", -1, [])]
        mutations.append(({"field": "byte_length", "value": 0.0}, "floating-point JSON tokens"))
        for index, (mutation, reason) in enumerate(mutations):
            with self.subTest(mutation=mutation):
                export = self.work / ("manifest-metadata-" + str(index))
                shutil.copytree(original, export)
                changed = decode(encode(manifest))
                if "missing_contract" in mutation:
                    del changed["contract"]
                elif "contract" in mutation:
                    changed["contract"] = mutation["contract"]
                elif "entry" in mutation:
                    changed["files"][empty_name] = mutation["entry"]
                elif "missing_field" in mutation:
                    del changed["files"][empty_name][mutation["missing_field"]]
                else:
                    changed["files"][empty_name][mutation["field"]] = mutation["value"]
                (export / "MANIFEST.json").write_bytes(encode(changed))
                before = self.hashes(export)
                error_type = InboxError if reason.startswith("EXPORT_") else ValueError
                with self.assertRaisesRegex(error_type, reason):
                    replay_export(r.selected_raw, export)
                self.assertEqual(self.hashes(export), before)
        # Existing open metadata shapes remain open; known required fields keep
        # their original meaning. Recalculated runtime measurements still replay.
        annotated = self.work / "manifest-annotated"
        shutil.copytree(original, annotated)
        manifest["annotation"] = {"owner_note": "retained extension"}
        for item in manifest["files"].values():
            item["annotation"] = None
        (annotated / "MANIFEST.json").write_bytes(encode(manifest))
        before = self.hashes(annotated)
        self.assertTrue(replay_export(r.selected_raw, annotated)["required_records_replayed"])
        self.assertEqual(self.hashes(annotated), before)
        self.assertEqual(self.hashes(original), original_hashes)
        self.assertEqual(r.box.get(final["inbox"]["report_ref"]), original_report)

    def test_native_replay_consumes_only_the_verified_snapshot(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                r, folder = self.receiver("a-completed-response-lost", label="snapshot-" + str(empty))
                if not empty:
                    self.receive(r, folder, "bundle.json")
                final = self.finish(r)
                original_report = r.box.get(final["inbox"]["report_ref"])
                export = self.work / ("snapshot-export-" + str(empty))
                r.export(final["inbox"]["run_id"], export)
                note = b"Unlisted local note; not evaluation input."
                extra_object = "objects/" + sha(note)
                (export / extra_object).write_bytes(note)
                (export / "owner-note.txt").write_bytes(note)
                before = self.hashes(export)
                original_selection = (export / "selection.json").read_bytes()
                run = bridge.subprocess.run
                observed = []
                def change_original_at_native_start(arguments, *args, **kwargs):
                    if str(bridge.ROOT / "reference/required-records/required_records.py") not in arguments:
                        return run(arguments, *args, **kwargs)
                    base = Path(arguments[arguments.index("--base") + 1].removeprefix("inbox="))
                    observed.append({"base": base, "extra_object": (base / extra_object).exists(),
                                     "note": (base / "owner-note.txt").exists()})
                    # A deterministic change between validation and native read:
                    # the evaluator must use the already verified selection.
                    (export / "selection.json").write_bytes(b"null")
                    try:
                        return run(arguments, *args, **kwargs)
                    finally:
                        (export / "selection.json").write_bytes(original_selection)
                with patch.object(bridge.subprocess, "run", side_effect=change_original_at_native_start):
                    result = replay_export(r.selected_raw, export)
                self.assertEqual(result, {"capsules_reassessed": 0 if empty else 1,
                    "required_records_replayed": True, "is_execution_ticket": False})
                self.assertEqual(len(observed), 1)
                self.assertNotEqual(observed[0]["base"], export)
                self.assertFalse(observed[0]["extra_object"] or observed[0]["note"])
                self.assertFalse(observed[0]["base"].exists())
                self.assertEqual(self.hashes(export), before)
                self.assertEqual(r.box.get(final["inbox"]["report_ref"]), original_report)

    def test_replay_has_no_trial_runner_dependency(self):
        r, folder = self.receiver("a-completed-response-lost")
        self.receive(r, folder, "bundle.json")
        final = self.finish(r)
        export = self.work / "without-trial-modules"
        r.export(final["inbox"]["run_id"], export)
        original_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name in ("run_trial", "scenario_inputs"):
                raise ImportError("trial-only module unavailable")
            return original_import(name, *args, **kwargs)
        with patch.object(builtins, "__import__", side_effect=guarded_import):
            self.assertTrue(replay_export(r.selected_raw, export)["required_records_replayed"])

    def test_cli_replay_mismatch_is_structured_error(self):
        r, folder = self.receiver("a-completed-response-lost")
        self.receive(r, folder, "bundle.json")
        final = self.finish(r)
        original_report = r.box.get(final["inbox"]["report_ref"])
        export = self.work / "cli-mismatch"
        r.export(final["inbox"]["run_id"], export)
        report = decode((export / "report.json").read_bytes())
        report["requirements"][0]["record_coverage"] = "missing"
        raw = encode(report)
        (export / "report.json").write_bytes(raw)
        manifest = decode((export / "MANIFEST.json").read_bytes())
        manifest["files"]["report.json"] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
        (export / "MANIFEST.json").write_bytes(encode(manifest))
        selected = self.work / "selected.json"
        selected.write_bytes(r.selected_raw)
        before = self.hashes(export)
        done = subprocess.run([sys.executable, "-E", "-s", "-B", str(bridge.HERE / "receive_handoff.py"),
            "--selection", str(selected), "replay", str(export)], capture_output=True, timeout=120)
        self.assertEqual(done.returncode, 3, done.stderr.decode() + done.stdout.decode())
        self.assertEqual(decode(done.stdout), {"status": "operation_error", "reason": "REPLAY_REPORT_MISMATCH",
                                              "is_execution_ticket": False})
        self.assertEqual(done.stderr, b"")
        self.assertEqual(self.hashes(export), before)
        self.assertEqual(r.box.get(final["inbox"]["report_ref"]), original_report)

    def test_source_version_changes_require_explicit_new_evaluation(self):
        r, f = self.receiver()
        self.receive(r, f)
        with patch.object(bridge, "reader_sources", return_value={"changed": True}):
            with self.assertRaisesRegex(InboxError, "RECEIVER_SOURCE_CHANGED"):
                r.prepare(FINAL_CUTOFF, ASSESSED)

    def test_missing_or_old_database_binding_is_not_resealed(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                r, _ = self.receiver(label="old-binding-" + str(missing))
                if missing:
                    r.box.db.execute("DELETE FROM meta WHERE key=?", (bridge.CONTRACT,))
                else:
                    r.box.db.execute("UPDATE meta SET value=? WHERE key=?",
                                     (sha(r.selected_raw), bridge.CONTRACT))
                before = r.path.read_bytes()
                with self.assertRaisesRegex(InboxError, "DATABASE_SELECTION_MISMATCH"):
                    Receiver(r.path, r.selected_raw)
                self.assertEqual(r.path.read_bytes(), before)

    def test_source_editions_bind_empty_and_nonempty_jobs_and_exports(self):
        # Every CLI invocation starts a fresh interpreter against real source
        # files. A fully repinned comment-only edition isolates version binding
        # from broken imports, stale digests, or changed evaluator behavior.
        source = self.work / "source edition"
        shutil.copytree(bridge.ROOT, source)
        selected = self.work / "selected.json"
        selected.write_bytes(choose(self.inputs / "a-completed-response-lost", "runtime-a"))
        cli = source / "inbox/receive_handoff.py"
        def call(*args, expected=0):
            done = subprocess.run([sys.executable, "-E", "-s", "-B", str(cli),
                "--selection", str(selected), *map(str, args)], capture_output=True, timeout=120)
            self.assertEqual(done.returncode, expected, done.stdout.decode() + done.stderr.decode())
            self.assertEqual(done.stderr, b"")
            return decode(done.stdout)
        def repin():
            pins = source / "sample/SOURCE-PINS.json"
            pins.write_bytes(encode({name: sha((source / "sample" / name).read_bytes())
                                    for name in decode(pins.read_bytes())}))
            manifest = source / "SOURCE-MANIFEST.json"
            value = decode(manifest.read_bytes())
            value["files"] = {name: sha((source / name).read_bytes()) for name in value["files"]}
            manifest.write_bytes(encode(value))
            check = subprocess.run([sys.executable, "-E", "-s", "-B", str(source / "check_environment.py"),
                "--sources-only"], capture_output=True, timeout=30)
            self.assertEqual(check.returncode, 0, check.stdout.decode() + check.stderr.decode())
        repin()
        original_sources = self.hashes(source)
        cases = {}
        for empty in (False, True):
            database = self.work / ("source-" + str(empty) + ".sqlite3")
            prefix = ("--db", database)
            call(*prefix, "init")
            if not empty:
                call(*prefix, "receive", "--event", "one", "--bundle",
                     self.inputs / "a-completed-response-lost/bundle.json", "--received-at", EARLY)
            prepared = call(*prefix, "prepare", "--cutoff", FINAL_CUTOFF, "--assessed-at", ASSESSED)
            run_id = prepared["run_id"]
            report = call(*prefix, "run", run_id)
            self.assertEqual(report["inbox"]["status"], "completed")
            self.assertEqual(report["record_coverage"], {"expected-post": "missing" if empty else "present"})
            self.assertEqual(call(*prefix, "status", run_id), report)
            export = self.work / ("source-export-" + str(empty))
            call(*prefix, "export", run_id, export)
            relocated = self.work / ("relocated evidence " + str(empty))
            export.rename(relocated)
            before = self.hashes(relocated)
            self.assertEqual(call("replay", relocated), {"capsules_reassessed": 0 if empty else 1,
                "required_records_replayed": True, "is_execution_ticket": False})
            frozen = decode((relocated / "selection.json").read_bytes())
            basis = decode((relocated / frozen["selection_basis_ref"]["path"]).read_bytes())
            self.assertEqual(unb64(basis["selection_b64"]), selected.read_bytes())
            self.assertEqual(basis["reader_sources"], bridge.reader_sources())
            self.assertEqual(self.hashes(relocated), before)
            cases[empty] = (database, run_id, relocated, before, database.read_bytes())
        self.assertEqual(self.hashes(source), original_sources)
        for changed in ("sample/handoff_reader.py", "inbox/bridge.py"):
            with self.subTest(changed=changed):
                target = source / changed
                original = target.read_bytes()
                target.write_bytes(original + b"\n# Coherent source-identity regression edition.\n")
                repin()
                for empty, (database, run_id, export, saved, saved_db) in cases.items():
                    with self.subTest(empty=empty):
                        prefix = ("--db", database)
                        for arguments in (("status", run_id), ("run", run_id),
                                ("prepare", "--cutoff", FINAL_CUTOFF, "--assessed-at", ASSESSED),
                                ("export", run_id, self.work / "must-not-export")):
                            self.assertEqual(call(*prefix, *arguments, expected=3)["reason"],
                                             "DATABASE_SELECTION_MISMATCH")
                        self.assertEqual(call("replay", export, expected=3)["reason"], "EXPORT_READER_VERSION")
                        self.assertEqual(self.hashes(export), saved)
                        self.assertEqual(database.read_bytes(), saved_db)
                # Selecting this new edition for a new store still allows a
                # legitimate missing-record assessment and database-free replay.
                fresh = self.work / (target.stem + "-new.sqlite3")
                prefix = ("--db", fresh)
                call(*prefix, "init")
                run_id = call(*prefix, "prepare", "--cutoff", FINAL_CUTOFF,
                              "--assessed-at", ASSESSED)["run_id"]
                self.assertEqual(call(*prefix, "run", run_id)["record_coverage"], {"expected-post": "missing"})
                export = self.work / (target.stem + "-new-export")
                call(*prefix, "export", run_id, export)
                self.assertEqual(call("replay", export)["capsules_reassessed"], 0)
                target.write_bytes(original)
                repin()
        self.assertFalse((self.work / "must-not-export").exists())
        for database, run_id, export, saved, saved_db in cases.values():
            self.assertEqual(call("--db", database, "status", run_id)["inbox"]["status"], "completed")
            self.assertTrue(call("replay", export)["required_records_replayed"])
            self.assertEqual(self.hashes(export), saved)
            self.assertEqual(database.read_bytes(), saved_db)

    def test_receipt_from_another_valid_capsule_cannot_be_substituted(self):
        r, f = self.receiver()
        self.receive(r, f, "bundle.json")
        capsules = {ref["digest"]["value"]: c for ref, c in r.capsules()}
        entries, _, _ = r.box._snapshot(r.s["namespace"])
        # Keep the receipt's own valid digest/ref while attaching it to the wrong
        # derivation entry. Individual hash validity is insufficient.
        self.assertGreater(len(entries), 1)
        entries[0]["originals"]["admission"]["ref"] = entries[1]["originals"]["admission"]["ref"]
        with self.assertRaisesRegex(InboxError, "PROJECTION_BINDING"):
            bridge.check_projection(entries, capsules, r.box.get, r.s["namespace"])

    def test_unrelated_receipt_in_same_namespace_blocks_preparation(self):
        r, f = self.receiver()
        self.receive(r, f)
        _, capsule = r.capsules()[0]
        admission = unb64(capsule["evaluation"]["projection"][0]["admission_b64"])
        r._deliver("other", "other", "receipt_pair", {"admission": r.box.put(admission)},
                   r.selection_ref, EARLY, r.s["namespace"])
        with self.assertRaisesRegex(InboxError, "PROJECTION_ENTRIES"):
            r.prepare(FINAL_CUTOFF, ASSESSED)

    def test_other_required_runtime_cannot_be_used_via_a_prepared_run_id(self):
        r, f = self.receiver()
        self.receive(r, f)
        prepared = r.prepare(FINAL_CUTOFF, ASSESSED)
        _, job = r.box._run(prepared["run_id"])
        plan = decode(r.box.get(job["plan_ref"]))
        plan["review_set"]["requirements"][0]["subject"]["native_context"]["runtime"] = "runtime-a"
        other = r.box.prepare(encode(plan))
        with self.assertRaisesRegex(InboxError, "RUN_REQUIREMENTS_CHANGED"):
            r.run(other["run_id"])
        self.assertEqual(r.box.status(other["run_id"])["status"], "prepared")

    def test_capacity_is_explicit_and_retains_existing_intakes(self):
        r, f = self.receiver()
        raw = (f / "before-handoff.json").read_bytes()
        for index in range(bridge.MAX_INTAKES):
            r.receive("input-" + str(index), raw, EARLY)
        identities = [x[0] for x in r.capsules()]
        with self.assertRaisesRegex(InboxError, "INTAKE_CAPACITY"):
            r.receive("overflow", raw, EARLY)
        self.assertEqual([x[0] for x in r.capsules()], identities)
        self.assertEqual(self.finish(r)["handoff"]["effect_state"], "unresolved")

    def test_database_selection_and_export_tampering_are_rejected(self):
        r, f = self.receiver()
        s = decode(r.selected_raw)
        s["requirements"][0]["runtime"] = "runtime-a"
        with self.assertRaisesRegex(InboxError, "DATABASE_SELECTION_MISMATCH"):
            Receiver(r.path, encode(s))
        self.receive(r, f, "bundle.json")
        final = self.finish(r)
        r.export(final["inbox"]["run_id"], self.work / "export")
        with self.assertRaisesRegex(InboxError, "EXPORT_RECEIVER_SELECTION"):
            replay_export(encode(s), self.work / "export")
        (self.work / "export/report.json").write_bytes(b"{}")
        with self.assertRaisesRegex(InboxError, "EXPORT_HASH"):
            replay_export(r.selected_raw, self.work / "export")

    def test_mixed_actor_requirements_keep_native_context_and_replay(self):
        folder = self.inputs / "b-after-unaccepted-a"
        for count in (2, 4):
            with self.subTest(requirements=count):
                selected = decode(choose(folder, "runtime-b"))
                due = selected["requirements"][0]["due_at"]
                pairs = [("runtime-a", "admission"), ("runtime-b", "post_execution")]
                if count == 4:
                    pairs += [("runtime-a", "post_execution"), ("runtime-b", "admission")]
                selected["requirements"] = [{"id": actor + "-" + kind.replace("_", "-"),
                    "runtime": actor, "record_kind": kind, "due_at": due} for actor, kind in pairs]
                r = Receiver(self.work / (str(count) + ".sqlite3"), encode(selected), create=True)
                self.receivers.append(r)
                self.receive(r, folder)
                old = self.finish(r)
                old_raw = r.box.get(old["inbox"]["report_ref"])
                self.receive(r, folder, "bundle.json", "later", LATE)
                final = self.finish(r)
                expected = {row["id"]: ("missing" if row["runtime"] == "runtime-a" and
                    row["record_kind"] == "post_execution" else "present") for row in selected["requirements"]}
                self.assertEqual(final["record_coverage"], expected)
                self.assertEqual(final["handoff"]["accepted"]["runtime"], "runtime-b")
                self.assertEqual(r.box.get(old["inbox"]["report_ref"]), old_raw)
                _, job = r.box._run(final["inbox"]["run_id"])
                rows = decode(r.box.get(job["review_set_ref"]))["requirements"]
                self.assertEqual(len({row["subject"]["operation_id"] for row in rows}), 2)
                self.assertTrue(all(row["subject"]["native_context"]["transaction_id"] ==
                                    r.operation["operation_key"] for row in rows))
                export = self.work / ("mixed-export-" + str(count))
                r.export(final["inbox"]["run_id"], export)
                self.assertEqual(replay_export(r.selected_raw, export)["capsules_reassessed"], 2)

    def test_empty_and_unassessable_only_missing_assessments_replay(self):
        for invalid in (False, True):
            with self.subTest(invalid_input=invalid):
                r, _ = self.receiver(label="empty-" + str(invalid))
                if invalid:
                    result = r.receive("invalid", b'{"records":[null]}', EARLY)
                    self.assertEqual(result["status"], "unassessable")
                final = self.finish(r)
                self.assertIsNone(final["handoff"])
                self.assertEqual(final["record_coverage"], {"expected-post": "missing"})
                raw_report = r.box.get(final["inbox"]["report_ref"])
                export = self.work / ("empty-export-" + str(invalid))
                r.export(final["inbox"]["run_id"], export)
                self.assertEqual(replay_export(r.selected_raw, export), {"capsules_reassessed": 0,
                    "required_records_replayed": True, "is_execution_ticket": False})
                self.assertEqual(r.box.get(final["inbox"]["report_ref"]), raw_report)
                self.assertEqual(len(r.capsules()), int(invalid))

    def test_stale_observation_basis_rejected_in_run_and_export_replay(self):
        r, folder = self.receiver()
        early = self.receive(r, folder)
        self.receive(r, folder, "bundle.json", "later", LATE)
        prepared = r.prepare(FINAL_CUTOFF, ASSESSED)
        _, job = r.box._run(prepared["run_id"])
        plan = decode(r.box.get(job["plan_ref"]))
        plan["collection_basis_ref"] = early["capsule_ref"]
        foreign = r.box.prepare(encode(plan))
        with self.assertRaisesRegex(InboxError, "RUN_OBSERVATION_BASIS"):
            r.run(foreign["run_id"])
        self.assertEqual(r.box.run(foreign["run_id"])["status"], "completed")
        export = self.work / "stale-basis-export"
        r.box.export(foreign["run_id"], export)
        with self.assertRaisesRegex(InboxError, "EXPORT_OBSERVATION_BASIS"):
            replay_export(r.selected_raw, export)

    def test_observation_basis_uses_one_chain_not_mapping_order(self):
        r, folder = self.receiver()
        early = self.receive(r, folder)
        later = self.receive(r, folder, "bundle.json", "later", LATE)
        capsules = {ref["digest"]["value"]: c for ref, c in reversed(r.capsules())}
        def basis(values, cutoff=FINAL_CUTOFF):
            return bridge.observation_basis(values, r.selection_ref, cutoff, r.box.v.stamp)
        self.assertEqual(basis(capsules), later["capsule_ref"])
        self.assertEqual(basis(capsules, FIRST_CUTOFF), early["capsule_ref"])
        latest = later["capsule_ref"]["digest"]["value"]
        first = early["capsule_ref"]["digest"]["value"]
        with self.assertRaisesRegex(InboxError, "OBSERVATION_HISTORY_MISSING"):
            basis({latest: capsules[latest]})
        fork = decode(encode(capsules))
        fork[latest]["previous_accepted_capsule"] = None
        with self.assertRaisesRegex(InboxError, "OBSERVATION_HISTORY_FORK"):
            basis(fork)
        cycle = decode(encode(capsules))
        cycle[first]["previous_accepted_capsule"] = latest
        with self.assertRaisesRegex(InboxError, "OBSERVATION_HISTORY_DISCONNECTED"):
            basis(cycle)

    def test_nonempty_evidence_cannot_be_relabelled_as_empty_snapshot(self):
        r, folder = self.receiver()
        self.receive(r, folder, "bundle.json")
        final = self.finish(r)
        export = self.work / "not-empty-export"
        r.export(final["inbox"]["run_id"], export)
        manifest = decode((export / "MANIFEST.json").read_bytes())
        frozen = decode((export / "selection.json").read_bytes())
        snapshot = decode((export / frozen["submission_snapshot_ref"]["path"]).read_bytes())
        snapshot["entries"] = []
        raw = encode(snapshot)
        ref = bridge.raw_ref(raw)
        (export / ref["path"]).write_bytes(raw)
        manifest["files"][ref["path"]] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
        frozen["submission_snapshot_ref"] = ref
        raw = encode(frozen)
        (export / "selection.json").write_bytes(raw)
        manifest["files"]["selection.json"] = {"raw_sha256": sha(raw), "byte_length": len(raw)}
        (export / "MANIFEST.json").write_bytes(encode(manifest))
        with self.assertRaisesRegex(InboxError, "PROJECTION_ENTRIES"):
            replay_export(r.selected_raw, export)

    def test_cli_receive_resume_status_and_bad_input(self):
        r, f = self.receiver()
        selected = self.work / "selection.json"
        selected.write_bytes(r.selected_raw)
        command = [sys.executable, "-E", "-s", "-B", str(bridge.HERE / "receive_handoff.py"),
                   "--selection", str(selected), "--db", str(r.path)]
        def cli(*args, expected=0):
            done = subprocess.run(command + list(args), capture_output=True, timeout=120)
            self.assertEqual(done.returncode, expected, done.stderr.decode() + done.stdout.decode())
            return decode(done.stdout)
        self.assertEqual(cli("receive", "--event", "cli", "--bundle", str(f / "bundle.json"),
                             "--received-at", EARLY)["status"], "assessed")
        prepared = cli("prepare", "--cutoff", FINAL_CUTOFF, "--assessed-at", ASSESSED)
        complete = cli("run", prepared["run_id"])
        self.assertEqual(cli("status", prepared["run_id"]), complete)
        self.assertEqual(cli("run", prepared["run_id"]), complete)
        bad = self.work / "bad.json"
        bad.write_bytes(b'{"records":[null]}')
        self.assertEqual(cli("receive", "--event", "bad", "--bundle", str(bad), expected=2)["status"], "unassessable")
        with r.lock():
            self.assertEqual(cli("receive", "--event", "busy", "--bundle", str(f / "bundle.json"), expected=3)["status"],
                             "retryable_busy")

    def test_cli_worker_failure_exit_is_not_success(self):
        r, f = self.receiver()
        selected = self.work / "selection.json"
        selected.write_bytes(r.selected_raw)
        response = {"inbox": {"status": "assessment_error"}, "handoff": None, "is_execution_ticket": False}
        with patch.object(sys, "argv", ["receive_handoff", "--selection", str(selected), "--db", str(r.path), "run", "id"]), \
             patch.object(receive_handoff, "Receiver") as fake, patch.object(sys, "stdout", new_callable=io.StringIO) as output:
            fake.return_value.run.return_value = response
            self.assertEqual(receive_handoff.main(), 3)
            self.assertEqual(decode(output.getvalue().encode()), response)


if __name__ == "__main__":
    unittest.main()
