"""Integration regressions using real files, SQLite Inbox and native evaluator."""
import copy
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
import package_intake as app
from recipient_inbox import Engine, Inbox
from package_example import CASES, generate
from file_set_fixture import tree_hashes


def load(path):
    return json.loads(path.read_bytes())


def normalize(value):
    result = copy.deepcopy(value)
    result["usage"].pop("elapsed_milliseconds")
    return result


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("VATE_PACKAGE_TEST_OUTPUT"):
            cls.output = Path(os.environ["VATE_PACKAGE_TEST_OUTPUT"])
            cls.output.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="vate-package-tests-")
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.output = Path(cls.temporary.name)
        cls.inputs = cls.output / "inputs"
        generate(cls.inputs)
        cls.originals = tree_hashes(cls.inputs)

    @classmethod
    def tearDownClass(cls):
        if tree_hashes(cls.inputs) != cls.originals:
            raise AssertionError("generated inputs changed during intake tests")

    def setUp(self):
        self.root = self.output / self._testMethodName
        self.root.mkdir()
        self.package = self.root / "package"; self.package.mkdir()
        self.inventory = load(self.inputs / "inventory.json")
        self.inventory["jobs"] = self.inventory["jobs"][:1]
        self.inv = self.root / "inventory.json"
        self.membership = self.root / "membership.json"
        self.manifest = {"kind": "local_selected_receipt_package", "version": 1,
                         "namespace": self.inventory["namespace"], "inventory_sha256": "",
                         "files": [], "deliveries": []}

    def pair(self, label="A", *, post_label=None, entry_id="entry-A", only=None):
        slots = {"admission": "admission-1/receipt.json", "post": "adapter/post-execution-receipt.json"}
        originals = {}
        for slot, relative in slots.items():
            if only and slot != only:
                continue
            producer = post_label if slot == "post" and post_label else label
            raw = (self.inputs / "producer" / CASES[producer] / relative).read_bytes()
            name = entry_id + "-" + slot + ".json"
            (self.package / name).write_bytes(raw)
            self.manifest["files"].append({"path": name, "bytes": len(raw), "sha256": app.sha(raw)})
            originals[slot] = name
        self.manifest["deliveries"].append({"entry_id": entry_id, "originals": originals})

    def freeze(self):
        self.inv.write_bytes(app.encoded(self.inventory))
        self.manifest["inventory_sha256"] = app.sha(self.inv.read_bytes())
        self.membership.write_bytes(app.encoded(self.manifest))

    def execute(self, *, output="run", box_type=Inbox, due_at="2026-10-16T20:03:00Z", frozen=False):
        if not frozen:
            self.freeze()
        result = app.execute(SOURCE, self.inv, self.membership, self.package, self.root / output,
                             due_at, Engine, box_type)
        self.result_root = self.root / output
        self.report = load(self.result_root / "report.json")
        self.collection = load(self.result_root / "COLLECTION.json")
        self.assertEqual(result["handling_status"], "completed")
        self.assertEqual(result["inventory_state"], self.collection["inventory_state"])
        plan = load(self.result_root / "submitted/plan.json")
        self.assertEqual(plan["inventory_state"], self.collection["inventory_state"])
        self.assertEqual(plan["assessment_cutoff"], self.collection["finished_at"])
        self.reassess()
        return result

    def reassess(self):
        path = self.result_root / "reassessment.json"
        command = [sys.executable, "-B", str(SOURCE / "reference/required-records/required_records.py"),
                   "--selection", str(self.result_root / "export/selection.json"),
                   "--base", "inbox=" + str(self.result_root / "export"), "--source-root", str(SOURCE),
                   "--output", str(path)]
        proc = subprocess.run(command, capture_output=True, timeout=120)
        (self.result_root / "reassessment.stdout").write_bytes(proc.stdout)
        (self.result_root / "reassessment.stderr").write_bytes(proc.stderr)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(normalize(load(path)), normalize(self.report))

    def coverage(self):
        return [row["record_coverage"] for row in self.report["requirements"]]

    def test_complete_pair(self):
        self.pair(); self.execute()
        self.assertEqual(self.collection["inventory_state"], "closed")
        self.assertEqual(self.coverage(), ["present"])
        self.assertEqual(self.report["native_calls"][0]["result"]["native_result"]["record_linkage"], "matched")
        box = Inbox(self.result_root / "inbox.sqlite3", Engine(SOURCE))
        try:
            for event in self.collection["events"]:
                if event["phase"] == "stored":
                    self.assertEqual(box.get(event["ref"]), (self.package / event["path"]).read_bytes())
        finally:
            box.close()

    def test_empty_selected_package(self):
        self.execute()
        self.assertEqual(self.collection["inventory_state"], "closed")
        self.assertEqual(self.coverage(), ["missing"])

    def test_empty_before_deadline(self):
        due = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
        self.execute(due_at=due)
        self.assertEqual(self.coverage(), ["pending"])

    def test_post_not_in_membership(self):
        self.pair(only="admission"); self.execute()
        self.assertEqual(self.collection["inventory_state"], "closed")
        self.assertEqual(self.coverage(), ["missing"])

    def test_listed_post_file_missing(self):
        self.pair(); (self.package / "entry-A-post.json").unlink(); self.execute()
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertEqual(self.coverage(), ["unresolved"])
        self.assertTrue(any(e["error_type"] == "FileNotFoundError" for e in self.collection["errors"]))

    def test_source_unavailable(self):
        self.pair(); self.package = self.root / "absent"; self.execute()
        self.assertEqual(self.collection["inventory_state"], "unavailable")
        self.assertEqual(self.coverage(), ["unresolved"])

    def test_extra_candidate_not_ignored(self):
        (self.package / "unlisted.json").write_text("{}\n"); self.execute()
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertEqual(self.coverage(), ["unresolved"])

    def test_raw_digest_mismatch(self):
        self.pair(); path = self.package / "entry-A-post.json"
        path.write_bytes(path.read_bytes() + b"\n"); self.execute()
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertEqual(self.coverage(), ["unresolved"])
        self.assertEqual((self.result_root / "observed/entry-A-post.json").read_bytes(), path.read_bytes())

    def test_native_mismatch_is_not_collection_failure(self):
        self.pair(post_label="C"); self.execute()
        self.assertEqual(self.collection["inventory_state"], "closed")
        # The received post belongs to C, while the independent requirement is A.
        self.assertEqual(self.coverage(), ["missing"])
        self.assertEqual(self.report["native_calls"][0]["result"]["native_result"]["record_linkage"], "mismatch")

    def test_present_post_can_have_native_mismatch(self):
        self.pair()
        path = self.package / "entry-A-post.json"
        post = load(path)
        context = copy.deepcopy(post["execution"])
        post["admission"]["receipt_id"] += "-mismatch"
        raw = app.encoded(post)
        path.write_bytes(raw)
        for member in self.manifest["files"]:
            if member["path"] == path.name:
                member.update(bytes=len(raw), sha256=app.sha(raw))
        self.execute()
        self.assertEqual(load(path)["execution"], context)
        self.assertEqual((self.result_root / "observed" / path.name).read_bytes(), raw)
        self.assertEqual(self.collection["inventory_state"], "closed")
        self.assertEqual(self.coverage(), ["present"])
        self.assertEqual(self.report["native_calls"][0]["result"]["native_result"]["record_linkage"], "mismatch")

    def test_unknown_receipt_not_dropped(self):
        raw = b'{"unknown": "record"}\n'; name = "unknown.json"
        (self.package / name).write_bytes(raw)
        self.manifest["files"] = [{"path": name, "bytes": len(raw), "sha256": app.sha(raw)}]
        self.manifest["deliveries"] = [{"entry_id": "unknown", "originals": {"post": name}}]
        self.execute()
        self.assertEqual(self.collection["inventory_state"], "closed")
        self.assertEqual(self.coverage(), ["unresolved"])
        self.assertTrue(self.report["entries"])

    def test_symlink_refused(self):
        self.pair(); path = self.package / "entry-A-post.json"
        raw = path.read_bytes(); target = self.root / "outside.json"; target.write_bytes(raw)
        path.unlink(); path.symlink_to(target); self.execute()
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertFalse((self.result_root / "observed/entry-A-post.json").exists())

    def test_fifo_refused_without_blocking(self):
        self.pair(); path = self.package / "entry-A-post.json"; path.unlink(); os.mkfifo(path)
        self.execute()
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertEqual(self.coverage(), ["unresolved"])

    def test_permission_denied(self):
        self.assertNotEqual(os.geteuid(), 0, "run this validation as a non-root user")
        self.pair(); path = self.package / "entry-A-post.json"; path.chmod(0)
        try:
            self.execute()
        finally:
            path.chmod(0o600)
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertTrue(any(e["error_type"] == "PermissionError" for e in self.collection["errors"]))
        self.assertEqual(self.coverage(), ["unresolved"])

    def test_real_inbox_slot_rejection(self):
        self.pair(); self.pair("B", entry_id="entry-B")
        class RejectSecond(Inbox):
            def receive(inner, raw):
                item = json.loads(raw)
                if item["entry_id"] == "entry-B":
                    # Actual earlier receipt registration creates a real slot conflict.
                    prior = copy.deepcopy(item); prior["event_id"] = "already-received-B"
                    super(RejectSecond, inner).receive(app.encoded(prior))
                return super(RejectSecond, inner).receive(raw)
        self.execute(box_type=RejectSecond)
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertEqual(self.coverage(), ["unresolved"])
        self.assertEqual(self.collection["registered_entries"], ["entry-A"])
        self.assertTrue(any(e["code"] == "SLOT_ALREADY_RECEIVED" for e in self.collection["errors"]))

    def test_real_database_put_failure(self):
        self.pair()
        class BrokenDatabase(Inbox):
            def put(inner, raw, media_type="application/json"):
                # A real SQLite write error at the first original put, after metadata puts.
                if raw == (self.package / "entry-A-admission.json").read_bytes():
                    inner.db.execute("PRAGMA query_only=ON")
                return super(BrokenDatabase, inner).put(raw, media_type)
        self.freeze()
        with self.assertRaises(Exception):
            self.execute(box_type=BrokenDatabase, frozen=True)
        out = self.root / "run"
        self.assertEqual(load(out / "COLLECTION.json")["inventory_state"], "partial")
        self.assertTrue((out / "observed/entry-A-post.json").exists())
        self.assertFalse((out / "submitted/plan.json").exists())
        self.assertTrue((out / "FAILURE.json").exists())

    def test_mutation_during_import(self):
        self.pair()
        class Mutating(Inbox):
            def receive(inner, raw):
                result = super(Mutating, inner).receive(raw)
                (self.package / "unexpected.json").write_text("{}")
                return result
        self.execute(box_type=Mutating)
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertEqual(self.coverage(), ["unresolved"])

    def test_scope_and_manifest_rejections(self):
        self.pair(); self.freeze()
        original = copy.deepcopy(self.manifest)
        cases = {}
        wrong = copy.deepcopy(original); wrong["namespace"] = "somewhere-else"; cases["namespace"] = wrong
        wrong = copy.deepcopy(original); wrong["inventory_sha256"] = "0" * 64; cases["inventory_hash"] = wrong
        wrong = copy.deepcopy(original); wrong["inventory_state"] = "closed"; cases["self_reported_closed"] = wrong
        wrong = copy.deepcopy(original); wrong["files"][0]["path"] = "../outside"; cases["traversal"] = wrong
        wrong = copy.deepcopy(original); wrong["files"].append(wrong["files"][0]); cases["duplicate"] = wrong
        wrong = copy.deepcopy(original); wrong["files"][0]["bytes"] = app.MIB + 1; cases["limit"] = wrong
        for name, value in cases.items():
            with self.subTest(name=name):
                self.membership.write_bytes(app.encoded(value))
                with self.assertRaises(ValueError):
                    self.execute(output=name, frozen=True)
                self.assertFalse((self.root / name / "COLLECTION.json").exists())
                self.assertFalse((self.root / name / "submitted/plan.json").exists())

    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            app.decode(b'{"files":[],"files":[]}')

    def test_invalid_review_rejected_before_collection(self):
        self.pair()
        valid_inventory = copy.deepcopy(self.inventory)
        cases = [("deadline", valid_inventory, "not-a-time")]
        missing = copy.deepcopy(valid_inventory)
        del missing["jobs"][0]["expected_context"]["runtime"]
        cases.append(("context_field", missing, "2026-10-16T20:03:00Z"))
        mismatch = copy.deepcopy(valid_inventory)
        mismatch["jobs"][0]["expected_context"]["effective_request_hash"] = "sha-256:" + "0" * 64
        cases.append(("context_hash", mismatch, "2026-10-16T20:03:00Z"))
        alias = copy.deepcopy(valid_inventory)
        second = copy.deepcopy(alias["jobs"][0])
        second.update(job_label="alias", operation_id="different-operation")
        alias["jobs"].append(second)
        cases.append(("context_alias", alias, "2026-10-16T20:03:00Z"))
        for name, inventory, due_at in cases:
            with self.subTest(name=name):
                self.inventory = inventory
                self.freeze()
                with patch.object(app, "collect") as collector, self.assertRaises(ValueError):
                    self.execute(output=name, due_at=due_at, frozen=True)
                collector.assert_not_called()
                out = self.root / name
                self.assertEqual(list((out / "observed").iterdir()), [])
                for rel in ("COLLECTION.json", "submitted/plan.json", "report.json", "SUMMARY.json"):
                    self.assertFalse((out / rel).exists(), rel)
                self.assertEqual(load(out / "FAILURE.json")["code"], "INVALID_INPUT")

    def test_actual_byte_budget_ignores_false_small_declarations(self):
        for index in range(9):
            name = "oversized-" + str(index) + ".json"
            raw = b"x" * app.MIB
            (self.package / name).write_bytes(raw)
            self.manifest["files"].append({"path": name, "bytes": 0, "sha256": app.sha(b"")})
            self.manifest["deliveries"].append({"entry_id": "entry-" + str(index), "originals": {"post": name}})
        self.execute()
        self.assertEqual(self.collection["inventory_state"], "partial")
        self.assertEqual(self.coverage(), ["unresolved"])
        self.assertEqual(self.collection["acquired_bytes"], app.MAX_TOTAL)
        self.assertEqual(sum(p.stat().st_size for p in (self.result_root / "observed").iterdir()), app.MAX_TOTAL)
        self.assertFalse((self.result_root / "observed/oversized-8.json").exists())

    def test_single_clock_regression_aborts_even_if_clock_recovers(self):
        self.pair(); self.freeze()
        class TransientDatetime:
            base = datetime.now(timezone.utc)
            calls = 0
            @classmethod
            def now(cls, tz):
                cls.calls += 1
                return cls.base + timedelta(microseconds=299 if cls.calls == 4 else cls.calls * 100)
        with patch.object(app, "datetime", TransientDatetime), self.assertRaises(app.ClockError):
            self.execute(frozen=True)
        self.assertFalse((self.root / "run/COLLECTION.json").exists())
        self.assertFalse((self.root / "run/submitted/plan.json").exists())
        self.assertEqual(load(self.root / "run/FAILURE.json")["error_type"], "ClockError")

    def test_clock_regression_aborts(self):
        clock = app.Clock(); clock.last = datetime.now(timezone.utc) + timedelta(days=1)
        with self.assertRaisesRegex(ValueError, "clock moved backwards"):
            clock.now()
        self.pair(); self.freeze()
        class Regressing(app.Clock):
            def now(inner):
                if not hasattr(inner, "count"):
                    inner.count = 0
                inner.count += 1
                if inner.count == 5:
                    inner.last = datetime.now(timezone.utc) + timedelta(days=1)
                return super(Regressing, inner).now()
        with patch.object(app, "Clock", Regressing), self.assertRaises(ValueError):
            self.execute(frozen=True)
        self.assertFalse((self.root / "run/COLLECTION.json").exists())
        self.assertFalse((self.root / "run/submitted/plan.json").exists())

    def test_process_kill_and_new_attempt(self):
        self.pair(); self.pair("B", entry_id="entry-B"); self.freeze()
        child = self.root / "interrupt_child.py"
        child.write_text('''import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2]+"/reference/recipient-inbox")
import package_intake as app
from recipient_inbox import Engine, Inbox
class StopAfterOne(Inbox):
    def receive(self, raw):
        result=super().receive(raw)
        (Path(sys.argv[6])/"STOP-POINT").write_text("one real delivery committed")
        os.kill(os.getpid(), signal.SIGSTOP)
        return result
app.execute(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),Path(sys.argv[5]),Path(sys.argv[6]),"2026-10-16T20:03:00Z",Engine,StopAfterOne)
''')
        out = self.root / "interrupted"
        with (self.root / "child.log").open("wb") as log:
            child_process = subprocess.Popen([sys.executable, "-B", str(child), str(HERE), str(SOURCE),
                                              str(self.inv), str(self.membership), str(self.package), str(out)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 90
                while not (out / "STOP-POINT").exists() and time.monotonic() < deadline and child_process.poll() is None:
                    time.sleep(0.05)
                self.assertTrue((out / "STOP-POINT").exists())
                child_process.kill(); child_process.wait(timeout=30)
            finally:
                if child_process.poll() is None:
                    child_process.kill(); child_process.wait(timeout=30)
        self.assertFalse((out / "COLLECTION.json").exists())
        self.assertFalse((out / "submitted/plan.json").exists())
        self.assertEqual(load(out / "STARTED.json")["state"], "in_progress")
        box = Inbox(out / "inbox.sqlite3", Engine(SOURCE))
        try:
            self.assertEqual(box.db.execute("SELECT count(*) FROM deliveries").fetchone()[0], 1)
        finally:
            box.close()
        before = {str(p.relative_to(out)): app.sha(p.read_bytes()) for p in out.rglob("*") if p.is_file()}
        with self.assertRaises(FileExistsError):
            self.execute(output="interrupted", frozen=True)
        self.execute(output="new-attempt", frozen=True)
        self.assertEqual(self.collection["inventory_state"], "closed")
        after = {str(p.relative_to(out)): app.sha(p.read_bytes()) for p in out.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_cli_exit_distinguishes_partial(self):
        self.freeze(); self.package = self.root / "missing"
        out = self.root / "cli"
        command = [sys.executable, "-B", str(HERE / "package_intake.py"), "--source-root", str(SOURCE),
                   "--inventory", str(self.inv), "--membership", str(self.membership), "--package", str(self.package),
                   "--output", str(out), "--due-at", "2026-10-16T20:03:00Z"]
        proc = subprocess.run(command, capture_output=True, timeout=120)
        (self.root / "CLI.json").write_bytes(app.encoded({"argv": command, "exit": proc.returncode,
                                                        "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode()}))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["inventory_state"], "unavailable")

    def test_cli_argument_error_has_no_output(self):
        out = self.root / "cli"
        command = [sys.executable, "-B", str(HERE / "package_intake.py"), "--output", str(out)]
        proc = subprocess.run(command, capture_output=True, timeout=120)
        (self.root / "CLI.json").write_bytes(app.encoded({"argv": command, "exit": proc.returncode,
                                                        "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode()}))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"usage:", proc.stderr)
        self.assertFalse(out.exists())

    def test_cli_bootstrap_errors_are_structured(self):
        self.freeze()
        empty_source = self.root / "empty-source"
        empty_source.mkdir()
        for name, source, error in (("absent", self.root / "absent-source", "FileNotFoundError"),
                                    ("empty", empty_source, "ModuleNotFoundError")):
            with self.subTest(name=name):
                out = self.root / name
                command = [sys.executable, "-B", str(HERE / "package_intake.py"),
                           "--source-root", str(source), "--inventory", str(self.inv),
                           "--membership", str(self.membership), "--package", str(self.package),
                           "--output", str(out), "--due-at", "2026-10-16T20:03:00Z"]
                proc = subprocess.run(command, capture_output=True, timeout=120)
                (self.root / (name + "-CLI.json")).write_bytes(app.encoded({"argv": command, "exit": proc.returncode,
                    "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode()}))
                self.assertEqual(proc.returncode, 64)
                self.assertEqual(proc.stderr, b"")
                failure = json.loads(proc.stdout)
                self.assertEqual(failure["handling_status"], "failed")
                self.assertEqual(failure["error_type"], error)
                self.assertFalse(out.exists())

    def test_generated_example_from_unrelated_working_directory(self):
        fixture = self.root / "example"
        generated = subprocess.run([sys.executable, "-B", str(HERE / "package_example.py"),
                                    "--output", str(fixture)], cwd=self.root, capture_output=True, timeout=120)
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        before = tree_hashes(fixture)
        inventory = load(fixture / "inventory.json")
        membership = load(fixture / "membership.json")
        self.assertEqual([row["job_label"] for row in inventory["jobs"]], ["A", "B", "C"])
        self.assertEqual([row["entry_id"] for row in membership["deliveries"]], ["entry-A", "entry-C"])
        self.assertEqual(membership["inventory_sha256"], app.sha((fixture / "inventory.json").read_bytes()))
        out = self.root / "intake"
        proc = subprocess.run([sys.executable, "-B", str(HERE / "package_intake.py"),
                               "--source-root", str(SOURCE), "--inventory", str(fixture / "inventory.json"),
                               "--membership", str(fixture / "membership.json"), "--package", str(fixture / "package"),
                               "--output", str(out), "--due-at", "2026-10-16T20:03:00Z"],
                              cwd=self.root, capture_output=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["inventory_state"], "closed")
        self.assertEqual([row["coverage"] for row in summary["requirements"]], ["present", "missing", "present"])
        self.result_root, self.report = out, load(out / "report.json")
        self.assertEqual([row["result"]["native_result"]["record_linkage"] for row in self.report["native_calls"]],
                         ["matched", "matched"])
        self.reassess()
        self.assertEqual(tree_hashes(fixture), before)

    def test_generator_preserves_existing_output(self):
        before = tree_hashes(self.inputs)
        with patch("package_example.capture_cases") as capture, self.assertRaises(FileExistsError):
            generate(self.inputs)
        capture.assert_not_called()
        self.assertEqual(tree_hashes(self.inputs), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
