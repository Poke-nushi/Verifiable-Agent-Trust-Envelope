"""Regression and semantic mutation tests for the local execution boundary."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from admission import evaluate, make_permit, make_policy
from demo_contract import (
    CONTRACT, HERE, MAX_ARTIFACT, MAX_SAFE_INTEGER, REQUIRED_SOURCE_FILES, Invalid, check_native_structure, check_size, check_transport_record,
    core, decode, digest, encode, now, object_hash, observe_files,
    provider_snapshot, read_json, read_raw, source_digests, time_value, tree, validate_operation, write_json,
)
from run_demo import Controller, SCENARIOS, make_manifest, run_case, source_record
from verify_evidence import recognize_execution_event, recognize_execution_journal, validate_schemas, verify


ENCODING_CASES = (
    ("utf-8", b"\xef\xbb\xbf"), ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff"),
    ("utf-32-le", b"\xff\xfe\x00\x00"), ("utf-32-be", b"\x00\x00\xfe\xff"),
)


class ExecutionDemoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = tempfile.TemporaryDirectory(prefix="vate-execution-captures-")
        cls.baselines = Path(cls.capture.name)
        for scenario in SCENARIOS:
            run_case(cls.baselines / scenario, scenario)

    @classmethod
    def tearDownClass(cls):
        cls.capture.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vate-execution-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def clone(self, scenario="allow"):
        case = self.root / scenario
        shutil.copytree(self.baselines / scenario, case)
        return case

    def copied_source(self, name):
        root = self.root / name
        for relative in REQUIRED_SOURCE_FILES:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE.parents[1] / relative, target)
        return root

    def change(self, case, path, edit):
        value = read_json(case / path)
        edit(value)
        (case / path).write_bytes(encode(value))

    def reseal(self, case):
        # Deliberately rehash mutable evidence in semantic probes: a checksum
        # mismatch alone would not test admission or observation semantics.
        (case / "manifest.json").write_bytes(encode(make_manifest(case)))

    def reseal_closed_snapshot(self, case):
        snapshot = provider_snapshot(case)
        self.change(case, "adapter/gate-1.json", lambda v: v.update(provider_snapshot=snapshot))
        (case / "adapter/after-dispatch-snapshot.json").write_bytes(encode(snapshot))
        self.reseal(case)

    def retained_execution_case(self, name, scenario="allow", *, related=True, denied=False):
        executed = Controller(self.root / (name + "-executed"), scenario)
        auth = executed.authorize()
        executed.dispatch(auth, auth.effective)
        executed.finish()
        self.assertEqual(executed.slot["state"], "confirmed_success")
        originals = provider_snapshot(executed.case)
        case = self.root / name
        if related:
            shutil.copytree(executed.case, case)
            gate = read_json(case / "adapter/gate-1.json")
            gate.update(provider_snapshot=originals, handoff=False, reason="UNEXPECTED_PROVIDER_STATE")
            gate["checks"] = gate["checks"][:-1] + [{"name": "UNEXPECTED_PROVIDER_STATE", "pass": False,
                                                     "detail": "UNEXPECTED_PROVIDER_STATE"}]
            (case / "adapter/gate-1.json").write_bytes(encode(gate))
            (case / "adapter/final-state.json").write_bytes(encode({"operation_key": executed.context["operation_key"],
                                                                   "attempt_key": None, "state": "not_dispatched"}))
            for artifact in ("dispatch.json", "attempt-start.json", "attempt-observation.json", "execute-stdout.bin",
                             "execute-stderr.bin", "execute-transport.json", "post-execution-receipt.json"):
                (case / "adapter" / artifact).unlink()
            self.reseal(case)
        else:
            controller = Controller(case, "deny" if denied else "allow")
            auth = controller.authorize(revoked=denied)
            for namespace in ("provider", "sandbox"):
                for path in (executed.case / namespace).iterdir():
                    shutil.copy2(path, case / namespace / path.name)
            with patch.object(controller, "provider_call") as call:
                controller.dispatch(auth, auth.effective or auth.original)
            call.assert_not_called()
            self.assertIsNone(controller.slot)
            controller.finish()
        self.assertEqual(provider_snapshot(case), originals)
        return case

    def assert_invalid(self, case, detail):
        report = verify(case)
        self.assertEqual(report["verdict"], "invalid", report)
        self.assertEqual(report["effect_state"], "unknown", report)
        self.assertIn(detail, str(report["issues"]))

    def retained_output_case(self, name, files, *, mutate_native=None, edited=False, denied=False):
        original = Controller(self.root / (name + "-old"), "allow")
        original.original["target"]["files"] = copy.deepcopy(files)
        original.policy["allowed_output_names"] = [item["name"] for item in files]
        (original.case / "inputs/original-operation.json").write_bytes(encode(original.original))
        (original.case / "policy.json").write_bytes(encode(original.policy))
        auth = original.authorize()
        original.dispatch(auth, auth.effective)
        original.finish()
        self.assertEqual(original.slot["state"], "confirmed_success")
        self.assertEqual(read_json(original.case / "provider/received.bin")["operation"]["target"]["files"], files)
        controller = Controller(self.root / name, "deny" if denied else "allow")
        auth = controller.authorize(revoked=denied)
        for namespace in ("provider", "sandbox"):
            for path in (original.case / namespace).iterdir():
                shutil.copy2(path, controller.case / namespace / path.name)
        if mutate_native is not None:
            native = read_json(controller.case / "provider/native-result.json")
            mutate_native(native)
            check_native_structure(native)  # Each counterexample remains structurally valid.
            raw = encode(native)
            (controller.case / "provider/native-result.json").write_bytes(raw)
            events = [decode(line) for line in read_raw(controller.case / "provider/invocations.jsonl").splitlines()]
            events[1]["native_digest"] = digest(raw)
            (controller.case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in events))
        if edited:
            for path in (controller.case / "sandbox").iterdir():
                path.write_bytes(b"Legitimate edit before the new operation's gate.\n")
        before = provider_snapshot(controller.case)
        with patch.object(controller, "provider_call") as call:
            gate = controller.dispatch(auth, auth.effective or auth.original)
        call.assert_not_called()
        self.assertFalse(gate["handoff"])
        self.assertIsNone(controller.slot)
        controller.finish()
        self.assertEqual(before, provider_snapshot(controller.case))
        self.assertFalse((controller.case / "adapter/execute-transport.json").exists())
        return controller.case

    def assert_invalid_modes(self, case, detail):
        self.assert_invalid(case, detail)
        for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
            with self.subTest(strict=strict):
                self.assert_namespace_cli(case, "invalid", strict=strict)

    def sized_controller(self, name, size, *, reconciled=False):
        controller = Controller(self.root / name, "response-loss-reconciled" if reconciled else "allow")
        controller.original["target"]["files"][0]["text"] = "x" * size
        (controller.case / "inputs/original-operation.json").write_bytes(encode(controller.original))
        auth = controller.authorize()
        controller.dispatch(auth, auth.effective, drop_response=reconciled)
        if reconciled:
            controller.try_fresh_authorization()
            controller.reconcile()
        controller.finish()
        return controller

    def response_fault_controller(self, name, execute_fault, *, reconcile=False, query_fault=None):
        controller = Controller(self.root / name, "allow")
        auth = controller.authorize()
        actual_call = controller.provider_call

        def faulty_call(command, payload, **kwargs):
            raw, transport = actual_call(command, payload, **kwargs)
            before = provider_snapshot(controller.case)
            fault = execute_fault if command == "execute" else query_fault
            if fault == "truncated":
                raw = raw[:-1]
            elif fault == "different-json":
                raw = encode({"unrelated": "response"})
            elif fault == "empty":
                raw = b""
            elif fault == "nonzero":
                transport["returncode"] = 1
            elif fault in ("array", "number"):
                raw = encode([] if fault == "array" else 1)
            elif fault:
                reply = decode(raw)
                if fault == "wrong-key":
                    reply["attempt_key"] = "attempt-unrelated"
                elif fault == "invalid-base64":
                    reply["native_base64"] = "@@@"
                elif fault == "different-native":
                    reply["native_base64"] = "e30="  # Valid base64 for different bytes: {}.
                elif fault == "unknown-status":
                    reply["status"] = "unknown"
                elif fault == "bool-size":
                    reply["current_files"][0]["size"] = False
                else:
                    self.fail("unexpected response fault")
                raw = encode(reply)
            if fault:
                (controller.case / f"adapter/{command}-stdout.bin").write_bytes(raw)
                transport["stdout_digest"] = digest(raw)
                (controller.case / f"adapter/{command}-transport.json").write_bytes(encode(transport))
            self.assertEqual(before, provider_snapshot(controller.case))
            return raw, transport

        with patch.object(controller, "provider_call", side_effect=faulty_call):
            controller.dispatch(auth, auth.effective)
            initial_observation = read_raw(controller.case / "adapter/attempt-observation.json")
            self.assertEqual(controller.slot["state"], "indeterminate")
            self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
            self.assertEqual(controller.try_fresh_authorization()["reason"], "OPERATION_INDETERMINATE")
            if reconcile:
                before = provider_snapshot(controller.case)
                controller.reconcile()
                self.assertEqual(before, provider_snapshot(controller.case))
                self.assertEqual(initial_observation, read_raw(controller.case / "adapter/attempt-observation.json"))
        controller.finish()
        return controller

    def assert_read_only_modes(self, case, verdict, effect, count):
        before = make_manifest(case)
        expected_code = {"verified": 0, "indeterminate": 2}[verdict]
        report = verify(case)
        self.assertEqual((report["verdict"], report["effect_state"], report["provider_execution_count"]),
                         (verdict, effect, count), report)
        for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
            command = [sys.executable, "-B", str(HERE / "verify_evidence.py"), str(case)]
            if strict:
                command.append("--strict-schema")
            result = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
            expected = {**report, "checks": report["checks"] + (["strict_existing_vate_schemas"] if strict else [])}
            self.assertEqual(decode(result.stdout), expected)
        self.assertEqual(before, make_manifest(case))
        return report

    def rebind_native(self, case, raw, *, update_post=True):
        # Refresh dependent bytes in allow/response-loss captures so mutations
        # reach semantic checks with a consistent raw inventory and source pin.
        (case / "provider/native-result.json").write_bytes(raw)
        if read_raw(case / "adapter/execute-stdout.bin"):
            (case / "adapter/execute-stdout.bin").write_bytes(raw)
            self.change(case, "adapter/execute-transport.json", lambda v: v.update(stdout_digest=digest(raw)))
        journal = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
        journal[-1]["native_digest"] = digest(raw)
        (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(v) + b"\n" for v in journal))
        (case / "adapter/after-dispatch-snapshot.json").write_bytes(encode(provider_snapshot(case)))
        post_path = case / "adapter/post-execution-receipt.json"
        if update_post and post_path.exists():
            post = read_json(post_path)
            post["demo_evidence"]["native_result"]["digest"] = digest(raw)
            post_path.write_bytes(encode(post))
            self.change(case, "adapter/attempt-observation.json", lambda v: v.update(post_receipt_digest=digest(encode(post))))
        self.reseal(case)

    def namespace_case(self, namespace, kind, scenario="allow"):
        case = self.root / f"{scenario}-{namespace}-{kind}"
        shutil.copytree(self.baselines / scenario, case)
        path = case / namespace
        if kind in ("missing", "file", "symlink", "dangling-symlink"):
            shutil.rmtree(path)
            if kind == "file":
                path.write_bytes(b"not a directory")
            elif kind in ("symlink", "dangling-symlink"):
                external = self.root / f"{namespace}-{kind}-target"
                if kind == "symlink":
                    external.mkdir()
                path.symlink_to(external, target_is_directory=True)
        elif kind == "empty-subdirectory":
            (path / "unexpected").mkdir()
        elif kind == "nonregular-entry":
            os.mkfifo(path / "unexpected")
        else:
            self.fail("unknown namespace mutation")
        # Retain the original manifest; this is missing/unsafe evidence, not a
        # new capture with its missing namespace hidden by resealing.
        self.assertEqual(read_raw(case / "manifest.json"), read_raw(self.baselines / scenario / "manifest.json"))
        return case

    def assert_namespace_cli(self, case, verdict, *, strict=False):
        argv = [sys.executable, "-B", str(HERE / "verify_evidence.py"), str(case)]
        if strict:
            argv.append("--strict-schema")
        result = subprocess.run(argv, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2 if verdict == "incomplete" else 1, result.stdout + result.stderr)
        for report in (verify(case), decode(result.stdout)):
            self.assertEqual(report["verdict"], verdict, report)
            self.assertEqual(report["effect_state"], "unknown", report)
            self.assertEqual(report["controller_observer_state"], "unknown", report)
            self.assertIsNone(report["provider_execution_count"], report)
            self.assertIsNone(report["provider_files_observed"], report)

    def test_required_scenarios_use_observations(self):
        expected = {
            "allow": ("verified", "created", 1), "deny": ("verified", "not_started", 0),
            "attenuate": ("verified", "created", 1), "swap-content": ("verified", "not_started", 0),
            "swap-destination": ("verified", "not_started", 0), "require-new-permit": ("verified", "not_started", 0),
            "response-loss": ("indeterminate", "unknown", 1), "response-loss-reconciled": ("verified", "created", 1),
            "missing-evidence": ("incomplete", "unknown", None), "tampered-evidence": ("invalid", "unknown", None),
        }
        for name, expected_tuple in expected.items():
            with self.subTest(case=name):
                report = verify(self.baselines / name)
                self.assertEqual((report["verdict"], report["effect_state"], report["provider_execution_count"]), expected_tuple, report)

    def test_permit_lifetime_bounds(self):
        controller = Controller(self.root / "permit-window", "allow")
        issued = "2026-09-15T00:00:00Z"
        for lifetime in (timedelta(seconds=1), timedelta(minutes=10)):
            with self.subTest(valid_lifetime=lifetime):
                permit = make_permit(controller.original, "auth-window", issued_at=issued)
                permit["expires_at"] = core.iso(time_value(issued) + lifetime)
                auth = evaluate(controller.original, permit, controller.policy,
                                resource=controller.context["resource"],
                                permit_uri="local:admission-1/permit.json", evaluated_at=issued)
                self.assertEqual(decode(auth.receipt)["decision"]["outcome"], "allow")
        for lifetime in (timedelta(seconds=-1), timedelta(0),
                         timedelta(minutes=10, microseconds=1), timedelta(minutes=20)):
            with self.subTest(invalid_lifetime=lifetime):
                permit = make_permit(controller.original, "auth-window", issued_at=issued)
                permit["expires_at"] = (time_value(issued) + lifetime).isoformat().replace("+00:00", "Z")
                with self.assertRaisesRegex(Invalid, "permit window"):
                    evaluate(controller.original, permit, controller.policy,
                             resource=controller.context["resource"],
                             permit_uri="local:admission-1/permit.json", evaluated_at=issued)

    def test_overlong_permit_rejected_by_gate_and_reader(self):
        for already_executed in (False, True):
            with self.subTest(already_executed=already_executed):
                controller = Controller(self.root / ("overlong-" + str(already_executed)), "allow")
                # Produce internally consistent evidence under a wider local
                # policy, then evaluate it under the actual ten-minute policy.
                with patch("admission.MAX_PERMIT_LIFETIME", timedelta(minutes=20)):
                    auth = controller.authorize()
                    if already_executed:
                        controller.dispatch(auth, auth.effective)
                        controller.finish()
                        self.assertEqual(controller.slot["state"], "confirmed_success")
                if not already_executed:
                    before = provider_snapshot(controller.case)
                    gate = controller.dispatch(auth, auth.effective)
                    self.assertFalse(gate["handoff"])
                    self.assertEqual(gate["reason"], "ADMISSION_BINDING_INVALID")
                    self.assertEqual(before, provider_snapshot(controller.case))
                    self.assertIsNone(controller.slot)
                    controller.finish()
                self.assert_invalid_modes(controller.case, "invalid permit window")

    def test_query_wrapper_encoding_preserves_original_bindings(self):
        for label, encoding, spaced, wrong_attempt in (
                ("utf8-spaces", "utf-8", True, False),
                ("utf16", "utf-16", False, False),
                ("utf32", "utf-32", False, False),
                ("utf16-wrong-attempt", "utf-16", False, True)):
            with self.subTest(label=label):
                controller = Controller(self.root / label, "response-loss")
                auth = controller.authorize()
                controller.dispatch(auth, auth.effective, drop_response=True)
                original_native = read_raw(controller.case / "provider/native-result.json")
                actual_call = controller.provider_call

                def encoded_query(command, payload, **kwargs):
                    raw, transport = actual_call(command, payload, **kwargs)
                    if command == "query":
                        reply = decode(raw)
                        if wrong_attempt:
                            reply["attempt_key"] = "attempt-unrelated"
                        text = json.dumps(reply, ensure_ascii=True, indent=2) if spaced else encode(reply).decode("utf-8")
                        raw = text.encode(encoding)
                        transport["stdout_digest"] = digest(raw)
                        (controller.case / "adapter/query-stdout.bin").write_bytes(raw)
                        (controller.case / "adapter/query-transport.json").write_bytes(encode(transport))
                    return raw, transport

                before = provider_snapshot(controller.case)
                with patch.object(controller, "provider_call", side_effect=encoded_query):
                    reconciliation = controller.reconcile()
                self.assertEqual(before, provider_snapshot(controller.case))
                self.assertEqual(original_native, read_raw(controller.case / "provider/native-result.json"))
                controller.finish()
                if wrong_attempt:
                    self.assertEqual(reconciliation["state"], "indeterminate")
                    self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
                    self.assert_read_only_modes(controller.case, "indeterminate", "unknown", 1)
                else:
                    self.assertEqual(reconciliation["state"], "confirmed_success")
                    self.assert_read_only_modes(controller.case, "verified", "created", 1)

    def test_unusable_execute_responses_preserve_unknown_and_allow_read_only_recovery(self):
        for fault in ("truncated", "different-json", "empty", "nonzero"):
            for reconcile in (False, True):
                with self.subTest(fault=fault, reconcile=reconcile):
                    controller = self.response_fault_controller(f"{fault}-{reconcile}", fault, reconcile=reconcile)
                    expected = ("verified", "created") if reconcile else ("indeterminate", "unknown")
                    report = self.assert_read_only_modes(controller.case, *expected, 1)
                    self.assertEqual(report["provider_files_observed"], observe_files(controller.case))
                    self.assertEqual((controller.case / "adapter/post-execution-receipt.json").exists(), reconcile)
                    journal = read_raw(controller.case / "provider/invocations.jsonl").splitlines()
                    self.assertEqual(len(journal), 2)

    def test_unusable_query_responses_preserve_unknown_without_erasing_originals(self):
        faults = ("truncated", "different-json", "empty", "nonzero", "array", "number", "wrong-key",
                  "invalid-base64", "different-native", "unknown-status", "bool-size")
        for execute_fault in ("truncated", "empty"):
            for query_fault in faults:
                with self.subTest(execute=execute_fault, query=query_fault):
                    controller = self.response_fault_controller(f"{execute_fault}-{query_fault}", execute_fault,
                                                               reconcile=True, query_fault=query_fault)
                    self.assertEqual(controller.slot["state"], "indeterminate")
                    self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
                    self.assertEqual(controller.gate(controller.auths[0], controller.auths[0].effective)["reason"],
                                     "OPERATION_INDETERMINATE")
                    self.assert_read_only_modes(controller.case, "indeterminate", "unknown", 1)

    def test_usable_response_cannot_be_relabelled_as_unknown(self):
        for query in (False, True):
            with self.subTest(query=query):
                case = self.clone("response-loss-reconciled" if query else "allow")
                path = "adapter/reconciliation.json" if query else "adapter/attempt-observation.json"
                observation = read_json(case / path)
                del observation["post_receipt_digest"]
                observation.update(state="indeterminate", observer_state="indeterminate", effect_state="unknown",
                                   reason="invented response failure")
                if not query:
                    observation["receipt_state"] = "not_emitted"
                (case / path).write_bytes(encode(observation))
                self.change(case, "adapter/final-state.json", lambda v: v.update(state="indeterminate"))
                (case / "adapter/post-execution-receipt.json").unlink()
                self.reseal(case)
                self.assert_invalid_modes(case, "conflicts with a valid")

    def test_rejection_reason_must_match_saved_response_acceptance(self):
        for query in (False, True):
            with self.subTest(query=query):
                controller = self.response_fault_controller(str(query), "truncated", reconcile=query, query_fault="empty")
                path = "adapter/reconciliation.json" if query else "adapter/attempt-observation.json"
                self.change(controller.case, path, lambda v: v.update(reason="a different response failure"))
                self.reseal(controller.case)
                self.assert_invalid_modes(controller.case, "must")

    def test_closed_gates_preserve_and_report_preexisting_regular_files(self):
        for denied in (False, True):
            for namespace in ("sandbox", "provider"):
                for raw in (b"", b"present before dispatch"):
                    with self.subTest(denied=denied, namespace=namespace, size=len(raw)):
                        controller = Controller(self.root / f"{denied}-{namespace}-{len(raw)}", "deny" if denied else "allow")
                        auth = controller.authorize(revoked=denied)
                        path = namespace + ("/summary.txt" if namespace == "sandbox" else "/received.bin")
                        (controller.case / path).write_bytes(raw)
                        before = provider_snapshot(controller.case)
                        with patch.object(controller, "provider_call") as call:
                            gate = controller.dispatch(auth, auth.effective or auth.original)
                        call.assert_not_called()
                        self.assertFalse(gate["handoff"])
                        self.assertEqual(gate["reason"], "ADMISSION_DENIED" if denied else "UNEXPECTED_PROVIDER_STATE")
                        self.assertIsNone(controller.slot)
                        self.assertEqual(gate["provider_snapshot"], before)
                        self.assertEqual(read_json(controller.case / "adapter/after-dispatch-snapshot.json"), before)
                        self.assertEqual(provider_snapshot(controller.case), before)
                        controller.finish()
                        report = self.assert_read_only_modes(controller.case, "verified", "not_started", 0)
                        self.assertEqual(report["provider_files_observed"], observe_files(controller.case))
                        self.assertEqual(read_raw(controller.case / path), raw)
                        self.assertFalse((controller.case / "adapter/attempt-start.json").exists())
                        self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())

    def test_closed_gate_preserves_regular_diagnostic_filename_characters(self):
        names = ("prior-note.log", "prior note.log", "診断.log", "prior..note.log",
                 "cafe\u0301 (1).log", "結果-\U0001f4c4.log")
        for denied in (False, True):
            for index, name in enumerate(names):
                with self.subTest(denied=denied, name=name):
                    controller = Controller(self.root / f"{denied}-{index}", "deny" if denied else "allow")
                    diagnostic = controller.case / "provider" / name
                    diagnostic.write_bytes(b"preexisting diagnostic\n")
                    auth = controller.authorize(revoked=denied)
                    before = provider_snapshot(controller.case)
                    with patch.object(controller, "provider_call") as call:
                        gate = controller.dispatch(auth, auth.effective or auth.original)
                    call.assert_not_called()
                    self.assertEqual(gate["reason"], "ADMISSION_DENIED" if denied else "UNEXPECTED_PROVIDER_STATE")
                    self.assertFalse(gate["handoff"])
                    self.assertIsNone(controller.slot)
                    controller.finish()
                    self.assert_read_only_modes(controller.case, "verified", "not_started", 0)
                    self.assertEqual(provider_snapshot(controller.case), before)
                    self.assertEqual(diagnostic.read_bytes(), b"preexisting diagnostic\n")

    def test_manifest_paths_reject_absolute_ambiguous_and_parent_components(self):
        paths = ("", ".", "..", "../outside.txt", "/outside.txt", "//host/share",
                 "./provider/invocations.jsonl", "provider/../outside.txt",
                 "provider/./invocations.jsonl", "provider//invocations.jsonl", "provider/",
                 r"C:\outside.txt", "C:/outside.txt", "C:outside.txt",
                 r"provider\..\outside.txt", "provider/\x00outside.txt")
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                case = self.root / str(index)
                shutil.copytree(self.baselines / "deny", case)
                manifest = read_json(case / "manifest.json")
                manifest["artifacts"][path] = manifest["artifacts"].pop("provider/invocations.jsonl")
                (case / "manifest.json").write_bytes(encode(manifest))
                self.assert_invalid_modes(case, "unsafe manifest path")

    def test_changes_after_gate_refusal_cannot_be_hidden_by_resealing(self):
        for mutation in ("change", "delete", "add"):
            for rewrite_after in (False, True):
                with self.subTest(mutation=mutation, rewrite_after=rewrite_after):
                    controller = Controller(self.root / f"{mutation}-{rewrite_after}", "allow")
                    auth = controller.authorize()
                    path = controller.case / "sandbox/summary.txt"
                    path.write_bytes(b"present at gate")
                    controller.dispatch(auth, auth.effective)
                    if mutation == "change":
                        path.write_bytes(b"changed after gate")
                    elif mutation == "delete":
                        path.unlink()
                    else:
                        (controller.case / "provider/received.bin").write_bytes(b"new after gate")
                    if rewrite_after:
                        (controller.case / "adapter/after-dispatch-snapshot.json").write_bytes(encode(provider_snapshot(controller.case)))
                    controller.finish()
                    self.assert_invalid_modes(controller.case, "after a closed gate" if rewrite_after else "snapshot mismatch")

    def test_gate_snapshots_are_required_and_bound_to_refusal_or_retry(self):
        for variant in ("missing", "changed", "boolean-size", "retry"):
            with self.subTest(variant=variant):
                case = self.root / variant
                shutil.copytree(self.baselines / ("response-loss" if variant == "retry" else "deny"), case)
                path = "adapter/gate-2.json" if variant == "retry" else "adapter/gate-1.json"
                gate = read_json(case / path)
                if variant == "missing":
                    del gate["provider_snapshot"]
                elif variant == "boolean-size":
                    gate["provider_snapshot"]["provider"]["invocations.jsonl"]["size"] = False
                else:
                    gate["provider_snapshot"]["sandbox"] = {"absent.txt": {"size": 0, "digest": digest(b"")}}
                (case / path).write_bytes(encode(gate))
                self.reseal(case)
                detail = {"missing": "gate: missing", "boolean-size": "gate snapshot", "retry": "retry gate provider snapshot"}.get(
                    variant, "after a closed gate")
                self.assert_invalid_modes(case, detail)

    def test_closed_gate_cannot_hide_current_operation_execution_originals(self):
        for scenario in ("allow", "attenuate"):
            for later_gate in (False, True):
                with self.subTest(scenario=scenario, later_gate=later_gate):
                    case = self.retained_execution_case(f"{scenario}-{later_gate}", scenario)
                    before = provider_snapshot(case)
                    if later_gate:
                        # An earlier execution of this same operation is also
                        # incompatible with an unused-operation claim.
                        self.change(case, "adapter/gate-1.json", lambda v: v.update(checked_at=now()))
                        self.reseal(case)
                    self.assert_invalid_modes(case, "closed gate conflicts with retained execution")
                    self.assertEqual(provider_snapshot(case), before)

    def test_closed_gate_preserves_unrelated_execution_originals(self):
        for scenario in ("allow", "attenuate"):
            for denied in (False, True):
                with self.subTest(scenario=scenario, denied=denied):
                    case = self.retained_execution_case(f"{scenario}-{denied}", scenario, related=False, denied=denied)
                    self.assertNotEqual(read_json(case / "context.json")["operation_key"],
                                        read_json(case / "provider/native-result.json")["operation_key"])
                    report = self.assert_read_only_modes(case, "verified", "not_started", 0)
                    self.assertEqual(report["provider_files_observed"], observe_files(case))

    def test_retained_same_operation_under_new_authorization_is_not_unused(self):
        executed = Controller(self.root / "original-execution", "allow")
        old_auth = executed.authorize()
        executed.dispatch(old_auth, old_auth.effective)
        executed.finish()
        for denied in (False, True):
            with self.subTest(denied=denied):
                controller = Controller(self.root / str(denied), "deny" if denied else "allow")
                controller.original = copy.deepcopy(executed.original)
                controller.context.update(operation_key=executed.context["operation_key"], resource=executed.context["resource"])
                (controller.case / "context.json").write_bytes(encode(controller.context))
                (controller.case / "inputs/original-operation.json").write_bytes(encode(controller.original))
                auth = controller.authorize(revoked=denied)
                self.assertNotEqual(decode(old_auth.permit)["authorization_key"], decode(auth.permit)["authorization_key"])
                for namespace in ("provider", "sandbox"):
                    for path in (executed.case / namespace).iterdir():
                        shutil.copy2(path, controller.case / namespace / path.name)
                controller.dispatch(auth, auth.effective or auth.original)
                self.assertIsNone(controller.slot)
                controller.finish()
                self.assert_invalid_modes(controller.case, "closed gate conflicts with retained execution")

    def test_retained_execution_missing_attribution_evidence_cannot_mean_zero_calls(self):
        for related in (False, True):
            for removed in (("native-result.json",), ("received.bin",), ("native-result.json", "received.bin"),
                            ("invocations.jsonl",)):
                with self.subTest(related=related, removed=removed):
                    case = self.retained_execution_case(f"{related}-{'-'.join(removed)}", related=related)
                    for name in removed:
                        (case / "provider" / name).unlink()
                    self.reseal_closed_snapshot(case)
                    for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                        self.assert_namespace_cli(case, "incomplete", strict=strict)

    def test_known_execution_events_remain_recognizable_when_fields_are_missing(self):
        variants = ("original-events", "no-digests", "no-attempt", "no-attempt-or-digests", "start-name-only", "completion-name-only")
        for scenario in ("allow", "attenuate"):
            for variant in variants:
                with self.subTest(scenario=scenario, variant=variant):
                    case = self.retained_execution_case(scenario + "-" + variant, scenario)
                    events = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                    for event in events:
                        if variant in ("no-digests", "no-attempt-or-digests"):
                            event.pop("received_digest", None)
                            event.pop("native_digest", None)
                        if variant in ("no-attempt", "no-attempt-or-digests"):
                            event.pop("attempt_key", None)
                    if variant.endswith("name-only"):
                        events = [{"event": "execute_received" if variant == "start-name-only" else "completed"}]
                    (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in events))
                    for name in ("received.bin", "native-result.json"):
                        (case / "provider" / name).unlink()
                    self.reseal_closed_snapshot(case)
                    for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                        self.assert_namespace_cli(case, "incomplete", strict=strict)

    def test_missing_journal_fields_with_retained_originals_are_invalid(self):
        for field in ("attempt_key", "received_digest", "native_digest"):
            with self.subTest(field=field):
                case = self.retained_execution_case(field, related=False)
                events = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                for event in events:
                    event.pop(field, None)
                (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in events))
                self.reseal_closed_snapshot(case)
                self.assert_invalid_modes(case, "retained provider journal")

    def test_unrelated_structured_diagnostic_log_is_not_an_execution_event(self):
        controller = Controller(self.root / "diagnostic-log", "allow")
        auth = controller.authorize()
        (controller.case / "provider/invocations.jsonl").write_bytes(encode({
            "event": "diagnostic", "message": "execute_received is a field label"}) + b"\n")
        controller.dispatch(auth, auth.effective)
        controller.finish()
        self.assert_read_only_modes(controller.case, "verified", "not_started", 0)

    def test_execution_recognition_survives_invalid_unrelated_fields(self):
        variants = {
            "float": b'{"event":"completed","pid":1.0}',
            "exponent": b'{"event":"completed","pid":1e9999}',
            "unsafe": b'{"event":"completed","pid":9007199254740992}',
            "duplicate-pid": b'{"event":"completed","pid":1,"pid":2}',
            "duplicate-event-first": b'{"event":"completed","event":"diagnostic"}',
            "duplicate-event-last": b'{"event":"diagnostic","event":"execute_received"}',
            "huge-integer": b'{"event":"completed","pid":' + b'9' * 5000 + b'}',
            "nonfinite": b'{"event":"completed","pid":NaN}',
            "escaped": b'{"ev\\u0065nt":"comple\\u0074ed","pid":1.0}',
            "deep-before-event": b'{"extra":' + b'[' * 10000 + b'0' + b']' * 10000 + b',"event":"completed"}',
            "deep-after-event": b'{"event":"completed","extra":' + b'[' * 10000 + b'0' + b']' * 10000 + b'}',
        }
        for scenario in ("allow", "attenuate"):
            for missing_originals in (False, True):
                for name, raw in variants.items():
                    with self.subTest(scenario=scenario, missing_originals=missing_originals, mutation=name):
                        if not name.startswith("deep"):
                            self.assertTrue(recognize_execution_event(raw))
                            # Recognition must never weaken the contract decoder.
                            with self.assertRaises(ValueError):
                                decode(raw)
                        case = self.retained_execution_case(f"{scenario}-{missing_originals}-{name}", scenario, related=False)
                        (case / "provider/invocations.jsonl").write_bytes(raw + b"\n")
                        if missing_originals:
                            for original in ("received.bin", "native-result.json"):
                                (case / "provider" / original).unlink()
                        self.reseal_closed_snapshot(case)
                        report = verify(case)
                        if missing_originals:
                            self.assertIn(report["verdict"], ("incomplete", "invalid"), report)
                        else:
                            self.assertEqual(report["verdict"], "invalid", report)
                        for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                            self.assert_namespace_cli(case, report["verdict"], strict=strict)

    def test_unrelated_journal_values_remain_opaque_after_recognition(self):
        logs = (
            b'Unrelated historical log text.',
            b'[INFO] completed a diagnostic check.',
            b'"completed"',
            b'{"event":"diagnostic","pid":1.0,"message":"completed"}',
            b'{"event":"diagnostic","pid":9007199254740992}',
            b'{"event":"diagnostic","pid":1,"pid":2}',
            b'{"event":"diagnostic","event":"trace","pid":NaN}',
            b'{"event":"diagnostic","pid":' + b'9' * 5000 + b'}',
            b'{"event":"diagnostic","context":{"event":"completed"}}',
            b'{"event":"diagnostic","message":"\\\"event\\\":\\\"completed\\\""}',
            b'[["event","completed"]]',
        )
        for index, raw in enumerate(logs):
            with self.subTest(index=index):
                self.assertFalse(recognize_execution_event(raw))
                controller = Controller(self.root / str(index), "allow")
                auth = controller.authorize()
                (controller.case / "provider/invocations.jsonl").write_bytes(raw + b"\n")
                before = provider_snapshot(controller.case)
                controller.dispatch(auth, auth.effective)
                controller.finish()
                self.assertEqual(before, provider_snapshot(controller.case))
                self.assert_read_only_modes(controller.case, "verified", "not_started", 0)

    def test_unclassifiable_journal_objects_cannot_establish_zero_calls(self):
        for index, raw in enumerate((b'{', b'{"event":"completed","pid":not-json}',
                                     b'{"event":"diagnostic","extra":', b'{"event":"completed","extra":"\xff"}',
                                     b'\xef\xbb\xbf{"event":"completed","pid":bad}',
                                     '{"event":"completed","pid":bad}'.encode('utf-16'))):
            with self.subTest(index=index):
                controller = Controller(self.root / str(index), "allow")
                auth = controller.authorize()
                (controller.case / "provider/invocations.jsonl").write_bytes(raw + b"\n")
                controller.dispatch(auth, auth.effective)
                controller.finish()
                self.assert_invalid_modes(controller.case, "cannot classify retained journal object")

    def test_recognition_limit_preserves_unknown_without_changing_runtime_limits(self):
        recursion_limit = sys.getrecursionlimit()
        integer_limit = sys.get_int_max_str_digits() if hasattr(sys, "get_int_max_str_digits") else None
        with patch("verify_evidence.json.loads", side_effect=RecursionError("too deep")):
            with self.assertRaisesRegex(Invalid, "cannot classify retained journal"):
                recognize_execution_event(b'{"event":"completed"}')
        self.assertEqual(sys.getrecursionlimit(), recursion_limit)
        if integer_limit is not None:
            self.assertEqual(sys.get_int_max_str_digits(), integer_limit)

    def test_recognition_encoding_exception_branches(self):
        variants = (
            ('{"event":"completed"}', b"", True, None),
            ('{"event":"completed","extra":}', b"", None, json.JSONDecodeError),
            ('{"event":"completed"}', b"\xff", None, UnicodeDecodeError),
            ('{"event":"diagnostic","pid":1.0}', b"", False, None),
            ('Unrelated historical text', b"\xff", False, UnicodeDecodeError),
        )
        for encoding, bom in ENCODING_CASES:
            for prefix in (b"", bom):
                for whitespace in ("", " \t", "\r\n \t"):
                    for body, tail, expected, error in variants:
                        with self.subTest(encoding=encoding, bom=bool(prefix), whitespace=repr(whitespace), body=body, tail=tail):
                            raw = prefix + (whitespace + body).encode(encoding) + tail
                            if error is not None:
                                with self.assertRaises(error):
                                    json.loads(raw)
                            if expected is None:
                                with self.assertRaisesRegex(Invalid, "cannot classify retained journal object"):
                                    recognize_execution_event(raw)
                            else:
                                self.assertIs(recognize_execution_event(raw), expected)

    def test_recognition_encoding_depth_keeps_unknown_and_runtime_limits(self):
        recursion_limit = sys.getrecursionlimit()
        integer_limit = sys.get_int_max_str_digits() if hasattr(sys, "get_int_max_str_digits") else None
        for encoding, bom in ENCODING_CASES:
            for prefix in (b"", bom):
                for depth in (1500, 10000):
                    with self.subTest(encoding=encoding, bom=bool(prefix), depth=depth):
                        text = ' \t{"event":"completed","extra":' + '[' * depth + '0' + ']' * depth + '}'
                        try:
                            recognized = recognize_execution_event(prefix + text.encode(encoding))
                        except Invalid as exc:
                            self.assertIn("JSON nesting exceeds", str(exc))
                        else:
                            self.assertTrue(recognized)
        self.assertEqual(sys.getrecursionlimit(), recursion_limit)
        if integer_limit is not None:
            self.assertEqual(sys.get_int_max_str_digits(), integer_limit)

    def test_encoding_failure_in_provider_originals_cannot_establish_zero_calls(self):
        for encoding, bom in ENCODING_CASES:
            for with_bom in (False, True):
                for filename in ("received.bin", "native-result.json"):
                    with self.subTest(encoding=encoding, bom=with_bom, filename=filename):
                        controller = Controller(self.root / f"{encoding}-{with_bom}-{filename}", "allow")
                        auth = controller.authorize()
                        text = '\r\n \t{"contract":"vate-demo-file-set-v1"}'
                        raw = (bom if with_bom else b"") + text.encode(encoding) + b"\xff"
                        (controller.case / "provider" / filename).write_bytes(raw)
                        controller.dispatch(auth, auth.effective)
                        controller.finish()
                        self.assert_invalid_modes(controller.case, "invalid JSON encoding")

    def test_encoding_of_journal_keeps_record_boundaries_and_opaque_lines(self):
        # These valid characters can resemble a separator across encoded byte
        # boundaries, or are split by str.splitlines despite being JSON data.
        diagnostic = json.dumps({"event": "diagnostic", "pid": 1.0, "message": "\u010a\u0a00\u0085\u2028\u2029"}, ensure_ascii=False)
        variants = {
            "known": (diagnostic + '\r\n{"event":"completed"}\r\n', b"", "incomplete"),
            "unicode": ('{"event":"completed"}', b"\xff", "invalid"),
            "diagnostic": (diagnostic + '\r\n{"event":"trace","pid":1.0}', b"", "verified"),
            "mixed-opaque": (diagnostic + '\r\nUnrelated historical text', b"\xff", "verified"),
        }
        for encoding, bom in ENCODING_CASES:
            for with_bom in (False, True):
                for variant, (text, tail, expected) in variants.items():
                    with self.subTest(encoding=encoding, bom=with_bom, variant=variant):
                        raw = (bom if with_bom else b"") + ('\r\n \t' + text).encode(encoding) + tail
                        controller = Controller(self.root / f"{encoding}-{with_bom}-{variant}", "allow")
                        auth = controller.authorize()
                        (controller.case / "provider/invocations.jsonl").write_bytes(raw)
                        before = provider_snapshot(controller.case)
                        controller.dispatch(auth, auth.effective)
                        controller.finish()
                        self.assertEqual(before, provider_snapshot(controller.case))
                        if expected == "verified":
                            self.assertFalse(recognize_execution_journal(raw))
                            self.assert_read_only_modes(controller.case, "verified", "not_started", 0)
                        else:
                            for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                                self.assert_namespace_cli(controller.case, expected, strict=strict)

    def test_provider_original_recognition_survives_invalid_fields(self):
        for filename in ("received.bin", "native-result.json"):
            for missing_companion in (False, True):
                for variant in ("float", "duplicate-contract-first", "duplicate-contract-last", "huge-integer", "deep"):
                    with self.subTest(filename=filename, missing_companion=missing_companion, variant=variant):
                        case = self.retained_execution_case(f"{filename}-{missing_companion}-{variant}", related=False)
                        value = read_json(case / "provider" / filename)
                        if variant == "float":
                            if filename == "native-result.json":
                                value["pid"] = float(value["pid"])
                            else:
                                value["operation"]["target"]["files"][0]["text"] = 1.0
                        raw = encode(value)
                        if variant == "duplicate-contract-first":
                            raw = raw[:-1] + b',"contract":"unrelated"}'
                        elif variant == "duplicate-contract-last":
                            raw = b'{"contract":"unrelated",' + raw[1:]
                        elif variant == "huge-integer":
                            raw = raw[:-1] + b',"extra":' + b'9' * 5000 + b'}'
                        elif variant == "deep":
                            raw = raw[:-1] + b',"extra":' + b'[' * 10000 + b'0' + b']' * 10000 + b'}'
                        (case / "provider" / filename).write_bytes(raw)
                        (case / "provider/invocations.jsonl").write_bytes(b"")
                        if missing_companion:
                            other = "received.bin" if filename == "native-result.json" else "native-result.json"
                            (case / "provider" / other).unlink()
                        self.reseal_closed_snapshot(case)
                        report = verify(case)
                        self.assertIn(report["verdict"], ("invalid", "incomplete") if missing_companion else ("invalid",), report)
                        for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                            self.assert_namespace_cli(case, report["verdict"], strict=strict)

    def test_current_reference_cues_survive_without_a_known_contract(self):
        for filename in ("received.bin", "native-result.json"):
            for field in ("operation_key", "authorization_key", "admission_digest", "resource", "input_hash"):
                with self.subTest(filename=filename, field=field):
                    controller = Controller(self.root / (filename + "-" + field), "allow")
                    auth = controller.authorize()
                    value = {"operation_key": controller.context["operation_key"],
                             "authorization_key": read_json(controller.case / "admission-1/permit.json")["authorization_key"],
                             "admission_digest": digest(auth.receipt), "resource": controller.context["resource"],
                             "input_hash": object_hash(decode(auth.effective))}[field]
                    pair = encode(field) + b":" + encode(value)
                    # Keep an earlier current reference even if a duplicate
                    # member would overwrite it; numeric format is irrelevant.
                    body = pair + b"," + encode(field) + b':"unrelated","extra":1.0'
                    if filename == "received.bin" and field == "resource":
                        body = b'"operation":{"target":{' + body + b'}}'
                    elif filename == "received.bin" and field == "operation_key":
                        body = b'"operation":{' + body + b'}'
                    raw = b'{"contract":"unrelated",' + body + b'}'
                    (controller.case / "provider" / filename).write_bytes(raw)
                    controller.dispatch(auth, auth.effective)
                    controller.finish()
                    for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                        self.assert_namespace_cli(controller.case, "incomplete", strict=strict)

    def test_non_demo_provider_records_remain_opaque_after_recognition(self):
        for filename in ("received.bin", "native-result.json"):
            with self.subTest(filename=filename):
                controller = Controller(self.root / filename, "allow")
                auth = controller.authorize()
                raw = b'{"contract":"diagnostic","pid":1.0,"context":{"contract":"vate-demo-file-set-v1"}}'
                (controller.case / "provider" / filename).write_bytes(raw)
                before = provider_snapshot(controller.case)
                controller.dispatch(auth, auth.effective)
                controller.finish()
                self.assertEqual(before, provider_snapshot(controller.case))
                self.assert_read_only_modes(controller.case, "verified", "not_started", 0)

    def test_native_structure_rejects_bad_inventory_and_outcome_in_both_paths(self):
        variants = {
            "nonhex": lambda n: n["files"][0]["digest"].update(value="g" * 64),
            "uppercase": lambda n: n["files"][0]["digest"].update(value="A" * 64),
            "short": lambda n: n["files"][0]["digest"].update(value="0" * 63),
            "value-number": lambda n: n["files"][0]["digest"].update(value=123),
            "algorithm": lambda n: n["files"][0]["digest"].update(alg="sha-512"),
            "digest-null": lambda n: n["files"][0].update(digest=None),
            "digest-extra-field": lambda n: n["files"][0]["digest"].update(extra="unrecognized"),
            "digest-missing-field": lambda n: n["files"][0]["digest"].pop("alg"),
            "unsafe-name": lambda n: n["files"][0].update(name="../summary.txt"),
            "name-type": lambda n: n["files"][0].update(name=False),
            "duplicate-name": lambda n: n["files"].append(copy.deepcopy(n["files"][0])),
            "empty-files": lambda n: n.update(files=[]),
            "outcome-object": lambda n: n.update(outcome={"not": "a string"}),
            "outcome-bool": lambda n: n.update(outcome=True),
            "outcome-enum": lambda n: n.update(outcome="unrecognized"),
        }
        for retained in (False, True):
            for name, mutate in variants.items():
                with self.subTest(retained=retained, mutation=name):
                    if retained:
                        case = self.retained_execution_case("retained-" + name, related=False)
                    else:
                        case = self.root / ("current-" + name)
                        shutil.copytree(self.baselines / "allow", case)
                    native = read_json(case / "provider/native-result.json")
                    mutate(native)
                    raw = encode(native)
                    if retained:
                        (case / "provider/native-result.json").write_bytes(raw)
                        events = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                        events[1]["native_digest"] = digest(raw)
                        (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in events))
                        self.reseal_closed_snapshot(case)
                    else:
                        self.rebind_native(case, raw)
                    self.assert_invalid_modes(case, "native")

    def test_live_adapter_does_not_emit_post_for_invalid_native_structure(self):
        for name in ("digest", "outcome"):
            with self.subTest(name=name):
                controller = Controller(self.root / name, "allow")
                auth = controller.authorize()
                actual_call = controller.provider_call

                def corrupt(command, payload, **kwargs):
                    raw, transport = actual_call(command, payload, **kwargs)
                    native = decode(raw)
                    if name == "digest":
                        native["files"][0]["digest"]["value"] = "not-a-hash"
                    else:
                        native["outcome"] = {"not": "a string"}
                    raw = encode(native)
                    (controller.case / "provider/native-result.json").write_bytes(raw)
                    events = [decode(line) for line in read_raw(controller.case / "provider/invocations.jsonl").splitlines()]
                    events[1]["native_digest"] = digest(raw)
                    (controller.case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in events))
                    (controller.case / "adapter/execute-stdout.bin").write_bytes(raw)
                    transport["stdout_digest"] = digest(raw)
                    (controller.case / "adapter/execute-transport.json").write_bytes(encode(transport))
                    return raw, transport

                with patch.object(controller, "provider_call", side_effect=corrupt):
                    controller.dispatch(auth, auth.effective)
                self.assertEqual(controller.slot["state"], "indeterminate")
                self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
                self.assertEqual(controller.gate(auth, auth.effective)["reason"], "OPERATION_INDETERMINATE")
                controller.finish()
                self.assert_invalid_modes(controller.case, "native")

    def test_native_structure_checks_every_declared_field_type(self):
        original = read_json(self.baselines / "allow/provider/native-result.json")
        check_native_structure(original)
        variants = {
            "contract": (False, "other-contract"),
            "runtime": (False, "other-runtime"),
            "operation_key": (False, "invalid/id"),
            "authorization_key": (False, "invalid/id"),
            "attempt_key": (False, "invalid/id"),
            "resource": (False, {}),
            "pid": (True, 0),
            "started_at": (False, "not-a-time"),
            "finished_at": (False, "not-a-time"),
            "input_hash": (False, "sha-256:" + "g" * 64),
        }
        for key, values in variants.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    native = copy.deepcopy(original)
                    native[key] = value
                    with self.assertRaises((Invalid, ValueError)):
                        check_native_structure(native)

    def test_native_digest_descriptors_are_validated_before_matching_references(self):
        bad_digests = (False, None, {}, {"alg": "sha-256"}, {"alg": "sha-256", "value": False},
                       {"alg": False, "value": "0" * 64}, {"alg": "sha-512", "value": "0" * 64},
                       {"alg": "sha-256", "value": "A" * 64}, {"alg": "sha-256", "value": "0" * 63},
                       {"alg": "sha-256", "value": "g" * 64},
                       {"alg": "sha-256", "value": "0" * 64, "extra": "unknown"})
        for retained in (False, True):
            for field in ("received_digest", "admission_digest"):
                for index, value in enumerate(bad_digests):
                    with self.subTest(retained=retained, field=field, value=value):
                        name = f"digest-{retained}-{field}-{index}"
                        if retained:
                            case = self.retained_execution_case(name, related=False)
                        else:
                            case = self.root / name
                            shutil.copytree(self.baselines / "allow", case)
                        native = read_json(case / "provider/native-result.json")
                        native[field] = value
                        if retained:
                            received = read_json(case / "provider/received.bin")
                            if field == "admission_digest":
                                # Consistently rebind the malformed descriptor, so
                                # reference equality alone cannot reject this case.
                                received[field] = value
                            received_raw = encode(received)
                            (case / "provider/received.bin").write_bytes(received_raw)
                            if field == "admission_digest":
                                native["received_digest"] = digest(received_raw)
                            raw = encode(native)
                            (case / "provider/native-result.json").write_bytes(raw)
                            events = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                            events[0]["received_digest"] = native["received_digest"]
                            events[1]["native_digest"] = digest(raw)
                            (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in events))
                            self.reseal_closed_snapshot(case)
                        else:
                            self.rebind_native(case, encode(native))
                        self.assert_invalid_modes(case, field + " digest")

    def test_retained_native_outputs_must_match_received_text(self):
        files = [{"name": "alpha.txt", "text": ""}, {"name": "summary.txt", "text": "観測したファイル。\n🙂 cafe\u0301\n"}]
        variants = {
            "wrong-name": lambda n: n["files"][0].update(name="beta.txt"),
            "wrong-size": lambda n: n["files"][0].update(size=1),
            "wrong-digest": lambda n: n["files"][-1].update(digest=digest(b"different content")),
            "missing-entry": lambda n: n["files"].pop(),
            "extra-entry": lambda n: n["files"].append({"name": "zzz.txt", "size": 0, "digest": digest(b"")}),
        }
        for denied in (False, True):
            for name, mutate in variants.items():
                with self.subTest(denied=denied, mutation=name):
                    case = self.retained_output_case(f"{denied}-{name}", files, mutate_native=mutate, denied=denied)
                    before = make_manifest(case)
                    self.assert_invalid_modes(case, "retained provider outputs differ from received operation text")
                    report = verify(case)
                    self.assertIsNone(report["provider_execution_count"])
                    self.assertIsNone(report["provider_files_observed"])
                    self.assertEqual(make_manifest(case), before)

    def test_retained_output_text_sets_allow_empty_unicode_and_prior_edits(self):
        unicode_file = {"name": "summary.txt", "text": "観測したファイル。\n🙂 cafe\u0301\n"}
        sets = {
            "empty": [{"name": "summary.txt", "text": ""}],
            "unicode": [unicode_file],
            "multiple": [{"name": "alpha.txt", "text": ""}, unicode_file],
        }
        for name, files in sets.items():
            for denied in (False, True):
                for edited in (False, True):
                    with self.subTest(files=name, denied=denied, edited=edited):
                        case = self.retained_output_case(f"{name}-{denied}-{edited}", files, edited=edited, denied=denied)
                        native = read_json(case / "provider/native-result.json")
                        self.assertEqual([item["name"] for item in native["files"]], [item["name"] for item in files])
                        self.assertEqual(native["files"] == observe_files(case), not edited)
                        report = self.assert_read_only_modes(case, "verified", "not_started", 0)
                        self.assertEqual(report["provider_files_observed"], observe_files(case))

    def test_retained_structure_does_not_require_old_outputs_to_remain_unchanged(self):
        original = Controller(self.root / "old", "allow")
        auth = original.authorize()
        original.dispatch(auth, auth.effective)
        original.finish()
        controller = Controller(self.root / "new", "allow")
        auth = controller.authorize()
        for namespace in ("provider", "sandbox"):
            for path in (original.case / namespace).iterdir():
                shutil.copy2(path, controller.case / namespace / path.name)
        (controller.case / "sandbox/summary.txt").write_bytes(b"Changed before this operation's gate.")
        before = provider_snapshot(controller.case)
        controller.dispatch(auth, auth.effective)
        controller.finish()
        self.assertEqual(before, provider_snapshot(controller.case))
        self.assert_read_only_modes(controller.case, "verified", "not_started", 0)

    def test_git_is_optional_and_does_not_remove_source_byte_checks(self):
        normal = source_record()
        with patch.dict(os.environ, {"PATH": ""}):
            controller = Controller(self.root / "without-git", "allow")
            auth = controller.authorize()
            controller.dispatch(auth, auth.effective)
            controller.finish()
            report = self.assert_read_only_modes(controller.case, "verified", "created", 1)
        source = read_json(controller.case / "source.json")
        self.assertIsNone(source["base_commit"])
        self.assertEqual(source["files"], normal["files"])
        self.assertEqual(report["provenance"]["source_content"], "matched_current_source_bytes")
        relative = next(iter(source["files"]))
        self.change(controller.case, "source.json", lambda v: v["files"][relative].update(value="0" * 64))
        self.reseal(controller.case)
        self.assert_invalid_modes(controller.case, "source bytes differ")

    def test_codec_recursion_failure_is_an_invalid_input_without_changing_runtime_limit(self):
        limit = sys.getrecursionlimit()
        for codec, value in (("loads", b"[]"), ("dumps", [])):
            with self.subTest(codec=codec), patch("demo_contract.json." + codec, side_effect=RecursionError("too deep")):
                with self.assertRaisesRegex(Invalid, "JSON nesting exceeds"):
                    decode(value) if codec == "loads" else encode(value)
        self.assertEqual(sys.getrecursionlimit(), limit)

    def test_deep_manifest_and_context_produce_json_invalid_reports(self):
        for depth in (1500, 10000):
            for target in ("manifest", "context"):
                with self.subTest(depth=depth, target=target):
                    case = self.root / f"{target}-{depth}"
                    shutil.copytree(self.baselines / "allow", case)
                    (case / (target + ".json")).write_bytes(b"[" * depth + b"0" + b"]" * depth)
                    if target == "context":
                        self.reseal(case)
                    for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                        self.assert_namespace_cli(case, "invalid", strict=strict)

    def test_deep_query_preserves_reconciliation_unknown_and_retry_guard(self):
        for depth in (1500, 10000):
            with self.subTest(depth=depth):
                controller = Controller(self.root / str(depth), "response-loss")
                auth = controller.authorize()
                controller.dispatch(auth, auth.effective, drop_response=True)
                before = provider_snapshot(controller.case)
                original = read_raw(controller.case / "adapter/attempt-observation.json")
                actual_call = controller.provider_call

                def deep_query(command, payload, **kwargs):
                    raw, transport = actual_call(command, payload, **kwargs)
                    raw = b"[" * depth + b"0" + b"]" * depth
                    (controller.case / "adapter/query-stdout.bin").write_bytes(raw)
                    transport["stdout_digest"] = digest(raw)
                    (controller.case / "adapter/query-transport.json").write_bytes(encode(transport))
                    return raw, transport

                with patch.object(controller, "provider_call", side_effect=deep_query):
                    record = controller.reconcile()
                self.assertEqual(record["state"], "indeterminate")
                self.assertEqual(read_json(controller.case / "adapter/reconciliation.json"), record)
                self.assertEqual(before, provider_snapshot(controller.case))
                self.assertEqual(original, read_raw(controller.case / "adapter/attempt-observation.json"))
                self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
                self.assertEqual(controller.gate(auth, auth.effective)["reason"], "OPERATION_INDETERMINATE")
                controller.finish()
                self.assert_read_only_modes(controller.case, "indeterminate", "unknown", 1)

    def test_closed_retained_records_require_consistent_identity_and_digest_links(self):
        for variant in ("native-operation", "received-operation", "admission", "journal-digest"):
            with self.subTest(variant=variant):
                case = self.retained_execution_case(variant)
                if variant == "native-operation":
                    self.change(case, "provider/native-result.json", lambda v: v.update(operation_key="op-unrelated"))
                elif variant == "received-operation":
                    self.change(case, "provider/received.bin", lambda v: v["operation"].update(operation_key="op-unrelated"))
                elif variant == "admission":
                    self.change(case, "provider/native-result.json", lambda v: v.update(admission_digest=digest(b"other admission")))
                journal = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                journal[1]["native_digest"] = digest(b"other native" if variant == "journal-digest" else
                                                     read_raw(case / "provider/native-result.json"))
                (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in journal))
                self.reseal_closed_snapshot(case)
                self.assert_invalid_modes(case, "retained provider")

    def test_unrelated_execution_must_predate_its_claimed_gate_snapshot(self):
        case = self.retained_execution_case("foreign-future", related=False)
        gate_time = time_value(read_json(case / "adapter/gate-1.json")["checked_at"])
        native = read_json(case / "provider/native-result.json")
        native.update(started_at=(gate_time + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
                      finished_at=(gate_time + timedelta(seconds=2)).isoformat().replace("+00:00", "Z"))
        native_raw = encode(native)
        (case / "provider/native-result.json").write_bytes(native_raw)
        journal = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
        journal[0]["at"] = native["started_at"]
        journal[1].update(at=native["finished_at"], native_digest=digest(native_raw))
        (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(event) + b"\n" for event in journal))
        self.reseal_closed_snapshot(case)
        self.assert_invalid_modes(case, "postdates the claimed pre-gate snapshot")

    def test_malformed_retained_original_cannot_erase_recognizable_execution(self):
        for related in (False, True):
            with self.subTest(related=related):
                case = self.retained_execution_case(str(related), related=related)
                (case / "provider/native-result.json").write_bytes(b"broken native bytes")
                self.reseal_closed_snapshot(case)
                self.assert_invalid_modes(case, "retained native record")

    def test_unrelated_opaque_provider_logs_remain_preserved(self):
        controller = Controller(self.root / "opaque", "allow")
        auth = controller.authorize()
        for name, raw in (("invocations.jsonl", b"Unrelated historical log.\n"),
                          ("received.bin", b"Previous input bytes"), ("native-result.json", b"Unrelated note")):
            (controller.case / "provider" / name).write_bytes(raw)
        before = provider_snapshot(controller.case)
        controller.dispatch(auth, auth.effective)
        controller.finish()
        self.assertEqual(provider_snapshot(controller.case), before)
        self.assert_read_only_modes(controller.case, "verified", "not_started", 0)

    def test_missing_required_observations_remain_incomplete_in_both_modes(self):
        for name, scenario in (("attempt-observation", "allow"), ("reconciliation", "response-loss-reconciled"),
                               ("after-dispatch-snapshot", "deny")):
            with self.subTest(name=name):
                case = self.clone(scenario)
                (case / f"adapter/{name}.json").unlink()
                for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                    self.assert_namespace_cli(case, "incomplete", strict=strict)

    def test_partial_query_evidence_is_incomplete_after_resealing(self):
        failed_query = self.response_fault_controller("failed-query", "empty", reconcile=True, query_fault="empty").case
        query_names = ("query-request.json", "query-stdout.bin", "query-stderr.bin", "query-transport.json",
                       "before-query-snapshot.json", "after-query-snapshot.json", "reconciliation.json")
        for outcome, baseline in (("success", self.baselines / "response-loss-reconciled"), ("unknown", failed_query)):
            for retained in (False, True):
                for name in query_names:
                    with self.subTest(outcome=outcome, retained=retained, name=name):
                        case = self.root / f"{outcome}-{retained}-{name}"
                        shutil.copytree(baseline, case)
                        for candidate in query_names:
                            remove = candidate != name if retained else candidate == name
                            if remove:
                                (case / "adapter" / candidate).unlink()
                        self.reseal(case)
                        before = tree(case)
                        for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                            self.assert_namespace_cli(case, "incomplete", strict=strict)
                        self.assertEqual(verify(case)["issues"][0]["kind"], "missing_required_evidence")
                        self.assertEqual(tree(case), before)

    def test_query_presence_preserves_normal_unknown_and_invalid_classification(self):
        for scenario, verdict, effect in (("allow", "verified", "created"),
                                         ("response-loss-reconciled", "verified", "created"),
                                         ("response-loss", "indeterminate", "unknown")):
            with self.subTest(scenario=scenario):
                self.assert_read_only_modes(self.baselines / scenario, verdict, effect, 1)
        failed = self.response_fault_controller("failed-query", "empty", reconcile=True, query_fault="empty")
        self.assert_read_only_modes(failed.case, "indeterminate", "unknown", 1)
        wrong_query = self.clone("response-loss-reconciled")
        self.change(wrong_query, "adapter/query-request.json", lambda v: v.update(attempt_key="attempt-unrelated"))
        self.reseal(wrong_query)
        self.assert_invalid_modes(wrong_query, "query key mismatch")
        extra = self.clone("response-loss")
        (extra / "adapter/query-unrecognized.json").write_bytes(encode({}))
        self.reseal(extra)
        self.assert_invalid_modes(extra, "unexpected or unconsumed evidence artifact")

    def test_live_and_offline_native_success_conditions_match(self):
        variants = {"contract": "native contract/runtime mismatch", "unknown-field": "native: missing or unknown field",
                    "missing-field": "native: missing or unknown field", "started-at": "time ordering",
                    "input-hash": "native input/admission", "received-event": "invocation journal mismatch",
                    "completed-event": "completion journal mismatch", "completed-digest": "completion journal mismatch"}
        for mode in ("execute", "query"):
            for variant, detail in variants.items():
                with self.subTest(mode=mode, variant=variant):
                    controller = Controller(self.root / (mode + "-" + variant), "allow")
                    auth = controller.authorize()
                    case = controller.case

                    def corrupt_records():
                        native = read_json(case / "provider/native-result.json")
                        journal = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                        if variant == "contract":
                            native["contract"] = "unsupported-native-contract"
                        elif variant == "unknown-field":
                            native["unexpected"] = "unregistered field"
                        elif variant == "missing-field":
                            del native["files"]
                        elif variant == "started-at":
                            start = time_value(read_json(case / "adapter/attempt-start.json")["dispatch_started_at"])
                            native["started_at"] = (start - timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
                            journal[0]["at"] = native["started_at"]
                        elif variant == "input-hash":
                            native["input_hash"] = "sha-256:" + "0" * 64
                        elif variant == "received-event":
                            journal[0]["event"] = "unrelated-event"
                        elif variant == "completed-event":
                            journal[1]["event"] = "unrelated-event"
                        raw = encode(native)
                        (case / "provider/native-result.json").write_bytes(raw)
                        journal[1]["native_digest"] = digest(b"other bytes") if variant == "completed-digest" else digest(raw)
                        (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(e) + b"\n" for e in journal))
                        return raw

                    if mode == "query":
                        controller.dispatch(auth, auth.effective, drop_response=True)
                        corrupt_records()  # The actual read-only child returns the altered originals.
                        observation = controller.reconcile()
                    else:
                        real_call = controller.provider_call

                        def faulty_call(command, payload, **kwargs):
                            _, transport = real_call(command, payload, **kwargs)
                            raw = corrupt_records()
                            (case / "adapter/execute-stdout.bin").write_bytes(raw)
                            transport["stdout_digest"] = digest(raw)
                            (case / "adapter/execute-transport.json").write_bytes(encode(transport))
                            return raw, transport

                        with patch.object(controller, "provider_call", side_effect=faulty_call):
                            controller.dispatch(auth, auth.effective)
                        observation = read_json(case / "adapter/attempt-observation.json")
                    self.assertEqual(observation["state"], "indeterminate", observation)
                    self.assertIn(detail, observation["reason"])
                    self.assertFalse((case / "adapter/post-execution-receipt.json").exists())
                    self.assertEqual(controller.gate(auth, auth.effective)["reason"], "OPERATION_INDETERMINATE")
                    controller.finish()
                    self.assert_invalid_modes(case, detail)

    def test_returncode_type_and_unknown_semantics_in_both_live_paths(self):
        for mode in ("execute", "query"):
            for code in (False, True, "0", 1, -1, None):
                with self.subTest(mode=mode, code=code):
                    case_name = mode + "-" + type(code).__name__ + "-" + str(code)
                    controller = Controller(self.root / case_name, "allow")
                    auth = controller.authorize()
                    if mode == "query":
                        controller.dispatch(auth, auth.effective, drop_response=True)
                    real_call = controller.provider_call

                    def faulty_call(command, payload, **kwargs):
                        raw, transport = real_call(command, payload, **kwargs)
                        transport["returncode"] = code
                        (controller.case / f"adapter/{command}-transport.json").write_bytes(encode(transport))
                        return raw, transport

                    with patch.object(controller, "provider_call", side_effect=faulty_call):
                        if mode == "execute":
                            controller.dispatch(auth, auth.effective)
                        else:
                            controller.reconcile()
                    self.assertEqual(controller.slot["state"], "indeterminate")
                    self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
                    self.assertEqual(controller.gate(auth, auth.effective)["reason"], "OPERATION_INDETERMINATE")
                    controller.finish()
                    if type(code) is int or code is None:
                        report = verify(controller.case)
                        self.assertEqual((report["verdict"], report["effect_state"]), ("indeterminate", "unknown"), report)
                    else:
                        self.assert_invalid_modes(controller.case, "returncode")

    def test_zero_and_one_byte_files_remain_valid_in_execute_and_query(self):
        for size in (0, 1):
            for reconciled in (False, True):
                with self.subTest(size=size, reconciled=reconciled):
                    controller = self.sized_controller(f"size-{size}-{reconciled}", size, reconciled=reconciled)
                    report = verify(controller.case)
                    self.assertEqual((report["verdict"], report["effect_state"]), ("verified", "created"), report)
                    self.assertEqual(read_raw(controller.case / "sandbox/summary.txt"), b"x" * size)
                    self.assertIs(type(report["provider_files_observed"][0]["size"]), int)

    def test_inventory_booleans_cannot_alias_zero_or_one_byte_sizes(self):
        variants = ("manifest", "initial-snapshot", "after-snapshot", "native", "post", "query-files", "before-query", "after-query")
        for size in (0, 1):
            for variant in variants:
                if variant == "initial-snapshot" and size != 0:
                    continue  # The initialized provider journal really has zero bytes.
                with self.subTest(size=size, variant=variant):
                    reconciled = variant in ("query-files", "before-query", "after-query")
                    case = self.sized_controller(f"{variant}-{size}", size, reconciled=reconciled).case
                    boolean = bool(size)
                    if variant == "manifest":
                        self.change(case, "manifest.json", lambda v: v["artifacts"]["sandbox/summary.txt"].update(size=boolean))
                    elif variant == "native":
                        native = read_json(case / "provider/native-result.json")
                        native["files"][0]["size"] = boolean
                        self.rebind_native(case, encode(native))
                    elif variant == "post":
                        self.change(case, "adapter/post-execution-receipt.json", lambda v: v["result"]["side_effects"][0].update(size=boolean))
                        raw = read_raw(case / "adapter/post-execution-receipt.json")
                        self.change(case, "adapter/attempt-observation.json", lambda v: v.update(post_receipt_digest=digest(raw)))
                        self.reseal(case)
                    elif variant == "query-files":
                        reply = decode(read_raw(case / "adapter/query-stdout.bin"))
                        reply["current_files"][0]["size"] = boolean
                        raw = encode(reply)
                        (case / "adapter/query-stdout.bin").write_bytes(raw)
                        self.change(case, "adapter/query-transport.json", lambda v: v.update(stdout_digest=digest(raw)))
                        self.reseal(case)
                    else:
                        path = {"initial-snapshot": "initial", "after-snapshot": "after-dispatch",
                                "before-query": "before-query", "after-query": "after-query"}[variant]
                        snapshot = read_json(case / f"adapter/{path}-snapshot.json")
                        if variant == "initial-snapshot":
                            snapshot["provider"]["invocations.jsonl"]["size"] = boolean
                        else:
                            snapshot["sandbox"]["summary.txt"]["size"] = boolean
                        (case / f"adapter/{path}-snapshot.json").write_bytes(encode(snapshot))
                        self.reseal(case)
                    self.assert_invalid_modes(case, "size")

    def test_live_native_size_and_query_inventory_reject_boolean_zero(self):
        for mode in ("execute", "query"):
            controller = Controller(self.root / mode, "allow")
            controller.original["target"]["files"][0]["text"] = ""
            (controller.case / "inputs/original-operation.json").write_bytes(encode(controller.original))
            auth = controller.authorize()
            if mode == "query":
                controller.dispatch(auth, auth.effective, drop_response=True)
            real_call = controller.provider_call

            def faulty_call(command, payload, **kwargs):
                raw, transport = real_call(command, payload, **kwargs)
                value = decode(raw)
                if mode == "execute":
                    value["files"][0]["size"] = False
                    raw = encode(value)
                    (controller.case / "provider/native-result.json").write_bytes(raw)
                    journal = [decode(line) for line in read_raw(controller.case / "provider/invocations.jsonl").splitlines()]
                    journal[1]["native_digest"] = digest(raw)
                    (controller.case / "provider/invocations.jsonl").write_bytes(b"".join(encode(e) + b"\n" for e in journal))
                else:
                    value["current_files"][0]["size"] = False
                    raw = encode(value)
                (controller.case / f"adapter/{command}-stdout.bin").write_bytes(raw)
                transport["stdout_digest"] = digest(raw)
                (controller.case / f"adapter/{command}-transport.json").write_bytes(encode(transport))
                return raw, transport

            with patch.object(controller, "provider_call", side_effect=faulty_call):
                if mode == "execute":
                    controller.dispatch(auth, auth.effective)
                    observation = read_json(controller.case / "adapter/attempt-observation.json")
                else:
                    observation = controller.reconcile()
            self.assertEqual(observation["state"], "indeterminate")
            self.assertIn("size", observation["reason"])
            self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())

    def test_numeric_ranges_preserve_zero_and_unavailable_as_distinct(self):
        for size in (0, 1, MAX_ARTIFACT):
            check_size(size, "artifact")
        for value in (False, True, None, "0", -1, MAX_ARTIFACT + 1):
            with self.subTest(size=value), self.assertRaisesRegex(Invalid, "size"):
                check_size(value, "artifact")
        transport = read_json(self.baselines / "allow/adapter/execute-transport.json")
        raw = read_raw(self.baselines / "allow/adapter/execute-stdout.bin")
        stderr = read_raw(self.baselines / "allow/adapter/execute-stderr.bin")
        pid = read_json(self.baselines / "allow/context.json")["controller_pid"]
        for code in (0, 1, -1, None):
            check_transport_record({**transport, "returncode": code}, "execute", raw, stderr, pid)
        for code in (False, True, "0", 1.0, MAX_SAFE_INTEGER + 1, -MAX_SAFE_INTEGER - 1):
            with self.subTest(returncode=code), self.assertRaisesRegex(Invalid, "returncode"):
                check_transport_record({**transport, "returncode": code}, "execute", raw, stderr, pid)

    def test_required_source_set_preserves_package_scope_and_handles_additions(self):
        expected = {"reference/execution-evidence-demo/" + name for name in (
            "admission.py", "demo_contract.py", "provider.py", "run_demo.py",
            "test_execution_demo.py", "verify_evidence.py", "README.md", "CASE-CONTRACT.md")}
        expected.add("reference/vate-verifier-core/vate_verifier_core.py")
        expected.update("schemas/" + name for name in (
            "admission-request.schema.json", "admission-receipt.schema.json", "post-execution-receipt.schema.json"))
        self.assertEqual(set(REQUIRED_SOURCE_FILES), expected)
        self.assertEqual(len(REQUIRED_SOURCE_FILES), len(expected))
        root = self.copied_source("source")
        case = self.clone()
        with patch("demo_contract.ROOT", root):
            normal = source_record()["files"]
            self.assertEqual(set(normal), expected)
            self.assertEqual(normal, source_digests())
            extra = "reference/execution-evidence-demo/additional.py"
            (root / extra).write_bytes(b"# Outside the declared reference snapshot.\n")
            self.assertEqual(source_record()["files"], normal)
            self.assertEqual(verify(case)["verdict"], "verified")
            self.change(case, "source.json", lambda v: v["files"].update({extra: digest(read_raw(root / extra))}))
            self.reseal(case)
            self.assert_invalid(case, "source bytes differ")
            self.assertEqual(verify(case)["provenance"]["source_content"], "mismatch")

    def test_required_source_file_and_record_omissions_never_verify(self):
        root = self.copied_source("source")
        # Loaded modules let this exercise every required input, including the
        # Python files whose absence would otherwise prevent CLI startup.
        for index, relative in enumerate(REQUIRED_SOURCE_FILES):
            path = root / relative
            original = read_raw(path)
            for mode in ("file", "record", "both"):
                with self.subTest(source=relative, mode=mode):
                    case = self.root / f"capture-{index}-{mode}"
                    shutil.copytree(self.baselines / "allow", case)
                    if mode != "file":
                        self.change(case, "source.json", lambda v: v["files"].pop(relative))
                        self.reseal(case)
                    if mode != "record":
                        path.unlink()
                    try:
                        before = tree(case)
                        with patch("demo_contract.ROOT", root):
                            report = verify(case)
                            if mode != "record":
                                with self.assertRaises(FileNotFoundError):
                                    source_record()
                            else:
                                self.assertEqual(set(source_record()["files"]), set(REQUIRED_SOURCE_FILES))
                        self.assertEqual(report["verdict"], "invalid" if mode == "record" else "incomplete", report)
                        self.assertEqual(report["effect_state"], "unknown", report)
                        self.assertIsNone(report["provider_execution_count"], report)
                        self.assertNotEqual(report["provenance"]["source_content"], "matched_current_source_bytes")
                        self.assertEqual(tree(case), before)
                    finally:
                        if mode != "record":
                            path.write_bytes(original)

    def test_required_source_empty_files_or_records_cannot_match(self):
        for mode in ("file", "record", "both"):
            with self.subTest(mode=mode):
                root = self.copied_source(mode + "-source")
                case = self.root / (mode + "-capture")
                shutil.copytree(self.baselines / "allow", case)
                if mode != "file":
                    self.change(case, "source.json", lambda v: v.update(files={}))
                    self.reseal(case)
                if mode != "record":
                    for relative in REQUIRED_SOURCE_FILES:
                        (root / relative).unlink()
                with patch("demo_contract.ROOT", root):
                    report = verify(case)
                    if mode != "record":
                        with self.assertRaises(FileNotFoundError):
                            source_record()
                self.assertEqual(report["verdict"], "invalid" if mode == "record" else "incomplete", report)
                self.assertEqual(report["effect_state"], "unknown", report)
                self.assertIsNone(report["provider_execution_count"], report)
                self.assertNotEqual(report["provenance"]["source_content"], "matched_current_source_bytes")

    def test_required_source_rejects_links_and_nonregular_files(self):
        case = self.clone()
        for kind in ("symlink", "dangling-symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                root = self.copied_source(kind)
                path = root / "reference/execution-evidence-demo/provider.py"
                external = root / "external"
                original = read_raw(path)
                if kind != "dangling-symlink":
                    external.write_bytes(original)
                path.unlink()
                if kind in ("symlink", "dangling-symlink"):
                    path.symlink_to(external)
                elif kind == "hardlink":
                    os.link(external, path)
                elif kind == "fifo":
                    os.mkfifo(path)
                else:
                    path.mkdir()
                with patch("demo_contract.ROOT", root):
                    with self.assertRaisesRegex(Invalid, "not a single regular file"):
                        source_record()
                    self.assert_invalid(case, "not a single regular file")
                    self.assertNotEqual(verify(case)["provenance"]["source_content"], "matched_current_source_bytes")
                if external.exists():
                    self.assertEqual(external.read_bytes(), original)

    def test_required_source_cli_closes_file_record_and_combined_omissions(self):
        cases = [(None, "control")] + [(relative, mode) for relative in (
            "reference/execution-evidence-demo/provider.py", "reference/execution-evidence-demo/run_demo.py",
            "reference/execution-evidence-demo/README.md", "schemas/admission-request.schema.json")
            for mode in ("file", "record", "both")]
        for index, (relative, mode) in enumerate(cases):
            with self.subTest(source=relative, mode=mode):
                root = self.copied_source(f"source-{index}")
                case = self.root / f"capture-{index}"
                shutil.copytree(self.baselines / "allow", case)
                if mode in ("record", "both"):
                    self.change(case, "source.json", lambda v: v["files"].pop(relative))
                    self.reseal(case)
                if mode in ("file", "both"):
                    (root / relative).unlink()
                expected = "verified" if mode == "control" else "invalid" if mode == "record" else "incomplete"
                before = tree(case)
                for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                    command = [sys.executable, "-B", str(root / "reference/execution-evidence-demo/verify_evidence.py"), str(case)]
                    result = subprocess.run(command + (["--strict-schema"] if strict else []), capture_output=True, timeout=10)
                    report = decode(result.stdout)
                    self.assertEqual(result.returncode, {"verified": 0, "invalid": 1, "incomplete": 2}[expected], result.stdout + result.stderr)
                    self.assertEqual(report["verdict"], expected, report)
                    if mode != "control":
                        self.assertEqual(report["effect_state"], "unknown", report)
                        self.assertIsNone(report["provider_execution_count"], report)
                        self.assertNotEqual(report["provenance"]["source_content"], "matched_current_source_bytes")
                self.assertEqual(tree(case), before)

    def test_source_content_checks_do_not_authenticate_producer_claims(self):
        case = self.clone()
        source = read_json(case / "source.json")
        self.assertNotIn("python_executable", source)
        self.assertNotIn(str(Path(sys.executable)), read_raw(case / "source.json").decode("utf-8"))
        report = verify(case)
        self.assertEqual(report["provenance"], {"source_content": "matched_current_source_bytes",
            "producer_claims": {"status": "unverified", "fields": ["base_commit", "python"]}})
        self.change(case, "source.json", lambda v: v.update(base_commit="not-a-commit", python="other-python",
                    python_executable="/fictional/private/machine/python"))
        self.reseal(case)
        for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
            command = [sys.executable, "-B", str(HERE / "verify_evidence.py"), str(case)] + (["--strict-schema"] if strict else [])
            result = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = decode(result.stdout)
            self.assertEqual(report["provenance"], {"source_content": "matched_current_source_bytes",
                "producer_claims": {"status": "unverified", "fields": ["base_commit", "python", "python_executable"]}})
            self.assertNotIn(b"/fictional/private/machine/python", result.stdout)
        relative = next(iter(source["files"]))
        self.change(case, "source.json", lambda v: v["files"][relative].update(value="0" * 64))
        self.reseal(case)
        self.assert_invalid_modes(case, "source bytes differ")
        self.assertEqual(verify(case)["provenance"]["source_content"], "mismatch")

    def test_cli_unicode_metadata_and_error_reports_round_trip_on_strict_stdout(self):
        case = self.clone()
        keys = ("build_tag", "環境", "\U0001f4c4", "\ud800", "\udcff")
        self.change(case, "source.json", lambda v: v.update({key: "unverified" for key in keys}))
        self.reseal(case)
        for invalid in (False, True):
            if invalid:
                # Non-ASCII evidence names also occur in rejection messages.
                (case / "provider/診断.log").symlink_to(case / "source.json")
            report = verify(case)
            self.assertEqual(report["verdict"], "invalid" if invalid else "verified", report)
            if not invalid:
                self.assertTrue(set(keys).issubset(report["provenance"]["producer_claims"]["fields"]))
            for encoding in ("utf-8:strict", "ascii:strict"):
                for strict in ((False, True) if importlib.util.find_spec("jsonschema") else (False,)):
                    with self.subTest(invalid=invalid, encoding=encoding, strict=strict):
                        command = [sys.executable, "-B", str(HERE / "verify_evidence.py"), str(case)]
                        if strict:
                            command.append("--strict-schema")
                        env = {**os.environ, "PYTHONIOENCODING": encoding}
                        result = subprocess.run(command, capture_output=True, env=env, timeout=5)
                        self.assertEqual(result.returncode, 1 if invalid else 0, result.stdout + result.stderr)
                        self.assertEqual(result.stderr, b"")
                        decoded = json.loads(result.stdout)
                        if not invalid:
                            expected = {**report, "checks": report["checks"] + (
                                ["strict_existing_vate_schemas"] if strict else [])}
                            self.assertEqual(decoded, expected)
                        else:
                            self.assertEqual(decoded["verdict"], "invalid")
                            self.assertEqual(decoded["issues"][0], report["issues"][0])
                            self.assertIn("診断.log", decoded["issues"][0]["detail"])

    def test_reconciliation_boolean_flag_does_not_accept_integer_one(self):
        case = self.clone("response-loss-reconciled")
        self.change(case, "adapter/reconciliation.json", lambda v: v.update(read_only_snapshot_match=1))
        self.reseal(case)
        self.assert_invalid_modes(case, "read_only_snapshot_match must be boolean true")

    def test_provider_input_and_unicode_output_are_real_bytes(self):
        case = self.baselines / "allow"
        raw = read_raw(case / "adapter/dispatch.json")
        self.assertEqual(read_raw(case / "provider/received.bin"), raw)
        operation = decode(raw)["operation"]
        self.assertEqual(read_raw(case / "sandbox/summary.txt"), operation["target"]["files"][0]["text"].encode("utf-8"))
        self.assertIn(b"\\u89b3", raw)
        self.assertNotEqual(read_json(case / "provider/native-result.json")["pid"], read_json(case / "context.json")["controller_pid"])

    def test_attenuation_is_a_subset_without_content_edits(self):
        case = self.baselines / "attenuate"
        original = read_json(case / "inputs/original-operation.json")
        effective = read_json(case / "admission-1/effective-operation.json")
        self.assertEqual([f["name"] for f in original["target"]["files"]], ["details.txt", "summary.txt"])
        self.assertEqual(effective["target"]["files"], [original["target"]["files"][1]])
        self.assertEqual([p.name for p in (case / "sandbox").iterdir()], ["summary.txt"])
        receipt = read_json(case / "admission-1/receipt.json")
        self.assertEqual(receipt["attenuation"]["original_request_hash"], object_hash(original))
        self.assertEqual(receipt["attenuation"]["effective_request_hash"], object_hash(effective))
        self.assertEqual(receipt["request"]["input_hash"], object_hash(original))
        record = read_json(case / "admission-1/decision-record.json")
        self.assertNotEqual(record["admission_request_object_hash"], record["original_input_hash"])

    def test_closed_gates_leave_empty_provider_and_outputs(self):
        for name in ("deny", "swap-content", "swap-destination", "require-new-permit"):
            case = self.baselines / name
            with self.subTest(case=name):
                self.assertFalse(read_json(case / "adapter/gate-1.json")["handoff"])
                self.assertEqual(read_raw(case / "provider/invocations.jsonl"), b"")
                self.assertEqual(list((case / "sandbox").iterdir()), [])
                self.assertFalse((case / "adapter/execute-transport.json").exists())
                self.assertFalse((case / "adapter/post-execution-receipt.json").exists())

    def test_loss_preserves_unknown_and_blocks_fresh_permit(self):
        case = self.baselines / "response-loss"
        observation = read_json(case / "adapter/attempt-observation.json")
        self.assertEqual(observation["effect_state"], "unknown")
        self.assertNotIn("finished_at", observation)
        self.assertNotIn("output_hash", observation)
        self.assertEqual(read_raw(case / "adapter/execute-stdout.bin"), b"")
        self.assertTrue((case / "sandbox/summary.txt").is_file())
        self.assertFalse((case / "adapter/post-execution-receipt.json").exists())
        retry = read_json(case / "adapter/gate-2.json")
        self.assertEqual(retry["reason"], "OPERATION_INDETERMINATE")
        self.assertTrue(retry["eligible_by_receipt"])
        self.assertEqual(read_json(case / "admission-2/receipt.json")["decision"]["outcome"], "allow")
        self.assertNotEqual(retry["authorization_key"], observation["authorization_key"])
        self.assertEqual(retry["prior_attempt_key"], observation["attempt_key"])

    def test_reconciliation_reads_without_new_effect_or_replacing_unknown_snapshot(self):
        case = self.baselines / "response-loss-reconciled"
        self.assertEqual(read_json(case / "adapter/before-query-snapshot.json"), read_json(case / "adapter/after-query-snapshot.json"))
        self.assertEqual(read_json(case / "adapter/attempt-observation.json")["state"], "indeterminate")
        self.assertEqual(read_json(case / "adapter/final-state.json")["state"], "confirmed_success")
        post = read_json(case / "adapter/post-execution-receipt.json")
        native = read_json(case / "provider/native-result.json")
        self.assertEqual(post["execution"]["finished_at"], native["finished_at"])
        self.assertEqual(post["demo_evidence"]["authorization_key"], native["authorization_key"])
        self.assertEqual(len(read_raw(case / "provider/invocations.jsonl").splitlines()), 2)

    def test_raw_native_reference_and_canonical_bytes_are_both_required(self):
        for name, scenario, update_post in (("stale-ref", "allow", False),
                ("rebound-ref", "allow", True), ("unknown", "response-loss", False)):
            with self.subTest(case=name):
                case = self.root / name
                shutil.copytree(self.baselines / scenario, case)
                native = read_json(case / "provider/native-result.json")
                raw = json.dumps(native, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
                self.rebind_native(case, raw, update_post=update_post)
                if scenario == "allow":
                    reference = read_json(case / "adapter/post-execution-receipt.json")["demo_evidence"]["native_result"]["digest"]
                    self.assertEqual(reference == digest(raw), update_post)
                self.assertIn("raw_artifact_inventory_and_digests", verify(case)["checks"])
                self.assert_invalid(case, "non-contract native JSON bytes")
        original = self.baselines / "allow"
        self.assertEqual(read_json(original / "adapter/post-execution-receipt.json")["demo_evidence"]["native_result"]["digest"],
                         digest(read_raw(original / "provider/native-result.json")))
        case = self.clone()
        self.change(case, "adapter/post-execution-receipt.json",
                    lambda v: v["demo_evidence"]["native_result"].update(digest=digest(b"different original bytes")))
        post = read_raw(case / "adapter/post-execution-receipt.json")
        self.change(case, "adapter/attempt-observation.json", lambda v: v.update(post_receipt_digest=digest(post)))
        self.reseal(case)
        self.assert_invalid(case, "post native evidence link mismatch")

    def test_live_adapter_rejects_noncanonical_native_on_query(self):
        controller = Controller(self.root / "case", "response-loss")
        auth = controller.authorize()
        controller.dispatch(auth, auth.effective, drop_response=True)
        native = read_json(controller.case / "provider/native-result.json")
        (controller.case / "provider/native-result.json").write_bytes(json.dumps(native, indent=2).encode("utf-8"))
        result = controller.reconcile()
        self.assertEqual(result["state"], "indeterminate")
        self.assertIn("non-contract native JSON bytes", result["reason"])
        self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
        self.assertEqual(controller.try_fresh_authorization()["reason"], "OPERATION_INDETERMINATE")

    def test_reconciliation_timestamps_follow_captured_local_processing_order(self):
        case = self.baselines / "response-loss-reconciled"
        stamps = [read_json(case / path)[field] for path, field in (
            ("provider/native-result.json", "finished_at"), ("adapter/execute-transport.json", "returned_at"),
            ("adapter/attempt-observation.json", "observed_at"), ("admission-2/decision-record.json", "evaluated_at"),
            ("adapter/gate-2.json", "checked_at"), ("adapter/query-transport.json", "returned_at"),
            ("adapter/reconciliation.json", "observed_at"), ("adapter/post-execution-receipt.json", "issued_at"))]
        self.assertEqual(list(map(time_value, stamps)), sorted(map(time_value, stamps)))
        for scenario, observation_path in (("allow", "adapter/attempt-observation.json"),
                                           ("response-loss-reconciled", "adapter/reconciliation.json")):
            with self.subTest(scenario=scenario):
                case = self.clone(scenario)
                early = read_json(case / "provider/native-result.json")["finished_at"]
                self.change(case, "adapter/post-execution-receipt.json", lambda v: v.update(issued_at=early))
                post = read_raw(case / "adapter/post-execution-receipt.json")
                self.change(case, observation_path, lambda v: v.update(post_receipt_digest=digest(post)))
                self.reseal(case)
                self.assert_invalid(case, "post predates response observation")

    def test_rehashed_query_cannot_predate_unknown_retry_or_its_return(self):
        for variant in ("unknown", "retry", "query-return"):
            with self.subTest(variant=variant):
                case = self.root / variant
                shutil.copytree(self.baselines / "response-loss-reconciled", case)
                if variant == "unknown":
                    early = read_json(case / "admission-1/permit.json")["issued_at"]
                    self.change(case, "adapter/query-transport.json", lambda v: v.update(returned_at=early))
                    self.change(case, "adapter/reconciliation.json", lambda v: v.update(observed_at=early))
                    detail = "query predates original unknown observation"
                elif variant == "retry":
                    early = read_json(case / "adapter/attempt-observation.json")["observed_at"]
                    self.change(case, "adapter/query-transport.json", lambda v: v.update(returned_at=early))
                    detail = "query predates retry gate"
                else:
                    early = read_json(case / "adapter/gate-2.json")["checked_at"]
                    self.change(case, "adapter/reconciliation.json", lambda v: v.update(observed_at=early))
                    detail = "reconciliation predates query"
                self.reseal(case)
                self.assert_invalid(case, detail)

    def test_rebuilt_fresh_authorization_cannot_predate_original_observation(self):
        case = self.clone("response-loss")
        original = read_json(case / "inputs/original-operation.json")
        permit = read_json(case / "admission-2/permit.json")
        original_permit = read_json(case / "admission-1/permit.json")
        # Backdate the whole window so the chronology probe retains a valid lifetime.
        permit.update(issued_at=original_permit["issued_at"], expires_at=original_permit["expires_at"])
        auth = evaluate(original, permit, read_json(case / "policy.json"), resource=original["target"]["resource"],
                        permit_uri="local:admission-2/permit.json",
                        evaluated_at=read_json(case / "provider/native-result.json")["finished_at"])
        for filename, raw in (("permit.json", auth.permit), ("request.json", auth.request),
                              ("core-result.json", auth.core_result), ("receipt.json", auth.receipt),
                              ("decision-record.json", auth.record), ("effective-operation.json", auth.effective)):
            (case / "admission-2" / filename).write_bytes(raw)
        self.change(case, "adapter/gate-2.json", lambda v: v.update(admission_digest=digest(auth.receipt)))
        self.reseal(case)
        self.assert_invalid(case, "fresh authorization predates original observation")

    def test_coherently_rehashed_invalid_execution_pids_cannot_pass(self):
        invalid = (None, True, False, "123", 0, -1,
                   read_json(self.baselines / "allow/context.json")["controller_pid"])
        for index, pid in enumerate(invalid):
            with self.subTest(pid=pid):
                case = self.root / str(index)
                shutil.copytree(self.baselines / "allow", case)
                native = read_json(case / "provider/native-result.json")
                native["pid"] = pid
                self.change(case, "adapter/execute-transport.json", lambda v: v.update(pid=pid))
                journal = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                for event in journal:
                    event["pid"] = pid
                (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(v) + b"\n" for v in journal))
                self.rebind_native(case, encode(native))
                self.assertIn("raw_artifact_inventory_and_digests", verify(case)["checks"])
                self.assert_invalid(case, "PID")

    def test_each_execution_pid_link_and_journal_boolean_are_checked(self):
        for variant in ("native", "transport", "received-journal", "completed-journal", "boolean-journal"):
            with self.subTest(variant=variant):
                case = self.root / variant
                shutil.copytree(self.baselines / "allow", case)
                native = read_json(case / "provider/native-result.json")
                # These values only test local linkage, not process authenticity.
                native["pid"] = 1
                self.change(case, "adapter/execute-transport.json", lambda v: v.update(pid=1))
                journal = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
                for event in journal:
                    event["pid"] = 1
                if variant == "native":
                    native["pid"] = 2
                elif variant == "transport":
                    self.change(case, "adapter/execute-transport.json", lambda v: v.update(pid=2))
                else:
                    journal[1 if variant == "completed-journal" else 0]["pid"] = True if variant == "boolean-journal" else 2
                (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(v) + b"\n" for v in journal))
                self.rebind_native(case, encode(native))
                self.assert_invalid(case, "process observation mismatch" if variant in ("native", "transport") else "PID")

    def test_successful_query_requires_its_own_positive_child_pid(self):
        baseline = self.baselines / "response-loss-reconciled"
        query_pid = read_json(baseline / "adapter/query-transport.json")["pid"]
        controller_pid = read_json(baseline / "context.json")["controller_pid"]
        self.assertIs(type(query_pid), int)
        self.assertGreater(query_pid, 0)
        self.assertNotEqual(query_pid, controller_pid)
        for index, pid in enumerate((None, True, False, "123", 0, -1, controller_pid)):
            with self.subTest(pid=pid):
                case = self.root / str(index)
                shutil.copytree(baseline, case)
                self.change(case, "adapter/query-transport.json", lambda v: v.update(pid=pid))
                self.reseal(case)
                self.assert_invalid(case, "query transport PID")

    def test_live_adapter_rejects_unobserved_successful_child(self):
        for command in ("execute", "query"):
            with self.subTest(command=command):
                controller = Controller(self.root / command, "allow")
                auth = controller.authorize()
                if command == "query":
                    controller.dispatch(auth, auth.effective, drop_response=True)
                real_call = controller.provider_call

                def unobserved_call(*args, **kwargs):
                    raw, transport = real_call(*args, **kwargs)
                    transport["pid"] = None
                    (controller.case / f"adapter/{command}-transport.json").write_bytes(encode(transport))
                    return raw, transport

                with patch.object(controller, "provider_call", side_effect=unobserved_call):
                    if command == "execute":
                        controller.dispatch(auth, auth.effective)
                        observation = read_json(controller.case / "adapter/attempt-observation.json")
                    else:
                        observation = controller.reconcile()
                self.assertEqual(observation["state"], "indeterminate")
                self.assertIn("PID", observation["reason"])
                self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())

    def test_actual_process_start_failure_preserves_unknown_and_retry_guard(self):
        for command in ("execute", "query"):
            with self.subTest(command=command):
                controller = Controller(self.root / command, "allow")
                auth = controller.authorize()
                if command == "query":
                    controller.dispatch(auth, auth.effective, drop_response=True)
                before = provider_snapshot(controller.case)
                with patch("run_demo.sys.executable", str(self.root / "missing-python")):
                    if command == "execute":
                        controller.dispatch(auth, auth.effective)
                    else:
                        controller.reconcile()
                self.assertEqual(controller.slot["state"], "indeterminate")
                self.assertEqual(before, provider_snapshot(controller.case))
                self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
                transport = read_json(controller.case / f"adapter/{command}-transport.json")
                self.assertIsNone(transport["pid"])
                self.assertIsNone(transport["returncode"])
                if command == "execute":
                    self.assertEqual(controller.try_fresh_authorization()["reason"], "OPERATION_INDETERMINATE")
                else:
                    # A fresh admission after query is a live guard probe, not
                    # an earlier retry record in the saved query chronology.
                    self.assertEqual(controller.gate(auth, auth.effective)["reason"], "OPERATION_INDETERMINATE")
                controller.finish()
                report = verify(controller.case)
                self.assertEqual(report["effect_state"], "unknown", report)
                self.assertEqual(report["verdict"], "incomplete" if command == "execute" else "indeterminate", report)
                self.assertEqual(report["provider_execution_count"], None if command == "execute" else 1)

    def test_live_adapter_checks_native_and_journal_against_execute_pid(self):
        for variant in ("native", "journal"):
            with self.subTest(variant=variant):
                controller = Controller(self.root / variant, "response-loss")
                auth = controller.authorize()
                controller.dispatch(auth, auth.effective, drop_response=True)
                if variant == "native":
                    self.change(controller.case, "provider/native-result.json", lambda v: v.update(pid=None))
                else:
                    path = controller.case / "provider/invocations.jsonl"
                    journal = [decode(line) for line in read_raw(path).splitlines()]
                    journal[0]["pid"] = None
                    path.write_bytes(b"".join(encode(v) + b"\n" for v in journal))
                result = controller.reconcile()
                self.assertEqual(result["state"], "indeterminate")
                self.assertIn("PID", result["reason"])
                self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())

    def test_same_authorization_and_fresh_authorization_after_success_are_blocked(self):
        controller = Controller(self.root / "case", "allow")
        auth = controller.authorize()
        controller.dispatch(auth, auth.effective)
        before = provider_snapshot(controller.case)
        self.assertEqual(controller.gate(auth, auth.effective)["reason"], "OPERATION_ALREADY_DISPATCHED")
        self.assertEqual(controller.try_fresh_authorization()["reason"], "OPERATION_ALREADY_DISPATCHED")
        self.assertEqual(before, provider_snapshot(controller.case))
        controller.finish()
        self.assertEqual(verify(controller.case)["verdict"], "verified")

    def test_expired_or_changed_sandbox_input_stops_before_provider(self):
        controller = Controller(self.root / "case", "allow")
        auth = controller.authorize()
        expiry = core.parse_time(decode(auth.receipt)["expires_at"])
        self.assertEqual(controller.gate(auth, auth.effective, checked_at=core.iso(expiry + timedelta(seconds=1)))["reason"], "ADMISSION_WINDOW_INVALID")
        value = decode(auth.effective)
        value["target"]["resource"] += "-other"
        self.assertEqual(controller.gate(auth, encode(value))["reason"], "EXECUTION_INPUT_MISMATCH")
        self.assertEqual(provider_snapshot(controller.case), controller.initial)

    def test_explicit_new_operation_allows_same_text(self):
        first, second = self.root / "first", self.root / "second"
        self.assertEqual(run_case(first, "allow")["verdict"], "verified")
        self.assertEqual(run_case(second, "allow")["verdict"], "verified")
        self.assertNotEqual(read_json(first / "context.json")["operation_key"], read_json(second / "context.json")["operation_key"])
        self.assertEqual(read_raw(first / "sandbox/summary.txt"), read_raw(second / "sandbox/summary.txt"))

    def test_query_missing_native_keeps_unknown_and_cannot_write(self):
        controller = Controller(self.root / "case", "response-loss")
        auth = controller.authorize()
        controller.dispatch(auth, auth.effective, drop_response=True)
        (controller.case / "provider/native-result.json").unlink()
        before = provider_snapshot(controller.case)
        self.assertEqual(controller.reconcile()["state"], "indeterminate")
        self.assertEqual(before, provider_snapshot(controller.case))
        self.assertFalse((controller.case / "adapter/post-execution-receipt.json").exists())
        self.assertEqual(controller.try_fresh_authorization()["reason"], "OPERATION_INDETERMINATE")

    def test_rehashed_request_substitution_fails(self):
        case = self.clone()
        self.change(case, "admission-1/request.json", lambda v: v.update(input_hash="sha-256:" + "f" * 64))
        self.reseal(case)
        self.assert_invalid(case, "admission capsule differs")

    def test_rehashed_effective_request_widening_fails(self):
        case = self.clone("attenuate")
        (case / "admission-1/effective-operation.json").write_bytes(read_raw(case / "inputs/original-operation.json"))
        self.reseal(case)
        self.assert_invalid(case, "admission capsule differs")

    def test_rehashed_action_binding_change_fails(self):
        case = self.clone()
        self.change(case, "admission-1/receipt.json", lambda v: v["request"]["action_binding"]["digest"].update(value="a" * 64))
        self.reseal(case)
        self.assert_invalid(case, "admission capsule differs")

    def test_rehashed_empty_gate_evaluations_fail(self):
        case = self.clone()
        self.change(case, "adapter/gate-1.json", lambda v: v.update(checks=[]))
        self.reseal(case)
        self.assert_invalid(case, "gate evaluation coverage mismatch")

    def test_rehashed_forged_success_output_hash_fails(self):
        case = self.clone()
        self.change(case, "adapter/post-execution-receipt.json", lambda v: v["result"].update(output_hash="sha-256:" + "0" * 64))
        self.reseal(case)
        self.assert_invalid(case, "post result differs from actual file effects")

    def test_rehashed_empty_side_effects_do_not_pass(self):
        case = self.clone()
        self.change(case, "adapter/post-execution-receipt.json", lambda v: v["result"].update(side_effects=[]))
        self.reseal(case)
        self.assert_invalid(case, "post result differs from actual file effects")

    def test_terminal_receipt_cannot_hide_unresolved_controller_state(self):
        case = self.clone("response-loss")
        (case / "adapter/post-execution-receipt.json").write_bytes(
            read_raw(self.baselines / "allow/adapter/post-execution-receipt.json"))
        self.reseal(case)
        self.assert_invalid(case, "unresolved attempt has a fabricated terminal receipt")

    def test_native_identity_substitution_is_detected_after_rehash(self):
        for field in ("operation_key", "authorization_key", "attempt_key", "runtime", "resource", "input_hash"):
            with self.subTest(field=field):
                case = self.root / field
                shutil.copytree(self.baselines / "allow", case)
                self.change(case, "provider/native-result.json", lambda v: v.update({field: "unrelated-value"}))
                self.reseal(case)
                self.assert_invalid(case, "native")

    def test_native_time_mutation_is_checked_even_without_a_terminal_receipt(self):
        case = self.clone("response-loss")
        expiry = core.parse_time(read_json(case / "admission-1/receipt.json")["expires_at"])
        late = core.iso(expiry + timedelta(seconds=1))
        self.change(case, "provider/native-result.json", lambda v: v.update(finished_at=late))
        self.change(case, "adapter/execute-transport.json", lambda v: v.update(returned_at=late))
        self.change(case, "adapter/attempt-observation.json", lambda v: v.update(observed_at=late))
        self.reseal(case)
        self.assert_invalid(case, "outside the admission window")

    def test_coherently_rehashed_false_success_still_fails_actual_content_check(self):
        case = self.clone()
        (case / "sandbox/summary.txt").write_bytes(b"Unadmitted replacement content.\n")
        files = observe_files(case)
        self.change(case, "provider/native-result.json", lambda v: v.update(files=files))
        native = read_raw(case / "provider/native-result.json")
        (case / "adapter/execute-stdout.bin").write_bytes(native)
        self.change(case, "adapter/execute-transport.json", lambda v: v.update(stdout_digest=digest(native)))
        journal = [decode(line) for line in read_raw(case / "provider/invocations.jsonl").splitlines()]
        journal[1]["native_digest"] = digest(native)
        (case / "provider/invocations.jsonl").write_bytes(b"".join(encode(v) + b"\n" for v in journal))
        (case / "adapter/after-dispatch-snapshot.json").write_bytes(encode(provider_snapshot(case)))
        post = read_json(case / "adapter/post-execution-receipt.json")
        post["result"]["output_hash"] = object_hash({"files": files})
        post["result"]["side_effects"] = [{"tool": post["result"]["side_effects"][0]["tool"],
            "resource": post["result"]["side_effects"][0]["resource"], **f} for f in files]
        post["demo_evidence"]["native_result"]["digest"] = digest(native)
        (case / "adapter/post-execution-receipt.json").write_bytes(encode(post))
        self.change(case, "adapter/attempt-observation.json", lambda v: v.update(post_receipt_digest=digest(encode(post))))
        self.reseal(case)
        self.assert_invalid(case, "actual output content differs from admitted text")

    def test_deleted_native_cannot_be_hidden_by_removing_manifest_entry(self):
        case = self.clone()
        (case / "provider/native-result.json").unlink()
        self.reseal(case)
        report = verify(case)
        self.assertEqual(report["verdict"], "incomplete", report)
        self.assertEqual(report["effect_state"], "unknown")

    def test_missing_journal_cannot_become_zero_calls(self):
        case = self.clone("deny")
        (case / "provider/invocations.jsonl").unlink()
        self.reseal(case)
        report = verify(case)
        self.assertEqual(report["verdict"], "incomplete", report)
        self.assertIsNone(report["provider_execution_count"])

    def test_extra_file_and_unconsumed_artifact_fail(self):
        case = self.clone()
        (case / "sandbox/unexpected.txt").write_bytes(b"extra")
        self.reseal(case)
        self.assert_invalid(case, "actual output set mismatch")
        other = self.clone("deny")
        (other / "unexpected.json").write_bytes(b"{}")
        self.reseal(other)
        self.assert_invalid(other, "unexpected or unconsumed")

    def test_empty_directories_cannot_disappear_from_completed_evidence(self):
        for namespace in ("sandbox", "provider"):
            with self.subTest(namespace=namespace):
                case = self.root / namespace
                shutil.copytree(self.baselines / "allow", case)
                original_manifest = read_raw(case / "manifest.json")
                (case / namespace / "unexpected").mkdir()
                self.assert_invalid(case, "directory in flat evidence namespace")
                with self.assertRaisesRegex(Invalid, "directory in flat evidence namespace"):
                    make_manifest(case)
                self.assertEqual(read_raw(case / "manifest.json"), original_manifest)
                # Even an absent inventory cannot mask the invalid namespace.
                (case / "manifest.json").unlink()
                self.assert_invalid(case, "directory in flat evidence namespace")

    def test_missing_namespace_stays_incomplete_in_reader_and_cli(self):
        for namespace in ("provider", "sandbox"):
            for scenario in ("allow", "deny", "response-loss"):
                with self.subTest(namespace=namespace, scenario=scenario):
                    case = self.namespace_case(namespace, "missing", scenario)
                    self.assert_namespace_cli(case, "incomplete")

    def test_present_unsafe_namespace_stays_invalid_in_reader_and_cli(self):
        for namespace in ("provider", "sandbox"):
            for kind in ("file", "symlink", "dangling-symlink", "empty-subdirectory", "nonregular-entry"):
                with self.subTest(namespace=namespace, kind=kind):
                    case = self.namespace_case(namespace, kind)
                    self.assert_namespace_cli(case, "invalid")

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "use the existing dev environment for strict schema checks")
    def test_strict_schema_cli_preserves_missing_and_unsafe_namespace_classification(self):
        for namespace in ("provider", "sandbox"):
            for kind in ("missing", "file", "symlink", "dangling-symlink", "empty-subdirectory", "nonregular-entry"):
                with self.subTest(namespace=namespace, kind=kind):
                    case = self.namespace_case(namespace, kind)
                    self.assert_namespace_cli(case, "incomplete" if kind == "missing" else "invalid", strict=True)

    def test_empty_directories_close_gate_without_allocating_attempt(self):
        for namespace, name in (("sandbox", "summary.txt"), ("sandbox", "unexpected"), ("provider", "unexpected")):
            with self.subTest(namespace=namespace, name=name):
                controller = Controller(self.root / (namespace + "-" + name), "allow")
                auth = controller.authorize()
                unexpected = controller.case / namespace / name
                unexpected.mkdir()
                with patch.object(controller, "provider_call") as call:
                    gate = controller.dispatch(auth, auth.effective)
                call.assert_not_called()
                self.assertFalse(gate["handoff"])
                self.assertEqual(gate["reason"], "UNEXPECTED_PROVIDER_STATE")
                self.assertIsNone(controller.slot)
                self.assertEqual(read_json(controller.case / "adapter/gate-1.json"), gate)
                self.assertEqual(read_raw(controller.case / "adapter/candidate-1.json"), auth.effective)
                self.assertEqual(read_raw(controller.case / "provider/invocations.jsonl"), b"")
                for path in ("provider/received.bin", "provider/native-result.json", "adapter/dispatch.json",
                             "adapter/attempt-start.json", "adapter/execute-transport.json", "adapter/post-execution-receipt.json"):
                    self.assertFalse((controller.case / path).exists(), path)
                self.assertEqual(list((controller.case / "sandbox").iterdir()), [unexpected] if namespace == "sandbox" else [])
                with self.assertRaisesRegex(Invalid, "directory in flat evidence namespace"):
                    controller.finish()
                self.assertEqual(read_json(controller.case / "adapter/final-state.json")["state"], "not_dispatched")
                self.assertFalse((controller.case / "manifest.json").exists())
                self.assert_invalid(controller.case, "directory in flat evidence namespace")

    def test_direct_provider_rejects_empty_directory_before_writing_evidence(self):
        for namespace, name in (("sandbox", "summary.txt"), ("provider", "unexpected")):
            with self.subTest(namespace=namespace):
                controller = Controller(self.root / namespace, "allow")
                auth = controller.authorize()
                (controller.case / namespace / name).mkdir()
                payload = {"contract": CONTRACT, "operation": decode(auth.effective), "attempt_key": "attempt-test",
                    "authorization_key": decode(auth.permit)["authorization_key"], "admission_digest": digest(auth.receipt),
                    "effective_input_hash": object_hash(decode(auth.effective)), "runtime": "urn:vate:demo:file-provider"}
                result = subprocess.run([sys.executable, "-B", str(HERE / "provider.py"), "execute", "--case-dir", str(controller.case)],
                    input=encode(payload), capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"directory in flat evidence namespace", result.stderr)
                self.assertEqual(read_raw(controller.case / "provider/invocations.jsonl"), b"")
                self.assertFalse((controller.case / "provider/received.bin").exists())
                self.assertFalse((controller.case / "provider/native-result.json").exists())
                self.assertTrue((controller.case / namespace / name).is_dir())

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "use the existing dev environment for strict schema checks")
    def test_schema_reader_rejects_empty_directories(self):
        case = self.clone()
        (case / "sandbox/unexpected").mkdir()
        with self.assertRaisesRegex(Invalid, "directory in flat evidence namespace"):
            validate_schemas(case)

    def test_invalid_query_mapping_and_retry_key_fail(self):
        case = self.clone("response-loss-reconciled")
        self.change(case, "adapter/query-request.json", lambda v: v.update(attempt_key="attempt-unrelated"))
        self.reseal(case)
        self.assert_invalid(case, "query key mismatch")
        other = self.clone("response-loss")
        self.change(other, "adapter/gate-2.json", lambda v: v.update(prior_attempt_key="attempt-unrelated"))
        self.reseal(other)
        self.assert_invalid(other, "retry attempt linkage mismatch")

    def test_existing_case_is_never_overwritten(self):
        case = self.root / "case"
        case.mkdir()
        sentinel = case / "user-file.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            Controller(case, "allow")
        self.assertEqual(sentinel.read_text(), "keep")

    def test_strict_json_and_operation_domains(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":1.0}', b'{"x":9007199254740992}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode(raw)
        original = read_json(self.baselines / "allow/inputs/original-operation.json")
        for filename in ("../escape.txt", "/tmp/escape.txt", "nested/file.txt", "bad\\name.txt"):
            value = copy.deepcopy(original)
            value["target"]["files"][0]["name"] = filename
            with self.subTest(filename=filename), self.assertRaises(Invalid):
                validate_operation(value, value["target"]["resource"])
        value = copy.deepcopy(original)
        value["target"]["files"].append(value["target"]["files"][0])
        with self.assertRaises(Invalid):
            validate_operation(value, value["target"]["resource"])

    def test_missing_or_unknown_local_policy_check_cannot_pass(self):
        operation = read_json(self.baselines / "allow/inputs/original-operation.json")
        permit = make_permit(operation, "auth-test", issued_at=core.iso(core.utc_now()))
        for policy in ({}, {**make_policy(), "unregistered_constraint": True}):
            with self.subTest(policy=policy), self.assertRaises(Invalid):
                evaluate(operation, permit, policy, resource=operation["target"]["resource"],
                         permit_uri="local:permit.json", evaluated_at=core.iso(core.utc_now()))

    def test_direct_provider_rejects_journal_links_and_nonregular_files(self):
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                controller = Controller(self.root / kind, "allow")
                auth = controller.authorize()
                payload = {"contract": CONTRACT, "operation": decode(auth.effective), "attempt_key": "attempt-test",
                    "authorization_key": decode(auth.permit)["authorization_key"], "admission_digest": digest(auth.receipt),
                    "effective_input_hash": object_hash(decode(auth.effective)), "runtime": "urn:vate:demo:file-provider"}
                external = self.root / (kind + "-outside.txt")
                external.write_bytes(b"unchanged")
                journal = controller.case / "provider/invocations.jsonl"
                journal.unlink()
                if kind == "symlink":
                    journal.symlink_to(external)
                elif kind == "hardlink":
                    os.link(external, journal)
                elif kind == "fifo":
                    os.mkfifo(journal)
                else:
                    journal.mkdir()
                result = subprocess.run([sys.executable, "-B", str(HERE / "provider.py"), "execute", "--case-dir", str(controller.case)],
                    input=encode(payload), capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(external.read_bytes(), b"unchanged")
                self.assertEqual(list((controller.case / "sandbox").iterdir()), [])
                self.assertFalse((controller.case / "provider/received.bin").exists())

    def test_nonempty_journal_cannot_be_reset_to_unused_by_missing_outputs(self):
        controller = Controller(self.root / "case", "allow")
        auth = controller.authorize()
        controller.dispatch(auth, auth.effective)
        (controller.case / "sandbox/summary.txt").unlink()
        before = provider_snapshot(controller.case)
        result = subprocess.run([sys.executable, "-B", str(HERE / "provider.py"), "execute", "--case-dir", str(controller.case)],
            input=read_raw(controller.case / "adapter/dispatch.json"), capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"journal is not empty", result.stderr)
        self.assertEqual(before, provider_snapshot(controller.case))

    def test_verifier_rejects_symlink_artifact_and_traversal_manifest(self):
        case = self.clone("deny")
        external = self.root / "outside.txt"
        external.write_bytes(b"unchanged")
        (case / "provider/invocations.jsonl").unlink()
        (case / "provider/invocations.jsonl").symlink_to(external)
        self.assert_invalid(case, "symlink")
        other = self.clone()
        self.change(other, "manifest.json", lambda v: v["artifacts"].update({"../outside.txt": {
            "role": "scenario_input_or_provenance", "size": 9, "digest": digest(b"unchanged")}}))
        self.assert_invalid(other, "unsafe manifest path")

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "use the existing dev environment for strict schema checks")
    def test_generated_requests_and_receipts_match_existing_schemas(self):
        for scenario in SCENARIOS:
            with self.subTest(case=scenario):
                validate_schemas(self.baselines / scenario)

    def test_read_only_verifier_and_cli_status(self):
        case = self.clone()
        before = make_manifest(case)
        result = subprocess.run([sys.executable, "-B", str(HERE / "verify_evidence.py"), str(case)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, make_manifest(case))
        other = self.clone("response-loss")
        result = subprocess.run([sys.executable, "-B", str(HERE / "verify_evidence.py"), str(other)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
