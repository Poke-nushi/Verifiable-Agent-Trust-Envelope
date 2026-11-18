"""Local policy validation applies before fixture generation, listening, and admission."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import http_verifier_demo as http


class VerifierPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example = http.load_policy(http.DEFAULT_POLICY)
        cls.schema = http.read_json(http.ROOT / "schemas/verifier-policy.schema.json")

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.file = self.root / "policy.json"
        self.request = {k: k for k in ("transaction_id", "requested_action", "requested_resource", "requested_tool")}

    def invalid_policies(self):
        for field in self.schema["required"]:
            policy = copy.deepcopy(self.example)
            del policy[field]
            yield field, policy
        values = {
            "version": ["other"], "profile": ["other"], "policy_id": [False], "policy_version": [""],
            "verifier_id": ["relative/path", "https://host/%zz"],
            "fail_closed": [0], "required_assurance_level": ["AL02", "AL5"],
            "accepted_states": [[], {**self.example["accepted_states"], "other": []}],
            "attenuation_handlers": [[], {"resource": "min"}, {"other": "min"}],
            "freshness": [None],
        }
        for field in ("allowed_actions", "allowed_resources", "accepted_states.passport",
                      "accepted_states.runtime", "accepted_states.permit"):
            obj = self.example
            for key in field.split("."):
                obj = obj[key]
            entry = obj[0]
            values[field] = [entry, {entry: True}, [entry, ""], [entry, 1]]
            if field.startswith("accepted_states."):
                values[field].extend([*obj, state] for state in ("suspended", "revoked", "quarantined"))
        for field, alternatives in values.items():
            for value in alternatives:
                policy = copy.deepcopy(self.example)
                parent = policy
                *path, last = field.split(".")
                for key in path:
                    parent = parent[key]
                parent[last] = value
                yield field, policy

    def test_file_and_direct_call_reject_invalid_policy_before_artifact_io(self):
        for field, policy in self.invalid_policies():
            with self.subTest(field=field, value=policy.get(field)):
                http.write_json(self.file, policy)
                with self.assertRaises(http.PolicyFileError):
                    http.load_policy(self.file)
                if field in ("policy_id", "policy_version"):
                    with self.assertRaisesRegex(ValueError, field):
                        http.verify_execute_request(verifier_dir=self.root, request=self.request, policy=policy)
                else:
                    result = http.verify_execute_request(verifier_dir=self.root, request=self.request, policy=policy)
                    report = result["verification_report"]
                    self.assertEqual((result["decision"], report["failed_checks"]), ("deny", ["verification_input"]))
                    self.assertFalse(report["receipt_emitted"])
                    self.assertNotIn("admission_receipt", result)
                    self.assertNotIn("admission_receipt_jws", result)
        for value in (None, []):
            with self.subTest(top=value), self.assertRaisesRegex(ValueError, "object"):
                http.verify_execute_request(verifier_dir=self.root, request=self.request, policy=value)
        for extension in ((1, 2), {1: "value"}, float("nan")):
            policy = {**self.example, "site_extension": extension}
            report = http.verify_execute_request(verifier_dir=self.root, request=self.request, policy=policy)["verification_report"]
            self.assertEqual(report["failed_checks"], ["verification_input"])
            self.assertFalse(report["receipt_emitted"])
        checks = []
        result = http.evaluate_execute_request(verifier_dir=self.root, request=self.request, checks=checks,
                                               policy={**self.example, "allowed_resources": "not a list"})
        self.assertEqual(result["check_details"], checks)
        self.assertEqual(result["verification_report"]["failed_checks"], ["verification_input"])
        self.assertFalse(result["verification_report"]["receipt_emitted"])

    def test_policy_schema_and_loader_agree_on_new_cases(self):
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ImportError:
            self.skipTest("jsonschema is not installed")
        checker = FormatChecker()
        checker.checks("uri")(lambda value: not isinstance(value, str) or http.is_absolute_uri(value))
        validator = Draft202012Validator(self.schema, format_checker=checker)
        for field, policy in self.invalid_policies():
            with self.subTest(field=field):
                self.assertFalse(validator.is_valid(policy))
        policy = copy.deepcopy(self.example)
        policy.update(fail_closed=False, allowed_actions=[], allowed_resources=["res:例", "res:例"],
                      attenuation_handlers={}, verifier_id="urn:example:verifier", notes={"site": "local"})
        policy["accepted_states"]["runtime"] = []
        policy["freshness"]["site_note"] = "local"
        for level in self.schema["properties"]["required_assurance_level"]["enum"]:
            policy["required_assurance_level"] = level
            self.assertTrue(validator.is_valid(policy))
            http.write_json(self.file, policy)
            self.assertEqual(http.load_policy(self.file), policy)

    def test_file_rejects_ambiguous_json_and_fractional_seconds(self):
        text = json.dumps(self.example)
        age = str(self.example["freshness"]["permit_max_age_seconds"])
        for bad in ('{"version":"other",' + text[1:],
                    '{"extra":NaN,' + text[1:],
                    text.replace('"permit_max_age_seconds": ' + age,
                                 '"permit_max_age_seconds": ' + age + '.0000000000000000001')):
            with self.subTest(), self.assertRaises(http.PolicyFileError):
                self.file.write_text(bad, encoding="utf-8")
                http.load_policy(self.file)

    def test_generation_and_startup_use_the_selected_file(self):
        output = self.root / "demo"
        output.mkdir()
        selected = output / "policy.json"
        policy = {**self.example, "policy_id": "local:example", "verifier_id": "urn:example:local"}
        raw = json.dumps(policy, indent=1).encode() + b"\n"
        selected.write_bytes(raw)
        http.generate_demo(output, policy_path=selected)
        self.assertEqual(selected.read_bytes(), raw)
        self.assertFalse(list(output.rglob("execution-receipt.*")))
        scenario = output / "scenarios/allow-active"
        request = http.read_json(scenario / "request.json")
        response = http.verify_execute_request(verifier_dir=scenario, request=request, policy=http.load_policy(selected))
        self.assertEqual(response["decision"], "allow")
        http.store_response_artifacts(scenario, response)
        self.file.write_text("{}", encoding="utf-8")
        with self.assertRaises(http.PolicyFileError):
            http.generate_demo(output, policy_path=self.file)
        self.assertEqual(selected.read_bytes(), raw)
        self.assertEqual(http.read_json(scenario / "http-verifier-response.json"), response)
        selected.unlink()
        rejected = subprocess.run([sys.executable, http.__file__, "serve", "--dir", ".", "--port", "0"],
                                  cwd=scenario, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(str(selected.resolve()), rejected.stderr)
        for name in ("http-verifier-response.json", "verifier-admission-receipt.json", "verifier-admission-receipt.jws"):
            self.assertFalse((scenario / name).exists())

    def test_corpus_requires_cases_and_preserves_json_types(self):
        self.assertFalse(http.run_corpus(self.root, policy_path=self.file)["ok"])
        self.assertFalse(http.compare_subset({"receipt_emitted": False}, {"receipt_emitted": 0}))
        self.assertFalse(http.compare_subset([{"flag": True}], [{"flag": 1}]))
        self.assertTrue(http.compare_subset({"amount": 1}, {"amount": 1.0, "other": True}))

    def test_regeneration_preserves_an_existing_tree_on_failure_or_unrelated_content(self):
        target = self.root / "demo"
        http.generate_demo(target, policy_path=http.DEFAULT_POLICY)
        request = target / "scenarios/allow-active/request.json"
        original = request.read_bytes()
        for name in ("operator-notes.txt", "execution-receipt.json"):
            with self.subTest(extra=name):
                extra = request.parent / name
                extra.write_text("keep this file")
                with self.assertRaises(http.demo.DemoOutputError):
                    http.generate_demo(target, policy_path=http.DEFAULT_POLICY)
                self.assertEqual(extra.read_text(), "keep this file")
                self.assertEqual(request.read_bytes(), original)
                extra.unlink()
        with patch.object(http, "ensure_verifier_key", side_effect=OSError("key generation unavailable")):
            with self.assertRaises(OSError):
                http.generate_demo(target, policy_path=http.DEFAULT_POLICY)
        self.assertEqual(request.read_bytes(), original)
        response = request.parent / "http-verifier-response.json"
        response.write_text("{}")
        http.generate_demo(target, policy_path=http.DEFAULT_POLICY)
        self.assertNotEqual(request.read_bytes(), original)
        self.assertFalse(response.exists())
