"""Request-phase metadata rejection precedes artifact access; extensions stay open."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

import a2a_metadata_adapter_demo as demo
from response_uri_vectors import REQUEST_IDS, response_vector


class MetadataValidationTests(unittest.TestCase):
    def metadata(self):
        return json.loads((demo.ROOT / "examples/a2a/metadata-admission-requested-with-signed-agent-card.json").read_bytes())

    def test_shared_uri_syntax_in_every_reference_position(self):
        cases = json.loads((Path(__file__).with_name("uri-test-vectors.json")).read_bytes())
        for case in cases:
            for position in ("artifact", "evidence", "extension"):
                with self.subTest(uri=case["uri"], position=position):
                    value = self.metadata()
                    if position == "artifact":
                        value["admission_request"]["uri"] = case["uri"]
                    elif position == "evidence":
                        value["evidence_refs"][0]["uri"] = case["uri"]
                    else:
                        value["extensions"] = {case["uri"]: {"arbitrary_annotation": True}}
                    self.assertEqual(not demo.admission_requested_metadata_failures(value), case["valid"])

    def test_invalid_shapes_fail_closed_before_any_artifact_read(self):
        bad = [
            ("issued_at", "not-a-date"), ("issued_at", "2026-02-29T00:00:00Z"),
            ("issued_at", "2026-07-01T00:00:00Z\n"), ("expires_at", "later"),
            ("issued_at", 1), ("expires_at", None), ("unknown_core_field", True),
            ("annotations", []), ("extensions", []), ("extensions", {"bad name": True}),
            ("extensions", {"x_name\n": True}), ("evidence_refs", {}),
            ("evidence_refs", [None]), ("decision", {}), ("policy_snapshot", {}),
            ("post_execution_receipt", []), ("admission_receipt", None),
        ]
        values = []
        for field, replacement in bad:
            value = self.metadata()
            value[field] = replacement
            values.append((field, value))
        for field, replacement in (("unknown", True), ("uri", "local:bad path"), ("type", ""),
                                   ("digest", {"alg": "sha-256", "value": "a" * 64, "extra": True})):
            value = self.metadata()
            value["admission_request"][field] = replacement
            values.append(("reference." + field, value))
        for field, replacement in (("signature_profile", {}), ("signature_profile", {"format": "jws", "canonicalization": "jcs", "required_headers": []}),
                                   ("extensions", {"bad name": True}), ("annotations", []), ("extra", True)):
            value = self.metadata()
            value["evidence_refs"][0][field] = replacement
            values.append(("evidence." + field, value))
        for label, value in values:
            with self.subTest(label=label, value=value), patch.object(demo, "read_raw") as read:
                response = demo.adapt_task_message({"metadata": {demo.EXTENSION_URI: value}})
                self.assertEqual(response["vate_decision"], {"outcome": "deny", "reason_codes": ["SCHEMA_INVALID", "FAIL_CLOSED"]})
                read.assert_not_called()

    def test_valid_optional_fields_and_extension_contents_remain_accepted(self):
        value = self.metadata()
        value.update(issued_at="2026-07-01t00:00:00.123456z", expires_at="2026-07-01T01:00:00+00:00",
                     decision="allow", annotations={"anything": [None, True, {"nested": 1}]},
                     extensions={"x_local-option": [True, None], "urn:example:extension": {"anything": []}})
        for field in ("policy_snapshot", "admission_receipt", "post_execution_receipt"):
            value[field] = copy.deepcopy(value["admission_request"])
        evidence = value["evidence_refs"][0]
        evidence.update(extensions=value["extensions"], annotations=value["annotations"],
                        signature_profile={"format": "jws", "canonicalization": "jcs", "required_headers": ["alg"]})
        self.assertEqual(demo.admission_requested_metadata_failures(value), [])

    def test_existing_local_demo_still_returns_admission(self):
        task = json.loads(demo.TASK_MESSAGE.read_bytes())
        response = demo.adapt_task_message(task)
        self.assertEqual(response["vate_decision"]["outcome"], "attenuate")

    def test_non_object_cli_inputs_retain_the_actual_failure_source(self):
        with tempfile.TemporaryDirectory(prefix="vate-a2a-invalid-") as temporary:
            path = Path(temporary) / "task.json"
            for value in (None, False, 0, "", [], ["invalid"]):
                with self.subTest(value=value):
                    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                    path.write_bytes(raw)
                    result = subprocess.run([sys.executable, "-B", demo.__file__, "run-demo",
                                             "--task-message", str(path)],
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    response = json.loads(result.stdout)
                    self.assertEqual(response["status"]["state"], "rejected")
                    self.assertEqual(response["vate_decision"],
                                     {"outcome": "deny", "reason_codes": ["SCHEMA_INVALID", "FAIL_CLOSED"]})
                    source = response["demo_local_failure_source"]
                    self.assertEqual(source["digest"], {"alg": "sha-256", "value": hashlib.sha256(raw).hexdigest()})
                    self.assertEqual(source["kind"], "a2a_task_message")
                    self.assertEqual(source["uri"], "inline:a2a-task-message")

    def test_explicit_null_and_omitted_sources_keep_distinct_receipt_evidence(self):
        metadata = self.metadata()
        omitted = demo.make_schema_invalid_decision(metadata, "invalid input")
        explicit = demo.make_schema_invalid_decision(metadata, "invalid input", source_artifact=None)
        self.assertNotIn("demo_local_failure_source", omitted)
        self.assertEqual(explicit["demo_local_failure_source"]["digest"]["value"], hashlib.sha256(b"null").hexdigest())
        omitted_receipt, explicit_receipt = omitted["admission_receipt"], explicit["admission_receipt"]
        self.assertEqual(omitted_receipt["evidence"][0]["digest"], metadata["admission_request"]["digest"])
        self.assertEqual(explicit_receipt["evidence"], [])
        self.assertNotEqual(omitted_receipt["receipt_id"], explicit_receipt["receipt_id"])
        self.assertNotIn("demo_local_failure_source", explicit_receipt)

    def test_generated_receipt_uris_preserve_ids_and_binding(self):
        for identifier in REQUEST_IDS:
            with self.subTest(request_id=identifier):
                vector = response_vector(identifier)
                request, receipt, post, response = (vector[key] for key in
                    ("admission_request", "admission_receipt", "post_execution_receipt", "response"))
                self.assertEqual(response["vate_decision"]["outcome"], "attenuate")
                self.assertEqual(receipt["request"]["request_id"], identifier)
                self.assertEqual(receipt["receipt_id"], "admrec-" + identifier)
                self.assertEqual(receipt["request"]["input_hash"], request["input_hash"])
                self.assertEqual(receipt["attenuation"]["original_request_hash"], request["input_hash"])
                metadata = response["metadata"][demo.EXTENSION_URI]
                post_metadata = response["post_execution_metadata_example"][demo.EXTENSION_URI]
                self.assertEqual(metadata["admission_receipt"], post_metadata["admission_receipt"])
                self.assertEqual(post["admission"]["uri"], metadata["admission_receipt"]["uri"])
                self.assertEqual(post["admission"]["digest"], metadata["admission_receipt"]["digest"])
                for reference, artifact, directory in (
                    (metadata["admission_receipt"], receipt, "admission-receipts"),
                    (post_metadata["post_execution_receipt"], post, "post-execution-receipts"),
                ):
                    uri = reference["uri"]
                    self.assertTrue(demo.is_absolute_uri(uri), uri)
                    parts = urlsplit(uri)
                    self.assertEqual((parts.scheme, parts.netloc, parts.query, parts.fragment), ("local", "", "", ""))
                    segments = parts.path.split("/")
                    self.assertEqual(segments[:2], ["generated", directory])
                    self.assertEqual(len(segments), 3)
                    self.assertEqual(unquote(segments[2][:-5]), artifact["receipt_id"])
                    self.assertEqual(reference["digest"]["value"], demo.core.canonical_hash(artifact).removeprefix("sha-256:"))
                self.assertEqual(post["execution"]["effective_request_hash"], receipt["attenuation"]["effective_request_hash"])


if __name__ == "__main__":
    unittest.main()
