"""Every evaluated local fixture belongs to the corpus snapshot.

Only temporary cases, reports and artifact copies are written. The committed
corpora, indexes and fixtures are read-only test inputs.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import vate_conformance as runner


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "conformance/al2-vate-v0.3"
BINDING_CORPUS = ROOT / "conformance/request-binding-v1"

# These are the supported file selectors, not all strings named artifact/path.
# Keep cases with meaningful evaluator results for each selector, including the
# three direct-reference context kinds that do not require sut_inputs aliases.
CHECK_REFERENCES = (
    ("integrity_checks", "artifact", "allow-ap2-hnp-preauthorized-mandate"),
    ("trust_checks", "trust_bundle", "deny-alg-not-allowed"),
    ("jose_checks", "proof_package", "allow-a2a-signed-agent-card-evidence"),
    ("jose_checks", "detached_payload", "allow-a2a-signed-agent-card-evidence"),
    ("jose_checks", "trust_bundle", "allow-a2a-signed-agent-card-evidence"),
    ("policy_snapshot_checks", "artifact", "allow-valid-with-policy-snapshot"),
    ("artifact_reference_checks", "artifact", "allow-a2a-signed-agent-card-evidence"),
    ("attenuation_checks", "artifact", "deny-attenuation-approval-string"),
    ("al2_context_checks", "artifact", "allow-valid-admission"),
    ("al2_context_checks", "artifact", "deny-runtime-proof-stale"),
    ("al2_context_checks", "artifact", "allow-replay-state-unused"),
    ("linkage_checks", "artifact", "post-execution-linkage-success"),
)


def read(path: Path):
    return json.loads(path.read_bytes())


def write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class CorpusReferenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="vate-corpus-references-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.corpus = self.root / "corpus"
        (self.corpus / "cases").mkdir(parents=True)
        shutil.copyfile(CORPUS / "conformance-case.schema.json",
                        self.corpus / "conformance-case.schema.json")
        self.case_path = self.corpus / "cases/case.json"

    def install_case(self, case):
        case = copy.deepcopy(case)
        case.pop("pairing", None)
        self.assertEqual(runner.case_envelope_failures(case), [])
        self.assertEqual(runner.sut_input_contract_failures(case), [])
        write(self.case_path, case)
        return case

    def fixture_copy(self, case, reference, *, name="input.fixture"):
        target = self.root / "inputs" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(runner.resolve_artifact_path(case, reference), target)
        return target

    def selected_reference(self, case, path, mode):
        if mode == "alias":
            case["artifacts"]["selected_fixture"] = str(path)
            return "selected_fixture"
        if mode == "relative":
            return os.path.relpath(path, ROOT)
        self.assertEqual(mode, "absolute")
        return str(path)

    def assert_evaluator_reads_manifested_files(self, manifest):
        observed = set()
        read_json = runner.read_json
        adapter = runner.request_binding_support()
        read_raw = adapter.read_raw

        def observe_json(path):
            observed.add(path.resolve())
            return read_json(path)

        def observe_raw(path):
            observed.add(path.resolve())
            return read_raw(path)

        with mock.patch.object(runner, "read_json", side_effect=observe_json), \
                mock.patch.object(adapter, "read_raw", side_effect=observe_raw):
            evaluated = runner.evaluate_case(self.case_path)
        self.assertTrue(evaluated["pass"], evaluated)
        manifest_paths = {(ROOT / row["path"]).resolve() for row in manifest}
        self.assertFalse(observed - manifest_paths, sorted(observed - manifest_paths))

    def save_passing_bundle(self):
        index = runner.make_corpus_index(self.corpus)
        write(self.corpus / "corpus.json", index)
        report = runner.run_corpus(self.corpus)
        self.assertNotIn("fatal_errors", report, report)
        self.assertEqual(report["summary"], {"total": 1, "passed": 1, "failed": 0, "skipped": 0})
        self.assert_evaluator_reads_manifested_files(index["manifest"])
        report_path = self.root / "report.json"
        implementation_path = self.root / "implementation.json"
        write(report_path, report)
        args = argparse.Namespace(corpus_root=str(self.corpus),
                                  conformance_report_uri=str(report_path), report=str(report_path))
        write(implementation_path, runner.make_implementation_report(args, report))
        bundle = runner.verify_report_bundle(self.corpus, report_path, implementation_path, None)
        self.assertEqual(bundle["summary"]["failed"], 0, bundle)
        return report_path, implementation_path, index

    def assert_byte_change_invalidates_bundle(self, path, *, fresh_passes=True):
        report_path, implementation_path, index = self.save_passing_bundle()
        resolved_path = runner.display_path(path.resolve())
        self.assertIn(resolved_path, [row["path"] for row in index["manifest"]])
        original = path.read_bytes()
        path.write_bytes(original + b"\n ")
        self.assertEqual(read(path), json.loads(original))
        manifest, digest, failures = runner.corpus_manifest(self.corpus)
        self.assertEqual(failures, [])
        self.assertNotEqual(digest, index["digest"])
        self.assertNotEqual(manifest, index["manifest"])
        changed = {row["path"] for row in manifest
                   if row not in index["manifest"]}
        self.assertEqual(changed, {resolved_path})
        fresh = runner.run_corpus(self.corpus)
        self.assertNotIn("fatal_errors", fresh, fresh)
        self.assertEqual(fresh["summary"]["failed"], 0 if fresh_passes else 1, fresh)
        bundle = runner.verify_report_bundle(self.corpus, report_path, implementation_path, None)
        failed = {check["name"] for check in bundle["checks"] if not check["pass"]}
        self.assertTrue({"corpus_index.digest", "conformance_report.corpus.digest",
                         "implementation_report.corpus.digest"} <= failed, bundle)

    def test_each_check_file_selector_binds_alias_absolute_and_relative_bytes(self):
        for collection, field, case_id in CHECK_REFERENCES:
            for mode in ("alias", "absolute", "relative"):
                with self.subTest(collection=collection, field=field, case=case_id, mode=mode):
                    case = read(CORPUS / "cases" / f"{case_id}.json")
                    selected = case[collection][0]
                    target = self.fixture_copy(case, selected[field])
                    selected[field] = self.selected_reference(case, target, mode)
                    self.install_case(case)
                    self.assert_byte_change_invalidates_bundle(target)

    def test_attenuation_direct_input_semantic_mutation_is_detected(self):
        case = read(CORPUS / "cases/deny-attenuation-approval-string.json")
        source_name = case["attenuation_checks"][0]["artifact"]
        target = self.fixture_copy(case, source_name)
        del case["artifacts"][source_name]
        case["attenuation_checks"][0]["artifact"] = str(target)
        self.install_case(case)
        report_path, implementation_path, index = self.save_passing_bundle()
        valid = read(ROOT / "examples/receipts/admission-attenuate-max-amount.example.json")["attenuation"]
        self.assertEqual(runner.attenuation_validation_failures(valid), [])
        write(target, valid)
        self.assertNotEqual(runner.corpus_manifest(self.corpus)[1], index["digest"])
        fresh = runner.run_corpus(self.corpus)
        self.assertEqual(fresh["summary"]["failed"], 1, fresh)
        self.assertTrue(any("expected valid=False actual valid=True" in failure
                            for failure in fresh["cases"][0]["failures"]), fresh)
        bundle = runner.verify_report_bundle(self.corpus, report_path, implementation_path, None)
        self.assertGreater(bundle["summary"]["failed"], 0, bundle)

    def test_default_linkage_and_policy_sources_use_registered_records(self):
        for case_id, collection, source_slot in (
                ("post-execution-linkage-success", "linkage_checks", "admission_receipt"),
                ("allow-valid-with-policy-snapshot", "policy_snapshot_checks", "admission_receipt")):
            with self.subTest(collection=collection):
                case = read(CORPUS / "cases" / f"{case_id}.json")
                check = case[collection][0]
                check.pop("artifact" if collection == "linkage_checks" else "reference_paths")
                target = self.fixture_copy(case, source_slot)
                case["artifacts"][source_slot] = str(target)
                self.install_case(case)
                self.assert_byte_change_invalidates_bundle(target)

    def test_reference_paths_sources_are_named_slots_not_file_paths(self):
        for collection, allowed in (
                ("policy_snapshot_checks", ("admission_receipt", "a2a_metadata")),
                ("artifact_reference_checks", ("admission_request", "admission_receipt",
                                               "post_execution_receipt", "a2a_metadata"))):
            with self.subTest(collection=collection):
                artifact_map = {name: str(self.root / f"{name}.json") for name in allowed}
                target = self.root / "target.json"
                case = {"artifacts": artifact_map, collection: [{
                    "artifact": str(target),
                    "reference_paths": [{"artifact": name, "path": "record.digest"} for name in allowed],
                }]}
                paths, failures = runner.referenced_paths(case)
                self.assertEqual(failures, [])
                self.assertEqual(set(paths), {target, *(Path(value) for value in artifact_map.values())})
                case[collection][0]["reference_paths"][0]["artifact"] = str(target)
                self.assertTrue(any(".reference_paths[0].artifact" in failure
                                    for failure in runner.case_check_collection_failures(case)))

    def test_alias_resolution_is_one_step_and_takes_precedence_over_direct_path(self):
        with mock.patch.object(runner, "ROOT", self.root):
            case = {"artifacts": {"selected": "second", "second": "not-recursive.json",
                                  "looks/like/a/path.json": "selected-file.json"},
                    "attenuation_checks": [{"artifact": "selected", "expect_valid": False},
                                           {"artifact": "looks/like/a/path.json", "expect_valid": False}]}
            paths, failures = runner.referenced_paths(case)
            self.assertEqual(failures, [])
            self.assertEqual(set(paths), {
                self.root / "second", self.root / "not-recursive.json",
                self.root / "selected-file.json",
            })
            self.assertEqual(runner.resolve_artifact_path(case, "selected"), self.root / "second")
            self.assertEqual(runner.resolve_artifact_path(case, "looks/like/a/path.json"),
                             self.root / "selected-file.json")
            self.assertEqual(runner.resolve_artifact_path(case, "plain-relative.json"),
                             self.root / "plain-relative.json")

    def test_manifest_deduplicates_resolved_files_and_preserves_raw_digest_basis(self):
        case = read(CORPUS / "cases/deny-attenuation-approval-string.json")
        target = self.fixture_copy(case, "bad_attenuation")
        alias = self.root / "input-link.json"
        alias.symlink_to(target)
        case["artifacts"].update(first=str(target), second=str(alias))
        case["attenuation_checks"][0]["artifact"] = os.path.relpath(alias, ROOT)
        self.install_case(case)
        manifest, digest, failures = runner.corpus_manifest(self.corpus)
        self.assertEqual(failures, [])
        selected = [row for row in manifest if row["path"] == runner.display_path(target.resolve())]
        self.assertEqual(selected, [{"path": runner.display_path(target.resolve()),
                                     "sha256": runner.sha256_file(target)}])
        self.assertEqual(manifest, sorted(manifest, key=lambda row: row["path"]))
        self.assertEqual(digest, runner.digest_descriptor(manifest))

    def test_unconsumed_metadata_is_not_treated_as_a_file_reference(self):
        case = read(CORPUS / "cases/post-execution-linkage-success.json")
        unrelated = self.root / "metadata-only.json"
        write(unrelated, {"unread": True})
        text = str(unrelated)
        case["annotations"] = {"artifact": text, "path": text, "uri": text}
        case["artifacts"]["mutation"] = {"artifact": text, "path": text}
        case["validation_focus"].append(text)
        for check in case["linkage_checks"]:
            if check["kind"] != "admission_digest":
                check["artifact"] = text
        case["linkage_checks"][0]["annotation"] = {"artifact": text, "path": text}
        case["artifact_reference_checks"][0]["reference_paths"][0]["annotation"] = {"artifact": text}
        self.install_case(case)
        _, _, index = self.save_passing_bundle()
        self.assertNotIn(runner.display_path(unrelated.resolve()), [row["path"] for row in index["manifest"]])
        write(unrelated, {"unread": False})
        self.assertEqual(runner.corpus_manifest(self.corpus)[1], index["digest"])

    def test_sut_inputs_and_replay_authority_must_remain_registered_aliases(self):
        case = read(CORPUS / "cases/deny-ap2-hnp-replay.json")
        authority = next(item for item in case["sut_inputs"]
                         if item["role"] == "normalized_payment_authority")
        artifact_name = authority["artifact"]
        target = self.fixture_copy(case, artifact_name)
        case["artifacts"][artifact_name] = str(target)
        self.install_case(case)
        self.assert_byte_change_invalidates_bundle(target)
        authority["artifact"] = str(target)
        self.assertTrue(any("missing string artifact path" in failure
                            for failure in runner.sut_input_contract_failures(case)))

    def test_status_context_is_included_through_required_sut_input_alias(self):
        case = read(CORPUS / "cases/allow-status-fresh-at-boundary.json")
        name = next(check["artifact"] for check in case["al2_context_checks"]
                    if check["kind"] == "status")
        target = self.fixture_copy(case, name)
        case["artifacts"][name] = str(target)
        self.install_case(case)
        self.assert_byte_change_invalidates_bundle(target)

    def binding_case_copy(self):
        case = read(BINDING_CORPUS / "cases/allow.json")
        directory = self.root / "binding-inputs"
        shutil.copytree(BINDING_CORPUS / "fixtures/allow", directory)
        case["artifacts"] = {name: str(directory / Path(path).name)
                             for name, path in case["artifacts"].items()}
        self.install_case(case)
        return case, directory

    def test_binding_manifest_members_outside_corpus_bind_input_bytes(self):
        _, directory = self.binding_case_copy()
        self.assert_byte_change_invalidates_bundle(directory / "original.json", fresh_passes=False)
        fresh = runner.run_corpus(self.corpus)
        self.assertIn("ARTIFACT_DIGEST_MISMATCH", " ".join(fresh["cases"][0]["failures"]))

    def test_binding_manifest_collects_valid_prefix_and_reports_invalid_later_entry(self):
        _, directory = self.binding_case_copy()
        manifest_path = directory / "binding-manifest.json"
        manifest = read(manifest_path)
        manifest["artifacts"].append({"path": "missing-required-fields.json"})
        write(manifest_path, manifest)
        before, digest, failures = runner.corpus_manifest(self.corpus)
        self.assertTrue(any("request_binding_manifest" in failure and "SCHEMA_INVALID" in failure
                            for failure in failures), failures)
        prefix_path = runner.display_path((directory / "original.json").resolve())
        self.assertIn(prefix_path, [row["path"] for row in before])
        target = directory / "original.json"
        target.write_bytes(target.read_bytes() + b"\n")
        self.assertNotEqual(runner.corpus_manifest(self.corpus)[1], digest)
        with self.assertRaisesRegex(RuntimeError, "invalid corpus manifest"):
            runner.make_corpus_index(self.corpus)
        report = runner.run_corpus(self.corpus)
        self.assertIn("fatal_errors", report)
        self.assertTrue(any("request_binding_manifest" in failure for failure in report["fatal_errors"]))

    def test_binding_manifest_collection_and_loading_share_safe_member_path_rules(self):
        _, directory = self.binding_case_copy()
        path = directory / "binding-manifest.json"
        original = read(path)
        adapter = runner.request_binding_support()
        for invalid in ("../outside.json", "/tmp/outside.json", "nested/input.json",
                        "https://example.invalid/input.json", "input.json\n", None, 42):
            with self.subTest(path=invalid):
                manifest = copy.deepcopy(original)
                manifest["artifacts"][0]["path"] = invalid
                write(path, manifest)
                with self.assertRaisesRegex(ValueError, "UNSAFE_ARTIFACT_PATH"):
                    adapter.load_manifest(path)
                _, _, failures = runner.corpus_manifest(self.corpus)
                self.assertTrue(any("UNSAFE_ARTIFACT_PATH" in failure for failure in failures), failures)

    def test_binding_loader_keeps_member_read_order_before_later_entry_validation(self):
        _, directory = self.binding_case_copy()
        path = directory / "binding-manifest.json"
        manifest = read(path)
        manifest["artifacts"][1] = {"path": "invalid-entry.json"}
        write(path, manifest)
        target = directory / manifest["artifacts"][0]["path"]
        target.write_bytes(target.read_bytes() + b"\n")
        adapter = runner.request_binding_support()
        with self.assertRaisesRegex(ValueError, "ARTIFACT_DIGEST_MISMATCH"):
            adapter.load_manifest(path)

    def test_binding_members_keep_regular_file_no_symlink_and_size_bounds(self):
        _, directory = self.binding_case_copy()
        target = directory / "original.json"
        original = target.read_bytes()
        other = self.root / "symlink-target.json"
        other.write_bytes(original)
        adapter = runner.request_binding_support()
        for kind in ("symlink", "directory", "missing", "too_large"):
            with self.subTest(kind=kind):
                if target.is_dir():
                    target.rmdir()
                elif target.exists() or target.is_symlink():
                    target.unlink()
                if kind == "symlink":
                    target.symlink_to(other)
                elif kind == "directory":
                    target.mkdir()
                elif kind == "too_large":
                    target.write_bytes(b" " * (adapter.binding.MAX_BYTES + 1))
                with self.assertRaises((OSError, ValueError)):
                    adapter.load_manifest(directory / "binding-manifest.json")
                manifest, _, failures = runner.corpus_manifest(self.corpus)
                self.assertTrue(any("request_binding_manifest" in failure for failure in failures), failures)
                self.assertNotIn(runner.display_path(other.resolve()), [row["path"] for row in manifest])

    def test_binding_duplicate_members_keep_prefix_and_fail_validation(self):
        _, directory = self.binding_case_copy()
        path = directory / "binding-manifest.json"
        manifest = read(path)
        manifest["artifacts"] = [manifest["artifacts"][0]] * 2
        write(path, manifest)
        adapter = runner.request_binding_support()
        with self.assertRaisesRegex(ValueError, "DUPLICATE_ARTIFACT_URI"):
            adapter.load_manifest(path)
        collected, _, failures = runner.corpus_manifest(self.corpus)
        self.assertTrue(any("DUPLICATE_ARTIFACT_URI" in failure for failure in failures), failures)
        self.assertIn(runner.display_path((directory / "original.json").resolve()),
                      [row["path"] for row in collected])

    def test_binding_manifest_slot_must_be_registered_before_member_reads(self):
        case, _ = self.binding_case_copy()
        del case["artifacts"]["request_binding_manifest"]
        write(self.case_path, case)
        adapter = runner.request_binding_support()
        with mock.patch.object(adapter, "manifest_entries") as entries:
            _, failures = runner.request_binding_referenced_paths(case)
            self.assertEqual(failures, ["request_binding_manifest: requires artifacts.request_binding_manifest"])
            _, _, failures = runner.corpus_manifest(self.corpus)
            self.assertTrue(any("request_binding requires artifacts.request_binding_manifest" in failure
                                for failure in failures), failures)
            entries.assert_not_called()

    def test_unreferenced_corpus_index_is_excluded_without_affecting_digest(self):
        self.install_case(read(CORPUS / "cases/allow-valid-admission.json"))
        before = runner.corpus_manifest(self.corpus)
        write(self.corpus / "corpus.json", {"not_a_case_input": True})
        self.assertEqual(runner.corpus_manifest(self.corpus), before)

    def test_explicit_corpus_index_input_is_rejected_directly_and_through_alias_or_symlink(self):
        index = self.corpus / "corpus.json"
        write(index, {"not_allowed_as_input": True})
        symlink = self.root / "index-link.json"
        symlink.symlink_to(index)
        for mode, path in (("absolute", index), ("relative", index), ("alias", index),
                           ("absolute", symlink), ("alias", symlink)):
            with self.subTest(mode=mode, symlink=path == symlink):
                case = read(CORPUS / "cases/deny-attenuation-approval-string.json")
                case["attenuation_checks"][0]["artifact"] = self.selected_reference(case, path, mode)
                self.install_case(case)
                manifest, _, failures = runner.corpus_manifest(self.corpus)
                self.assertTrue(any("corpus index cannot be used as a case artifact" in failure
                                    for failure in failures), failures)
                self.assertNotIn(runner.display_path(index.resolve()), [row["path"] for row in manifest])
                with self.assertRaisesRegex(RuntimeError, "self-referential digest"):
                    runner.make_corpus_index(self.corpus)

    def test_binding_manifest_cannot_hide_an_index_input(self):
        case, _ = self.binding_case_copy()
        index = self.corpus / "corpus.json"
        write(index, {"not_allowed_as_input": True})
        adapter = runner.request_binding_support()
        member = dict(adapter.binding.reference(index.read_bytes()), path="corpus.json")
        path = self.corpus / "binding-manifest.json"
        write(path, {"contract": adapter.MANIFEST_CONTRACT, "artifacts": [member]})
        case["artifacts"]["request_binding_manifest"] = str(path)
        self.install_case(case)
        _, _, failures = runner.corpus_manifest(self.corpus)
        self.assertTrue(any("self-referential digest" in failure for failure in failures), failures)

    def test_missing_direct_inputs_have_manifest_failures_and_index_cli_fails(self):
        case = read(CORPUS / "cases/deny-attenuation-approval-string.json")
        case["attenuation_checks"][0]["artifact"] = str(self.root / "missing.fixture")
        self.install_case(case)
        output = self.root / "index.json"
        process = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/vate_conformance.py"), "index",
             "--corpus-root", str(self.corpus), "--out", str(output)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("corpus manifest artifact is not a readable regular file", process.stderr)
        self.assertNotIn("Traceback", process.stderr)
        self.assertFalse(output.exists())

    def test_invalid_and_looping_artifact_paths_produce_manifest_diagnostics(self):
        loop = self.root / "loop.fixture"
        loop.symlink_to(loop.name)
        for reference in (str(self.root / "null\x00.fixture"), str(loop)):
            with self.subTest(reference=reference):
                case = read(CORPUS / "cases/deny-attenuation-approval-string.json")
                case["attenuation_checks"][0]["artifact"] = reference
                self.install_case(case)
                _, _, failures = runner.corpus_manifest(self.corpus)
                self.assertTrue(any("corpus manifest artifact" in failure for failure in failures), failures)
                with self.assertRaisesRegex(RuntimeError, "invalid corpus manifest"):
                    runner.make_corpus_index(self.corpus)

    def test_artifact_path_resolution_errors_are_caught_without_retrying_resolution(self):
        case = read(CORPUS / "cases/deny-attenuation-approval-string.json")
        target = self.root / "resolution-failure.fixture"
        case["attenuation_checks"][0]["artifact"] = str(target)
        self.install_case(case)
        resolve = Path.resolve
        for exception in (OSError("unreadable path"), ValueError("invalid path"),
                          RuntimeError("symlink loop")):
            with self.subTest(exception=type(exception).__name__):
                def resolve_path(path, *args, **kwargs):
                    if path == target:
                        raise exception
                    return resolve(path, *args, **kwargs)
                with mock.patch.object(Path, "resolve", resolve_path):
                    _, _, failures = runner.corpus_manifest(self.corpus)
                self.assertTrue(any("path could not be resolved" in failure
                                    and type(exception).__name__ in failure for failure in failures), failures)

    def test_invalid_reference_types_are_reported_instead_of_ignored(self):
        for value in (None, "", 42, False, {}, []):
            with self.subTest(value=value):
                case = {"artifacts": {}, "attenuation_checks": [{"artifact": value}]}
                paths, failures = runner.referenced_paths(case)
                self.assertEqual(paths, [])
                self.assertEqual(failures, ["attenuation_checks[0].artifact: expected non-empty artifact reference"])
        case = {"artifacts": {"bad_alias": {}}, "attenuation_checks": [{"artifact": "bad_alias"}]}
        paths, failures = runner.referenced_paths(case)
        self.assertEqual(paths, [])
        self.assertEqual(failures, ["attenuation_checks[0].artifact: artifact path is invalid"])

    def test_current_corpus_manifests_remain_identical_to_committed_indexes(self):
        for corpus in (CORPUS, BINDING_CORPUS):
            with self.subTest(corpus=corpus.name):
                index = read(corpus / "corpus.json")
                manifest, digest, failures = runner.corpus_manifest(corpus)
                self.assertEqual(failures, [])
                self.assertEqual(manifest, index["manifest"])
                self.assertEqual(digest, index["digest"])


if __name__ == "__main__":
    unittest.main()
