"""Regression tests for the comparison in check_recorded_set.py.

The comparison must tell two JSON values apart whenever their text differs in
type, field presence, length or value. Python's == does not: 0 equals false,
1 equals true, 0 equals 0.0, and dict.get gives None for an absent field.
These tests change each retained report of the published recorded set in every
such way, at every place it applies, and require every change to be reported.

They read the real captures, so install the pinned packages first:
python -m pip install -r reference/restoration-rb-receiving/requirements-recorded.txt
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check_recorded_set as check

# What the three captures give: a passed record check, and a second reader that agrees.
AGREES = lambda raw: ("accept", "boundary-recorded")  # noqa: E731
REMOVE = object()


def walk(value, path=()):
    yield path, value
    if type(value) is dict:
        for key, item in value.items():
            yield from walk(item, path + (key,))
    elif type(value) is list:
        for index, item in enumerate(value):
            yield from walk(item, path + (index,))


def at(root, path):
    for step in path:
        root = root[step]
    return root


def edited(report, path, value):
    result = copy.deepcopy(report)
    parent = at(result, path[:-1])
    if value is REMOVE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = value
    return result


def replacements(node):
    """Other-typed values that Python's == can confuse with node, and some it cannot."""
    if type(node) is bool:
        return [("boolean as integer", int(node)), ("boolean as string", str(node).lower())]
    if type(node) is int:
        found = [("integer as float", float(node)), ("integer as string", str(node))]
        return found + ([("integer as boolean", bool(node))] if node in (0, 1) else [])
    if type(node) is str:
        return [("string as null", None), ("string as array", [node])]
    if node is None:
        return [("null as false", False), ("null as zero", 0), ("null as empty string", ""),
                ("null as empty array", []), ("null as empty object", {})]
    return [(f"{check.json_name(node)} as null", None)]


def mutations(report):
    """Each change made once at every place it applies, as (label, changed report)."""
    for path, node in list(walk(report)):
        where = ".".join(str(step) for step in path) or "report"
        if path:
            for label, value in replacements(node):
                yield f"{where}: {label}", edited(report, path, value)
            if type(at(report, path[:-1])) is dict:
                yield f"{where}: field removed", edited(report, path, REMOVE)
        if type(node) is dict:
            added = copy.deepcopy(report)
            at(added, path)["extra_field"] = None
            yield f"{where}: new null field", added
        if type(node) is list:
            appended = copy.deepcopy(report)
            at(appended, path).append(None)
            yield f"{where}: null item appended", appended
            if len({json.dumps(item) for item in node}) > 1:
                reordered = copy.deepcopy(report)
                at(reordered, path).reverse()
                yield f"{where}: items reordered", reordered


class DifferencesTests(unittest.TestCase):
    def test_values_python_calls_equal_are_different_json(self):
        pairs = (
            (0, False), (1, True), (False, 0), (True, 1), (0, 0.0), (1, 1.0),
            ({"a": 0}, {"a": False}), ([0], [False]), ([[1]], [[True]]),
            ({"a": {"b": [1, {"c": 0}]}}, {"a": {"b": [1, {"c": False}]}}),
            ({"a": None}, {}), ({}, {"a": None}), ({"a": 1, "b": None}, {"a": 1}),
            ("0", 0), (0, "0"), (None, 0), (None, False), (None, ""), (None, []),
            ([], {}), ([], None), ([1, 2], [1, 2, 3]), ([1, 2], [2, 1]), ("a", "b"), (1, 2),
        )
        for retained, fresh in pairs:
            for first, second in ((retained, fresh), (fresh, retained)):
                with self.subTest(retained=first, fresh=second):
                    self.assertTrue(check.differences(first, second))

    def test_the_same_json_value_has_no_difference(self):
        value = {"a": 1, "b": [1, 2, {"c": None, "d": False}], "e": "text", "f": {}}
        reordered = {"f": {}, "e": "text", "b": [1, 2, {"d": False, "c": None}], "a": 1}
        self.assertEqual(check.differences(value, copy.deepcopy(value)), [])
        self.assertEqual(check.differences(value, reordered), [])

    def test_a_difference_names_its_path_and_both_types(self):
        retained = {"observation_check": {"derived_counts": {"postRevocationCommits": False}}}
        fresh = {"observation_check": {"derived_counts": {"postRevocationCommits": 0}}}
        self.assertEqual(check.differences(retained, fresh),
                         ["observation_check.derived_counts.postRevocationCommits: boolean in retained, integer in fresh"])
        self.assertEqual(check.differences({"a": []}, {"a": [{}]}), ["a: 0 items in retained, 1 in fresh"])
        self.assertEqual(check.differences({"a": None}, {}), ["a: absent in fresh"])
        self.assertEqual(check.differences({}, {"a": None}), ["a: absent in retained"])

    def test_only_the_reader_source_digest_and_length_may_differ(self):
        source = {"digest_basis": "raw_file_sha256", "sha256": "a" * 64, "byte_length": 10}
        other = {**source, "sha256": "b" * 64, "byte_length": 11}
        self.assertEqual(check.differences({"reader_source": source}, {"reader_source": other}), [])
        for label, changed in (("digest as integer", {**source, "sha256": 0}),
                               ("length as boolean", {**source, "byte_length": True}),
                               ("length as float", {**source, "byte_length": 10.0}),
                               ("basis changed", {**source, "digest_basis": "other"}),
                               ("field added", {**source, "extra": None}),
                               ("field removed", {k: v for k, v in source.items() if k != "sha256"}),
                               ("null", None)):
            with self.subTest(label):
                self.assertTrue(check.differences({"reader_source": changed}, {"reader_source": source}))
        self.assertTrue(check.differences({}, {"reader_source": source}))


class RecordedCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = check.set_root()
        cls.reports = {name: json.loads((cls.root / name / "report.json").read_bytes()) for name in check.CASES}

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name)

    def case_dir(self, name):
        target = self.temp / name
        if not target.exists():
            shutil.copytree(self.root / name, target)
        return target

    def compare(self, name, report=None, raw=None, second_reader=AGREES):
        """Run compare_case on a copy of the case whose retained report is replaced."""
        case = self.case_dir(name)
        if raw is None and report is not None:
            raw = json.dumps(report).encode()
        if raw is not None:
            (case / "report.json").write_bytes(raw)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = check.compare_case(name, case, second_reader)
        return result, out.getvalue()

    def test_each_unchanged_capture_reproduces(self):
        for name in check.CASES:
            with self.subTest(case=name):
                result, out = self.compare(name)
                self.assertTrue(result, out)
                self.assertIn("report same", out)

    def test_zero_commits_as_false_is_a_difference(self):
        # postRevocationCommits is 0 in no_commit and 1 in commit_observed.
        for name, number in (("no_commit", 0), ("commit_observed", 1)):
            with self.subTest(case=name):
                report = copy.deepcopy(self.reports[name])
                counts = report["observation_check"]["derived_counts"]
                self.assertIs(type(counts["postRevocationCommits"]), int)
                self.assertEqual(counts["postRevocationCommits"], number)
                counts["postRevocationCommits"] = bool(number)
                result, out = self.compare(name, report)
                self.assertFalse(result, out)
                self.assertIn("observation_check.derived_counts.postRevocationCommits: boolean in retained, integer in fresh", out)

    def test_a_new_null_field_is_a_difference_in_each_case(self):
        for name in check.CASES:
            with self.subTest(case=name):
                report = {**self.reports[name], "extra_field": None}
                result, out = self.compare(name, report)
                self.assertFalse(result, out)
                self.assertIn("extra_field: absent in fresh", out)

    def test_a_null_field_removed_is_a_difference_in_each_case(self):
        for name in check.CASES:
            with self.subTest(case=name):
                report = copy.deepcopy(self.reports[name])
                nulls = [path for path, node in walk(report) if path and node is None
                         and type(at(report, path[:-1])) is dict]
                if name == "not_established":
                    # Its derived counts stay null rather than become zero.
                    self.assertIn(("observation_check", "derived_counts"), nulls)
                for path in nulls:
                    result, out = self.compare(name, edited(report, path, REMOVE))
                    self.assertFalse(result, out)

    def test_every_change_of_type_presence_or_length_is_reported_in_each_case(self):
        for name in check.CASES:
            with self.subTest(case=name):
                tried = 0
                for label, report in mutations(self.reports[name]):
                    result, out = self.compare(name, report)
                    self.assertFalse(result, f"{name}, {label}: {out}")
                    self.assertNotIn("report same", out, f"{name}, {label}")
                    tried += 1
                self.assertGreater(tried, 100)

    def test_a_duplicate_key_in_the_retained_report_is_a_difference(self):
        # json.loads keeps the last duplicate, so the earlier one would pass unseen.
        for name in check.CASES:
            with self.subTest(case=name):
                raw = (self.root / name / "report.json").read_bytes()
                marker = b'"ruleset":'
                self.assertEqual(raw.count(marker), 1)
                result, out = self.compare(name, raw=raw.replace(marker, b'"ruleset":"other",' + marker))
                self.assertFalse(result, out)
                self.assertIn("unreadable (DUPLICATE_JSON_KEY)", out)

    def test_a_retained_report_that_is_not_an_object_is_a_difference(self):
        for name in check.CASES:
            for raw in (b"[]", b"null", b"0", b'"report"', b"{}"):
                with self.subTest(case=name, retained=raw):
                    result, out = self.compare(name, raw=raw)
                    self.assertFalse(result, out)

    def test_reader_source_must_stay_present_and_keep_its_shape(self):
        for name in check.CASES:
            with self.subTest(case=name):
                report = copy.deepcopy(self.reports[name])
                del report["reader_source"]
                result, out = self.compare(name, report)
                self.assertFalse(result, out)
                self.assertIn("reader_source: absent in retained", out)

    def test_a_changed_reader_source_digest_and_length_are_allowed_and_reported(self):
        for name in check.CASES:
            with self.subTest(case=name):
                report = copy.deepcopy(self.reports[name])
                report["reader_source"]["sha256"] = "0" * 64
                report["reader_source"]["byte_length"] += 1
                result, out = self.compare(name, report)
                self.assertTrue(result, out)
                self.assertIn("(reader source changed)", out)

    def test_key_order_and_layout_of_the_retained_report_do_not_matter(self):
        for name in check.CASES:
            with self.subTest(case=name):
                report = self.reports[name]
                reordered = {key: report[key] for key in reversed(list(report))}
                result, out = self.compare(name, raw=json.dumps(reordered, indent=2).encode())
                self.assertTrue(result, out)

    def test_a_disagreeing_second_reader_fails_the_case(self):
        for name in check.CASES:
            for answer in (("reject", "boundary-recorded"), ("accept", "other-reason")):
                with self.subTest(case=name, second_reader=answer):
                    result, out = self.compare(name, second_reader=lambda raw: answer)
                    self.assertFalse(result, out)
                    self.assertIn("report same", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
