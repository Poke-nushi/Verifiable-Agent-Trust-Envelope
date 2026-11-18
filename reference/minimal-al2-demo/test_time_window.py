"""Signed-bundle regressions for the legacy demo's inclusive execution window."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import trust_envelope_demo as demo


class ExecutionWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="vate-al2-window-")
        cls.addClassCleanup(temporary.cleanup)
        cls.bundle_dir = Path(temporary.name) / "bundle"
        cls.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Keep fixture times and status freshness deterministic; use real signatures.
        with patch.object(demo, "utc_now", return_value=cls.now):
            cls.base_bundle = demo.build_demo_bundle(cls.bundle_dir)

    def assert_window(self, runtime_window, permit_window, execution, expected):
        bundle = copy.deepcopy(self.base_bundle)
        runtime = bundle["artifacts"]["runtime_proof"]["payload"]
        permit = bundle["artifacts"]["permit"]["payload"]
        receipt = bundle["artifacts"]["receipt"]["payload"]

        def timestamp(seconds):
            return demo.iso(self.now + timedelta(seconds=seconds))

        runtime["issued_at"], runtime["expires_at"] = map(timestamp, runtime_window)
        permit["issued_at"], permit["constraints"]["expires_at"] = map(timestamp, permit_window)
        receipt["started_at"], receipt["finished_at"] = map(timestamp, execution)
        for name in ("runtime_proof", "permit", "receipt"):
            demo.resign_artifact(bundle, name, self.bundle_dir)
        demo.write_bundle(self.bundle_dir, bundle)
        checked_at = self.now + timedelta(seconds=max(execution))
        with patch.object(demo, "utc_now", return_value=checked_at):
            report = demo.verify_demo(self.bundle_dir, status_mode="stapled")

        checks = {check["name"]: check["ok"] for check in report["checks"]}
        self.assertIs(checks["permit_runtime_window"], expected)
        self.assertIs(report["ok"], expected)
        # Rejection must come from the time window, not invalid signatures or status.
        self.assertEqual(
            {name for name, ok in checks.items() if not ok},
            set() if expected else {"permit_runtime_window"},
        )
        self.assertEqual(
            json.loads((self.bundle_dir / "verification-report.json").read_text()), report,
        )

    def test_valid_intervals_and_inclusive_boundaries(self):
        # All pairs are seconds from the same origin: runtime, permit, execution.
        cases = (
            ("inside_both_windows", (0, 300), (30, 180), (60, 120)),
            ("starts_at_runtime_issuance", (30, 300), (0, 180), (30, 120)),
            ("starts_at_permit_issuance", (0, 300), (30, 180), (30, 120)),
            ("finishes_at_runtime_expiry", (0, 180), (30, 300), (60, 180)),
            ("finishes_at_permit_expiry", (0, 300), (30, 180), (60, 180)),
            ("zero_duration_inside", (0, 300), (30, 180), (60, 60)),
            ("single_shared_instant", (0, 60), (60, 180), (60, 60)),
        )
        for name, runtime, permit, execution in cases:
            with self.subTest(name=name):
                self.assert_window(runtime, permit, execution, True)

    def test_passport_covers_execution_even_when_checked_later(self):
        base = self.base_bundle["artifacts"]["receipt"]["payload"]
        start, finish = (demo.parse_time(base[k]) for k in ("started_at", "finished_at"))
        second = timedelta(seconds=1)
        for lower, upper, expected in ((start, finish, True), (start + second, finish, False),
                                       (start, finish - second, False)):
            with self.subTest(lower=lower, upper=upper):
                bundle = copy.deepcopy(self.base_bundle)
                bundle["artifacts"]["passport"]["payload"].update(valid_from=demo.iso(lower), valid_until=demo.iso(upper))
                demo.resign_artifact(bundle, "passport", self.bundle_dir)
                demo.write_bundle(self.bundle_dir, bundle)
                with patch.object(demo, "utc_now", return_value=finish + second):
                    report = demo.verify_demo(self.bundle_dir, status_mode="stapled")
                failures = {check["name"] for check in report["checks"] if not check["ok"]}
                self.assertEqual(failures, set() if expected else {"passport_window"})

    def test_time_boundaries_are_read_without_rounding(self):
        self.assertEqual(demo.parse_time("2026-01-01T09:00:00.000001000+09:00"),
                         demo.parse_time("2026-01-01t00:00:00.000001z"))
        with self.assertRaises(ValueError):
            demo.parse_time("2026-01-01T00:00:00.0000001Z")
        instant = self.now + timedelta(microseconds=317)
        with patch.object(demo, "datetime", wraps=datetime) as clock:
            clock.now.return_value = instant
            self.assertEqual(demo.utc_now(), instant)

    def test_execution_must_be_complete_at_the_reported_check_time(self):
        bundle = copy.deepcopy(self.base_bundle)
        finish = self.now + timedelta(seconds=2, microseconds=17)
        bundle["artifacts"]["receipt"]["payload"]["finished_at"] = demo.iso(finish)
        demo.resign_artifact(bundle, "receipt", self.bundle_dir)
        demo.write_bundle(self.bundle_dir, bundle)
        for when in (finish - timedelta(microseconds=1), finish, finish + timedelta(microseconds=1)):
            with self.subTest(when=when), patch.object(demo, "utc_now", return_value=when):
                report = demo.verify_demo(self.bundle_dir, status_mode="push")
                self.assertEqual(demo.parse_time(report["checked_at"]), when)
                failures = {row["name"] for row in report["checks"] if not row["ok"]}
                self.assertEqual(failures, {"receipt_completed"} if when < finish else set())

    def test_invalid_intervals_fail_only_the_window_check(self):
        cases = (
            ("finishes_before_start", (0, 300), (30, 180), (60, 59)),
            ("starts_before_runtime_issuance", (30, 300), (0, 180), (29, 120)),
            ("starts_before_permit_issuance", (0, 300), (30, 180), (29, 120)),
            ("finishes_after_runtime_expiry", (0, 180), (30, 300), (60, 181)),
            ("finishes_after_permit_expiry", (0, 300), (30, 180), (60, 181)),
            ("disjoint_windows", (0, 60), (61, 180), (60, 61)),
        )
        for name, runtime, permit, execution in cases:
            with self.subTest(name=name):
                self.assert_window(runtime, permit, execution, False)


if __name__ == "__main__":
    unittest.main()
