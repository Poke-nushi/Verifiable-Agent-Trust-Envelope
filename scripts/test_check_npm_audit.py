import unittest
from unittest.mock import call, patch

import check_npm_audit as audit


def report(severity=None):
    counts = dict.fromkeys(("info", "low", "moderate", "high", "critical"), 0)
    entries = {}
    if severity:
        entries["example"] = {"name": "example", "severity": severity}
        counts[severity] = 1
    counts["total"] = len(entries)
    return {"auditReportVersion": 2, "vulnerabilities": entries, "metadata": {"vulnerabilities": counts}}


class DependencyAuditTests(unittest.TestCase):
    def test_threshold(self):
        for severity in (None, "info", "low"):
            with self.subTest(severity=severity):
                self.assertFalse(audit.has_blocking_findings(report(severity), 0))
        for severity in ("moderate", "high", "critical"):
            with self.subTest(severity=severity):
                self.assertTrue(audit.has_blocking_findings(report(severity), 1))

    def test_incomplete_or_inconsistent_reports_fail(self):
        inconsistent = report("high")
        inconsistent["metadata"]["vulnerabilities"]["total"] = 0
        for data, status in (({"error": {"code": "NETWORK"}}, 1), (inconsistent, 1),
                             (report(), 1), (report("high"), 0)):
            with self.subTest(data=data, status=status), self.assertRaises(ValueError):
                audit.has_blocking_findings(data, status)

    def test_blocking_findings_in_either_scope_fail_the_check(self):
        for full, production in ((True, False), (False, True)):
            with self.subTest(full=full, production=production):
                with patch.object(audit, "run_audit", side_effect=[full, production]) as run:
                    with self.assertRaises(ValueError):
                        audit.main()
                self.assertEqual(run.call_args_list, [call("--include=dev"), call("--omit=dev")])


if __name__ == "__main__":
    unittest.main()
