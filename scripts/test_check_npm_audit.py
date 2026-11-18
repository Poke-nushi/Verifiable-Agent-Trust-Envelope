import copy
import unittest
from unittest.mock import patch

import check_npm_audit as audit


def finding(name, via, severity="high"):
    return {"name": name, "severity": severity, "via": via, "nodes": [f"node_modules/{name}"]}


def report(entries, *, high=0, moderate=0, low=0):
    counts = {"total": high + moderate + low, "high": high, "low": low, "moderate": moderate,
              "info": 0, "critical": 0}
    return {"auditReportVersion": 2, "vulnerabilities": entries, "metadata": {"vulnerabilities": counts}}


class DependencyAuditTests(unittest.TestCase):
    def setUp(self):
        advisory = {"url": "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
                    "name": "picomatch", "dependency": "picomatch", "severity": "high", "range": "<=4.0.7"}
        self.findings = {"picomatch": finding("picomatch", [advisory]), "fdir": finding("fdir", ["picomatch"])}
        self.packages = {"node_modules/picomatch": {"version": "4.0.7", "dev": True},
                         "node_modules/fdir": {"version": "6.5.0", "dev": True}}

    def test_reviewed_direct_and_inherited_cause(self):
        self.assertTrue(audit.covered_by_review(self.findings, self.packages))
        self.findings["fdir"]["via"].append({"url": "https://example.org/another-advisory"})
        self.assertFalse(audit.covered_by_review(self.findings, self.packages))

    def test_review_excludes_other_versions_scopes_and_paths(self):
        for name, replacement in (
            ("version", {"version": "4.0.8", "dev": True}),
            ("production", {"version": "4.0.7"}),
        ):
            with self.subTest(name=name):
                packages = dict(self.packages)
                packages["node_modules/picomatch"] = replacement
                self.assertFalse(audit.covered_by_review(self.findings, packages))
        self.findings["fdir"]["nodes"].append("node_modules/other/node_modules/fdir")
        self.assertFalse(audit.covered_by_review(self.findings, self.packages))

    def test_changed_or_unresolved_causes_fail(self):
        for name, via in (("picomatch", []), ("picomatch", ["fdir"]),
                          ("fdir", ["missing"]), ("fdir", ["picomatch", "missing"])):
            with self.subTest(name=name, via=via):
                changed = copy.deepcopy(self.findings)
                changed[name]["via"] = via
                self.assertFalse(audit.covered_by_review(changed, self.packages))
        self.findings["picomatch"]["via"][0]["url"] = "https://example.org/another-advisory"
        self.assertFalse(audit.covered_by_review(self.findings, self.packages))

    def test_unrelated_findings_keep_the_existing_threshold(self):
        low = finding("other", ["other-advisory"], severity="low")
        entries = dict(self.findings, other=low)
        blocking = audit.blocking_findings(report(entries, low=1, high=2), 1)
        self.assertTrue(audit.covered_by_review(blocking, self.packages))
        low["severity"] = "moderate"
        blocking = audit.blocking_findings(report(entries, moderate=1, high=2), 1)
        self.assertFalse(audit.covered_by_review(blocking, self.packages))

    def test_incomplete_or_unsuccessful_audit_never_passes_as_clean(self):
        for data, status in (({"error": {"code": "NETWORK"}}, 1), (report({}), 1),
                             (report({}, high=1), 0), (report(self.findings, high=2), 0)):
            with self.subTest(data=data, status=status), self.assertRaises(ValueError):
                audit.blocking_findings(data, status)
        self.assertEqual(audit.blocking_findings(report({}), 0), {})

    def test_clean_runs_need_no_review_and_production_findings_are_never_covered(self):
        with patch.dict(audit.os.environ, {}, clear=True):
            with patch.object(audit, "run_audit", side_effect=[{}, {}]), patch("builtins.print"):
                audit.main()
            with patch.object(audit, "run_audit", side_effect=[self.findings, {}]):
                with self.assertRaisesRegex(ValueError, "no active review"):
                    audit.main()
        with patch.dict(audit.os.environ, {"VATE_REVIEWED_NPM_TREE": "reviewed"}):
            with patch.object(audit, "run_audit", side_effect=[self.findings, self.findings]):
                with self.assertRaisesRegex(ValueError, "production"):
                    audit.main()
            with patch.object(audit, "run_audit", side_effect=[self.findings, {}]), \
                    patch.object(audit.subprocess, "check_output", return_value="different-tree"):
                with self.assertRaisesRegex(ValueError, "outside the reviewed source tree"):
                    audit.main()


if __name__ == "__main__":
    unittest.main()
