import json
import tempfile
import unittest
from pathlib import Path

from dumbbell.models import Finding, ScanResult, Severity
from dumbbell.report import to_json, to_markdown, to_sarif
from dumbbell.rules import RULES


def make_result(findings=None):
    root = Path(tempfile.gettempdir()) / "dumbbell-report-tests"
    return ScanResult(
        root=str(root),
        findings=list(findings or []),
        files_scanned=3,
        files_skipped=1,
        bytes_scanned=2048,
        elapsed=0.25,
    )


def make_finding():
    rule = next(item for item in RULES if item.id == "SEC-003")
    root = Path(tempfile.gettempdir()) / "dumbbell-report-tests"
    return Finding(
        rule=rule,
        path=str(root / "app.py"),
        line=7,
        column=5,
        snippet="AWS_ACCESS_KEY_ID = ***REDACTED***",
    )


class ReportTests(unittest.TestCase):
    def test_json_report(self):
        result = make_result([make_finding()])
        payload = json.loads(to_json(result))
        self.assertEqual(payload["tool"]["name"], "DUMBBELL")
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["findings"][0]["rule"], "SEC-003")
        self.assertEqual(payload["findings"][0]["file"], "app.py")

    def test_markdown_report(self):
        result = make_result([make_finding()])
        text = to_markdown(result)
        self.assertIn("# DUMBBELL security report", text)
        self.assertIn("SEC-003", text)
        self.assertIn("***REDACTED***", text)
        self.assertIn("| CRITICAL |", text)

    def test_sarif_report(self):
        result = make_result([make_finding()])
        payload = json.loads(to_sarif(result))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "DUMBBELL")
        self.assertEqual(run["results"][0]["ruleId"], "SEC-003")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "app.py",
        )

    def test_reports_include_remediation_advice(self):
        finding = make_finding()
        result = make_result([finding])
        remediation = finding.rule.remediation
        self.assertIn(remediation, to_json(result))
        self.assertIn(remediation, to_markdown(result))
        self.assertIn(remediation, to_sarif(result))

    def test_empty_result(self):
        result = make_result()
        payload = json.loads(to_json(result))
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertEqual(payload["summary"]["risk_score"], 0)
        self.assertIn("No findings", to_markdown(result))
        sarif = json.loads(to_sarif(result))
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_risk_score_is_capped(self):
        finding = make_finding()
        result = make_result([finding] * 20)
        self.assertEqual(result.risk_score(), 100)

    def test_severity_counts_include_all_levels(self):
        finding = make_finding()
        counts = make_result([finding]).severity_counts()
        self.assertEqual(set(counts), {severity.name for severity in Severity.ordered()})
        self.assertEqual(counts[finding.severity.name], 1)
        self.assertEqual(sum(counts.values()), 1)


if __name__ == "__main__":
    unittest.main()
