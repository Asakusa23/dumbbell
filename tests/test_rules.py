import unittest

from dumbbell.models import Severity
from dumbbell.rules import RULES


class RuleCatalogueTests(unittest.TestCase):
    def test_ids_are_unique(self):
        identifiers = [rule.id for rule in RULES]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_every_rule_compiles(self):
        for rule in RULES:
            self.assertIsNotNone(rule._compiled, rule.id)

    def test_metadata_is_present(self):
        for rule in RULES:
            self.assertTrue(rule.title, rule.id)
            self.assertTrue(rule.category, rule.id)
            self.assertTrue(rule.description, rule.id)
            self.assertTrue(rule.remediation, rule.id)
            self.assertTrue(rule.pattern, rule.id)
            self.assertIsInstance(rule.severity, Severity)

    def test_expected_rules_exist(self):
        identifiers = {rule.id for rule in RULES}
        expected = {
            "SQLI-001",
            "SQLI-002",
            "SQLI-003",
            "SQLI-004",
            "SQLI-005",
            "SQLI-007",
            "SQLI-008",
            "SQLI-016",
            "CMDI-003",
            "CMDI-006",
            "CMDI-009",
            "CMDI-010",
            "SEC-003",
            "SEC-005",
            "SEC-006",
            "SEC-011",
            "CRY-001",
            "CRY-009",
            "WEB-001",
            "WEB-003",
            "PATH-001",
            "PATH-005",
            "SSRF-001",
            "XXE-001",
            "AUTH-002",
            "AUTH-003",
            "DESER-002",
            "MISC-005",
        }
        self.assertTrue(expected.issubset(identifiers))

    def test_all_rules_apply_to_every_file_type(self):
        for rule in RULES:
            for suffix, name in (
                (".py", "app.py"),
                (".js", "app.js"),
                (".ts", "app.ts"),
                (".rs", "main.rs"),
                (".go", "main.go"),
                (".java", "App.java"),
                (".cs", "Program.cs"),
                (".rb", "app.rb"),
                (".c", "main.c"),
                (".sh", "deploy.sh"),
                ("", "Makefile"),
                (".xyz", "unknown.xyz"),
            ):
                self.assertTrue(rule.matches_extension(suffix, name), rule.id)

    def test_every_rule_explains_how_to_fix(self):
        for rule in RULES:
            self.assertGreaterEqual(len(rule.remediation), 20, rule.id)

    def test_redaction_enabled_for_secrets(self):
        secret_rules = [rule for rule in RULES if rule.category == "Secrets"]
        self.assertTrue(secret_rules)
        self.assertTrue(any(rule.redact for rule in secret_rules))


if __name__ == "__main__":
    unittest.main()
