"""The rule corpus, the coverage note, and the README stay in step."""

from __future__ import annotations

import unittest

from rulelab.coverage import render_coverage
from rulelab.paths import COVERAGE_PATH, DATA_DIR, ROOT, RULES_DIR
from rulelab.runner import format_report, run_tests, tests_ok
from rulelab.validate import rule_techniques, validate_rules


class CorpusTests(unittest.TestCase):
    def test_every_rule_matches_its_fixtures(self) -> None:
        results, errors = run_tests(RULES_DIR, DATA_DIR)
        self.assertEqual(errors, [], "\n".join(errors))
        self.assertTrue(tests_ok(results, errors), format_report(results, errors))
        self.assertGreaterEqual(len(results), 15)
        self.assertLessEqual(len(results), 20)

    def test_coverage_document_matches_the_rules(self) -> None:
        text, errors = render_coverage(RULES_DIR)
        self.assertEqual(errors, [])
        self.assertEqual(COVERAGE_PATH.read_text(encoding="utf-8"), text)

    def test_readme_lists_every_rule_and_technique(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        loaded, errors = validate_rules(RULES_DIR)
        self.assertEqual(errors, [])
        for path, rule in loaded:
            relative = path.relative_to(RULES_DIR).as_posix()
            self.assertIn(relative, readme)
            self.assertIn(rule["title"], readme)
            for technique_id in rule_techniques(rule["tags"]):
                self.assertIn(technique_id, readme)


if __name__ == "__main__":
    unittest.main()
