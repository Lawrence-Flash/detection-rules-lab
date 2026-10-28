"""Tests for rule schema checks and the synthetic-event runner."""

from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from rulelab.runner import run_tests, tests_ok
from rulelab.validate import validate_rule, validate_rules

GOOD_RULE = """
title: Lab Example
id: 2de4ec25-ac45-4299-ab99-14f8f1ffd4d4
status: test
description: |
  Example rule used by the unit tests.
author: Lawrence Tshabalala
date: '2026-10-28'
references:
  - https://attack.mitre.org/techniques/T1685/005/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
falsepositives:
  - An administrator cleared the Security log during a documented maintenance window.
level: high
tags:
  - attack.defense-impairment
  - attack.t1685.005
"""


class ValidateTests(unittest.TestCase):
    def test_good_rule_passes(self) -> None:
        from rulelab.yaml_lite import loads

        rule = loads(GOOD_RULE)
        self.assertEqual(validate_rule(rule, Path("rules/windows/example.yml")), [])

    def test_wrong_author_bad_uuid_and_aggregation_fail(self) -> None:
        from rulelab.yaml_lite import loads

        text = GOOD_RULE.replace("Lawrence Tshabalala", "Someone Else").replace(
            "2de4ec25-ac45-4299-ab99-14f8f1ffd4d4", "not-a-uuid"
        )
        text = text.replace("condition: selection", "condition: selection | count() > 3")
        errors = validate_rule(loads(text), Path("rules/windows/example.yml"))
        joined = "\n".join(errors)
        self.assertIn("author", joined)
        self.assertIn("UUID", joined)
        self.assertIn("aggregation", joined)

    def test_tactic_tag_must_match_the_technique(self) -> None:
        from rulelab.yaml_lite import loads

        text = GOOD_RULE.replace("attack.defense-impairment", "attack.execution")
        errors = validate_rule(loads(text), Path("example.yml"))
        self.assertTrue(any("missing tag" in error or "do not belong" in error for error in errors))

    def test_runner_catches_a_negative_match_and_a_public_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules" / "windows"
            data = root / "data" / "windows"
            rules.mkdir(parents=True)
            data.mkdir(parents=True)
            (rules / "example.yml").write_text(textwrap.dedent(GOOD_RULE), encoding="utf-8")
            positive = [
                {
                    "synthetic": True,
                    "lab_note": "Synthetic clear of the security log.",
                    "EventID": 1102,
                    "IpAddress": "203.0.113.10",
                }
            ]
            negative = [
                {
                    "synthetic": True,
                    "lab_note": "Synthetic nearby event that is not 1102.",
                    "EventID": 1100,
                    "IpAddress": "8.8.8.8",
                }
            ]
            (data / "example_positive.json").write_text(json.dumps(positive), encoding="utf-8")
            (data / "example_negative.json").write_text(json.dumps(negative), encoding="utf-8")
            results, errors = run_tests(root / "rules", root / "data")
            self.assertEqual(errors, [])
            self.assertFalse(tests_ok(results, errors))
            details = " ".join(item.detail for item in results[0].failures)
            self.assertIn("8.8.8.8", details)

    def test_directory_duplicate_ids_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules"
            rules.mkdir()
            text = textwrap.dedent(GOOD_RULE)
            (rules / "one.yml").write_text(text, encoding="utf-8")
            (rules / "two.yml").write_text(text.replace("Lab Example", "Lab Example Two"), encoding="utf-8")
            _loaded, errors = validate_rules(rules)
            self.assertTrue(any("duplicate id" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
