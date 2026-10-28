"""Tests for the small YAML reader."""

from __future__ import annotations

import unittest

from rulelab.errors import YamlError
from rulelab.yaml_lite import loads


class YamlLiteTests(unittest.TestCase):
    def test_mapping_sequence_and_types(self) -> None:
        loaded = loads(
            """
# comment
title: Linux SSH Failed Password
count: 2
enabled: true
empty: null
logsource:
  product: linux
  service: auth
tags:
  - attack.credential-access
  - attack.t1110.001
"""
        )
        self.assertEqual(loaded["title"], "Linux SSH Failed Password")
        self.assertEqual(loaded["count"], 2)
        self.assertIs(loaded["enabled"], True)
        self.assertIsNone(loaded["empty"])
        self.assertEqual(loaded["logsource"]["service"], "auth")
        self.assertEqual(loaded["tags"][1], "attack.t1110.001")

    def test_quotes_comments_and_literal_block(self) -> None:
        loaded = loads(
            r"""
description: |
  Detects a failed password.
  One event is not a burst.
message|re: 'Failed password for (invalid user )?[A-Za-z0-9_.-]+ from '
path: '\powershell.exe'  # single quotes keep the backslash
encoded: "..\\"
quote: 'it''s a lab'
"""
        )
        self.assertEqual(
            loaded["description"],
            "Detects a failed password.\nOne event is not a burst.\n",
        )
        self.assertEqual(
            loaded["message|re"],
            "Failed password for (invalid user )?[A-Za-z0-9_.-]+ from ",
        )
        self.assertEqual(loaded["path"], "\\powershell.exe")
        self.assertEqual(loaded["encoded"], "..\\")
        self.assertEqual(loaded["quote"], "it's a lab")

    def test_tabs_and_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaises(YamlError):
            loads("title:\tbad\n")
        with self.assertRaises(YamlError):
            loads("title: one\ntitle: two\n")

    def test_flow_style_is_not_silently_parsed_as_a_structure(self) -> None:
        # The reader does not implement flow collections. A plain scalar is
        # returned rather than a list, which keeps the gap obvious.
        loaded = loads("tags: [one, two]\n")
        self.assertEqual(loaded["tags"], "[one, two]")


if __name__ == "__main__":
    unittest.main()
