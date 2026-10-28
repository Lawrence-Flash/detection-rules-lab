"""Command line for `python3 -m rulelab`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rulelab import __version__
from rulelab.coverage import write_coverage
from rulelab.errors import RuleLabError
from rulelab.paths import COVERAGE_PATH, DATA_DIR, EXAMPLES_DIR, RULES_DIR
from rulelab.runner import format_report, run_tests, tests_ok
from rulelab.validate import validate_rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rulelab",
        description=(
            "Check Detection Rules Lab Sigma rules offline. "
            "No network access and no SIEM connection."
        ),
    )
    parser.add_argument("--version", action="version", version=f"rulelab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    validate_cmd = sub.add_parser("validate", help="check rule files, tags, and detection syntax")
    _add_rules(validate_cmd)

    test_cmd = sub.add_parser("test", help="match every rule against its positive and negative events")
    _add_rules(test_cmd)
    test_cmd.add_argument("--data", type=Path, default=DATA_DIR, help="directory of synthetic events")

    coverage_cmd = sub.add_parser("coverage", help="print ATT&CK coverage and write docs/coverage.md")
    _add_rules(coverage_cmd)
    coverage_cmd.add_argument("--output", type=Path, default=COVERAGE_PATH, help="markdown output path")

    convert_cmd = sub.add_parser(
        "convert",
        help="optionally convert rules to Splunk SPL and Elastic Lucene with pySigma",
    )
    _add_rules(convert_cmd)
    convert_cmd.add_argument(
        "--output",
        type=Path,
        default=EXAMPLES_DIR,
        help="directory for generated query examples",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return _cmd_validate(args.rules)
        if args.command == "test":
            return _cmd_test(args.rules, args.data)
        if args.command == "coverage":
            return _cmd_coverage(args.rules, args.output)
        if args.command == "convert":
            from rulelab.convert import convert_rules

            return convert_rules(args.rules, args.output)
    except RuleLabError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 1
    print(f"unknown command {args.command}", file=sys.stderr)
    return 2


def _add_rules(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rules", type=Path, default=RULES_DIR, help="directory of Sigma YAML rules")


def _cmd_validate(rules_dir: Path) -> int:
    loaded, errors = validate_rules(rules_dir)
    for error in errors:
        print(f"ERROR {error}")
    if errors:
        print(f"{len(loaded)} rule file(s) read, {len(errors)} error(s)")
        return 1
    print(f"Validated {len(loaded)} rules in {rules_dir}")
    return 0


def _cmd_test(rules_dir: Path, data_dir: Path) -> int:
    results, errors = run_tests(rules_dir, data_dir)
    print(format_report(results, errors))
    return 0 if tests_ok(results, errors) else 1


def _cmd_coverage(rules_dir: Path, output: Path) -> int:
    text, errors = write_coverage(rules_dir, output)
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1
    print(text, end="" if text.endswith("\n") else "\n")
    print(f"Wrote {output}")
    return 0
