"""Run each Sigma rule against its synthetic positive and negative events."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rulelab.errors import SigmaSyntaxError
from rulelab.matcher import rule_matches
from rulelab.paths import display_path
from rulelab.validate import validate_rules

# RFC 5737 documentation ranges, the IPv6 documentation prefix, and loopback.
# Loopback is allowed because a few Windows logons are local by definition.
_ALLOWED_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("127.0.0.1/32"),
    ipaddress.ip_network("::1/128"),
)
_IP_FIELDS = {
    "ip",
    "ipaddress",
    "src_ip",
    "source_ip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "client_ip",
    "remote_ip",
}


@dataclass
class CaseFailure:
    label: str
    detail: str


@dataclass
class RuleTestResult:
    path: Path
    positives: int = 0
    negatives: int = 0
    failures: list[CaseFailure] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


def run_tests(rules_dir: Path, data_dir: Path) -> tuple[list[RuleTestResult], list[str]]:
    """Validate rules, then match positive and negative events.

    Structural problems are returned separately from per-event match failures
    so a broken file is not reported as a quiet miss.
    """
    loaded, errors = validate_rules(rules_dir)
    results: list[RuleTestResult] = []
    if errors:
        return results, errors

    expected_files: set[Path] = set()
    for path, rule in loaded:
        positive, negative = _event_paths(path, rules_dir, data_dir)
        expected_files.add(positive.resolve())
        expected_files.add(negative.resolve())
        result = RuleTestResult(path=path)
        _check_file(rule, positive, should_match=True, result=result)
        _check_file(rule, negative, should_match=False, result=result)
        results.append(result)

    if data_dir.is_dir():
        actual = {path.resolve() for path in data_dir.rglob("*.json") if path.is_file()}
        extra = sorted(actual - expected_files)
        for path in extra:
            errors.append(f"{display_path(path)}: JSON file is not paired with a rule")
    return results, errors


def format_report(results: list[RuleTestResult], errors: list[str]) -> str:
    lines: list[str] = []
    for error in errors:
        lines.append(f"ERROR {error}")
    passed = 0
    failed = 0
    positives = 0
    negatives = 0
    for result in results:
        positives += result.positives
        negatives += result.negatives
        name = display_path(result.path)
        if result.ok:
            passed += 1
            lines.append(
                f"PASS  {name}  positives={result.positives} negatives={result.negatives}"
            )
            continue
        failed += 1
        lines.append(f"FAIL  {name}")
        for failure in result.failures:
            lines.append(f"      {failure.label}: {failure.detail}")
    event_count = positives + negatives
    lines.append(
        f"{passed} passed, {failed} failed, {event_count} events "
        f"({positives} positive, {negatives} negative)"
    )
    if errors:
        lines.append(f"{len(errors)} structural error(s)")
    return "\n".join(lines)


def tests_ok(results: list[RuleTestResult], errors: list[str]) -> bool:
    return not errors and all(result.ok for result in results)


def _event_paths(rule_path: Path, rules_dir: Path, data_dir: Path) -> tuple[Path, Path]:
    relative = rule_path.relative_to(rules_dir)
    positive = data_dir / relative.parent / f"{relative.stem}_positive.json"
    negative = data_dir / relative.parent / f"{relative.stem}_negative.json"
    return positive, negative


def _check_file(rule: dict[str, Any], path: Path, should_match: bool, result: RuleTestResult) -> None:
    kind = "positive" if should_match else "negative"
    if not path.is_file():
        result.failures.append(CaseFailure(kind, f"missing {display_path(path)}"))
        return
    try:
        events = _load_events(path)
    except ValueError as exc:
        result.failures.append(CaseFailure(kind, str(exc)))
        return
    if should_match:
        result.positives = len(events)
    else:
        result.negatives = len(events)
    for index, event in enumerate(events):
        label = f"{kind}[{index}]"
        for problem in _ip_problems(event):
            result.failures.append(CaseFailure(label, problem))
        try:
            matched = rule_matches(rule, event)
        except SigmaSyntaxError as exc:
            result.failures.append(CaseFailure(label, str(exc)))
            continue
        if should_match and not matched:
            result.failures.append(CaseFailure(label, "did not match"))
        elif not should_match and matched:
            result.failures.append(CaseFailure(label, "matched and should not have"))


def _load_events(path: Path) -> list[dict[str, Any]]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{display_path(path)} is not valid JSON ({exc})") from exc
    if isinstance(loaded, dict):
        loaded = [loaded]
    if not isinstance(loaded, list) or not loaded:
        raise ValueError(f"{display_path(path)} must be a non-empty JSON list or object")
    events: list[dict[str, Any]] = []
    for index, item in enumerate(loaded):
        if not isinstance(item, dict):
            raise ValueError(f"{display_path(path)}[{index}] must be an object")
        if item.get("synthetic") is not True:
            raise ValueError(
                f"{display_path(path)}[{index}] must set \"synthetic\": true "
                "so real logs are not mixed into the lab"
            )
        events.append(item)
    return events


def _ip_problems(event: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for key, value in event.items():
        if str(key).casefold() not in _IP_FIELDS:
            continue
        if value in (None, "", "-"):
            continue
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            problems.append(f"{key}={value!r} is not an IP address")
            continue
        if not any(address in network for network in _ALLOWED_NETWORKS):
            problems.append(
                f"{key}={value} is outside the documentation ranges "
                "(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and loopback"
            )
    return problems
