"""Schema checks for Sigma rules in this lab.

These checks are intentionally stricter than the Sigma specification. Every
rule has to carry the fields the project asks for, a real UUID, the lab
author, a technique from ``rulelab.attack``, and a count-free detection the
built-in matcher can run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from rulelab.attack import TECHNIQUES, expected_tags, technique_tag
from rulelab.errors import SigmaSyntaxError, YamlError
from rulelab.matcher import lint_detection
from rulelab.paths import display_path
from rulelab.yaml_lite import loads

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
)

ALLOWED_FIELDS = set(REQUIRED_FIELDS) | {"modified"}
AUTHOR = "Lawrence Tshabalala"
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
LOGSOURCE_KEYS = {"category", "product", "service", "definition"}
LOGSOURCE_REQUIRED_ONE = {"category", "product", "service"}
_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")
_DATE_FORMATS = ("%Y-%m-%d", "%Y/%m/%d")


def load_rule_yaml(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Return ``(rule, errors)``. ``rule`` is None when the file is not a mapping."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"{_display(path)}: {exc}"]
    try:
        loaded = loads(text)
    except YamlError as exc:
        return None, [f"{_display(path)}: {exc}"]
    if not isinstance(loaded, dict):
        return None, [f"{_display(path)}: the rule file must be a YAML mapping"]
    return loaded, []


def validate_rule(rule: Mapping[str, Any], path: Path | None = None) -> list[str]:
    """Return human-readable problems. An empty list means the rule passed."""
    label = _display(path) if path is not None else "<rule>"
    errors: list[str] = []

    def add(message: str) -> None:
        errors.append(f"{label}: {message}")

    if "timeframe" in rule:
        add("timeframe is not allowed; this lab does not run aggregations")

    unknown = sorted(set(rule) - ALLOWED_FIELDS)
    if unknown:
        add("unknown field(s): " + ", ".join(unknown))

    for field in REQUIRED_FIELDS:
        if field not in rule:
            add(f"missing required field {field!r}")
    if errors:
        return errors

    title = rule["title"]
    if not isinstance(title, str) or not title.strip():
        add("title must be a non-empty string")

    rule_id = rule["id"]
    if not isinstance(rule_id, str):
        add("id must be a UUID string")
    else:
        try:
            UUID(rule_id)
        except ValueError:
            add(f"id is not a UUID: {rule_id!r}")

    if rule["status"] not in STATUSES:
        add(f"status must be one of {sorted(STATUSES)}")

    description = rule["description"]
    if not isinstance(description, str) or not description.strip():
        add("description must be a non-empty string")

    if rule["author"] != AUTHOR:
        add(f"author must be {AUTHOR!r}")

    if not _valid_date(rule["date"]):
        add("date must be a real calendar date as YYYY-MM-DD or YYYY/MM/DD")

    if rule["level"] not in LEVELS:
        add(f"level must be one of {sorted(LEVELS)}")

    _check_string_list(rule["references"], "references", add, urls=True)
    _check_string_list(rule["falsepositives"], "falsepositives", add, urls=False)
    _check_logsource(rule["logsource"], add)
    _check_tags(rule["tags"], rule.get("references"), add)
    _check_detection(rule["detection"], add)
    return errors


def validate_rules(rules_dir: Path) -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
    """Validate every YAML rule under ``rules_dir``."""
    files = iter_rule_files(rules_dir)
    if not files:
        return [], [f"{rules_dir}: no .yml or .yaml rules found"]

    loaded: list[tuple[Path, dict[str, Any]]] = []
    errors: list[str] = []
    seen_ids: dict[str, Path] = {}
    seen_titles: dict[str, Path] = {}

    for path in files:
        rule, load_errors = load_rule_yaml(path)
        errors.extend(load_errors)
        if rule is None:
            continue
        errors.extend(validate_rule(rule, path))
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            previous = seen_ids.get(rule_id)
            if previous is not None:
                errors.append(
                    f"{_display(path)}: duplicate id {rule_id} (also {_display(previous)})"
                )
            else:
                seen_ids[rule_id] = path
        title = rule.get("title")
        if isinstance(title, str):
            previous_title = seen_titles.get(title)
            if previous_title is not None:
                errors.append(
                    f"{_display(path)}: duplicate title {title!r} (also {_display(previous_title)})"
                )
            else:
                seen_titles[title] = path
        loaded.append((path, rule))
    return loaded, errors


def iter_rule_files(rules_dir: Path) -> list[Path]:
    if not rules_dir.is_dir():
        return []
    files = [
        path
        for path in rules_dir.rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    ]
    return sorted(files, key=lambda path: path.as_posix())


def rule_techniques(tags: list[str]) -> list[str]:
    """Return technique ids referenced by Sigma attack tags, in tag order."""
    found: list[str] = []
    for tag in tags:
        if not _TECHNIQUE_TAG.fullmatch(tag):
            continue
        technique_id = tag[len("attack.") :].upper()
        found.append(technique_id)
    return found


def _check_string_list(value: Any, field: str, add: Any, urls: bool) -> None:
    if not isinstance(value, list) or not value:
        add(f"{field} must be a non-empty list")
        return
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            add(f"{field}[{index}] must be a non-empty string")
            continue
        if urls and not (item.startswith("https://") or item.startswith("http://")):
            add(f"{field}[{index}] must be an http(s) URL")


def _check_logsource(value: Any, add: Any) -> None:
    if not isinstance(value, dict) or not value:
        add("logsource must be a mapping")
        return
    unknown = sorted(set(value) - LOGSOURCE_KEYS)
    if unknown:
        add("logsource has unknown key(s): " + ", ".join(unknown))
    if not any(key in value and isinstance(value[key], str) and value[key].strip() for key in LOGSOURCE_REQUIRED_ONE):
        add("logsource needs category, product, or service")
    for key, item in value.items():
        if not isinstance(item, str) or not item.strip():
            add(f"logsource.{key} must be a non-empty string")


def _check_tags(tags: Any, references: Any, add: Any) -> None:
    if not isinstance(tags, list) or not tags:
        add("tags must be a non-empty list")
        return
    if not all(isinstance(tag, str) for tag in tags):
        add("every tag must be a string")
        return
    technique_ids = rule_techniques(tags)
    if not technique_ids:
        add("tags must include at least one attack.tNNNN[.NNN] technique")
        return
    unknown = [technique_id for technique_id in technique_ids if technique_id not in TECHNIQUES]
    if unknown:
        add(
            "technique tag is not in rulelab/attack.py: "
            + ", ".join(unknown)
            + ". Add it there only after checking the MITRE page."
        )
        return
    expected = expected_tags(technique_ids)
    actual = set(tags)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        add("missing tag(s) required by the mapped technique(s): " + ", ".join(missing))
    if extra:
        add("tag(s) do not belong to the mapped technique(s): " + ", ".join(extra))
    if isinstance(references, list):
        normalized = {_strip_slash(item) for item in references if isinstance(item, str)}
        for technique_id in technique_ids:
            url = _strip_slash(str(TECHNIQUES[technique_id]["url"]))
            if url not in normalized:
                add(f"references must include {url}/ for {technique_id}")
    # technique_tag is the form we expect; keep the helper used so a rename breaks loudly.
    for technique_id in technique_ids:
        if technique_tag(technique_id) not in tags:
            add(f"missing {technique_tag(technique_id)}")


def _check_detection(detection: Any, add: Any) -> None:
    if not isinstance(detection, dict):
        add("detection must be a mapping")
        return
    try:
        lint_detection(detection)
    except SigmaSyntaxError as exc:
        add(str(exc))


def _valid_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    for fmt in _DATE_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        # strptime accepts some overflows by rolling over; require a round trip.
        return parsed.strftime(fmt) == value
    return False


def _strip_slash(url: str) -> str:
    return url.rstrip("/")


def _display(path: Path | None) -> str:
    if path is None:
        return "<rule>"
    return display_path(path)
