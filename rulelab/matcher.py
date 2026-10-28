"""A small Sigma matcher for the modifiers used by this lab.

Supported condition forms:

- selection names
- ``and``, ``or``, ``not``, and parentheses (``and`` binds tighter than ``or``)
- ``1 of selection*``, ``all of selection*``, and ``1 of them``

``N of`` counts how many selections match this one event. It is not a count
across a time window. ``| count``, ``near``, and other aggregations are rejected.

Supported field modifiers: ``contains``, ``startswith``, ``endswith``, ``re``,
and ``all``. Plain values and the wildcard modifiers are case-insensitive.
``*`` and ``?`` are Sigma wildcards. ``re`` is a Python regular expression and
is case-sensitive unless the pattern includes ``(?i)``.

A list of values under one field is OR, unless ``all`` is present, in which
case every value must match. Fields in one selection are AND. A list of
mappings is OR. A list of plain strings is a keyword search across event values.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Mapping, Sequence
from typing import Any

from rulelab.errors import SigmaSyntaxError

MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re"}
ALL_MODIFIER = "all"
SUPPORTED_MODIFIERS = MATCH_MODIFIERS | {ALL_MODIFIER}

_AGGREGATION = re.compile(r"(?i)(\||\b(?:count|min|max|avg|sum|near)\b)")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\*?|\d+")
_MISSING = object()

# AST nodes are small tuples so the condition can be checked before any event
# is matched.
Ast = tuple[Any, ...]


def rule_matches(rule: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    """Return whether ``event`` satisfies ``rule``'s detection."""
    detection = rule.get("detection")
    if not isinstance(detection, Mapping):
        raise SigmaSyntaxError("detection must be a mapping")
    ast = parse_condition(str(detection.get("condition", "")), _selection_names(detection))
    return eval_ast(ast, detection, event)


def parse_condition(condition: str, selection_names: Sequence[str]) -> Ast:
    """Parse a count-free Sigma condition and resolve ``of`` globs."""
    if not isinstance(condition, str) or not condition.strip():
        raise SigmaSyntaxError("condition must be a non-empty string")
    if _AGGREGATION.search(condition):
        raise SigmaSyntaxError(
            "aggregations are not supported (no '| count', near, or timeframe)"
        )
    parser = _ConditionParser(_tokenize(condition), list(selection_names))
    ast = parser.parse_or()
    if parser.peek() is not None:
        raise SigmaSyntaxError(f"trailing token {parser.peek()!r} in condition")
    return ast


def referenced_names(ast: Ast) -> set[str]:
    """Selection names a parsed condition actually uses."""
    kind = ast[0]
    if kind == "sel":
        return {ast[1]}
    if kind == "not":
        return referenced_names(ast[1])
    if kind in {"and", "or"}:
        return referenced_names(ast[1]) | referenced_names(ast[2])
    if kind == "of":
        return set(ast[2])
    raise SigmaSyntaxError(f"unknown condition node {kind!r}")


def lint_detection(detection: Mapping[str, Any]) -> Ast:
    """Check modifiers and the condition. Return the condition AST."""
    if "condition" not in detection:
        raise SigmaSyntaxError("detection is missing condition")
    if not isinstance(detection["condition"], str):
        raise SigmaSyntaxError("condition must be a string")
    names = _selection_names(detection)
    if not names:
        raise SigmaSyntaxError("detection needs at least one selection")
    for name in names:
        lint_selection(detection[name], name)
    ast = parse_condition(str(detection["condition"]), names)
    unused = set(names) - referenced_names(ast)
    if unused:
        raise SigmaSyntaxError(
            "selection not used by the condition: " + ", ".join(sorted(unused))
        )
    return ast


def lint_selection(selection: Any, where: str) -> None:
    if isinstance(selection, Mapping):
        if not selection:
            raise SigmaSyntaxError(f"selection {where} is empty")
        for key, value in selection.items():
            lint_field(str(key), value, where)
        return
    if isinstance(selection, list):
        if not selection:
            raise SigmaSyntaxError(f"selection {where} is an empty list")
        if all(isinstance(item, Mapping) for item in selection):
            for index, item in enumerate(selection):
                lint_selection(item, f"{where}[{index}]")
            return
        if all(not isinstance(item, (Mapping, list)) for item in selection):
            return
        raise SigmaSyntaxError(f"selection {where} mixes maps and values")
    raise SigmaSyntaxError(f"selection {where} must be a mapping or a list")


def lint_field(key: str, expected: Any, where: str) -> None:
    _field, mode, use_all = _split_modifiers(key, where)
    values = expected if isinstance(expected, list) else [expected]
    if use_all and not isinstance(expected, list):
        raise SigmaSyntaxError(f"{where}: modifier 'all' needs a list of values")
    if isinstance(expected, list) and not expected:
        raise SigmaSyntaxError(f"{where}: {key} has an empty value list")
    for value in values:
        if isinstance(value, (Mapping, list)):
            raise SigmaSyntaxError(f"{where}: {key} values must be scalars")
        if mode == "re":
            _compile_regex(as_text(value), f"{where}: {key}")


def eval_ast(ast: Ast, detection: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    kind = ast[0]
    if kind == "sel":
        return selection_matches(detection[ast[1]], event)
    if kind == "not":
        return not eval_ast(ast[1], detection, event)
    if kind == "and":
        return eval_ast(ast[1], detection, event) and eval_ast(ast[2], detection, event)
    if kind == "or":
        return eval_ast(ast[1], detection, event) or eval_ast(ast[2], detection, event)
    if kind == "of":
        needed, names = ast[1], ast[2]
        matched = sum(1 for name in names if selection_matches(detection[name], event))
        if needed == "all":
            return bool(names) and matched == len(names)
        return matched >= int(needed)
    raise SigmaSyntaxError(f"unknown condition node {kind!r}")


def selection_matches(selection: Any, event: Mapping[str, Any]) -> bool:
    if isinstance(selection, Mapping):
        return all(field_matches(str(key), value, event) for key, value in selection.items())
    if isinstance(selection, list):
        if all(isinstance(item, Mapping) for item in selection):
            return any(selection_matches(item, event) for item in selection)
        return keyword_matches(selection, event)
    raise SigmaSyntaxError("selection must be a mapping or a list")


def field_matches(key: str, expected: Any, event: Mapping[str, Any]) -> bool:
    field, mode, use_all = _split_modifiers(key, key)
    actual = lookup(event, field)
    if actual is _MISSING:
        return False
    values = expected if isinstance(expected, list) else [expected]
    results = [_one_value_matches(actual, value, mode) for value in values]
    if use_all:
        return all(results)
    return any(results)


def keyword_matches(keywords: Sequence[Any], event: Mapping[str, Any]) -> bool:
    """Case-insensitive substring search over event values, skipping lab metadata."""
    haystack = " ".join(_walk_values(event)).casefold()
    return any(as_text(keyword).casefold() in haystack for keyword in keywords)


def lookup(event: Mapping[str, Any], field: str) -> Any:
    if field in event:
        return event[field]
    folded = field.casefold()
    for key, value in event.items():
        if str(key).casefold() == folded:
            return value
    return _MISSING


def as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return str(value)


def _selection_names(detection: Mapping[str, Any]) -> list[str]:
    return [str(key) for key in detection if key != "condition"]


def _tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    index = 0
    while index < len(condition):
        if condition[index].isspace():
            index += 1
            continue
        if condition[index] in "()":
            tokens.append(condition[index])
            index += 1
            continue
        match = _TOKEN.match(condition, index)
        if not match:
            raise SigmaSyntaxError(
                f"unexpected {condition[index]!r} in condition {condition!r}"
            )
        tokens.append(match.group(0))
        index = match.end()
    if not tokens:
        raise SigmaSyntaxError("condition is empty")
    return tokens


class _ConditionParser:
    def __init__(self, tokens: list[str], names: list[str]) -> None:
        self.tokens = tokens
        self.names = names
        self.i = 0

    def peek(self) -> str | None:
        if self.i >= len(self.tokens):
            return None
        return self.tokens[self.i]

    def _pop(self) -> str:
        token = self.peek()
        if token is None:
            raise SigmaSyntaxError("condition ended early")
        self.i += 1
        return token

    def parse_or(self) -> Ast:
        left = self.parse_and()
        while (self.peek() or "").lower() == "or":
            self._pop()
            left = ("or", left, self.parse_and())
        return left

    def parse_and(self) -> Ast:
        left = self.parse_not()
        while (self.peek() or "").lower() == "and":
            self._pop()
            left = ("and", left, self.parse_not())
        return left

    def parse_not(self) -> Ast:
        if (self.peek() or "").lower() == "not":
            self._pop()
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Ast:
        token = self._pop()
        if token == "(":
            node = self.parse_or()
            closing = self._pop()
            if closing != ")":
                raise SigmaSyntaxError("missing ')' in condition")
            return node
        lowered = token.lower()
        if lowered == "all" or token.isdigit():
            of_token = self._pop()
            if of_token.lower() != "of":
                raise SigmaSyntaxError(f"expected 'of' after {token!r}")
            target = self._pop()
            expanded = _expand_of(target, self.names)
            if lowered == "all":
                return ("of", "all", expanded)
            needed = int(token)
            if needed < 1:
                raise SigmaSyntaxError("'0 of' is not a useful condition")
            if needed > len(expanded):
                raise SigmaSyntaxError(
                    f"{needed} of {target} only matches {len(expanded)} selection(s)"
                )
            return ("of", needed, expanded)
        if token not in self.names:
            raise SigmaSyntaxError(f"condition refers to unknown selection {token!r}")
        return ("sel", token)


def _expand_of(target: str, names: list[str]) -> list[str]:
    ordered = list(names)
    if target.lower() == "them":
        if not ordered:
            raise SigmaSyntaxError("'them' does not match any selection")
        return ordered
    matched = [name for name in ordered if fnmatch.fnmatchcase(name, target)]
    if not matched:
        raise SigmaSyntaxError(f"{target!r} does not match any selection")
    return matched


def _split_modifiers(key: str, where: str) -> tuple[str, str, bool]:
    parts = key.split("|")
    field, modifiers = parts[0], [part.lower() for part in parts[1:]]
    if not field:
        raise SigmaSyntaxError(f"{where}: empty field name")
    unknown = [modifier for modifier in modifiers if modifier not in SUPPORTED_MODIFIERS]
    if unknown:
        raise SigmaSyntaxError(
            f"{where}: unsupported modifier '{unknown[0]}' on {key}"
        )
    use_all = ALL_MODIFIER in modifiers
    match_mods = [modifier for modifier in modifiers if modifier != ALL_MODIFIER]
    if len(match_mods) > 1:
        raise SigmaSyntaxError(f"{where}: only one match modifier is allowed on {key}")
    mode = match_mods[0] if match_mods else "plain"
    return field, mode, use_all


def _one_value_matches(actual: Any, expected: Any, mode: str) -> bool:
    if isinstance(actual, list):
        return any(_one_value_matches(item, expected, mode) for item in actual)
    text = as_text(actual)
    pattern = as_text(expected)
    if mode == "re":
        return _compile_regex(pattern, "re").search(text) is not None
    return _wildcard_match(text, pattern, mode)


def _compile_regex(pattern: str, where: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise SigmaSyntaxError(f"{where}: invalid regular expression ({exc})") from exc


def _wildcard_match(text: str, pattern: str, mode: str) -> bool:
    if mode == "plain" and "*" not in pattern and "?" not in pattern:
        return text.casefold() == pattern.casefold()
    body = _glob_to_regex(pattern)
    if mode == "contains":
        expression = f"(?i){body}"
    elif mode == "startswith":
        expression = f"(?i)\\A{body}"
    elif mode == "endswith":
        expression = f"(?i){body}\\Z"
    else:
        expression = f"(?i)\\A{body}\\Z"
    return re.search(expression, text) is not None


def _glob_to_regex(pattern: str) -> str:
    pieces: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern) and pattern[index + 1] in "*?\\":
            pieces.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "*":
            pieces.append(".*")
        elif char == "?":
            pieces.append(".")
        else:
            pieces.append(re.escape(char))
        index += 1
    return "".join(pieces)


def _walk_values(value: Any, key: str | None = None) -> list[str]:
    if key in {"synthetic", "lab_note"}:
        return []
    if isinstance(value, Mapping):
        found: list[str] = []
        for child_key, child in value.items():
            found.extend(_walk_values(child, str(child_key)))
        return found
    if isinstance(value, list):
        found = []
        for child in value:
            found.extend(_walk_values(child, key))
        return found
    return [as_text(value)]
