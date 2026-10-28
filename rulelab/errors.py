"""Errors raised by the Detection Rules Lab tools."""

from __future__ import annotations


class RuleLabError(Exception):
    """Base error for rule loading, checks, and matching."""


class YamlError(RuleLabError):
    """The lab's YAML reader found something outside the supported subset."""

    def __init__(self, message: str, line: int | None = None) -> None:
        self.line = line
        if line is not None:
            message = f"line {line}: {message}"
        super().__init__(message)


class SigmaSyntaxError(RuleLabError):
    """A detection block uses syntax this lab does not implement."""
