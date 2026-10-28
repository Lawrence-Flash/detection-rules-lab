"""YAML reader for the subset of Sigma used in this lab.

The standard library has no YAML parser. Rules stay YAML, which is what Sigma
is written in, and this module reads the subset the lab actually uses:

- space-indented mappings and sequences
- comments that start with ``#`` outside quotes
- plain, single-quoted, and double-quoted scalars
- literal blocks opened with ``|``
- ``true``, ``false``, ``null``, and decimal integers

Flow collections (``[a, b]`` and ``{a: b}``), anchors, tags, folded scalars
(``>``), and tabs are rejected.
"""

from __future__ import annotations

import re

from rulelab.errors import YamlError

_INT = re.compile(r"-?(0|[1-9][0-9]*)\Z")


def loads(text: str) -> object:
    """Parse a YAML document from ``text`` and return lists, dicts, and scalars."""
    for line_no, line in enumerate(text.splitlines(), 1):
        if "\t" in line:
            raise YamlError("tabs are not allowed for indentation", line_no)
    parser = _Parser(text.splitlines())
    parser.skip_noise()
    if parser.eof:
        return None
    if parser.indent(parser.i) != 0:
        raise YamlError("top-level content must start at column 0", parser.line_no)
    value = parser.parse_node(0)
    parser.skip_noise()
    if not parser.eof:
        raise YamlError("trailing content", parser.line_no)
    return value


def _strip_comment(content: str) -> str:
    """Remove an unquoted ``#`` comment. ``#`` inside quotes is kept."""
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(content):
        if in_double and char == "\\" and not escaped:
            escaped = True
            continue
        if char == "'" and not in_double and not escaped:
            in_single = not in_single
        elif char == '"' and not in_single and not escaped:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            if index == 0 or content[index - 1].isspace():
                return content[:index].rstrip()
        escaped = False
    return content.strip()


def _split_key(content: str, line_no: int) -> tuple[str, str]:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(content):
        if in_double and char == "\\" and not escaped:
            escaped = True
            continue
        if char == "'" and not in_double and not escaped:
            in_single = not in_single
        elif char == '"' and not in_single and not escaped:
            in_double = not in_double
        elif char == ":" and not in_single and not in_double:
            key = content[:index].strip()
            if not key:
                raise YamlError("empty mapping key", line_no)
            return key, content[index + 1 :].strip()
        escaped = False
    raise YamlError("expected 'key: value'", line_no)


def _parse_scalar(src: str, line_no: int) -> object:
    src = src.strip()
    if src in {"", "null", "Null", "NULL", "~"}:
        return None
    if src in {"true", "True", "TRUE"}:
        return True
    if src in {"false", "False", "FALSE"}:
        return False
    if src.startswith("'"):
        if len(src) < 2 or not src.endswith("'"):
            raise YamlError("unterminated single-quoted string", line_no)
        return src[1:-1].replace("''", "'")
    if src.startswith('"'):
        if len(src) < 2 or not src.endswith('"'):
            raise YamlError("unterminated double-quoted string", line_no)
        return _unescape_double(src[1:-1], line_no)
    if _INT.fullmatch(src):
        return int(src)
    return src


def _unescape_double(inner: str, line_no: int) -> str:
    escapes = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "/": "/"}
    pieces: list[str] = []
    index = 0
    while index < len(inner):
        char = inner[index]
        if char != "\\":
            pieces.append(char)
            index += 1
            continue
        if index + 1 >= len(inner) or inner[index + 1] not in escapes:
            raise YamlError("unsupported escape in double-quoted string", line_no)
        pieces.append(escapes[inner[index + 1]])
        index += 2
    return "".join(pieces)


class _Parser:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.i = 0

    @property
    def eof(self) -> bool:
        return self.i >= len(self.lines)

    @property
    def line_no(self) -> int:
        return self.i + 1

    def indent(self, index: int) -> int:
        raw = self.lines[index]
        return len(raw) - len(raw.lstrip(" "))

    def skip_noise(self) -> None:
        while not self.eof:
            raw = self.lines[self.i]
            if raw.strip() == "" or raw.lstrip().startswith("#"):
                self.i += 1
                continue
            break

    def parse_node(self, indent: int) -> object:
        self.skip_noise()
        if self.eof:
            raise YamlError("expected a value", self.line_no)
        content = _strip_comment(self.lines[self.i].strip())
        if content == "-" or content.startswith("- "):
            return self.parse_seq(indent)
        return self.parse_map(indent)

    def parse_map(self, indent: int) -> dict[str, object]:
        mapping: dict[str, object] = {}
        while not self.eof:
            self.skip_noise()
            if self.eof:
                break
            line_indent = self.indent(self.i)
            if line_indent < indent:
                break
            if line_indent > indent:
                raise YamlError("unexpected indent in mapping", self.line_no)
            content = _strip_comment(self.lines[self.i].strip())
            if content == "-" or content.startswith("- "):
                raise YamlError("expected a mapping entry", self.line_no)
            line_no = self.line_no
            key, value_src = _split_key(content, line_no)
            if key in mapping:
                raise YamlError(f"duplicate key {key!r}", line_no)
            self.i += 1
            if value_src == "|":
                mapping[key] = self.parse_literal(indent)
            elif value_src == "":
                self.skip_noise()
                if not self.eof and self.indent(self.i) > indent:
                    mapping[key] = self.parse_node(self.indent(self.i))
                else:
                    mapping[key] = None
            else:
                mapping[key] = _parse_scalar(value_src, line_no)
        return mapping

    def parse_seq(self, indent: int) -> list[object]:
        items: list[object] = []
        while not self.eof:
            self.skip_noise()
            if self.eof:
                break
            line_indent = self.indent(self.i)
            if line_indent < indent:
                break
            if line_indent > indent:
                raise YamlError("unexpected indent in sequence", self.line_no)
            content = _strip_comment(self.lines[self.i].strip())
            if content == "-":
                item_src = ""
            elif content.startswith("- "):
                item_src = content[2:].strip()
            else:
                raise YamlError("expected a sequence entry", self.line_no)
            line_no = self.line_no
            self.i += 1
            if item_src == "":
                self.skip_noise()
                if not self.eof and self.indent(self.i) > indent:
                    items.append(self.parse_node(self.indent(self.i)))
                else:
                    items.append(None)
            elif item_src == "|":
                items.append(self.parse_literal(indent))
            else:
                items.append(_parse_scalar(item_src, line_no))
        return items

    def parse_literal(self, parent_indent: int) -> str:
        """Read a ``|`` block. ``#`` inside the block is content, not a comment."""
        chunks: list[str] = []
        base: int | None = None
        while not self.eof:
            raw = self.lines[self.i]
            if raw.strip() == "":
                chunks.append("")
                self.i += 1
                continue
            line_indent = self.indent(self.i)
            if line_indent <= parent_indent:
                break
            if base is None:
                base = line_indent
            if line_indent < base:
                raise YamlError("literal block is indented less than its first line", self.line_no)
            chunks.append(raw[base:])
            self.i += 1
        if not chunks:
            return ""
        return "\n".join(chunks) + "\n"
