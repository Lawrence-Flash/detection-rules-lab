"""Repository paths used when commands are started from another directory."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
DATA_DIR = ROOT / "tests" / "data"
COVERAGE_PATH = ROOT / "docs" / "coverage.md"
EXAMPLES_DIR = ROOT / "examples"


def display_path(path: Path) -> str:
    """Prefer a path relative to the repository, then to the working directory."""
    resolved = path.resolve()
    for base in (ROOT, Path.cwd()):
        try:
            return resolved.relative_to(base.resolve()).as_posix()
        except ValueError:
            continue
    return path.as_posix()
