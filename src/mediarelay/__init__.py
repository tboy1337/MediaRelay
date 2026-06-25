"""MediaRelay — secure personal video streaming server."""

from __future__ import annotations

import re
from pathlib import Path


def _version_from_metadata() -> str | None:
    """Read version from installed package metadata."""
    try:
        from importlib.metadata import version

        return version("mediarelay")
    except (ImportError, OSError, ValueError):
        return None


def _version_from_pyproject() -> str | None:
    """Read version from pyproject.toml for editable checkouts."""
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if not pyproject.is_file():
        return None

    try:
        content = pyproject.read_text(encoding="utf-8")
    except OSError:
        return None

    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if match is None:
        return None

    return match.group(1)


def _get_version() -> str:
    """Return the installed package version, with fallbacks for editable checkouts."""
    return _version_from_metadata() or _version_from_pyproject() or "0.0.0.dev"


__version__ = _get_version()
