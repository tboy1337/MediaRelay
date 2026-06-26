"""Sanitize subtitle file content before serving to the browser."""

from __future__ import annotations

import re

_HTML_TAG_RE = re.compile(r"<[^>]*>")
_DANGEROUS_URI_RE = re.compile(r"(?i)(javascript|data)\s*:")


def sanitize_subtitle_content(content: str) -> str:
    """Remove HTML tags and dangerous URI schemes from subtitle cue text."""
    sanitized = _DANGEROUS_URI_RE.sub("", content)
    return _HTML_TAG_RE.sub("", sanitized)
