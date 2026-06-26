"""Sanitize subtitle file content before serving to the browser."""

from __future__ import annotations

import re

_HTML_TAG_RE = re.compile(r"<[^>]*>")
_DANGEROUS_URI_RE = re.compile(r"(?i)(javascript|data|vbscript|file|about)\s*:")
_WEBVTT_BLOCK_RE = re.compile(r"(?im)^(?:STYLE|NOTE)(?:\s+.*)?\n(?:.*\n)*?(?:\n|$)")


def sanitize_subtitle_content(content: str) -> str:
    """Remove HTML tags, dangerous URI schemes, and WEBVTT STYLE/NOTE blocks."""
    without_blocks = _WEBVTT_BLOCK_RE.sub("", content)
    without_uris = _DANGEROUS_URI_RE.sub("", without_blocks)
    return _HTML_TAG_RE.sub("", without_uris)
