"""Sanitize subtitle file content before serving to the browser."""

from __future__ import annotations

import re

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]*>")
_DANGEROUS_URI_RE = re.compile(
    r"(?i)(javascript|data|vbscript|file|about|blob|view-source|chrome|ms-its)\s*:"
)
_WEBVTT_BLOCK_RE = re.compile(r"(?im)^(?:STYLE|NOTE)(?:\s+.*)?\n(?:.*\n)*?(?:\n|$)")


def sanitize_subtitle_content(content: str) -> str:
    """Remove HTML tags, dangerous URI schemes, and WEBVTT STYLE/NOTE blocks."""
    without_controls = _CONTROL_CHAR_RE.sub("", content)
    without_blocks = _WEBVTT_BLOCK_RE.sub("", without_controls)
    without_comments = _HTML_COMMENT_RE.sub("", without_blocks)
    without_uris = _DANGEROUS_URI_RE.sub("", without_comments)
    return _HTML_TAG_RE.sub("", without_uris)
