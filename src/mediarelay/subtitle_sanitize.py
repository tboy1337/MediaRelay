"""Sanitize subtitle file content before serving to the browser."""

from __future__ import annotations

import re
from urllib.parse import unquote

from .constants import MAX_SUBTITLE_DECODE_PASSES

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_BIDI_CHAR_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]*>")
_DANGEROUS_URI_RE = re.compile(
    r"(?i)(javascript|data|vbscript|file|about|blob|view-source|chrome|ms-its)\s*:"
)
_WEBVTT_BLOCK_RE = re.compile(r"(?im)^(?:STYLE|NOTE)(?:\s+.*)?\n(?:.*\n)*?(?:\n|$)")


def _decode_percent_encoding_bounded(content: str) -> str:
    """Decode percent-encoded sequences in bounded passes before URI checks."""
    decoded = content
    for _ in range(MAX_SUBTITLE_DECODE_PASSES):
        try:
            next_decoded = unquote(decoded)
        except (ValueError, UnicodeDecodeError):
            break
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return decoded


def sanitize_subtitle_content(content: str) -> str:
    """Remove HTML tags, dangerous URI schemes, and WEBVTT STYLE/NOTE blocks."""
    without_controls = _CONTROL_CHAR_RE.sub("", content)
    without_bidi = _BIDI_CHAR_RE.sub("", without_controls)
    decoded = _decode_percent_encoding_bounded(without_bidi)
    without_blocks = _WEBVTT_BLOCK_RE.sub("", decoded)
    without_comments = _HTML_COMMENT_RE.sub("", without_blocks)
    without_uris = _DANGEROUS_URI_RE.sub("", without_comments)
    return _HTML_TAG_RE.sub("", without_uris)
