"""Path resolution and breadcrumb utilities with traversal protection."""

from __future__ import annotations

import mimetypes
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

from .config import ServerConfig
from .constants import AUDIO_EXTENSIONS

if TYPE_CHECKING:
    from .logging_config import SecurityEventLogger

_EXTENSION_MIME_FALLBACKS: dict[str, str] = {
    ".mkv": "video/x-matroska",
    ".webm": "video/webm",
    ".m4v": "video/x-m4v",
    ".flv": "video/x-flv",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    ".mp4": "video/mp4",
    ".mp3": "audio/mpeg",
    ".aac": "audio/aac",
    ".ogg": "audio/ogg",
    ".wav": "audio/wav",
}


def is_audio_file(filename: str) -> bool:
    """Return True when the filename has a known audio extension."""
    return Path(filename).suffix.lower() in AUDIO_EXTENSIONS


def guess_media_mime_type(filename: str) -> str:
    """Return the MIME type for a media filename."""
    suffix = Path(filename).suffix.lower()
    if suffix in _EXTENSION_MIME_FALLBACKS:
        return _EXTENSION_MIME_FALLBACKS[suffix]

    guessed, _encoding = mimetypes.guess_type(filename)
    if guessed:
        return guessed

    return "application/octet-stream"


def resolve_path(path: Path) -> Path:
    """Resolve a path, following symlinks for jail containment checks."""
    return path.resolve()


def get_breadcrumbs(config: ServerConfig, path: Path) -> list[dict[str, str]]:
    """Generate breadcrumb navigation for a path within the video directory."""
    video_dir = Path(config.video_directory)
    crumbs = [{"name": "Home", "path": "/"}]

    try:
        relative_path = path.relative_to(video_dir)
        current_path = ""
        for part in relative_path.parts:
            current_path = f"{current_path}/{part}"
            crumbs.append({"name": part, "path": current_path})
    except ValueError:
        pass

    return crumbs


def get_safe_path(
    config: ServerConfig,
    requested_path: str,
    *,
    client_ip: str,
    security_logger: SecurityEventLogger | None = None,
    log_error: Callable[[str], None] | None = None,
) -> Path | None:
    """Ensure the requested path is within the video directory."""
    if not requested_path:
        return Path(config.video_directory)

    for _ in range(3):
        decoded_path = unquote(requested_path)
        if decoded_path == requested_path:
            break
        requested_path = decoded_path

    requested_path = unicodedata.normalize("NFC", requested_path)

    if "\x00" in requested_path:
        if security_logger:
            security_logger.log_security_violation(
                "path_traversal",
                f"Null byte in path: {requested_path!r}",
                client_ip,
            )
        return None

    if requested_path.startswith(("/", "\\")):
        if security_logger:
            security_logger.log_security_violation(
                "path_traversal",
                f"Absolute path attempt: {requested_path}",
                client_ip,
            )
        return None

    if "\\" in requested_path:
        if security_logger:
            security_logger.log_security_violation(
                "path_traversal",
                f"Path traversal attempt: {requested_path}",
                client_ip,
            )
        return None

    normalized_path = requested_path.replace("\\", "/")
    if "//" in normalized_path or ".." in normalized_path.split("/"):
        if security_logger:
            security_logger.log_security_violation(
                "path_traversal",
                f"Path traversal attempt: {requested_path}",
                client_ip,
            )
        return None

    full_path = Path(config.video_directory) / requested_path

    try:
        resolved_path = resolve_path(full_path)
        resolved_video_dir = resolve_path(Path(config.video_directory))
        resolved_path.relative_to(resolved_video_dir)
        return resolved_path
    except ValueError:
        if security_logger:
            security_logger.log_security_violation(
                "path_traversal",
                f"Path traversal attempt: {requested_path}",
                client_ip,
            )
    except (RuntimeError, OSError) as error:
        if log_error is not None and callable(log_error):
            log_error(f"Path error: {str(error)} for path: {requested_path}")

    return None
