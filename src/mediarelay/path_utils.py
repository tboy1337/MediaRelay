"""Path resolution and breadcrumb utilities with traversal protection."""

from __future__ import annotations

import logging
import mimetypes
import os
import threading
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

from .config import ServerConfig
from .constants import AUDIO_EXTENSIONS, MAX_LOGGED_PATH_LENGTH

if TYPE_CHECKING:
    from .logging_config import SecurityEventLogger

_PATH_LOGGER = logging.getLogger(__name__)

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


def _contains_unsafe_path_chars(path: str) -> bool:
    """Return True when the path contains control or non-printable characters."""
    for char in path:
        code = ord(char)
        if code < 32 or code == 127:
            return True
        if unicodedata.category(char).startswith("C"):
            return True
    return False


def _decode_url_path(requested_path: str) -> str:
    """Apply multi-pass URL decoding (capped) to a requested path."""
    for _ in range(10):
        decoded_path = unquote(requested_path)
        if decoded_path == requested_path:
            break
        requested_path = decoded_path
    return unicodedata.normalize("NFKC", requested_path)


def _truncate_log_detail(detail: str) -> str:
    """Truncate attacker-controlled detail strings before security logging."""
    if len(detail) <= MAX_LOGGED_PATH_LENGTH:
        return detail
    return f"{detail[:MAX_LOGGED_PATH_LENGTH]}...(truncated)"


def _log_path_violation(
    security_logger: SecurityEventLogger | None,
    violation_type: str,
    detail: str,
    client_ip: str,
) -> None:
    """Emit a structured security violation when a logger is available."""
    if security_logger:
        security_logger.log_security_violation(
            violation_type, _truncate_log_detail(detail), client_ip
        )


def _validate_path_segments(
    requested_path: str,
    *,
    client_ip: str,
    security_logger: SecurityEventLogger | None,
) -> bool:
    """Return False when the path string fails segment-level safety checks."""
    if _contains_unsafe_path_chars(requested_path):
        _log_path_violation(
            security_logger,
            "path_traversal",
            f"Unsafe characters in path: {requested_path!r}",
            client_ip,
        )
        return False

    if requested_path.startswith(("/", "\\")):
        _log_path_violation(
            security_logger,
            "path_traversal",
            f"Absolute path attempt: {requested_path}",
            client_ip,
        )
        return False

    if "\\" in requested_path:
        _log_path_violation(
            security_logger,
            "path_traversal",
            f"Path traversal attempt: {requested_path}",
            client_ip,
        )
        return False

    normalized_path = requested_path.replace("\\", "/")
    path_segments = normalized_path.split("/")
    if any(
        segment.startswith(".") and segment not in {".", ".."}
        for segment in path_segments
        if segment
    ):
        _log_path_violation(
            security_logger,
            "dotfile_access",
            f"Dotfile access attempt: {requested_path}",
            client_ip,
        )
        return False

    if "//" in normalized_path or ".." in path_segments:
        _log_path_violation(
            security_logger,
            "path_traversal",
            f"Path traversal attempt: {requested_path}",
            client_ip,
        )
        return False

    return True


class InodeLinkIndex:
    """Thread-safe cache of inode link counts under the video directory jail."""

    def __init__(self, jail_root: Path) -> None:
        self._jail_root = jail_root.resolve()
        self._counts: dict[tuple[int, int], int] = {}
        self._lock = threading.Lock()
        self._fingerprint: tuple[int, int] | None = None

    def refresh(self, *, force: bool = False) -> None:
        """Rebuild the inode link count index from the jail root."""
        fingerprint = _compute_jail_fingerprint(self._jail_root)
        with self._lock:
            if not force and fingerprint == self._fingerprint:
                _PATH_LOGGER.debug(
                    "Inode index refresh skipped; jail fingerprint unchanged"
                )
                return

        counts = _build_inode_counts(self._jail_root)

        with self._lock:
            self._counts = counts
            self._fingerprint = fingerprint

    def count_links(self, ino: int, dev: int) -> int | None:
        """Return cached link count for an inode, or None when not indexed."""
        with self._lock:
            return self._counts.get((dev, ino))


def _count_jail_entries(root: Path) -> int:
    """Count directory entries under root without collecting paths."""
    count = 0
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    count += 1
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
        except OSError:
            continue
    return count


def _compute_jail_fingerprint(jail_root: Path) -> tuple[int, int]:
    """Return a cheap fingerprint of the jail tree for refresh skip decisions."""
    try:
        jail_stat = jail_root.stat()
        mtime_ns = jail_stat.st_mtime_ns
    except OSError:
        return (0, 0)

    return (mtime_ns, _count_jail_entries(jail_root))


def _scandir_walk(root: Path) -> list[Path]:
    """Walk a directory tree using os.scandir for lower overhead than rglob."""
    paths: list[Path] = []
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entry_path = Path(entry.path)
                    paths.append(entry_path)
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry_path)
        except OSError:
            continue
    return paths


def _inode_key_for_path(path: Path) -> tuple[int, int] | None:
    """Return the (dev, ino) key for a path, or None when stat fails."""
    try:
        stat_result = path.lstat() if path.is_symlink() else path.stat()
    except OSError:
        return None
    return (stat_result.st_dev, stat_result.st_ino)


def _build_inode_counts(jail_root: Path) -> dict[tuple[int, int], int]:
    """Count inode references for every path entry under the jail root."""
    counts: dict[tuple[int, int], int] = {}
    jail_key = _inode_key_for_path(jail_root)
    if jail_key is not None:
        counts[jail_key] = counts.get(jail_key, 0) + 1

    for path in _scandir_walk(jail_root):
        key = _inode_key_for_path(path)
        if key is None:
            continue
        counts[key] = counts.get(key, 0) + 1
    return counts


def _count_inode_links_under_jail(ino: int, dev: int, jail_root: Path) -> int:
    """Count directory entries under jail_root that reference the given inode."""
    count = 0
    jail_key = _inode_key_for_path(jail_root)
    if jail_key is not None and jail_key == (dev, ino):
        count += 1

    for path in _scandir_walk(jail_root):
        key = _inode_key_for_path(path)
        if key == (dev, ino):
            count += 1
    return count


def _is_hardlink_outside_jail(
    resolved_path: Path,
    jail_root: Path,
    *,
    inode_index: InodeLinkIndex | None = None,
) -> bool:
    """Return True when a file hard link references content also linked outside jail."""
    if not resolved_path.is_file():
        return False

    try:
        stat_result = resolved_path.stat()
    except OSError:
        return False

    if stat_result.st_nlink <= 1:
        return False

    jail_resolved = jail_root.resolve()
    links_in_jail: int | None = None
    if inode_index is not None:
        links_in_jail = inode_index.count_links(stat_result.st_ino, stat_result.st_dev)

    if links_in_jail is None:
        _PATH_LOGGER.warning(
            "Inode index miss for (%s, %s); falling back to live scan",
            stat_result.st_dev,
            stat_result.st_ino,
        )
        links_in_jail = _count_inode_links_under_jail(
            stat_result.st_ino, stat_result.st_dev, jail_resolved
        )

    return links_in_jail < stat_result.st_nlink


def _resolve_within_jail(
    video_directory: str,
    requested_path: str,
    *,
    client_ip: str,
    security_logger: SecurityEventLogger | None,
    log_error: Callable[[str], None] | None,
    inode_index: InodeLinkIndex | None = None,
) -> Path | None:
    """Resolve a relative path and verify jail containment including hard links."""
    full_path = Path(video_directory) / requested_path

    try:
        resolved_path = resolve_path(full_path)
        resolved_video_dir = resolve_path(Path(video_directory))
        resolved_path.relative_to(resolved_video_dir)
    except ValueError:
        _log_path_violation(
            security_logger,
            "path_traversal",
            f"Path traversal attempt: {requested_path}",
            client_ip,
        )
        return None
    except (RuntimeError, OSError) as error:
        if log_error is not None:
            log_error(f"Path error: {str(error)} for path: {requested_path}")
        _log_path_violation(
            security_logger,
            "path_resolution_error",
            f"Path resolution failed for {requested_path!r}: {error}",
            client_ip,
        )
        return None

    if _is_hardlink_outside_jail(
        resolved_path, resolved_video_dir, inode_index=inode_index
    ):
        _log_path_violation(
            security_logger,
            "hardlink_escape",
            f"Hard link escape attempt: {requested_path}",
            client_ip,
        )
        return None

    return resolved_path


def revalidate_before_serve(resolved_path: Path, video_directory: str) -> bool:
    """Re-check jail containment and hard links immediately before serving a file."""
    try:
        current_path = resolve_path(resolved_path)
        jail_root = resolve_path(Path(video_directory))
        current_path.relative_to(jail_root)
    except (ValueError, RuntimeError, OSError):
        return False

    if not current_path.is_file():
        return False

    return not _is_hardlink_outside_jail(current_path, jail_root, inode_index=None)


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
    inode_index: InodeLinkIndex | None = None,
) -> Path | None:
    """Ensure the requested path is within the video directory."""
    if not requested_path:
        return Path(config.video_directory)

    requested_path = _decode_url_path(requested_path)

    if not _validate_path_segments(
        requested_path,
        client_ip=client_ip,
        security_logger=security_logger,
    ):
        return None

    return _resolve_within_jail(
        config.video_directory,
        requested_path,
        client_ip=client_ip,
        security_logger=security_logger,
        log_error=log_error,
        inode_index=inode_index,
    )
