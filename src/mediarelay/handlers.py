"""HTTP request handlers for directory listing, streaming, and API endpoints."""

from __future__ import annotations

import math
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from flask import Response, jsonify, request
from werkzeug.exceptions import RequestedRangeNotSatisfiable
from werkzeug.wsgi import wrap_file

from .constants import MAX_SUBTITLE_FILE_SIZE, SUBTITLE_EXTENSIONS
from .logging_config import truncate_logged_path
from .path_utils import (
    ValidatedFileHandle,
    get_breadcrumbs,
    get_safe_path,
    guess_media_mime_type,
    is_audio_file,
    open_validated_file,
)
from .session_store import get_csrf_token, get_session_username
from .subtitle_sanitize import sanitize_subtitle_content
from .templates import render_index_template

if TYPE_CHECKING:
    from .server import MediaRelayServer


class _DirectoryEntry(TypedDict):
    name: str
    relative_path: str
    is_dir: bool
    size: int
    modified: str


@dataclass(frozen=True)
class _PaginationResult:
    items: list[dict[str, object]]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_prev: bool
    has_next: bool
    range_start: int
    range_end: int


def _parse_page_arg() -> int | tuple[str, int]:
    """Parse the page query parameter; return page number or an error response."""
    raw_page = request.args.get("page")
    if raw_page is None:
        return 1
    try:
        page = int(raw_page)
    except (TypeError, ValueError):
        return "Invalid page parameter", 400
    if page < 1:
        return "Invalid page parameter", 400
    return page


def _paginate_listing(
    items: list[dict[str, object]],
    page: int,
    page_size: int,
) -> _PaginationResult:
    """Slice a sorted listing and return pagination metadata."""
    total_items = len(items)
    total_pages = max(1, math.ceil(total_items / page_size)) if total_items else 1

    if page > total_pages:
        return _PaginationResult(
            items=[],
            page=page,
            page_size=page_size,
            total_items=total_items,
            total_pages=total_pages,
            has_prev=page > 1,
            has_next=False,
            range_start=0,
            range_end=0,
        )

    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]
    range_start = start + 1 if total_items else 0
    range_end = start + len(page_items)
    return _PaginationResult(
        items=page_items,
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        has_prev=page > 1,
        has_next=page < total_pages,
        range_start=range_start,
        range_end=range_end,
    )


def _listing_page_url(directory_path: str, page: int) -> str:
    """Build a pagination URL preserving the current directory path."""
    base = f"/{directory_path}" if directory_path else "/"
    if page <= 1:
        return base
    return f"{base}?page={page}"


@dataclass(frozen=True)
class _DirectoryListingResult:
    items: list[_DirectoryEntry]
    exceeds_cap: bool


@dataclass(frozen=True)
class _ListingContext:
    safe_path: Path
    listing: _DirectoryListingResult
    pagination: _PaginationResult
    directory_path: str
    parent_path: str
    is_root: bool


def _directory_navigation_paths(
    safe_path: Path, video_root: Path
) -> tuple[str, str, bool]:
    """Return directory_path, parent_path, and is_root for a safe listing path."""
    is_root = safe_path == video_root
    parent_path = "/"
    directory_path = ""
    if not is_root:
        try:
            directory_path = str(safe_path.relative_to(video_root)).replace("\\", "/")
            parent_path = "/" + str(safe_path.parent.relative_to(video_root)).replace(
                "\\", "/"
            )
        except ValueError:
            parent_path = "/"
    return directory_path, parent_path, is_root


def _directory_cap_error_message(max_entries: int) -> str:
    return f"Directory contains too many entries (maximum {max_entries})"


def _load_directory_listing(
    server: MediaRelayServer,
    safe_path: Path,
) -> _DirectoryListingResult | tuple[str, int]:
    """Collect directory entries or return an HTTP error tuple."""
    video_root = Path(server.config.video_directory)
    client_ip = server.get_client_ip()
    try:
        listing = _collect_directory_items(
            safe_path,
            video_root,
            server.config.allowed_extensions,
            server.config.max_directory_entries,
            log_warning=server.app.logger.warning,
        )
        if listing.exceeds_cap:
            if server.security_logger:
                server.security_logger.log_security_violation(
                    "directory_listing_truncated",
                    (
                        f"Directory {safe_path} exceeds maximum listing size "
                        f"({server.config.max_directory_entries})"
                    ),
                    client_ip,
                )
            return (
                _directory_cap_error_message(server.config.max_directory_entries),
                413,
            )
        return listing
    except PermissionError:
        if server.security_logger:
            server.security_logger.log_security_violation(
                "access_denied",
                f"Permission denied reading directory: {safe_path}",
                client_ip,
            )
        return "Access denied to directory", 403
    except OSError as error:
        server.app.logger.error(
            "Error reading directory %s: %s",
            truncate_logged_path(str(safe_path)),
            error,
        )
        return "Error reading directory", 500


def _resolve_directory_listing(
    server: MediaRelayServer,
    safe_path: Path,
    page: int,
    *,
    item_builder: Callable[[_DirectoryEntry], dict[str, object]],
    sort_key: Callable[[dict[str, object]], tuple[object, ...]],
) -> _ListingContext | tuple[str, int]:
    """Load, sort, and paginate a directory listing."""
    listing_result = _load_directory_listing(server, safe_path)
    if isinstance(listing_result, tuple):
        return listing_result

    items = [item_builder(entry) for entry in listing_result.items]
    sorted_items = sorted(items, key=sort_key)  # type: ignore[misc]
    pagination = _paginate_listing(sorted_items, page, server.config.page_size)
    video_root = Path(server.config.video_directory)
    directory_path, parent_path, is_root = _directory_navigation_paths(
        safe_path, video_root
    )
    return _ListingContext(
        safe_path=safe_path,
        listing=listing_result,
        pagination=pagination,
        directory_path=directory_path,
        parent_path=parent_path,
        is_root=is_root,
    )


def _index_listing_item(entry: _DirectoryEntry) -> dict[str, object]:
    return {
        "name": entry["name"],
        "path": "/" + entry["relative_path"],
        "is_dir": entry["is_dir"],
        "size": entry["size"],
        "modified": entry["modified"],
        "is_audio": not entry["is_dir"] and is_audio_file(entry["name"]),
    }


def _api_listing_item(entry: _DirectoryEntry) -> dict[str, object]:
    return {
        "name": entry["name"],
        "path": entry["relative_path"],
        "is_directory": entry["is_dir"],
        "size": entry["size"],
        "modified": entry["modified"],
    }


def _render_media_player(
    server: MediaRelayServer,
    safe_path: Path,
    video_root: Path,
    client_ip: str,
) -> str:
    """Render the media player page for a single file."""
    relative_path = safe_path.relative_to(video_root)
    parent_path = (
        "/" + str(relative_path.parent) if str(relative_path.parent) != "." else "/"
    )

    if server.security_logger:
        server.security_logger.log_file_access(
            str(relative_path),
            client_ip,
            True,
            get_session_username(),
        )

    subtitle_path: str | None = None
    vtt_file = safe_path.with_suffix(".vtt")
    srt_file = safe_path.with_suffix(".srt")
    if vtt_file.is_file():
        subtitle_path = str(vtt_file.relative_to(video_root)).replace("\\", "/")
    elif srt_file.is_file():
        subtitle_path = str(srt_file.relative_to(video_root)).replace("\\", "/")

    media_kind = "audio" if is_audio_file(safe_path.name) else "video"

    return render_index_template(
        video_file=safe_path.name,
        video_path=str(relative_path).replace("\\", "/"),
        video_mime_type=guess_media_mime_type(safe_path.name),
        media_kind=media_kind,
        parent_path=parent_path,
        subtitle_path=subtitle_path,
        csrf_token=get_csrf_token(),
    )


def _collect_directory_items(
    directory: Path,
    video_root: Path,
    allowed_extensions: set[str],
    max_entries: int,
    *,
    log_warning: Callable[[str], None] | None = None,
) -> _DirectoryListingResult:
    """Collect listable directory entries, skipping dotfiles and unreadable items."""
    items: list[_DirectoryEntry] = []
    exceeds_cap = False
    listable_count = 0
    try:
        scanner = os.scandir(directory)
    except PermissionError:
        raise
    except OSError as error:
        if log_warning is not None:
            log_warning(f"Error reading directory {directory}: {error}")
        raise

    with scanner:
        for entry in scanner:
            if entry.name.startswith("."):
                continue
            entry_path = Path(entry.path)
            if (
                not entry.is_dir(follow_symlinks=False)
                and entry_path.suffix.lower() not in allowed_extensions
            ):
                continue

            listable_count += 1
            if listable_count > max_entries:
                exceeds_cap = True
                break

            try:
                relative_path = entry_path.relative_to(video_root)
                item_stat = (
                    entry_path.lstat() if entry_path.is_symlink() else entry_path.stat()
                )
            except (OSError, PermissionError, ValueError) as error:
                if log_warning is not None:
                    log_warning(f"Skipping unreadable entry {entry_path}: {error}")
                listable_count -= 1
                continue

            items.append(
                {
                    "name": entry.name,
                    "relative_path": str(relative_path).replace("\\", "/"),
                    "is_dir": entry.is_dir(follow_symlinks=False),
                    "size": (
                        item_stat.st_size if entry.is_file(follow_symlinks=False) else 0
                    ),
                    "modified": datetime.fromtimestamp(item_stat.st_mtime).isoformat(),
                }
            )

    return _DirectoryListingResult(items=items, exceeds_cap=exceeds_cap)


def handle_index_request(
    server: MediaRelayServer, subpath: str
) -> str | tuple[str, int] | Response:
    """Handle index page requests with authentication."""
    if not server.check_authentication():
        return server.auth_required_response()

    page_result = _parse_page_arg()
    if isinstance(page_result, tuple):
        return page_result
    page = page_result

    client_ip = server.get_client_ip()
    safe_path = get_safe_path(
        server.config,
        subpath,
        client_ip=client_ip,
        security_logger=server.security_logger,
        log_error=server.app.logger.error,
        inode_index=server.inode_link_index,
    )
    if not safe_path or not safe_path.exists():
        if server.security_logger and subpath:
            server.security_logger.log_file_access(
                subpath,
                client_ip,
                False,
                get_session_username(),
            )
        return "Path not found", 404

    video_root = Path(server.config.video_directory)

    if safe_path.is_file():
        if safe_path.suffix.lower() in server.config.allowed_extensions:
            return _render_media_player(server, safe_path, video_root, client_ip)
        if server.security_logger:
            server.security_logger.log_security_violation(
                "unauthorized_file_type",
                f"Unauthorized file type access: {subpath}",
                client_ip,
            )
        return "File type not allowed", 403

    listing_context = _resolve_directory_listing(
        server,
        safe_path,
        page,
        item_builder=_index_listing_item,
        sort_key=lambda item: (not item["is_dir"], str(item["name"]).lower()),  # type: ignore[misc]
    )
    if isinstance(listing_context, tuple):
        return listing_context

    pagination = listing_context.pagination
    return render_index_template(
        items=pagination.items,
        is_root=listing_context.is_root,
        parent_path=listing_context.parent_path,
        breadcrumbs=get_breadcrumbs(server.config, safe_path),
        page=pagination.page,
        total_pages=pagination.total_pages,
        total_items=pagination.total_items,
        has_prev=pagination.has_prev,
        has_next=pagination.has_next,
        range_start=pagination.range_start,
        range_end=pagination.range_end,
        prev_page_url=_listing_page_url(
            listing_context.directory_path, pagination.page - 1
        ),
        next_page_url=_listing_page_url(
            listing_context.directory_path, pagination.page + 1
        ),
        csrf_token=get_csrf_token(),
    )


def _check_stream_auth_and_path(
    server: MediaRelayServer, video_path: str
) -> tuple[Path, str] | Response | tuple[str, int]:
    """Validate authentication and resolve a safe stream path."""
    if not server.check_authentication():
        return server.auth_required_response()

    client_ip = server.get_client_ip()
    safe_path = get_safe_path(
        server.config,
        video_path,
        client_ip=client_ip,
        security_logger=server.security_logger,
        log_error=server.app.logger.error,
        inode_index=server.inode_link_index,
    )
    if not safe_path or not safe_path.is_file():
        if server.security_logger:
            server.security_logger.log_file_access(
                video_path,
                client_ip,
                False,
                get_session_username(),
            )
        return "Video not found", 404

    if safe_path.suffix.lower() not in server.config.allowed_extensions:
        if server.security_logger:
            server.security_logger.log_security_violation(
                "unauthorized_file_type",
                f"Unauthorized file type access: {video_path}",
                client_ip,
            )
        return "File type not allowed", 403

    return safe_path, client_ip


def _check_stream_size_limits(
    server: MediaRelayServer,
    video_path: str,
    safe_path: Path,
    client_ip: str,
) -> tuple[str, int] | None:
    """Return an HTTP error tuple when the file exceeds configured size limits."""
    file_size = safe_path.stat().st_size
    is_subtitle = safe_path.suffix.lower() in SUBTITLE_EXTENSIONS
    if is_subtitle:
        subtitle_limit = MAX_SUBTITLE_FILE_SIZE
        if server.config.max_file_size > 0:
            subtitle_limit = min(subtitle_limit, server.config.max_file_size)
        if file_size > subtitle_limit:
            if server.security_logger:
                server.security_logger.log_security_violation(
                    "subtitle_too_large",
                    (
                        f"Stream rejected for oversized subtitle {video_path}: "
                        f"{file_size} bytes exceeds limit {subtitle_limit}"
                    ),
                    client_ip,
                )
            return "Subtitle file exceeds maximum allowed size", 413

    if server.config.max_file_size > 0 and file_size > server.config.max_file_size:
        if server.security_logger:
            server.security_logger.log_security_violation(
                "file_too_large",
                (
                    f"Stream rejected for oversized file {video_path}: "
                    f"{file_size} bytes exceeds limit {server.config.max_file_size}"
                ),
                client_ip,
            )
        return "File exceeds maximum allowed size", 413

    return None


def _build_subtitle_response(fd: int) -> Response:
    """Build a sanitized plain-text response for subtitle files."""
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as subtitle_file:
        raw_content = subtitle_file.read()
    sanitized = sanitize_subtitle_content(raw_content)
    response = Response(sanitized, mimetype="text/plain")
    response.charset = "utf-8"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _build_media_stream_response(
    validated_file: ValidatedFileHandle, filename: str
) -> Response:
    """Build a range-capable streaming response for media files."""
    stat_result = os.fstat(validated_file.fd)
    try:
        file_obj = os.fdopen(validated_file.fd, "rb")
    except OSError:
        os.close(validated_file.fd)
        raise
    try:
        response = Response(
            wrap_file(request.environ, file_obj),
            mimetype=guess_media_mime_type(filename),
            direct_passthrough=True,
        )
        response.content_length = stat_result.st_size
        response.last_modified = stat_result.st_mtime
        response.cache_control.no_cache = True
        try:
            response = response.make_conditional(
                request.environ,
                accept_ranges=True,
                complete_length=stat_result.st_size,
            )
        except RequestedRangeNotSatisfiable:
            file_obj.close()
            raise
    except RequestedRangeNotSatisfiable:
        raise
    except Exception:
        file_obj.close()
        raise
    return response


def _attach_stream_perf_logging(
    server: MediaRelayServer,
    response: Response,
    video_path: str,
    file_size: int,
) -> None:
    """Register a callback to log stream serve duration when the response closes."""
    perf_logger = server.performance_logger
    if perf_logger is None:
        return

    serve_start = time.time()

    def _log_serve_metrics() -> None:
        duration = time.time() - serve_start
        perf_logger.log_file_serve_time(video_path, file_size, duration)

    response.call_on_close(_log_serve_metrics)


def handle_stream_request(
    server: MediaRelayServer, video_path: str
) -> Response | tuple[str, int]:
    """Handle video streaming requests with range support."""
    auth_result = _check_stream_auth_and_path(server, video_path)
    if isinstance(auth_result, Response):
        return auth_result
    if isinstance(auth_result[0], str):
        return auth_result
    safe_path, client_ip = auth_result
    size_error = _check_stream_size_limits(server, video_path, safe_path, client_ip)
    if size_error is not None:
        return size_error

    file_size = safe_path.stat().st_size
    is_subtitle = safe_path.suffix.lower() in SUBTITLE_EXTENSIONS

    if server.security_logger:
        server.security_logger.log_file_access(
            video_path,
            client_ip,
            True,
            get_session_username(),
        )

    validated_file = open_validated_file(
        safe_path,
        server.config.video_directory,
        inode_index=server.inode_link_index,
    )
    if validated_file is None:
        if server.security_logger:
            server.security_logger.log_file_access(
                video_path,
                client_ip,
                False,
                get_session_username(),
            )
        return "Video not found", 404

    try:
        if is_subtitle:
            response = _build_subtitle_response(validated_file.fd)
        else:
            response = _build_media_stream_response(validated_file, safe_path.name)

        _attach_stream_perf_logging(server, response, video_path, file_size)
        return response

    except (OSError, PermissionError, FileNotFoundError) as error:
        server.app.logger.error(
            "Error streaming file %s: %s",
            truncate_logged_path(video_path),
            error,
        )
        return "Error streaming file", 500


def handle_api_files_request(
    server: MediaRelayServer,
) -> Response | tuple[Response, int]:
    """Handle API files listing request."""
    if not server.check_authentication():
        return jsonify({"error": "Authentication required"}), 401  # type: ignore[misc]

    page_result = _parse_page_arg()
    if isinstance(page_result, tuple):
        return jsonify({"error": page_result[0]}), page_result[1]  # type: ignore[misc]
    page = page_result

    try:
        path_param = request.args.get("path", "")
        client_ip = server.get_client_ip()
        safe_path = get_safe_path(
            server.config,
            path_param,
            client_ip=client_ip,
            security_logger=server.security_logger,
            log_error=server.app.logger.error,
            inode_index=server.inode_link_index,
        )

        if not safe_path or not safe_path.exists():
            return jsonify({"error": "Path not found"}), 404  # type: ignore[misc]

        if not safe_path.is_dir():
            return jsonify({"error": "Path is not a directory"}), 400  # type: ignore[misc]

        listing_context = _resolve_directory_listing(
            server,
            safe_path,
            page,
            item_builder=_api_listing_item,
            sort_key=lambda item: (not item["is_directory"], str(item["name"]).lower()),  # type: ignore[misc]
        )
        if isinstance(listing_context, tuple):
            error_message, status_code = listing_context
            return jsonify({"error": error_message}), status_code  # type: ignore[misc]

        pagination = listing_context.pagination
        return jsonify(
            {  # type: ignore[misc]
                "files": pagination.items,
                "path": path_param,
                "page": pagination.page,
                "page_size": pagination.page_size,
                "total_items": pagination.total_items,
                "total_pages": pagination.total_pages,
            }
        )

    except (OSError, ValueError) as error:
        server.app.logger.error("API files error: %s", error)
        return jsonify({"error": "Internal server error"}), 500  # type: ignore[misc]
