"""HTTP request handlers for directory listing, streaming, and API endpoints."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from flask import Response, jsonify, request, send_from_directory, session

from .path_utils import (
    get_breadcrumbs,
    get_safe_path,
    guess_media_mime_type,
    is_audio_file,
)
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


def _session_username() -> str:
    return str(session.get("username", "unknown"))  # type: ignore[misc]


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


def _collect_directory_items(
    directory: Path,
    video_root: Path,
    allowed_extensions: set[str],
    *,
    log_warning: Callable[[str], None] | None = None,
) -> list[_DirectoryEntry]:
    """Collect listable directory entries, skipping dotfiles and unreadable items."""
    items: list[_DirectoryEntry] = []
    try:
        entries = list(directory.iterdir())
    except PermissionError:
        raise
    except OSError as error:
        if log_warning is not None:
            log_warning(f"Error reading directory {directory}: {error}")
        raise

    for item in entries:
        if item.name.startswith("."):
            continue
        if not item.is_dir() and item.suffix.lower() not in allowed_extensions:
            continue

        try:
            relative_path = item.relative_to(video_root)
            item_stat = item.stat()
        except (OSError, PermissionError, ValueError) as error:
            if log_warning is not None:
                log_warning(f"Skipping unreadable entry {item}: {error}")
            continue

        items.append(
            {
                "name": item.name,
                "relative_path": str(relative_path).replace("\\", "/"),
                "is_dir": item.is_dir(),
                "size": item_stat.st_size if item.is_file() else 0,
                "modified": datetime.fromtimestamp(item_stat.st_mtime).isoformat(),
            }
        )

    return items


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
    )
    if not safe_path or not safe_path.exists():
        if server.security_logger and subpath:
            server.security_logger.log_file_access(
                subpath,
                client_ip,
                False,
                _session_username(),
            )
        return "Path not found", 404

    video_root = Path(server.config.video_directory)

    if safe_path.is_file():
        if safe_path.suffix.lower() in server.config.allowed_extensions:
            relative_path = safe_path.relative_to(video_root)
            parent_path = (
                "/" + str(relative_path.parent)
                if str(relative_path.parent) != "."
                else "/"
            )

            if server.security_logger:
                server.security_logger.log_file_access(
                    str(relative_path),
                    client_ip,
                    True,
                    _session_username(),
                )

            subtitle_path: str | None = None
            srt_file = safe_path.with_suffix(".srt")
            if srt_file.is_file():
                subtitle_path = str(srt_file.relative_to(video_root)).replace("\\", "/")

            media_kind = "audio" if is_audio_file(safe_path.name) else "video"

            return render_index_template(
                video_file=safe_path.name,
                video_path=str(relative_path).replace("\\", "/"),
                video_mime_type=guess_media_mime_type(safe_path.name),
                media_kind=media_kind,
                parent_path=parent_path,
                subtitle_path=subtitle_path,
            )
        return "Not a video file", 400

    try:
        raw_items = _collect_directory_items(
            safe_path,
            video_root,
            server.config.allowed_extensions,
            log_warning=server.app.logger.warning,
        )
        items = [
            {
                "name": entry["name"],
                "path": "/" + entry["relative_path"],
                "is_dir": entry["is_dir"],
                "size": entry["size"],
                "modified": entry["modified"],
                "is_audio": not entry["is_dir"] and is_audio_file(entry["name"]),
            }
            for entry in raw_items
        ]
    except PermissionError:
        if server.security_logger:
            server.security_logger.log_security_violation(
                "access_denied",
                f"Permission denied reading directory: {safe_path}",
                client_ip,
            )
        return "Access denied to directory", 403
    except OSError as error:
        server.app.logger.error(f"Error reading directory {safe_path}: {str(error)}")
        return "Error reading directory", 500

    sorted_items = sorted(items, key=lambda x: (not x["is_dir"], str(x["name"]).lower()))  # type: ignore[misc]
    pagination = _paginate_listing(sorted_items, page, server.config.page_size)

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

    return render_index_template(
        items=pagination.items,
        is_root=is_root,
        parent_path=parent_path,
        breadcrumbs=get_breadcrumbs(server.config, safe_path),
        page=pagination.page,
        total_pages=pagination.total_pages,
        total_items=pagination.total_items,
        has_prev=pagination.has_prev,
        has_next=pagination.has_next,
        range_start=pagination.range_start,
        range_end=pagination.range_end,
        prev_page_url=_listing_page_url(directory_path, pagination.page - 1),
        next_page_url=_listing_page_url(directory_path, pagination.page + 1),
    )


def handle_stream_request(
    server: MediaRelayServer, video_path: str
) -> Response | tuple[str, int]:
    """Handle video streaming requests with range support."""
    if not server.check_authentication():
        return server.auth_required_response()

    client_ip = server.get_client_ip()
    safe_path = get_safe_path(
        server.config,
        video_path,
        client_ip=client_ip,
        security_logger=server.security_logger,
        log_error=server.app.logger.error,
    )
    if not safe_path or not safe_path.is_file():
        if server.security_logger:
            server.security_logger.log_file_access(
                video_path,
                client_ip,
                False,
                _session_username(),
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

    if server.security_logger:
        server.security_logger.log_file_access(
            video_path,
            client_ip,
            True,
            _session_username(),
        )

    start_time = time.time()

    try:
        directory = safe_path.parent
        filename = safe_path.name
        response = send_from_directory(directory, filename)

        if server.performance_logger:
            duration = time.time() - start_time
            file_size = safe_path.stat().st_size
            server.performance_logger.log_file_serve_time(
                video_path, file_size, duration
            )

        return response

    except (OSError, PermissionError, FileNotFoundError) as error:
        server.app.logger.error(f"Error streaming file {video_path}: {str(error)}")
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
        )

        if not safe_path or not safe_path.exists():
            return jsonify({"error": "Path not found"}), 404  # type: ignore[misc]

        if not safe_path.is_dir():
            return jsonify({"error": "Path is not a directory"}), 400  # type: ignore[misc]

        video_root = Path(server.config.video_directory)
        raw_items = _collect_directory_items(
            safe_path,
            video_root,
            server.config.allowed_extensions,
            log_warning=server.app.logger.warning,
        )
        files = [
            {
                "name": entry["name"],
                "path": entry["relative_path"],
                "is_directory": entry["is_dir"],
                "size": entry["size"],
                "modified": entry["modified"],
            }
            for entry in raw_items
        ]

        sorted_files = sorted(  # type: ignore[misc]
            files,
            key=lambda x: (not x["is_directory"], x["name"].lower()),  # type: ignore[misc]
        )
        pagination = _paginate_listing(
            sorted_files, page, server.config.page_size  # type: ignore[arg-type]
        )

        return jsonify(
            {  # type: ignore[misc]
                "files": pagination.items,
                "path": path_param,
                "total_files": pagination.total_items,
                "page": pagination.page,
                "page_size": pagination.page_size,
                "total_items": pagination.total_items,
                "total_pages": pagination.total_pages,
            }
        )

    except (OSError, PermissionError, ValueError) as error:
        server.app.logger.error(f"API files error: {str(error)}")
        return jsonify({"error": "Internal server error"}), 500  # type: ignore[misc]
