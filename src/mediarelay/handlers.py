"""HTTP request handlers for directory listing, streaming, and API endpoints."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from flask import (
    Response,
    jsonify,
    render_template_string,
    request,
    send_from_directory,
    session,
)

from .path_utils import get_breadcrumbs, get_safe_path
from .templates import INDEX_HTML_TEMPLATE

if TYPE_CHECKING:
    from .server import MediaRelayServer


def handle_index_request(
    server: MediaRelayServer, subpath: str
) -> str | tuple[str, int] | Response:
    """Handle index page requests with authentication."""
    if not server.check_authentication():
        return server.auth_required_response()

    client_ip = server.get_client_ip()
    safe_path = get_safe_path(
        server.config,
        subpath,
        client_ip=client_ip,
        security_logger=server.security_logger,
        log_error=server.app.logger.error,
    )
    if not safe_path or not safe_path.exists():
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
                    session.get("username", "unknown"),  # type: ignore[misc]
                )

            return render_template_string(
                INDEX_HTML_TEMPLATE,
                video_file=safe_path.name,
                video_path=str(relative_path).replace("\\", "/"),
                parent_path=parent_path,
            )
        return "Not a video file", 400

    items = []
    try:
        for item in safe_path.iterdir():
            if item.is_dir() or item.suffix.lower() in server.config.allowed_extensions:
                relative_path = item.relative_to(video_root)
                items.append(
                    {
                        "name": item.name,
                        "path": "/" + str(relative_path).replace("\\", "/"),
                        "is_dir": item.is_dir(),
                        "size": item.stat().st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(
                            item.stat().st_mtime
                        ).isoformat(),
                    }
                )
    except PermissionError:
        return "Access denied to directory", 403
    except OSError as error:
        server.app.logger.error(f"Error reading directory {safe_path}: {str(error)}")
        return "Error reading directory", 500

    is_root = safe_path == video_root
    parent_path = "/"
    if not is_root:
        try:
            parent_path = "/" + str(safe_path.parent.relative_to(video_root)).replace(
                "\\", "/"
            )
        except ValueError:
            parent_path = "/"

    return render_template_string(
        INDEX_HTML_TEMPLATE,
        items=sorted(items, key=lambda x: (not x["is_dir"], x["name"].lower())),  # type: ignore[misc]
        is_root=is_root,
        parent_path=parent_path,
        breadcrumbs=get_breadcrumbs(server.config, safe_path),
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
            session.get("username", "unknown"),  # type: ignore[misc]
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
        files = []
        for item in safe_path.iterdir():
            if item.is_dir() or item.suffix.lower() in server.config.allowed_extensions:
                relative_path = item.relative_to(video_root)
                files.append(
                    {
                        "name": item.name,
                        "path": str(relative_path).replace("\\", "/"),
                        "is_directory": item.is_dir(),
                        "size": item.stat().st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(
                            item.stat().st_mtime
                        ).isoformat(),
                    }
                )

        return jsonify(
            {  # type: ignore[misc]
                "files": sorted(  # type: ignore[misc]
                    files,
                    key=lambda x: (not x["is_directory"], x["name"].lower()),  # type: ignore[misc]
                ),
                "path": path_param,
                "total_files": len(files),
            }
        )

    except (OSError, PermissionError, ValueError) as error:
        server.app.logger.error(f"API files error: {str(error)}")
        return jsonify({"error": "Internal server error"}), 500  # type: ignore[misc]
