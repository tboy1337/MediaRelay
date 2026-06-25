"""Flask route registration for MediaRelay."""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from flask import Response, g, jsonify, request, session

from . import __version__
from .auth import auth_required_response, check_authentication
from .constants import HSTS_HEADER_VALUE, MAX_PATH_LENGTH, MAX_URL_LENGTH
from .handlers import (
    handle_api_files_request,
    handle_index_request,
    handle_stream_request,
)
from .logging_config import get_request_logger

if TYPE_CHECKING:
    from .server import MediaRelayServer


def register_routes(server: MediaRelayServer) -> None:
    """Register all application routes and request middleware."""

    @server.app.before_request
    def before_request() -> tuple[str, int] | None:
        """Process requests before handling."""
        g.start_time = time.time()
        g.request_id = secrets.token_hex(8)
        client_ip = server.get_client_ip()

        full_url = request.url
        if len(full_url) > MAX_URL_LENGTH:
            if server.security_logger:
                server.security_logger.log_security_violation(
                    "url_too_long",
                    f"URL length {len(full_url)} exceeds maximum {MAX_URL_LENGTH}",
                    client_ip,
                )
            return "Request URI Too Long", 414

        if len(request.path) > MAX_PATH_LENGTH:
            if server.security_logger:
                server.security_logger.log_security_violation(
                    "path_too_long",
                    f"Path length {len(request.path)} exceeds maximum {MAX_PATH_LENGTH}",
                    client_ip,
                )
            return "Request URI Too Long", 414

        get_request_logger("mediarelay").debug(
            "Request %s: %s %s from %s",
            g.request_id,  # type: ignore[misc]
            request.method,
            request.path,
            client_ip,
        )
        return None

    @server.app.after_request
    def after_request(response: Response) -> Response:
        """Process responses and add security headers."""
        if hasattr(g, "request_id"):
            response.headers["X-Request-ID"] = str(g.request_id)  # type: ignore[misc]
        for header, value in server.config.security_headers.items():
            response.headers[header] = value
        if server.config.session_cookie_secure:
            response.headers["Strict-Transport-Security"] = HSTS_HEADER_VALUE

        if not request.path.startswith("/stream/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"

        if hasattr(g, "start_time") and server.performance_logger:
            duration = time.time() - g.start_time  # type: ignore[misc]
            server.performance_logger.log_request_duration(
                request.endpoint or request.path, duration, response.status_code  # type: ignore[misc]
            )

        return response

    @server.app.route("/health")
    def health_check() -> Response | tuple[Response, int]:
        """Health check endpoint for monitoring."""
        is_authenticated = check_authentication(server, establish_session=False)

        try:
            is_healthy = server.config.check_runtime_health()
        except (OSError, PermissionError, RuntimeError):
            is_healthy = False

        status = "healthy" if is_healthy else "unhealthy"
        status_code = 200 if is_healthy else 503

        if not is_authenticated:
            return jsonify({"status": status}), status_code  # type: ignore[misc]

        health_data = {  # type: ignore[misc]
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "uptime_seconds": round(
                time.time() - getattr(server, "_start_time", time.time()), 2  # type: ignore[misc]
            ),
            "video_directory_accessible": is_healthy,
            "config_valid": is_healthy,
            "rate_limiting_enabled": server.config.rate_limit_enabled,
        }

        return jsonify(health_data), status_code  # type: ignore[misc]

    @server.app.route("/logout", methods=["POST"])
    def logout() -> Response | tuple[Response, int]:
        """Logout endpoint that properly invalidates the session."""
        if not check_authentication(server):
            return auth_required_response(server)

        username: str = str(session.get("username", "unknown"))  # type: ignore[misc]
        client_ip = server.get_client_ip()

        if server.security_logger:
            server.security_logger.log_logout(
                username,
                client_ip,
                request.headers.get("User-Agent", ""),
            )
        server.app.logger.info(f"User '{username}' logged out from {client_ip}")

        session.clear()

        return Response(
            "Logged out successfully. Close browser to complete logout.",
            200,
            {
                "WWW-Authenticate": 'Basic realm="Video Streaming Server"',
                "Clear-Site-Data": '"cookies", "storage"',
            },
        )

    @server.app.route("/logout", methods=["GET"])
    def logout_get() -> tuple[str, int]:
        """Reject GET logout to prevent CSRF-forced logout."""
        return "Method Not Allowed - use POST to logout", 405

    @server.app.route("/")
    @server.app.route("/<path:subpath>")
    def index(subpath: str = "") -> str | tuple[str, int] | Response:
        """Handle directory listing and video playback pages."""
        return handle_index_request(server, subpath)

    def _stream_handler(video_path: str) -> Response | tuple[str, int]:
        """Stream video files with range support."""
        return handle_stream_request(server, video_path)

    if server.limiter is not None:
        _stream_handler = server.limiter.exempt(_stream_handler)

    server.app.route("/stream/<path:video_path>")(_stream_handler)

    @server.app.route("/api/files")
    def api_files() -> Response | tuple[Response, int]:
        """API endpoint for file listing."""
        return handle_api_files_request(server)
