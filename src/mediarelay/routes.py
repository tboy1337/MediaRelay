"""Flask route registration for MediaRelay."""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from flask import Response, abort, jsonify, request

from . import __version__
from .auth import auth_required_response, check_authentication
from .constants import HSTS_HEADER_VALUE, MAX_PATH_LENGTH, MAX_URL_LENGTH
from .handlers import (
    handle_api_files_request,
    handle_index_request,
    handle_stream_request,
)
from .logging_config import get_request_logger
from .session_store import (
    clear_session,
    get_csrf_token,
    get_request_id,
    get_session_username,
    get_start_time,
    has_request_timing,
    is_session_authenticated,
    set_length_violation,
    set_request_id,
    set_start_time,
    validate_csrf_token,
)

if TYPE_CHECKING:
    from .server import MediaRelayServer


def _should_send_csrf_token() -> bool:
    """Return True when the response should include a CSRF token header."""
    if request.path.startswith("/stream/"):
        return False
    if request.path == "/health":
        return False
    if request.path.startswith("/api/"):
        return False
    if request.path == "/logout":
        return False
    return True


def register_routes(server: MediaRelayServer) -> None:
    """Register all application routes and request middleware."""

    @server.app.before_request
    def before_request() -> tuple[str, int] | None:
        """Process requests before handling."""
        set_start_time(time.time())
        set_request_id(secrets.token_hex(8))
        client_ip = server.get_client_ip()

        full_url = request.url
        if len(full_url) > MAX_URL_LENGTH:
            set_length_violation(
                "url_too_long",
                f"URL length {len(full_url)} exceeds maximum {MAX_URL_LENGTH}",
            )
            abort(414)

        if len(request.path) > MAX_PATH_LENGTH:
            set_length_violation(
                "path_too_long",
                f"Path length {len(request.path)} exceeds maximum {MAX_PATH_LENGTH}",
            )
            abort(414)

        request_id = get_request_id()
        request_logger = get_request_logger("mediarelay.request")
        request_logger.debug(
            "request_id=%s method=%s path=%s client_ip=%s",
            request_id,
            request.method,
            request.path,
            client_ip,
        )
        return None

    @server.app.after_request
    def after_request(response: Response) -> Response:
        """Process responses and add security headers."""
        request_id = get_request_id()
        if request_id is not None:
            response.headers["X-Request-ID"] = request_id
        for header, value in server.config.security_headers.items():
            response.headers[header] = value
        if server.config.should_send_hsts():
            response.headers["Strict-Transport-Security"] = HSTS_HEADER_VALUE

        if is_session_authenticated() and _should_send_csrf_token():
            csrf_token = get_csrf_token()
            if csrf_token is not None:
                response.headers["X-CSRF-Token"] = csrf_token

        if request.path.startswith("/stream/"):
            response.headers["Cache-Control"] = "private, no-store"
            response.headers["Pragma"] = "no-cache"
        else:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"

        if has_request_timing() and server.performance_logger:
            if not request.path.startswith("/stream/"):
                start_time = get_start_time()
                if start_time is not None:
                    duration = time.time() - start_time
                    server.performance_logger.log_request_duration(
                        request.endpoint or request.path,
                        duration,
                        response.status_code,
                    )
                    request_logger = get_request_logger("mediarelay.request")
                    request_logger.debug(
                        "request_id=%s status=%s duration=%.4fs",
                        request_id,
                        response.status_code,
                        duration,
                    )

        return response

    def _health_handler() -> Response | tuple[Response, int]:
        """Health check endpoint for monitoring."""
        is_authenticated = check_authentication(
            server, establish_session=False, record_lockout=False
        )

        try:
            is_healthy = server.check_runtime_health()
        except (OSError, PermissionError, RuntimeError):
            is_healthy = False

        status = "healthy" if is_healthy else "unhealthy"
        status_code = 200 if is_healthy else 503

        if not is_authenticated:
            liveness_status = "ok" if is_healthy else "degraded"
            liveness_code = 200 if is_healthy else 503
            return jsonify({"status": liveness_status}), liveness_code  # type: ignore[misc]

        health_data = {  # type: ignore[misc]
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "uptime_seconds": round(server.uptime_seconds(), 2),
            "video_directory_accessible": is_healthy,
            "rate_limiting_enabled": server.config.rate_limit_enabled,
        }

        return jsonify(health_data), status_code  # type: ignore[misc]

    if server.limiter is not None:
        _health_handler = server.limiter.exempt(_health_handler)

    server.app.route("/health")(_health_handler)

    @server.app.route("/logout", methods=["POST"])
    def logout() -> Response | tuple[Response, int]:
        """Logout endpoint that properly invalidates the session."""
        if not check_authentication(server):
            return auth_required_response(server)

        csrf_value = request.headers.get("X-CSRF-Token") or request.form.get(
            "csrf_token"
        )
        if not validate_csrf_token(csrf_value):
            client_ip = server.get_client_ip()
            if server.security_logger:
                server.security_logger.log_security_violation(
                    "csrf_validation_failed",
                    "Logout rejected due to missing or invalid CSRF token",
                    client_ip,
                )
            return Response("CSRF validation failed", 403)

        username = get_session_username()
        client_ip = server.get_client_ip()

        if server.security_logger:
            server.security_logger.log_logout(
                username,
                client_ip,
                request.headers.get("User-Agent", ""),
            )
        server.app.logger.info(f"User '{username}' logged out from {client_ip}")

        clear_session()

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
        abort(405)

    @server.app.route("/")
    @server.app.route("/<path:subpath>")
    def index(subpath: str = "") -> str | tuple[str, int] | Response:
        """Handle directory listing and video playback pages."""
        return handle_index_request(server, subpath)

    def _stream_handler(video_path: str) -> Response | tuple[str, int]:
        """Stream video files with range support."""
        return handle_stream_request(server, video_path)

    if server.limiter is not None:
        stream_limit = f"{server.config.stream_rate_limit_per_minute} per minute"
        _stream_handler = server.limiter.limit(stream_limit)(_stream_handler)

    server.app.route("/stream/<path:video_path>")(_stream_handler)

    @server.app.route("/api/files")
    def api_files() -> Response | tuple[Response, int]:
        """API endpoint for file listing."""
        return handle_api_files_request(server)
