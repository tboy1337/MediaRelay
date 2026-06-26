"""Flask error handlers for MediaRelay."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flask import Response, request

from .auth import auth_required_response
from .constants import MAX_LOGGED_ERROR_LENGTH
from .session_store import get_length_violation

if TYPE_CHECKING:
    from .server import MediaRelayServer


def register_error_handlers(server: MediaRelayServer) -> None:
    """Register custom HTTP error handlers on the Flask application."""

    @server.app.errorhandler(400)  # type: ignore[misc]
    def bad_request(error: Exception) -> tuple[str, int]:
        """Handle bad request errors."""
        error_text = str(error)
        if len(error_text) > MAX_LOGGED_ERROR_LENGTH:
            error_text = f"{error_text[:MAX_LOGGED_ERROR_LENGTH]}...(truncated)"
        server.app.logger.warning(
            f"Bad request from {server.get_client_ip()}: {error_text}"
            f"{server._request_id_suffix()}"
        )
        return "Bad Request - Invalid parameters", 400

    @server.app.errorhandler(401)  # type: ignore[misc]
    def unauthorized(_error: Exception) -> Response:
        """Handle unauthorized access."""
        return auth_required_response(server)

    @server.app.errorhandler(403)  # type: ignore[misc]
    def forbidden(_error: Exception) -> tuple[str, int]:
        """Handle forbidden access."""
        if server.security_logger:
            server.security_logger.log_security_violation(
                "forbidden_access",
                f"Forbidden access attempt: {request.path}"
                f"{server._request_id_suffix()}",
                server.get_client_ip(),
            )
        return "Access Forbidden", 403

    @server.app.errorhandler(404)  # type: ignore[misc]
    def not_found(_error: Exception) -> tuple[str, int]:
        """Handle not found errors."""
        server.app.logger.warning(
            f"Resource not found: {request.path} from {server.get_client_ip()}"
            f"{server._request_id_suffix()}"
        )
        return "Resource Not Found", 404

    @server.app.errorhandler(405)  # type: ignore[misc]
    def method_not_allowed(_error: Exception) -> tuple[str, int]:
        """Handle method not allowed errors."""
        server.app.logger.warning(
            f"Method not allowed: {request.method} {request.path} from "
            f"{server.get_client_ip()}{server._request_id_suffix()}"
        )
        return "Method Not Allowed", 405

    @server.app.errorhandler(413)  # type: ignore[misc]
    def request_entity_too_large(_error: Exception) -> tuple[str, int]:
        """Handle file too large errors."""
        server.app.logger.warning(
            f"Request entity too large: {request.path} from "
            f"{server.get_client_ip()}{server._request_id_suffix()}"
        )
        return "File Too Large", 413

    @server.app.errorhandler(414)  # type: ignore[misc]
    def uri_too_long(_error: Exception) -> tuple[str, int]:
        """Handle request URI too long errors."""
        violation_type, violation_detail = get_length_violation()
        if server.security_logger:
            server.security_logger.log_security_violation(
                violation_type,
                f"{violation_detail}{server._request_id_suffix()}",
                server.get_client_ip(),
            )
        return "Request URI Too Long", 414

    @server.app.errorhandler(429)  # type: ignore[misc]
    def rate_limit_handler(error: Exception) -> Response:
        """Handle rate limit exceeded."""
        if server.security_logger:
            server.security_logger.log_rate_limit_exceeded(
                server.get_client_ip(),
                request.endpoint or request.path,
            )
        retry_after_attr = getattr(error, "retry_after", None)
        if retry_after_attr is not None:
            retry_after = str(max(1, int(retry_after_attr)))
        elif server.config.rate_limit_per_minute > 0:
            retry_after = str(max(1, 60))
        else:
            retry_after = "60"
        return Response(
            "Rate Limit Exceeded - Too Many Requests",
            429,
            {"Retry-After": retry_after},
        )

    @server.app.errorhandler(500)  # type: ignore[misc]
    def internal_error(error: Exception) -> tuple[str, int]:
        """Handle internal server errors."""
        server.app.logger.error(
            f"Server error: {str(error)}{server._request_id_suffix()}",
            exc_info=True,
        )
        return "Internal Server Error", 500
