"""Flask error handlers for MediaRelay."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flask import Response, request

from .auth import auth_required_response

if TYPE_CHECKING:
    from .server import MediaRelayServer


def register_error_handlers(server: MediaRelayServer) -> None:
    """Register custom HTTP error handlers on the Flask application."""

    @server.app.errorhandler(400)  # type: ignore[misc]
    def bad_request(error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
        """Handle bad request errors."""
        server.app.logger.warning(
            f"Bad request from {server.get_client_ip()}: {error}"  # type: ignore[misc]
            f"{server._request_id_suffix()}"
        )
        return "Bad Request - Invalid parameters", 400

    @server.app.errorhandler(401)  # type: ignore[misc]
    def unauthorized(_error: Any) -> Response:  # type: ignore[misc, explicit-any]
        """Handle unauthorized access."""
        return auth_required_response(server)

    @server.app.errorhandler(403)  # type: ignore[misc]
    def forbidden(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
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
    def not_found(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
        """Handle not found errors."""
        server.app.logger.warning(
            f"Resource not found: {request.path} from {server.get_client_ip()}"
            f"{server._request_id_suffix()}"
        )
        return "Resource Not Found", 404

    @server.app.errorhandler(413)  # type: ignore[misc]
    def request_entity_too_large(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
        """Handle file too large errors."""
        return "File Too Large", 413

    @server.app.errorhandler(429)  # type: ignore[misc]
    def rate_limit_handler(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
        """Handle rate limit exceeded."""
        if server.security_logger:
            server.security_logger.log_rate_limit_exceeded(
                server.get_client_ip(),
                request.endpoint or request.path,
            )
        return "Rate Limit Exceeded - Too Many Requests", 429

    @server.app.errorhandler(500)  # type: ignore[misc]
    def internal_error(error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
        """Handle internal server errors."""
        server.app.logger.error(
            f"Server error: {str(error)}{server._request_id_suffix()}",
            exc_info=True,
        )  # type: ignore[misc]
        return "Internal Server Error", 500
