"""MediaRelay server core: Flask app, authentication, routing, and Waitress runtime."""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from flask import Flask, Response, g, jsonify, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from waitress import serve
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

from . import __version__
from .config import ServerConfig, create_sample_env_file, load_config
from .constants import (
    HSTS_HEADER_VALUE,
    LOCKOUT_CLEANUP_INTERVAL_SECONDS,
    MAX_PATH_LENGTH,
    MAX_URL_LENGTH,
)
from .handlers import (
    handle_api_files_request,
    handle_index_request,
    handle_stream_request,
)
from .lockout import AccountLockoutManager
from .logging_config import (
    LoggingComponents,
    PerformanceLogger,
    SecurityEventLogger,
    cleanup_logging,
    log_system_info,
    setup_logging,
)
from .path_utils import get_breadcrumbs, get_safe_path


class MediaRelayServer:
    """Main video streaming server class with comprehensive features."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.app = self._create_app()
        self.security_logger: SecurityEventLogger | None = None
        self.performance_logger: PerformanceLogger | None = None
        self.limiter: Limiter | None = None
        self.lockout_manager = AccountLockoutManager(
            max_attempts=config.lockout_max_attempts,
            lockout_duration=config.lockout_duration,
        )
        self._lockout_cleanup_timer: threading.Timer | None = None
        self._logging_components: LoggingComponents | None = None
        self._setup_logging()
        self._warn_ephemeral_secret_key()
        self._warn_behind_proxy()
        self._setup_rate_limiting()
        self._register_routes()
        self._register_error_handlers()

    def _warn_ephemeral_secret_key(self) -> None:
        """Warn when the secret key is auto-generated instead of set in the environment."""
        if os.getenv("VIDEO_SERVER_SECRET_KEY") is None:
            self.app.logger.warning(
                "VIDEO_SERVER_SECRET_KEY not set in environment; using auto-generated "
                "key. Sessions will not persist across restarts."
            )

    def _warn_behind_proxy(self) -> None:
        """Warn when reverse-proxy mode is enabled without a trusted proxy in front."""
        if self.config.behind_proxy:
            self.app.logger.warning(
                "VIDEO_SERVER_BEHIND_PROXY is enabled: client IP and rate limits use "
                "X-Forwarded-For. Only enable this when MediaRelay is behind a "
                "trusted reverse proxy. Direct exposure allows IP spoofing."
            )

    def _start_lockout_cleanup(self) -> None:
        """Schedule periodic cleanup of expired lockout tracker entries."""

        def _run_cleanup() -> None:
            self.lockout_manager.cleanup_expired()
            self._lockout_cleanup_timer = threading.Timer(
                LOCKOUT_CLEANUP_INTERVAL_SECONDS, _run_cleanup
            )
            self._lockout_cleanup_timer.daemon = True
            self._lockout_cleanup_timer.start()

        self._lockout_cleanup_timer = threading.Timer(
            LOCKOUT_CLEANUP_INTERVAL_SECONDS, _run_cleanup
        )
        self._lockout_cleanup_timer.daemon = True
        self._lockout_cleanup_timer.start()

    def _stop_lockout_cleanup(self) -> None:
        """Cancel the periodic lockout cleanup timer."""
        if self._lockout_cleanup_timer is not None:
            self._lockout_cleanup_timer.cancel()
            self._lockout_cleanup_timer = None

    def get_client_ip(self) -> str:
        """Return the client IP, honoring reverse-proxy headers when configured."""
        if self.config.behind_proxy and request.access_route:
            return request.access_route[0]
        return request.remote_addr or "unknown"

    def _rate_limit_key(self) -> str:
        """Rate limiter key function respecting reverse-proxy configuration."""
        if self.config.behind_proxy and request.access_route:
            return request.access_route[0]
        return get_remote_address()

    def auth_required_response(self) -> Response:
        """Build a 401 response, including Retry-After when the account is locked out."""
        headers = {"WWW-Authenticate": 'Basic realm="Video Streaming Server"'}
        auth = request.authorization
        if auth and auth.username:
            client_ip = self.get_client_ip()
            if self.lockout_manager.is_locked_out(client_ip, auth.username):
                remaining = self.lockout_manager.get_remaining_lockout_seconds(
                    client_ip, auth.username
                )
                headers["Retry-After"] = str(max(1, int(remaining)))
        return Response("Authentication Required", 401, headers)

    def _create_app(self) -> Flask:
        """Create and configure Flask application."""
        app = Flask(__name__)
        app.secret_key = self.config.secret_key
        app.config["MAX_CONTENT_LENGTH"] = (
            None if self.config.max_file_size <= 0 else self.config.max_file_size
        )
        app.config["SESSION_COOKIE_SECURE"] = self.config.session_cookie_secure
        app.config["SESSION_COOKIE_HTTPONLY"] = self.config.session_cookie_httponly
        app.config["SESSION_COOKIE_SAMESITE"] = self.config.session_cookie_samesite
        app.config["PERMANENT_SESSION_LIFETIME"] = self.config.session_timeout
        app.config["DEBUG"] = self.config.debug

        if self.config.behind_proxy:
            app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
                app.wsgi_app,
                x_for=1,
                x_proto=1,
                x_host=1,
            )

        return app

    def _setup_logging(self) -> None:
        """Initialize logging system."""
        components = setup_logging(self.config)
        self._logging_components = components
        self.security_logger = components["security_logger"]
        self.performance_logger = components["performance_logger"]
        log_system_info(self.config)

    def _shutdown_cleanup(self) -> None:
        """Release background resources and flush log handlers on shutdown."""
        self._stop_lockout_cleanup()
        if self._logging_components is not None:
            cleanup_logging(self._logging_components)
            self._logging_components = None
        logging.shutdown()

    def _setup_rate_limiting(self) -> None:
        """Configure rate limiting."""
        if self.config.rate_limit_enabled:
            server = self

            def rate_limit_key() -> str:
                return server._rate_limit_key()

            self.limiter = Limiter(
                app=self.app,
                key_func=rate_limit_key,
                default_limits=[f"{self.config.rate_limit_per_minute} per minute"],
            )
        else:
            self.limiter = None

    def _register_routes(self) -> None:
        """Register all application routes."""

        @self.app.before_request
        def before_request() -> tuple[str, int] | None:
            """Process requests before handling."""
            g.start_time = time.time()
            g.request_id = secrets.token_hex(8)
            client_ip = self.get_client_ip()

            full_url = request.url
            if len(full_url) > MAX_URL_LENGTH:
                if self.security_logger:
                    self.security_logger.log_security_violation(
                        "url_too_long",
                        f"URL length {len(full_url)} exceeds maximum {MAX_URL_LENGTH}",
                        client_ip,
                    )
                return "Request URI Too Long", 414

            if len(request.path) > MAX_PATH_LENGTH:
                if self.security_logger:
                    self.security_logger.log_security_violation(
                        "path_too_long",
                        f"Path length {len(request.path)} exceeds maximum {MAX_PATH_LENGTH}",
                        client_ip,
                    )
                return "Request URI Too Long", 414

            self.app.logger.debug(
                f"Request {g.request_id}: {request.method} {request.path} "  # type: ignore[misc]
                f"from {client_ip}"
            )
            return None

        @self.app.after_request
        def after_request(response: Response) -> Response:
            """Process responses and add security headers."""
            for header, value in self.config.security_headers.items():
                response.headers[header] = value
            if self.config.session_cookie_secure:
                response.headers["Strict-Transport-Security"] = HSTS_HEADER_VALUE

            if hasattr(g, "start_time") and self.performance_logger:
                duration = time.time() - g.start_time  # type: ignore[misc]
                self.performance_logger.log_request_duration(
                    request.endpoint or request.path, duration, response.status_code  # type: ignore[misc]
                )

            return response

        @self.app.route("/health")
        def health_check() -> Response | tuple[Response, int]:
            """Health check endpoint for monitoring."""
            is_authenticated = self.check_authentication()

            try:
                test_path = Path(self.config.video_directory)
                is_healthy = test_path.exists() and os.access(test_path, os.R_OK)
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
                    time.time() - getattr(self, "_start_time", time.time()), 2  # type: ignore[misc]
                ),
                "video_directory_accessible": is_healthy,
                "config_valid": True,
                "rate_limiting_enabled": self.config.rate_limit_enabled,
            }

            return jsonify(health_data), status_code  # type: ignore[misc]

        logout_methods: list[str] = ["GET", "POST"]

        @self.app.route("/logout", methods=logout_methods)
        def logout() -> Response | tuple[Response, int]:
            """Logout endpoint that properly invalidates the session."""
            if not self.check_authentication():
                return self.auth_required_response()

            username: str = str(session.get("username", "unknown"))  # type: ignore[misc]
            client_ip = self.get_client_ip()

            if self.security_logger:
                self.security_logger.log_auth_attempt(
                    username,
                    True,
                    client_ip,
                    request.headers.get("User-Agent", ""),
                )
            self.app.logger.info(f"User '{username}' logged out from {client_ip}")

            session.clear()

            return Response(
                "Logged out successfully. Close browser to complete logout.",
                200,
                {
                    "WWW-Authenticate": 'Basic realm="Video Streaming Server"',
                    "Clear-Site-Data": '"cookies", "storage"',
                },
            )

        @self.app.route("/")
        @self.app.route("/<path:subpath>")
        def index(subpath: str = "") -> str | tuple[str, int] | Response:
            """Handle directory listing and video playback pages."""
            return handle_index_request(self, subpath)

        @self.app.route("/stream/<path:video_path>")
        def stream(video_path: str) -> Response | tuple[str, int]:
            """Stream video files with range support."""
            return handle_stream_request(self, video_path)

        @self.app.route("/api/files")
        def api_files() -> Response | tuple[Response, int]:
            """API endpoint for file listing."""
            return handle_api_files_request(self)

    def _register_error_handlers(self) -> None:
        """Register custom error handlers."""

        @self.app.errorhandler(400)  # type: ignore[misc]
        def bad_request(error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle bad request errors."""
            self.app.logger.warning(
                f"Bad request from {self.get_client_ip()}: {error}"  # type: ignore[misc]
            )
            return "Bad Request - Invalid parameters", 400

        @self.app.errorhandler(401)  # type: ignore[misc]
        def unauthorized(_error: Any) -> tuple[Response, int]:  # type: ignore[misc, explicit-any]
            """Handle unauthorized access."""
            return (self.auth_required_response(), 401)

        @self.app.errorhandler(403)  # type: ignore[misc]
        def forbidden(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle forbidden access."""
            if self.security_logger:
                self.security_logger.log_security_violation(
                    "forbidden_access",
                    f"Forbidden access attempt: {request.path}",
                    self.get_client_ip(),
                )
            return "Access Forbidden", 403

        @self.app.errorhandler(404)  # type: ignore[misc]
        def not_found(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle not found errors."""
            return "Resource Not Found", 404

        @self.app.errorhandler(413)  # type: ignore[misc]
        def request_entity_too_large(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle file too large errors."""
            return "File Too Large", 413

        @self.app.errorhandler(429)  # type: ignore[misc]
        def rate_limit_handler(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle rate limit exceeded."""
            if self.security_logger:
                self.security_logger.log_rate_limit_exceeded(
                    self.get_client_ip(),
                    request.endpoint or request.path,
                )
            return "Rate Limit Exceeded - Too Many Requests", 429

        @self.app.errorhandler(500)  # type: ignore[misc]
        def internal_error(error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle internal server errors."""
            self.app.logger.error(f"Server error: {str(error)}", exc_info=True)  # type: ignore[misc]
            return "Internal Server Error", 500

    def check_auth(self, username: str | None, password: str | None) -> bool:
        """Verify username and password with lockout protection."""
        ip_address = self.get_client_ip()
        user_agent = request.headers.get("User-Agent", "")

        if not username or not password:
            if self.security_logger:
                self.security_logger.log_auth_attempt(
                    username or "empty",
                    False,
                    ip_address,
                    user_agent,
                )
            return False

        if self.lockout_manager.is_locked_out(ip_address, username):
            remaining = self.lockout_manager.get_remaining_lockout_seconds(
                ip_address, username
            )
            if self.security_logger:
                self.security_logger.log_security_violation(
                    "account_lockout",
                    f"Login attempt while locked out for user '{username}' "
                    f"({remaining}s remaining)",
                    ip_address,
                )
            return False

        valid = hmac.compare_digest(
            username, self.config.username
        ) and check_password_hash(self.config.password_hash, password)

        if self.security_logger:
            self.security_logger.log_auth_attempt(
                username,
                valid,
                ip_address,
                user_agent,
            )

        if valid:
            self.lockout_manager.record_successful_login(ip_address, username)
        else:
            now_locked = self.lockout_manager.record_failed_attempt(
                ip_address, username
            )
            if now_locked and self.security_logger:
                self.security_logger.log_security_violation(
                    "account_locked",
                    f"Account locked out after {self.config.lockout_max_attempts} "
                    f"failed attempts for user '{username}'",
                    ip_address,
                )

        return valid

    def get_safe_path(self, requested_path: str | None) -> Path | None:
        """Ensure the requested path is within the video directory."""
        path_value = "" if requested_path is None else requested_path
        return get_safe_path(
            self.config,
            path_value,
            client_ip=self.get_client_ip(),
            security_logger=self.security_logger,
            log_error=self.app.logger.error,
        )

    def get_breadcrumbs(self, path: Path) -> list[dict[str, str]]:
        """Generate breadcrumb navigation."""
        return get_breadcrumbs(self.config, path)

    def check_authentication(self) -> bool:
        """Check if the current request is authenticated with lockout protection."""
        current_time = time.time()
        if session.get("authenticated"):  # type: ignore[misc]
            last_activity = session.get("last_activity", 0)  # type: ignore[misc]
            if current_time - last_activity <= self.config.session_timeout:  # type: ignore[misc]
                login_ip = session.get("login_ip")  # type: ignore[misc]
                client_ip = self.get_client_ip()
                if login_ip and login_ip != client_ip:
                    if self.security_logger:
                        self.security_logger.log_security_violation(
                            "session_ip_mismatch",
                            (
                                f"Session invalidated due to IP change from "
                                f"{login_ip} to {client_ip}"
                            ),
                            client_ip,
                        )
                    session.clear()
                    return False
                session["last_activity"] = current_time
                return True

            session.clear()

        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return False

        ip_address = self.get_client_ip()

        if self.lockout_manager.is_locked_out(ip_address, auth.username):
            return False

        if self.check_auth(auth.username, auth.password):
            session.clear()
            session["authenticated"] = True
            session["username"] = auth.username
            session["last_activity"] = current_time
            session["login_time"] = current_time
            session["login_ip"] = self.get_client_ip()
            session.permanent = True
            return True

        return False

    def run(self) -> None:
        """Start the production server."""
        self._start_time = time.time()
        self._start_lockout_cleanup()

        video_dir = Path(self.config.video_directory)
        if not video_dir.exists():
            self.app.logger.error(
                f"Video directory does not exist: {self.config.video_directory}"
            )
            raise ValueError(f"Directory {self.config.video_directory} does not exist!")

        self.app.logger.info("Starting server with configuration:")
        self.app.logger.info(f"  Video directory: {self.config.video_directory}")
        self.app.logger.info(f"  Host: {self.config.host}")
        self.app.logger.info(f"  Port: {self.config.port}")
        self.app.logger.info(f"  Threads: {self.config.threads}")
        self.app.logger.info(f"  Production mode: {self.config.is_production()}")
        self.app.logger.info(f"  Rate limiting: {self.config.rate_limit_enabled}")

        print("MediaRelay starting...")
        print(f"Server running on http://{self.config.host}:{self.config.port}")
        print(f"Video directory: {self.config.video_directory}")
        print("Press Ctrl+C to stop the server")

        def _request_shutdown(signum: int, _frame: object) -> None:
            self.app.logger.info("Shutdown signal received: %s", signum)
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, _request_shutdown)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _request_shutdown)

        try:
            serve(
                self.app,
                host=self.config.host,
                port=self.config.port,
                threads=self.config.threads,
                cleanup_interval=30,
                channel_timeout=300,
                connection_limit=1000,
            )
        except KeyboardInterrupt:
            self.app.logger.info("Server shutdown requested")
            print("\nServer stopped")
        except Exception as error:
            self.app.logger.error(f"Server error: {str(error)}", exc_info=True)
            raise
        finally:
            self._shutdown_cleanup()


@click.command()
@click.option("--config-file", "-c", help="Path to configuration file")
@click.option("--host", "-h", help="Host to bind to (overrides config)")
@click.option("--port", "-p", type=int, help="Port to bind to (overrides config)")
@click.option("--debug", "-d", is_flag=True, help="Enable debug mode")
@click.option(
    "--generate-config", is_flag=True, help="Generate sample configuration file"
)
def main(
    config_file: str | None,
    host: str | None,
    port: int | None,
    debug: bool,
    generate_config: bool,
) -> None:
    """Enhanced Video Streaming Server - Production Ready."""
    if generate_config:
        create_sample_env_file()
        return

    try:
        env_path = Path(config_file) if config_file else None
        config = load_config(env_path)

        if host:
            config.host = host
        if port:
            config.port = port
        if debug:
            if config.is_production():
                raise ValueError(
                    "Cannot enable --debug when FLASK_ENV=production. "
                    "Debug mode must not be used in production."
                )
            config.debug = True

        server = MediaRelayServer(config)
        if debug:
            server.app.config["DEBUG"] = True
        server.run()

    except ValueError as error:
        print(f"Configuration Error: {error}")
        print("\nTips:")
        print("1. Run 'mediarelay-genpass' to create a password hash")
        print("2. Set VIDEO_SERVER_PASSWORD_HASH environment variable")
        print("3. Ensure video directory exists and is accessible")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except (RuntimeError, OSError, ImportError) as error:
        print(f"Server Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
