"""MediaRelay server core: Flask app orchestration and Waitress runtime."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

import click
from flask import Flask, Response, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from waitress import serve
from werkzeug.middleware.proxy_fix import ProxyFix

from .auth import auth_required_response as _auth_required_response
from .auth import check_auth as _check_auth
from .auth import check_authentication as _check_authentication
from .config import ServerConfig, create_sample_env_file, load_config
from .constants import LOCKOUT_CLEANUP_INTERVAL_SECONDS
from .error_handlers import register_error_handlers
from .lockout import AccountLockoutManager
from .logging_config import (
    LoggingComponents,
    PerformanceLogger,
    SecurityEventLogger,
    cleanup_logging,
    log_system_info,
    setup_logging,
)
from .path_utils import InodeLinkIndex, get_breadcrumbs, get_safe_path
from .routes import register_routes
from .session_store import get_request_id


def _client_address_from_request(behind_proxy: bool, proxy_trusted: bool) -> str:
    """Return the client IP, honoring reverse-proxy headers when trusted."""
    if behind_proxy and proxy_trusted and request.access_route:
        return request.access_route[0]
    return request.remote_addr or "unknown"


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
            username_lockout_enabled=config.username_lockout_enabled,
        )
        self._lockout_cleanup_timer: threading.Timer | None = None
        self._logging_components: LoggingComponents | None = None
        self._start_time: float = time.time()
        self.inode_link_index = InodeLinkIndex(Path(config.video_directory))
        self.inode_index_ready = False
        self._setup_logging()
        self._initialize_inode_index()
        self._warn_ephemeral_secret_key()
        self._warn_legacy_flask_env()
        self._warn_behind_proxy()
        self._warn_non_production()
        self._setup_rate_limiting()
        register_routes(self)
        register_error_handlers(self)

    def _initialize_inode_index(self) -> None:
        """Build the inode link index synchronously at startup."""
        try:
            self.inode_link_index.refresh(force=True)
            self.inode_index_ready = True
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.inode_index_ready = False
            self.app.logger.warning(
                "Inode index initial build failed: %s", error, exc_info=True
            )
            if self.config.is_production():
                raise RuntimeError(
                    "Inode hardlink index failed to build in production mode. "
                    "Verify the video directory is readable and run "
                    "'mediarelay-validate' before starting the server."
                ) from error

    def check_runtime_health(self) -> bool:
        """Verify runtime-critical paths and inode index are ready."""
        if not self.config.check_runtime_health():
            return False
        return self.inode_index_ready

    def _warn_ephemeral_secret_key(self) -> None:
        """Warn when the secret key is auto-generated instead of set in the environment."""
        if os.getenv("VIDEO_SERVER_SECRET_KEY") is None:
            self.app.logger.warning(
                "VIDEO_SERVER_SECRET_KEY not set in environment; using auto-generated "
                "key. Sessions will not persist across restarts."
            )

    def _warn_behind_proxy(self) -> None:
        """Warn when reverse-proxy mode is enabled without a trusted proxy in front."""
        if self.config.behind_proxy and not self.config.proxy_trusted:
            self.app.logger.warning(
                "VIDEO_SERVER_BEHIND_PROXY is enabled but VIDEO_SERVER_PROXY_TRUSTED "
                "is false: client IP and rate limits use the direct connection "
                "address, not X-Forwarded-For. Set VIDEO_SERVER_PROXY_TRUSTED=true "
                "only when MediaRelay is behind a trusted reverse proxy."
            )
        elif self.config.behind_proxy:
            self.app.logger.info(
                "VIDEO_SERVER_BEHIND_PROXY and VIDEO_SERVER_PROXY_TRUSTED are enabled."
            )

    def _warn_legacy_flask_env(self) -> None:
        """Warn when the deprecated FLASK_ENV variable is still set."""
        if os.getenv("FLASK_ENV") is not None:
            self.app.logger.warning(
                "FLASK_ENV is deprecated and ignored. Set VIDEO_SERVER_PRODUCTION=true "
                "for production credential and cookie checks."
            )

    def _warn_non_production(self) -> None:
        """Warn when production-only validation rules are not active."""
        if not self.config.is_production():
            self.app.logger.warning(
                "VIDEO_SERVER_PRODUCTION is not enabled; production credential and "
                "cookie checks are disabled. Set VIDEO_SERVER_PRODUCTION=true before "
                "going live."
            )

    def _schedule_next_lockout_cleanup(self) -> None:
        """Schedule the next lockout tracker cleanup run."""
        self._lockout_cleanup_timer = threading.Timer(
            LOCKOUT_CLEANUP_INTERVAL_SECONDS, self._run_lockout_cleanup
        )
        self._lockout_cleanup_timer.daemon = True
        self._lockout_cleanup_timer.start()

    def _run_lockout_cleanup(self) -> None:
        """Run lockout cleanup and reschedule; survives individual cleanup failures."""
        try:
            self.lockout_manager.cleanup_expired()
            self.inode_link_index.refresh()
        except Exception as error:  # pylint: disable=broad-exception-caught
            # Timer must keep firing even if a single cleanup pass fails.
            self.app.logger.error("Lockout cleanup failed: %s", error, exc_info=True)
        self._schedule_next_lockout_cleanup()

    def _start_lockout_cleanup(self) -> None:
        """Schedule periodic cleanup of expired lockout tracker entries."""
        self._schedule_next_lockout_cleanup()

    def _stop_lockout_cleanup(self) -> None:
        """Cancel the periodic lockout cleanup timer."""
        if self._lockout_cleanup_timer is not None:
            self._lockout_cleanup_timer.cancel()
            self._lockout_cleanup_timer = None

    def get_client_ip(self) -> str:
        """Return the client IP, honoring reverse-proxy headers when trusted."""
        return _client_address_from_request(
            self.config.behind_proxy, self.config.proxy_trusted
        )

    def uptime_seconds(self) -> float:
        """Return elapsed seconds since the server process started."""
        return time.time() - self._start_time

    def _rate_limit_key(self) -> str:
        """Rate limiter key function respecting reverse-proxy configuration."""
        if self.config.behind_proxy and self.config.proxy_trusted:
            return _client_address_from_request(True, True)
        return get_remote_address()

    def auth_required_response(self) -> Response:
        """Build a 401 response, including Retry-After when the account is locked out."""
        return _auth_required_response(self)

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

        if self.config.behind_proxy and self.config.proxy_trusted:
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

    def _request_id_suffix(self) -> str:
        """Return a log suffix with the current request ID when available."""
        request_id = get_request_id()
        return f" [request_id={request_id}]" if request_id else ""

    def check_auth(self, username: str | None, password: str | None) -> bool:
        """Verify username and password with lockout protection."""
        return _check_auth(self, username, password)

    def get_safe_path(self, requested_path: str | None) -> Path | None:
        """Ensure the requested path is within the video directory."""
        path_value = "" if requested_path is None else requested_path
        return get_safe_path(
            self.config,
            path_value,
            client_ip=self.get_client_ip(),
            security_logger=self.security_logger,
            log_error=self.app.logger.error,
            inode_index=self.inode_link_index,
        )

    def get_breadcrumbs(self, path: Path) -> list[dict[str, str]]:
        """Generate breadcrumb navigation."""
        return get_breadcrumbs(self.config, path)

    def check_authentication(
        self, *, establish_session: bool = True, record_lockout: bool = True
    ) -> bool:
        """Check if the current request is authenticated with lockout protection."""
        return _check_authentication(
            self, establish_session=establish_session, record_lockout=record_lockout
        )

    def run(self) -> None:
        """Start the production server."""
        self._start_time = time.time()
        self._start_lockout_cleanup()

        self.app.logger.info("Starting server with configuration:")
        self.app.logger.info(f"  Video directory: {self.config.video_directory}")
        self.app.logger.info(f"  Host: {self.config.host}")
        self.app.logger.info(f"  Port: {self.config.port}")
        self.app.logger.info(f"  Threads: {self.config.threads}")
        self.app.logger.info(f"  Production mode: {self.config.is_production()}")
        self.app.logger.info(f"  Rate limiting: {self.config.rate_limit_enabled}")

        self.app.logger.info("Starting MediaRelay server")
        self.app.logger.info(
            "Server running on http://%s:%s", self.config.host, self.config.port
        )
        self.app.logger.info("Press Ctrl+C to stop the server")

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
                cleanup_interval=self.config.cleanup_interval,
                channel_timeout=self.config.channel_timeout,
                connection_limit=self.config.connection_limit,
            )
        except KeyboardInterrupt:
            self.app.logger.info("Server shutdown requested")
            self.app.logger.info("Server stopped")
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.app.logger.error(f"Server error: {str(error)}", exc_info=True)
            raise
        finally:
            self.app.logger.info("Running shutdown cleanup")
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
        if port is not None:
            config.port = port
        if debug:
            if config.is_production():
                raise ValueError(
                    "Cannot enable --debug when VIDEO_SERVER_PRODUCTION=true. "
                    "Debug mode must not be used in production."
                )
            config.debug = True

        config.validate_config()

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
    except (RuntimeError, OSError, ImportError, PermissionError) as error:
        print(f"Server Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
