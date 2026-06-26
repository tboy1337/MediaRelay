"""
Advanced Logging Configuration for Video Streaming Server
--------------------------------------------------------
Provides comprehensive, production-ready logging with structured logging,
multiple handlers, and security event tracking.
"""

import json
import logging
import logging.handlers
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

import colorlog
import psutil

from .config import ServerConfig
from .constants import MAX_LOGGED_PATH_LENGTH
from .session_store import get_request_id


def _current_request_id() -> str | None:
    """Return the current Flask request ID when inside a request context."""
    return get_request_id()


class _JsonLineFormatter(logging.Formatter):
    """Emit log records whose message is already a JSON object string."""

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


_MAX_LOGGED_USERNAME_LENGTH = 64


def _truncate_logged_path(file_path: str) -> str:
    """Truncate attacker-controlled path strings before security logging."""
    if len(file_path) <= MAX_LOGGED_PATH_LENGTH:
        return file_path
    return f"{file_path[:MAX_LOGGED_PATH_LENGTH]}...(truncated)"


class SecurityEventLogger:
    """Specialized logger for security events and audit trails"""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.logger = logging.getLogger("security")
        self.handlers: list[logging.Handler] = []
        self._setup_security_logger()

    def _setup_security_logger(self) -> None:
        """Set up dedicated security event logging"""
        security_log_file = Path(self.config.log_directory) / "security.log"
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file,
            maxBytes=self.config.log_max_bytes,
            backupCount=self.config.log_backup_count,
        )
        security_handler.setFormatter(_JsonLineFormatter())
        self.logger.addHandler(security_handler)
        self.handlers.append(security_handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    def _build_event_data(self, event_data: dict[str, Any]) -> dict[str, Any]:  # type: ignore[explicit-any]
        """Attach request_id when available."""
        request_id = _current_request_id()
        if request_id is not None:
            event_data["request_id"] = request_id
        return event_data

    def _safe_emit(self, level: int, message: str) -> None:
        """Emit a security log record without breaking the request on I/O failure."""
        try:
            self.logger.log(level, message)
        except (OSError, PermissionError) as error:
            logging.getLogger("mediarelay").warning(
                "Security log write failed: %s", error
            )

    def log_auth_attempt(
        self, username: str, success: bool, ip_address: str, user_agent: str = ""
    ) -> None:
        """Log authentication attempts"""
        logged_username = username[:_MAX_LOGGED_USERNAME_LENGTH]
        event_data = self._build_event_data(
            {
                "event_type": "authentication",
                "username": logged_username,
                "success": success,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        level = logging.INFO if success else logging.WARNING
        self._safe_emit(level, json.dumps(event_data))

    def log_logout(self, username: str, ip_address: str, user_agent: str = "") -> None:
        """Log user logout events."""
        logged_username = username[:_MAX_LOGGED_USERNAME_LENGTH]
        event_data = self._build_event_data(
            {
                "event_type": "logout",
                "username": logged_username,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        self._safe_emit(logging.INFO, json.dumps(event_data))

    def log_file_access(
        self, file_path: str, ip_address: str, success: bool, user: str = ""
    ) -> None:
        """Log file access attempts"""
        event_data = self._build_event_data(
            {
                "event_type": "file_access",
                "file_path": _truncate_logged_path(file_path),
                "ip_address": ip_address,
                "success": success,
                "user": user,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        level = logging.INFO if success else logging.WARNING
        self._safe_emit(level, json.dumps(event_data))

    def log_security_violation(
        self, violation_type: str, details: str, ip_address: str
    ) -> None:
        """Log security violations"""
        event_data = self._build_event_data(
            {
                "event_type": "security_violation",
                "violation_type": violation_type,
                "details": details,
                "ip_address": ip_address,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        self._safe_emit(logging.ERROR, json.dumps(event_data))

    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str) -> None:
        """Log rate limit violations"""
        event_data = self._build_event_data(
            {
                "event_type": "rate_limit_exceeded",
                "ip_address": ip_address,
                "endpoint": endpoint,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        self._safe_emit(logging.WARNING, json.dumps(event_data))

    def cleanup(self) -> None:
        """Clean up logger resources"""
        for handler in self.handlers:
            handler.close()
            self.logger.removeHandler(handler)
        self.handlers.clear()


class PerformanceLogger:
    """Logger for performance metrics and monitoring"""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.logger = logging.getLogger("performance")
        self.handlers: list[logging.Handler] = []
        self._setup_performance_logger()

    def _setup_performance_logger(self) -> None:
        """Set up performance metrics logging"""
        perf_log_file = Path(self.config.log_directory) / "performance.log"
        perf_handler = logging.handlers.RotatingFileHandler(
            perf_log_file,
            maxBytes=self.config.log_max_bytes,
            backupCount=self.config.log_backup_count,
        )
        perf_handler.setFormatter(_JsonLineFormatter())
        self.logger.addHandler(perf_handler)
        self.handlers.append(perf_handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    def _safe_emit(self, level: int, message: str) -> None:
        """Emit a performance log record without breaking the request on I/O failure."""
        try:
            self.logger.log(level, message)
        except (OSError, PermissionError) as error:
            logging.getLogger("mediarelay").warning(
                "Performance log write failed: %s", error
            )

    def log_request_duration(
        self, endpoint: str, duration: float, status_code: int
    ) -> None:
        """Log request duration metrics"""
        metric_data = {
            "type": "request_duration",
            "endpoint": endpoint,
            "duration_ms": round(duration * 1000, 2),
            "status_code": status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self._safe_emit(logging.INFO, json.dumps(metric_data))

    def log_file_serve_time(
        self, file_path: str, file_size: int, duration: float
    ) -> None:
        """Log file serving performance"""
        metric_data = {
            "type": "file_serve",
            "file_path": _truncate_logged_path(file_path),
            "file_size_bytes": file_size,
            "duration_ms": round(duration * 1000, 2),
            "throughput_mbps": (
                round((file_size / (1024 * 1024)) / duration, 2) if duration > 0 else 0
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self._safe_emit(logging.INFO, json.dumps(metric_data))

    def cleanup(self) -> None:
        """Clean up logger resources"""
        for handler in self.handlers:
            handler.close()
            self.logger.removeHandler(handler)
        self.handlers.clear()


class LoggingComponents(TypedDict):
    """Return type for setup_logging."""

    root_logger: logging.Logger
    security_logger: SecurityEventLogger
    performance_logger: PerformanceLogger
    console_handler: logging.Handler | None
    file_handler: logging.Handler
    error_handler: logging.Handler


def setup_logging(config: ServerConfig) -> LoggingComponents:
    """
    Set up comprehensive logging system for the application

    Returns:
        Dict containing configured loggers and handlers
    """

    log_dir = Path(config.log_directory)
    log_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    try:
        log_level = getattr(logging, config.log_level.upper())  # type: ignore[misc]
        root_logger.setLevel(log_level)  # type: ignore[misc]
    except AttributeError:
        logging.getLogger("mediarelay").warning(
            "Invalid VIDEO_SERVER_LOG_LEVEL %r; falling back to INFO",
            config.log_level,
        )
        root_logger.setLevel(logging.INFO)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    console_handler: logging.Handler | None = None
    if config.log_console:
        stream_handler = colorlog.StreamHandler(sys.stdout)
        console_formatter = colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "red,bg_white",
            },
        )
        stream_handler.setFormatter(console_formatter)
        console_handler = stream_handler
        root_logger.addHandler(console_handler)

    app_log_file = log_dir / "app.log"
    file_handler = logging.handlers.RotatingFileHandler(
        app_log_file, maxBytes=config.log_max_bytes, backupCount=config.log_backup_count
    )

    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(pathname)s:%(lineno)d]"
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    error_log_file = log_dir / "error.log"
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file,
        maxBytes=config.log_max_bytes,
        backupCount=config.log_backup_count,
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    root_logger.addHandler(error_handler)

    security_logger = SecurityEventLogger(config)
    performance_logger = PerformanceLogger(config)

    flask_logger = logging.getLogger("werkzeug")
    flask_logger.setLevel(logging.WARNING if config.is_production() else logging.INFO)

    logging.info(f"Logging system initialized. Log directory: {log_dir}")
    logging.info(f"Log level: {config.log_level}")
    logging.info(f"Production mode: {config.is_production()}")

    return {
        "root_logger": root_logger,
        "security_logger": security_logger,
        "performance_logger": performance_logger,
        "console_handler": console_handler,
        "file_handler": file_handler,
        "error_handler": error_handler,
    }


def cleanup_logging(components: LoggingComponents) -> None:
    """Close and remove all logging handlers created by setup_logging."""
    security_logger = components.get("security_logger")
    if isinstance(security_logger, SecurityEventLogger):
        security_logger.cleanup()

    performance_logger = components.get("performance_logger")
    if isinstance(performance_logger, PerformanceLogger):
        performance_logger.cleanup()

    root_logger = components.get("root_logger")
    if isinstance(root_logger, logging.Logger):
        for handler in list(root_logger.handlers):
            handler.close()
            root_logger.removeHandler(handler)


def get_request_logger(name: str) -> logging.Logger:
    """Get a logger for request handling with proper configuration"""
    return logging.getLogger(f"request.{name}")


def _collect_system_info(config: ServerConfig) -> dict[str, Any]:  # type: ignore[explicit-any]
    """Build system information dictionary for startup logging."""
    current_dir = os.getcwd()
    try:
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_free_gb": round(psutil.disk_usage(current_dir).free / (1024**3), 2),
            "config": config.to_dict(),  # type: ignore[misc]
        }
    except (ImportError, OSError):
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": "unknown",
            "memory_total_gb": "unknown",
            "disk_free_gb": "unknown",
            "config": config.to_dict(),  # type: ignore[misc]
        }


def log_system_info(config: ServerConfig) -> None:
    """Log system information for debugging and monitoring"""
    logger = logging.getLogger("system")
    system_info = _collect_system_info(config)  # type: ignore[misc]
    logger.info(
        "System Information: %s",
        json.dumps(system_info, indent=2),  # type: ignore[misc]
    )


if __name__ == "__main__":
    from .config import load_config

    config = load_config()
    logging_components = setup_logging(config)

    logging.debug("This is a debug message")
    logging.info("This is an info message")
    logging.warning("This is a warning message")
    logging.error("This is an error message")

    security_logger = logging_components["security_logger"]
    security_logger.log_auth_attempt("testuser", True, "127.0.0.1", "Test Browser")

    perf_logger = logging_components["performance_logger"]
    perf_logger.log_request_duration("/test", 0.250, 200)

    print("Logging test completed. Check the logs directory for output files.")
