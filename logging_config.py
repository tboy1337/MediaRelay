"""
Advanced Logging Configuration for Video Streaming Server
--------------------------------------------------------
Provides comprehensive, production-ready logging with structured logging,
multiple handlers, and security event tracking.
"""

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import colorlog
import structlog

from config import ServerConfig


class SecurityEventLogger:
    """Specialized logger for security events and audit trails"""

    def __init__(self, config: ServerConfig):
        self.config = config
        self.logger = logging.getLogger("security")
        self.handlers: list[logging.Handler] = []  # Track handlers for cleanup
        self._setup_security_logger()

    def _setup_security_logger(self) -> None:
        """Set up dedicated security event logging"""
        # Create security log file handler
        security_log_file = Path(self.config.log_directory) / "security.log"
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file,
            maxBytes=self.config.log_max_bytes,
            backupCount=self.config.log_backup_count,
        )

        # Security events use JSON format for better parsing
        security_formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"event": %(message)s, "module": "%(name)s", "line": %(lineno)d}'
        )
        security_handler.setFormatter(security_formatter)

        self.logger.addHandler(security_handler)
        self.handlers.append(security_handler)  # Track for cleanup
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Don't propagate to root logger

    def log_auth_attempt(
        self, username: str, success: bool, ip_address: str, user_agent: str = ""
    ) -> None:
        """Log authentication attempts"""
        event_data = {
            "event_type": "authentication",
            "username": username,
            "success": success,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        level = logging.INFO if success else logging.WARNING
        self.logger.log(level, json.dumps(event_data))

    def log_file_access(
        self, file_path: str, ip_address: str, success: bool, user: str = ""
    ) -> None:
        """Log file access attempts"""
        event_data = {
            "event_type": "file_access",
            "file_path": file_path,
            "ip_address": ip_address,
            "success": success,
            "user": user,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        level = logging.INFO if success else logging.WARNING
        self.logger.log(level, json.dumps(event_data))

    def log_security_violation(
        self, violation_type: str, details: str, ip_address: str
    ) -> None:
        """Log security violations"""
        event_data = {
            "event_type": "security_violation",
            "violation_type": violation_type,
            "details": details,
            "ip_address": ip_address,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self.logger.error(json.dumps(event_data))

    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str) -> None:
        """Log rate limit violations"""
        event_data = {
            "event_type": "rate_limit_exceeded",
            "ip_address": ip_address,
            "endpoint": endpoint,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self.logger.warning(json.dumps(event_data))

    def cleanup(self) -> None:
        """Clean up logger resources"""
        for handler in self.handlers:
            handler.close()
            self.logger.removeHandler(handler)
        self.handlers.clear()


class PerformanceLogger:
    """Logger for performance metrics and monitoring"""

    def __init__(self, config: ServerConfig):
        self.config = config
        self.logger = logging.getLogger("performance")
        self.handlers: list[logging.Handler] = []  # Track handlers for cleanup
        self._setup_performance_logger()

    def _setup_performance_logger(self) -> None:
        """Set up performance metrics logging"""
        perf_log_file = Path(self.config.log_directory) / "performance.log"
        perf_handler = logging.handlers.RotatingFileHandler(
            perf_log_file,
            maxBytes=self.config.log_max_bytes,
            backupCount=self.config.log_backup_count,
        )

        perf_formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "metric": %(message)s}'
        )
        perf_handler.setFormatter(perf_formatter)

        self.logger.addHandler(perf_handler)
        self.handlers.append(perf_handler)  # Track for cleanup
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

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

        self.logger.info(json.dumps(metric_data))

    def log_file_serve_time(
        self, file_path: str, file_size: int, duration: float
    ) -> None:
        """Log file serving performance"""
        metric_data = {
            "type": "file_serve",
            "file_path": file_path,
            "file_size_bytes": file_size,
            "duration_ms": round(duration * 1000, 2),
            "throughput_mbps": (
                round((file_size / (1024 * 1024)) / duration, 2) if duration > 0 else 0
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self.logger.info(json.dumps(metric_data))

    def cleanup(self) -> None:
        """Clean up logger resources"""
        for handler in self.handlers:
            handler.close()
            self.logger.removeHandler(handler)
        self.handlers.clear()


def setup_logging(config: ServerConfig) -> dict[str, Any]:  # type: ignore[explicit-any]
    """
    Set up comprehensive logging system for the application

    Returns:
        Dict containing configured loggers and handlers
    """

    # Create logs directory
    log_dir = Path(config.log_directory)
    log_dir.mkdir(parents=True, exist_ok=True)

    # Configure structlog for structured logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,  # type: ignore[misc]
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Root logger configuration
    root_logger = logging.getLogger()
    try:
        log_level = getattr(logging, config.log_level.upper())  # type: ignore[misc]
        root_logger.setLevel(log_level)  # type: ignore[misc]
    except AttributeError:
        # Invalid log level, fall back to INFO
        root_logger.setLevel(logging.INFO)

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler with color support
    console_handler = colorlog.StreamHandler(sys.stdout)
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
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler for general application logs
    app_log_file = log_dir / "app.log"
    file_handler = logging.handlers.RotatingFileHandler(
        app_log_file, maxBytes=config.log_max_bytes, backupCount=config.log_backup_count
    )

    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(pathname)s:%(lineno)d]"
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Error-only handler for critical issues
    error_log_file = log_dir / "error.log"
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file,
        maxBytes=config.log_max_bytes,
        backupCount=config.log_backup_count,
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    root_logger.addHandler(error_handler)

    # Initialize specialized loggers
    security_logger = SecurityEventLogger(config)
    performance_logger = PerformanceLogger(config)

    # Flask request logging
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


def get_request_logger(name: str) -> logging.Logger:
    """Get a logger for request handling with proper configuration"""
    return logging.getLogger(f"request.{name}")


def log_system_info(config: ServerConfig) -> None:
    """Log system information for debugging and monitoring"""
    logger = logging.getLogger("system")

    import platform

    try:
        # Try to get disk usage for current directory instead of root
        import os

        import psutil

        current_dir = os.getcwd()

        system_info = {  # type: ignore[misc]
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_free_gb": round(psutil.disk_usage(current_dir).free / (1024**3), 2),
            "config": config.to_dict(),  # type: ignore[misc]
        }
    except ImportError:
        # Fallback without psutil
        system_info = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": "unknown",
            "memory_total_gb": "unknown",
            "disk_free_gb": "unknown",
            "config": config.to_dict(),  # type: ignore[misc]
        }

    logger.info(f"System Information: {json.dumps(system_info, indent=2)}")  # type: ignore[misc]


if __name__ == "__main__":
    # Test logging configuration
    from config import load_config

    config = load_config()
    logging_components = setup_logging(config)  # type: ignore[misc]

    # Test different log levels
    logging.debug("This is a debug message")
    logging.info("This is an info message")
    logging.warning("This is a warning message")
    logging.error("This is an error message")

    # Test security logger
    security_logger = logging_components["security_logger"]  # type: ignore[misc]
    security_logger.log_auth_attempt("testuser", True, "127.0.0.1", "Test Browser")  # type: ignore[misc]

    # Test performance logger
    perf_logger = logging_components["performance_logger"]  # type: ignore[misc]
    perf_logger.log_request_duration("/test", 0.250, 200)  # type: ignore[misc]

    print("Logging test completed. Check the logs directory for output files.")
