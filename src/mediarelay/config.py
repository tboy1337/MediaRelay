"""
Configuration management for MediaRelay
---------------------------------------
Handles environment variables, configuration files, and default settings
for production deployment.
"""

import hashlib
import logging
import os
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click
from dotenv import load_dotenv

from .constants import (
    AUDIO_EXTENSIONS,
    DEFAULT_MAX_DIRECTORY_ENTRIES,
    DEFAULT_PAGE_SIZE,
    DEFAULT_STREAM_RATE_LIMIT_PER_MINUTE,
    MAX_CHANNEL_TIMEOUT,
    MAX_CLEANUP_INTERVAL,
    MAX_CONNECTION_LIMIT,
    MAX_DIRECTORY_ENTRIES,
    MAX_LOCKOUT_DURATION_SECONDS,
    MAX_LOCKOUT_MAX_ATTEMPTS,
    MAX_LOG_BACKUP_COUNT,
    MAX_LOG_MAX_BYTES,
    MAX_PAGE_SIZE,
    MAX_RATE_LIMIT_PER_MINUTE,
    MAX_SESSION_MAX_LIFETIME,
    MAX_SESSION_TIMEOUT,
    MAX_THREADS,
    MAX_USERNAME_LENGTH,
    MIN_PAGE_SIZE,
    MIN_PRODUCTION_SECRET_KEY_LENGTH,
    VIDEO_EXTENSIONS,
)

_DEFAULT_ALLOWED_EXTENSIONS: frozenset[str] = (
    VIDEO_EXTENSIONS | AUDIO_EXTENSIONS | frozenset({".srt"})
)

_PLACEHOLDER_SECRET_KEYS = frozenset(
    {"", "your-secret-key-here", "change-me", "changeme"}
)
_PLACEHOLDER_PASSWORD_HASHES = frozenset({"", "your-password-hash-here"})
_VALID_SAMESITE_VALUES = frozenset({"Strict", "Lax", "None"})
_VALID_LOG_LEVELS = frozenset(logging.getLevelNamesMapping().keys())
_VALID_PASSWORD_HASH_PREFIXES = ("scrypt:", "pbkdf2:", "argon2:")

_CONFIG_LOGGER = logging.getLogger(__name__)


def _get_default_video_directory() -> str:
    """Get default video directory, with fallback if home cannot be determined"""
    try:
        return str(Path.home() / "Videos")
    except (RuntimeError, OSError):
        return "./videos"


def _parse_int_env(
    name: str,
    default: str,
    *,
    min_val: int | None = None,
    max_val: int | None = None,
) -> int:
    """Parse an integer environment variable with validation."""
    raw = os.getenv(name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc

    if min_val is not None and value < min_val:
        raise ValueError(f"{name} must be at least {min_val}, got {value}")
    if max_val is not None and value > max_val:
        raise ValueError(f"{name} must be at most {max_val}, got {value}")
    return value


def _parse_bool_env(name: str, default: str) -> bool:
    """Parse a boolean environment variable."""
    return os.getenv(name, default).strip().lower() in ("true", "yes", "1", "on")


def _parse_samesite(value: str) -> str:
    """Validate SameSite cookie attribute value."""
    normalized = value.strip()
    lowered = normalized.lower()
    if lowered == "strict":
        normalized = "Strict"
    elif lowered == "lax":
        normalized = "Lax"
    elif lowered == "none":
        normalized = "None"

    if normalized not in _VALID_SAMESITE_VALUES:
        raise ValueError(
            f"VIDEO_SERVER_SESSION_COOKIE_SAMESITE must be one of "
            f"{sorted(_VALID_SAMESITE_VALUES)}, got {value!r}"
        )
    return normalized


def _validate_allowed_extensions(extensions: set[str]) -> None:
    """Reject extensions outside the built-in media allowlist."""
    invalid: list[str] = []
    for ext in extensions:
        if not ext.startswith(".") or ext != ext.lower():
            invalid.append(ext)
            continue
        body = ext[1:]
        if not body or not body.isalnum():
            invalid.append(ext)
            continue
        if ext not in _DEFAULT_ALLOWED_EXTENSIONS:
            invalid.append(ext)
    if invalid:
        raise ValueError(
            f"Invalid VIDEO_SERVER_ALLOWED_EXTENSIONS: {sorted(invalid)}. "
            f"Allowed values: {sorted(_DEFAULT_ALLOWED_EXTENSIONS)}"
        )


def _validate_log_level(log_level: str) -> None:
    """Reject invalid logging level names at configuration time."""
    if log_level.upper() not in _VALID_LOG_LEVELS:
        raise ValueError(
            f"VIDEO_SERVER_LOG_LEVEL must be one of "
            f"{sorted(_VALID_LOG_LEVELS)}, got {log_level!r}"
        )


def _validate_video_directory(video_directory: str) -> None:
    """Ensure the configured video directory exists and is readable."""
    video_path = Path(video_directory)
    if not video_path.exists():
        raise ValueError(f"Video directory does not exist: {video_directory}")
    if not video_path.is_dir():
        raise ValueError(f"Video directory path is not a directory: {video_directory}")
    if not os.access(video_path, os.R_OK):
        raise ValueError(f"Video directory is not readable: {video_directory}")


def _validate_log_directory(log_directory: str) -> None:
    """Ensure the log directory exists and is writable."""
    log_path = Path(log_directory)
    try:
        log_path.mkdir(parents=True, exist_ok=True)
        probe_file = log_path / ".write_probe"
        probe_file.write_text("", encoding="utf-8")
        probe_file.unlink()
    except OSError as exc:
        raise ValueError(f"Log directory is not writable: {log_directory}") from exc


def _validate_password_hash_format(password_hash: str) -> None:
    """Ensure the password hash uses a supported Werkzeug hash format."""
    normalized = password_hash.strip()
    if normalized.startswith("$2"):
        raise ValueError(
            "VIDEO_SERVER_PASSWORD_HASH uses bcrypt format, which is not supported. "
            "Run mediarelay-genpass to generate a Werkzeug scrypt hash."
        )
    if not any(
        normalized.startswith(prefix) for prefix in _VALID_PASSWORD_HASH_PREFIXES
    ):
        raise ValueError(
            "VIDEO_SERVER_PASSWORD_HASH must be a Werkzeug hash "
            "(scrypt:, pbkdf2:, or argon2:). "
            "Run mediarelay-genpass to create one."
        )


def _validate_credentials(config: "ServerConfig") -> None:
    """Validate username and password hash settings."""
    if not config.username.strip():
        raise ValueError("VIDEO_SERVER_USERNAME must not be empty or whitespace")

    if len(config.username) > MAX_USERNAME_LENGTH:
        raise ValueError(
            f"VIDEO_SERVER_USERNAME must be at most {MAX_USERNAME_LENGTH} "
            f"characters, got {len(config.username)}"
        )

    if not config.password_hash:
        raise ValueError(
            "VIDEO_SERVER_PASSWORD_HASH must be set. "
            "Run mediarelay-genpass to create one."
        )

    if config.is_production() and config.password_hash in _PLACEHOLDER_PASSWORD_HASHES:
        raise ValueError(
            "VIDEO_SERVER_PASSWORD_HASH must be set to a real hash, not a "
            "placeholder. Run mediarelay-genpass to create one."
        )

    _validate_password_hash_format(config.password_hash)


def _validate_server_settings(config: "ServerConfig") -> None:
    """Validate server port, threads, file limits, and extensions."""
    if not config.allowed_extensions:
        raise ValueError(
            "allowed_extensions cannot be empty. "
            "Unset VIDEO_SERVER_ALLOWED_EXTENSIONS to use defaults."
        )

    _validate_allowed_extensions(config.allowed_extensions)

    if config.max_file_size < 0:
        raise ValueError(
            f"max_file_size cannot be negative, got: {config.max_file_size}"
        )

    if not (1 <= config.port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got: {config.port}")

    if config.threads < 1:
        raise ValueError(f"Thread count must be at least 1, got: {config.threads}")

    _validate_log_level(config.log_level)


def _validate_session_settings(config: "ServerConfig") -> None:
    """Validate session cookie and timeout settings."""
    if config.session_max_lifetime < config.session_timeout:
        raise ValueError(
            "VIDEO_SERVER_SESSION_MAX_LIFETIME must be greater than or equal to "
            f"VIDEO_SERVER_SESSION_TIMEOUT ({config.session_timeout}), "
            f"got {config.session_max_lifetime}"
        )

    if config.session_cookie_samesite == "None" and not config.session_cookie_secure:
        raise ValueError(
            "VIDEO_SERVER_SESSION_COOKIE_SAMESITE=None requires "
            "VIDEO_SERVER_SESSION_COOKIE_SECURE=true"
        )


def _validate_production_settings(config: "ServerConfig") -> None:
    """Enforce production-only security requirements."""
    if not config.is_production():
        return

    if config.debug:
        raise ValueError(
            "Debug mode cannot be enabled in production. "
            "Set VIDEO_SERVER_DEBUG=false."
        )

    if not config.session_cookie_secure:
        raise ValueError(
            "VIDEO_SERVER_SESSION_COOKIE_SECURE must be true in production."
        )

    if not config.session_cookie_httponly:
        raise ValueError(
            "VIDEO_SERVER_SESSION_COOKIE_HTTPONLY must be true in production."
        )

    env_secret = os.getenv("VIDEO_SERVER_SECRET_KEY", "")
    if env_secret.strip() in _PLACEHOLDER_SECRET_KEYS:
        raise ValueError(
            "VIDEO_SERVER_SECRET_KEY must be set to a secure value in "
            "production. Run mediarelay-genpass to create one."
        )
    if os.getenv("VIDEO_SERVER_SECRET_KEY") is None:
        raise ValueError(
            "VIDEO_SERVER_SECRET_KEY must be set in production. "
            "Auto-generated keys do not persist across restarts. "
            "Run mediarelay-genpass to create one."
        )
    if len(env_secret.strip()) < MIN_PRODUCTION_SECRET_KEY_LENGTH:
        raise ValueError(
            f"VIDEO_SERVER_SECRET_KEY must be at least "
            f"{MIN_PRODUCTION_SECRET_KEY_LENGTH} characters in production."
        )

    if not config.rate_limit_enabled:
        raise ValueError("VIDEO_SERVER_RATE_LIMIT must be true in production.")


def _default_security_headers() -> dict[str, str]:
    """Return security headers applied to every response (HSTS added conditionally)."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Security-Policy": (
            "default-src 'self'; media-src 'self'; style-src 'self' 'unsafe-inline'"
        ),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        ),
        "X-Permitted-Cross-Domain-Policies": "none",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }


@dataclass
class ServerConfig:
    """Server configuration dataclass with environment variable support"""

    # Server Settings
    # nosec B104: Binding to 0.0.0.0 is intentional for a server that needs to be
    # accessible from other machines. Users should configure firewall rules appropriately.
    host: str = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_HOST", "0.0.0.0")  # nosec B104
    )
    port: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_PORT", "5000", min_val=1, max_val=65535
        )
    )
    debug: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_DEBUG", "false")
    )
    production: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_PRODUCTION", "false")
    )
    threads: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_THREADS", "6", min_val=1, max_val=MAX_THREADS
        )
    )

    # Waitress server tuning
    channel_timeout: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_CHANNEL_TIMEOUT",
            "300",
            min_val=1,
            max_val=MAX_CHANNEL_TIMEOUT,
        )
    )
    connection_limit: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_CONNECTION_LIMIT",
            "1000",
            min_val=1,
            max_val=MAX_CONNECTION_LIMIT,
        )
    )
    cleanup_interval: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_CLEANUP_INTERVAL",
            "30",
            min_val=1,
            max_val=MAX_CLEANUP_INTERVAL,
        )
    )
    page_size: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_PAGE_SIZE",
            str(DEFAULT_PAGE_SIZE),
            min_val=MIN_PAGE_SIZE,
            max_val=MAX_PAGE_SIZE,
        )
    )

    # Security Settings
    secret_key: str = field(
        default_factory=lambda: os.getenv(
            "VIDEO_SERVER_SECRET_KEY", secrets.token_hex(32)
        )
    )
    username: str = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_USERNAME", "tboy1337")
    )
    password_hash: str = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_PASSWORD_HASH", "")
    )
    session_timeout: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_SESSION_TIMEOUT",
            "3600",
            min_val=1,
            max_val=MAX_SESSION_TIMEOUT,
        )
    )
    session_max_lifetime: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_SESSION_MAX_LIFETIME",
            "86400",
            min_val=1,
            max_val=MAX_SESSION_MAX_LIFETIME,
        )
    )
    lockout_max_attempts: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS",
            "5",
            min_val=1,
            max_val=MAX_LOCKOUT_MAX_ATTEMPTS,
        )
    )
    lockout_duration: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_LOCKOUT_DURATION",
            "900",
            min_val=60,
            max_val=MAX_LOCKOUT_DURATION_SECONDS,
        )
    )

    # Directory Settings
    video_directory: str = field(
        default_factory=lambda: os.getenv(
            "VIDEO_SERVER_DIRECTORY", _get_default_video_directory()
        )
    )
    log_directory: str = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_LOG_DIR", "./logs")
    )

    # File Settings
    allowed_extensions: set[str] = field(
        default_factory=lambda: (
            {
                ext.strip().lower()
                for ext in os.getenv("VIDEO_SERVER_ALLOWED_EXTENSIONS", "").split(",")
                if ext.strip()
            }
            if os.getenv("VIDEO_SERVER_ALLOWED_EXTENSIONS") is not None
            else set(_DEFAULT_ALLOWED_EXTENSIONS)
        )
    )
    max_directory_entries: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_MAX_DIRECTORY_ENTRIES",
            str(DEFAULT_MAX_DIRECTORY_ENTRIES),
            min_val=1,
            max_val=MAX_DIRECTORY_ENTRIES,
        )
    )
    max_file_size: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_MAX_FILE_SIZE", "21474836480"
        )
    )

    # Logging Settings
    log_level: str = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_LOG_LEVEL", "INFO")
    )
    log_max_bytes: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_LOG_MAX_BYTES",
            "10485760",
            min_val=1,
            max_val=MAX_LOG_MAX_BYTES,
        )
    )
    log_backup_count: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_LOG_BACKUP_COUNT",
            "5",
            min_val=0,
            max_val=MAX_LOG_BACKUP_COUNT,
        )
    )
    log_console: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_LOG_CONSOLE", "true")
    )

    # Rate Limiting
    rate_limit_enabled: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_RATE_LIMIT", "true")
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_RATE_LIMIT_PER_MIN",
            "60",
            min_val=1,
            max_val=MAX_RATE_LIMIT_PER_MINUTE,
        )
    )
    stream_rate_limit_per_minute: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE",
            str(DEFAULT_STREAM_RATE_LIMIT_PER_MINUTE),
            min_val=1,
            max_val=MAX_RATE_LIMIT_PER_MINUTE,
        )
    )

    # Security Headers (HSTS applied separately when enabled)
    security_headers: dict[str, str] = field(default_factory=_default_security_headers)

    # Session Cookie Settings
    session_cookie_secure: bool = field(
        default_factory=lambda: _parse_bool_env(
            "VIDEO_SERVER_SESSION_COOKIE_SECURE", "true"
        )
    )
    session_cookie_httponly: bool = field(
        default_factory=lambda: _parse_bool_env(
            "VIDEO_SERVER_SESSION_COOKIE_HTTPONLY", "true"
        )
    )
    session_cookie_samesite: str = field(
        default_factory=lambda: _parse_samesite(
            os.getenv("VIDEO_SERVER_SESSION_COOKIE_SAMESITE", "Strict")
        )
    )

    # Reverse proxy (nginx) — trust X-Forwarded-* headers when enabled
    behind_proxy: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_BEHIND_PROXY", "false")
    )
    proxy_trusted: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_PROXY_TRUSTED", "false")
    )
    hsts_enabled: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_HSTS", "false")
    )

    def __post_init__(self) -> None:
        """Validate configuration after initialization"""
        self.validate_config()

    def validate_config(self) -> None:
        """Validate configuration settings"""
        _validate_video_directory(self.video_directory)
        _validate_credentials(self)
        _validate_server_settings(self)
        _validate_session_settings(self)
        _validate_production_settings(self)
        _validate_log_directory(self.log_directory)
        if self.is_production():
            _validate_deployment_settings(self)

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.production

    @property
    def credential_epoch(self) -> str:
        """Fingerprint of username and password hash for session invalidation."""
        payload = f"{self.username}:{self.password_hash}".encode()
        return hashlib.sha256(payload).hexdigest()

    def should_send_hsts(self) -> bool:
        """Return True when Strict-Transport-Security should be sent."""
        return self.hsts_enabled or self.behind_proxy

    def check_runtime_health(self) -> bool:
        """Verify runtime-critical paths are accessible (lightweight health check)."""
        try:
            video_path = Path(self.video_directory)
            return (
                video_path.exists()
                and video_path.is_dir()
                and os.access(video_path, os.R_OK)
            )
        except (OSError, PermissionError, RuntimeError):
            return False

    def to_dict(self) -> dict[str, Any]:  # type: ignore[explicit-any]
        """Convert config to dictionary (excluding sensitive data)"""
        return {
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "threads": self.threads,
            "channel_timeout": self.channel_timeout,
            "connection_limit": self.connection_limit,
            "cleanup_interval": self.cleanup_interval,
            "page_size": self.page_size,
            "username": self.username,
            "session_timeout": self.session_timeout,
            "session_max_lifetime": self.session_max_lifetime,
            "lockout_max_attempts": self.lockout_max_attempts,
            "lockout_duration": self.lockout_duration,
            "video_directory": self.video_directory,
            "log_directory": self.log_directory,
            "allowed_extensions": list(self.allowed_extensions),
            "max_directory_entries": self.max_directory_entries,
            "max_file_size": self.max_file_size,
            "log_level": self.log_level,
            "log_console": self.log_console,
            "rate_limit_enabled": self.rate_limit_enabled,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "stream_rate_limit_per_minute": self.stream_rate_limit_per_minute,
            "session_cookie_secure": self.session_cookie_secure,
            "session_cookie_httponly": self.session_cookie_httponly,
            "session_cookie_samesite": self.session_cookie_samesite,
            "behind_proxy": self.behind_proxy,
            "proxy_trusted": self.proxy_trusted,
            "hsts_enabled": self.hsts_enabled,
            "is_production": self.is_production(),
        }


_WINDOWS_WORLD_READABLE_PRINCIPALS: tuple[str, ...] = (
    "Everyone",
    r"BUILTIN\Users",
    r"NT AUTHORITY\Authenticated Users",
)


def _warn_windows_insecure_env_file_permissions(env_path: Path) -> None:
    """Warn when a .env file ACL may grant read access to broad principals."""
    icacls_exe = shutil.which("icacls")
    if icacls_exe is None:
        return

    try:
        result = (
            subprocess.run(  # nosec B603 - fixed icacls path; reads ACL metadata only
                [icacls_exe, str(env_path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        )
    except (OSError, subprocess.SubprocessError):
        return

    if result.returncode != 0:
        return

    for line in result.stdout.splitlines():
        upper_line = line.upper()
        if "(R)" not in upper_line:
            continue
        for principal in _WINDOWS_WORLD_READABLE_PRINCIPALS:
            if principal.upper() in upper_line:
                _CONFIG_LOGGER.warning(
                    ".env file %s may be readable by %s. "
                    "Restrict permissions (e.g. icacls %s /inheritance:r "
                    "/grant:r %%USERNAME%%:F).",
                    env_path,
                    principal,
                    env_path.name,
                )
                return


def _warn_insecure_env_file_permissions(env_path: Path) -> None:
    """Warn when a .env file may be readable by users other than the owner."""
    if os.name == "nt":
        _warn_windows_insecure_env_file_permissions(env_path)
        return

    try:
        mode = env_path.stat().st_mode
    except OSError:
        return

    if mode & (stat.S_IRGRP | stat.S_IROTH):
        _CONFIG_LOGGER.warning(
            ".env file %s is readable by group or others (mode %o). "
            "Restrict permissions (e.g. chmod 600).",
            env_path,
            mode & 0o777,
        )


def load_config(config_file: Path | None = None) -> ServerConfig:
    """Load configuration from environment variables and return ServerConfig instance."""
    if config_file is not None:
        if not config_file.exists():
            raise ValueError(f"Configuration file not found: {config_file}")
        _warn_insecure_env_file_permissions(config_file)
        load_dotenv(config_file, override=True)
    else:
        env_file = Path(".env")
        if env_file.exists():
            _warn_insecure_env_file_permissions(env_file)
            load_dotenv(env_file)

    return ServerConfig()


def _validate_deployment_settings(config: ServerConfig) -> None:
    """Additional production deployment checks beyond startup validation."""
    video_path = Path(config.video_directory)
    if os.access(video_path, os.W_OK):
        raise ValueError(
            f"Video directory must not be writable by the server process: "
            f"{config.video_directory}"
        )

    log_path = Path(config.log_directory)
    if not log_path.exists():
        raise ValueError(f"Log directory does not exist: {config.log_directory}")
    if not os.access(log_path, os.W_OK):
        raise ValueError(f"Log directory is not writable: {config.log_directory}")

    if config.host == "0.0.0.0" and not config.behind_proxy:
        _CONFIG_LOGGER.warning(
            "VIDEO_SERVER_HOST is 0.0.0.0 without VIDEO_SERVER_BEHIND_PROXY. "
            "Bind to 127.0.0.1 behind a reverse proxy or restrict access with "
            "firewall rules. Run mediarelay-validate after setting "
            "VIDEO_SERVER_PRODUCTION=true."
        )

    if config.behind_proxy and not config.proxy_trusted:
        raise ValueError(
            "VIDEO_SERVER_BEHIND_PROXY is enabled but VIDEO_SERVER_PROXY_TRUSTED "
            "is false. Set VIDEO_SERVER_PROXY_TRUSTED=true when MediaRelay is "
            "reachable exclusively through your trusted reverse proxy."
        )

    if config.max_file_size == 0:
        _CONFIG_LOGGER.warning(
            "VIDEO_SERVER_MAX_FILE_SIZE is 0 in production; streaming size "
            "limits are disabled. Run mediarelay-validate to review deployment "
            "settings."
        )


def validate_deployment_config(config_file: Path | None = None) -> ServerConfig:
    """Load and validate configuration for production deployment.

    Raises:
        ValueError: If configuration is invalid or uses placeholder credentials.
    """
    config = load_config(config_file)

    if not config.is_production():
        raise ValueError(
            "VIDEO_SERVER_PRODUCTION must be true for deployment validation. "
            "Set VIDEO_SERVER_PRODUCTION=true in your environment or .env file."
        )

    return config


def create_sample_env_file() -> None:
    """Create a sample .env file with default values"""
    sample_env = """# MediaRelay Configuration
# Copy this file to .env and modify the values as needed

# Server Settings
# Use 127.0.0.1 when behind a reverse proxy; 0.0.0.0 exposes all interfaces
VIDEO_SERVER_HOST=0.0.0.0
VIDEO_SERVER_PORT=5000
VIDEO_SERVER_DEBUG=false
VIDEO_SERVER_THREADS=6
VIDEO_SERVER_CHANNEL_TIMEOUT=300
VIDEO_SERVER_CONNECTION_LIMIT=1000
VIDEO_SERVER_CLEANUP_INTERVAL=30
VIDEO_SERVER_PAGE_SIZE=100

# Security Settings (REQUIRED — run mediarelay-genpass to generate real values)
VIDEO_SERVER_SECRET_KEY=your-secret-key-here
VIDEO_SERVER_USERNAME=tboy1337
VIDEO_SERVER_PASSWORD_HASH=your-password-hash-here
VIDEO_SERVER_SESSION_TIMEOUT=3600
VIDEO_SERVER_SESSION_MAX_LIFETIME=86400
VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS=5
VIDEO_SERVER_LOCKOUT_DURATION=900

# Session Cookie Settings
# Set SESSION_COOKIE_SECURE=false for local HTTP development without TLS
VIDEO_SERVER_SESSION_COOKIE_SECURE=true
VIDEO_SERVER_SESSION_COOKIE_HTTPONLY=true
VIDEO_SERVER_SESSION_COOKIE_SAMESITE=Strict

# Directory Settings
VIDEO_SERVER_DIRECTORY=/path/to/your/videos
VIDEO_SERVER_LOG_DIR=./logs

# File Settings
# Comma-separated extensions (leave unset for defaults: .mp4,.mkv,.avi,...)
# VIDEO_SERVER_ALLOWED_EXTENSIONS=.mp4,.mkv,.avi,.mov,.webm,.m4v,.flv,.srt,.mp3,.aac,.ogg,.wav
# Maximum directory entries per listing request (prevents memory exhaustion)
VIDEO_SERVER_MAX_DIRECTORY_ENTRIES=10000
# Maximum file size in bytes (21474836480 = 20GB, set to 0 to disable limit)
VIDEO_SERVER_MAX_FILE_SIZE=21474836480

# Logging Settings
VIDEO_SERVER_LOG_LEVEL=INFO
VIDEO_SERVER_LOG_MAX_BYTES=10485760
VIDEO_SERVER_LOG_BACKUP_COUNT=5
VIDEO_SERVER_LOG_CONSOLE=true

# Rate Limiting
VIDEO_SERVER_RATE_LIMIT=true
VIDEO_SERVER_RATE_LIMIT_PER_MIN=60
# Higher limit for /stream/ range requests (seeking during playback)
VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE=600

# Reverse Proxy — ONLY enable when behind a trusted reverse proxy (nginx, etc.)
# If enabled without a proxy, client IPs can be spoofed via X-Forwarded-For
VIDEO_SERVER_BEHIND_PROXY=false
# Set true only when MediaRelay is unreachable except through your trusted proxy
VIDEO_SERVER_PROXY_TRUSTED=false
# Send HSTS header when true (also sent automatically when BEHIND_PROXY is true)
VIDEO_SERVER_HSTS=false

# Environment (production enforces real credentials at startup)
VIDEO_SERVER_PRODUCTION=true
"""

    env_file = Path(".env.example")
    if env_file.exists():
        print(f"Sample environment file already exists: {env_file}")
        print("Delete or rename it manually to regenerate.")
        return

    with open(env_file, "w", encoding="utf-8") as f:
        f.write(sample_env)

    print(f"Sample environment file created: {env_file}")
    print("Copy this to .env and update the values for your deployment")


def main() -> None:
    """Console entry point for mediarelay-config."""
    create_sample_env_file()


@click.command()
@click.option("--config-file", "-c", help="Path to configuration file")
def validate_main(config_file: str | None) -> None:
    """Console entry point for mediarelay-validate."""
    try:
        env_path = Path(config_file) if config_file else None
        config = validate_deployment_config(env_path)
        print("Configuration is valid for deployment.")
        print(f"  Host: {config.host}:{config.port}")
        print(f"  Video directory: {config.video_directory}")
        print(f"  Production mode: {config.is_production()}")
        print(f"  Behind proxy: {config.behind_proxy}")
    except ValueError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
