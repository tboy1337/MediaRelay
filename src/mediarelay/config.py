"""
Configuration management for Video Streaming Server
-------------------------------------------------
Handles environment variables, configuration files, and default settings
for production deployment.
"""

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click

_PLACEHOLDER_SECRET_KEYS = frozenset(
    {"", "your-secret-key-here", "change-me", "changeme"}
)
_PLACEHOLDER_PASSWORD_HASHES = frozenset({"", "your-password-hash-here"})
_VALID_SAMESITE_VALUES = frozenset({"Strict", "Lax", "None"})


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
    return os.getenv(name, default).lower() in ("true", "yes", "1", "on")


def _parse_samesite(value: str) -> str:
    """Validate SameSite cookie attribute value."""
    if value not in _VALID_SAMESITE_VALUES:
        raise ValueError(
            f"VIDEO_SERVER_SESSION_COOKIE_SAMESITE must be one of "
            f"{sorted(_VALID_SAMESITE_VALUES)}, got {value!r}"
        )
    return value


def _default_security_headers() -> dict[str, str]:
    """Return security headers applied to every response (HSTS added conditionally)."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": (
            "default-src 'self'; media-src 'self'; style-src 'self' 'unsafe-inline'"
        ),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        ),
        "X-Permitted-Cross-Domain-Policies": "none",
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
    threads: int = field(
        default_factory=lambda: _parse_int_env("VIDEO_SERVER_THREADS", "6", min_val=1)
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
            "VIDEO_SERVER_SESSION_TIMEOUT", "3600", min_val=1
        )
    )
    lockout_max_attempts: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS", "5", min_val=1
        )
    )
    lockout_duration: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_LOCKOUT_DURATION", "900", min_val=60
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
            set(
                ext.strip()
                for ext in os.getenv("VIDEO_SERVER_ALLOWED_EXTENSIONS", "").split(",")
                if ext.strip()
            )
            if os.getenv("VIDEO_SERVER_ALLOWED_EXTENSIONS") is not None
            else {
                ".mp4",
                ".mkv",
                ".avi",
                ".mov",
                ".webm",
                ".m4v",
                ".flv",
                ".srt",
                ".mp3",
                ".aac",
                ".ogg",
                ".wav",
            }
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
            "VIDEO_SERVER_LOG_MAX_BYTES", "10485760", min_val=1
        )
    )
    log_backup_count: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_LOG_BACKUP_COUNT", "5", min_val=0
        )
    )

    # Rate Limiting
    rate_limit_enabled: bool = field(
        default_factory=lambda: _parse_bool_env("VIDEO_SERVER_RATE_LIMIT", "true")
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: _parse_int_env(
            "VIDEO_SERVER_RATE_LIMIT_PER_MIN", "60", min_val=1
        )
    )

    # Security Headers (HSTS applied separately when session_cookie_secure is True)
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

    def __post_init__(self) -> None:
        """Validate configuration after initialization"""
        self.validate_config()

    def validate_config(self) -> None:
        """Validate configuration settings"""
        video_path = Path(self.video_directory)
        if not video_path.exists():
            raise ValueError(f"Video directory does not exist: {self.video_directory}")
        if not video_path.is_dir():
            raise ValueError(
                f"Video directory path is not a directory: {self.video_directory}"
            )

        if not self.password_hash:
            raise ValueError(
                "VIDEO_SERVER_PASSWORD_HASH must be set. "
                "Run mediarelay-genpass to create one."
            )

        if self.is_production() and self.password_hash in _PLACEHOLDER_PASSWORD_HASHES:
            raise ValueError(
                "VIDEO_SERVER_PASSWORD_HASH must be set to a real hash, not a "
                "placeholder. Run mediarelay-genpass to create one."
            )

        if not (1 <= self.port <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got: {self.port}")

        if self.threads < 1:
            raise ValueError(f"Thread count must be at least 1, got: {self.threads}")

        if self.is_production():
            env_secret = os.getenv("VIDEO_SERVER_SECRET_KEY", "")
            if env_secret.strip() in _PLACEHOLDER_SECRET_KEYS:
                raise ValueError(
                    "VIDEO_SERVER_SECRET_KEY must be set to a secure value in "
                    "production. Run mediarelay-genpass to create one."
                )

        log_path = Path(self.log_directory)
        log_path.mkdir(parents=True, exist_ok=True)

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return os.getenv("FLASK_ENV", "development") == "production"

    def to_dict(self) -> dict[str, Any]:  # type: ignore[explicit-any]
        """Convert config to dictionary (excluding sensitive data)"""
        return {
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "threads": self.threads,
            "username": self.username,
            "session_timeout": self.session_timeout,
            "lockout_max_attempts": self.lockout_max_attempts,
            "lockout_duration": self.lockout_duration,
            "video_directory": self.video_directory,
            "log_directory": self.log_directory,
            "allowed_extensions": list(self.allowed_extensions),
            "max_file_size": self.max_file_size,
            "log_level": self.log_level,
            "rate_limit_enabled": self.rate_limit_enabled,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "session_cookie_secure": self.session_cookie_secure,
            "session_cookie_httponly": self.session_cookie_httponly,
            "session_cookie_samesite": self.session_cookie_samesite,
            "behind_proxy": self.behind_proxy,
            "is_production": self.is_production(),
        }


def load_config(config_file: Path | None = None) -> ServerConfig:
    """Load configuration from environment variables and return ServerConfig instance."""
    try:
        from dotenv import load_dotenv

        if config_file is not None:
            if not config_file.exists():
                raise ValueError(f"Configuration file not found: {config_file}")
            load_dotenv(config_file, override=True)
        else:
            env_file = Path(".env")
            if env_file.exists():
                load_dotenv(env_file)
    except ImportError:
        if config_file is not None:
            raise ValueError(
                "python-dotenv is required to load a configuration file"
            ) from None

    return ServerConfig()


def validate_deployment_config(config_file: Path | None = None) -> ServerConfig:
    """Load and validate configuration for production deployment.

    Raises:
        ValueError: If configuration is invalid or uses placeholder credentials.
    """
    config = load_config(config_file)

    if config.password_hash in _PLACEHOLDER_PASSWORD_HASHES:
        raise ValueError(
            "VIDEO_SERVER_PASSWORD_HASH must be set to a real hash, not a "
            "placeholder. Run mediarelay-genpass to create one."
        )

    return config


def create_sample_env_file() -> None:
    """Create a sample .env file with default values"""
    sample_env = """# Video Streaming Server Configuration
# Copy this file to .env and modify the values as needed

# Server Settings
VIDEO_SERVER_HOST=0.0.0.0
VIDEO_SERVER_PORT=5000
VIDEO_SERVER_DEBUG=false
VIDEO_SERVER_THREADS=6

# Security Settings (REQUIRED)
VIDEO_SERVER_SECRET_KEY=your-secret-key-here
VIDEO_SERVER_USERNAME=tboy1337
VIDEO_SERVER_PASSWORD_HASH=your-password-hash-here
VIDEO_SERVER_SESSION_TIMEOUT=3600
VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS=5
VIDEO_SERVER_LOCKOUT_DURATION=900

# Session Cookie Settings
VIDEO_SERVER_SESSION_COOKIE_SECURE=true
VIDEO_SERVER_SESSION_COOKIE_HTTPONLY=true
VIDEO_SERVER_SESSION_COOKIE_SAMESITE=Strict

# Directory Settings
VIDEO_SERVER_DIRECTORY=/path/to/your/videos
VIDEO_SERVER_LOG_DIR=./logs

# File Settings
# Comma-separated extensions (leave unset for defaults: .mp4,.mkv,.avi,...)
# VIDEO_SERVER_ALLOWED_EXTENSIONS=.mp4,.mkv,.avi,.mov,.webm,.m4v,.flv,.srt,.mp3,.aac,.ogg,.wav
# Maximum file size in bytes (21474836480 = 20GB, set to 0 to disable limit)
VIDEO_SERVER_MAX_FILE_SIZE=21474836480

# Logging Settings
VIDEO_SERVER_LOG_LEVEL=INFO
VIDEO_SERVER_LOG_MAX_BYTES=10485760
VIDEO_SERVER_LOG_BACKUP_COUNT=5

# Rate Limiting
VIDEO_SERVER_RATE_LIMIT=true
VIDEO_SERVER_RATE_LIMIT_PER_MIN=60

# Reverse Proxy (set true when behind nginx or similar)
VIDEO_SERVER_BEHIND_PROXY=false

# Environment
FLASK_ENV=production
"""

    env_file = Path(".env.example")
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
