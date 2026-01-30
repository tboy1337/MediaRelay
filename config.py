"""
Configuration management for Video Streaming Server
-------------------------------------------------
Handles environment variables, configuration files, and default settings
for production deployment.
"""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _get_default_video_directory() -> str:
    """Get default video directory, with fallback if home cannot be determined"""
    try:
        return str(Path.home() / "Videos")
    except (RuntimeError, OSError):
        # Fallback if home directory cannot be determined (e.g., in tests)
        return "./videos"


@dataclass
class ServerConfig:
    """Server configuration dataclass with environment variable support"""

    # Server Settings
    # nosec B104: Binding to 0.0.0.0 is intentional for a server that needs to be
    # accessible from other machines. Users should configure firewall rules appropriately.
    host: str = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_HOST", "0.0.0.0")
    )  # nosec B104
    port: int = field(
        default_factory=lambda: int(os.getenv("VIDEO_SERVER_PORT", "5000"))
    )
    debug: bool = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_DEBUG", "false").lower()
        in ("true", "yes", "1", "on")
    )
    threads: int = field(
        default_factory=lambda: int(os.getenv("VIDEO_SERVER_THREADS", "6"))
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
        default_factory=lambda: int(os.getenv("VIDEO_SERVER_SESSION_TIMEOUT", "3600"))
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
        default_factory=lambda: int(
            os.getenv("VIDEO_SERVER_MAX_FILE_SIZE", "21474836480")
        )
    )  # 20GB default

    # Logging Settings
    log_level: str = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_LOG_LEVEL", "INFO")
    )
    log_max_bytes: int = field(
        default_factory=lambda: int(os.getenv("VIDEO_SERVER_LOG_MAX_BYTES", "10485760"))
    )  # 10MB
    log_backup_count: int = field(
        default_factory=lambda: int(os.getenv("VIDEO_SERVER_LOG_BACKUP_COUNT", "5"))
    )

    # Rate Limiting
    rate_limit_enabled: bool = field(
        default_factory=lambda: os.getenv("VIDEO_SERVER_RATE_LIMIT", "true").lower()
        == "true"
    )
    rate_limit_per_minute: int = field(
        default_factory=lambda: int(os.getenv("VIDEO_SERVER_RATE_LIMIT_PER_MIN", "60"))
    )

    # Security Headers
    security_headers: dict[str, str] = field(
        default_factory=lambda: {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; media-src 'self'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
            "X-Permitted-Cross-Domain-Policies": "none",
        }
    )

    # Session Cookie Settings
    session_cookie_secure: bool = field(
        default_factory=lambda: os.getenv(
            "VIDEO_SERVER_SESSION_COOKIE_SECURE", "true"
        ).lower()
        == "true"
    )
    session_cookie_httponly: bool = field(
        default_factory=lambda: os.getenv(
            "VIDEO_SERVER_SESSION_COOKIE_HTTPONLY", "true"
        ).lower()
        == "true"
    )
    session_cookie_samesite: str = field(
        default_factory=lambda: os.getenv(
            "VIDEO_SERVER_SESSION_COOKIE_SAMESITE", "Strict"
        )
    )

    def __post_init__(self) -> None:
        """Validate configuration after initialization"""
        self.validate_config()

    def validate_config(self) -> None:
        """Validate configuration settings"""
        # Validate video directory
        video_path = Path(self.video_directory)
        if not video_path.exists():
            raise ValueError(f"Video directory does not exist: {self.video_directory}")
        if not video_path.is_dir():
            raise ValueError(
                f"Video directory path is not a directory: {self.video_directory}"
            )

        # Validate password hash
        if not self.password_hash:
            raise ValueError(
                "PASSWORD_HASH must be set. Run generate_password.py to create one."
            )

        # Validate port range
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got: {self.port}")

        # Validate thread count
        if self.threads < 1:
            raise ValueError(f"Thread count must be at least 1, got: {self.threads}")

        # Create log directory if it doesn't exist
        log_path = Path(self.log_directory)
        log_path.mkdir(parents=True, exist_ok=True)

    def get_database_url(self) -> str | None:
        """Get database URL if configured (for future use)"""
        return os.getenv("DATABASE_URL")

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return os.getenv("FLASK_ENV", "development") == "production"

    def to_dict(self) -> dict[str, Any]:  # type: ignore[explicit-any]
        """Convert config to dictionary (excluding sensitive data)"""
        config_dict = {
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "threads": self.threads,
            "username": self.username,
            "session_timeout": self.session_timeout,
            "video_directory": self.video_directory,
            "log_directory": self.log_directory,
            "allowed_extensions": list(self.allowed_extensions),
            "max_file_size": self.max_file_size,
            "log_level": self.log_level,
            "rate_limit_enabled": self.rate_limit_enabled,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "is_production": self.is_production(),
        }
        return config_dict


def load_config() -> ServerConfig:
    """Load configuration from environment variables and return ServerConfig instance"""
    # Try to load .env file if it exists
    try:
        from dotenv import load_dotenv

        env_file = Path(".env")
        if env_file.exists():
            load_dotenv(env_file)
    except ImportError:
        pass  # dotenv not available, continue without it

    return ServerConfig()


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

# Directory Settings
VIDEO_SERVER_DIRECTORY=/path/to/your/videos
VIDEO_SERVER_LOG_DIR=./logs

# File Settings
# Maximum file size in bytes (21474836480 = 20GB, set to 0 to disable limit)
VIDEO_SERVER_MAX_FILE_SIZE=21474836480

# Logging Settings
VIDEO_SERVER_LOG_LEVEL=INFO
VIDEO_SERVER_LOG_MAX_BYTES=10485760
VIDEO_SERVER_LOG_BACKUP_COUNT=5

# Rate Limiting
VIDEO_SERVER_RATE_LIMIT=true
VIDEO_SERVER_RATE_LIMIT_PER_MIN=60

# Environment
FLASK_ENV=production
"""

    env_file = Path(".env.example")
    with open(env_file, "w", encoding="utf-8") as f:
        f.write(sample_env)

    print(f"Sample environment file created: {env_file}")
    print("Copy this to .env and update the values for your deployment")


if __name__ == "__main__":
    # Create sample .env file when run directly
    create_sample_env_file()
