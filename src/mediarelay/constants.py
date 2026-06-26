"""Shared security and server constants for MediaRelay."""

MAX_URL_LENGTH: int = 2048
MAX_PATH_LENGTH: int = 1024
MAX_LOGGED_PATH_LENGTH: int = 256
MAX_LOGGED_USER_AGENT_LENGTH: int = 512
DEFAULT_LOCKOUT_MAX_ATTEMPTS: int = 5
DEFAULT_LOCKOUT_DURATION_SECONDS: int = 900  # 15 minutes
LOCKOUT_CLEANUP_INTERVAL_SECONDS: int = 300  # 5 minutes
HSTS_HEADER_VALUE: str = "max-age=31536000; includeSubDomains"
DEFAULT_PAGE_SIZE: int = 100
MAX_PAGE_SIZE: int = 500
MIN_PAGE_SIZE: int = 1
DEFAULT_MAX_DIRECTORY_ENTRIES: int = 10000
MAX_LOCKOUT_TRACKERS: int = 10000
DEFAULT_STREAM_RATE_LIMIT_PER_MINUTE: int = 600

# Upper bounds for numeric configuration (prevent accidental resource exhaustion)
MAX_THREADS: int = 256
MAX_CONNECTION_LIMIT: int = 100_000
MAX_CHANNEL_TIMEOUT: int = 86_400
MAX_CLEANUP_INTERVAL: int = 86_400
MAX_RATE_LIMIT_PER_MINUTE: int = 10_000
MAX_LOCKOUT_MAX_ATTEMPTS: int = 100
MAX_LOCKOUT_DURATION_SECONDS: int = 86_400
MAX_SESSION_TIMEOUT: int = 2_592_000  # 30 days
MAX_SESSION_MAX_LIFETIME: int = 2_592_000  # 30 days
MAX_DIRECTORY_ENTRIES: int = 1_000_000
MAX_LOG_MAX_BYTES: int = 1_073_741_824  # 1 GiB
MAX_LOG_BACKUP_COUNT: int = 100
MIN_PRODUCTION_SECRET_KEY_LENGTH: int = 32
MAX_USERNAME_LENGTH: int = 128

AUDIO_EXTENSIONS: frozenset[str] = frozenset({".mp3", ".aac", ".ogg", ".wav"})
VIDEO_EXTENSIONS: frozenset[str] = frozenset(
    {".mp4", ".mkv", ".avi", ".mov", ".webm", ".m4v", ".flv"}
)
