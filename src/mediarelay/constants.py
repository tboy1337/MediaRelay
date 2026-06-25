"""Shared security and server constants for MediaRelay."""

MAX_URL_LENGTH: int = 2048
MAX_PATH_LENGTH: int = 1024
DEFAULT_LOCKOUT_MAX_ATTEMPTS: int = 5
DEFAULT_LOCKOUT_DURATION_SECONDS: int = 900  # 15 minutes
LOCKOUT_CLEANUP_INTERVAL_SECONDS: int = 300  # 5 minutes
HSTS_HEADER_VALUE: str = "max-age=31536000; includeSubDomains"
