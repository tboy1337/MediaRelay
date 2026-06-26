"""Account lockout tracking for failed authentication attempts."""

import threading
import time
from dataclasses import dataclass, field

from .constants import (
    DEFAULT_LOCKOUT_DURATION_SECONDS,
    DEFAULT_LOCKOUT_MAX_ATTEMPTS,
    MAX_LOCKOUT_TRACKERS,
)


@dataclass
class LoginAttemptTracker:
    """Track failed login attempts for account lockout."""

    failed_attempts: int = 0
    lockout_until: float = 0.0
    last_attempt: float = field(default_factory=time.time)


class AccountLockoutManager:
    """Thread-safe manager for tracking failed login attempts and account lockouts."""

    def __init__(
        self,
        max_attempts: int = DEFAULT_LOCKOUT_MAX_ATTEMPTS,
        lockout_duration: int = DEFAULT_LOCKOUT_DURATION_SECONDS,
    ) -> None:
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self._trackers: dict[str, LoginAttemptTracker] = {}
        self._lock = threading.Lock()

    def _get_key(self, ip_address: str, username: str) -> str:
        """Generate a unique key for tracking (combines IP and username)."""
        return f"{ip_address}:{username}"

    def is_locked_out(self, ip_address: str, username: str) -> bool:
        """Check if an IP/username combination is currently locked out."""
        key = self._get_key(ip_address, username)
        current_time = time.time()

        with self._lock:
            tracker = self._trackers.get(key)
            if tracker is None:
                return False

            if tracker.lockout_until > current_time:
                return True

            if tracker.lockout_until > 0 and tracker.lockout_until <= current_time:
                tracker.lockout_until = 0.0
                tracker.failed_attempts = 0

            return False

    def get_remaining_lockout_seconds(self, ip_address: str, username: str) -> int:
        """Get remaining lockout time in seconds."""
        key = self._get_key(ip_address, username)
        current_time = time.time()

        with self._lock:
            tracker = self._trackers.get(key)
            if tracker is None or tracker.lockout_until <= current_time:
                return 0
            return int(tracker.lockout_until - current_time)

    def _cleanup_expired_locked(self, current_time: float) -> int:
        """Remove expired lockout entries. Caller must hold ``_lock``."""
        keys_to_remove = [
            key
            for key, tracker in self._trackers.items()
            if (tracker.lockout_until > 0 and tracker.lockout_until <= current_time)
            or (
                tracker.lockout_until <= current_time
                and current_time - tracker.last_attempt > self.lockout_duration
            )
            or (
                tracker.failed_attempts == 0
                and tracker.lockout_until <= 0
                and current_time - tracker.last_attempt > self.lockout_duration
            )
        ]
        for key in keys_to_remove:
            del self._trackers[key]
        return len(keys_to_remove)

    def _evict_oldest_tracker_if_needed(self, current_time: float) -> bool:
        """Make room for a new tracker without evicting active lockouts.

        Returns True when a new tracker slot is available.
        """
        if len(self._trackers) < MAX_LOCKOUT_TRACKERS:
            return True

        self._cleanup_expired_locked(current_time)
        if len(self._trackers) < MAX_LOCKOUT_TRACKERS:
            return True

        inactive_keys = [
            key
            for key, tracker in self._trackers.items()
            if (tracker.lockout_until <= current_time and tracker.failed_attempts == 0)
        ]
        if not inactive_keys:
            return False

        oldest_key = min(
            inactive_keys,
            key=lambda tracker_key: self._trackers[tracker_key].last_attempt,
        )
        del self._trackers[oldest_key]
        return True

    def record_failed_attempt(
        self, ip_address: str, username: str
    ) -> tuple[bool, bool]:
        """Record a failed login attempt.

        Returns:
            A tuple of (now_locked, tracker_exhausted).
        """
        key = self._get_key(ip_address, username)
        current_time = time.time()

        with self._lock:
            if key not in self._trackers:
                if not self._evict_oldest_tracker_if_needed(current_time):
                    emergency = LoginAttemptTracker()
                    emergency.failed_attempts = self.max_attempts
                    emergency.lockout_until = current_time + self.lockout_duration
                    emergency.last_attempt = current_time
                    self._trackers[key] = emergency
                    return True, True
                self._trackers[key] = LoginAttemptTracker()

            tracker = self._trackers[key]

            if tracker.lockout_until > 0 and tracker.lockout_until <= current_time:
                tracker.lockout_until = 0.0
                tracker.failed_attempts = 0

            tracker.failed_attempts += 1
            tracker.last_attempt = current_time

            if tracker.failed_attempts >= self.max_attempts:
                tracker.lockout_until = current_time + self.lockout_duration
                return True, False

            return False, False

    def record_successful_login(self, ip_address: str, username: str) -> None:
        """Clear failed attempts on successful login."""
        key = self._get_key(ip_address, username)

        with self._lock:
            if key in self._trackers:
                del self._trackers[key]

    def get_failed_attempts(self, ip_address: str, username: str) -> int:
        """Get current failed attempt count."""
        key = self._get_key(ip_address, username)

        with self._lock:
            tracker = self._trackers.get(key)
            return tracker.failed_attempts if tracker else 0

    def cleanup_expired(self) -> int:
        """Remove expired lockout entries. Returns count removed."""
        current_time = time.time()

        with self._lock:
            return self._cleanup_expired_locked(current_time)
