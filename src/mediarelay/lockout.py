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
        *,
        username_lockout_enabled: bool = True,
    ) -> None:
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.username_lockout_enabled = username_lockout_enabled
        self._trackers: dict[str, LoginAttemptTracker] = {}
        self._username_trackers: dict[str, LoginAttemptTracker] = {}
        self._lock = threading.Lock()

    def _get_key(self, ip_address: str, username: str) -> str:
        """Generate a unique key for tracking (combines IP and username)."""
        return f"{ip_address}:{username}"

    @staticmethod
    def _is_tracker_locked(
        tracker: LoginAttemptTracker | None, current_time: float
    ) -> bool:
        """Return True when a tracker is actively locked out."""
        if tracker is None:
            return False

        if tracker.lockout_until > current_time:
            return True

        if tracker.lockout_until > 0 and tracker.lockout_until <= current_time:
            tracker.lockout_until = 0.0
            tracker.failed_attempts = 0

        return False

    @staticmethod
    def _remaining_lockout_seconds(
        tracker: LoginAttemptTracker | None, current_time: float
    ) -> int:
        """Return remaining lockout seconds for a tracker."""
        if tracker is None or tracker.lockout_until <= current_time:
            return 0
        return int(tracker.lockout_until - current_time)

    def is_locked_out(self, ip_address: str, username: str) -> bool:
        """Check if an IP/username combination is currently locked out."""
        key = self._get_key(ip_address, username)
        current_time = time.time()

        with self._lock:
            if self._is_tracker_locked(self._trackers.get(key), current_time):
                return True
            if self.username_lockout_enabled:
                return self._is_tracker_locked(
                    self._username_trackers.get(username), current_time
                )
            return False

    def get_remaining_lockout_seconds(self, ip_address: str, username: str) -> int:
        """Get remaining lockout time in seconds."""
        key = self._get_key(ip_address, username)
        current_time = time.time()

        with self._lock:
            ip_remaining = self._remaining_lockout_seconds(
                self._trackers.get(key), current_time
            )
            if not self.username_lockout_enabled:
                return ip_remaining
            username_remaining = self._remaining_lockout_seconds(
                self._username_trackers.get(username), current_time
            )
            return max(ip_remaining, username_remaining)

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

        username_keys_to_remove = [
            key
            for key, tracker in self._username_trackers.items()
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
        for key in username_keys_to_remove:
            del self._username_trackers[key]

        return len(keys_to_remove) + len(username_keys_to_remove)

    def _evict_oldest_tracker_if_needed(
        self,
        trackers: dict[str, LoginAttemptTracker],
        current_time: float,
    ) -> bool:
        """Make room for a new tracker without evicting active lockouts."""
        if len(trackers) < MAX_LOCKOUT_TRACKERS:
            return True

        self._cleanup_expired_locked(current_time)
        if len(trackers) < MAX_LOCKOUT_TRACKERS:
            return True

        inactive_keys = [
            key
            for key, tracker in trackers.items()
            if (tracker.lockout_until <= current_time and tracker.failed_attempts == 0)
        ]
        if not inactive_keys:
            return False

        oldest_key = min(
            inactive_keys,
            key=lambda tracker_key: trackers[tracker_key].last_attempt,
        )
        del trackers[oldest_key]
        return len(trackers) < MAX_LOCKOUT_TRACKERS

    def _record_failed_on_tracker(
        self,
        trackers: dict[str, LoginAttemptTracker],
        key: str,
        current_time: float,
    ) -> tuple[bool, bool]:
        """Record a failed attempt on a single tracker map."""
        if key not in trackers:
            if not self._evict_oldest_tracker_if_needed(trackers, current_time):
                emergency = LoginAttemptTracker()
                emergency.failed_attempts = self.max_attempts
                emergency.lockout_until = current_time + self.lockout_duration
                emergency.last_attempt = current_time
                trackers[key] = emergency
                return True, True
            trackers[key] = LoginAttemptTracker()

        tracker = trackers[key]

        if tracker.lockout_until > 0 and tracker.lockout_until <= current_time:
            tracker.lockout_until = 0.0
            tracker.failed_attempts = 0

        tracker.failed_attempts += 1
        tracker.last_attempt = current_time

        if tracker.failed_attempts >= self.max_attempts:
            tracker.lockout_until = current_time + self.lockout_duration
            return True, False

        return False, False

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
            ip_locked, ip_exhausted = self._record_failed_on_tracker(
                self._trackers, key, current_time
            )
            if ip_exhausted:
                return True, True

            username_locked = False
            if self.username_lockout_enabled:
                username_locked, username_exhausted = self._record_failed_on_tracker(
                    self._username_trackers, username, current_time
                )
                if username_exhausted:
                    return True, True

            return ip_locked or username_locked, False

    def record_successful_login(self, ip_address: str, username: str) -> None:
        """Clear failed attempts on successful login."""
        key = self._get_key(ip_address, username)

        with self._lock:
            if key in self._trackers:
                del self._trackers[key]
            if username in self._username_trackers:
                del self._username_trackers[username]

    def get_failed_attempts(self, ip_address: str, username: str) -> int:
        """Get current failed attempt count for an IP/username pair."""
        key = self._get_key(ip_address, username)

        with self._lock:
            tracker = self._trackers.get(key)
            return tracker.failed_attempts if tracker else 0

    def cleanup_expired(self) -> int:
        """Remove expired lockout entries. Returns count removed."""
        current_time = time.time()

        with self._lock:
            return self._cleanup_expired_locked(current_time)
