"""
Security tests for Video Streaming Server
-----------------------------------------
Comprehensive security testing including authentication, authorization,
input validation, and protection against common web vulnerabilities.
"""

import base64
import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import quote

import pytest
from flask import session
from werkzeug.security import check_password_hash

from mediarelay.auth import (
    _session_invalid_reason,
    _username_matches,
    check_auth,
    check_authentication,
)
from mediarelay.config import ServerConfig
from mediarelay.constants import (
    DEFAULT_LOCKOUT_DURATION_SECONDS as LOCKOUT_DURATION_SECONDS,
)
from mediarelay.constants import DEFAULT_LOCKOUT_MAX_ATTEMPTS as MAX_FAILED_ATTEMPTS
from mediarelay.constants import (
    MAX_PATH_LENGTH,
    MAX_SUBTITLE_FILE_SIZE,
    MAX_URL_LENGTH,
)
from mediarelay.handlers import _collect_directory_items
from mediarelay.lockout import AccountLockoutManager, LoginAttemptTracker
from mediarelay.logging_config import SecurityEventLogger
from mediarelay.server import MediaRelayServer
from mediarelay.session_store import SessionAuthState
from mediarelay.subtitle_sanitize import sanitize_subtitle_content
from tests.helpers import authenticate_client


class TestAccountLockoutManager:
    """Test cases for AccountLockoutManager"""

    def test_lockout_manager_initialization(self) -> None:
        """Test lockout manager initialization with default values"""
        manager = AccountLockoutManager()
        assert manager.max_attempts == MAX_FAILED_ATTEMPTS
        assert manager.lockout_duration == LOCKOUT_DURATION_SECONDS

    def test_lockout_manager_custom_values(self) -> None:
        """Test lockout manager initialization with custom values"""
        manager = AccountLockoutManager(max_attempts=3, lockout_duration=300)
        assert manager.max_attempts == 3
        assert manager.lockout_duration == 300

    def test_not_locked_out_initially(self) -> None:
        """Test that new IP/username combo is not locked out"""
        manager = AccountLockoutManager()
        assert manager.is_locked_out("192.168.1.1", "testuser") is False

    def test_lockout_after_max_attempts(self) -> None:
        """Test account lockout after max failed attempts"""
        manager = AccountLockoutManager(max_attempts=3, lockout_duration=300)

        # Record 2 failed attempts - should not lock out yet
        assert manager.record_failed_attempt("192.168.1.1", "testuser") == (
            False,
            False,
        )
        assert manager.record_failed_attempt("192.168.1.1", "testuser") == (
            False,
            False,
        )
        assert manager.is_locked_out("192.168.1.1", "testuser") is False

        # Third attempt should trigger lockout
        assert manager.record_failed_attempt("192.168.1.1", "testuser") == (
            True,
            False,
        )
        assert manager.is_locked_out("192.168.1.1", "testuser") is True

    def test_get_remaining_lockout_seconds(self) -> None:
        """Test remaining lockout time calculation"""
        manager = AccountLockoutManager(max_attempts=1, lockout_duration=60)

        # Trigger lockout
        manager.record_failed_attempt("192.168.1.1", "testuser")

        remaining = manager.get_remaining_lockout_seconds("192.168.1.1", "testuser")
        assert remaining > 0
        assert remaining <= 60

    def test_successful_login_clears_attempts(self) -> None:
        """Test that successful login clears failed attempts"""
        manager = AccountLockoutManager(max_attempts=5, lockout_duration=300)

        # Record some failed attempts
        manager.record_failed_attempt("192.168.1.1", "testuser")
        manager.record_failed_attempt("192.168.1.1", "testuser")
        assert manager.get_failed_attempts("192.168.1.1", "testuser") == 2

        # Successful login should clear attempts
        manager.record_successful_login("192.168.1.1", "testuser")
        assert manager.get_failed_attempts("192.168.1.1", "testuser") == 0

    def test_different_ip_tracked_separately(self) -> None:
        """Test that different IPs are tracked separately when username lockout is off."""
        manager = AccountLockoutManager(
            max_attempts=3,
            lockout_duration=300,
            username_lockout_enabled=False,
        )

        # Lock out first IP
        for _ in range(3):
            manager.record_failed_attempt("192.168.1.1", "testuser")

        assert manager.is_locked_out("192.168.1.1", "testuser") is True
        assert manager.is_locked_out("192.168.1.2", "testuser") is False

    def test_username_locked_across_ips(self) -> None:
        """Username-wide lockout blocks login from any IP after enough failures."""
        manager = AccountLockoutManager(max_attempts=3, lockout_duration=300)

        manager.record_failed_attempt("192.168.1.1", "testuser")
        manager.record_failed_attempt("192.168.1.2", "testuser")
        assert manager.record_failed_attempt("192.168.1.3", "testuser") == (
            True,
            False,
        )

        assert manager.is_locked_out("192.168.1.1", "testuser") is True
        assert manager.is_locked_out("192.168.1.9", "testuser") is True

    def test_username_lockout_disabled(self) -> None:
        """Username-wide lockout can be disabled independently of per-IP lockout."""
        manager = AccountLockoutManager(
            max_attempts=2,
            lockout_duration=300,
            username_lockout_enabled=False,
        )

        manager.record_failed_attempt("10.0.0.1", "testuser")
        manager.record_failed_attempt("10.0.0.2", "testuser")

        assert manager.is_locked_out("10.0.0.1", "testuser") is False
        assert manager.is_locked_out("10.0.0.3", "testuser") is False

    def test_successful_login_clears_username_tracker(self) -> None:
        """Successful login clears both per-IP and username trackers."""
        manager = AccountLockoutManager(max_attempts=5, lockout_duration=300)

        manager.record_failed_attempt("192.168.1.1", "testuser")
        manager.record_failed_attempt("192.168.1.2", "testuser")
        manager.record_successful_login("192.168.1.1", "testuser")

        assert manager.get_failed_attempts("192.168.1.1", "testuser") == 0
        assert manager.is_locked_out("192.168.1.3", "testuser") is False

    def test_different_username_tracked_separately(self) -> None:
        """Test that different usernames are tracked separately"""
        manager = AccountLockoutManager(max_attempts=3, lockout_duration=300)

        # Lock out first user
        for _ in range(3):
            manager.record_failed_attempt("192.168.1.1", "user1")

        assert manager.is_locked_out("192.168.1.1", "user1") is True
        assert manager.is_locked_out("192.168.1.1", "user2") is False

    def test_cleanup_expired_entries(self) -> None:
        """Test cleanup of stale non-lockout tracker entries"""
        manager = AccountLockoutManager(max_attempts=3, lockout_duration=1)
        manager._trackers["192.168.1.1:testuser"] = LoginAttemptTracker(
            failed_attempts=0,
            lockout_until=0.0,
            last_attempt=time.time() - 10,
        )

        removed = manager.cleanup_expired()
        assert removed == 1
        assert "192.168.1.1:testuser" not in manager._trackers

    def test_cleanup_expired_stale_attempts_with_failed_count(self) -> None:
        """Stale trackers with prior failed attempts are removed after lockout duration."""
        manager = AccountLockoutManager(max_attempts=3, lockout_duration=1)
        manager._trackers["192.168.1.1:testuser"] = LoginAttemptTracker(
            failed_attempts=2,
            lockout_until=0.0,
            last_attempt=time.time() - 10,
        )

        removed = manager.cleanup_expired()
        assert removed == 1
        assert "192.168.1.1:testuser" not in manager._trackers

    def test_lockout_expiry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that lockout expires after duration"""
        manager = AccountLockoutManager(max_attempts=1, lockout_duration=0)
        current = [1000.0]

        def fake_time() -> float:
            return current[0]

        monkeypatch.setattr("mediarelay.lockout.time.time", fake_time)

        # Trigger lockout
        manager.record_failed_attempt("192.168.1.1", "testuser")

        # With lockout_duration=0, should immediately expire
        current[0] += 0.01
        assert manager.is_locked_out("192.168.1.1", "testuser") is False

    def test_get_remaining_lockout_seconds_zero_when_not_locked(self) -> None:
        manager = AccountLockoutManager()
        assert manager.get_remaining_lockout_seconds("192.168.1.1", "testuser") == 0

    def test_expired_lockout_resets_before_new_failed_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager = AccountLockoutManager(max_attempts=3, lockout_duration=1)
        current = [1000.0]

        def fake_time() -> float:
            return current[0]

        monkeypatch.setattr("mediarelay.lockout.time.time", fake_time)

        for _ in range(3):
            manager.record_failed_attempt("192.168.1.1", "testuser")
        assert manager.is_locked_out("192.168.1.1", "testuser") is True

        current[0] += 1.1
        assert manager.is_locked_out("192.168.1.1", "testuser") is False
        assert manager.record_failed_attempt("192.168.1.1", "testuser") == (
            False,
            False,
        )
        assert manager.get_failed_attempts("192.168.1.1", "testuser") == 1

    def test_expired_lockout_resets_inside_record_failed_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Expired lockout resets when record_failed_attempt runs without is_locked_out."""
        manager = AccountLockoutManager(max_attempts=2, lockout_duration=1)
        current = [1000.0]

        def fake_time() -> float:
            return current[0]

        monkeypatch.setattr("mediarelay.lockout.time.time", fake_time)

        manager.record_failed_attempt("10.0.0.1", "user")
        assert manager.record_failed_attempt("10.0.0.1", "user") == (True, False)

        current[0] += 1.1
        assert manager.record_failed_attempt("10.0.0.1", "user") == (False, False)
        assert manager.get_failed_attempts("10.0.0.1", "user") == 1

    def test_concurrent_failed_attempts_thread_safe(self) -> None:
        """Concurrent failed attempts must not corrupt lockout state."""
        manager = AccountLockoutManager(max_attempts=5, lockout_duration=300)
        barrier = threading.Barrier(10)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                manager.record_failed_attempt("10.0.0.1", "user")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert not errors
        assert manager.is_locked_out("10.0.0.1", "user")

    def test_lockout_tracker_eviction_when_at_capacity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inactive tracker entries with zero failures are evicted at capacity."""
        monkeypatch.setattr("mediarelay.lockout.MAX_LOCKOUT_TRACKERS", 2)
        manager = AccountLockoutManager(max_attempts=10, lockout_duration=300)

        manager._trackers["1.1.1.1:user1"] = (
            LoginAttemptTracker()
        )  # pylint: disable=protected-access
        manager._trackers["2.2.2.2:user2"] = (
            LoginAttemptTracker()
        )  # pylint: disable=protected-access
        assert len(manager._trackers) == 2  # pylint: disable=protected-access

        manager.record_failed_attempt("3.3.3.3", "user3")
        assert len(manager._trackers) == 2  # pylint: disable=protected-access
        assert "3.3.3.3:user3" in manager._trackers  # pylint: disable=protected-access

    def test_partial_attempt_tracker_evicted_at_capacity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Oldest non-locked trackers with in-progress attempts are evicted."""
        monkeypatch.setattr("mediarelay.lockout.MAX_LOCKOUT_TRACKERS", 2)
        manager = AccountLockoutManager(max_attempts=10, lockout_duration=300)

        manager.record_failed_attempt("1.1.1.1", "user1")
        manager.record_failed_attempt("2.2.2.2", "user2")
        assert manager.get_failed_attempts("1.1.1.1", "user1") == 1
        assert manager.get_failed_attempts("2.2.2.2", "user2") == 1

        now_locked, tracker_exhausted = manager.record_failed_attempt(
            "3.3.3.3", "user3"
        )
        assert now_locked is False
        assert tracker_exhausted is False
        assert not manager.is_locked_out("3.3.3.3", "user3")
        assert len(manager._trackers) == 2  # pylint: disable=protected-access
        assert "3.3.3.3:user3" in manager._trackers  # pylint: disable=protected-access

    def test_active_lockout_not_evicted_at_capacity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Active lockouts must not be evicted when the tracker is at capacity."""
        monkeypatch.setattr("mediarelay.lockout.MAX_LOCKOUT_TRACKERS", 2)
        manager = AccountLockoutManager(max_attempts=2, lockout_duration=300)

        manager.record_failed_attempt("1.1.1.1", "locked_user")
        assert manager.record_failed_attempt("1.1.1.1", "locked_user") == (True, False)
        assert manager.is_locked_out("1.1.1.1", "locked_user")

        manager.record_failed_attempt("2.2.2.2", "other")
        manager.record_failed_attempt("3.3.3.3", "flooder")

        assert manager.is_locked_out("1.1.1.1", "locked_user")
        assert (
            "1.1.1.1:locked_user" in manager._trackers
        )  # pylint: disable=protected-access

    def test_username_tracker_exhaustion_does_not_emergency_lockout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Username tracker exhaustion does not lock out unrelated users."""
        monkeypatch.setattr("mediarelay.lockout.MAX_LOCKOUT_TRACKERS", 2)
        manager = AccountLockoutManager(
            max_attempts=2,
            lockout_duration=300,
            username_lockout_enabled=True,
        )
        lockout_until = time.time() + 300
        for name in ("user_a", "user_b"):
            tracker = LoginAttemptTracker()
            tracker.failed_attempts = 2
            tracker.lockout_until = lockout_until
            tracker.last_attempt = time.time()
            manager._username_trackers[name] = (  # pylint: disable=protected-access
                tracker
            )

        now_locked, tracker_exhausted = manager.record_failed_attempt(
            "9.9.9.9", "user_c"
        )
        assert now_locked is False
        assert tracker_exhausted is True
        assert not manager.is_locked_out("9.9.9.9", "user_c")

    def test_remaining_lockout_seconds_without_username_lockout(self) -> None:
        """When username lockout is disabled, only IP tracker time is returned."""
        manager = AccountLockoutManager(
            max_attempts=2,
            lockout_duration=300,
            username_lockout_enabled=False,
        )
        manager.record_failed_attempt("1.1.1.1", "user")
        manager.record_failed_attempt("1.1.1.1", "user")
        remaining = manager.get_remaining_lockout_seconds("1.1.1.1", "user")
        assert remaining > 0

    def test_username_tracker_cleanup_removes_stale_entries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Expired username tracker entries are removed during cleanup."""
        current = [1000.0]

        def fake_time() -> float:
            return current[0]

        monkeypatch.setattr("mediarelay.lockout.time.time", fake_time)
        manager = AccountLockoutManager(
            max_attempts=5,
            lockout_duration=300,
            username_lockout_enabled=True,
        )
        stale = LoginAttemptTracker()
        stale.last_attempt = 0.0
        stale.lockout_until = 0.0
        stale.failed_attempts = 0
        manager._username_trackers["stale_user"] = (  # pylint: disable=protected-access
            stale
        )

        removed = manager.cleanup_expired()
        assert removed >= 1
        assert (
            "stale_user" not in manager._username_trackers
        )  # pylint: disable=protected-access

    def test_lockout_capacity_exceeded_does_not_lock_new_attackers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """New attackers are not locked when every tracker slot is an active lockout."""
        monkeypatch.setattr("mediarelay.lockout.MAX_LOCKOUT_TRACKERS", 2)
        manager = AccountLockoutManager(max_attempts=2, lockout_duration=300)

        manager.record_failed_attempt("1.1.1.1", "user_a")
        assert manager.record_failed_attempt("1.1.1.1", "user_a") == (True, False)
        manager.record_failed_attempt("2.2.2.2", "user_b")
        assert manager.record_failed_attempt("2.2.2.2", "user_b") == (True, False)

        assert manager.record_failed_attempt("3.3.3.3", "attacker") == (False, True)
        assert not manager.is_locked_out("3.3.3.3", "attacker")

    def test_evict_after_expired_cleanup_frees_slot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Expired lockout entries are cleaned up to free tracker slots at capacity."""
        monkeypatch.setattr("mediarelay.lockout.MAX_LOCKOUT_TRACKERS", 2)
        current_time = [1000.0]
        monkeypatch.setattr("mediarelay.lockout.time.time", lambda: current_time[0])
        manager = AccountLockoutManager(max_attempts=2, lockout_duration=300)

        expired_a = LoginAttemptTracker()
        expired_a.lockout_until = 500.0
        expired_a.failed_attempts = 2
        expired_a.last_attempt = 400.0
        manager._trackers["1.1.1.1:user_a"] = (  # pylint: disable=protected-access
            expired_a
        )

        expired_b = LoginAttemptTracker()
        expired_b.lockout_until = 500.0
        expired_b.failed_attempts = 2
        expired_b.last_attempt = 400.0
        manager._trackers["2.2.2.2:user_b"] = (  # pylint: disable=protected-access
            expired_b
        )

        now_locked, tracker_exhausted = manager.record_failed_attempt(
            "3.3.3.3", "user_c"
        )
        assert tracker_exhausted is False
        assert now_locked is False
        assert "3.3.3.3:user_c" in manager._trackers  # pylint: disable=protected-access

    def test_empty_username_does_not_pollute_username_tracker(self) -> None:
        """Failed attempts with empty usernames skip username-wide lockout tracking."""
        manager = AccountLockoutManager(
            max_attempts=2,
            lockout_duration=300,
            username_lockout_enabled=True,
        )

        manager.record_failed_attempt("1.1.1.1", "")
        manager.record_failed_attempt("2.2.2.2", "   ")

        assert "" not in manager._username_trackers  # pylint: disable=protected-access
        assert (
            "   " not in manager._username_trackers
        )  # pylint: disable=protected-access
        assert manager.get_failed_attempts("1.1.1.1", "") == 1


class TestLockoutTrackerExhaustedAuth:
    """Integration tests for lockout tracker exhaustion during authentication."""

    def test_lockout_tracker_capacity_exceeded_logs_security_violation(
        self, server_config: ServerConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Failed login when tracker is saturated logs lockout_tracker_capacity_exceeded."""
        monkeypatch.setattr("mediarelay.lockout.MAX_LOCKOUT_TRACKERS", 2)
        server = MediaRelayServer(server_config)
        server.lockout_manager = AccountLockoutManager(
            max_attempts=2, lockout_duration=300
        )

        server.lockout_manager.record_failed_attempt("1.1.1.1", "user_a")
        server.lockout_manager.record_failed_attempt("1.1.1.1", "user_a")
        server.lockout_manager.record_failed_attempt("2.2.2.2", "user_b")
        server.lockout_manager.record_failed_attempt("2.2.2.2", "user_b")

        credentials = base64.b64encode(b"attacker:wrongpass").decode("utf-8")
        assert server.security_logger is not None
        with patch.object(server.security_logger, "log_security_violation") as mock_log:
            with server.app.test_client() as client:
                response = client.get(
                    "/",
                    headers={"Authorization": f"Basic {credentials}"},
                )

        assert response.status_code == 401
        violation_types = [call.args[0] for call in mock_log.call_args_list]
        assert "lockout_tracker_capacity_exceeded" in violation_types


class TestLoginAttemptTracker:
    """Test cases for LoginAttemptTracker dataclass"""

    def test_default_initialization(self) -> None:
        """Test default initialization"""
        tracker = LoginAttemptTracker()
        assert tracker.failed_attempts == 0
        assert tracker.lockout_until == 0.0
        assert tracker.last_attempt > 0  # Should be set to current time


class TestAuthModule:
    """Direct tests for auth module edge cases."""

    def test_account_locked_logs_security_violation(
        self, media_relay_server, server_config
    ) -> None:
        """Lockout threshold must log an account_locked security violation."""
        media_relay_server.security_logger = Mock()
        media_relay_server.lockout_manager = AccountLockoutManager(
            max_attempts=2, lockout_duration=60
        )

        with media_relay_server.app.test_request_context():
            media_relay_server.check_auth("attacker", "wrong1")
            media_relay_server.check_auth("attacker", "wrong2")

        violation_types = [
            call.args[0]
            for call in media_relay_server.security_logger.log_security_violation.call_args_list
        ]
        assert "account_locked" in violation_types

    def test_empty_credentials_logs_empty_username(self, media_relay_server) -> None:
        """Empty credentials must log username as 'empty'."""
        media_relay_server.security_logger = Mock()

        with media_relay_server.app.test_request_context():
            assert media_relay_server.check_auth(None, None) is False

        media_relay_server.security_logger.log_auth_attempt.assert_called_once()
        assert (
            media_relay_server.security_logger.log_auth_attempt.call_args.args[0]
            == "empty"
        )

    def test_auth_required_response_omits_retry_after_when_not_locked(
        self, media_relay_server, server_config
    ) -> None:
        """401 without lockout must not include Retry-After."""
        credentials = base64.b64encode(
            f"{server_config.username}:wrongpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_request_context(
            headers={"Authorization": f"Basic {credentials}"}
        ):
            response = media_relay_server.auth_required_response()

        assert response.status_code == 401
        assert "Retry-After" not in response.headers

    def test_auth_required_response_omits_retry_after_without_auth_header(
        self, media_relay_server
    ) -> None:
        """401 without credentials must not include Retry-After."""
        with media_relay_server.app.test_request_context():
            response = media_relay_server.auth_required_response()

        assert response.status_code == 401
        assert "Retry-After" not in response.headers

    @patch("mediarelay.auth.check_password_hash", return_value=False)
    def test_check_auth_always_verifies_password_hash(
        self, mock_check_hash: Mock, media_relay_server, server_config
    ) -> None:
        """Password hash must be checked even when username does not match."""
        with media_relay_server.app.test_request_context():
            assert media_relay_server.check_auth("wronguser", "anypassword") is False

        mock_check_hash.assert_called_once_with(
            server_config.password_hash, "anypassword"
        )

    @patch("mediarelay.auth._username_matches", return_value=False)
    @patch("mediarelay.auth.check_password_hash", return_value=False)
    def test_check_auth_uses_constant_time_username_compare(
        self,
        mock_check_hash: Mock,
        mock_username_matches: Mock,
        media_relay_server,
        server_config,
    ) -> None:
        """Username comparison must use constant-time digest comparison."""
        with media_relay_server.app.test_request_context():
            assert media_relay_server.check_auth("wronguser", "anypassword") is False

        mock_username_matches.assert_called_once_with(
            server_config.username, "wronguser"
        )
        mock_check_hash.assert_called_once()

    def test_wrong_length_username_returns_false(
        self, media_relay_server, server_config
    ) -> None:
        """Usernames with different lengths are rejected without raising."""
        assert _username_matches(server_config.username, "x") is False
        with media_relay_server.app.test_request_context():
            assert media_relay_server.check_auth("x", "anypassword") is False


class TestAuthenticationSecurity:
    """Test cases for authentication security"""

    def test_brute_force_protection_lockout(
        self, media_relay_server, server_config
    ):  # pylint: disable=unused-argument
        """Test that brute force attempts trigger lockout"""
        with media_relay_server.app.test_request_context():
            # Reset lockout manager
            media_relay_server.lockout_manager = AccountLockoutManager(
                max_attempts=3, lockout_duration=60
            )

            # Simulate failed login attempts
            for _ in range(3):
                result = media_relay_server.check_auth("attacker", "wrongpass")
                assert result is False

            # Account should now be locked
            result = media_relay_server.check_auth("attacker", "wrongpass")
            assert result is False

            # Verify lockout is in effect
            assert media_relay_server.lockout_manager.is_locked_out(
                "127.0.0.1", "attacker"
            ) or media_relay_server.lockout_manager.is_locked_out("unknown", "attacker")

    def test_brute_force_protection_logging(
        self, media_relay_server, server_config
    ):  # pylint: disable=unused-argument
        """Test that brute force attempts are logged"""
        failed_attempts = []

        # Mock the security logger to capture attempts
        original_log_auth = media_relay_server.security_logger.log_auth_attempt

        def mock_log_auth(
            username: str, success: bool, ip: str, user_agent: str = ""
        ) -> None:
            failed_attempts.append((username, success))
            original_log_auth(username, success, ip, user_agent)

        media_relay_server.security_logger.log_auth_attempt = mock_log_auth

        with media_relay_server.app.test_request_context():
            # Reset lockout manager to prevent lockout
            media_relay_server.lockout_manager = AccountLockoutManager(
                max_attempts=10, lockout_duration=60
            )

            # Simulate multiple failed login attempts
            for _ in range(5):
                result = media_relay_server.check_auth("attacker", "wrongpass")
                assert result is False

        # Should have logged 5 failed attempts
        failed_auth_attempts = [
            attempt for attempt in failed_attempts if not attempt[1]
        ]
        assert len(failed_auth_attempts) == 5

    def test_session_fixation_protection(self, flask_client, server_config):
        """Test protection against session fixation attacks"""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        # Get initial session
        flask_client.get("/health")

        # Attempt to fix session ID
        with flask_client.session_transaction() as sess:
            sess["malicious_key"] = "malicious_value"

        # Login should clear session and create new session state
        response = flask_client.get(
            "/", headers={"Authorization": f"Basic {credentials}"}
        )

        assert response.status_code == 200

        # Check that authentication was successful and session was regenerated
        with flask_client.session_transaction() as sess:
            assert sess.get("authenticated") is True
            # Malicious key should be cleared because session is regenerated on login
            assert sess.get("malicious_key") is None
            # New session data should be present
            assert sess.get("login_time") is not None
            assert sess.get("login_ip") is not None

    def test_session_hijacking_protection(self, flask_client, server_config):
        """Test session cookie security attributes"""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        response = flask_client.get(
            "/", headers={"Authorization": f"Basic {credentials}"}
        )

        # Check session cookie attributes in headers
        set_cookie_header = response.headers.get("Set-Cookie", "")

        # In production, these should be set
        if server_config.is_production():
            assert "Secure" in set_cookie_header
        assert "HttpOnly" in set_cookie_header
        assert "SameSite=Strict" in set_cookie_header

    def test_session_ip_mismatch_invalidates_session(
        self, flask_client, server_config, media_relay_server
    ):
        """Session is cleared when client IP changes after login."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        response = flask_client.get(
            "/", headers={"Authorization": f"Basic {credentials}"}
        )
        assert response.status_code == 200

        with patch.object(
            media_relay_server, "get_client_ip", return_value="10.0.0.99"
        ):
            response = flask_client.get("/")
            assert response.status_code == 401

        with flask_client.session_transaction() as sess:
            assert sess.get("authenticated") is None

    def test_session_ip_change_allowed_when_bind_disabled(
        self, flask_client, server_config, media_relay_server, monkeypatch
    ) -> None:
        """Session survives IP change when VIDEO_SERVER_SESSION_BIND_IP is false."""
        monkeypatch.setattr(server_config, "session_bind_ip", False)
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        response = flask_client.get(
            "/", headers={"Authorization": f"Basic {credentials}"}
        )
        assert response.status_code == 200

        with patch.object(
            media_relay_server, "get_client_ip", return_value="10.0.0.99"
        ):
            response = flask_client.get("/")
            assert response.status_code == 200

    def test_session_max_lifetime_expires(self, flask_client, server_config):
        """Session is cleared when absolute max lifetime is exceeded."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        response = flask_client.get(
            "/", headers={"Authorization": f"Basic {credentials}"}
        )
        assert response.status_code == 200

        with flask_client.session_transaction() as sess:
            sess["login_time"] = time.time() - server_config.session_max_lifetime - 1
            sess["last_activity"] = time.time()

        response = flask_client.get("/")
        assert response.status_code == 401

        with flask_client.session_transaction() as sess:
            assert sess.get("authenticated") is None

    def test_session_max_lifetime_falls_through_to_basic_auth(
        self, flask_client, server_config
    ):
        """Expired session with valid Basic Auth re-authenticates on the same request."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        auth_header = {"Authorization": f"Basic {credentials}"}

        response = flask_client.get("/", headers=auth_header)
        assert response.status_code == 200

        with flask_client.session_transaction() as sess:
            sess["login_time"] = time.time() - server_config.session_max_lifetime - 1
            sess["last_activity"] = time.time()

        response = flask_client.get("/", headers=auth_header)
        assert response.status_code == 200

        with flask_client.session_transaction() as sess:
            assert sess.get("authenticated") is True

    def test_lockout_invalidates_active_session(
        self, media_relay_server, server_config
    ):
        """Locked-out accounts cannot continue using an existing session."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        media_relay_server.lockout_manager = AccountLockoutManager(
            max_attempts=1, lockout_duration=60
        )
        media_relay_server.security_logger = MagicMock()

        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/", headers={"Authorization": f"Basic {credentials}"}
            )
            assert response.status_code == 200

            client_ip = "127.0.0.1"
            media_relay_server.lockout_manager.record_failed_attempt(
                client_ip, server_config.username
            )

            response = client.get("/")
            assert response.status_code == 401
            media_relay_server.security_logger.log_security_violation.assert_called()
            assert "account_lockout" in str(
                media_relay_server.security_logger.log_security_violation.call_args
            )

    def test_session_invalid_reason_none_auth_state(
        self, media_relay_server, server_config
    ):
        """Defensive branch when authenticated flag is set but auth state is absent."""
        with patch(
            "mediarelay.auth.read_session_auth_state",
            return_value=None,
        ):
            assert _session_invalid_reason(media_relay_server, time.time()) == (
                "invalid_session_state"
            )

    def test_session_invalid_reason_idle_timeout(
        self, media_relay_server, server_config
    ):
        """Idle timeout invalidates an otherwise valid session."""
        current_time = time.time()
        auth_state = SessionAuthState(
            last_activity=current_time - server_config.session_timeout - 1,
            login_time=current_time - 100,
            login_ip="127.0.0.1",
            username=server_config.username,
            credential_epoch=server_config.credential_epoch,
        )
        with patch(
            "mediarelay.auth.read_session_auth_state",
            return_value=auth_state,
        ):
            assert _session_invalid_reason(media_relay_server, current_time) == (
                "session_idle_timeout"
            )

    def test_session_invalid_reason_missing_login_ip(
        self, media_relay_server, server_config
    ):
        """Sessions without a bound login IP are invalid."""
        current_time = time.time()
        auth_state = SessionAuthState(
            last_activity=current_time,
            login_time=current_time - 100,
            login_ip=None,
            username=server_config.username,
            credential_epoch=server_config.credential_epoch,
        )
        with patch(
            "mediarelay.auth.read_session_auth_state",
            return_value=auth_state,
        ):
            assert _session_invalid_reason(media_relay_server, current_time) == (
                "session_missing_login_ip"
            )

    def test_session_invalid_reason_credential_changed(
        self, media_relay_server, server_config
    ):
        """Credential rotation invalidates existing sessions."""
        current_time = time.time()
        auth_state = SessionAuthState(
            last_activity=current_time,
            login_time=current_time - 100,
            login_ip="127.0.0.1",
            username=server_config.username,
            credential_epoch="stale-epoch",
        )
        with patch(
            "mediarelay.auth.read_session_auth_state",
            return_value=auth_state,
        ):
            assert _session_invalid_reason(media_relay_server, current_time) == (
                "credential_changed"
            )

    def test_session_invalid_reason_max_lifetime_exceeded(
        self, media_relay_server, server_config
    ):
        """Absolute session lifetime invalidates the session."""
        current_time = time.time()
        auth_state = SessionAuthState(
            last_activity=current_time,
            login_time=current_time - server_config.session_max_lifetime - 1,
            login_ip="127.0.0.1",
            username=server_config.username,
            credential_epoch=server_config.credential_epoch,
        )
        with patch(
            "mediarelay.auth.read_session_auth_state",
            return_value=auth_state,
        ):
            assert _session_invalid_reason(media_relay_server, current_time) == (
                "session_max_lifetime_exceeded"
            )

    def test_concurrent_sessions_allowed(self, media_relay_server, server_config):
        """Test that multiple independent clients can hold sessions concurrently"""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        # Create two separate clients
        with (
            media_relay_server.app.test_client() as client1,
            media_relay_server.app.test_client() as client2,
        ):
            # Login with both clients
            response1 = client1.get(
                "/", headers={"Authorization": f"Basic {credentials}"}
            )
            response2 = client2.get(
                "/", headers={"Authorization": f"Basic {credentials}"}
            )

            # Both should be successful
            assert response1.status_code == 200
            assert response2.status_code == 200

    def test_password_hash_protection(self, server_config):
        """Test that password hash is not exposed"""
        config_dict = server_config.to_dict()

        # Password hash should not be in config dict
        assert "password_hash" not in config_dict
        assert server_config.password_hash not in str(config_dict)

    def test_lockout_response_includes_retry_after(
        self, media_relay_server, server_config
    ):
        """Test that lockout response includes Retry-After header"""
        media_relay_server.lockout_manager = AccountLockoutManager(
            max_attempts=1, lockout_duration=60
        )

        invalid_credentials = base64.b64encode(
            f"{server_config.username}:wrongpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {invalid_credentials}"})
            response = client.get(
                "/", headers={"Authorization": f"Basic {invalid_credentials}"}
            )

            assert response.status_code == 401
            assert response.headers.get("Retry-After") is not None
            assert int(response.headers["Retry-After"]) >= 1


class TestLogoutEndpoint:
    """Test cases for logout endpoint"""

    def test_logout_clears_session(self, media_relay_server, server_config):
        """Test that logout properly clears the session"""
        with media_relay_server.app.test_client() as client:
            csrf_token = authenticate_client(client, server_config.username, "testpass")

            with client.session_transaction() as sess:
                assert sess.get("authenticated") is True

            response = client.post("/logout", headers={"X-CSRF-Token": csrf_token})
            assert response.status_code == 200

            with client.session_transaction() as sess:
                assert sess.get("authenticated") is None

    def test_logout_response_headers(self, media_relay_server, server_config):
        """Test that logout response includes proper headers"""
        with media_relay_server.app.test_client() as client:
            csrf_token = authenticate_client(client, server_config.username, "testpass")
            response = client.post("/logout", headers={"X-CSRF-Token": csrf_token})
            assert "Clear-Site-Data" in response.headers
            assert "WWW-Authenticate" in response.headers

    def test_logout_requires_authentication(self, flask_client):
        """Test that logout requires prior authentication"""
        response = flask_client.post("/logout")
        assert response.status_code == 401

    def test_logout_requires_csrf_token(self, media_relay_server, server_config):
        """POST logout without CSRF token is rejected."""
        with media_relay_server.app.test_client() as client:
            authenticate_client(client, server_config.username, "testpass")
            response = client.post("/logout")
            assert response.status_code == 403
            assert b"CSRF validation failed" in response.data

    def test_logout_rejects_invalid_csrf_token(self, media_relay_server, server_config):
        """POST logout with wrong CSRF token is rejected."""
        with media_relay_server.app.test_client() as client:
            authenticate_client(client, server_config.username, "testpass")
            response = client.post("/logout", headers={"X-CSRF-Token": "invalid-token"})
            assert response.status_code == 403

    def test_logout_accepts_csrf_form_field(self, media_relay_server, server_config):
        """POST logout accepts CSRF token in form body."""
        with media_relay_server.app.test_client() as client:
            csrf_token = authenticate_client(client, server_config.username, "testpass")
            response = client.post("/logout", data={"csrf_token": csrf_token})
            assert response.status_code == 200

            with client.session_transaction() as sess:
                assert sess.get("authenticated") is None

    def test_authenticated_response_includes_csrf_token(
        self, media_relay_server, server_config
    ):
        """Authenticated responses expose X-CSRF-Token for logout clients."""
        with media_relay_server.app.test_client() as client:
            csrf_token = authenticate_client(client, server_config.username, "testpass")
            assert len(csrf_token) > 0

    def test_authenticated_index_includes_logout_button(
        self, media_relay_server, server_config
    ) -> None:
        """Authenticated HTML pages include a logout control with CSRF token."""
        with media_relay_server.app.test_client() as client:
            authenticate_client(client, server_config.username, "testpass")
            response = client.get("/")
            assert response.status_code == 200
            body = response.get_data(as_text=True)
            assert 'action="/logout"' in body
            assert 'name="csrf_token"' in body
            assert "<script>" not in body
            assert "Log out" in body

    def test_logout_get_returns_method_not_allowed(
        self, media_relay_server, server_config
    ):
        """GET logout is rejected to prevent CSRF-forced logout."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {credentials}"})
            response = client.get("/logout")
            assert response.status_code == 405
            assert "Method Not Allowed" in response.get_data(as_text=True)


class TestCsrfTokenHeaderScope:
    """CSRF token response header is limited to HTML browsing routes."""

    def test_csrf_header_on_authenticated_index(
        self, media_relay_server, server_config
    ) -> None:
        with media_relay_server.app.test_client() as client:
            authenticate_client(client, server_config.username, "testpass")
            response = client.get("/")
            assert response.status_code == 200
            assert response.headers.get("X-CSRF-Token")

    def test_csrf_header_absent_on_stream(
        self, media_relay_server, server_config
    ) -> None:
        video_dir = Path(server_config.video_directory)
        (video_dir / "clip.mp4").write_bytes(b"\x00" * 16)
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/stream/clip.mp4",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert response.status_code == 200
            assert "X-CSRF-Token" not in response.headers

    def test_csrf_header_absent_on_api_files(
        self, media_relay_server, server_config
    ) -> None:
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/api/files",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert response.status_code == 200
            assert "X-CSRF-Token" not in response.headers

    def test_csrf_header_absent_on_health(
        self, media_relay_server, server_config
    ) -> None:
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/health",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert response.status_code == 200
            assert "X-CSRF-Token" not in response.headers

    def test_csp_includes_script_src_none_on_index(
        self, media_relay_server, server_config
    ) -> None:
        with media_relay_server.app.test_client() as client:
            authenticate_client(client, server_config.username, "testpass")
            response = client.get("/")
            csp = response.headers.get("Content-Security-Policy", "")
            assert "script-src 'none'" in csp


class TestHealthEndpointSecurity:
    """Test cases for secured health endpoint"""

    def test_health_unauthenticated_minimal_info(self, flask_client):
        """Test that unauthenticated requests get minimal readiness info"""
        response = flask_client.get("/health")
        data = json.loads(response.data)

        assert response.status_code == 200
        assert data["status"] == "ok"
        # Should NOT have detailed info without authentication
        assert "uptime_seconds" not in data
        assert "version" not in data
        assert "rate_limiting_enabled" not in data

    def test_health_authenticated_detailed_info(
        self, authenticated_client, temp_video_dir  # pylint: disable=unused-argument
    ):
        """Test that authenticated requests get detailed health info"""
        response = authenticated_client.get("/health")
        data = json.loads(response.data)

        # Should have detailed info for authenticated requests
        assert "status" in data
        assert "uptime_seconds" in data
        assert "version" in data
        assert "timestamp" in data
        assert "video_directory_accessible" in data
        assert "rate_limiting_enabled" in data

    def test_health_uptime_is_positive_and_increases(
        self,
        authenticated_client,
        media_relay_server,
        temp_video_dir,  # pylint: disable=unused-argument
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Authenticated health responses report monotonic server uptime."""
        current = [1000.0]

        def fake_time() -> float:
            return current[0]

        monkeypatch.setattr("mediarelay.routes.time.time", fake_time)
        media_relay_server._start_time = 995.0  # drives uptime_seconds()

        first = json.loads(authenticated_client.get("/health").data)
        assert first["uptime_seconds"] >= 0

        current[0] += 5.0
        second = json.loads(authenticated_client.get("/health").data)
        assert second["uptime_seconds"] >= first["uptime_seconds"]

    def test_health_returns_correct_status_code(self, flask_client):
        """Test health endpoint returns 200 ok when healthy and unauthenticated."""
        response = flask_client.get("/health")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "ok"

    def test_health_unauthenticated_degraded_when_unhealthy(
        self, media_relay_server
    ) -> None:
        """Unauthenticated health returns degraded when video directory is inaccessible."""
        with media_relay_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=False):
                response = client.get("/health")

        assert response.status_code == 503
        data = json.loads(response.data)
        assert data["status"] == "degraded"
        assert "version" not in data

    def test_health_basic_auth_does_not_create_session(
        self, flask_client, server_config
    ) -> None:
        """Basic Auth on /health must not establish a Flask session."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with flask_client.session_transaction() as sess:
            assert not sess.get("authenticated")

        response = flask_client.get(
            "/health",
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert response.status_code in [200, 503]
        data = json.loads(response.data)
        assert "version" in data

        with flask_client.session_transaction() as sess:
            assert not sess.get("authenticated")

    def test_health_failed_auth_does_not_increment_lockout(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """Failed Basic Auth on /health must not record lockout attempts."""
        wrong_creds = base64.b64encode(
            f"{server_config.username}:wrongpassword".encode("utf-8")
        ).decode("utf-8")
        auth_header = {"Authorization": f"Basic {wrong_creds}"}

        with media_relay_server.app.test_client() as client:
            for _ in range(server_config.lockout_max_attempts + 5):
                response = client.get("/health", headers=auth_header)
                assert response.status_code in (200, 503)

            assert not media_relay_server.lockout_manager.is_locked_out(
                "127.0.0.1", server_config.username
            )
            assert (
                media_relay_server.lockout_manager.get_failed_attempts(
                    "127.0.0.1", server_config.username
                )
                == 0
            )

    def test_health_locked_out_still_verifies_password_hash(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """Locked /health probes still run password hash work without lockout accounting."""
        wrong_creds = base64.b64encode(
            f"{server_config.username}:wrongpassword".encode("utf-8")
        ).decode("utf-8")
        auth_header = {"Authorization": f"Basic {wrong_creds}"}

        with media_relay_server.app.test_request_context():
            for _ in range(server_config.lockout_max_attempts):
                media_relay_server.check_auth(server_config.username, "wrongpassword")

        with patch(
            "mediarelay.auth.check_password_hash", return_value=False
        ) as mock_hash:
            with media_relay_server.app.test_client() as client:
                failed_before = media_relay_server.lockout_manager.get_failed_attempts(
                    "127.0.0.1", server_config.username
                )
                response = client.get("/health", headers=auth_header)
                failed_after = media_relay_server.lockout_manager.get_failed_attempts(
                    "127.0.0.1", server_config.username
                )

        assert response.status_code in (200, 503)
        mock_hash.assert_called()
        assert failed_after == failed_before

    def test_health_valid_auth_returns_detailed_info(
        self, flask_client, server_config: ServerConfig
    ) -> None:
        """Valid Basic Auth on /health returns detailed health payload."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        response = flask_client.get(
            "/health",
            headers={"Authorization": f"Basic {credentials}"},
        )
        assert response.status_code in (200, 503)
        data = json.loads(response.data)
        assert "version" in data
        assert "uptime_seconds" in data


class TestSubtitleSanitization:
    """Tests for subtitle content sanitization before streaming."""

    def test_sanitize_strips_html_and_dangerous_uris(self) -> None:
        content = (
            "WEBVTT\n\n"
            "00:00:00.000 --> 00:00:01.000\n"
            "<img src=x onerror=alert(1)>\n"
            "javascript:alert(1)\n"
        )
        sanitized = sanitize_subtitle_content(content)
        assert "<img" not in sanitized
        assert "javascript:" not in sanitized
        assert "00:00:00.000 --> 00:00:01.000" in sanitized

    def test_sanitize_strips_data_and_vbscript_uris(self) -> None:
        content = (
            "WEBVTT\n\ndata:text/html,<script>alert(1)</script>\nvbscript:msgbox(1)"
        )
        sanitized = sanitize_subtitle_content(content)
        assert "data:" not in sanitized
        assert "vbscript:" not in sanitized

    def test_sanitize_strips_webvtt_style_and_note_blocks(self) -> None:
        content = (
            "WEBVTT\n\n"
            "STYLE\n"
            "::cue { color: red; }\n"
            "\n"
            "NOTE dangerous note block\n"
            "\n"
            "00:00:00.000 --> 00:00:01.000\n"
            "Safe cue text\n"
        )
        sanitized = sanitize_subtitle_content(content)
        assert "STYLE" not in sanitized
        assert "::cue" not in sanitized
        assert "NOTE dangerous" not in sanitized
        assert "Safe cue text" in sanitized

    def test_sanitize_strips_control_characters(self) -> None:
        content = "WEBVTT\n\n\x00\x01Safe cue text\n"
        sanitized = sanitize_subtitle_content(content)
        assert "\x00" not in sanitized
        assert "\x01" not in sanitized
        assert "Safe cue text" in sanitized

    def test_sanitize_strips_html_comments_and_blob_uris(self) -> None:
        content = (
            "WEBVTT\n\n<!-- hidden -->\n"
            "00:00:00.000 --> 00:00:01.000\n"
            "blob:evil\n"
            "view-source:secret\n"
        )
        sanitized = sanitize_subtitle_content(content)
        assert "<!--" not in sanitized
        assert "hidden" not in sanitized
        assert "blob:" not in sanitized
        assert "view-source:" not in sanitized
        assert "00:00:00.000 --> 00:00:01.000" in sanitized

    def test_sanitize_strips_bidi_override_characters(self) -> None:
        content = "WEBVTT\n\n\u202eHidden\u202c visible cue\n"
        sanitized = sanitize_subtitle_content(content)
        assert "\u202e" not in sanitized
        assert "\u202c" not in sanitized
        assert "visible cue" in sanitized

    def test_sanitize_strips_percent_encoded_dangerous_uris(self) -> None:
        content = "WEBVTT\n\n%6a%61%76%61%73%63%72%69%70%74:alert(1)\n"
        sanitized = sanitize_subtitle_content(content)
        assert "javascript:" not in sanitized.lower()
        assert "alert(1)" in sanitized

    def test_stream_subtitle_strips_malicious_content(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """Malicious VTT content is sanitized when streamed."""
        video_dir = Path(server_config.video_directory)
        subtitle = video_dir / "evil.vtt"
        subtitle.write_text(
            "WEBVTT\n\n00:00:00.000 --> 00:00:01.000\n" "<script>alert(1)</script>\n",
            encoding="utf-8",
        )
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/stream/evil.vtt",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert response.status_code == 200
            body = response.get_data(as_text=True)
            assert "<script>" not in body
            assert "00:00:00.000 --> 00:00:01.000" in body

    def test_stream_srt_strips_malicious_content(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """Malicious SRT content is sanitized when streamed."""
        video_dir = Path(server_config.video_directory)
        subtitle = video_dir / "evil.srt"
        subtitle.write_text(
            "1\n00:00:00,000 --> 00:00:01,000\n<script>alert(1)</script>\n",
            encoding="utf-8",
        )
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/stream/evil.srt",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert response.status_code == 200
            body = response.get_data(as_text=True)
            assert "<script>" not in body
            assert "00:00:00,000 --> 00:00:01,000" in body

    def test_stream_oversized_subtitle_returns_413(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """Subtitle files larger than MAX_SUBTITLE_FILE_SIZE are rejected."""
        video_dir = Path(server_config.video_directory)
        subtitle = video_dir / "huge.vtt"
        subtitle.write_bytes(b"x" * (MAX_SUBTITLE_FILE_SIZE + 1))
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/stream/huge.vtt",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert response.status_code == 413

    def test_stream_subtitle_capped_by_max_file_size(
        self,
        monkeypatch: pytest.MonkeyPatch,
        media_relay_server: MediaRelayServer,
        server_config: ServerConfig,
    ) -> None:
        """Subtitle limit is capped by max_file_size when that value is smaller."""
        media_relay_server.config.max_file_size = 128
        video_dir = Path(server_config.video_directory)
        subtitle = video_dir / "capped.vtt"
        subtitle.write_bytes(b"x" * 200)
        assert 200 < MAX_SUBTITLE_FILE_SIZE
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/stream/capped.vtt",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert response.status_code == 413


class TestSessionInvalidationLogging:
    """Tests for session invalidation security audit logging."""

    def test_session_idle_timeout_logs_security_event(
        self, flask_client, server_config, media_relay_server
    ) -> None:
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        response = flask_client.get(
            "/", headers={"Authorization": f"Basic {credentials}"}
        )
        assert response.status_code == 200

        with flask_client.session_transaction() as sess:
            sess["last_activity"] = time.time() - server_config.session_timeout - 1

        assert media_relay_server.security_logger is not None
        with patch.object(
            media_relay_server.security_logger, "log_security_violation"
        ) as mock_log:
            response = flask_client.get("/")
            assert response.status_code == 401
            violation_types = [call.args[0] for call in mock_log.call_args_list]
            assert "session_invalidated" in violation_types

    def test_session_invalidated_without_security_logger_clears_session(
        self, flask_client, server_config, media_relay_server
    ) -> None:
        """Invalid sessions are cleared even when security logging is disabled."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        response = flask_client.get(
            "/", headers={"Authorization": f"Basic {credentials}"}
        )
        assert response.status_code == 200

        with flask_client.session_transaction() as sess:
            sess["last_activity"] = time.time() - server_config.session_timeout - 1

        media_relay_server.security_logger = None
        response = flask_client.get("/")
        assert response.status_code == 401


class TestCsrfTokenScope:
    """Tests for CSRF token header exposure scope."""

    def test_stream_response_omits_csrf_token(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """Stream responses must not expose X-CSRF-Token."""
        video_dir = Path(server_config.video_directory)
        (video_dir / "clip.mp4").write_bytes(b"\x00" * 64)
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {credentials}"})
            response = client.get("/stream/clip.mp4")
            assert response.status_code == 200
            assert "X-CSRF-Token" not in response.headers

    def test_api_response_omits_csrf_token(
        self, authenticated_client, server_config: ServerConfig
    ) -> None:
        """API JSON responses must not expose X-CSRF-Token."""
        response = authenticated_client.get("/api/files")
        assert response.status_code == 200
        assert "X-CSRF-Token" not in response.headers

    def test_html_response_omits_csrf_when_token_unavailable(
        self, authenticated_client
    ) -> None:
        """HTML responses omit CSRF header when no token is available."""
        with patch("mediarelay.routes.get_csrf_token", return_value=None):
            response = authenticated_client.get("/")
        assert response.status_code == 200
        assert "X-CSRF-Token" not in response.headers


class TestAuthDirect:
    """Direct unit tests for mediarelay.auth helpers."""

    def test_check_authentication_skips_session_when_disabled(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """establish_session=False authenticates without creating a session."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_request_context(
            headers={"Authorization": f"Basic {credentials}"}
        ):
            assert (
                check_authentication(media_relay_server, establish_session=False)
                is True
            )
            assert not session.get("authenticated")

    def test_check_auth_without_security_logger(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """check_auth succeeds when security_logger is None."""
        media_relay_server.security_logger = None

        with media_relay_server.app.test_request_context():
            assert (
                check_auth(media_relay_server, server_config.username, "testpass")
                is True
            )

    def test_check_auth_empty_credentials_without_security_logger(
        self, media_relay_server: MediaRelayServer
    ) -> None:
        """Empty credentials return False without logging when logger is absent."""
        media_relay_server.security_logger = None

        with media_relay_server.app.test_request_context():
            assert check_auth(media_relay_server, None, None) is False

    def test_locked_out_login_without_security_logger(
        self, media_relay_server: MediaRelayServer, server_config: ServerConfig
    ) -> None:
        """Locked-out login attempts return False when security_logger is None."""
        media_relay_server.security_logger = None
        media_relay_server.lockout_manager.record_failed_attempt(
            "127.0.0.1", server_config.username
        )
        for _ in range(server_config.lockout_max_attempts - 1):
            media_relay_server.lockout_manager.record_failed_attempt(
                "127.0.0.1", server_config.username
            )

        with media_relay_server.app.test_request_context():
            assert (
                check_auth(media_relay_server, server_config.username, "wrong") is False
            )


class TestURLLengthValidation:
    """Test cases for URL and path length validation"""

    def test_url_length_limit_enforcement(self, authenticated_client):
        """Test that overly long URLs are rejected"""
        # Create a URL that exceeds the limit
        long_path = "a" * (MAX_URL_LENGTH + 100)
        response = authenticated_client.get(f"/{long_path}")

        # Should return 414 URI Too Long
        assert response.status_code == 414

    def test_path_length_limit_enforcement(self, authenticated_client):
        """Test that overly long paths are rejected"""
        # Create a path that exceeds the limit
        long_path = "a" * (MAX_PATH_LENGTH + 100) + ".mp4"
        response = authenticated_client.get(f"/stream/{long_path}")

        # Should return 414 URI Too Long
        assert response.status_code == 414

    def test_normal_length_urls_allowed(self, authenticated_client):
        """Test that normal length URLs are processed normally"""
        # Normal length path
        response = authenticated_client.get("/test_video.mp4")

        # Should process normally (200 for video player, not 414)
        assert response.status_code in [200, 404]

    def test_url_length_security_logging(self, media_relay_server, server_config):
        """Test that long URL attempts are logged"""
        media_relay_server.security_logger = MagicMock()

        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            long_path = "a" * (MAX_URL_LENGTH + 100)
            client.get(
                f"/{long_path}", headers={"Authorization": f"Basic {credentials}"}
            )

            # Security violation should be logged
            media_relay_server.security_logger.log_security_violation.assert_called()
            violation_type = media_relay_server.security_logger.log_security_violation.call_args.args[
                0
            ]
            assert violation_type == "url_too_long"

    def test_path_length_security_logging(self, media_relay_server, server_config):
        """Test that long path attempts are logged with path_too_long."""
        media_relay_server.security_logger = MagicMock()

        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            long_path = "a" * (MAX_PATH_LENGTH + 100) + ".mp4"
            client.get(
                f"/stream/{long_path}",
                headers={"Authorization": f"Basic {credentials}"},
            )

            media_relay_server.security_logger.log_security_violation.assert_called()
            violation_type = media_relay_server.security_logger.log_security_violation.call_args.args[
                0
            ]
            assert violation_type == "path_too_long"


class TestAuthorizationSecurity:
    """Test cases for authorization and access control"""

    def test_unauthorized_access_blocked(self, flask_client):
        """Test that unauthorized access is properly blocked"""
        protected_endpoints = ["/", "/stream/test_video.mp4", "/subdir/", "/api/files"]

        for endpoint in protected_endpoints:
            response = flask_client.get(endpoint)
            assert (
                response.status_code == 401
            ), f"Endpoint {endpoint} should require auth"

    def test_authorization_header_required(self, flask_client):
        """Test that proper authorization header is required"""
        # Invalid authorization header formats
        invalid_auth_headers = [
            "Bearer token123",  # Wrong auth type
            "Basic",  # Missing credentials
            "Basic invalid_base64",  # Invalid base64
            "Basic " + base64.b64encode(b"onlyusername").decode(),  # Missing password
        ]

        for auth_header in invalid_auth_headers:
            response = flask_client.get("/", headers={"Authorization": auth_header})
            assert response.status_code == 401

    def test_file_access_authorization(
        self, authenticated_client, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test file access authorization"""
        # Should be able to access files in video directory
        response = authenticated_client.get("/stream/test_video.mp4")
        assert response.status_code == 200

        # Should not be able to access files outside video directory
        # (This is handled by path traversal protection)
        response = authenticated_client.get("/stream/../../../etc/passwd")
        assert response.status_code in [403, 404]

    def test_directory_traversal_authorization(
        self, authenticated_client, security_test_payloads
    ):
        """Test authorization against directory traversal"""
        for payload in security_test_payloads["path_traversal"]:
            response = authenticated_client.get(f"/{payload}")
            assert response.status_code in [
                403,
                404,
            ], f"Should block payload: {payload}"

            response = authenticated_client.get(f"/stream/{payload}")
            assert response.status_code in [
                403,
                404,
            ], f"Should block stream payload: {payload}"


class TestInputValidationSecurity:
    """Test cases for input validation and sanitization"""

    def test_path_parameter_validation(
        self, authenticated_client, security_test_payloads
    ):
        """Test path parameter validation against injection attacks"""
        # Test various malicious path parameters
        malicious_paths = security_test_payloads["path_traversal"] + [
            "file\x00.mp4",  # Null byte injection
            "file\r\n.mp4",  # CRLF injection
            "file\t.mp4",  # Tab injection
            "file with spaces and special chars!@#$.mp4",
        ]

        for path in malicious_paths:
            is_traversal = path in security_test_payloads["path_traversal"]
            has_injection = any(char in path for char in ("\x00", "\r", "\n", "\t"))
            expected_blocked = {403, 404, 400} if has_injection else {403, 404}

            response = authenticated_client.get(f"/{path}")
            if is_traversal or has_injection:
                assert (
                    response.status_code in expected_blocked
                ), f"Unexpected status for path {path!r}: {response.status_code}"
            else:
                assert response.status_code in {200, 403, 404, 400}

            response = authenticated_client.get(f"/stream/{path}")
            if is_traversal or has_injection:
                assert (
                    response.status_code in expected_blocked
                ), f"Unexpected stream status for {path!r}: {response.status_code}"
            else:
                assert response.status_code in {200, 403, 404, 400}

    def test_query_parameter_validation(
        self, authenticated_client, security_test_payloads
    ):
        """Test query parameter validation"""
        # Test API endpoint with malicious query parameters
        malicious_queries = [
            "?path=../../../etc/passwd",
            "?path=" + security_test_payloads["path_traversal"][0],
            '?path=<script>alert("xss")</script>',
            "?path='; DROP TABLE users; --",
        ]

        for query in malicious_queries:
            response = authenticated_client.get(f"/api/files{query}")
            # Should be blocked or return error
            assert response.status_code in [400, 403, 404]

    def test_filename_validation(self, authenticated_client, temp_video_dir):
        """Test filename validation and sanitization"""
        # Create files with special characters
        special_files = [
            "file with spaces.mp4",
            "file-with-dashes.mp4",
            "file_with_underscores.mp4",
            "file.with.dots.mp4",
        ]

        for filename in special_files:
            test_file = temp_video_dir / filename
            test_file.write_text("test content")

            # Should be able to access properly named files
            response = authenticated_client.get(f"/stream/{filename}")
            assert response.status_code in [200, 404]  # 404 if URL encoding issues

    def test_content_type_validation(self, authenticated_client, temp_video_dir):
        """Test content type validation"""
        # Create files with video extensions but different content
        suspicious_files = [
            ("script.mp4", '<?php system($_GET["cmd"]); ?>'),
            ("malware.avi", "MZ\x90\x00"),  # PE executable header
            ("exploit.mkv", '<script>alert("xss")</script>'),
        ]

        for filename, content in suspicious_files:
            test_file = temp_video_dir / filename
            test_file.write_bytes(content.encode("utf-8", errors="ignore"))

            # Server should serve files based on extension, not content
            # But actual content validation would be a more advanced feature
            response = authenticated_client.get(f"/stream/{filename}")
            if response.status_code == 200:
                # If served, should have appropriate content type headers
                assert response.headers.get("Content-Type") is not None


class TestInjectionAttackProtection:
    """Test cases for protection against injection attacks"""

    @pytest.mark.parametrize(
        "malicious_filename",
        [
            "<script>alert(1)</script>.mp4",
            '"><img src=x onerror=alert(1)>.mp4',
            "javascript-alert.mp4",
        ],
    )
    def test_xss_protection(
        self, authenticated_client, temp_video_dir, malicious_filename: str
    ):
        """Test XSS protection in file names rendered in HTML output."""
        try:
            test_file = temp_video_dir / malicious_filename
            test_file.write_text("test content")
        except (OSError, ValueError):
            pytest.skip(f"Filesystem cannot create filename: {malicious_filename!r}")

        response = authenticated_client.get(f"/{quote(malicious_filename)}")
        assert response.status_code == 200
        response_text = response.get_data(as_text=True)
        assert "onerror=alert" not in response_text.lower()
        if "<script>" in malicious_filename.lower():
            assert malicious_filename not in response_text
        if "<" in malicious_filename:
            assert malicious_filename not in response_text
            assert "&lt;" in response_text

    def test_xss_payloads_blocked_in_api_path_query(
        self, authenticated_client, security_test_payloads
    ):
        """XSS payloads in API path queries must not be reflected unescaped."""
        for payload in security_test_payloads["xss_payloads"]:
            response = authenticated_client.get(f"/api/files?path={quote(payload)}")
            assert response.status_code in [400, 403, 404]
            if response.status_code == 200:
                assert payload not in response.get_data(as_text=True)

    def test_command_injection_protection(self, authenticated_client):
        """Test protection against command injection in file paths"""
        command_injection_payloads = [
            "file.mp4; rm -rf /",
            "file.mp4 | cat /etc/passwd",
            "file.mp4 && whoami",
            "file.mp4`id`",
            "$(whoami).mp4",
        ]

        for payload in command_injection_payloads:
            response = authenticated_client.get(f"/stream/{payload}")
            # Should be safely handled (blocked or 404)
            assert response.status_code in [403, 404]

    def test_sql_injection_protection(
        self, authenticated_client, security_test_payloads
    ):
        """Test SQL injection protection in query parameters"""
        # Even though this app doesn't use SQL, test parameter handling
        for payload in security_test_payloads["sql_injection"]:
            response = authenticated_client.get(f"/api/files?path={payload}")
            # Should be blocked or return safe error
            assert response.status_code in [400, 403, 404]

    def test_header_injection_protection(self, flask_client, server_config):
        """Test protection against header injection attacks"""
        # Try to inject headers through various parameters
        malicious_headers = [
            "\r\nSet-Cookie: malicious=true",
            "\r\nLocation: http://evil.com",
            "\nX-Malicious: true",
        ]

        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        for malicious_header in malicious_headers:
            try:
                # Try header injection through various vectors
                response = flask_client.get(
                    f"/{malicious_header}",
                    headers={"Authorization": f"Basic {credentials}"},
                )

                # Check that injected headers are not present
                assert "malicious" not in str(response.headers).lower()
                assert response.headers.get("X-Malicious") is None
            except ValueError:
                # Some invalid paths might raise ValueError, which is fine
                pass


class TestDenialOfServiceProtection:
    """Test cases for DoS protection"""

    def test_large_path_handling(self, authenticated_client):
        """Test handling of very large path parameters"""
        # Very long path - should be rejected before reaching path validation
        long_path = "a" * 10000 + ".mp4"
        response = authenticated_client.get(f"/stream/{long_path}")

        # Should be rejected with 414 URI Too Long
        assert response.status_code == 414

    def test_deeply_nested_paths(self, authenticated_client):
        """Test handling of deeply nested directory paths"""
        # Create deeply nested path
        deep_path = "/".join(["dir"] * 100) + "/file.mp4"
        response = authenticated_client.get(f"/stream/{deep_path}")

        assert response.status_code == 404

    @pytest.mark.timeout(15)
    def test_concurrent_auth_requests(self, media_relay_server, server_config):
        """Test server stability under concurrent authentication requests"""
        results = []
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        def make_auth_request():
            try:
                with media_relay_server.app.test_client() as client:
                    response = client.get(
                        "/", headers={"Authorization": f"Basic {credentials}"}
                    )
                    results.append(response.status_code)
            except Exception as e:  # pylint: disable=broad-exception-caught
                results.append(f"Error: {str(e)}")

        # Create multiple concurrent requests (reduced from 20 to 5 for stability)
        threads = [threading.Thread(target=make_auth_request) for _ in range(5)]

        start_time = time.time()
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=5.0)

        end_time = time.time()

        # All requests should complete within reasonable time
        assert end_time - start_time < 10.0

        # All requests should succeed with valid credentials
        successful_requests = [r for r in results if r == 200]
        assert len(successful_requests) == 5

    def test_repeated_api_requests_remain_stable(self, authenticated_client):
        """Repeated API listing requests should succeed without server errors."""
        for _ in range(25):
            response = authenticated_client.get("/api/files")
            assert response.status_code == 200

    @pytest.mark.timeout(10)
    def test_request_timeout_handling(self, media_relay_server):
        """Test that requests don't hang indefinitely"""
        # This test ensures requests complete within reasonable time
        with media_relay_server.app.test_client() as client:
            response = client.get("/health")
            assert response.status_code == 200


class TestSecurityLogging:
    """Test cases for security event logging"""

    def test_failed_auth_logging(self, media_relay_server, server_config, tmp_path):
        """Test logging of failed authentication attempts"""
        server_config.log_directory = str(tmp_path)

        # Reset security logger with new config
        media_relay_server.security_logger = SecurityEventLogger(server_config)

        # Attempt failed authentication
        with media_relay_server.app.test_request_context():
            media_relay_server.check_auth("baduser", "badpass")

        # Check security log
        security_log = tmp_path / "security.log"
        assert security_log.exists()

        log_content = security_log.read_text()
        assert "authentication" in log_content
        assert "baduser" in log_content
        assert "false" in log_content.lower()

    def test_path_traversal_logging(
        self, authenticated_client, tmp_path, media_relay_server
    ):
        """Test logging of path traversal attempts"""
        media_relay_server.config.log_directory = str(tmp_path)

        media_relay_server.security_logger = SecurityEventLogger(
            media_relay_server.config
        )

        response = authenticated_client.get("/stream/../../../etc/passwd")
        assert response.status_code in [403, 404]

        security_log = tmp_path / "security.log"
        assert security_log.exists()
        assert "path_traversal" in security_log.read_text()

    def test_security_violation_metadata(self, media_relay_server, tmp_path):
        """Test that security violations log appropriate metadata"""
        media_relay_server.config.log_directory = str(tmp_path)

        security_logger = SecurityEventLogger(media_relay_server.config)

        security_logger.log_security_violation(
            "test_violation", "Test security violation details", "192.168.1.100"
        )

        security_log = tmp_path / "security.log"
        log_content = security_log.read_text().strip()
        event = json.loads(log_content)
        assert event["event_type"] == "security_violation"
        assert event["violation_type"] == "test_violation"
        assert event["ip_address"] == "192.168.1.100"

    def test_comprehensive_path_traversal_security_violations(
        self, media_relay_server, tmp_path
    ):
        """Test comprehensive path traversal security violation logging"""
        media_relay_server.config.log_directory = str(tmp_path)
        media_relay_server.security_logger = SecurityEventLogger(
            media_relay_server.config
        )

        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "path//with//double//slashes",
            "/absolute/path/attack",
            "path/../../../sensitive/file",
            "path/./../../etc/hosts",
        ]

        with media_relay_server.app.test_request_context():
            for path in dangerous_paths:
                result = media_relay_server.get_safe_path(path)
                assert result is None

        security_log = tmp_path / "security.log"
        assert security_log.exists()
        log_lines = [
            line for line in security_log.read_text().splitlines() if line.strip()
        ]
        assert len(log_lines) >= len(dangerous_paths)


class TestCryptographicSecurity:
    """Test cases for cryptographic security"""

    def test_session_secret_key_randomness(self, server_config):
        """Test that session secret key is sufficiently random"""
        # Secret key should be long and contain variety of characters
        assert len(server_config.secret_key) >= 32

        # Should contain different character types
        key_chars = set(server_config.secret_key)
        assert len(key_chars) > 10  # Should have reasonable character diversity

    def test_password_hash_strength(self, server_config):
        """Test password hash appears to use strong hashing"""
        # Hash should not be the plain password
        assert server_config.password_hash != "testpass"

        # Should be properly formatted hash
        assert len(server_config.password_hash) > 20

        # Should verify correctly
        assert check_password_hash(server_config.password_hash, "testpass")

        # Should not verify incorrect password
        assert not check_password_hash(server_config.password_hash, "wrongpass")

    def test_session_token_uniqueness(self, media_relay_server, server_config):
        """Test that session tokens are unique across sessions"""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        session_data = []

        # Create multiple sessions
        for _ in range(5):
            with media_relay_server.app.test_client() as client:
                response = client.get(
                    "/", headers={"Authorization": f"Basic {credentials}"}
                )

                if response.status_code == 200:
                    # Extract session cookie
                    set_cookie = response.headers.get("Set-Cookie", "")
                    session_data.append(set_cookie)

        # Session cookies should be different (if they exist)
        unique_sessions = set(session_data)
        if len(session_data) > 1:
            assert len(unique_sessions) > 1  # Should have some uniqueness


@pytest.mark.timeout(60)
class TestSecurityPerformance:
    """Functional load tests for security features"""

    @pytest.mark.timeout(20)
    def test_authentication_performance(self, media_relay_server, server_config):
        """Repeated authentication checks return consistent results."""
        with media_relay_server.app.test_request_context():
            with patch("mediarelay.auth.check_password_hash", return_value=True):
                results = [
                    media_relay_server.check_auth(server_config.username, "testpass")
                    for _ in range(50)
                ]
        assert all(results)

    @pytest.mark.timeout(10)
    def test_path_validation_performance(self, media_relay_server):
        """Path validation rejects dangerous paths consistently under load."""

        test_paths = [
            "valid/path/file.mp4",
            "../../../etc/passwd",
            "normal_file.mp4",
            "..\\..\\windows\\system32\\config\\sam",
        ]

        with media_relay_server.app.test_request_context():
            for _ in range(25):
                for path in test_paths:
                    result = media_relay_server.get_safe_path(path)
                    if ".." in path or path.startswith("/") or "\\" in path:
                        assert result is None
                    elif path == "valid/path/file.mp4":
                        assert result is not None

    @pytest.mark.timeout(10)
    def test_security_logging_performance(self, media_relay_server, tmp_path):
        """Security logger accepts a burst of events without error."""

        media_relay_server.config.log_directory = str(tmp_path)

        security_logger = SecurityEventLogger(media_relay_server.config)

        for i in range(25):
            security_logger.log_auth_attempt(f"user{i}", i % 2 == 0, "127.0.0.1")

        security_log = tmp_path / "security.log"
        assert security_log.exists()
        assert len(security_log.read_text().splitlines()) >= 25


class TestDirectoryListingSymlinkMetadata:
    """Directory listings must not leak target metadata through symlinks."""

    def test_symlink_listing_uses_lstat_not_target_stat(self, tmp_path: Path) -> None:
        """Symlink size in listings comes from lstat, not the link target."""
        video_root = tmp_path / "jail"
        video_root.mkdir()
        outside = tmp_path / "outside.mp4"
        outside.write_bytes(b"x" * 50_000)

        link = video_root / "link.mp4"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("Symlink creation not supported in this environment")

        result = _collect_directory_items(video_root, video_root, {".mp4"}, 100)
        assert len(result.items) == 1
        assert result.items[0]["size"] < 50_000

    def test_symlink_listing_prefers_lstat_when_paths_differ(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Listing code calls lstat for symlinks so stat() cannot leak target size."""
        video_root = tmp_path / "jail"
        video_root.mkdir()
        entry_file = video_root / "linked.mp4"
        entry_file.write_bytes(b"x")

        large_stat = os.stat_result((0, 0, 0, 0, 0, 0, 99_999, 0, 0, 0))
        small_lstat = os.stat_result((0, 0, 0, 0, 0, 0, 42, 0, 0, 0))

        original_is_symlink = Path.is_symlink

        def is_symlink_for_linked(self: Path) -> bool:
            return self == entry_file or original_is_symlink(self)

        def lstat_for_linked(self: Path) -> os.stat_result:
            if self == entry_file:
                return small_lstat
            return os.lstat(self)

        def stat_for_linked(self: Path) -> os.stat_result:
            if self == entry_file:
                return large_stat
            return os.stat(self)

        monkeypatch.setattr(Path, "is_symlink", is_symlink_for_linked)
        monkeypatch.setattr(Path, "lstat", lstat_for_linked)
        monkeypatch.setattr(Path, "stat", stat_for_linked)

        result = _collect_directory_items(video_root, video_root, {".mp4"}, 100)
        assert len(result.items) == 1
        assert result.items[0]["size"] == 42


class TestSymlinkPathContainment:
    """Test symlink path jail enforcement"""

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Windows requires elevated privileges to create symlinks",
    )
    def test_symlink_outside_video_dir_blocked(self, media_relay_server, tmp_path):
        """Symlinks pointing outside the video directory are rejected"""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret.txt"
        secret_file.write_text("secret", encoding="utf-8")

        link_path = Path(media_relay_server.config.video_directory) / "escape_link"
        try:
            link_path.symlink_to(secret_file)
        except OSError:
            pytest.skip("Platform does not support creating symlinks")

        with media_relay_server.app.test_request_context():
            safe_path = media_relay_server.get_safe_path("escape_link")
            assert safe_path is None


class TestHardlinkPathContainment:
    """Test hard-link path jail enforcement"""

    def test_hardlink_outside_video_dir_blocked(self, media_relay_server, tmp_path):
        """Hard links pointing at files outside the video directory are rejected"""
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret.mp4"
        secret_file.write_text("secret", encoding="utf-8")

        link_path = Path(media_relay_server.config.video_directory) / "escape_link.mp4"
        try:
            os.link(secret_file, link_path)
        except (OSError, NotImplementedError):
            pytest.skip("Platform does not support creating hard links")

        with media_relay_server.app.test_request_context():
            safe_path = media_relay_server.get_safe_path("escape_link.mp4")
            assert safe_path is None


class TestParametrizedPathTraversal:
    """Parametrized path traversal attack payloads"""

    @pytest.mark.parametrize(
        "payload",
        [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252fetc%252fpasswd",
            "subdir/../../outside",
            "test\x00hidden.mp4",
        ],
    )
    def test_path_traversal_payloads(self, media_relay_server, payload):
        """Known traversal payloads must be blocked"""
        with media_relay_server.app.test_request_context():
            assert media_relay_server.get_safe_path(payload) is None


class TestReverseProxySupport:
    """Test reverse-proxy client IP handling"""

    def test_client_ip_ignores_forwarded_when_not_behind_proxy(self, server_config):
        """Without behind_proxy, X-Forwarded-For must not override remote_addr."""
        server_config.behind_proxy = False
        server = MediaRelayServer(server_config)

        with server.app.test_request_context(
            "/",
            environ_base={
                "REMOTE_ADDR": "192.168.1.50",
                "HTTP_X_FORWARDED_FOR": "203.0.113.5",
            },
        ):
            assert server.get_client_ip() == "192.168.1.50"

    def test_client_ip_ignores_forwarded_when_proxy_not_trusted(self, server_config):
        """behind_proxy without proxy_trusted must use REMOTE_ADDR, not X-Forwarded-For."""
        server_config.behind_proxy = True
        server_config.proxy_trusted = False
        server = MediaRelayServer(server_config)

        with server.app.test_request_context(
            "/",
            environ_base={
                "REMOTE_ADDR": "192.168.1.50",
                "HTTP_X_FORWARDED_FOR": "203.0.113.5",
            },
        ):
            assert server.get_client_ip() == "192.168.1.50"

    def test_client_ip_from_forwarded_header(self, monkeypatch, server_config):
        """Behind a proxy, client IP comes from X-Forwarded-For"""
        server_config.behind_proxy = True
        server_config.proxy_trusted = True
        server = MediaRelayServer(server_config)

        with server.app.test_request_context(
            "/",
            environ_base={
                "REMOTE_ADDR": "10.0.0.1",
                "HTTP_X_FORWARDED_FOR": "203.0.113.5",
            },
        ):
            assert server.get_client_ip() == "203.0.113.5"

    def test_client_ip_from_multi_hop_forwarded_header(self, server_config):
        """Multi-hop X-Forwarded-For must resolve to the leftmost client IP."""
        server_config.behind_proxy = True
        server_config.proxy_trusted = True
        server = MediaRelayServer(server_config)

        with server.app.test_request_context(
            "/",
            environ_base={
                "REMOTE_ADDR": "10.0.0.1",
                "HTTP_X_FORWARDED_FOR": "203.0.113.5, 198.51.100.10",
            },
        ):
            assert server.get_client_ip() == "203.0.113.5"
            assert server.get_client_ip() != "198.51.100.10"

    def test_lockout_uses_forwarded_client_ip(self, server_config):
        """Account lockout tracks the forwarded client IP behind a proxy"""
        server_config.behind_proxy = True
        server_config.proxy_trusted = True
        server = MediaRelayServer(server_config)
        server.lockout_manager = AccountLockoutManager(
            max_attempts=2, lockout_duration=60
        )

        with server.app.test_request_context(
            "/",
            environ_base={
                "REMOTE_ADDR": "10.0.0.1",
                "HTTP_X_FORWARDED_FOR": "203.0.113.50",
            },
        ):
            assert server.check_auth("attacker", "wrong") is False
            assert server.check_auth("attacker", "wrong") is False
            assert server.lockout_manager.is_locked_out("203.0.113.50", "attacker")

    def test_auth_response_includes_retry_after_when_locked(
        self, media_relay_server, server_config
    ):
        """Locked-out accounts receive Retry-After on 401 responses"""
        media_relay_server.lockout_manager = AccountLockoutManager(
            max_attempts=1, lockout_duration=120
        )
        client_ip = "203.0.113.99"
        credentials = base64.b64encode(
            f"{server_config.username}:wrongpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_request_context(
            "/stream/test_video.mp4",
            environ_base={"REMOTE_ADDR": client_ip},
            headers={"Authorization": f"Basic {credentials}"},
        ):
            media_relay_server.lockout_manager.record_failed_attempt(
                client_ip, server_config.username
            )
            response = media_relay_server.auth_required_response()
            assert response.status_code == 401
            assert "Retry-After" in response.headers
            assert int(response.headers["Retry-After"]) >= 1
