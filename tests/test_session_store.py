"""Unit tests for typed Flask session and request-context helpers."""

from __future__ import annotations

import pytest
from flask import Flask

from mediarelay.session_store import (
    clear_session,
    establish_session,
    get_csrf_token,
    get_length_violation,
    get_request_id,
    get_session_credential_epoch,
    get_session_last_activity,
    get_session_login_ip,
    get_session_login_time,
    get_session_username,
    get_start_time,
    has_request_timing,
    is_session_authenticated,
    issue_csrf_token,
    read_session_auth_state,
    set_length_violation,
    set_request_id,
    set_start_time,
    touch_session_activity,
    validate_csrf_token,
)


@pytest.fixture
def app() -> Flask:
    """Minimal Flask app with secret key for session tests."""
    flask_app = Flask(__name__)
    flask_app.config["SECRET_KEY"] = "test-secret-key"
    return flask_app


class TestSessionStoreOutsideRequest:
    """Helpers must behave safely outside an active request context."""

    def test_get_request_id_without_context(self) -> None:
        assert get_request_id() is None

    def test_get_start_time_without_context(self) -> None:
        assert get_start_time() is None

    def test_has_request_timing_without_context(self) -> None:
        assert has_request_timing() is False


class TestSessionValueCoercion:
    """Session values with unexpected types fall back to defaults."""

    def test_non_bool_authenticated_treated_as_false(self, app: Flask) -> None:
        with app.test_request_context():
            from flask import session

            session["authenticated"] = 1
            assert is_session_authenticated() is False

    def test_non_float_last_activity_defaults_to_zero(self, app: Flask) -> None:
        with app.test_request_context():
            from flask import session

            session["last_activity"] = []
            assert get_session_last_activity() == 0.0

    def test_non_string_credential_epoch_returns_none(self, app: Flask) -> None:
        with app.test_request_context():
            from flask import session

            session["credential_epoch"] = 12345
            assert get_session_credential_epoch() is None

    def test_non_string_username_defaults_to_unknown(self, app: Flask) -> None:
        with app.test_request_context():
            from flask import session

            session["username"] = 42
            assert get_session_username() == "unknown"


class TestSessionAuthState:
    """Authenticated session read/write helpers."""

    def test_read_session_auth_state_when_unauthenticated(self, app: Flask) -> None:
        with app.test_request_context():
            assert read_session_auth_state() is None

    def test_establish_and_read_session_auth_state(self, app: Flask) -> None:
        with app.test_request_context():
            establish_session(
                username="alice",
                current_time=1000.0,
                login_ip="10.0.0.1",
                credential_epoch="epoch-1",
            )
            assert is_session_authenticated() is True
            state = read_session_auth_state()
            assert state is not None
            assert state.username == "alice"
            assert state.login_ip == "10.0.0.1"
            assert state.credential_epoch == "epoch-1"
            assert state.last_activity == 1000.0
            assert state.login_time == 1000.0

    def test_touch_session_activity_updates_timestamp(self, app: Flask) -> None:
        with app.test_request_context():
            establish_session(
                username="alice",
                current_time=1000.0,
                login_ip="10.0.0.1",
                credential_epoch="epoch-1",
            )
            touch_session_activity(2000.0)
            assert get_session_last_activity() == 2000.0

    def test_clear_session_removes_authentication(self, app: Flask) -> None:
        with app.test_request_context():
            establish_session(
                username="alice",
                current_time=1000.0,
                login_ip="10.0.0.1",
                credential_epoch="epoch-1",
            )
            clear_session()
            assert is_session_authenticated() is False
            assert get_session_login_ip() is None
            assert get_session_login_time() is None


class TestRequestContextHelpers:
    """Request-scoped ``g`` object helpers."""

    def test_request_id_round_trip(self, app: Flask) -> None:
        with app.test_request_context():
            set_request_id("req-abc")
            assert get_request_id() == "req-abc"

    def test_start_time_round_trip(self, app: Flask) -> None:
        with app.test_request_context():
            set_start_time(42.5)
            assert get_start_time() == 42.5
            assert has_request_timing() is True

    def test_has_request_timing_false_when_unset(self, app: Flask) -> None:
        with app.test_request_context():
            assert has_request_timing() is False

    def test_get_start_time_in_context_without_value(self, app: Flask) -> None:
        with app.test_request_context():
            assert get_start_time() is None


class TestLengthViolationContext:
    """URL/path length violation metadata on Flask ``g``."""

    def test_set_and_get_length_violation(self, app: Flask) -> None:
        with app.test_request_context():
            set_length_violation("path_too_long", "Path exceeds limit")
            violation_type, detail = get_length_violation()
            assert violation_type == "path_too_long"
            assert detail == "Path exceeds limit"

    def test_get_length_violation_defaults(self, app: Flask) -> None:
        with app.test_request_context():
            violation_type, detail = get_length_violation()
            assert violation_type == "url_too_long"
            assert detail == "Request URI too long"


class TestCsrfToken:
    """Tests for session CSRF token helpers."""

    def test_issue_and_validate_csrf_token(self, app: Flask) -> None:
        with app.test_request_context():
            token = issue_csrf_token()
            assert validate_csrf_token(token) is True
            assert validate_csrf_token("wrong") is False
            assert validate_csrf_token(None) is False

    def test_establish_session_issues_csrf_token(self, app: Flask) -> None:
        with app.test_request_context():
            establish_session(
                username="testuser",
                current_time=1.0,
                login_ip="127.0.0.1",
                credential_epoch="epoch",
            )
            assert get_csrf_token() is not None

    def test_clear_session_removes_csrf_token(self, app: Flask) -> None:
        with app.test_request_context():
            issue_csrf_token()
            clear_session()
            assert get_csrf_token() is None
