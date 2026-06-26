"""Typed Flask session and request-context helpers."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import cast

from flask import g, has_request_context, session

_CSRF_SESSION_KEY = "csrf_token"


@dataclass(frozen=True)
class SessionAuthState:
    """Authenticated session fields used for validation."""

    last_activity: float
    login_time: float | None
    login_ip: str | None
    username: str | None
    credential_epoch: str | None


def _session_value(
    key: str, default: str | bool | float | None
) -> str | bool | float | None:
    """Read a value from the Flask session with a typed boundary."""
    value = session.get(key, default)
    if isinstance(value, (str, bool, float)) or value is None:
        return value
    return default


def is_session_authenticated() -> bool:
    """Return True when the session is marked authenticated."""
    return bool(_session_value("authenticated", False))


def get_session_last_activity() -> float:
    """Return session last-activity timestamp (0 when unset)."""
    value = _session_value("last_activity", 0)
    return float(value) if value is not None else 0.0


def get_session_login_time() -> float | None:
    """Return session login timestamp when present."""
    value = _session_value("login_time", None)
    if value is None:
        return None
    return float(value)


def get_session_login_ip() -> str | None:
    """Return the IP bound to the session when present."""
    value = _session_value("login_ip", None)
    if value is None:
        return None
    return str(value)


def get_session_username() -> str:
    """Return the session username or 'unknown'."""
    value = _session_value("username", "unknown")
    return str(value) if value is not None else "unknown"


def get_session_credential_epoch() -> str | None:
    """Return the credential epoch stored in the session."""
    value = _session_value("credential_epoch", None)
    return value if isinstance(value, str) else None


def read_session_auth_state() -> SessionAuthState | None:
    """Return session auth fields when authenticated, else None."""
    if not is_session_authenticated():
        return None
    return SessionAuthState(
        last_activity=get_session_last_activity(),
        login_time=get_session_login_time(),
        login_ip=get_session_login_ip(),
        username=cast(str | None, _session_value("username", None)),
        credential_epoch=get_session_credential_epoch(),
    )


def touch_session_activity(current_time: float) -> None:
    """Update session last-activity timestamp."""
    session["last_activity"] = current_time


def clear_session() -> None:
    """Clear all session data."""
    session.clear()


def issue_csrf_token() -> str:
    """Generate and store a CSRF token in the current session."""
    token = secrets.token_urlsafe(32)
    session[_CSRF_SESSION_KEY] = token
    return token


def get_csrf_token() -> str | None:
    """Return the CSRF token from the session when present."""
    value = _session_value(_CSRF_SESSION_KEY, None)
    return value if isinstance(value, str) else None


def validate_csrf_token_value(value: str | None) -> bool:
    """Return True when the value matches the session CSRF token."""
    session_token = get_csrf_token()
    if session_token is None or not value:
        return False
    return hmac.compare_digest(session_token, value)


def validate_csrf_token(header_value: str | None) -> bool:
    """Return True when the header matches the session CSRF token."""
    return validate_csrf_token_value(header_value)


def establish_session(
    *,
    username: str,
    current_time: float,
    login_ip: str,
    credential_epoch: str,
) -> None:
    """Create a fresh authenticated session."""
    session.clear()
    session["authenticated"] = True
    session["username"] = username
    session["last_activity"] = current_time
    session["login_time"] = current_time
    session["login_ip"] = login_ip
    session["credential_epoch"] = credential_epoch
    session.permanent = True
    issue_csrf_token()


def get_request_id() -> str | None:
    """Return the current request ID when inside a request context."""
    if not has_request_context():
        return None
    request_id = getattr(g, "request_id", None)
    return str(request_id) if request_id is not None else None


def set_request_id(request_id: str) -> None:
    """Store the request ID on the Flask ``g`` object."""
    g.request_id = request_id


def get_start_time() -> float | None:
    """Return request start time when set on ``g``."""
    if not has_request_context():
        return None
    start_time = getattr(g, "start_time", None)
    if start_time is None:
        return None
    return float(start_time)


def set_start_time(start_time: float) -> None:
    """Record request start time on ``g``."""
    g.start_time = start_time


def set_length_violation(violation_type: str, detail: str) -> None:
    """Store URL/path length violation metadata on ``g``."""
    g.length_violation_type = violation_type
    g.length_violation_detail = detail


def get_length_violation() -> tuple[str, str]:
    """Return length violation type and detail from ``g``."""
    violation_type = str(getattr(g, "length_violation_type", "url_too_long"))
    violation_detail = str(
        getattr(
            g,
            "length_violation_detail",
            "Request URI too long",
        )
    )
    return violation_type, violation_detail


def has_request_timing() -> bool:
    """Return True when request start time is available on ``g``."""
    return has_request_context() and hasattr(g, "start_time")
