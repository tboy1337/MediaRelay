"""Authentication helpers for MediaRelay."""

from __future__ import annotations

import hmac
import time
from typing import TYPE_CHECKING

from flask import Response, request
from werkzeug.security import check_password_hash

from .session_store import (
    clear_session,
)
from .session_store import establish_session as create_auth_session
from .session_store import (
    is_session_authenticated,
    read_session_auth_state,
    touch_session_activity,
)

if TYPE_CHECKING:
    from .server import MediaRelayServer


def auth_required_response(server: MediaRelayServer) -> Response:
    """Build a 401 response, including Retry-After when the account is locked out."""
    headers = {"WWW-Authenticate": 'Basic realm="Video Streaming Server"'}
    auth = request.authorization
    if auth and auth.username:
        client_ip = server.get_client_ip()
        if server.lockout_manager.is_locked_out(client_ip, auth.username):
            remaining = server.lockout_manager.get_remaining_lockout_seconds(
                client_ip, auth.username
            )
            headers["Retry-After"] = str(max(1, int(remaining)))
    return Response("Authentication Required", 401, headers)


def check_auth(
    server: MediaRelayServer,
    username: str | None,
    password: str | None,
    *,
    record_lockout: bool = True,
) -> bool:
    """Verify username and password with lockout protection."""
    ip_address = server.get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    if not username or not password:
        if record_lockout and server.security_logger:
            server.security_logger.log_auth_attempt(
                username or "empty",
                False,
                ip_address,
                user_agent,
            )
        return False

    if server.lockout_manager.is_locked_out(ip_address, username):
        if record_lockout:
            check_password_hash(server.config.password_hash, password)
            remaining = server.lockout_manager.get_remaining_lockout_seconds(
                ip_address, username
            )
            if server.security_logger:
                server.security_logger.log_security_violation(
                    "account_lockout",
                    f"Login attempt while locked out for user '{username}' "
                    f"({remaining}s remaining)",
                    ip_address,
                )
        return False

    username_ok = hmac.compare_digest(username, server.config.username)
    password_ok = check_password_hash(server.config.password_hash, password)
    valid = username_ok and password_ok

    if record_lockout and server.security_logger:
        server.security_logger.log_auth_attempt(
            username,
            valid,
            ip_address,
            user_agent,
        )

    if record_lockout:
        if valid:
            server.lockout_manager.record_successful_login(ip_address, username)
        else:
            now_locked, tracker_exhausted = (
                server.lockout_manager.record_failed_attempt(ip_address, username)
            )
            if tracker_exhausted:
                if server.security_logger:
                    server.security_logger.log_security_violation(
                        "lockout_tracker_capacity_exceeded",
                        ("Lockout tracker at capacity; failed attempt not " "recorded"),
                        ip_address,
                    )
            if now_locked and server.security_logger:
                server.security_logger.log_security_violation(
                    "account_locked",
                    f"Account locked out after {server.config.lockout_max_attempts} "
                    f"failed attempts for user '{username}'",
                    ip_address,
                )

    return valid


def _session_invalid_reason(
    server: MediaRelayServer, current_time: float
) -> str | None:
    """Return a reason string when the active session is invalid, else None."""
    auth_state = read_session_auth_state()
    if auth_state is None:
        return "invalid_session_state"

    if current_time - auth_state.last_activity > server.config.session_timeout:
        return "session_idle_timeout"

    if auth_state.login_time is not None and (
        current_time - auth_state.login_time > server.config.session_max_lifetime
    ):
        return "session_max_lifetime_exceeded"

    if not auth_state.login_ip:
        return "session_missing_login_ip"

    if auth_state.credential_epoch != server.config.credential_epoch:
        return "credential_changed"

    if server.config.session_bind_ip:
        client_ip = server.get_client_ip()
        if auth_state.login_ip != client_ip:
            return "session_ip_mismatch"

    username = auth_state.username
    client_ip = server.get_client_ip()
    if username and server.lockout_manager.is_locked_out(client_ip, str(username)):
        return "account_lockout"

    return None


def check_authentication(
    server: MediaRelayServer,
    *,
    establish_session: bool = True,
    record_lockout: bool = True,
) -> bool:
    """Check if the current request is authenticated with lockout protection."""
    current_time = time.time()
    if is_session_authenticated():
        invalid_reason = _session_invalid_reason(server, current_time)
        if invalid_reason is None:
            touch_session_activity(current_time)
            return True
        if server.security_logger:
            server.security_logger.log_security_violation(
                "session_invalidated",
                f"Session invalidated: {invalid_reason}",
                server.get_client_ip(),
            )
        clear_session()

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return False

    if check_auth(server, auth.username, auth.password, record_lockout=record_lockout):
        if establish_session:
            create_auth_session(
                username=auth.username,
                current_time=current_time,
                login_ip=server.get_client_ip(),
                credential_epoch=server.config.credential_epoch,
            )
        return True

    return False
