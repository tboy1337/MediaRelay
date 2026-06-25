"""Authentication helpers for MediaRelay."""

from __future__ import annotations

import hmac
import time
from typing import TYPE_CHECKING

from flask import Response, request, session
from werkzeug.security import check_password_hash

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
    server: MediaRelayServer, username: str | None, password: str | None
) -> bool:
    """Verify username and password with lockout protection."""
    ip_address = server.get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    if not username or not password:
        if server.security_logger:
            server.security_logger.log_auth_attempt(
                username or "empty",
                False,
                ip_address,
                user_agent,
            )
        return False

    if server.lockout_manager.is_locked_out(ip_address, username):
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

    if server.security_logger:
        server.security_logger.log_auth_attempt(
            username,
            valid,
            ip_address,
            user_agent,
        )

    if valid:
        server.lockout_manager.record_successful_login(ip_address, username)
    else:
        now_locked = server.lockout_manager.record_failed_attempt(ip_address, username)
        if now_locked and server.security_logger:
            server.security_logger.log_security_violation(
                "account_locked",
                f"Account locked out after {server.config.lockout_max_attempts} "
                f"failed attempts for user '{username}'",
                ip_address,
            )

    return valid


def check_authentication(
    server: MediaRelayServer, *, establish_session: bool = True
) -> bool:
    """Check if the current request is authenticated with lockout protection."""
    current_time = time.time()
    if session.get("authenticated"):  # type: ignore[misc]
        last_activity = session.get("last_activity", 0)  # type: ignore[misc]
        if current_time - last_activity <= server.config.session_timeout:  # type: ignore[misc]
            login_ip = session.get("login_ip")  # type: ignore[misc]
            client_ip = server.get_client_ip()
            if login_ip and login_ip != client_ip:
                if server.security_logger:
                    server.security_logger.log_security_violation(
                        "session_ip_mismatch",
                        (
                            f"Session invalidated due to IP change from "
                            f"{login_ip} to {client_ip}"
                        ),
                        client_ip,
                    )
                session.clear()
                return False
            session["last_activity"] = current_time
            return True

        session.clear()

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return False

    ip_address = server.get_client_ip()

    if server.lockout_manager.is_locked_out(ip_address, auth.username):
        remaining = server.lockout_manager.get_remaining_lockout_seconds(
            ip_address, auth.username
        )
        if server.security_logger:
            server.security_logger.log_security_violation(
                "account_lockout",
                f"Login attempt while locked out for user '{auth.username}' "
                f"({remaining}s remaining)",
                ip_address,
            )
        return False

    if check_auth(server, auth.username, auth.password):
        if establish_session:
            session.clear()
            session["authenticated"] = True
            session["username"] = auth.username
            session["last_activity"] = current_time
            session["login_time"] = current_time
            session["login_ip"] = server.get_client_ip()
            session.permanent = True
        return True

    return False
