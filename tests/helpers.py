"""Shared helpers for MediaRelay integration tests."""

from __future__ import annotations

import base64

from flask.testing import FlaskClient


def authenticate_client(client: FlaskClient, username: str, password: str) -> str:
    """Authenticate via Basic Auth and return the CSRF token from the response."""
    credentials = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode(
        "utf-8"
    )
    response = client.get("/", headers={"Authorization": f"Basic {credentials}"})
    assert response.status_code == 200
    csrf_token = response.headers.get("X-CSRF-Token")
    assert csrf_token is not None
    return csrf_token


def logout_client(client: FlaskClient, csrf_token: str) -> FlaskClient:
    """POST /logout with a valid CSRF token."""
    client.post("/logout", headers={"X-CSRF-Token": csrf_token})
    return client
