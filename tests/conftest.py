"""
Pytest configuration and shared fixtures
---------------------------------------
Common test fixtures and configuration for the entire test suite.
"""

import base64
import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from flask.testing import FlaskClient
from werkzeug.security import generate_password_hash

from mediarelay.config import ServerConfig
from mediarelay.server import MediaRelayServer
from tests.helpers import authenticate_client


@pytest.fixture(autouse=True)
def _default_non_production_env(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Keep tests in development mode unless they opt into production_server_config."""
    if "production_server_config" in request.fixturenames:
        return
    monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "false")


@pytest.fixture(scope="session")
def temp_video_dir() -> Generator[Path, None, None]:
    """Create a temporary video directory with test files"""
    temp_dir = Path(tempfile.mkdtemp())

    # Create test video files and directories
    (temp_dir / "test_video.mp4").write_text("fake video content")
    (temp_dir / "test_video.mkv").write_text("fake mkv content")
    (temp_dir / "subtitles.srt").write_text("fake subtitle content")
    (temp_dir / "invalid_file.txt").write_text("invalid file")

    # Create subdirectory with files
    subdir = temp_dir / "subdir"
    subdir.mkdir()
    (subdir / "sub_video.avi").write_text("fake avi content")

    # Create empty directory
    (temp_dir / "empty_dir").mkdir()

    yield temp_dir

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def large_listing_dir(temp_video_dir: Path) -> Path:
    """Function-scoped subdirectory for bulk listing tests without polluting session fixture."""
    bulk_dir = temp_video_dir / "bulk_listing"
    bulk_dir.mkdir(exist_ok=True)
    return bulk_dir


@pytest.fixture(scope="session")
def temp_log_dir() -> Generator[Path, None, None]:
    """Create a temporary log directory"""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def production_server_config(
    monkeypatch: pytest.MonkeyPatch,
    temp_video_dir: Path,
    temp_log_dir: Path,
) -> ServerConfig:
    """Production-mode configuration with deployment validation satisfied."""
    monkeypatch.setenv("VIDEO_SERVER_HOST", "127.0.0.1")
    monkeypatch.setenv("VIDEO_SERVER_PORT", "5001")
    monkeypatch.setenv("VIDEO_SERVER_USERNAME", "testuser")
    monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", generate_password_hash("testpass"))
    monkeypatch.setenv(
        "VIDEO_SERVER_SECRET_KEY", "test-secret-key-for-unit-tests-32chars"
    )
    monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(temp_video_dir))
    monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(temp_log_dir))
    monkeypatch.setenv("VIDEO_SERVER_DEBUG", "false")
    monkeypatch.setenv("VIDEO_SERVER_RATE_LIMIT", "true")
    monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "true")
    monkeypatch.setenv("VIDEO_SERVER_BEHIND_PROXY", "false")
    monkeypatch.setenv("VIDEO_SERVER_PROXY_TRUSTED", "false")

    real_access = os.access
    resolved_video = temp_video_dir.resolve()

    def access(
        path: os.PathLike[str] | str | int,
        mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> bool:
        if mode == os.W_OK and Path(path).resolve() == resolved_video:
            return False
        return real_access(path, mode, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "access", access)

    return ServerConfig()


@pytest.fixture
def server_config(
    monkeypatch: pytest.MonkeyPatch,
    temp_video_dir: Path,
    temp_log_dir: Path,
) -> ServerConfig:
    """Create a test configuration with isolated environment variables."""
    monkeypatch.setenv("VIDEO_SERVER_HOST", "127.0.0.1")
    monkeypatch.setenv("VIDEO_SERVER_PORT", "5001")
    monkeypatch.setenv("VIDEO_SERVER_USERNAME", "testuser")
    monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", generate_password_hash("testpass"))
    monkeypatch.setenv(
        "VIDEO_SERVER_SECRET_KEY", "test-secret-key-for-unit-tests-32chars"
    )
    monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(temp_video_dir))
    monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(temp_log_dir))
    monkeypatch.setenv("VIDEO_SERVER_DEBUG", "true")
    monkeypatch.setenv("VIDEO_SERVER_RATE_LIMIT", "false")
    monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "false")

    return ServerConfig()


@pytest.fixture
def media_relay_server(server_config: ServerConfig) -> MediaRelayServer:
    """Create a test server instance"""
    server = MediaRelayServer(server_config)
    return server


@pytest.fixture
def flask_client(
    media_relay_server: MediaRelayServer,
) -> Generator[FlaskClient, None, None]:
    """Create a test client for the Flask app"""
    media_relay_server.app.config["TESTING"] = True
    with media_relay_server.app.test_client() as client:
        yield client


@pytest.fixture
def authenticated_client(
    flask_client: FlaskClient, server_config: ServerConfig
) -> Generator[FlaskClient, None, None]:
    """Create an authenticated test client with an established session."""
    authenticate_client(flask_client, server_config.username, "testpass")
    yield flask_client


@pytest.fixture
def security_test_payloads() -> dict[str, list[str]]:
    """Security test payloads for various attack vectors"""
    return {
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ],
        "xss_payloads": [
            '<script>alert("xss")</script>',
            '"><script>alert("xss")</script>',
            "javascript:alert('xss')",
            '<img src=x onerror=alert("xss")>',
        ],
        "sql_injection": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users--",
        ],
    }
