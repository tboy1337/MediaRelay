"""
Pytest configuration and shared fixtures
---------------------------------------
Common test fixtures and configuration for the entire test suite.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator

import pytest
from werkzeug.security import generate_password_hash

from config import ServerConfig
from streaming_server import MediaRelayServer


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


@pytest.fixture(scope="session")
def temp_log_dir() -> Generator[Path, None, None]:
    """Create a temporary log directory"""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_config(temp_video_dir: Path, temp_log_dir: Path) -> ServerConfig:
    """Create a test configuration"""
    # Set environment variables for testing
    os.environ["VIDEO_SERVER_HOST"] = "127.0.0.1"
    os.environ["VIDEO_SERVER_PORT"] = "5001"  # Use test port
    os.environ["VIDEO_SERVER_USERNAME"] = "testuser"
    os.environ["VIDEO_SERVER_PASSWORD_HASH"] = generate_password_hash("testpass")
    os.environ["VIDEO_SERVER_DIRECTORY"] = str(temp_video_dir)
    os.environ["VIDEO_SERVER_LOG_DIR"] = str(temp_log_dir)
    os.environ["VIDEO_SERVER_DEBUG"] = "true"
    os.environ["VIDEO_SERVER_RATE_LIMIT"] = "false"
    os.environ["FLASK_ENV"] = "testing"

    config = ServerConfig()
    return config


@pytest.fixture
def test_server(test_config: ServerConfig) -> MediaRelayServer:
    """Create a test server instance"""
    server = MediaRelayServer(test_config)
    return server


@pytest.fixture
def test_client(test_server: MediaRelayServer):
    """Create a test client for the Flask app"""
    test_server.app.config["TESTING"] = True
    with test_server.app.test_client() as client:
        yield client


@pytest.fixture
def authenticated_client(test_client, test_config: ServerConfig):
    """Create an authenticated test client"""
    import base64

    credentials = base64.b64encode(
        f"{test_config.username}:testpass".encode("utf-8")
    ).decode("utf-8")

    test_client.environ_base["HTTP_AUTHORIZATION"] = f"Basic {credentials}"
    yield test_client


@pytest.fixture
def mock_files_data() -> Dict[str, Any]:
    """Mock file system data for testing"""
    return {
        "files": [
            {
                "name": "test_video.mp4",
                "path": "test_video.mp4",
                "is_directory": False,
                "size": 1024000,
                "modified": "2023-01-01T12:00:00",
            },
            {
                "name": "test_folder",
                "path": "test_folder",
                "is_directory": True,
                "size": 0,
                "modified": "2023-01-01T12:00:00",
            },
        ]
    }


@pytest.fixture(autouse=True)
def cleanup_session():
    """Clean up session data after each test"""
    yield
    # Clean up any session data or environment variables if needed


@pytest.fixture
def security_test_payloads() -> Dict[str, list]:
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
