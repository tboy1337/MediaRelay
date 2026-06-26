"""
Integration tests for Video Streaming Server
-------------------------------------------
Comprehensive tests for the main streaming server functionality including
authentication, file serving, security, and API endpoints.
Includes comprehensive integration and streaming tests.
"""

import base64
import json
import logging
import os
import signal
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner
from flask import g, session
from werkzeug.exceptions import (
    BadRequest,
    Forbidden,
    NotFound,
    RequestEntityTooLarge,
    Unauthorized,
)
from werkzeug.security import generate_password_hash

from mediarelay.config import ServerConfig
from mediarelay.handlers import handle_index_request, handle_stream_request
from mediarelay.lockout import AccountLockoutManager
from mediarelay.path_utils import InodeLinkIndex
from mediarelay.server import MediaRelayServer, main
from mediarelay.templates import INDEX_HTML_TEMPLATE, render_index_template
from tests.constants import TEST_PASSWORD_HASH
from tests.helpers import authenticate_client


class TestMediaRelayServer:
    """Test cases for MediaRelayServer initialization and configuration"""

    def test_server_initialization(self, server_config):
        """Test server initialization with configuration"""
        server = MediaRelayServer(server_config)

        assert server.config == server_config
        assert server.app is not None
        assert server.security_logger is not None
        assert server.performance_logger is not None

    def test_flask_app_configuration(self, media_relay_server):
        """Test Flask app configuration"""
        app = media_relay_server.app

        assert app.config["TESTING"] is False  # Will be set by test client
        expected_max_length = (
            None
            if media_relay_server.config.max_file_size <= 0
            else media_relay_server.config.max_file_size
        )
        assert app.config["MAX_CONTENT_LENGTH"] == expected_max_length
        assert app.secret_key == media_relay_server.config.secret_key

    def test_security_configuration(self, media_relay_server):
        """Test security-related configuration"""
        app = media_relay_server.app

        assert app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"
        assert (
            app.config["PERMANENT_SESSION_LIFETIME"]
            == media_relay_server.config.session_timeout
        )

    def test_rate_limiting_enabled(self, server_config):
        """Test rate limiting when enabled"""
        server_config.rate_limit_enabled = True
        server = MediaRelayServer(server_config)

        assert hasattr(server, "limiter")
        assert server.limiter is not None

    def test_rate_limiting_disabled(self, server_config):
        """Test rate limiting when disabled"""
        server_config.rate_limit_enabled = False
        server = MediaRelayServer(server_config)

        assert server.limiter is None

    def test_health_endpoint_without_rate_limiter(self, server_config):
        """Health check works when the rate limiter is not configured."""
        server_config.rate_limit_enabled = False
        server = MediaRelayServer(server_config)
        server.app.config["TESTING"] = True

        try:
            with server.app.test_client() as client:
                response = client.get("/health")
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data["status"] in {"ok", "degraded"}
        finally:
            server._shutdown_cleanup()

    def test_inode_index_initializes_synchronously_at_startup(self, server_config):
        """Inode index initialization runs synchronously at startup."""
        with patch.object(InodeLinkIndex, "refresh") as mock_refresh:
            server = MediaRelayServer(server_config)
            try:
                assert server.inode_index_ready is True
                mock_refresh.assert_called_once_with(force=True)
            finally:
                server._shutdown_cleanup()

    def test_inode_index_init_failure_reports_degraded_health(self, server_config):
        """Failed inode index build marks health as degraded in non-production mode."""
        with patch.object(
            InodeLinkIndex,
            "refresh",
            side_effect=OSError("index build failed"),
        ):
            server = MediaRelayServer(server_config)
            try:
                assert server.inode_index_ready is False
                server.app.config["TESTING"] = True
                with server.app.test_client() as client:
                    response = client.get("/health")
                    assert response.status_code == 503
                    data = json.loads(response.data)
                    assert data["status"] == "degraded"
            finally:
                server._shutdown_cleanup()

    def test_inode_index_init_failure_raises_in_production(
        self, production_server_config
    ):
        """Production mode refuses to start when inode index build fails."""
        with patch.object(
            InodeLinkIndex,
            "refresh",
            side_effect=OSError("index build failed"),
        ):
            with pytest.raises(RuntimeError, match="Inode hardlink index failed"):
                MediaRelayServer(production_server_config)


class TestMediaRelayServerComprehensive:
    """Comprehensive tests for complete coverage of MediaRelayServer"""

    def test_server_initialization_with_all_features(self):
        """Test server initialization with all features enabled"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"VIDEO_SERVER_PRODUCTION": "false"}):
                config = ServerConfig(
                    video_directory=temp_dir,
                    password_hash=TEST_PASSWORD_HASH,
                    rate_limit_enabled=True,
                    debug=True,
                )

                server = MediaRelayServer(config)

            # Test that all components are initialized
            assert server.config == config
            assert server.app is not None
            assert server.limiter is not None
            assert hasattr(server, "security_logger")
            assert hasattr(server, "performance_logger")

    def test_server_with_rate_limiting_disabled(self):
        """Test server initialization with rate limiting disabled"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash=TEST_PASSWORD_HASH,
                rate_limit_enabled=False,
            )

            server = MediaRelayServer(config)
            assert server.limiter is None

    def test_index_html_template_structure(self, media_relay_server):
        """Test INDEX_HTML_TEMPLATE contains required UI structure."""
        template = INDEX_HTML_TEMPLATE

        assert "<!DOCTYPE html>" in template
        assert "Video Streaming Server" in template
        assert "<video controls" in template
        assert "<audio controls" in template
        assert "breadcrumb" in template

    def test_render_index_template_escapes_unsafe_filenames(self) -> None:
        """User-controlled filenames must be HTML-escaped in rendered output."""
        unsafe_name = '<script>alert("xss")</script>'
        rendered = render_index_template(
            video_file=unsafe_name,
            video_path=f"movies/{unsafe_name}.mp4",
            video_mime_type="video/mp4",
            media_kind="video",
            parent_path="/",
            subtitle_path=None,
        )
        assert unsafe_name not in rendered
        assert "&lt;script&gt;" in rendered

    def test_handle_index_request_comprehensive(
        self, media_relay_server, temp_video_dir
    ):
        """Test _handle_index_request method comprehensively"""
        # Create test files
        video_file = temp_video_dir / "test.mp4"
        video_file.write_text("fake video content")

        subdir = temp_video_dir / "subdir"
        subdir.mkdir(exist_ok=True)

        non_video_file = temp_video_dir / "document.txt"
        non_video_file.write_text("not a video")

        with media_relay_server.app.test_request_context():
            with patch.object(
                media_relay_server, "check_authentication", return_value=True
            ):
                # Test directory listing
                result = handle_index_request(media_relay_server, "")
                assert isinstance(result, str)
                assert "test.mp4" in result or "Video Streaming Server" in result

                # Test video file display
                result = handle_index_request(media_relay_server, "test.mp4")
                assert isinstance(result, str)
                assert "test.mp4" in result

                # Test non-video file (should return 403)
                result = handle_index_request(media_relay_server, "document.txt")
                assert result == ("File type not allowed", 403)

                # Test non-existent path
                result = handle_index_request(media_relay_server, "nonexistent.mp4")
                assert result == ("Path not found", 404)

    def test_handle_index_request_without_auth(self, media_relay_server):
        """Test _handle_index_request without authentication"""
        with media_relay_server.app.test_request_context():
            with patch.object(
                media_relay_server, "check_authentication", return_value=False
            ):
                result = handle_index_request(media_relay_server, "")
                assert result.status_code == 401


class TestAuthentication:
    """Test cases for authentication functionality"""

    def test_check_auth_valid_credentials(self, media_relay_server, server_config):
        """Test authentication with valid credentials"""
        with media_relay_server.app.test_request_context():
            result = media_relay_server.check_auth(server_config.username, "testpass")
            assert result is True

    def test_check_auth_invalid_username(self, media_relay_server):
        """Test authentication with invalid username"""
        with media_relay_server.app.test_request_context():
            result = media_relay_server.check_auth("wronguser", "testpass")
            assert result is False

    def test_check_auth_invalid_password(self, media_relay_server, server_config):
        """Test authentication with invalid password"""
        with media_relay_server.app.test_request_context():
            result = media_relay_server.check_auth(server_config.username, "wrongpass")
            assert result is False

    def test_check_auth_empty_credentials(self, media_relay_server):
        """Test authentication with empty credentials"""
        with media_relay_server.app.test_request_context():
            result = media_relay_server.check_auth("", "")
            assert result is False

            result = media_relay_server.check_auth("user", "")
            assert result is False

            result = media_relay_server.check_auth("", "pass")
            assert result is False

    def test_check_authentication_with_session(self, media_relay_server):
        """Test authentication check with valid session"""
        with media_relay_server.app.test_request_context(
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
        ):
            session["authenticated"] = True
            session["last_activity"] = time.time()
            session["login_time"] = time.time()
            session["login_ip"] = "127.0.0.1"
            session["username"] = media_relay_server.config.username
            session["credential_epoch"] = media_relay_server.config.credential_epoch
            assert media_relay_server.check_authentication() is True

    def test_check_authentication_http_auth(self, media_relay_server, server_config):
        """Test authentication check with HTTP Basic Auth"""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_request_context(
            headers={"Authorization": f"Basic {credentials}"}
        ):
            assert media_relay_server.check_authentication() is True

    def test_check_auth_method_coverage(self):
        """Test check_auth method with various scenarios"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Use a real password hash for testing
            password_hash = generate_password_hash("correct_password")

            config = ServerConfig(
                video_directory=temp_dir, password_hash=password_hash, username="admin"
            )

            server = MediaRelayServer(config)

            # Need request context for check_auth to work
            with server.app.test_request_context():
                # Test correct credentials
                assert server.check_auth("admin", "correct_password") is True

                # Test wrong password
                assert server.check_auth("admin", "wrong_password") is False

                # Test wrong username
                assert server.check_auth("wrong_user", "correct_password") is False

                # Test empty credentials
                assert server.check_auth("", "") is False
                assert server.check_auth(None, None) is False


class TestPathSecurity:
    """Test cases for path traversal protection"""

    def test_get_safe_path_normal(self, media_relay_server, temp_video_dir):
        """Test safe path handling with normal paths"""
        with media_relay_server.app.test_request_context():
            safe_path = media_relay_server.get_safe_path("test_video.mp4")
            expected_path = temp_video_dir / "test_video.mp4"
            assert safe_path == expected_path

    def test_get_safe_path_empty(
        self, media_relay_server, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test safe path handling with empty path"""
        with media_relay_server.app.test_request_context():
            safe_path = media_relay_server.get_safe_path("")
            assert safe_path == Path(media_relay_server.config.video_directory)

    def test_get_safe_path_none(
        self, media_relay_server, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test safe path handling with None path"""
        with media_relay_server.app.test_request_context():
            safe_path = media_relay_server.get_safe_path(None)
            assert safe_path == Path(media_relay_server.config.video_directory)

    def test_path_traversal_protection(
        self, media_relay_server, security_test_payloads
    ):
        """Test protection against path traversal attacks"""
        with media_relay_server.app.test_request_context():
            for payload in security_test_payloads["path_traversal"]:
                safe_path = media_relay_server.get_safe_path(payload)
                assert safe_path is None

    def test_get_safe_path_comprehensive_edge_cases(self, media_relay_server):
        """Test get_safe_path with comprehensive edge cases"""
        with media_relay_server.app.test_request_context():
            # Test with None
            result = media_relay_server.get_safe_path(None)
            assert result == Path(media_relay_server.config.video_directory)

            # Test with empty string
            result = media_relay_server.get_safe_path("")
            assert result == Path(media_relay_server.config.video_directory)

            # Test with various malicious paths
            dangerous_paths = [
                "../../../etc/passwd",
                "..\\..\\windows\\system32",
                "path//with//double//slashes",
                "/absolute/path/attack",
                "path/../../../sensitive/file",
                "path/./../../etc/hosts",
                "path\\..\\.\\..\\windows\\system32",
                "path/../traversal",
            ]

            for path in dangerous_paths:
                result = media_relay_server.get_safe_path(path)
                assert result is None


class TestDirectoryListing:
    """Test cases for directory listing functionality"""

    def test_breadcrumbs_generation(self, media_relay_server, temp_video_dir):
        """Test breadcrumb navigation generation"""
        subdir_path = temp_video_dir / "subdir"
        breadcrumbs = media_relay_server.get_breadcrumbs(subdir_path)

        assert len(breadcrumbs) >= 1
        assert breadcrumbs[0]["name"] == "Home"
        assert breadcrumbs[0]["path"] == "/"

        # Should include subdirectory
        assert any(crumb["name"] == "subdir" for crumb in breadcrumbs)

    def test_breadcrumbs_root_directory(self, media_relay_server, temp_video_dir):
        """Test breadcrumbs for root directory"""
        breadcrumbs = media_relay_server.get_breadcrumbs(temp_video_dir)

        assert len(breadcrumbs) == 1
        assert breadcrumbs[0]["name"] == "Home"

    def test_breadcrumbs_comprehensive(self, media_relay_server, temp_video_dir):
        """Test get_breadcrumbs method comprehensively"""
        # Test root directory
        crumbs = media_relay_server.get_breadcrumbs(temp_video_dir)
        assert len(crumbs) == 1
        assert crumbs[0]["name"] == "Home"

        # Test subdirectory
        subdir = temp_video_dir / "subdir" / "nested"
        subdir.mkdir(parents=True)
        crumbs = media_relay_server.get_breadcrumbs(subdir)
        assert len(crumbs) >= 2
        assert any(c["name"] == "Home" for c in crumbs)
        assert any(c["name"] == "nested" for c in crumbs)

    def test_directory_listing_with_auth(
        self, authenticated_client, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test directory listing with authentication"""
        response = authenticated_client.get("/")

        assert response.status_code == 200
        assert b"test_video.mp4" in response.data
        assert b"test_video.mkv" in response.data
        assert b"subdir" in response.data

    def test_directory_listing_without_auth(self, flask_client):
        """Test directory listing without authentication"""
        response = flask_client.get("/")

        assert response.status_code == 401
        assert "Basic" in response.headers.get("WWW-Authenticate", "")

    def test_subdirectory_listing(self, authenticated_client):
        """Test listing contents of subdirectory"""
        response = authenticated_client.get("/subdir/")

        assert response.status_code == 200
        assert b"sub_video.avi" in response.data


class TestVideoStreaming:
    """Test cases for video streaming functionality"""

    def test_stream_valid_video(self, authenticated_client):
        """Test streaming a valid video file"""
        response = authenticated_client.get("/stream/test_video.mp4")

        assert response.status_code == 200
        assert response.data == b"fake video content"

    @pytest.mark.timeout(10)  # Add timeout to prevent hanging
    def test_stream_video_without_auth(self, flask_client):
        """Test streaming video without authentication"""
        response = flask_client.get("/stream/test_video.mp4")

        assert response.status_code == 401

    @pytest.mark.timeout(10)  # Add timeout to prevent hanging
    def test_stream_nonexistent_file(self, authenticated_client):
        """Test streaming nonexistent file"""
        response = authenticated_client.get("/stream/nonexistent.mp4")

        assert response.status_code == 404

    @pytest.mark.timeout(10)  # Add timeout to prevent hanging
    def test_stream_invalid_file_type(self, authenticated_client):
        """Test streaming invalid file type"""
        response = authenticated_client.get("/stream/invalid_file.txt")

        assert response.status_code == 403

    def test_video_player_page(self, authenticated_client):
        """Test video player page rendering"""
        response = authenticated_client.get("/test_video.mp4")

        assert response.status_code == 200
        assert b"<video controls" in response.data
        assert b"test_video.mp4" in response.data

    def test_subtitle_file_access(self, authenticated_client):
        """Test accessing subtitle files"""
        response = authenticated_client.get("/stream/subtitles.srt")

        assert response.status_code == 200
        assert response.data == b"fake subtitle content"
        assert response.headers.get("Content-Type") == "text/plain; charset=utf-8"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_vtt_file_streaming(self, authenticated_client, temp_video_dir):
        """Test streaming WebVTT subtitle files from the default allowlist."""
        vtt_path = temp_video_dir / "captions.vtt"
        vtt_path.write_text("WEBVTT\n", encoding="utf-8")

        response = authenticated_client.get("/stream/captions.vtt")

        assert response.status_code == 200
        assert response.data.decode("utf-8").startswith("WEBVTT")
        assert response.headers.get("Content-Type") == "text/plain; charset=utf-8"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_stream_range_request_partial_content(self, authenticated_client):
        """Test HTTP Range request returns partial content for seeking"""
        headers = {"Range": "bytes=0-4"}
        response = authenticated_client.get("/stream/test_video.mp4", headers=headers)

        assert response.status_code == 206
        assert response.data == b"fake "
        assert response.headers.get("Accept-Ranges") == "bytes"
        content_range = response.headers.get("Content-Range", "")
        assert content_range.startswith("bytes 0-4/")

    def test_stream_range_request_invalid_range(self, authenticated_client):
        """Test invalid Range request returns 416"""
        headers = {"Range": "bytes=10000-20000"}
        response = authenticated_client.get("/stream/test_video.mp4", headers=headers)

        assert response.status_code == 416

    def test_stream_range_request_suffix(self, authenticated_client):
        """Test suffix Range request returns partial content."""
        headers = {"Range": "bytes=-5"}
        response = authenticated_client.get("/stream/test_video.mp4", headers=headers)

        assert response.status_code == 206
        assert len(response.data) == 5

    def test_stream_range_request_open_ended(self, authenticated_client):
        """Test open-ended Range request returns partial content."""
        headers = {"Range": "bytes=5-"}
        response = authenticated_client.get("/stream/test_video.mp4", headers=headers)

        assert response.status_code == 206
        assert response.data == b"video content"

    def test_stream_range_request_malformed_header(self, authenticated_client):
        """Test malformed Range header returns 416 when conditional responses are enabled."""
        headers = {"Range": "invalid-range"}
        response = authenticated_client.get("/stream/test_video.mp4", headers=headers)

        assert response.status_code == 416

    @pytest.mark.parametrize(
        "subpath,expected_names",
        [
            ("", {"Home"}),
            ("subdir", {"Home", "subdir"}),
        ],
    )
    def test_breadcrumbs_for_paths(self, media_relay_server, subpath, expected_names):
        """Test breadcrumb generation stays within the video directory"""
        with media_relay_server.app.test_request_context():
            if subpath:
                safe_path = media_relay_server.get_safe_path(subpath)
            else:
                safe_path = Path(media_relay_server.config.video_directory)

            assert safe_path is not None
            crumbs = media_relay_server.get_breadcrumbs(safe_path)
            crumb_names = {crumb["name"] for crumb in crumbs}
            assert crumb_names == expected_names


class TestAPIEndpoints:
    """Test cases for API endpoints"""

    def test_health_check_endpoint(self, flask_client):
        """Test health check endpoint (unauthenticated - liveness only)"""
        response = flask_client.get("/health")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "ok"
        assert "version" not in data

    def test_health_check_endpoint_authenticated(self, authenticated_client):
        """Test health check endpoint with authentication (detailed info)"""
        response = authenticated_client.get("/health")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data
        assert data["version"] != "2.0.0"
        assert "video_directory_accessible" in data

    def test_api_files_endpoint_with_auth(self, authenticated_client):
        """Test API files endpoint with authentication"""
        response = authenticated_client.get("/api/files")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert "files" in data
        assert "path" in data
        assert "total_items" in data
        assert isinstance(data["files"], list)

    def test_api_files_endpoint_without_auth(self, flask_client):
        """Test API files endpoint without authentication"""
        response = flask_client.get("/api/files")

        assert response.status_code == 401
        data = json.loads(response.data)
        assert "error" in data

    def test_api_files_with_path_parameter(self, authenticated_client):
        """Test API files endpoint with path parameter"""
        response = authenticated_client.get("/api/files?path=subdir")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert data["path"] == "subdir"
        # Should contain subdirectory files
        filenames = [f["name"] for f in data["files"]]
        assert "sub_video.avi" in filenames

    def test_api_files_invalid_path(self, authenticated_client):
        """Test API files endpoint with invalid path"""
        response = authenticated_client.get("/api/files?path=../../../etc")

        assert response.status_code == 404
        data = json.loads(response.data)
        assert "error" in data


class TestHealthCheckComprehensive:
    """Comprehensive tests for health check endpoint"""

    def test_health_check_healthy_unauthenticated(self, media_relay_server):
        """Test health check when healthy (unauthenticated - liveness only)"""
        with media_relay_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=True):
                with patch("os.access", return_value=True):
                    response = client.get("/health")
                    assert response.status_code == 200

                    data = json.loads(response.data)
                    assert data["status"] == "ok"
                    assert "timestamp" not in data

    def test_health_check_unhealthy_unauthenticated(self, media_relay_server):
        """Unauthenticated health returns degraded when video directory is inaccessible."""
        with media_relay_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=False):
                response = client.get("/health")
                assert response.status_code == 503

                data = json.loads(response.data)
                assert data["status"] == "degraded"

    def test_health_check_unhealthy_authenticated(
        self, media_relay_server, server_config
    ):
        """Authenticated health reports unhealthy when disk is inaccessible."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        with media_relay_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=False):
                response = client.get(
                    "/health",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 503

                data = json.loads(response.data)
                assert data["status"] == "unhealthy"

    def test_health_check_exception(self, media_relay_server):
        """Test health check with exception (authenticated readiness)"""
        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        with media_relay_server.app.test_client() as client:
            with patch.object(Path, "exists", side_effect=OSError("Test error")):
                response = client.get(
                    "/health",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 503

    def test_health_check_permission_error(self, media_relay_server, server_config):
        """Test health check when runtime health raises PermissionError."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        with media_relay_server.app.test_client() as client:
            with patch.object(
                media_relay_server.config,
                "check_runtime_health",
                side_effect=PermissionError("denied"),
            ):
                response = client.get(
                    "/health",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 503


class TestErrorHandling:
    """Test cases for error handling"""

    def test_404_error_handler(self, authenticated_client):
        """Test 404 error handler"""
        response = authenticated_client.get("/nonexistent-path")

        assert response.status_code == 404
        assert b"Path not found" in response.data

    def test_403_error_handler(self, authenticated_client):
        """Test 403 error handler"""
        # Try to access invalid file type
        response = authenticated_client.get("/stream/invalid_file.txt")

        assert response.status_code == 403
        assert b"File type not allowed" in response.data

    def test_400_error_handling(self, authenticated_client):
        """Test bad request error handling for invalid page parameter"""
        response = authenticated_client.get("/?page=invalid")

        assert response.status_code == 400
        assert b"Invalid page parameter" in response.data

    def test_index_disallowed_file_type_returns_403(self, authenticated_client):
        """Disallowed file types on index route return 403, not 400."""
        response = authenticated_client.get("/invalid_file.txt")

        assert response.status_code == 403
        assert b"File type not allowed" in response.data

    def test_session_timeout_handling(self, media_relay_server):
        """Test session timeout and clearing logic"""
        with media_relay_server.app.test_client() as client:
            with client.session_transaction() as sess:
                # Set up an expired session
                sess["authenticated"] = True
                sess["last_activity"] = time.time() - (
                    media_relay_server.config.session_timeout + 100
                )
                sess["username"] = "testuser"

            # Make a request that should trigger session timeout
            response = client.get("/")

            # Session should be cleared and user redirected to auth
            assert response.status_code == 401


class TestMaxFileSizeHandling:
    """Test cases for max file size handling"""

    def test_max_file_size_enabled(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Test Flask app with file size limit enabled"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        monkeypatch.setenv("VIDEO_SERVER_MAX_FILE_SIZE", "1073741824")
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", TEST_PASSWORD_HASH)
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(log_dir))

        config = ServerConfig()
        server = MediaRelayServer(config)
        try:
            assert server.app.config["MAX_CONTENT_LENGTH"] == 1073741824
        finally:
            server._shutdown_cleanup()

    def test_max_file_size_disabled_zero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Test Flask app with file size limit disabled (zero)"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        monkeypatch.setenv("VIDEO_SERVER_MAX_FILE_SIZE", "0")
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", TEST_PASSWORD_HASH)
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(log_dir))

        config = ServerConfig()
        server = MediaRelayServer(config)
        try:
            assert server.app.config["MAX_CONTENT_LENGTH"] is None
        finally:
            server._shutdown_cleanup()

    def test_stream_rejects_oversized_file(self, tmp_path: Path) -> None:
        """Streaming must reject files larger than VIDEO_SERVER_MAX_FILE_SIZE."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        video_file = video_dir / "large.mp4"
        video_file.write_text("x" * 64, encoding="utf-8")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            max_file_size=32,
        )
        server = MediaRelayServer(config)
        server.security_logger = MagicMock()
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        try:
            with server.app.test_client() as client:
                response = client.get(
                    "/stream/large.mp4",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 413
                server.security_logger.log_security_violation.assert_called()
        finally:
            server._shutdown_cleanup()

    def test_stream_rejects_oversized_file_without_security_logger(
        self, tmp_path: Path
    ) -> None:
        """Oversized stream rejection works when security_logger is None."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        video_file = video_dir / "large.mp4"
        video_file.write_text("x" * 64, encoding="utf-8")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            max_file_size=32,
        )
        server = MediaRelayServer(config)
        server.security_logger = None
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        try:
            with server.app.test_client() as client:
                response = client.get(
                    "/stream/large.mp4",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 413
        finally:
            server._shutdown_cleanup()

    def test_stream_logs_performance_on_response_close(self, tmp_path: Path) -> None:
        """Stream performance metrics are logged after the response body is sent."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        (video_dir / "clip.mp4").write_text("video content", encoding="utf-8")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            max_file_size=0,
        )
        server = MediaRelayServer(config)
        server.app.config["TESTING"] = True
        mock_perf = MagicMock()
        server.performance_logger = mock_perf

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        try:
            with server.app.test_request_context(
                "/stream/clip.mp4",
                headers={"Authorization": f"Basic {credentials}"},
            ):
                with patch.object(server, "check_authentication", return_value=True):
                    response = handle_stream_request(server, "clip.mp4")
                assert response.status_code == 200
                assert response._on_close
                for callback in response._on_close:
                    callback()
            mock_perf.log_file_serve_time.assert_called_once()
        finally:
            server._shutdown_cleanup()

    def test_stream_sets_video_content_type(self, tmp_path: Path) -> None:
        """Video streams include an explicit Content-Type header."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        (video_dir / "clip.mp4").write_text("video content", encoding="utf-8")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            max_file_size=0,
        )
        server = MediaRelayServer(config)
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        try:
            with server.app.test_client() as client:
                response = client.get(
                    "/stream/clip.mp4",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 200
                assert response.headers.get("Content-Type") == "video/mp4"
        finally:
            server._shutdown_cleanup()

    def test_stream_success_without_performance_logger(self, tmp_path: Path) -> None:
        """Streaming succeeds when performance_logger is None."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        video_file = video_dir / "clip.mp4"
        video_file.write_text("video content", encoding="utf-8")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            max_file_size=0,
        )
        server = MediaRelayServer(config)
        server.performance_logger = None
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        try:
            with server.app.test_client() as client:
                response = client.get(
                    "/stream/clip.mp4",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 200
        finally:
            server._shutdown_cleanup()

    def test_stream_allows_large_file_when_max_file_size_zero(
        self, tmp_path: Path
    ) -> None:
        """Streaming must not enforce size limits when VIDEO_SERVER_MAX_FILE_SIZE is 0."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        video_file = video_dir / "large.mp4"
        video_file.write_text("x" * 64, encoding="utf-8")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            max_file_size=0,
        )
        server = MediaRelayServer(config)
        server.security_logger = MagicMock()
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        try:
            with server.app.test_client() as client:
                response = client.get(
                    "/stream/large.mp4",
                    headers={"Authorization": f"Basic {credentials}"},
                )
                assert response.status_code == 200
                server.security_logger.log_security_violation.assert_not_called()
        finally:
            server._shutdown_cleanup()


class TestSecurityHeaders:
    """Test cases for security headers"""

    def test_security_headers_applied(self, flask_client, server_config):
        """Test that security headers are applied to all responses"""
        response = flask_client.get("/health")

        expected_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-Permitted-Cross-Domain-Policies",
        ]

        for header in expected_headers:
            assert header in response.headers

        assert "Cross-Origin-Opener-Policy" in response.headers
        assert "Cross-Origin-Resource-Policy" in response.headers

        if server_config.should_send_hsts():
            assert "Strict-Transport-Security" in response.headers
        else:
            assert "Strict-Transport-Security" not in response.headers

    def test_content_security_policy(self, flask_client):
        """Test Content Security Policy header"""
        response = flask_client.get("/health")

        csp = response.headers.get("Content-Security-Policy")
        assert "default-src 'self'" in csp
        assert "media-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp

    def test_hsts_header_when_hsts_enabled_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HSTS is sent when VIDEO_SERVER_HSTS=true without behind_proxy."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", TEST_PASSWORD_HASH)
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv("VIDEO_SERVER_HSTS", "true")
        monkeypatch.setenv("VIDEO_SERVER_BEHIND_PROXY", "false")
        monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "false")

        server = MediaRelayServer(ServerConfig())
        with server.app.test_client() as client:
            response = client.get("/health")
        assert "Strict-Transport-Security" in response.headers
        server._shutdown_cleanup()


class TestSessionManagement:
    """Test cases for session management"""

    def test_session_creation_on_auth(self, media_relay_server, server_config):
        """Test session creation on successful authentication"""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            response = client.get(
                "/", headers={"Authorization": f"Basic {credentials}"}
            )

            assert response.status_code == 200

            # Session should be created
            with client.session_transaction() as sess:
                assert sess.get("authenticated") is True
                assert sess.get("username") == server_config.username
                assert "last_activity" in sess
                assert sess.get("credential_epoch") == server_config.credential_epoch

    def test_session_invalid_without_login_ip(self, media_relay_server, server_config):
        """Sessions missing login_ip must be rejected."""
        with media_relay_server.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["authenticated"] = True
                sess["username"] = server_config.username
                sess["last_activity"] = time.time()
                sess["login_time"] = time.time()
                sess["credential_epoch"] = server_config.credential_epoch

            response = client.get("/")
            assert response.status_code == 401

    def test_session_invalid_after_credential_change(
        self, media_relay_server, server_config
    ) -> None:
        """Sessions must end when username or password hash changes."""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {credentials}"})
            assert client.get("/").status_code == 200

            server_config.password_hash = generate_password_hash("newpass")

            assert client.get("/").status_code == 401

    def test_session_persistence(self, media_relay_server, server_config):
        """Test session persistence across requests"""
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            # First request with auth
            client.get("/", headers={"Authorization": f"Basic {credentials}"})

            # Second request without auth should work due to session
            response = client.get("/")
            assert response.status_code == 200

    def test_session_timeout(self, media_relay_server):
        """Test session timeout functionality"""
        with media_relay_server.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["authenticated"] = True
                sess["last_activity"] = (
                    time.time() - media_relay_server.config.session_timeout - 1
                )

            response = client.get("/")
            assert response.status_code == 401


class TestFileTypeHandling:
    """Test cases for different file types and extensions"""

    def test_supported_video_formats(self, authenticated_client, temp_video_dir):
        """Test support for different video formats"""
        supported_formats = [".mp4", ".mkv", ".avi", ".mov", ".webm", ".m4v", ".flv"]

        for ext in supported_formats:
            test_file = temp_video_dir / f"test_video{ext}"
            test_file.write_text(f"fake content for {ext}")

            response = authenticated_client.get(f"/stream/test_video{ext}")
            assert response.status_code == 200, f"Failed for extension {ext}"

    def test_unsupported_file_types(self, authenticated_client, temp_video_dir):
        """Test rejection of unsupported file types"""
        unsupported_file = temp_video_dir / "document.pdf"
        unsupported_file.write_text("fake PDF content")

        response = authenticated_client.get("/stream/document.pdf")
        assert response.status_code == 403

    def test_case_insensitive_extensions(self, authenticated_client, temp_video_dir):
        """Test case-insensitive file extension handling"""
        upper_case_file = temp_video_dir / "test_video.MP4"
        upper_case_file.write_text("fake video content")

        response = authenticated_client.get("/stream/test_video.MP4")
        assert response.status_code == 200


class TestMainFunctionComprehensive:
    """Comprehensive tests for the main function"""

    @patch("mediarelay.server.MediaRelayServer")
    @patch("mediarelay.server.load_config")
    def test_main_function_normal_operation(self, mock_load_config, mock_server_class):
        """Test main function normal operation"""
        # Setup mocks
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        mock_server = Mock()
        mock_server_class.return_value = mock_server

        # Test with no arguments using CliRunner
        runner = CliRunner()
        result = runner.invoke(main, [])

        assert result.exit_code == 0
        mock_server_class.assert_called_once_with(mock_config)
        mock_server.run.assert_called_once()

    @patch("mediarelay.server.load_config")
    def test_main_function_value_error(self, mock_load_config):
        """Test main function with ValueError"""
        mock_load_config.side_effect = ValueError("Configuration error")

        runner = CliRunner()
        result = runner.invoke(main, [])

        assert result.exit_code == 1
        assert "Configuration Error: Configuration error" in result.output

    @patch("mediarelay.server.load_config")
    @patch("mediarelay.server.MediaRelayServer")
    def test_main_function_keyboard_interrupt(
        self, mock_server_class, mock_load_config
    ):
        """Test main function with KeyboardInterrupt"""
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        mock_server = Mock()
        mock_server.run.side_effect = KeyboardInterrupt()
        mock_server_class.return_value = mock_server

        # Should not raise SystemExit
        runner = CliRunner()
        result = runner.invoke(main, [])

        assert result.exit_code == 0
        assert "Shutdown complete" in result.output

    @patch("mediarelay.server.load_config")
    @patch("mediarelay.server.MediaRelayServer")
    def test_main_function_generic_exception(self, mock_server_class, mock_load_config):
        """Test main function with generic exception"""
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        mock_server = Mock()
        mock_server.run.side_effect = RuntimeError("Server error")
        mock_server_class.return_value = mock_server

        runner = CliRunner()
        result = runner.invoke(main, [])

        assert result.exit_code == 1
        assert "Server Error: Server error" in result.output

    @pytest.mark.parametrize(
        ("exception_type", "message"),
        [
            (OSError, "Disk full"),
            (ImportError, "Missing module"),
            (PermissionError, "Permission denied"),
        ],
    )
    @patch("mediarelay.server.load_config")
    @patch("mediarelay.server.MediaRelayServer")
    def test_main_function_server_errors(
        self,
        mock_server_class,
        mock_load_config,
        exception_type: type[BaseException],
        message: str,
    ) -> None:
        """Test main function exits with code 1 on server startup failures."""
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        mock_server = Mock()
        mock_server.run.side_effect = exception_type(message)
        mock_server_class.return_value = mock_server

        runner = CliRunner()
        result = runner.invoke(main, [])

        assert result.exit_code == 1
        assert f"Server Error: {message}" in result.output


class TestServerRunMethod:
    """Test the server run method comprehensively"""

    @patch("mediarelay.server.serve")
    @patch("builtins.print")
    def test_run_method_successful_start(self, mock_print, mock_serve):
        """Test successful server start"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash=TEST_PASSWORD_HASH,
                host="127.0.0.1",
                port=5000,
                threads=4,
            )
            server = MediaRelayServer(config)

            server.run()

            # Verify serve was called with correct parameters
            args, kwargs = mock_serve.call_args
            assert args[0] == server.app
            assert kwargs["host"] == "127.0.0.1"
            assert kwargs["port"] == 5000
            assert kwargs["threads"] == 4

            # Verify startup messages
            mock_print.assert_any_call("MediaRelay starting...")
            mock_print.assert_any_call(f"Server running on http://127.0.0.1:5000")

    @patch("mediarelay.server.serve")
    @patch("builtins.print")
    def test_run_method_keyboard_interrupt(self, mock_print, mock_serve):
        """Test server run with KeyboardInterrupt"""
        mock_serve.side_effect = KeyboardInterrupt()

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)

            with patch.object(server, "_shutdown_cleanup") as mock_shutdown:
                server.run()

            mock_shutdown.assert_called_once()
            mock_print.assert_any_call("\nServer stopped")

    @patch("mediarelay.server.serve")
    def test_run_method_generic_exception(self, mock_serve):
        """Test server run with generic exception"""
        mock_serve.side_effect = RuntimeError("Server error")

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)

            with patch.object(server.app.logger, "error") as mock_error:
                with pytest.raises(RuntimeError):
                    server.run()

            mock_error.assert_called_once()
            assert "Server error" in mock_error.call_args[0][0]

    @patch("mediarelay.server.serve")
    def test_run_method_generic_exception_calls_cleanup(self, mock_serve):
        """finally block runs cleanup after a generic server error."""
        mock_serve.side_effect = RuntimeError("Server error")

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)

            with patch.object(server, "_shutdown_cleanup") as mock_shutdown:
                with pytest.raises(RuntimeError):
                    server.run()

            mock_shutdown.assert_called_once()


@pytest.mark.timeout(30)
class TestPerformance:
    """Functional tests for streaming server scalability."""

    def test_large_directory_listing(self, authenticated_client, temp_video_dir):
        """Large directory listings render successfully."""
        for i in range(100):
            (temp_video_dir / f"test_video_{i:03d}.mp4").write_text(f"fake content {i}")

        response = authenticated_client.get("/")

        assert response.status_code == 200
        assert "test_video_000.mp4" in response.get_data(as_text=True)


class TestRequestLogging:
    """Test cases for request logging and monitoring"""

    def test_request_id_generation(self, media_relay_server):
        """Test request ID generation"""
        with media_relay_server.app.test_request_context():
            with media_relay_server.app.test_client() as client:
                response = client.get("/health")
                # Request should complete successfully
                assert response.status_code == 200

    def test_performance_logging(self, authenticated_client):
        """Test performance logging for requests"""
        response = authenticated_client.get("/")

        # Should complete without error
        assert response.status_code == 200
        # Performance metrics should be logged (tested in logging tests)

    def test_security_event_logging(self, flask_client, security_test_payloads):
        """Test security event logging"""
        # Try path traversal attack
        response = flask_client.get(
            f'/stream/{security_test_payloads["path_traversal"][0]}'
        )

        # Should be blocked and logged
        assert response.status_code == 401  # Unauthorized due to no auth

    def test_after_request_performance_logging(self, media_relay_server):
        """Test performance logging in after_request handler"""
        # Mock the performance logger
        media_relay_server.performance_logger = MagicMock()

        with media_relay_server.app.test_client() as client:
            with media_relay_server.app.test_request_context("/test"):
                # Set up request context with start_time (this triggers performance logging)
                g.start_time = time.time() - 0.1  # 100ms ago
                g.request_id = "test_request_123"

                # Create and process a response
                response = media_relay_server.app.make_response("test response")
                response.status_code = 200

                # Process the response (triggers after_request)
                processed_response = media_relay_server.app.process_response(response)

                # Verify performance logging was called
                media_relay_server.performance_logger.log_request_duration.assert_called_once()

    def test_after_request_skips_performance_log_when_start_time_missing(
        self, media_relay_server, authenticated_client
    ):
        """Performance logging is skipped when timing is set but start_time is missing."""
        media_relay_server.performance_logger = MagicMock()
        with (
            patch("mediarelay.routes.has_request_timing", return_value=True),
            patch("mediarelay.routes.get_start_time", return_value=None),
        ):
            response = authenticated_client.get("/")
        assert response.status_code == 200
        media_relay_server.performance_logger.log_request_duration.assert_not_called()


class TestErrorHandlers:
    """Test custom HTTP error handlers"""

    def test_request_entity_too_large_handler(self, media_relay_server):
        """Test 413 error handler"""
        with media_relay_server.app.test_request_context():
            result = media_relay_server.app.handle_http_exception(
                RequestEntityTooLarge()
            )
            if isinstance(result, tuple):
                message, status = result
                assert status == 413
                assert "File Too Large" in message
            else:
                assert result.status_code == 413

    def test_internal_error_handler(self, media_relay_server):
        """Test 500 error handler via triggered exception"""

        @media_relay_server.app.route("/test-500")  # type: ignore[untyped-decorator]
        def trigger_error() -> None:
            raise RuntimeError("intentional test failure")

        media_relay_server.app.config["TESTING"] = True
        media_relay_server.app.config["PROPAGATE_EXCEPTIONS"] = False

        with media_relay_server.app.test_client() as client:
            response = client.get("/test-500")
            assert response.status_code == 500
            assert b"Internal Server Error" in response.data

    def test_rate_limit_error_handler(self, tmp_path):
        """Test 429 response when rate limit is exceeded"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            username="testuser",
            rate_limit_enabled=True,
            rate_limit_per_minute=1,
        )
        server = MediaRelayServer(config)
        server.security_logger = MagicMock()
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        auth_header = {"Authorization": f"Basic {credentials}"}

        with server.app.test_client() as client:
            assert client.get("/", headers=auth_header).status_code == 200
            response = client.get("/")
            assert response.status_code == 429
            assert b"Rate Limit Exceeded" in response.data
            assert response.headers.get("Retry-After") == "60"
            assert client.get("/health").status_code == 200

    def test_stream_route_has_separate_rate_limit(self, tmp_path: Path) -> None:
        """Stream endpoint uses a higher dedicated rate limit for range requests."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        (video_dir / "test.mp4").write_text("fake video content")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            rate_limit_enabled=True,
            rate_limit_per_minute=2,
            stream_rate_limit_per_minute=3,
        )
        server = MediaRelayServer(config)
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        auth_header = {"Authorization": f"Basic {credentials}"}

        with server.app.test_client() as client:
            for _ in range(3):
                response = client.get("/stream/test.mp4", headers=auth_header)
                assert response.status_code == 200

            assert (
                client.get("/stream/test.mp4", headers=auth_header).status_code == 429
            )

            for _ in range(5):
                assert client.get("/health").status_code == 200

            assert client.get("/", headers=auth_header).status_code == 200
            assert client.get("/", headers=auth_header).status_code == 200
            assert client.get("/", headers=auth_header).status_code == 429

    def test_bad_request_error_handler(self, media_relay_server):
        """Test 400 error handler"""
        with media_relay_server.app.test_request_context():
            result = media_relay_server.app.handle_http_exception(BadRequest())
            if isinstance(result, tuple):
                message, status = result
                assert status == 400
                assert "Bad Request" in message

    def test_unauthorized_error_handler(self, media_relay_server):
        """Test 401 error handler"""
        with media_relay_server.app.test_request_context():
            result = media_relay_server.app.handle_http_exception(Unauthorized())
            if isinstance(result, tuple):
                response, status = result
                assert status == 401
                assert response.status_code == 401

    def test_forbidden_error_handler(self, media_relay_server):
        """Test 403 error handler"""
        media_relay_server.security_logger = MagicMock()
        with media_relay_server.app.test_request_context("/secret"):
            result = media_relay_server.app.handle_http_exception(Forbidden())
            if isinstance(result, tuple):
                message, status = result
                assert status == 403
                assert "Forbidden" in message
        media_relay_server.security_logger.log_security_violation.assert_called()

    def test_rate_limit_key_uses_proxy_ip(self, tmp_path):
        """Rate limiter key honors X-Forwarded-For when behind_proxy is enabled."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            behind_proxy=True,
            proxy_trusted=True,
            rate_limit_enabled=True,
            rate_limit_per_minute=60,
        )
        server = MediaRelayServer(config)
        with server.app.test_request_context(
            "/health", headers={"X-Forwarded-For": "203.0.113.50"}
        ):
            assert server._rate_limit_key() == "203.0.113.50"

    def test_lockout_cleanup_timer_invokes_cleanup(self, tmp_path):
        """Lockout cleanup callback removes expired entries."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir), password_hash=TEST_PASSWORD_HASH
        )
        server = MediaRelayServer(config)
        server.lockout_manager.record_failed_attempt("127.0.0.1", "user")
        server.lockout_manager._trackers["127.0.0.1:user"].last_attempt = (
            0  # noqa: SLF001
        )

        start_calls = 0

        def make_timer(_interval: float, callback: object) -> MagicMock:
            mock = MagicMock()

            def start() -> None:
                nonlocal start_calls
                start_calls += 1
                if start_calls == 1 and callable(callback):
                    callback()

            mock.start = start
            return mock

        with patch("mediarelay.server.threading.Timer", side_effect=make_timer):
            server._start_lockout_cleanup()

        assert server.lockout_manager.get_failed_attempts("127.0.0.1", "user") == 0


class TestSessionCookieWiring:
    """Test session cookie configuration wiring"""

    def test_session_cookie_config_from_env(self, tmp_path, monkeypatch):
        """Session cookie settings from config are applied to Flask"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "false")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            log_directory=str(tmp_path / "logs"),
            session_cookie_secure=False,
            session_cookie_httponly=False,
            session_cookie_samesite="Lax",
        )
        server = MediaRelayServer(config)

        assert server.app.config["SESSION_COOKIE_SECURE"] is False
        assert server.app.config["SESSION_COOKIE_HTTPONLY"] is False
        assert server.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


class TestCLIConfigFile:
    """Test CLI --config-file option"""

    def test_main_loads_config_file(self, tmp_path):
        """Main passes config file path to load_config"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        env_file = tmp_path / "custom.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n",
            encoding="utf-8",
        )

        with patch("mediarelay.server.load_config") as mock_load:
            mock_load.return_value = MagicMock(
                host="127.0.0.1",
                port=5000,
                debug=False,
                video_directory=str(video_dir),
            )
            with patch("mediarelay.server.MediaRelayServer") as mock_server:
                mock_server.return_value.run.side_effect = KeyboardInterrupt()
                runner = CliRunner()
                runner.invoke(
                    main,
                    ["--config-file", str(env_file)],
                )
                mock_load.assert_called_once_with(env_file)


class TestServerWarnings:
    """Tests for startup warning helpers."""

    def test_warn_ephemeral_secret_key_logs_warning(
        self, media_relay_server, monkeypatch
    ):
        """Warn when VIDEO_SERVER_SECRET_KEY is not set in environment."""
        monkeypatch.delenv("VIDEO_SERVER_SECRET_KEY", raising=False)
        with patch.object(media_relay_server.app.logger, "warning") as mock_warning:
            media_relay_server._warn_ephemeral_secret_key()
        mock_warning.assert_called_once()
        assert "VIDEO_SERVER_SECRET_KEY not set" in mock_warning.call_args[0][0]

    def test_warn_behind_proxy_logs_warning(self, media_relay_server):
        """Warn when reverse-proxy mode is enabled."""
        media_relay_server.config.behind_proxy = True
        with patch.object(media_relay_server.app.logger, "warning") as mock_warning:
            media_relay_server._warn_behind_proxy()
        mock_warning.assert_called_once()
        assert "VIDEO_SERVER_BEHIND_PROXY is enabled" in mock_warning.call_args[0][0]

    def test_warn_non_production_logs_warning(self, media_relay_server, monkeypatch):
        """Warn when VIDEO_SERVER_PRODUCTION is not enabled."""
        monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "false")
        with patch.object(media_relay_server.app.logger, "warning") as mock_warning:
            media_relay_server._warn_non_production()
        mock_warning.assert_called_once()
        assert "VIDEO_SERVER_PRODUCTION is not enabled" in mock_warning.call_args[0][0]

    def test_warn_non_production_silent_in_production(self, media_relay_server):
        """No warning when production mode is enabled on the config snapshot."""
        media_relay_server.config.production = True
        with patch.object(media_relay_server.app.logger, "warning") as mock_warning:
            media_relay_server._warn_non_production()
        mock_warning.assert_not_called()

    def test_warn_legacy_flask_env_logs_warning(self, media_relay_server, monkeypatch):
        """Warn when deprecated FLASK_ENV is still set."""
        monkeypatch.setenv("FLASK_ENV", "production")
        with patch.object(media_relay_server.app.logger, "warning") as mock_warning:
            media_relay_server._warn_legacy_flask_env()
        mock_warning.assert_called_once()
        assert "FLASK_ENV is deprecated" in mock_warning.call_args[0][0]


class TestMainCliOptions:
    """Tests for mediarelay CLI flags."""

    @patch("mediarelay.server.MediaRelayServer")
    @patch("mediarelay.server.load_config")
    @patch("mediarelay.server.create_sample_env_file")
    def test_main_generate_config(
        self, mock_create_env, mock_load_config, mock_server_class
    ):
        """--generate-config writes sample env and exits."""
        runner = CliRunner()
        result = runner.invoke(main, ["--generate-config"])
        assert result.exit_code == 0
        mock_create_env.assert_called_once()
        mock_load_config.assert_not_called()
        mock_server_class.assert_not_called()

    @patch("mediarelay.server.MediaRelayServer")
    @patch("mediarelay.server.load_config")
    def test_main_host_port_debug_overrides(
        self, mock_load_config, mock_server_class, monkeypatch
    ):
        """CLI host, port, and debug flags override loaded config."""
        mock_config = MagicMock()
        mock_config.is_production.return_value = False
        mock_load_config.return_value = mock_config
        mock_server = MagicMock()
        mock_server_class.return_value = mock_server

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--host", "10.0.0.1", "--port", "9000", "--debug"],
        )
        assert result.exit_code == 0
        assert mock_config.host == "10.0.0.1"
        assert mock_config.port == 9000
        assert mock_config.debug is True

    @patch("mediarelay.server.MediaRelayServer")
    @patch("mediarelay.server.load_config")
    def test_main_debug_in_production_rejected(
        self, mock_load_config, mock_server_class
    ):
        """--debug with VIDEO_SERVER_PRODUCTION=true is rejected."""
        mock_config = MagicMock()
        mock_config.is_production.return_value = True
        mock_load_config.return_value = mock_config

        runner = CliRunner()
        result = runner.invoke(main, ["--debug"])
        assert result.exit_code == 1
        assert "Cannot enable --debug" in result.output
        mock_server_class.assert_not_called()


class TestGracefulShutdown:
    """Tests for signal-driven shutdown and resource cleanup."""

    @patch("mediarelay.server.serve")
    def test_shutdown_cleanup_called_on_keyboard_interrupt(self, mock_serve):
        """finally block runs cleanup after KeyboardInterrupt."""
        mock_serve.side_effect = KeyboardInterrupt()

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)
            with patch.object(server, "_shutdown_cleanup") as mock_cleanup:
                server.run()
            mock_cleanup.assert_called_once()

    @patch("mediarelay.server.serve")
    def test_lockout_cleanup_timer_started(self, mock_serve):
        """Lockout cleanup timer is scheduled when server starts."""
        mock_serve.side_effect = KeyboardInterrupt()

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)
            with patch.object(server, "_start_lockout_cleanup") as mock_start:
                with patch.object(server, "_shutdown_cleanup"):
                    server.run()
            mock_start.assert_called_once()

    @patch("mediarelay.server.serve")
    def test_signal_handler_raises_keyboard_interrupt(self, mock_serve):
        """SIGINT handler should raise KeyboardInterrupt to stop Waitress."""
        shutdown_handler: object = None

        def capture_signal(signum: int, handler: object) -> None:
            nonlocal shutdown_handler
            if signum == signal.SIGINT:
                shutdown_handler = handler

        def invoke_handler_from_serve(*_args: object, **_kwargs: object) -> None:
            assert shutdown_handler is not None
            with pytest.raises(KeyboardInterrupt):
                shutdown_handler(signal.SIGINT, None)  # type: ignore[operator]

        mock_serve.side_effect = invoke_handler_from_serve

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)
            with patch("mediarelay.server.signal.signal", side_effect=capture_signal):
                with patch.object(server, "_shutdown_cleanup"):
                    server.run()

    @patch("mediarelay.server.serve")
    def test_sigterm_handler_raises_keyboard_interrupt(self, mock_serve):
        """SIGTERM handler should raise KeyboardInterrupt to stop Waitress."""
        shutdown_handler: object = None

        def capture_signal(signum: int, handler: object) -> None:
            nonlocal shutdown_handler
            if signum == signal.SIGTERM:
                shutdown_handler = handler

        def invoke_handler_from_serve(*_args: object, **_kwargs: object) -> None:
            assert shutdown_handler is not None
            with pytest.raises(KeyboardInterrupt):
                shutdown_handler(signal.SIGTERM, None)  # type: ignore[operator]

        mock_serve.side_effect = invoke_handler_from_serve

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)
            with patch("mediarelay.server.signal.signal", side_effect=capture_signal):
                with patch.object(server, "_shutdown_cleanup"):
                    server.run()

    @patch("mediarelay.server.serve")
    def test_run_registers_sigint_only_when_sigterm_unavailable(self, mock_serve):
        """Only SIGINT is registered when SIGTERM is unavailable on the platform."""
        registered: list[int] = []
        real_hasattr = hasattr

        def capture_signal(signum: int, _handler: object) -> None:
            registered.append(signum)

        def fake_hasattr(obj: object, name: str) -> bool:
            if obj is signal and name == "SIGTERM":
                return False
            return real_hasattr(obj, name)

        mock_serve.side_effect = KeyboardInterrupt()

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH
            )
            server = MediaRelayServer(config)
            with (
                patch("builtins.hasattr", side_effect=fake_hasattr),
                patch("mediarelay.server.signal.signal", side_effect=capture_signal),
                patch.object(server, "_shutdown_cleanup"),
            ):
                server.run()

        assert registered == [signal.SIGINT]

    def test_stream_revalidation_failure_returns_404(self, authenticated_client):
        """Stream returns 404 when validated file open fails (TOCTOU)."""
        with patch("mediarelay.handlers.open_validated_file", return_value=None):
            response = authenticated_client.get("/stream/test_video.mp4")
        assert response.status_code == 404

    def test_behind_proxy_trusted_logs_info(self, server_config: ServerConfig) -> None:
        """Info log when both proxy flags are enabled."""
        server_config.behind_proxy = True
        server_config.proxy_trusted = True
        server = MediaRelayServer(server_config)
        with patch.object(server.app.logger, "info") as mock_info:
            server._warn_behind_proxy()
        server._shutdown_cleanup()
        mock_info.assert_called_once()
        assert "VIDEO_SERVER_PROXY_TRUSTED are enabled" in mock_info.call_args[0][0]

    def test_lockout_cleanup_reschedules_after_failure(self, server_config):
        """Lockout cleanup timer reschedules even when cleanup_expired fails."""
        server = MediaRelayServer(server_config)
        with patch.object(
            server.lockout_manager,
            "cleanup_expired",
            side_effect=RuntimeError("cleanup failed"),
        ):
            with patch.object(
                server, "_schedule_next_lockout_cleanup"
            ) as mock_schedule:
                server._run_lockout_cleanup()
        mock_schedule.assert_called_once()

    def test_stop_lockout_cleanup_without_active_timer(self, server_config):
        """Stopping lockout cleanup is safe when no timer is scheduled."""
        server = MediaRelayServer(server_config)
        server._lockout_cleanup_timer = None
        server._stop_lockout_cleanup()

    def test_shutdown_cleanup_without_logging_components(self, server_config):
        """Shutdown is safe when logging components were never initialized."""
        server = MediaRelayServer(server_config)
        server._logging_components = None
        server._shutdown_cleanup()


class TestVideoMimeTypeInPlayer:
    """Tests that the HTML player receives correct MIME types."""

    def test_mkv_player_uses_matroska_mime(self, authenticated_client):
        """MKV files should use video/x-matroska in the player."""
        response = authenticated_client.get("/test_video.mkv")
        assert response.status_code == 200
        assert 'type="video/x-matroska"' in response.get_data(as_text=True)

    def test_mp3_player_uses_audio_element(self, authenticated_client, temp_video_dir):
        """MP3 files should render an audio player, not a video element."""
        audio_file = temp_video_dir / "track.mp3"
        audio_file.write_text("fake audio", encoding="utf-8")

        response = authenticated_client.get("/track.mp3")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "<audio controls" in html
        assert "<video controls" not in html
        assert 'type="audio/mpeg"' in html


class TestProductionAuditFixes:
    """Tests for production audit remediation."""

    def test_response_includes_request_id_header(self, flask_client):
        response = flask_client.get("/health")
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) == 16

    def test_index_response_has_no_store_cache_control(self, authenticated_client):
        response = authenticated_client.get("/")
        assert response.status_code == 200
        assert response.headers.get("Cache-Control") == "no-store"
        assert response.headers.get("Pragma") == "no-cache"

    def test_stream_response_has_private_no_store_cache_control(
        self, authenticated_client, temp_video_dir
    ):
        response = authenticated_client.get("/stream/test_video.mp4")
        assert response.status_code == 200
        assert response.headers.get("Cache-Control") == "private, no-store"
        assert response.headers.get("Pragma") == "no-cache"

    def test_logout_uses_log_logout(self, media_relay_server, server_config):
        media_relay_server.security_logger = MagicMock()

        with media_relay_server.app.test_client() as client:
            csrf_token = authenticate_client(client, server_config.username, "testpass")
            client.post("/logout", headers={"X-CSRF-Token": csrf_token})

        media_relay_server.security_logger.log_logout.assert_called_once()

    def test_health_video_directory_accessible_reflects_runtime(
        self, authenticated_client
    ):
        response = authenticated_client.get("/health")
        data = json.loads(response.data)
        assert data["video_directory_accessible"] is True

    def test_check_authentication_lockout_logs_violation(
        self, media_relay_server, server_config
    ):
        media_relay_server.security_logger = MagicMock()
        media_relay_server.lockout_manager = AccountLockoutManager(
            max_attempts=1, lockout_duration=60
        )
        media_relay_server.lockout_manager.record_failed_attempt(
            "127.0.0.1", "testuser"
        )

        credentials = base64.b64encode(b"testuser:wrong").decode("utf-8")
        with media_relay_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {credentials}"})

        media_relay_server.security_logger.log_security_violation.assert_called()
        assert "account_lockout" in str(
            media_relay_server.security_logger.log_security_violation.call_args
        )

    def test_subtitle_track_when_srt_exists(
        self, media_relay_server, server_config, temp_video_dir, authenticated_client
    ):
        video = temp_video_dir / "captioned.mp4"
        video.write_text("video", encoding="utf-8")
        srt = temp_video_dir / "captioned.srt"
        srt.write_text("subtitle", encoding="utf-8")

        response = authenticated_client.get("/captioned.mp4")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'kind="subtitles"' in html
        assert "/stream/captioned.srt" in html

    def test_subtitle_track_when_vtt_exists(
        self, media_relay_server, server_config, temp_video_dir, authenticated_client
    ):
        video = temp_video_dir / "webvtt_video.mp4"
        video.write_text("video", encoding="utf-8")
        vtt = temp_video_dir / "webvtt_video.vtt"
        vtt.write_text("WEBVTT\n", encoding="utf-8")

        response = authenticated_client.get("/webvtt_video.mp4")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'kind="subtitles"' in html
        assert "/stream/webvtt_video.vtt" in html
        assert "/stream/webvtt_video.srt" not in html

    def test_subtitle_prefers_vtt_over_srt(
        self, media_relay_server, server_config, temp_video_dir, authenticated_client
    ):
        video = temp_video_dir / "dual_caption.mp4"
        video.write_text("video", encoding="utf-8")
        (temp_video_dir / "dual_caption.srt").write_text("srt", encoding="utf-8")
        (temp_video_dir / "dual_caption.vtt").write_text("WEBVTT\n", encoding="utf-8")

        response = authenticated_client.get("/dual_caption.mp4")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "/stream/dual_caption.vtt" in html
        assert "/stream/dual_caption.srt" not in html

    def test_api_files_rejects_file_path(self, authenticated_client, temp_video_dir):
        response = authenticated_client.get("/api/files?path=test_video.mp4")
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "Path is not a directory"

    def test_not_found_handler_logs_warning(self, media_relay_server):
        with media_relay_server.app.test_request_context("/missing"):
            g.request_id = "abcd1234"
            with patch.object(media_relay_server.app.logger, "warning") as mock_warning:
                media_relay_server.app.handle_user_exception(NotFound())
                mock_warning.assert_called_once()
                assert "missing" in str(mock_warning.call_args)
                assert "abcd1234" in str(mock_warning.call_args)

    def test_directory_pagination_html(
        self, authenticated_client, media_relay_server, temp_video_dir
    ):
        media_relay_server.config.page_size = 10
        listing_dir = temp_video_dir / "pagination_test"
        listing_dir.mkdir()
        for i in range(25):
            (listing_dir / f"page_item_{i:02d}.mp4").write_text("x")

        page_one = authenticated_client.get("/pagination_test")
        assert page_one.status_code == 200
        html_one = page_one.get_data(as_text=True)
        assert "Showing 1&ndash;10 of" in html_one or "Showing 1–10 of" in html_one
        assert "page_item_09.mp4" in html_one
        assert "page_item_15.mp4" not in html_one
        assert "Next" in html_one

        page_two = authenticated_client.get("/pagination_test?page=2")
        assert page_two.status_code == 200
        html_two = page_two.get_data(as_text=True)
        assert "page_item_15.mp4" in html_two

    def test_directory_pagination_api(
        self, authenticated_client, media_relay_server, temp_video_dir
    ):
        media_relay_server.config.page_size = 5
        listing_dir = temp_video_dir / "api_pagination"
        listing_dir.mkdir()
        for i in range(12):
            (listing_dir / f"api_item_{i:02d}.mp4").write_text("x")

        response = authenticated_client.get("/api/files?path=api_pagination&page=2")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["page"] == 2
        assert data["page_size"] == 5
        assert data["total_items"] == 12
        assert data["total_pages"] == 3
        assert len(data["files"]) == 5

    def test_invalid_page_parameter_returns_400(self, authenticated_client):
        response = authenticated_client.get("/?page=0")
        assert response.status_code == 400

        response = authenticated_client.get("/?page=abc")
        assert response.status_code == 400

    def test_api_invalid_page_parameter_returns_400(self, authenticated_client):
        response = authenticated_client.get("/api/files?page=abc")
        assert response.status_code == 400

        response = authenticated_client.get("/api/files?page=0")
        assert response.status_code == 400

    def test_page_beyond_last_returns_empty_slice(
        self, authenticated_client, media_relay_server, temp_video_dir
    ):
        media_relay_server.config.page_size = 10
        listing_dir = temp_video_dir / "beyond_last"
        listing_dir.mkdir()
        (listing_dir / "only.mp4").write_text("x")

        response = authenticated_client.get("/beyond_last?page=99")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "only.mp4" not in html

    def test_behind_proxy_wraps_wsgi_app_with_proxyfix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", TEST_PASSWORD_HASH)
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv("VIDEO_SERVER_BEHIND_PROXY", "true")
        monkeypatch.setenv("VIDEO_SERVER_PROXY_TRUSTED", "true")
        monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "false")

        server = MediaRelayServer(ServerConfig())
        assert type(server.app.wsgi_app).__name__ == "ProxyFix"

    def test_proxyfix_not_applied_when_proxy_untrusted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", TEST_PASSWORD_HASH)
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv("VIDEO_SERVER_BEHIND_PROXY", "true")
        monkeypatch.setenv("VIDEO_SERVER_PROXY_TRUSTED", "false")
        monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "false")

        server = MediaRelayServer(ServerConfig())
        assert type(server.app.wsgi_app).__name__ != "ProxyFix"
        server._shutdown_cleanup()

    def test_rate_limit_response_includes_retry_after(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            username="testuser",
            rate_limit_enabled=True,
            rate_limit_per_minute=1,
        )
        server = MediaRelayServer(config)
        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        auth_header = {"Authorization": f"Basic {credentials}"}
        with server.app.test_client() as client:
            assert client.get("/health").status_code == 200
            assert client.get("/", headers=auth_header).status_code == 200
            response = client.get("/")
        assert response.status_code == 429
        assert response.headers.get("Retry-After") == "60"
        server._shutdown_cleanup()


class TestProductionServerSmoke:
    """Smoke tests for production-mode server startup and readiness."""

    def test_production_server_starts_and_reports_readiness(
        self, production_server_config: ServerConfig
    ) -> None:
        server = MediaRelayServer(production_server_config)
        credentials = base64.b64encode(
            f"{production_server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with server.app.test_client() as client:
            liveness = client.get("/health")
            assert liveness.status_code == 200
            assert json.loads(liveness.data)["status"] == "ok"

            readiness = client.get(
                "/health",
                headers={"Authorization": f"Basic {credentials}"},
            )
            assert readiness.status_code == 200
            data = json.loads(readiness.data)
            assert data["status"] == "healthy"
            assert "version" in data
            assert data["video_directory_accessible"] is True

        server._shutdown_cleanup()
