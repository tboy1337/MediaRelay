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
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from click.testing import CliRunner
from flask import session
from werkzeug.security import generate_password_hash

from mediarelay.config import ServerConfig
from mediarelay.handlers import handle_index_request
from mediarelay.lockout import AccountLockoutManager
from mediarelay.server import MediaRelayServer, main
from mediarelay.templates import INDEX_HTML_TEMPLATE


class TestMediaRelayServer:
    """Test cases for MediaRelayServer initialization and configuration"""

    def test_server_initialization(self, test_config):
        """Test server initialization with configuration"""
        server = MediaRelayServer(test_config)

        assert server.config == test_config
        assert server.app is not None
        assert server.security_logger is not None
        assert server.performance_logger is not None

    def test_flask_app_configuration(self, test_server):
        """Test Flask app configuration"""
        app = test_server.app

        assert app.config["TESTING"] is False  # Will be set by test client
        expected_max_length = (
            None
            if test_server.config.max_file_size <= 0
            else test_server.config.max_file_size
        )
        assert app.config["MAX_CONTENT_LENGTH"] == expected_max_length
        assert app.secret_key == test_server.config.secret_key

    def test_security_configuration(self, test_server):
        """Test security-related configuration"""
        app = test_server.app

        assert app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"
        assert (
            app.config["PERMANENT_SESSION_LIFETIME"]
            == test_server.config.session_timeout
        )

    def test_rate_limiting_enabled(self, test_config):
        """Test rate limiting when enabled"""
        test_config.rate_limit_enabled = True
        server = MediaRelayServer(test_config)

        assert hasattr(server, "limiter")
        assert server.limiter is not None

    def test_rate_limiting_disabled(self, test_config):
        """Test rate limiting when disabled"""
        test_config.rate_limit_enabled = False
        server = MediaRelayServer(test_config)

        assert server.limiter is None


class TestMediaRelayServerComprehensive:
    """Comprehensive tests for complete coverage of MediaRelayServer"""

    def test_server_initialization_with_all_features(self):
        """Test server initialization with all features enabled"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(os.environ, {"FLASK_ENV": "development"}):
                config = ServerConfig(
                    video_directory=temp_dir,
                    password_hash="test_hash",
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
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            server = MediaRelayServer(config)
            assert server.limiter is None

    def test_get_html_template_method(self, test_server):
        """Test _get_html_template method"""
        template = INDEX_HTML_TEMPLATE

        assert "<!DOCTYPE html>" in template
        assert "Video Streaming Server" in template
        assert "<video controls" in template
        assert "<audio controls" in template
        assert "breadcrumb" in template

    def test_handle_index_request_comprehensive(self, test_server, temp_video_dir):
        """Test _handle_index_request method comprehensively"""
        # Create test files
        video_file = temp_video_dir / "test.mp4"
        video_file.write_text("fake video content")

        subdir = temp_video_dir / "subdir"
        subdir.mkdir(exist_ok=True)

        non_video_file = temp_video_dir / "document.txt"
        non_video_file.write_text("not a video")

        with test_server.app.test_request_context():
            with patch.object(test_server, "check_authentication", return_value=True):
                # Test directory listing
                result = handle_index_request(test_server, "")
                assert isinstance(result, str)
                assert "test.mp4" in result or "Video Streaming Server" in result

                # Test video file display
                result = handle_index_request(test_server, "test.mp4")
                assert isinstance(result, str)
                assert "test.mp4" in result

                # Test non-video file (should return 400)
                result = handle_index_request(test_server, "document.txt")
                assert result == ("Not a video file", 400)

                # Test non-existent path
                result = handle_index_request(test_server, "nonexistent.mp4")
                assert result == ("Path not found", 404)

    def test_handle_index_request_without_auth(self, test_server):
        """Test _handle_index_request without authentication"""
        with test_server.app.test_request_context():
            with patch.object(test_server, "check_authentication", return_value=False):
                result = handle_index_request(test_server, "")
                assert result.status_code == 401


class TestAuthentication:
    """Test cases for authentication functionality"""

    def test_check_auth_valid_credentials(self, test_server, test_config):
        """Test authentication with valid credentials"""
        with test_server.app.test_request_context():
            result = test_server.check_auth(test_config.username, "testpass")
            assert result is True

    def test_check_auth_invalid_username(self, test_server):
        """Test authentication with invalid username"""
        with test_server.app.test_request_context():
            result = test_server.check_auth("wronguser", "testpass")
            assert result is False

    def test_check_auth_invalid_password(self, test_server, test_config):
        """Test authentication with invalid password"""
        with test_server.app.test_request_context():
            result = test_server.check_auth(test_config.username, "wrongpass")
            assert result is False

    def test_check_auth_empty_credentials(self, test_server):
        """Test authentication with empty credentials"""
        with test_server.app.test_request_context():
            result = test_server.check_auth("", "")
            assert result is False

            result = test_server.check_auth("user", "")
            assert result is False

            result = test_server.check_auth("", "pass")
            assert result is False

    def test_check_authentication_with_session(self, test_server):
        """Test authentication check with valid session"""
        with test_server.app.test_request_context(
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
        ):
            session["authenticated"] = True
            session["last_activity"] = time.time()
            session["login_time"] = time.time()
            session["login_ip"] = "127.0.0.1"
            session["username"] = test_server.config.username
            assert test_server.check_authentication() is True

    def test_check_authentication_http_auth(self, test_server, test_config):
        """Test authentication check with HTTP Basic Auth"""
        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with test_server.app.test_request_context(
            headers={"Authorization": f"Basic {credentials}"}
        ):
            assert test_server.check_authentication() is True

    def test_check_auth_method_coverage(self):
        """Test check_auth method with various scenarios"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Use a real password hash for testing
            from werkzeug.security import generate_password_hash

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

    def test_get_safe_path_normal(self, test_server, temp_video_dir):
        """Test safe path handling with normal paths"""
        with test_server.app.test_request_context():
            safe_path = test_server.get_safe_path("test_video.mp4")
            expected_path = temp_video_dir / "test_video.mp4"
            assert safe_path == expected_path

    def test_get_safe_path_empty(
        self, test_server, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test safe path handling with empty path"""
        with test_server.app.test_request_context():
            safe_path = test_server.get_safe_path("")
            assert safe_path == Path(test_server.config.video_directory)

    def test_get_safe_path_none(
        self, test_server, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test safe path handling with None path"""
        with test_server.app.test_request_context():
            safe_path = test_server.get_safe_path(None)
            assert safe_path == Path(test_server.config.video_directory)

    def test_path_traversal_protection(self, test_server, security_test_payloads):
        """Test protection against path traversal attacks"""
        with test_server.app.test_request_context():
            for payload in security_test_payloads["path_traversal"]:
                safe_path = test_server.get_safe_path(payload)
                assert safe_path is None

    def test_get_safe_path_comprehensive_edge_cases(self, test_server):
        """Test get_safe_path with comprehensive edge cases"""
        with test_server.app.test_request_context():
            # Test with None
            result = test_server.get_safe_path(None)
            assert result == Path(test_server.config.video_directory)

            # Test with empty string
            result = test_server.get_safe_path("")
            assert result == Path(test_server.config.video_directory)

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
                result = test_server.get_safe_path(path)
                assert result is None


class TestDirectoryListing:
    """Test cases for directory listing functionality"""

    def test_breadcrumbs_generation(self, test_server, temp_video_dir):
        """Test breadcrumb navigation generation"""
        subdir_path = temp_video_dir / "subdir"
        breadcrumbs = test_server.get_breadcrumbs(subdir_path)

        assert len(breadcrumbs) >= 1
        assert breadcrumbs[0]["name"] == "Home"
        assert breadcrumbs[0]["path"] == "/"

        # Should include subdirectory
        assert any(crumb["name"] == "subdir" for crumb in breadcrumbs)

    def test_breadcrumbs_root_directory(self, test_server, temp_video_dir):
        """Test breadcrumbs for root directory"""
        breadcrumbs = test_server.get_breadcrumbs(temp_video_dir)

        assert len(breadcrumbs) == 1
        assert breadcrumbs[0]["name"] == "Home"

    def test_breadcrumbs_comprehensive(self, test_server, temp_video_dir):
        """Test get_breadcrumbs method comprehensively"""
        # Test root directory
        crumbs = test_server.get_breadcrumbs(temp_video_dir)
        assert len(crumbs) == 1
        assert crumbs[0]["name"] == "Home"

        # Test subdirectory
        subdir = temp_video_dir / "subdir" / "nested"
        subdir.mkdir(parents=True)
        crumbs = test_server.get_breadcrumbs(subdir)
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

    def test_directory_listing_without_auth(self, test_client):
        """Test directory listing without authentication"""
        response = test_client.get("/")

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
    def test_stream_video_without_auth(self, test_client):
        """Test streaming video without authentication"""
        response = test_client.get("/stream/test_video.mp4")

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

    @pytest.mark.parametrize(
        "subpath,expected_names",
        [
            ("", {"Home"}),
            ("subdir", {"Home", "subdir"}),
        ],
    )
    def test_breadcrumbs_for_paths(self, test_server, subpath, expected_names):
        """Test breadcrumb generation stays within the video directory"""
        with test_server.app.test_request_context():
            if subpath:
                safe_path = test_server.get_safe_path(subpath)
            else:
                safe_path = Path(test_server.config.video_directory)

            assert safe_path is not None
            crumbs = test_server.get_breadcrumbs(safe_path)
            crumb_names = {crumb["name"] for crumb in crumbs}
            assert crumb_names == expected_names


class TestAPIEndpoints:
    """Test cases for API endpoints"""

    def test_health_check_endpoint(self, test_client):
        """Test health check endpoint (unauthenticated - minimal info)"""
        response = test_client.get("/health")

        assert response.status_code in [200, 503]
        data = json.loads(response.data)

        # Unauthenticated requests should only get status
        assert data["status"] in ["healthy", "unhealthy"]

    def test_health_check_endpoint_authenticated(self, authenticated_client):
        """Test health check endpoint with authentication (detailed info)"""
        response = authenticated_client.get("/health")

        assert response.status_code in [200, 503]
        data = json.loads(response.data)

        # Authenticated requests should get full details
        assert data["status"] in ["healthy", "unhealthy"]
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
        assert "total_files" in data
        assert isinstance(data["files"], list)

    def test_api_files_endpoint_without_auth(self, test_client):
        """Test API files endpoint without authentication"""
        response = test_client.get("/api/files")

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

    def test_health_check_healthy_unauthenticated(self, test_server):
        """Test health check when healthy (unauthenticated - minimal info)"""
        with test_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=True):
                with patch("os.access", return_value=True):
                    response = client.get("/health")
                    assert response.status_code == 200

                    data = json.loads(response.data)
                    assert data["status"] == "healthy"
                    # Unauthenticated should not get detailed info
                    assert "timestamp" not in data

    def test_health_check_unhealthy(self, test_server):
        """Test health check when video directory is not accessible"""
        with test_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=False):
                response = client.get("/health")
                assert response.status_code == 503

                data = json.loads(response.data)
                assert data["status"] == "unhealthy"

    def test_health_check_exception(self, test_server):
        """Test health check with exception"""
        with test_server.app.test_client() as client:
            with patch.object(Path, "exists", side_effect=OSError("Test error")):
                response = client.get("/health")
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
        """Test bad request error handling"""
        # Try to view a non-video file as video player
        response = authenticated_client.get("/invalid_file.txt")

        assert response.status_code == 400
        assert b"Not a video file" in response.data

    def test_session_timeout_handling(self, test_server):
        """Test session timeout and clearing logic"""
        with test_server.app.test_client() as client:
            with client.session_transaction() as sess:
                # Set up an expired session
                sess["authenticated"] = True
                sess["last_activity"] = time.time() - (
                    test_server.config.session_timeout + 100
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
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", "test_hash")
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
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", "test_hash")
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(log_dir))

        config = ServerConfig()
        server = MediaRelayServer(config)
        try:
            assert server.app.config["MAX_CONTENT_LENGTH"] is None
        finally:
            server._shutdown_cleanup()


class TestSecurityHeaders:
    """Test cases for security headers"""

    def test_security_headers_applied(self, test_client, test_config):
        """Test that security headers are applied to all responses"""
        response = test_client.get("/health")

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

        if test_config.session_cookie_secure:
            assert "Strict-Transport-Security" in response.headers
        else:
            assert "Strict-Transport-Security" not in response.headers

    def test_content_security_policy(self, test_client):
        """Test Content Security Policy header"""
        response = test_client.get("/health")

        csp = response.headers.get("Content-Security-Policy")
        assert "default-src 'self'" in csp
        assert "media-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp


class TestSessionManagement:
    """Test cases for session management"""

    def test_session_creation_on_auth(self, test_server, test_config):
        """Test session creation on successful authentication"""
        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with test_server.app.test_client() as client:
            response = client.get(
                "/", headers={"Authorization": f"Basic {credentials}"}
            )

            assert response.status_code == 200

            # Session should be created
            with client.session_transaction() as sess:
                assert sess.get("authenticated") is True
                assert sess.get("username") == test_config.username
                assert "last_activity" in sess

    def test_session_persistence(self, test_server, test_config):
        """Test session persistence across requests"""
        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with test_server.app.test_client() as client:
            # First request with auth
            client.get("/", headers={"Authorization": f"Basic {credentials}"})

            # Second request without auth should work due to session
            response = client.get("/")
            assert response.status_code == 200

    def test_session_timeout(self, test_server):
        """Test session timeout functionality"""
        with test_server.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["authenticated"] = True
                sess["last_activity"] = (
                    time.time() - test_server.config.session_timeout - 1
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


class TestServerRunMethod:
    """Test the server run method comprehensively"""

    @patch("mediarelay.server.serve")
    @patch("builtins.print")
    def test_run_method_successful_start(self, mock_print, mock_serve):
        """Test successful server start"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
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
            config = ServerConfig(video_directory=temp_dir, password_hash="test_hash")
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
            config = ServerConfig(video_directory=temp_dir, password_hash="test_hash")
            server = MediaRelayServer(config)

            with pytest.raises(RuntimeError):
                server.run()


@pytest.mark.timeout(30)
class TestPerformance:
    """Performance tests for the streaming server"""

    def test_large_directory_listing(self, authenticated_client, temp_video_dir):
        """Test performance with large directory listings"""
        # Create many test files
        for i in range(100):
            (temp_video_dir / f"test_video_{i:03d}.mp4").write_text(f"fake content {i}")

        start_time = time.time()
        response = authenticated_client.get("/")
        end_time = time.time()

        assert response.status_code == 200
        assert end_time - start_time < 10.0


class TestRequestLogging:
    """Test cases for request logging and monitoring"""

    def test_request_id_generation(self, test_server):
        """Test request ID generation"""
        with test_server.app.test_request_context():
            with test_server.app.test_client() as client:
                response = client.get("/health")
                # Request should complete successfully
                assert response.status_code == 200

    def test_performance_logging(self, authenticated_client):
        """Test performance logging for requests"""
        response = authenticated_client.get("/")

        # Should complete without error
        assert response.status_code == 200
        # Performance metrics should be logged (tested in logging tests)

    def test_security_event_logging(self, test_client, security_test_payloads):
        """Test security event logging"""
        # Try path traversal attack
        response = test_client.get(
            f'/stream/{security_test_payloads["path_traversal"][0]}'
        )

        # Should be blocked and logged
        assert response.status_code == 401  # Unauthorized due to no auth

    def test_after_request_performance_logging(self, test_server):
        """Test performance logging in after_request handler"""
        from flask import g

        # Mock the performance logger
        test_server.performance_logger = MagicMock()

        with test_server.app.test_client() as client:
            with test_server.app.test_request_context("/test"):
                # Set up request context with start_time (this triggers performance logging)
                g.start_time = time.time() - 0.1  # 100ms ago
                g.request_id = "test_request_123"

                # Create and process a response
                response = test_server.app.make_response("test response")
                response.status_code = 200

                # Process the response (triggers after_request)
                processed_response = test_server.app.process_response(response)

                # Verify performance logging was called
                test_server.performance_logger.log_request_duration.assert_called_once()


class TestErrorHandlers:
    """Test custom HTTP error handlers"""

    def test_request_entity_too_large_handler(self, test_server):
        """Test 413 error handler"""
        from werkzeug.exceptions import RequestEntityTooLarge

        with test_server.app.test_request_context():
            result = test_server.app.handle_http_exception(RequestEntityTooLarge())
            if isinstance(result, tuple):
                message, status = result
                assert status == 413
                assert "File Too Large" in message
            else:
                assert result.status_code == 413

    def test_internal_error_handler(self, test_server):
        """Test 500 error handler via triggered exception"""

        @test_server.app.route("/test-500")  # type: ignore[untyped-decorator]
        def trigger_error() -> None:
            raise RuntimeError("intentional test failure")

        test_server.app.config["TESTING"] = True
        test_server.app.config["PROPAGATE_EXCEPTIONS"] = False

        with test_server.app.test_client() as client:
            response = client.get("/test-500")
            assert response.status_code == 500
            assert b"Internal Server Error" in response.data

    def test_rate_limit_error_handler(self, tmp_path):
        """Test 429 response when rate limit is exceeded"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            rate_limit_enabled=True,
            rate_limit_per_minute=1,
        )
        server = MediaRelayServer(config)
        server.security_logger = MagicMock()
        server.app.config["TESTING"] = True

        with server.app.test_client() as client:
            assert client.get("/health").status_code == 200
            response = client.get("/health")
            assert response.status_code == 429
            assert b"Rate Limit Exceeded" in response.data

    def test_stream_route_exempt_from_rate_limit(self, tmp_path: Path) -> None:
        """Stream endpoint is exempt from rate limiting to support range requests."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        (video_dir / "test.mp4").write_text("fake video content")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=generate_password_hash("testpass"),
            username="testuser",
            rate_limit_enabled=True,
            rate_limit_per_minute=2,
        )
        server = MediaRelayServer(config)
        server.app.config["TESTING"] = True

        credentials = base64.b64encode(b"testuser:testpass").decode("utf-8")
        auth_header = {"Authorization": f"Basic {credentials}"}

        with server.app.test_client() as client:
            for _ in range(5):
                response = client.get("/stream/test.mp4", headers=auth_header)
                assert response.status_code == 200

            assert client.get("/health").status_code == 200
            assert client.get("/health").status_code == 200
            assert client.get("/health").status_code == 429

    def test_bad_request_error_handler(self, test_server):
        """Test 400 error handler"""
        from werkzeug.exceptions import BadRequest

        with test_server.app.test_request_context():
            result = test_server.app.handle_http_exception(BadRequest())
            if isinstance(result, tuple):
                message, status = result
                assert status == 400
                assert "Bad Request" in message

    def test_unauthorized_error_handler(self, test_server):
        """Test 401 error handler"""
        from werkzeug.exceptions import Unauthorized

        with test_server.app.test_request_context():
            result = test_server.app.handle_http_exception(Unauthorized())
            if isinstance(result, tuple):
                response, status = result
                assert status == 401
                assert response.status_code == 401

    def test_forbidden_error_handler(self, test_server):
        """Test 403 error handler"""
        from werkzeug.exceptions import Forbidden

        test_server.security_logger = MagicMock()
        with test_server.app.test_request_context("/secret"):
            result = test_server.app.handle_http_exception(Forbidden())
            if isinstance(result, tuple):
                message, status = result
                assert status == 403
                assert "Forbidden" in message
        test_server.security_logger.log_security_violation.assert_called()

    def test_rate_limit_key_uses_proxy_ip(self, tmp_path):
        """Rate limiter key honors X-Forwarded-For when behind_proxy is enabled."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            behind_proxy=True,
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
        config = ServerConfig(video_directory=str(video_dir), password_hash="test_hash")
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
        monkeypatch.setenv("FLASK_ENV", "testing")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
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
        from click.testing import CliRunner

        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        env_file = tmp_path / "custom.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=test_hash\n"
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

    def test_warn_ephemeral_secret_key_logs_warning(self, test_server, monkeypatch):
        """Warn when VIDEO_SERVER_SECRET_KEY is not set in environment."""
        monkeypatch.delenv("VIDEO_SERVER_SECRET_KEY", raising=False)
        with patch.object(test_server.app.logger, "warning") as mock_warning:
            test_server._warn_ephemeral_secret_key()
        mock_warning.assert_called_once()
        assert "VIDEO_SERVER_SECRET_KEY not set" in mock_warning.call_args[0][0]

    def test_warn_behind_proxy_logs_warning(self, test_server):
        """Warn when reverse-proxy mode is enabled."""
        test_server.config.behind_proxy = True
        with patch.object(test_server.app.logger, "warning") as mock_warning:
            test_server._warn_behind_proxy()
        mock_warning.assert_called_once()
        assert "VIDEO_SERVER_BEHIND_PROXY is enabled" in mock_warning.call_args[0][0]


class TestMainCliOptions:
    """Tests for mediarelay CLI flags."""

    @patch("mediarelay.server.MediaRelayServer")
    @patch("mediarelay.server.load_config")
    @patch("mediarelay.server.create_sample_env_file")
    def test_main_generate_config(
        self, mock_create_env, mock_load_config, mock_server_class
    ):
        """--generate-config writes sample env and exits."""
        from click.testing import CliRunner

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
        from click.testing import CliRunner

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
        """--debug with FLASK_ENV=production is rejected."""
        from click.testing import CliRunner

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
            config = ServerConfig(video_directory=temp_dir, password_hash="test_hash")
            server = MediaRelayServer(config)
            with patch.object(server, "_shutdown_cleanup") as mock_cleanup:
                server.run()
            mock_cleanup.assert_called_once()

    @patch("mediarelay.server.serve")
    def test_lockout_cleanup_timer_started(self, mock_serve):
        """Lockout cleanup timer is scheduled when server starts."""
        mock_serve.side_effect = KeyboardInterrupt()

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(video_directory=temp_dir, password_hash="test_hash")
            server = MediaRelayServer(config)
            with patch.object(server, "_start_lockout_cleanup") as mock_start:
                with patch.object(server, "_shutdown_cleanup"):
                    server.run()
            mock_start.assert_called_once()

    @patch("mediarelay.server.serve")
    def test_signal_handler_raises_keyboard_interrupt(self, mock_serve):
        """SIGINT handler should raise KeyboardInterrupt to stop Waitress."""
        import signal as signal_module

        shutdown_handler: object = None

        def capture_signal(signum: int, handler: object) -> None:
            nonlocal shutdown_handler
            if signum == signal_module.SIGINT:
                shutdown_handler = handler

        def invoke_handler_from_serve(*_args: object, **_kwargs: object) -> None:
            assert shutdown_handler is not None
            with pytest.raises(KeyboardInterrupt):
                shutdown_handler(signal_module.SIGINT, None)  # type: ignore[operator]

        mock_serve.side_effect = invoke_handler_from_serve

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(video_directory=temp_dir, password_hash="test_hash")
            server = MediaRelayServer(config)
            with patch("mediarelay.server.signal.signal", side_effect=capture_signal):
                with patch.object(server, "_shutdown_cleanup"):
                    server.run()

    def test_lockout_cleanup_reschedules_after_failure(self, test_config):
        """Lockout cleanup timer reschedules even when cleanup_expired fails."""
        server = MediaRelayServer(test_config)
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

    def test_stop_lockout_cleanup_without_active_timer(self, test_config):
        """Stopping lockout cleanup is safe when no timer is scheduled."""
        server = MediaRelayServer(test_config)
        server._lockout_cleanup_timer = None
        server._stop_lockout_cleanup()


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

    def test_response_includes_request_id_header(self, test_client):
        response = test_client.get("/health")
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

    def test_logout_uses_log_logout(self, test_server, test_config):
        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")
        test_server.security_logger = MagicMock()

        with test_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {credentials}"})
            client.post("/logout")

        test_server.security_logger.log_logout.assert_called_once()

    def test_health_config_valid_reflects_runtime(self, authenticated_client):
        response = authenticated_client.get("/health")
        data = json.loads(response.data)
        assert data["config_valid"] is True
        assert data["video_directory_accessible"] is True

    def test_check_authentication_lockout_logs_violation(
        self, test_server, test_config
    ):
        test_server.security_logger = MagicMock()
        test_server.lockout_manager = AccountLockoutManager(
            max_attempts=1, lockout_duration=60
        )
        test_server.lockout_manager.record_failed_attempt("127.0.0.1", "testuser")

        credentials = base64.b64encode(b"testuser:wrong").decode("utf-8")
        with test_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {credentials}"})

        test_server.security_logger.log_security_violation.assert_called()
        assert "account_lockout" in str(
            test_server.security_logger.log_security_violation.call_args
        )

    def test_subtitle_track_when_srt_exists(
        self, test_server, test_config, temp_video_dir, authenticated_client
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

    def test_api_files_rejects_file_path(self, authenticated_client, temp_video_dir):
        response = authenticated_client.get("/api/files?path=test_video.mp4")
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "Path is not a directory"

    def test_not_found_handler_logs_warning(self, test_server):
        from werkzeug.exceptions import NotFound

        with test_server.app.test_request_context("/missing"):
            from flask import g

            g.request_id = "abcd1234"
            with patch.object(test_server.app.logger, "warning") as mock_warning:
                test_server.app.handle_user_exception(NotFound())
                mock_warning.assert_called_once()
                assert "missing" in str(mock_warning.call_args)
                assert "abcd1234" in str(mock_warning.call_args)

    def test_directory_pagination_html(
        self, authenticated_client, test_server, temp_video_dir
    ):
        test_server.config.page_size = 10
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
        self, authenticated_client, test_server, temp_video_dir
    ):
        test_server.config.page_size = 5
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
        self, authenticated_client, test_server, temp_video_dir
    ):
        test_server.config.page_size = 10
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
        monkeypatch.setenv("VIDEO_SERVER_PASSWORD_HASH", "test_hash")
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv("VIDEO_SERVER_BEHIND_PROXY", "true")
        monkeypatch.setenv("FLASK_ENV", "testing")

        server = MediaRelayServer(ServerConfig())
        assert type(server.app.wsgi_app).__name__ == "ProxyFix"
