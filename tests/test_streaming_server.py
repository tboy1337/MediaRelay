"""
Integration tests for Video Streaming Server
-------------------------------------------
Comprehensive tests for the main streaming server functionality including
authentication, file serving, security, and API endpoints.
Includes comprehensive tests for 100% coverage.
"""

import base64
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import session

from config import ServerConfig
from streaming_server import MediaRelayServer, main


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
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
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
        template = test_server._get_html_template()

        assert "<!DOCTYPE html>" in template
        assert "Video Streaming Server" in template
        assert "<video controls" in template
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
            with patch.object(test_server, "_check_authentication", return_value=True):
                # Test directory listing
                result = test_server._handle_index_request("")
                assert isinstance(result, str)
                assert "test.mp4" in result or "Video Streaming Server" in result

                # Test video file display
                result = test_server._handle_index_request("test.mp4")
                assert isinstance(result, str)
                assert "test.mp4" in result

                # Test non-video file (should return 400)
                result = test_server._handle_index_request("document.txt")
                assert result == ("Not a video file", 400)

                # Test non-existent path
                result = test_server._handle_index_request("nonexistent.mp4")
                assert result == ("Path not found", 404)

    def test_handle_index_request_without_auth(self, test_server):
        """Test _handle_index_request without authentication"""
        with test_server.app.test_request_context():
            with patch.object(test_server, "_check_authentication", return_value=False):
                result = test_server._handle_index_request("")
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

    def test_requires_auth_decorator_with_session(self, test_server):
        """Test auth decorator with valid session"""

        @test_server.requires_auth
        def test_endpoint():
            return "success"

        with test_server.app.test_request_context():
            # Mock session data directly in g or flask context
            with test_server.app.test_request_context():
                session["authenticated"] = True
                session["last_activity"] = time.time()

                # Should allow access
                result = test_endpoint()
                assert result == "success"

    def test_requires_auth_decorator_http_auth(self, test_server, test_config):
        """Test auth decorator with HTTP Basic Auth"""

        @test_server.requires_auth
        def test_endpoint():
            return "success"

        credentials = base64.b64encode(
            f"{test_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with test_server.app.test_request_context(
            headers={"Authorization": f"Basic {credentials}"}
        ):
            result = test_endpoint()
            assert result == "success"

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
                assert server.check_auth("admin", "correct_password") == True

                # Test wrong password
                assert server.check_auth("admin", "wrong_password") == False

                # Test wrong username
                assert server.check_auth("wrong_user", "correct_password") == False

                # Test empty credentials
                assert server.check_auth("", "") == False
                assert server.check_auth(None, None) == False


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


class TestAPIEndpoints:
    """Test cases for API endpoints"""

    def test_health_check_endpoint(self, test_client):
        """Test health check endpoint"""
        response = test_client.get("/health")

        assert response.status_code == 200
        data = json.loads(response.data)

        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "version" in data
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

    def test_health_check_healthy(self, test_server):
        """Test health check when everything is healthy"""
        with test_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=True):
                with patch("os.access", return_value=True):
                    response = client.get("/health")
                    assert response.status_code == 200

                    data = json.loads(response.data)
                    assert data["status"] == "healthy"
                    assert "timestamp" in data
                    assert "version" in data

    def test_health_check_degraded(self, test_server):
        """Test health check when video directory is not accessible"""
        with test_server.app.test_client() as client:
            with patch.object(Path, "exists", return_value=False):
                response = client.get("/health")
                assert response.status_code == 503

                data = json.loads(response.data)
                assert data["status"] == "degraded"

    def test_health_check_exception(self, test_server):
        """Test health check with exception"""
        with test_server.app.test_client() as client:
            with patch.object(Path, "exists", side_effect=Exception("Test error")):
                response = client.get("/health")
                assert response.status_code in [
                    500,
                    503,
                ]  # Either internal error or service unavailable


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
        self, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test Flask app with file size limit enabled"""
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["VIDEO_SERVER_MAX_FILE_SIZE"] = "1073741824"  # 1GB
            os.environ["VIDEO_SERVER_PASSWORD_HASH"] = "test_hash"
            os.environ["VIDEO_SERVER_DIRECTORY"] = temp_dir

            config = ServerConfig()
            server = MediaRelayServer(config)

            assert server.app.config["MAX_CONTENT_LENGTH"] == 1073741824

    def test_max_file_size_disabled_zero(
        self, temp_video_dir
    ):  # pylint: disable=unused-argument
        """Test Flask app with file size limit disabled (zero)"""
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["VIDEO_SERVER_MAX_FILE_SIZE"] = "0"
            os.environ["VIDEO_SERVER_PASSWORD_HASH"] = "test_hash"
            os.environ["VIDEO_SERVER_DIRECTORY"] = temp_dir

            config = ServerConfig()
            server = MediaRelayServer(config)

            assert server.app.config["MAX_CONTENT_LENGTH"] is None


class TestSecurityHeaders:
    """Test cases for security headers"""

    def test_security_headers_applied(self, test_client):
        """Test that security headers are applied to all responses"""
        response = test_client.get("/health")

        expected_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy",
        ]

        for header in expected_headers:
            assert header in response.headers

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

    @patch("streaming_server.MediaRelayServer")
    @patch("streaming_server.load_config")
    def test_main_function_normal_operation(self, mock_load_config, mock_server_class):
        """Test main function normal operation"""
        # Setup mocks
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        mock_server = Mock()
        mock_server_class.return_value = mock_server

        # Test with no arguments
        with patch("streaming_server.click.Context") as mock_ctx:
            mock_ctx.return_value.params = {}
            result = main(None, None, None, False, False)

            mock_server_class.assert_called_once_with(mock_config)
            mock_server.run.assert_called_once()

    @patch("streaming_server.load_config")
    @patch("builtins.print")
    def test_main_function_value_error(self, mock_print, mock_load_config):
        """Test main function with ValueError"""
        mock_load_config.side_effect = ValueError("Configuration error")

        with pytest.raises(SystemExit) as excinfo:
            main(None, None, None, False, False)

        assert excinfo.value.code == 1
        mock_print.assert_any_call("Configuration Error: Configuration error")

    @patch("streaming_server.load_config")
    @patch("streaming_server.MediaRelayServer")
    @patch("builtins.print")
    def test_main_function_keyboard_interrupt(
        self, mock_print, mock_server_class, mock_load_config
    ):
        """Test main function with KeyboardInterrupt"""
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        mock_server = Mock()
        mock_server.run.side_effect = KeyboardInterrupt()
        mock_server_class.return_value = mock_server

        # Should not raise SystemExit
        main(None, None, None, False, False)
        mock_print.assert_any_call("\nShutdown complete")

    @patch("streaming_server.load_config")
    @patch("streaming_server.MediaRelayServer")
    @patch("builtins.print")
    def test_main_function_generic_exception(
        self, mock_print, mock_server_class, mock_load_config
    ):
        """Test main function with generic exception"""
        mock_config = Mock()
        mock_load_config.return_value = mock_config
        mock_server = Mock()
        mock_server.run.side_effect = RuntimeError("Server error")
        mock_server_class.return_value = mock_server

        with pytest.raises(SystemExit) as excinfo:
            main(None, None, None, False, False)

        assert excinfo.value.code == 1
        mock_print.assert_any_call("Server Error: Server error")


class TestServerRunMethod:
    """Test the server run method comprehensively"""

    @patch("streaming_server.serve")
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
            mock_print.assert_any_call("Video Streaming Server starting...")
            mock_print.assert_any_call(f"Server running on http://127.0.0.1:5000")

    @patch("streaming_server.serve")
    @patch("builtins.print")
    def test_run_method_keyboard_interrupt(self, mock_print, mock_serve):
        """Test server run with KeyboardInterrupt"""
        mock_serve.side_effect = KeyboardInterrupt()

        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(video_directory=temp_dir, password_hash="test_hash")
            server = MediaRelayServer(config)

            server.run()  # Should not raise exception

            mock_print.assert_any_call("\nServer stopped by user")

    @patch("streaming_server.serve")
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
        assert end_time - start_time < 2.0  # Should complete within 2 seconds


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
