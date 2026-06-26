"""
Unit tests for comprehensive error handling
------------------------------------------
Tests for error handling, exception cases, and edge conditions.
"""

import base64
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.exceptions import TooManyRequests

from mediarelay.config import ServerConfig
from mediarelay.constants import MAX_LOGGED_PATH_LENGTH
from mediarelay.handlers import (
    handle_api_files_request,
    handle_index_request,
    handle_stream_request,
)
from mediarelay.logging_config import truncate_logged_path
from mediarelay.server import MediaRelayServer
from tests.constants import TEST_PASSWORD_HASH


class TestServerErrorHandling:
    """Test cases for server error handling"""

    def test_server_missing_video_directory(self, server_config):
        """Test configuration validation when video directory is missing."""
        server_config.video_directory = "/nonexistent/directory"

        with pytest.raises(ValueError, match="does not exist"):
            server_config.validate_config()

    def test_server_permission_denied_directory(self, server_config, tmp_path):
        """Test server behavior when directory listing raises PermissionError"""
        denied_dir = tmp_path / "denied"
        denied_dir.mkdir()
        server_config.video_directory = str(denied_dir)

        server = MediaRelayServer(server_config)
        with server.app.test_request_context():
            with patch.object(server, "check_authentication", return_value=True):
                with patch(
                    "mediarelay.handlers.os.scandir",
                    side_effect=PermissionError("Permission denied"),
                ):
                    response = handle_index_request(server, "")
                    assert response == ("Access denied to directory", 403)

    def test_directory_listing_skips_dotfiles(
        self, media_relay_server, server_config, temp_video_dir, authenticated_client
    ):
        """Hidden dotfiles must not appear in directory listings."""
        (temp_video_dir / ".hidden.mp4").write_text("secret", encoding="utf-8")
        (temp_video_dir / "visible.mp4").write_text("video", encoding="utf-8")

        response = authenticated_client.get("/")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "visible.mp4" in html
        assert ".hidden.mp4" not in html

    def test_direct_dotfile_stream_rejected(self, authenticated_client, temp_video_dir):
        """Direct requests for dotfiles must be rejected even when the file exists."""
        (temp_video_dir / ".hidden.mp4").write_text("secret", encoding="utf-8")

        response = authenticated_client.get("/stream/.hidden.mp4")
        assert response.status_code == 404

        index_response = authenticated_client.get("/.hidden.mp4")
        assert index_response.status_code == 404

    def test_directory_listing_skips_unreadable_entries(
        self, media_relay_server, server_config, temp_video_dir, authenticated_client
    ):
        """Unreadable directory entries must not crash the listing."""
        readable = temp_video_dir / "readable.mp4"
        readable.write_text("video", encoding="utf-8")
        unreadable = temp_video_dir / "broken.mp4"
        unreadable.write_text("video", encoding="utf-8")

        original_stat = Path.stat

        def selective_stat(self: Path, *args: object, **kwargs: object) -> object:
            if self.name == "broken.mp4":
                raise PermissionError("denied")
            return original_stat(self, *args, **kwargs)

        with patch.object(Path, "stat", selective_stat):
            response = authenticated_client.get("/")

        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "readable.mp4" in html
        assert "broken.mp4" not in html

    def test_server_video_directory_is_file(self, server_config, tmp_path):
        """Test server behavior when video directory is actually a file"""
        fake_dir = tmp_path / "not_a_directory.txt"
        fake_dir.write_text("This is a file, not a directory")

        server_config.video_directory = str(fake_dir)

        # Should raise an error during config validation or server initialization
        # The config validation happens first, so we expect a ValueError there
        with pytest.raises(ValueError, match="is not a directory"):
            server_config.validate_config()


class TestRequestErrorHandling:
    """Test cases for request error handling"""

    def test_malformed_authorization_header(self, media_relay_server):
        """Test handling of malformed authorization headers"""
        with media_relay_server.app.test_client() as client:
            # Test completely malformed header
            response = client.get("/", headers={"Authorization": "Malformed"})
            assert response.status_code == 401

            # Test missing credentials
            response = client.get("/", headers={"Authorization": "Basic"})
            assert response.status_code == 401

            # Test invalid base64
            response = client.get("/", headers={"Authorization": "Basic invalid!"})
            assert response.status_code == 401

    def test_extremely_long_path(self, authenticated_client):
        """Test handling of extremely long file paths"""
        long_path = "a" * 5000  # Very long path
        response = authenticated_client.get(f"/stream/{long_path}")

        assert response.status_code == 414

    def test_null_bytes_in_path(self, authenticated_client):
        """Test handling of null bytes in file paths"""
        malicious_path = "test\x00.mp4"
        response = authenticated_client.get(f"/stream/{malicious_path}")

        assert response.status_code == 404

    def test_unicode_in_path(self, authenticated_client):
        """Test handling of unicode characters in paths"""
        unicode_path = "test_Ñ„Ð°Ð¹Ð».mp4"  # Cyrillic characters
        response = authenticated_client.get(f"/stream/{unicode_path}")

        # Should handle gracefully as not found
        assert response.status_code == 404


class TestMemoryErrorHandling:
    """Test cases for memory-related error handling"""

    def test_large_file_listing(self, authenticated_client, large_listing_dir):
        """Test server behavior with very large directory listings"""
        # Create many files to test memory usage
        for i in range(1000):
            (large_listing_dir / f"video_{i:04d}.mp4").write_text("fake content")

        response = authenticated_client.get("/bulk_listing")

        # Should handle large directories without running out of memory
        assert response.status_code == 200

    def test_directory_listing_exceeds_max_entries(
        self, monkeypatch, authenticated_client, media_relay_server, temp_video_dir
    ):
        """Directories above max_directory_entries return HTTP 413."""
        monkeypatch.setenv("VIDEO_SERVER_MAX_DIRECTORY_ENTRIES", "5")
        media_relay_server.config.max_directory_entries = 5
        listing_dir = temp_video_dir / "huge_dir"
        listing_dir.mkdir()
        for i in range(6):
            (listing_dir / f"entry_{i:02d}.mp4").write_text("x")

        response = authenticated_client.get("/huge_dir")
        assert response.status_code == 413

        api_response = authenticated_client.get("/api/files?path=huge_dir")
        assert api_response.status_code == 413
        data = json.loads(api_response.data)
        assert "too many entries" in data["error"].lower()

    def test_very_large_file_access(self, authenticated_client, temp_video_dir):
        """Test accessing metadata of very large files"""
        # Create a test file entry (don't actually create large file)
        large_file = temp_video_dir / "large_file.mp4"
        large_file.write_text("content")

        # Mock the file to appear very large

        mock_stat_result = MagicMock()
        mock_stat_result.st_size = 10 * 1024**3  # 10GB
        mock_stat_result.st_mtime = 1640995200  # Fixed timestamp
        mock_stat_result.st_mode = 0o100644  # Regular file mode

        with patch.object(Path, "stat", return_value=mock_stat_result):
            with patch.object(Path, "is_file", return_value=True):
                response = authenticated_client.get("/")
                assert response.status_code in (200, 403)


class TestFileSystemErrorHandling:
    """Test cases for file system error handling"""

    def test_index_handler_os_error_returns_500(
        self, media_relay_server, server_config
    ):
        """Index handler returns 500 when directory listing fails."""
        auth = base64.b64encode(b"testuser:testpass").decode()
        with media_relay_server.app.test_request_context(
            "/",
            method="GET",
            headers={"Authorization": f"Basic {auth}"},
        ):
            with patch.object(
                media_relay_server, "check_authentication", return_value=True
            ):
                with patch(
                    "mediarelay.handlers.get_safe_path",
                    return_value=Path(server_config.video_directory),
                ):
                    with patch(
                        "mediarelay.handlers.os.scandir",
                        side_effect=OSError("read error"),
                    ):
                        result = handle_index_request(media_relay_server, "")
        assert result == ("Error reading directory", 500)

    def test_index_handler_parent_path_value_error_fallback(
        self, media_relay_server, server_config
    ):
        """Index handler falls back to root parent path when relative_to fails."""
        auth = base64.b64encode(b"testuser:testpass").decode()
        safe_path = Path(server_config.video_directory) / "subdir"
        safe_path.mkdir(exist_ok=True)
        video_root = Path(server_config.video_directory)

        with media_relay_server.app.test_request_context(
            "/subdir",
            method="GET",
            headers={"Authorization": f"Basic {auth}"},
        ):
            with patch.object(
                media_relay_server, "check_authentication", return_value=True
            ):
                with patch("mediarelay.handlers.get_safe_path", return_value=safe_path):
                    with patch.object(
                        Path,
                        "relative_to",
                        side_effect=ValueError("outside jail"),
                    ):
                        result = handle_index_request(media_relay_server, "subdir")

        assert isinstance(result, str)
        assert 'href="/"' in result


class TestHandlerErrorPaths:
    """Tests for handler 500 error responses."""

    def test_stream_handler_os_error_returns_500(self, media_relay_server):
        """Stream handler returns 500 when send_file fails."""
        from mediarelay.path_utils import ValidatedFileHandle

        auth = base64.b64encode(b"testuser:testpass").decode()
        with media_relay_server.app.test_request_context(
            "/stream/test_video.mp4",
            method="GET",
            headers={"Authorization": f"Basic {auth}"},
        ):
            with patch.object(
                media_relay_server, "check_authentication", return_value=True
            ):
                with patch(
                    "mediarelay.handlers.open_validated_file",
                    return_value=ValidatedFileHandle(fd=0, path=Path("test_video.mp4")),
                ):
                    with patch(
                        "mediarelay.handlers.send_file",
                        side_effect=OSError("disk error"),
                    ):
                        result = handle_stream_request(
                            media_relay_server, "test_video.mp4"
                        )
        assert result == ("Error streaming file", 500)

    def test_api_files_handler_os_error_returns_500(self, media_relay_server):
        """API files handler returns 500 on filesystem errors."""
        mock_dir = MagicMock()
        mock_dir.exists.return_value = True
        mock_dir.is_dir.return_value = True

        auth = base64.b64encode(b"testuser:testpass").decode()
        with media_relay_server.app.test_request_context(
            "/api/files",
            method="GET",
            headers={"Authorization": f"Basic {auth}"},
        ):
            with patch.object(
                media_relay_server, "check_authentication", return_value=True
            ):
                with patch("mediarelay.handlers.get_safe_path", return_value=mock_dir):
                    with patch(
                        "mediarelay.handlers.os.scandir",
                        side_effect=OSError("read error"),
                    ):
                        result = handle_api_files_request(media_relay_server)
        assert result[1] == 500

    def test_api_files_handler_permission_error_returns_403(self, media_relay_server):
        """API files handler returns 403 on permission denied."""
        mock_dir = MagicMock()
        mock_dir.exists.return_value = True
        mock_dir.is_dir.return_value = True

        auth = base64.b64encode(b"testuser:testpass").decode()
        media_relay_server.security_logger = MagicMock()
        with media_relay_server.app.test_request_context(
            "/api/files",
            method="GET",
            headers={"Authorization": f"Basic {auth}"},
        ):
            with patch.object(
                media_relay_server, "check_authentication", return_value=True
            ):
                with patch("mediarelay.handlers.get_safe_path", return_value=mock_dir):
                    with patch(
                        "mediarelay.handlers.os.scandir",
                        side_effect=PermissionError("denied"),
                    ):
                        result = handle_api_files_request(media_relay_server)
        assert result[1] == 403
        media_relay_server.security_logger.log_security_violation.assert_called_once()


class TestProductionAuditErrorHandlers:
    """Tests for centralized error handlers added during production audit."""

    def test_get_logout_uses_method_not_allowed_handler(
        self, media_relay_server, server_config
    ):
        credentials = base64.b64encode(
            f"{server_config.username}:testpass".encode("utf-8")
        ).decode("utf-8")

        with media_relay_server.app.test_client() as client:
            client.get("/", headers={"Authorization": f"Basic {credentials}"})
            response = client.get("/logout")

        assert response.status_code == 405
        assert response.get_data(as_text=True) == "Method Not Allowed"

    def test_performance_logger_failure_does_not_break_response(
        self, authenticated_client, media_relay_server
    ):
        with patch.object(
            media_relay_server.performance_logger.logger,
            "log",
            side_effect=OSError("disk full"),
        ):
            response = authenticated_client.get("/health")

        assert response.status_code == 200

    def test_health_unhealthy_when_runtime_health_raises(
        self, authenticated_client, media_relay_server
    ):
        with patch.object(
            media_relay_server.config,
            "check_runtime_health",
            side_effect=RuntimeError("health probe failed"),
        ):
            response = authenticated_client.get("/health")

        assert response.status_code == 503
        data = json.loads(response.data)
        assert data["status"] == "unhealthy"


class TestHandlerUtilities:
    """Tests for small handler utilities and error-handler branches."""

    def test_truncate_log_path_short_path_unchanged(self) -> None:
        path = "movies/video.mp4"
        assert truncate_logged_path(path) == path

    def test_truncate_log_path_long_path_truncated(self) -> None:
        long_path = "a" * (MAX_LOGGED_PATH_LENGTH + 20)
        truncated = truncate_logged_path(long_path)
        assert truncated.endswith("...(truncated)")
        assert len(truncated) < len(long_path)


class TestRateLimitErrorHandlerBranches:
    """Cover retry_after fallback branches in the 429 error handler."""

    def test_rate_limit_handler_uses_error_retry_after(
        self, media_relay_server
    ) -> None:
        error = TooManyRequests()
        error.retry_after = 42

        with media_relay_server.app.test_request_context("/"):
            handler = media_relay_server.app.error_handler_spec[None][429][
                TooManyRequests
            ]
            response = handler(error)

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "42"

    def test_rate_limit_handler_default_retry_when_limit_disabled(
        self, media_relay_server
    ) -> None:
        media_relay_server.config.rate_limit_per_minute = 0

        with media_relay_server.app.test_request_context("/"):
            handler = media_relay_server.app.error_handler_spec[None][429][
                TooManyRequests
            ]
            response = handler(TooManyRequests())

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "60"
