"""Unit tests for path utilities and MIME type detection."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mediarelay.config import ServerConfig
from mediarelay.path_utils import (
    get_breadcrumbs,
    get_safe_path,
    guess_media_mime_type,
    resolve_path,
)


class TestGuessMediaMimeType:
    """Tests for guess_media_mime_type."""

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("movie.mp4", "video/mp4"),
            ("movie.mkv", "video/x-matroska"),
            ("movie.webm", "video/webm"),
            ("movie.avi", "video/x-msvideo"),
            ("movie.mov", "video/quicktime"),
            ("track.mp3", "audio/mpeg"),
            ("track.ogg", "audio/ogg"),
            ("unknown.xyz", "application/octet-stream"),
        ],
    )
    def test_guess_media_mime_type(self, filename: str, expected: str) -> None:
        assert guess_media_mime_type(filename) == expected

    def test_guess_media_mime_type_case_insensitive_extension(self) -> None:
        assert guess_media_mime_type("movie.MKV") == "video/x-matroska"


class TestGetSafePath:
    """Tests for path jail and traversal protection."""

    @pytest.fixture
    def video_config(self, tmp_path: Path) -> ServerConfig:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        (video_dir / "test.mp4").write_text("content", encoding="utf-8")
        return ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            log_directory=str(tmp_path / "logs"),
        )

    def test_empty_path_returns_video_root(self, video_config: ServerConfig) -> None:
        result = get_safe_path(video_config, "", client_ip="127.0.0.1")
        assert result == Path(video_config.video_directory)

    @pytest.mark.parametrize(
        "payload",
        [
            "..",
            "../..",
            "/../",
            "//etc",
            "test/../secret",
            "subdir/../../outside",
            "%2e%2e%2fetc%2fpasswd",
        ],
    )
    def test_path_traversal_rejected(
        self, video_config: ServerConfig, payload: str
    ) -> None:
        security_logger = MagicMock()
        result = get_safe_path(
            video_config,
            payload,
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called()

    def test_null_byte_rejected(self, video_config: ServerConfig) -> None:
        security_logger = MagicMock()
        result = get_safe_path(
            video_config,
            "test\x00.mp4",
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called_once()
        assert "Null byte" in security_logger.log_security_violation.call_args[0][1]

    def test_valid_relative_path(self, video_config: ServerConfig) -> None:
        result = get_safe_path(video_config, "test.mp4", client_ip="127.0.0.1")
        assert result is not None
        assert result.name == "test.mp4"

    def test_os_error_logged_via_callback(self, video_config: ServerConfig) -> None:
        log_error = MagicMock()
        with patch(
            "mediarelay.path_utils.resolve_path",
            MagicMock(side_effect=OSError("resolve failed")),
        ):
            result = get_safe_path(
                video_config,
                "test.mp4",
                client_ip="127.0.0.1",
                log_error=log_error,
            )
        assert result is None
        log_error.assert_called_once()


class TestGetBreadcrumbs:
    """Tests for breadcrumb navigation."""

    def test_root_breadcrumbs(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            log_directory=str(tmp_path / "logs"),
        )
        crumbs = get_breadcrumbs(config, video_dir)
        assert crumbs == [{"name": "Home", "path": "/"}]

    def test_nested_breadcrumbs(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        nested = video_dir / "movies" / "action"
        nested.mkdir(parents=True)
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            log_directory=str(tmp_path / "logs"),
        )
        crumbs = get_breadcrumbs(config, nested)
        assert crumbs[0] == {"name": "Home", "path": "/"}
        assert crumbs[-1]["name"] == "action"


class TestResolvePath:
    """Tests for resolve_path helper."""

    def test_resolve_path_returns_absolute(self, tmp_path: Path) -> None:
        path = tmp_path / "file.txt"
        path.write_text("x", encoding="utf-8")
        resolved = resolve_path(path)
        assert resolved.is_absolute()
