"""Unit tests for path utilities and MIME type detection."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mediarelay.config import ServerConfig
from mediarelay.path_utils import (
    InodeLinkIndex,
    get_breadcrumbs,
    get_safe_path,
    guess_media_mime_type,
    is_audio_file,
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
            ("movie.m4v", "video/x-m4v"),
            ("movie.flv", "video/x-flv"),
            ("track.aac", "audio/aac"),
            ("track.wav", "audio/wav"),
            ("unknown.xyz", "application/octet-stream"),
        ],
    )
    def test_guess_media_mime_type(self, filename: str, expected: str) -> None:
        assert guess_media_mime_type(filename) == expected

    def test_guess_media_mime_type_case_insensitive_extension(self) -> None:
        assert guess_media_mime_type("movie.MKV") == "video/x-matroska"

    def test_guess_media_mime_type_via_stdlib_mimetypes(self) -> None:
        """Extensions not in the fallback map should use mimetypes.guess_type."""
        guessed = guess_media_mime_type("clip.wmv")
        assert guessed != "application/octet-stream"
        assert guessed.startswith("video/")


class TestIsAudioFile:
    """Tests for is_audio_file helper."""

    @pytest.mark.parametrize(
        "filename",
        ["track.mp3", "track.aac", "track.ogg", "track.wav", "TRACK.MP3"],
    )
    def test_audio_extensions(self, filename: str) -> None:
        assert is_audio_file(filename) is True

    @pytest.mark.parametrize(
        "filename",
        ["movie.mp4", "movie.mkv", "document.srt"],
    )
    def test_non_audio_extensions(self, filename: str) -> None:
        assert is_audio_file(filename) is False


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
            "/etc/passwd",
            "\\windows\\system32",
            "test/../secret",
            "subdir/../../outside",
            "%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f",
            "..\\..\\windows\\system32",
            "subdir\\..\\secret",
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
        assert (
            "Unsafe characters"
            in security_logger.log_security_violation.call_args[0][1]
        )

    def test_control_characters_rejected(self, video_config: ServerConfig) -> None:
        security_logger = MagicMock()
        result = get_safe_path(
            video_config,
            "test\t.mp4",
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called_once()

    def test_unicode_control_characters_rejected(
        self, video_config: ServerConfig
    ) -> None:
        security_logger = MagicMock()
        result = get_safe_path(
            video_config,
            "test\u200b.mp4",
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called_once()

    def test_triple_url_encoding_rejected(self, video_config: ServerConfig) -> None:
        """Paths requiring multiple decode passes must still be blocked."""
        security_logger = MagicMock()
        payload = "%25252e%25252e%25252f"
        result = get_safe_path(
            video_config,
            payload,
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called()

    def test_dotfile_path_rejected(self, video_config: ServerConfig) -> None:
        security_logger = MagicMock()
        video_dir = Path(video_config.video_directory)
        (video_dir / ".hidden.mp4").write_text("secret", encoding="utf-8")
        result = get_safe_path(
            video_config,
            ".hidden.mp4",
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called_once()
        assert (
            security_logger.log_security_violation.call_args[0][0] == "dotfile_access"
        )

    @pytest.mark.parametrize(
        "payload",
        [
            "%25252e%25252e%25252f",
            "%2525252e%2525252e%2525252f",
        ],
    )
    def test_deep_url_encoding_rejected(
        self, video_config: ServerConfig, payload: str
    ) -> None:
        """Paths requiring four or more decode passes must still be blocked."""
        security_logger = MagicMock()
        result = get_safe_path(
            video_config,
            payload,
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called()

    def test_valid_relative_path(self, video_config: ServerConfig) -> None:
        result = get_safe_path(video_config, "test.mp4", client_ip="127.0.0.1")
        assert result is not None
        assert result.name == "test.mp4"

    def test_filename_with_double_dots_allowed(
        self, video_config: ServerConfig
    ) -> None:
        """Filenames containing '..' as substring must not be treated as traversal."""
        video_dir = Path(video_config.video_directory)
        (video_dir / "my..video.mp4").write_text("content", encoding="utf-8")
        result = get_safe_path(video_config, "my..video.mp4", client_ip="127.0.0.1")
        assert result is not None
        assert result.name == "my..video.mp4"

    def test_os_error_logged_via_callback(self, video_config: ServerConfig) -> None:
        log_error = MagicMock()
        security_logger = MagicMock()
        with patch(
            "mediarelay.path_utils.resolve_path",
            MagicMock(side_effect=OSError("resolve failed")),
        ):
            result = get_safe_path(
                video_config,
                "test.mp4",
                client_ip="127.0.0.1",
                security_logger=security_logger,
                log_error=log_error,
            )
        assert result is None
        log_error.assert_called_once()
        security_logger.log_security_violation.assert_called_once()
        assert (
            security_logger.log_security_violation.call_args[0][0]
            == "path_resolution_error"
        )

    def test_hardlink_outside_jail_rejected(self, tmp_path: Path) -> None:
        """Hard links to files outside the video directory must be blocked."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret.mp4"
        secret_file.write_text("secret", encoding="utf-8")
        link_path = video_dir / "stolen.mp4"
        try:
            os.link(secret_file, link_path)
        except (OSError, NotImplementedError):
            pytest.skip("Platform does not support creating hard links")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            log_directory=str(tmp_path / "logs"),
        )
        security_logger = MagicMock()
        result = get_safe_path(
            config,
            "stolen.mp4",
            client_ip="127.0.0.1",
            security_logger=security_logger,
        )
        assert result is None
        security_logger.log_security_violation.assert_called_once()
        assert (
            security_logger.log_security_violation.call_args[0][0] == "hardlink_escape"
        )

    def test_hardlink_within_jail_allowed(self, tmp_path: Path) -> None:
        """Hard links wholly inside the video directory remain accessible."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        original = video_dir / "movie.mp4"
        original.write_text("content", encoding="utf-8")
        alias = video_dir / "alias.mp4"
        try:
            os.link(original, alias)
        except (OSError, NotImplementedError):
            pytest.skip("Platform does not support creating hard links")

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            log_directory=str(tmp_path / "logs"),
        )
        result = get_safe_path(config, "alias.mp4", client_ip="127.0.0.1")
        assert result is not None
        assert result.name == "alias.mp4"


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

    def test_breadcrumbs_outside_video_root_return_home_only(
        self, tmp_path: Path
    ) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            log_directory=str(tmp_path / "logs"),
        )
        crumbs = get_breadcrumbs(config, outside)
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

    @pytest.mark.parametrize(
        "relative_parts",
        [
            ("a",),
            ("a", "b", "c"),
            ("deep", "nested", "folder", "file"),
        ],
    )
    def test_breadcrumb_depth(
        self, tmp_path: Path, relative_parts: tuple[str, ...]
    ) -> None:
        video_dir = tmp_path / "videos"
        target = video_dir.joinpath(*relative_parts)
        target.mkdir(parents=True)
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash="test_hash",
            log_directory=str(tmp_path / "logs"),
        )
        crumbs = get_breadcrumbs(config, target)
        assert len(crumbs) == len(relative_parts) + 1
        assert crumbs[0] == {"name": "Home", "path": "/"}
        assert crumbs[-1]["name"] == relative_parts[-1]


class TestResolvePath:
    """Tests for resolve_path helper."""

    def test_resolve_path_returns_absolute(self, tmp_path: Path) -> None:
        path = tmp_path / "file.txt"
        path.write_text("x", encoding="utf-8")
        resolved = resolve_path(path)
        assert resolved.is_absolute()


class TestInodeLinkIndex:
    """Tests for inode link count caching."""

    def test_refresh_indexes_files(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        (video_dir / "clip.mp4").write_text("content", encoding="utf-8")

        index = InodeLinkIndex(video_dir)
        index.refresh()

        stat_result = (video_dir / "clip.mp4").stat()
        count = index.count_links(stat_result.st_ino, stat_result.st_dev)
        assert count == 1

    def test_hardlink_check_falls_back_when_inode_index_misses(
        self, tmp_path: Path
    ) -> None:
        """When count_links returns None, hardlink check uses a live directory scan."""
        from mediarelay.path_utils import _is_hardlink_outside_jail

        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        clip = video_dir / "clip.mp4"
        clip.write_text("content", encoding="utf-8")

        index = InodeLinkIndex(video_dir)
        jail_root = video_dir.resolve()
        resolved = clip.resolve()

        with patch.object(index, "count_links", return_value=None):
            assert (
                _is_hardlink_outside_jail(resolved, jail_root, inode_index=index)
                is False
            )
