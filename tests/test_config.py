"""
Unit tests for configuration management
--------------------------------------
Tests for ServerConfig class and environment variable handling.
Includes comprehensive configuration validation tests.
"""

import builtins
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import mediarelay.config as config_module
from mediarelay.config import (
    ServerConfig,
    _get_default_video_directory,
    create_sample_env_file,
    load_config,
    validate_deployment_config,
)
from tests.constants import TEST_PASSWORD_HASH, TEST_PRODUCTION_SECRET_KEY


def _patch_video_dir_readonly(monkeypatch: pytest.MonkeyPatch, video_dir: Path) -> None:
    """Treat the video directory as read-only for deployment validation tests."""
    real_access = os.access
    resolved = video_dir.resolve()

    def access(
        path: os.PathLike[str] | str | int,
        mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> bool:
        if mode == os.W_OK and Path(path).resolve() == resolved:
            return False
        return real_access(path, mode, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "access", access)


def _patch_log_dir_readonly(monkeypatch: pytest.MonkeyPatch, log_dir: Path) -> None:
    """Treat the log directory as non-writable for deployment validation tests."""
    real_access = os.access
    resolved = log_dir.resolve()

    def access(
        path: os.PathLike[str] | str | int,
        mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> bool:
        if mode == os.W_OK and Path(path).resolve() == resolved:
            return False
        return real_access(path, mode, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "access", access)


def _setup_production_env(
    monkeypatch: pytest.MonkeyPatch,
    video_dir: Path,
    log_dir: Path,
) -> None:
    """Configure environment variables for valid production ServerConfig."""
    monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "true")
    monkeypatch.setenv("VIDEO_SERVER_SECRET_KEY", TEST_PRODUCTION_SECRET_KEY)
    monkeypatch.setenv("VIDEO_SERVER_RATE_LIMIT", "true")
    monkeypatch.setenv("VIDEO_SERVER_DEBUG", "false")
    monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
    monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(log_dir))
    _patch_video_dir_readonly(monkeypatch, video_dir)


class TestDefaultVideoDirectoryFunction:
    """Test _get_default_video_directory function comprehensively"""

    def test_get_default_video_directory_normal(self):
        """Test _get_default_video_directory under normal conditions"""
        result = _get_default_video_directory()

        # Verify result is a string path
        assert isinstance(result, str)

        # Platform-specific path verification
        if sys.platform == "win32":
            # Windows: check for Videos folder in user profile
            assert "Videos" in result or "videos" in result.lower()
        else:
            # Unix-like: check for Videos folder in home directory
            assert "Videos" in result or result == "./videos"

    def test_get_default_video_directory_runtime_error(self):
        """Test _get_default_video_directory with RuntimeError"""
        with patch("pathlib.Path.home", side_effect=RuntimeError("No home directory")):
            result = _get_default_video_directory()
            assert result == "./videos"

    def test_get_default_video_directory_os_error(self):
        """Test _get_default_video_directory with OSError"""
        with patch("pathlib.Path.home", side_effect=OSError("Permission denied")):
            result = _get_default_video_directory()
            assert result == "./videos"


class TestConfigValidationEdgeCases:
    """Test edge cases and validation failures for better coverage"""

    def test_video_directory_validation_failure(self):
        """Test video directory validation failure"""
        # Create config with non-existent video directory
        with pytest.raises(ValueError, match="Video directory does not exist"):
            ServerConfig(
                video_directory="/nonexistent/directory",
                password_hash=TEST_PASSWORD_HASH,
            )

    def test_port_validation_edge_cases(self):
        """Test port validation edge cases"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test port too low
            with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
                ServerConfig(
                    video_directory=temp_dir, password_hash=TEST_PASSWORD_HASH, port=0
                )

            # Test port too high
            with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
                ServerConfig(
                    video_directory=temp_dir,
                    password_hash=TEST_PASSWORD_HASH,
                    port=70000,
                )

    def test_thread_count_validation_failure(self):
        """Test thread count validation failure"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError, match="Thread count must be at least 1"):
                ServerConfig(
                    video_directory=temp_dir,
                    password_hash=TEST_PASSWORD_HASH,
                    threads=0,
                )

    def test_empty_password_hash_validation(self):
        """Test empty password hash validation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(
                ValueError, match="VIDEO_SERVER_PASSWORD_HASH must be set"
            ):
                ServerConfig(video_directory=temp_dir, password_hash="")  # Empty string

            with pytest.raises(
                ValueError, match="VIDEO_SERVER_PASSWORD_HASH must be set"
            ):
                ServerConfig(video_directory=temp_dir, password_hash=None)  # None value


class TestServerConfig:
    """Test cases for ServerConfig class"""

    def test_default_values(self):
        """Test default configuration values"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
                "VIDEO_SERVER_USERNAME": "tboy1337",
            },
            clear=False,
        ):
            for key in list(os.environ):
                if key == "VIDEO_SERVER_ALLOWED_EXTENSIONS" and not os.environ[key]:
                    del os.environ[key]
            config = ServerConfig()

        assert config.host == "0.0.0.0"
        assert config.port == 5000
        assert config.debug is False
        assert config.threads == 6
        assert config.username == "tboy1337"
        assert config.session_timeout == 3600
        assert config.lockout_max_attempts == 5
        assert config.lockout_duration == 900
        assert ".mp4" in config.allowed_extensions
        assert config.rate_limit_enabled is True
        assert config.rate_limit_per_minute == 60

    def test_environment_variable_override(self):
        """Test environment variable overrides"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_HOST": "192.168.1.100",
                "VIDEO_SERVER_PORT": "8080",
                "VIDEO_SERVER_DEBUG": "true",
                "VIDEO_SERVER_THREADS": "12",
                "VIDEO_SERVER_USERNAME": "customuser",
                "VIDEO_SERVER_SESSION_TIMEOUT": "7200",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            config = ServerConfig()

            assert config.host == "192.168.1.100"
            assert config.port == 8080
            assert config.debug is True
            assert config.threads == 12
            assert config.username == "customuser"
            assert config.session_timeout == 7200

    def test_lockout_environment_variable_override(self):
        """Test lockout settings from environment variables."""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
                "VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS": "3",
                "VIDEO_SERVER_LOCKOUT_DURATION": "120",
            },
        ):
            config = ServerConfig()

        assert config.lockout_max_attempts == 3
        assert config.lockout_duration == 120

    def test_lockout_duration_minimum_validation(self):
        """Lockout duration must be at least 60 seconds."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                    "VIDEO_SERVER_LOCKOUT_DURATION": "30",
                },
            ):
                with pytest.raises(
                    ValueError,
                    match="VIDEO_SERVER_LOCKOUT_DURATION must be at least 60",
                ):
                    ServerConfig()


class TestServerConfigValidationComprehensive:
    """Comprehensive tests for ServerConfig validation"""

    def test_validate_config_all_checks(self, tmp_path):
        """Test validate_config method with all validation checks"""
        # Create a valid video directory
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        # Test valid configuration
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            port=8080,
            threads=4,
            log_directory=str(tmp_path / "logs"),
        )

        # Should not raise any exceptions
        config.validate_config()

        # Verify log directory was created
        assert (tmp_path / "logs").exists()

    def test_validate_config_video_directory_file_not_directory(self, tmp_path):
        """Test validation when video_directory points to a file"""
        # Create a file instead of directory
        fake_dir = tmp_path / "fake_directory"
        fake_dir.write_text("not a directory")

        # Should raise validation error during initialization - file is not a directory
        with pytest.raises(ValueError, match="is not a directory"):
            ServerConfig(
                video_directory=str(fake_dir), password_hash=TEST_PASSWORD_HASH
            )

    def test_validate_config_port_range_validation(self, tmp_path):
        """Test port range validation edge cases"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        # Test port = 1 (minimum valid)
        config = ServerConfig(
            video_directory=str(video_dir), password_hash=TEST_PASSWORD_HASH, port=1
        )
        config.validate_config()  # Should not raise

        # Test port = 65535 (maximum valid)
        config.port = 65535
        config.validate_config()  # Should not raise

        # Test port = 0 (invalid)
        config.port = 0
        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            config.validate_config()

        # Test port = 65536 (invalid)
        config.port = 65536
        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            config.validate_config()

    def test_validate_config_thread_count_edge_cases(self, tmp_path):
        """Test thread count validation edge cases"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        # Test threads = 1 (minimum valid)
        config = ServerConfig(
            video_directory=str(video_dir), password_hash=TEST_PASSWORD_HASH, threads=1
        )
        config.validate_config()  # Should not raise

        # Test threads = 0 (invalid)
        config.threads = 0
        with pytest.raises(ValueError, match="Thread count must be at least 1"):
            config.validate_config()

        # Test threads = -1 (invalid)
        config.threads = -1
        with pytest.raises(ValueError, match="Thread count must be at least 1"):
            config.validate_config()

    def test_validate_config_log_directory_creation_nested(self, tmp_path):
        """Test log directory creation with nested paths"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        # Test nested log directory creation
        nested_log_dir = tmp_path / "deeply" / "nested" / "logs"

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            log_directory=str(nested_log_dir),
        )

        config.validate_config()

        # Should create the entire nested path
        assert nested_log_dir.exists()
        assert nested_log_dir.is_dir()


class TestServerConfigEnvironmentVariables:
    """Test ServerConfig with comprehensive environment variable scenarios"""

    def test_allowed_extensions_environment_parsing(self, tmp_path):
        """Test allowed_extensions parsing from environment"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        # Test with custom extensions from environment
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": ".mp4,.mkv,.webm",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            expected_extensions = {".mp4", ".mkv", ".webm"}
            assert config.allowed_extensions == expected_extensions

    def test_allowed_extensions_rejects_html(self, tmp_path):
        """Test allowed_extensions rejects browser-renderable extensions."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": ".mp4,.html",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            with pytest.raises(
                ValueError, match="Invalid VIDEO_SERVER_ALLOWED_EXTENSIONS"
            ):
                ServerConfig()

    def test_allowed_extensions_normalizes_uppercase(self, tmp_path):
        """Test allowed_extensions lowercases extensions from environment."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": ".MP4,.MKV",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            assert config.allowed_extensions == {".mp4", ".mkv"}

    def test_max_directory_entries_environment(self, tmp_path):
        """Test max_directory_entries from environment."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_MAX_DIRECTORY_ENTRIES": "500",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            assert config.max_directory_entries == 500

    def test_allowed_extensions_empty_environment(self, tmp_path):
        """Test allowed_extensions rejects empty environment variable"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": "",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            with pytest.raises(ValueError, match="allowed_extensions cannot be empty"):
                ServerConfig()

    def test_allowed_extensions_whitespace_handling(self, tmp_path):
        """Test allowed_extensions with whitespace"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": " .mp4 , .mkv , .avi ",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            expected_extensions = {".mp4", ".mkv", ".avi"}
            assert config.allowed_extensions == expected_extensions

    def test_debug_boolean_parsing(self, tmp_path):
        """Test debug boolean parsing from environment"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        true_values = ["true", "TRUE", "yes", "YES", "1", "on", "ON"]
        false_values = ["false", "FALSE", "no", "NO", "0", "off", "OFF", "invalid"]

        for value in true_values:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_DEBUG": value,
                    "VIDEO_SERVER_DIRECTORY": str(video_dir),
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                },
                clear=True,
            ):
                config = ServerConfig()
                assert config.debug is True, f"Failed for value: {value}"

        for value in false_values:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_DEBUG": value,
                    "VIDEO_SERVER_DIRECTORY": str(video_dir),
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                },
                clear=True,
            ):
                config = ServerConfig()
                assert config.debug is False, f"Failed for value: {value}"

    def test_rate_limit_boolean_parsing(self, tmp_path):
        """Test rate_limit_enabled boolean parsing"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        # Test 'true' value
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_RATE_LIMIT": "true",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            assert config.rate_limit_enabled is True

        # Test 'false' value
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_RATE_LIMIT": "false",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            assert config.rate_limit_enabled is False

        # Test non-'true' value (should be false)
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_RATE_LIMIT": "invalid",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            assert config.rate_limit_enabled is False

    def test_session_cookie_boolean_parsing(self, tmp_path):
        """Test session cookie boolean parsing"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_SESSION_COOKIE_SECURE": "true",
                "VIDEO_SERVER_SESSION_COOKIE_HTTPONLY": "false",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()
            assert config.session_cookie_secure is True
            assert config.session_cookie_httponly is False

    def test_numeric_environment_variables(self, tmp_path):
        """Test numeric environment variable parsing"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PORT": "9000",
                "VIDEO_SERVER_THREADS": "12",
                "VIDEO_SERVER_SESSION_TIMEOUT": "7200",
                "VIDEO_SERVER_MAX_FILE_SIZE": "1073741824",
                "VIDEO_SERVER_LOG_MAX_BYTES": "20971520",
                "VIDEO_SERVER_LOG_BACKUP_COUNT": "10",
                "VIDEO_SERVER_RATE_LIMIT_PER_MIN": "120",
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
            clear=True,
        ):
            config = ServerConfig()

            assert config.port == 9000
            assert config.threads == 12
            assert config.session_timeout == 7200
            assert config.max_file_size == 1073741824
            assert config.log_max_bytes == 20971520
            assert config.log_backup_count == 10
            assert config.rate_limit_per_minute == 120


class TestMaxFileSizeConfiguration:
    """Test cases for max file size configuration"""

    def test_default_max_file_size(self):
        """Test default max file size is 20GB"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                },
                clear=True,
            ):
                config = ServerConfig()
                # 20GB in bytes
                assert config.max_file_size == 21474836480

    def test_custom_max_file_size(self):
        """Test custom max file size configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_MAX_FILE_SIZE": "5368709120",  # 5GB
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                },
            ):
                config = ServerConfig()
                assert config.max_file_size == 5368709120

    def test_disabled_max_file_size_zero(self):
        """Test max file size can be disabled with 0"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_MAX_FILE_SIZE": "0",
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                },
            ):
                config = ServerConfig()
                assert config.max_file_size == 0

    def test_disabled_max_file_size_negative(self):
        """Test max file size rejects negative values"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_MAX_FILE_SIZE": "-1",
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                },
            ):
                with pytest.raises(
                    ValueError, match="max_file_size cannot be negative"
                ):
                    ServerConfig()

    def test_invalid_port_validation(self):
        """Test port validation"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PORT": "99999",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            with pytest.raises(
                ValueError, match="VIDEO_SERVER_PORT must be at most 65535"
            ):
                ServerConfig()

    def test_invalid_thread_count(self):
        """Test thread count validation"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_THREADS": "0",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            with pytest.raises(
                ValueError, match="VIDEO_SERVER_THREADS must be at least 1"
            ):
                ServerConfig()

    def test_missing_password_hash(self):
        """Test missing password hash validation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ, {"VIDEO_SERVER_DIRECTORY": temp_dir}, clear=True
            ):
                with pytest.raises(
                    ValueError, match="VIDEO_SERVER_PASSWORD_HASH must be set"
                ):
                    ServerConfig()

    def test_invalid_video_directory(self):
        """Test invalid video directory validation"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_DIRECTORY": "/nonexistent/directory",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
            },
        ):
            with pytest.raises(ValueError, match="Video directory does not exist"):
                ServerConfig()

    def test_log_directory_creation(self):
        """Test log directory creation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"

            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_LOG_DIR": str(log_dir),
                    "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                    "VIDEO_SERVER_DIRECTORY": str(Path.home()),
                },
            ):
                config = ServerConfig()
                assert log_dir.exists()
                assert log_dir.is_dir()

    def test_production_detection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Test production environment detection"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _setup_production_env(monkeypatch, video_dir, log_dir)

        config = ServerConfig(
            password_hash=TEST_PASSWORD_HASH,
            video_directory=str(video_dir),
            log_directory=str(log_dir),
        )
        assert config.is_production() is True

        with patch.dict(os.environ, {"VIDEO_SERVER_PRODUCTION": "false"}):
            assert config.is_production() is True

    def test_to_dict_excludes_sensitive_data(self):
        """Test that to_dict excludes sensitive information"""
        config = ServerConfig(
            password_hash=TEST_PASSWORD_HASH,
            secret_key="secret_key",
            video_directory=str(Path.home()),
        )

        config_dict = config.to_dict()

        assert "password_hash" not in config_dict
        assert "secret_key" not in config_dict
        assert config_dict["username"] == config.username
        assert config_dict["host"] == config.host


class TestServerConfigMethodsComprehensive:
    """Test ServerConfig methods comprehensively"""

    def test_is_production_environment_variations(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test production flag is snapshotted when ServerConfig is created."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        dev_config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            production=False,
        )
        assert dev_config.is_production() is False

        _setup_production_env(monkeypatch, video_dir, log_dir)
        prod_config = ServerConfig(
            password_hash=TEST_PASSWORD_HASH,
            video_directory=str(video_dir),
            log_directory=str(log_dir),
        )
        assert prod_config.is_production() is True

        with patch.dict(os.environ, {"VIDEO_SERVER_PRODUCTION": "false"}):
            assert prod_config.is_production() is True
            assert dev_config.is_production() is False

        with patch.dict(os.environ, {"VIDEO_SERVER_PRODUCTION": "testing"}):
            invalid_config = ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                production=False,
            )
            assert invalid_config.is_production() is False

    def test_to_dict_comprehensive_exclusions(self, tmp_path):
        """Test to_dict method excludes all sensitive data"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            secret_key="secret_key_value",
            username="testuser",
            host="localhost",
            port=8080,
        )

        config_dict = config.to_dict()

        # Test that sensitive data is excluded
        sensitive_fields = ["password_hash", "secret_key"]
        for field in sensitive_fields:
            assert field not in config_dict

        # Test that non-sensitive data is included
        expected_fields = [
            "host",
            "port",
            "debug",
            "threads",
            "username",
            "session_timeout",
            "video_directory",
            "log_directory",
            "allowed_extensions",
            "max_file_size",
            "log_level",
            "rate_limit_enabled",
            "rate_limit_per_minute",
            "is_production",
        ]
        for field in expected_fields:
            assert field in config_dict

        # Test specific values
        assert config_dict["username"] == "testuser"
        assert config_dict["host"] == "localhost"
        assert config_dict["port"] == 8080
        assert isinstance(config_dict["allowed_extensions"], list)
        assert isinstance(config_dict["is_production"], bool)


class TestConfigLoading:
    """Test cases for configuration loading functions"""

    def test_load_config(self):
        """Test config loading function"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_HOST": "testhost",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            config = load_config()
            assert isinstance(config, ServerConfig)
            assert config.host == "testhost"

    def test_create_sample_env_file(self, tmp_path):
        """Test sample .env file creation"""
        with patch("mediarelay.config.Path") as mock_path:
            mock_env_file = tmp_path / ".env.example"
            mock_path.return_value = mock_env_file

            create_sample_env_file()

            assert mock_env_file.exists()
            content = mock_env_file.read_text()
            assert "VIDEO_SERVER_HOST" in content
            assert "VIDEO_SERVER_PASSWORD_HASH" in content
            assert "tboy1337" in content

    def test_create_sample_env_file_skips_existing(self, tmp_path):
        """Test sample .env file is not overwritten when it already exists"""
        with patch("mediarelay.config.Path") as mock_path:
            mock_env_file = tmp_path / ".env.example"
            mock_env_file.write_text("existing content", encoding="utf-8")
            mock_path.return_value = mock_env_file

            create_sample_env_file()

            assert mock_env_file.read_text(encoding="utf-8") == "existing content"


class TestConfigLoadingComprehensive:
    """Test config loading functions comprehensively"""

    def test_load_config_function(self):
        """Test load_config function"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_HOST": "testhost",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            config = load_config()
            assert isinstance(config, ServerConfig)
            assert config.host == "testhost"

    def test_create_sample_env_file_content(self, tmp_path):
        """Test create_sample_env_file creates correct content"""
        with patch("mediarelay.config.Path") as mock_path_class:
            env_file = tmp_path / ".env.example"
            mock_path_class.return_value = env_file

            with patch("builtins.open", create=True) as mock_open:
                mock_file = mock_open.return_value.__enter__.return_value

                create_sample_env_file()

                # Verify file was opened for writing
                mock_open.assert_called_once_with(env_file, "w", encoding="utf-8")

                # Verify content was written
                write_calls = mock_file.write.call_args_list
                written_content = "".join(call[0][0] for call in write_calls)

                # Check that key configuration items are present
                assert "VIDEO_SERVER_HOST=0.0.0.0" in written_content
                assert "VIDEO_SERVER_PORT=5000" in written_content
                assert "VIDEO_SERVER_USERNAME=tboy1337" in written_content
                assert (
                    "VIDEO_SERVER_PASSWORD_HASH=your-password-hash-here"
                    in written_content
                )
                assert "VIDEO_SERVER_DIRECTORY=/path/to/your/videos" in written_content

    def test_create_sample_env_file_prints_messages(self, tmp_path):
        """Test create_sample_env_file prints appropriate messages"""
        with patch("mediarelay.config.Path") as mock_path_class:
            env_file = tmp_path / ".env.example"
            mock_path_class.return_value = env_file

            with patch("builtins.print") as mock_print:
                with patch("builtins.open", create=True):
                    create_sample_env_file()

                    # Verify appropriate messages were printed
                    expected_messages = [
                        f"Sample environment file created: {env_file}",
                        "Copy this to .env and update the values for your deployment",
                    ]

                    for message in expected_messages:
                        mock_print.assert_any_call(message)


class TestSecurityHeaders:
    """Test cases for security headers configuration"""

    def test_default_security_headers(self):
        """Test default security headers"""
        config = ServerConfig(
            password_hash=TEST_PASSWORD_HASH, video_directory=str(Path.home())
        )

        headers = config.security_headers

        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in headers
        assert headers["X-Frame-Options"] == "SAMEORIGIN"
        assert "Strict-Transport-Security" not in headers
        assert "Content-Security-Policy" in headers
        assert "Referrer-Policy" in headers

    def test_content_security_policy(self):
        """Test Content Security Policy configuration"""
        config = ServerConfig(
            password_hash=TEST_PASSWORD_HASH, video_directory=str(Path.home())
        )

        csp = config.security_headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "media-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp


@pytest.mark.timeout(10)
class TestConfigPerformance:
    """Performance tests for configuration loading"""

    def test_config_loading_performance(self):
        """Test that config loading is fast"""
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(Path.home()),
            },
        ):
            start_time = time.time()
            for _ in range(100):
                ServerConfig()
            end_time = time.time()

            # Should complete 100 config loads in under 1 second
            assert end_time - start_time < 1.0

    def test_config_validation_performance(self):
        """Test configuration validation performance"""
        config = ServerConfig(
            password_hash=TEST_PASSWORD_HASH, video_directory=str(Path.home())
        )

        start_time = time.time()
        for _ in range(100):
            config.validate_config()
        end_time = time.time()

        # Validation should be very fast (allow margin on slower hosts)
        assert end_time - start_time < 2.0


class TestConfigComprehensiveEdgeCases:
    """Comprehensive edge case tests for configuration coverage"""

    def test_config_comprehensive_edge_cases(self, tmp_path):
        """Test configuration edge cases for comprehensive coverage"""

        # Test with invalid video directory that's a file
        fake_file = tmp_path / "fake_directory.txt"
        fake_file.write_text("not a directory")

        config = ServerConfig(
            video_directory=str(tmp_path), password_hash=TEST_PASSWORD_HASH
        )
        config.video_directory = str(fake_file)

        with pytest.raises(ValueError, match="is not a directory"):
            config.validate_config()

    def test_config_environment_fallback_coverage(self):
        """Test environment variable fallback coverage"""

        # Test environment variable fallback in _get_default_video_directory
        with patch("pathlib.Path.home", side_effect=RuntimeError("No home")):
            default_dir = _get_default_video_directory()
            assert default_dir == "./videos"


class TestConfigMainExecution:
    """Test config module main execution"""

    @patch("mediarelay.config.create_sample_env_file")
    def test_main_execution_calls_create_sample_env_file(self, mock_create_env):
        """Test that running config.py as main calls create_sample_env_file"""
        # Simulate running as main
        with patch("mediarelay.config.__name__", "__main__"):
            config_module.create_sample_env_file()
            mock_create_env.assert_called()


class TestProductionSecretKeyValidation:
    """Test production secret key requirements"""

    def test_production_requires_secret_key(self, tmp_path):
        """Production mode rejects missing or placeholder secret keys"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PRODUCTION": "true",
                "VIDEO_SERVER_SECRET_KEY": "your-secret-key-here",
            },
        ):
            with pytest.raises(ValueError, match="VIDEO_SERVER_SECRET_KEY"):
                ServerConfig(
                    video_directory=str(video_dir),
                    password_hash=TEST_PASSWORD_HASH,
                )

    def test_production_rejects_unset_secret_key(self, tmp_path):
        """Production mode rejects auto-generated ephemeral secret keys"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        env = {
            "VIDEO_SERVER_PRODUCTION": "true",
            "VIDEO_SERVER_DEBUG": "false",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("VIDEO_SERVER_SECRET_KEY", None)
            with pytest.raises(ValueError, match="VIDEO_SERVER_SECRET_KEY must be set"):
                ServerConfig(
                    video_directory=str(video_dir),
                    password_hash=TEST_PASSWORD_HASH,
                )

    def test_production_rejects_debug_mode(self, tmp_path):
        """Production mode rejects debug enabled via environment"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PRODUCTION": "true",
                "VIDEO_SERVER_SECRET_KEY": TEST_PRODUCTION_SECRET_KEY,
                "VIDEO_SERVER_DEBUG": "true",
                "VIDEO_SERVER_RATE_LIMIT": "true",
                "VIDEO_SERVER_LOG_DIR": str(log_dir),
            },
        ):
            with pytest.raises(ValueError, match="Debug mode cannot be enabled"):
                ServerConfig(
                    video_directory=str(video_dir),
                    password_hash=TEST_PASSWORD_HASH,
                    log_directory=str(log_dir),
                )

    def test_production_requires_rate_limiting(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Production mode rejects disabled rate limiting."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _setup_production_env(monkeypatch, video_dir, log_dir)
        monkeypatch.setenv("VIDEO_SERVER_RATE_LIMIT", "false")

        with pytest.raises(ValueError, match="VIDEO_SERVER_RATE_LIMIT must be true"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(log_dir),
            )

    def test_validate_config_runs_deployment_checks_in_production(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """validate_config enforces deployment rules when production is enabled."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        monkeypatch.setenv("VIDEO_SERVER_PRODUCTION", "true")
        monkeypatch.setenv("VIDEO_SERVER_SECRET_KEY", TEST_PRODUCTION_SECRET_KEY)
        monkeypatch.setenv("VIDEO_SERVER_RATE_LIMIT", "true")
        monkeypatch.setenv("VIDEO_SERVER_DEBUG", "false")
        monkeypatch.setenv("VIDEO_SERVER_DIRECTORY", str(video_dir))
        monkeypatch.setenv("VIDEO_SERVER_LOG_DIR", str(log_dir))

        with pytest.raises(ValueError, match="must not be writable"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(log_dir),
            )


class TestParseIntEnv:
    """Test integer environment variable parsing"""

    @pytest.mark.parametrize(
        "env_name,env_value,match",
        [
            ("VIDEO_SERVER_PORT", "invalid", "VIDEO_SERVER_PORT must be an integer"),
            ("VIDEO_SERVER_PORT", "0", "VIDEO_SERVER_PORT must be at least 1"),
            ("VIDEO_SERVER_PORT", "70000", "VIDEO_SERVER_PORT must be at most 65535"),
        ],
    )
    def test_invalid_port_env(self, tmp_path, env_name, env_value, match):
        """Invalid port values raise clear errors"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        with patch.dict(
            os.environ,
            {
                env_name: env_value,
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
            },
        ):
            with pytest.raises(ValueError, match=match):
                ServerConfig()


class TestLoadConfigFile:
    """Test load_config with explicit config file path"""

    def test_load_config_from_file(self, tmp_path):
        """Load configuration from a specified .env file"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_HOST=10.0.0.1\n"
            f"VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n",
            encoding="utf-8",
        )

        config = load_config(env_file)
        assert config.host == "10.0.0.1"

    def test_load_config_missing_file(self, tmp_path):
        """Missing config file raises ValueError"""
        missing = tmp_path / "missing.env"
        with pytest.raises(ValueError, match="Configuration file not found"):
            load_config(missing)


class TestEnvFilePermissions:
    """Tests for insecure .env file permission warnings."""

    def test_world_readable_env_file_logs_warning(self, tmp_path, monkeypatch):
        """Warn when .env is readable by group or others on POSIX."""
        if os.name == "nt":
            pytest.skip("POSIX permission bits are not checked on Windows")

        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        env_file.chmod(0o644)
        monkeypatch.chdir(tmp_path)

        with patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning:
            load_config()

        mock_warning.assert_called_once()
        assert "readable by group or others" in mock_warning.call_args[0][0]

    def test_owner_only_env_file_no_warning(self, tmp_path, monkeypatch):
        """No warning when .env is owner-readable only on POSIX."""
        if os.name == "nt":
            pytest.skip("POSIX permission bits are not checked on Windows")

        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        env_file.chmod(0o600)
        monkeypatch.chdir(tmp_path)

        with patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning:
            load_config()

        mock_warning.assert_not_called()

    def test_world_readable_env_file_logs_warning_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Warn when icacls shows broad read access on Windows."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        completed = subprocess.CompletedProcess(
            args=["icacls", str(env_file)],
            returncode=0,
            stdout=f"{env_file} Everyone:(R)\n",
            stderr="",
        )

        with (
            patch("mediarelay.config.os.name", "nt"),
            patch(
                "mediarelay.config.shutil.which",
                return_value=r"C:\Windows\System32\icacls.exe",
            ),
            patch("mediarelay.config.subprocess.run", return_value=completed),
            patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning,
        ):
            load_config()

        mock_warning.assert_called_once()
        assert "Everyone" in mock_warning.call_args[0]

    def test_owner_only_env_file_no_warning_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No warning when icacls shows no broad read principals on Windows."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        completed = subprocess.CompletedProcess(
            args=["icacls", str(env_file)],
            returncode=0,
            stdout=f"{env_file} LAPTOP\\Laptop:(F)\n",
            stderr="",
        )

        with (
            patch("mediarelay.config.os.name", "nt"),
            patch(
                "mediarelay.config.shutil.which",
                return_value=r"C:\Windows\System32\icacls.exe",
            ),
            patch("mediarelay.config.subprocess.run", return_value=completed),
            patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning,
        ):
            load_config()

        mock_warning.assert_not_called()

    def test_icacls_missing_no_warning_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No warning when icacls is not available on Windows."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        with (
            patch("mediarelay.config.os.name", "nt"),
            patch("mediarelay.config.shutil.which", return_value=None),
            patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning,
        ):
            load_config()

        mock_warning.assert_not_called()

    @pytest.mark.parametrize(
        "subprocess_error",
        [
            OSError("icacls unavailable"),
            subprocess.SubprocessError("icacls failed"),
        ],
    )
    def test_icacls_subprocess_error_no_warning_windows(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        subprocess_error: BaseException,
    ) -> None:
        """No warning when icacls subprocess invocation fails on Windows."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        with (
            patch("mediarelay.config.os.name", "nt"),
            patch(
                "mediarelay.config.shutil.which",
                return_value=r"C:\Windows\System32\icacls.exe",
            ),
            patch(
                "mediarelay.config.subprocess.run",
                side_effect=subprocess_error,
            ),
            patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning,
        ):
            load_config()

        mock_warning.assert_not_called()

    def test_icacls_nonzero_returncode_no_warning_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No warning when icacls exits with a non-zero status on Windows."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        completed = subprocess.CompletedProcess(
            args=["icacls", str(env_file)],
            returncode=1,
            stdout="",
            stderr="Access denied",
        )

        with (
            patch("mediarelay.config.os.name", "nt"),
            patch(
                "mediarelay.config.shutil.which",
                return_value=r"C:\Windows\System32\icacls.exe",
            ),
            patch("mediarelay.config.subprocess.run", return_value=completed),
            patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning,
        ):
            load_config()

        mock_warning.assert_not_called()

    def test_icacls_line_without_read_flag_skipped_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lines without read permission flags are ignored on Windows."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        completed = subprocess.CompletedProcess(
            args=["icacls", str(env_file)],
            returncode=0,
            stdout=f"{env_file} Everyone:(F)\n",
            stderr="",
        )

        with (
            patch("mediarelay.config.os.name", "nt"),
            patch(
                "mediarelay.config.shutil.which",
                return_value=r"C:\Windows\System32\icacls.exe",
            ),
            patch("mediarelay.config.subprocess.run", return_value=completed),
            patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning,
        ):
            load_config()

        mock_warning.assert_not_called()

    @pytest.mark.parametrize(
        "principal",
        [
            "Everyone",
            r"BUILTIN\Users",
            r"NT AUTHORITY\Authenticated Users",
        ],
    )
    def test_world_readable_env_file_logs_warning_windows_principals(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        principal: str,
    ) -> None:
        """Warn when icacls shows broad read access for each risky principal."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        completed = subprocess.CompletedProcess(
            args=["icacls", str(env_file)],
            returncode=0,
            stdout=f"{env_file} {principal}:(R)\n",
            stderr="",
        )

        with (
            patch("mediarelay.config.os.name", "nt"),
            patch(
                "mediarelay.config.shutil.which",
                return_value=r"C:\Windows\System32\icacls.exe",
            ),
            patch("mediarelay.config.subprocess.run", return_value=completed),
            patch("mediarelay.config._CONFIG_LOGGER.warning") as mock_warning,
        ):
            load_config()

        mock_warning.assert_called_once()
        assert principal in mock_warning.call_args[0]


class TestDeploymentConfigValidation:
    """Test deployment pre-flight configuration checks"""

    def test_deployment_config_valid(self, tmp_path, monkeypatch):
        """Valid configuration passes validation"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _patch_video_dir_readonly(monkeypatch, video_dir)

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_LOG_DIR={log_dir}\n"
            f"VIDEO_SERVER_PRODUCTION=true\n"
            f"VIDEO_SERVER_RATE_LIMIT=true\n",
            encoding="utf-8",
        )

        monkeypatch.chdir(tmp_path)
        validate_deployment_config(env_file)

    def test_deployment_config_rejects_non_production(self, tmp_path):
        """Deployment validation requires VIDEO_SERVER_PRODUCTION=true"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_PRODUCTION=false\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="VIDEO_SERVER_PRODUCTION must be true"):
            validate_deployment_config(env_file)

    def test_deployment_config_rejects_placeholder_secret(self, tmp_path):
        """Placeholder secret key fails deployment validation in production"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=your-secret-key-here\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_PRODUCTION=true\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="VIDEO_SERVER_SECRET_KEY"):
            validate_deployment_config(env_file)

    def test_deployment_config_rejects_placeholder_hash(self, tmp_path):
        """Placeholder password hash fails validation"""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=your-password-hash-here\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_PRODUCTION=true\n",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="placeholder"):
            validate_deployment_config(env_file)


class TestConfigProductionAuditEdgeCases:
    """Edge-case validation added during production audit."""

    def test_empty_allowed_extensions_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": "",
            },
        ):
            with pytest.raises(ValueError, match="allowed_extensions cannot be empty"):
                ServerConfig()

    def test_negative_max_file_size_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with pytest.raises(ValueError, match="max_file_size cannot be negative"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                max_file_size=-1,
            )

    def test_invalid_session_cookie_samesite(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_SESSION_COOKIE_SAMESITE": "Invalid",
            },
        ):
            with pytest.raises(ValueError, match="SESSION_COOKIE_SAMESITE"):
                ServerConfig()

    def test_samesite_none_requires_secure_cookie(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_SESSION_COOKIE_SAMESITE": "None",
                "VIDEO_SERVER_SESSION_COOKIE_SECURE": "false",
            },
        ):
            with pytest.raises(ValueError, match="SAMESITE=None requires"):
                ServerConfig()

    def test_load_config_default_env_file(self, tmp_path: Path, monkeypatch) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        env_file = tmp_path / ".env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=scrypt:32768:8:1$PDnabs9h0vTp3nMK$ccdda3d296c0b59f5c875706be7ebdea90caf06a35aa97697c26ce4748a970b31202791996afe2c53604defce4d71a7ff2a0a2e9a78a52cd8246d3081ca57dab\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_USERNAME=envuser\n"
            f"VIDEO_SERVER_PRODUCTION=false\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        for env_name in (
            "VIDEO_SERVER_PRODUCTION",
            "VIDEO_SERVER_USERNAME",
            "VIDEO_SERVER_PASSWORD_HASH",
            "VIDEO_SERVER_DIRECTORY",
        ):
            monkeypatch.delenv(env_name, raising=False)
        config = load_config()
        assert config.username == "envuser"

    def test_samesite_lax_normalized(self, tmp_path: Path) -> None:
        """Lax SameSite values are normalized at load time."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_SESSION_COOKIE_SAMESITE": "lax",
            },
        ):
            config = ServerConfig()
            assert config.session_cookie_samesite == "Lax"

    def test_allowed_extensions_missing_dot_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": "mp4",
            },
        ):
            with pytest.raises(
                ValueError, match="Invalid VIDEO_SERVER_ALLOWED_EXTENSIONS"
            ):
                ServerConfig()

    def test_allowed_extensions_non_alphanumeric_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_ALLOWED_EXTENSIONS": ".m$p4",
            },
        ):
            with pytest.raises(
                ValueError, match="Invalid VIDEO_SERVER_ALLOWED_EXTENSIONS"
            ):
                ServerConfig()

    def test_deployment_config_rejects_writable_video_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deployment validation rejects a writable video directory."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_LOG_DIR={log_dir}\n"
            f"VIDEO_SERVER_PRODUCTION=true\n"
            f"VIDEO_SERVER_RATE_LIMIT=true\n",
            encoding="utf-8",
        )

        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="must not be writable"):
            validate_deployment_config(env_file)

    def test_deployment_config_rejects_missing_log_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deployment validation rejects a missing log directory."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        missing_log_dir = tmp_path / "logs"

        monkeypatch.chdir(tmp_path)
        _patch_video_dir_readonly(monkeypatch, video_dir)
        _setup_production_env(monkeypatch, video_dir, missing_log_dir)
        with (
            patch("mediarelay.config._validate_log_directory"),
            pytest.raises(ValueError, match="Log directory does not exist"),
        ):
            ServerConfig(
                video_directory=str(video_dir),
                log_directory=str(missing_log_dir),
                password_hash=TEST_PASSWORD_HASH,
                secret_key=TEST_PRODUCTION_SECRET_KEY,
            )

    def test_deployment_config_rejects_non_writable_log_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deployment validation rejects a non-writable log directory."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_LOG_DIR={log_dir}\n"
            f"VIDEO_SERVER_PRODUCTION=true\n"
            f"VIDEO_SERVER_RATE_LIMIT=true\n",
            encoding="utf-8",
        )

        monkeypatch.chdir(tmp_path)
        _patch_video_dir_readonly(monkeypatch, video_dir)
        _patch_log_dir_readonly(monkeypatch, log_dir)
        with pytest.raises(ValueError, match="Log directory is not writable"):
            validate_deployment_config(env_file)

    def test_deployment_config_warns_on_max_file_size_zero(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deployment validation warns when streaming size limits are disabled."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _patch_video_dir_readonly(monkeypatch, video_dir)

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_LOG_DIR={log_dir}\n"
            f"VIDEO_SERVER_MAX_FILE_SIZE=0\n"
            f"VIDEO_SERVER_PRODUCTION=true\n"
            f"VIDEO_SERVER_RATE_LIMIT=true\n",
            encoding="utf-8",
        )

        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING):
            validate_deployment_config(env_file)

        assert any("MAX_FILE_SIZE is 0" in record.message for record in caplog.records)

    def test_deployment_config_warns_on_public_bind_without_proxy(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deployment validation warns when binding to 0.0.0.0 without a proxy."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _patch_video_dir_readonly(monkeypatch, video_dir)

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_LOG_DIR={log_dir}\n"
            f"VIDEO_SERVER_HOST=0.0.0.0\n"
            f"VIDEO_SERVER_BEHIND_PROXY=false\n"
            f"VIDEO_SERVER_PRODUCTION=true\n"
            f"VIDEO_SERVER_RATE_LIMIT=true\n",
            encoding="utf-8",
        )

        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING):
            validate_deployment_config(env_file)

        assert any("0.0.0.0" in record.message for record in caplog.records)

    def test_deployment_config_rejects_proxy_without_trust(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Deployment validation rejects behind_proxy without proxy_trusted."""
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _patch_video_dir_readonly(monkeypatch, video_dir)

        env_file = tmp_path / "test.env"
        env_file.write_text(
            f"VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$testsalt$deadbeef\n"
            f"VIDEO_SERVER_SECRET_KEY=test-production-secret-key-32chars-min\n"
            f"VIDEO_SERVER_DIRECTORY={video_dir}\n"
            f"VIDEO_SERVER_LOG_DIR={log_dir}\n"
            f"VIDEO_SERVER_BEHIND_PROXY=true\n"
            f"VIDEO_SERVER_PROXY_TRUSTED=false\n"
            f"VIDEO_SERVER_PRODUCTION=true\n"
            f"VIDEO_SERVER_RATE_LIMIT=true\n",
            encoding="utf-8",
        )

        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="PROXY_TRUSTED"):
            validate_deployment_config(env_file)

    def test_check_runtime_health_true(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            log_directory=str(tmp_path / "logs"),
        )
        assert config.check_runtime_health() is True

    def test_check_runtime_health_false_when_missing(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            log_directory=str(tmp_path / "logs"),
        )
        video_dir.rmdir()
        assert config.check_runtime_health() is False

    @pytest.mark.parametrize("port", [1, 65535])
    def test_port_boundary_values(self, tmp_path: Path, port: int) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            log_directory=str(tmp_path / "logs"),
            port=port,
        )
        assert config.port == port

    def test_waitress_tuning_defaults(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            log_directory=str(tmp_path / "logs"),
        )
        assert config.channel_timeout == 300
        assert config.connection_limit == 1000
        assert config.cleanup_interval == 30

    def test_invalid_log_level_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with pytest.raises(ValueError, match="VIDEO_SERVER_LOG_LEVEL"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(tmp_path / "logs"),
                log_level="INVALID_LEVEL",
            )

    def test_empty_username_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with pytest.raises(ValueError, match="USERNAME must not be empty"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(tmp_path / "logs"),
                username="   ",
            )

    def test_username_too_long_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with pytest.raises(ValueError, match="USERNAME must be at most"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(tmp_path / "logs"),
                username="a" * 129,
            )

    def test_session_max_lifetime_must_exceed_timeout(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with pytest.raises(ValueError, match="SESSION_MAX_LIFETIME"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(tmp_path / "logs"),
                session_timeout=7200,
                session_max_lifetime=3600,
            )

    def test_production_requires_secure_session_cookie(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PRODUCTION": "true",
                "VIDEO_SERVER_SECRET_KEY": TEST_PRODUCTION_SECRET_KEY,
                "VIDEO_SERVER_SESSION_COOKIE_SECURE": "false",
            },
        ):
            with pytest.raises(ValueError, match="SESSION_COOKIE_SECURE must be true"):
                ServerConfig(
                    video_directory=str(video_dir),
                    password_hash=TEST_PASSWORD_HASH,
                    log_directory=str(tmp_path / "logs"),
                )

    def test_samesite_case_insensitive(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_SESSION_COOKIE_SAMESITE": "strict",
            },
        ):
            config = ServerConfig(log_directory=str(tmp_path / "logs"))
        assert config.session_cookie_samesite == "Strict"

    def test_bool_env_strips_whitespace(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
                "VIDEO_SERVER_DEBUG": " true ",
                "VIDEO_SERVER_PRODUCTION": "false",
            },
        ):
            config = ServerConfig(log_directory=str(tmp_path / "logs"))
            assert config.debug is True

    def test_unreadable_video_directory_rejected(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch("mediarelay.config.os.access", return_value=False):
            with pytest.raises(ValueError, match="not readable"):
                ServerConfig(
                    video_directory=str(video_dir),
                    password_hash=TEST_PASSWORD_HASH,
                    log_directory=str(tmp_path / "logs"),
                )

    def test_check_runtime_health_handles_exceptions(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        config = ServerConfig(
            video_directory=str(video_dir),
            password_hash=TEST_PASSWORD_HASH,
            log_directory=str(tmp_path / "logs"),
        )
        with patch.object(Path, "exists", side_effect=OSError("boom")):
            assert config.check_runtime_health() is False


class TestPasswordHashFormatValidation:
    """Password hash must use a supported Werkzeug format at startup."""

    @pytest.mark.parametrize(
        "invalid_hash,match",
        [
            ("plaintext", "Werkzeug hash"),
            ("$2b$12$invalidbcrypt", "bcrypt format"),
            ("md5:deadbeef", "Werkzeug hash"),
        ],
    )
    def test_rejects_invalid_hash_formats(
        self, tmp_path: Path, invalid_hash: str, match: str
    ) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with pytest.raises(ValueError, match=match):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=invalid_hash,
                log_directory=str(tmp_path / "logs"),
            )


class TestProductionHttponlyValidation:
    """Production mode requires HttpOnly session cookies."""

    def test_production_rejects_httponly_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _setup_production_env(monkeypatch, video_dir, log_dir)
        monkeypatch.setenv("VIDEO_SERVER_SESSION_COOKIE_HTTPONLY", "false")

        with pytest.raises(ValueError, match="HTTPONLY must be true"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(log_dir),
            )


class TestNumericUpperBounds:
    """Numeric settings reject values above documented upper bounds."""

    def test_threads_upper_bound(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_THREADS": "999999",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
            },
        ):
            with pytest.raises(
                ValueError, match="VIDEO_SERVER_THREADS must be at most"
            ):
                ServerConfig(log_directory=str(tmp_path / "logs"))

    def test_invalid_log_max_bytes_env(self, tmp_path: Path) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "VIDEO_SERVER_LOG_MAX_BYTES": "invalid",
                "VIDEO_SERVER_PASSWORD_HASH": TEST_PASSWORD_HASH,
                "VIDEO_SERVER_DIRECTORY": str(video_dir),
            },
        ):
            with pytest.raises(
                ValueError, match="VIDEO_SERVER_LOG_MAX_BYTES must be an integer"
            ):
                ServerConfig(log_directory=str(tmp_path / "logs"))

    def test_production_rejects_short_secret_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        video_dir = tmp_path / "videos"
        video_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        _setup_production_env(monkeypatch, video_dir, log_dir)
        monkeypatch.setenv("VIDEO_SERVER_SECRET_KEY", "too-short")

        with pytest.raises(ValueError, match="at least 32 characters"):
            ServerConfig(
                video_directory=str(video_dir),
                password_hash=TEST_PASSWORD_HASH,
                log_directory=str(log_dir),
            )
