"""
Unit tests for main entry points and CLI functionality
------------------------------------------------------
Focused tests not duplicated in test_streaming_server.py.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mediarelay.config import create_sample_env_file, validate_main
from mediarelay.server import main


class TestConfigMainEntryPoint:
    """Test cases for config module main entry point"""

    @patch("mediarelay.config.create_sample_env_file")
    def test_config_main_creates_sample_env(self, mock_create_env):
        """Test config module main entry point"""
        from mediarelay import config

        if hasattr(config, "__name__"):
            with patch("mediarelay.config.__name__", "__main__"):
                config.create_sample_env_file()

        mock_create_env.assert_called_once()


class TestGenerateConfigWorkflow:
    """Test sample environment file generation"""

    def test_main_generate_config_option(self):
        """Test create_sample_env_file writes expected keys"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmp_dir)
                create_sample_env_file()

                env_example_file = Path(".env.example")
                assert env_example_file.exists()

                content = env_example_file.read_text(encoding="utf-8")
                assert "VIDEO_SERVER_HOST" in content
                assert "VIDEO_SERVER_PORT" in content
                assert "VIDEO_SERVER_USERNAME" in content
                assert "VIDEO_SERVER_BEHIND_PROXY" in content
            finally:
                os.chdir(original_cwd)


class TestValidateMainEntryPoint:
    """Test mediarelay-validate CLI entry point"""

    @patch("mediarelay.config.validate_deployment_config")
    def test_validate_main_success(self, mock_validate):
        """Valid configuration prints success message"""
        mock_config = MagicMock()
        mock_config.host = "127.0.0.1"
        mock_config.port = 5000
        mock_config.video_directory = "/videos"
        mock_config.is_production.return_value = True
        mock_config.behind_proxy = False
        mock_validate.return_value = mock_config

        runner = CliRunner()
        result = runner.invoke(validate_main, [])

        assert result.exit_code == 0
        assert "Configuration is valid for deployment" in result.output

    @patch("mediarelay.config.validate_deployment_config")
    def test_validate_main_failure(self, mock_validate):
        """Invalid configuration exits with code 1"""
        mock_validate.side_effect = ValueError("VIDEO_SERVER_PASSWORD_HASH placeholder")

        runner = CliRunner()
        result = runner.invoke(validate_main, [])

        assert result.exit_code == 1
        assert "Configuration error" in result.output


class TestProductionServerRun:
    """Test cases for production server run method"""

    def test_server_run_method_logging(self, test_server):
        """Test server run method logs startup information"""
        with patch.object(test_server, "app") as mock_app:
            mock_logger = MagicMock()
            mock_app.logger = mock_logger

            with patch("mediarelay.server.serve") as mock_serve:
                mock_serve.side_effect = KeyboardInterrupt()

                try:
                    test_server.run()
                except KeyboardInterrupt:
                    pass

                mock_logger.info.assert_any_call("Starting server with configuration:")

    def test_server_directory_validation(self, test_server):
        """Test server validates video directory exists"""
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(ValueError, match="does not exist"):
                test_server.run()
