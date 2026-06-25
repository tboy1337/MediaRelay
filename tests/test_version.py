"""Tests for mediarelay package version resolution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import mediarelay
import mediarelay.__init__ as init_module


class TestVersionResolution:
    """Test version fallback logic in mediarelay.__init__."""

    def test_version_from_metadata_when_installed(self) -> None:
        with patch.object(init_module, "_version_from_metadata", return_value="1.2.3"):
            with patch.object(
                init_module, "_version_from_pyproject", return_value=None
            ):
                assert init_module._get_version() == "1.2.3"

    def test_version_from_pyproject_when_metadata_missing(self) -> None:
        with patch.object(init_module, "_version_from_metadata", return_value=None):
            with patch.object(
                init_module, "_version_from_pyproject", return_value="2.0.0"
            ):
                assert init_module._get_version() == "2.0.0"

    def test_version_dev_fallback(self) -> None:
        with patch.object(init_module, "_version_from_metadata", return_value=None):
            with patch.object(
                init_module, "_version_from_pyproject", return_value=None
            ):
                assert init_module._get_version() == "0.0.0.dev"

    def test_version_from_metadata_handles_errors(self) -> None:
        with patch(
            "importlib.metadata.version",
            side_effect=ValueError("not installed"),
        ):
            assert init_module._version_from_metadata() is None

    def test_version_from_pyproject_missing_file(self, tmp_path: Path) -> None:
        package_dir = tmp_path / "src" / "mediarelay"
        package_dir.mkdir(parents=True)
        init_file = package_dir / "__init__.py"
        init_file.write_text("", encoding="utf-8")

        with patch.object(init_module, "__file__", str(init_file)):
            assert init_module._version_from_pyproject() is None

    def test_version_from_pyproject_parses_version(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            'version = "9.9.9"\n', encoding="utf-8"
        )
        package_dir = tmp_path / "src" / "mediarelay"
        package_dir.mkdir(parents=True)
        init_file = package_dir / "__init__.py"
        init_file.write_text("", encoding="utf-8")

        with patch.object(init_module, "__file__", str(init_file)):
            assert init_module._version_from_pyproject() == "9.9.9"

    def test_version_from_pyproject_oserror(self, tmp_path: Path) -> None:
        package_dir = tmp_path / "src" / "mediarelay"
        package_dir.mkdir(parents=True)
        init_file = package_dir / "__init__.py"
        init_file.write_text("", encoding="utf-8")

        with patch.object(init_module, "__file__", str(init_file)):
            with patch.object(Path, "read_text", side_effect=OSError("read failed")):
                assert init_module._version_from_pyproject() is None

    def test_module_exports_version_string(self) -> None:
        assert isinstance(mediarelay.__version__, str)
        assert mediarelay.__version__
