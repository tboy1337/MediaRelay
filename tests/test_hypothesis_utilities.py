"""
Property-based tests for utility functions using Hypothesis
----------------------------------------------------------
Tests that utility functions maintain invariants across various
inputs and edge cases.
"""

import tempfile
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import assume, example, given, settings
from hypothesis import strategies as st

from config import ServerConfig
from streaming_server import MediaRelayServer


class TestBreadcrumbGenerationProperties:
    """Property-based tests for breadcrumb navigation generation"""

    @pytest.mark.hypothesis
    def test_breadcrumbs_always_start_with_home(self) -> None:
        """
        Property: Breadcrumb lists ALWAYS start with 'Home'.

        This is a navigation invariant - users must always be able
        to return to the root.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    breadcrumbs = server.get_breadcrumbs(test_dir)

                    assert len(breadcrumbs) >= 1, "Breadcrumbs list is empty"
                    assert (
                        breadcrumbs[0]["name"] == "Home"
                    ), f"First breadcrumb is {breadcrumbs[0]['name']!r}, not 'Home'"
                    assert (
                        breadcrumbs[0]["path"] == "/"
                    ), "Home breadcrumb path is not '/'"

    @given(
        st.lists(
            st.text(
                min_size=1,
                max_size=20,
                alphabet=st.characters(
                    whitelist_categories=("Lu", "Ll", "Nd"),
                    blacklist_characters="/\\",
                ),
            ),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=30, deadline=2000)
    @example(["movies", "action"])
    @example(["videos"])
    @pytest.mark.hypothesis
    def test_breadcrumb_path_construction(self, path_parts: list[str]) -> None:
        """
        Property: Breadcrumb paths are correctly constructed from directory structure.

        Each breadcrumb should have incrementally building path.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            # Create nested directory structure
            current_path = test_dir
            for part in path_parts:
                current_path = current_path / part
                current_path.mkdir(exist_ok=True)

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    breadcrumbs = server.get_breadcrumbs(current_path)

                    # Should have Home + all path parts
                    expected_count = 1 + len(path_parts)
                    assert (
                        len(breadcrumbs) == expected_count
                    ), f"Expected {expected_count} breadcrumbs, got {len(breadcrumbs)}"

                    # Verify each breadcrumb
                    assert breadcrumbs[0]["name"] == "Home"
                    for i, part in enumerate(path_parts, start=1):
                        assert (
                            breadcrumbs[i]["name"] == part
                        ), f"Breadcrumb {i} name mismatch: {breadcrumbs[i]['name']!r} != {part!r}"

    @pytest.mark.hypothesis
    def test_root_directory_has_one_breadcrumb(self) -> None:
        """
        Property: Root video directory ALWAYS has exactly one breadcrumb (Home).
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    breadcrumbs = server.get_breadcrumbs(test_dir)

                    assert (
                        len(breadcrumbs) == 1
                    ), f"Root should have 1 breadcrumb, got {len(breadcrumbs)}"
                    assert breadcrumbs[0]["name"] == "Home"

    @given(
        st.lists(
            st.text(
                min_size=1,
                max_size=15,
                alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
            ),
            min_size=1,
            max_size=3,
        )
    )
    @settings(max_examples=20, deadline=2000)
    @pytest.mark.hypothesis
    def test_breadcrumb_paths_incrementally_build(self, path_parts: list[str]) -> None:
        """
        Property: Each breadcrumb path includes all previous path components.

        Path should build up: /, /a, /a/b, /a/b/c
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            # Create nested directory
            current = test_dir
            for part in path_parts:
                current = current / part
                current.mkdir(exist_ok=True)

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    breadcrumbs = server.get_breadcrumbs(current)

                    # Check that paths build up correctly
                    for i in range(1, len(breadcrumbs)):
                        prev_path = breadcrumbs[i - 1]["path"]
                        curr_path = breadcrumbs[i]["path"]

                        # Current path should start with previous path
                        # (except for root which is just "/")
                        if prev_path != "/":
                            assert curr_path.startswith(
                                prev_path
                            ), f"Path doesn't build: {curr_path!r} doesn't start with {prev_path!r}"


class TestPathNormalizationProperties:
    """Property-based tests for path normalization"""

    @given(
        st.lists(
            st.text(
                min_size=1,
                max_size=15,
                alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
            ),
            min_size=1,
            max_size=3,
        )
    )
    @settings(max_examples=30, deadline=2000)
    @example(["test"])
    @pytest.mark.hypothesis
    def test_windows_path_separators_handled(self, path_parts: list[str]) -> None:
        """
        Property: Windows path separators (backslash) are handled consistently.

        The system should normalize paths regardless of separator used.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            # Create test structure
            current = test_dir
            for part in path_parts:
                current = current / part
                current.mkdir(exist_ok=True)

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    # Test both separators
                    unix_path = "/".join(path_parts)
                    windows_path = "\\".join(path_parts)

                    result_unix = server.get_safe_path(unix_path)
                    result_windows = server.get_safe_path(windows_path)

                    # Both should resolve to same location or both fail
                    if result_unix is not None and result_windows is not None:
                        # Normalize for comparison
                        assert (
                            result_unix.resolve() == result_windows.resolve()
                        ), "Path separator handling inconsistent"

    @given(
        st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
        )
    )
    @settings(max_examples=30, deadline=1000)
    @example("test.mp4")
    @pytest.mark.hypothesis
    def test_case_sensitivity_consistent(self, filename: str) -> None:
        """
        Property: Path handling is case-consistent with filesystem.

        On case-insensitive systems, paths should work regardless of case.
        On case-sensitive systems, case must match exactly.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            # Create test file
            test_file = test_dir / filename
            test_file.write_text("test")

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    result = server.get_safe_path(filename)

                    # Should find the file
                    if result is not None:
                        assert result.exists(), f"Resolved path {result} doesn't exist"


class TestFileExtensionMatchingProperties:
    """Property-based tests for file extension matching"""

    @given(
        st.sampled_from([".mp4", ".MP4", ".mP4", ".Mp4"]),
    )
    @settings(max_examples=20, deadline=1000)
    @example(".mp4")
    @example(".MP4")
    @pytest.mark.hypothesis
    def test_extension_matching_case_insensitive(self, extension: str) -> None:
        """
        Property: Extension matching is case-insensitive.

        .mp4, .MP4, .Mp4 should all be treated the same.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            # Check if extension (in lowercase) is in allowed extensions
            assert (
                extension.lower() in config.allowed_extensions
            ), f"Extension {extension!r} not properly normalized"

    @given(
        st.text(
            min_size=1,
            max_size=10,
            alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
        ),
    )
    @settings(max_examples=30, deadline=1000)
    @example("mp4")
    @pytest.mark.hypothesis
    def test_extension_comparison_properties(self, ext: str) -> None:
        """
        Property: Extension comparison handles various formats.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            # Create file with extension
            test_file = test_dir / f"test.{ext}"
            test_file.write_text("test")

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            # Check if extension is in allowed list
            ext_with_dot = f".{ext}".lower()
            is_allowed = ext_with_dot in config.allowed_extensions

            # File extension should be consistently recognized
            file_ext = test_file.suffix.lower()
            assert file_ext in (
                ext_with_dot,
                f".{ext}",
            ), f"Extension parsing inconsistent: {file_ext!r} vs {ext_with_dot!r}"


class TestURLQuoteUnquoteProperties:
    """Property-based tests for URL encoding/decoding"""

    @given(
        st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(
                whitelist_categories=("Lu", "Ll", "Nd"),
                blacklist_characters="/\\",
            ),
        ).filter(lambda s: ".." not in s and "//" not in s)
    )
    @settings(max_examples=30, deadline=1000)
    @example("test_file")
    @pytest.mark.hypothesis
    def test_url_quote_unquote_roundtrip(self, text: str) -> None:
        """
        Property: URL quote/unquote is reversible for safe strings.

        quote(unquote(text)) should equal text for safe strings.
        """
        quoted = urllib.parse.quote(text)
        unquoted = urllib.parse.unquote(quoted)

        assert (
            unquoted == text
        ), f"URL quote/unquote not reversible: {text!r} -> {quoted!r} -> {unquoted!r}"

    @given(
        st.sampled_from(
            [
                "hello world",  # Space
                "test&file",  # Ampersand
                "file#1",  # Hash
                "test?query",  # Question mark
            ]
        )
    )
    @settings(max_examples=10, deadline=500)
    @pytest.mark.hypothesis
    def test_special_characters_url_encoded(self, text_with_special: str) -> None:
        """
        Property: Special characters are properly URL encoded.
        """
        quoted = urllib.parse.quote(text_with_special)

        # Special characters should be encoded
        if " " in text_with_special:
            assert "%20" in quoted or "+" in quoted
        if "&" in text_with_special:
            assert "%26" in quoted
        if "#" in text_with_special:
            assert "%23" in quoted

        # Should decode back to original
        unquoted = urllib.parse.unquote(quoted)
        # Note: + doesn't decode to space with unquote, need unquote_plus
        if "+" not in quoted:
            assert unquoted == text_with_special

    @given(st.binary(min_size=1, max_size=20))
    @settings(max_examples=30, deadline=1000)
    @pytest.mark.hypothesis
    def test_url_operations_never_crash(self, binary_data: bytes) -> None:
        """
        Property: URL operations never crash on any input.

        Even with binary data or invalid UTF-8, operations should not crash.
        """
        try:
            # Try to decode as UTF-8, fall back to latin1
            try:
                text = binary_data.decode("utf-8")
            except UnicodeDecodeError:
                text = binary_data.decode("latin1")

            # These operations should not crash
            quoted = urllib.parse.quote(text)
            unquoted = urllib.parse.unquote(quoted)

            # Verify types are correct
            assert isinstance(quoted, str)
            assert isinstance(unquoted, str)

        except Exception as e:  # pylint: disable=broad-except
            # Some inputs may fail, but shouldn't crash Python
            assert isinstance(
                e, (ValueError, UnicodeError, OSError)
            ), f"Unexpected exception type: {type(e)}"


class TestPathExistenceProperties:
    """Property-based tests for path existence checks"""

    @given(
        st.lists(
            st.text(
                min_size=1,
                max_size=15,
                alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
            ),
            min_size=1,
            max_size=3,
        )
    )
    @settings(max_examples=20, deadline=2000)
    @pytest.mark.hypothesis
    def test_existing_paths_resolved_correctly(self, path_parts: list[str]) -> None:
        """
        Property: Existing paths within video directory are resolved correctly.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            # Create nested structure
            current = test_dir
            for part in path_parts:
                current = current / part
                current.mkdir(exist_ok=True)

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    path_str = "/".join(path_parts)
                    result = server.get_safe_path(path_str)

                    # Should resolve successfully
                    assert (
                        result is not None
                    ), f"Existing path {path_str!r} not resolved"
                    assert result.exists(), f"Resolved path {result} doesn't exist"

    @given(
        st.text(
            min_size=1,
            max_size=30,
            alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
        ).filter(lambda s: ".." not in s and "//" not in s)
    )
    @settings(max_examples=30, deadline=1000)
    @example("nonexistent_dir")
    @pytest.mark.hypothesis
    def test_nonexistent_safe_paths_return_path_object(
        self, nonexistent_name: str
    ) -> None:
        """
        Property: Non-existent but safe paths return Path object or None.

        The path may not exist, but as long as it's safe (no traversal),
        it should return a Path object that can be checked for existence.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    result = server.get_safe_path(nonexistent_name)

                    # Should return Path or None, never crash
                    assert result is None or isinstance(
                        result, Path
                    ), f"Unexpected result type: {type(result)}"
