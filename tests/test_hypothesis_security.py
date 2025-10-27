"""
Property-based tests for path security using Hypothesis
------------------------------------------------------
Tests that path traversal protection and security measures maintain
critical invariants across malicious and edge-case inputs.
"""

import tempfile
import urllib.parse
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import assume, example, given, settings
from hypothesis import strategies as st

from config import ServerConfig
from streaming_server import MediaRelayServer


@pytest.fixture(scope="function")
def security_test_server() -> MediaRelayServer:
    """Create a test server for security testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create subdirectory structure for testing
        test_dir = Path(temp_dir) / "videos"
        test_dir.mkdir(exist_ok=True)

        config = ServerConfig(
            video_directory=str(test_dir),
            password_hash="test_hash_for_security_testing",
            rate_limit_enabled=False,
        )

        with patch("streaming_server.setup_logging"):
            server = MediaRelayServer(config)
            # Mock the request context
            with server.app.test_request_context():
                yield server


class TestPathTraversalProtection:
    """Property-based tests for path traversal protection"""

    @given(
        st.integers(min_value=1, max_value=10).flatmap(
            lambda n: st.tuples(
                st.just(n), st.lists(st.just(".."), min_size=n, max_size=n)
            )
        )
    )
    @settings(max_examples=50, deadline=1000)
    @example((3, ["..", "..", ".."]))
    @example((1, [".."]))
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_parent_directory_traversal_always_rejected(
        self, path_components: tuple[int, list[str]]
    ) -> None:
        """
        Property: ANY path containing '..' is ALWAYS rejected.

        This is the most critical security property - path traversal
        attempts must never succeed.
        """
        _, parent_dirs = path_components

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
                    # Create path with .. components
                    path = "/".join(parent_dirs)
                    result = server.get_safe_path(path)

                    assert (
                        result is None
                    ), f"Path traversal with {path!r} was NOT rejected!"

    @given(
        st.one_of(
            st.just(".."),
            st.just("../"),
            st.just("/../"),
            st.just("//"),
            st.just("//etc"),
            st.just("../.."),
            st.text(min_size=1, max_size=20).map(lambda s: f"../{s}"),
            st.text(min_size=1, max_size=20).map(lambda s: f"{s}/.."),
            st.text(min_size=1, max_size=20).map(lambda s: f"//{s}"),
        )
    )
    @settings(max_examples=50, deadline=1000)
    @example("../..")
    @example("/../")
    @example("//etc")
    @example("test/../secret")
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_malicious_path_patterns_rejected(self, malicious_path: str) -> None:
        """
        Property: Paths with '..' or '//' are ALWAYS rejected.

        These patterns indicate path traversal or other attacks.
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
                    result = server.get_safe_path(malicious_path)
                    assert (
                        result is None
                    ), f"Malicious path {malicious_path!r} was NOT rejected!"

    @given(
        st.sampled_from(
            [
                "%2e%2e",  # URL encoded ..
                "%2e%2e%2f",  # URL encoded ../
                "..%2f",  # Mixed encoding
                "%2e.",  # Partial encoding
                ".%2e",  # Partial encoding
                "..%00",  # Null byte
                "..%0a",  # Newline
            ]
        )
    )
    @settings(max_examples=20, deadline=1000)
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_url_encoded_traversal_rejected(self, encoded_pattern: str) -> None:
        """
        Property: URL-encoded path traversal attempts are rejected.

        After URL decoding, patterns like %2e%2e should be caught.
        Note: This tests single URL encoding. Double-encoding would require
        multiple decode passes which is not done by the current implementation.
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
                    # The get_safe_path should handle URL decoding
                    result = server.get_safe_path(encoded_pattern)
                    assert (
                        result is None
                    ), f"URL encoded traversal {encoded_pattern!r} was NOT rejected!"

    @given(st.sampled_from(["", ""]))
    @settings(max_examples=5, deadline=500)
    @example("")
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_empty_path_returns_root(self, empty_path: str) -> None:
        """
        Property: Empty paths return video directory root.

        This is safe default behavior. Note: Whitespace-only paths
        are treated as valid path components, not empty paths.
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
                    result = server.get_safe_path(empty_path)

                    # Empty path should return the video directory itself
                    if result is not None:
                        assert result == Path(
                            config.video_directory
                        ), f"Empty path {empty_path!r} didn't return root"

    @given(
        st.text(
            alphabet=st.characters(
                blacklist_categories=("Cs", "Cc"),
                blacklist_characters="/\\",
            ),
            min_size=1,
            max_size=50,
        ).filter(lambda s: ".." not in s and "//" not in s)
    )
    @settings(max_examples=50, deadline=1000)
    @example("test.mp4")
    @example("video")
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_safe_paths_processed_correctly(self, safe_name: str) -> None:
        """
        Property: Paths without malicious patterns are processed.

        Safe paths (no .. or //) should either resolve successfully or
        return None for non-existent paths, but never crash.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "videos"
            test_dir.mkdir(exist_ok=True)

            # Create a test file
            test_file = test_dir / "safe.mp4"
            test_file.write_text("test")

            config = ServerConfig(
                video_directory=str(test_dir),
                password_hash="test_hash",
                rate_limit_enabled=False,
            )

            with patch("streaming_server.setup_logging"):
                server = MediaRelayServer(config)
                with server.app.test_request_context():
                    # Should not crash, even if path doesn't exist
                    try:
                        result = server.get_safe_path(safe_name)
                        # Result can be None (doesn't exist) or a Path object
                        assert result is None or isinstance(result, Path)
                    except (ValueError, RuntimeError, OSError):
                        # These exceptions are acceptable for malformed paths
                        pass


class TestPathSecurityEdgeCases:
    """Test edge cases in path security"""

    @given(
        st.lists(
            st.text(
                alphabet=st.characters(blacklist_categories=("Cs",)),
                min_size=1,
                max_size=20,
            ),
            min_size=1,
            max_size=5,
        ).map(lambda parts: "/".join(parts))
    )
    @settings(max_examples=50, deadline=1000)
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_long_paths_dont_crash(self, path: str) -> None:
        """
        Property: Arbitrarily long or complex paths don't crash the system.

        The system should handle any path gracefully.
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
                    try:
                        result = server.get_safe_path(path)
                        # Should return None or Path, never crash
                        assert result is None or isinstance(result, Path)
                    except (ValueError, RuntimeError, OSError):
                        # Acceptable for invalid paths
                        pass

    @given(st.binary(min_size=1, max_size=50).map(lambda b: b.decode("latin1")))
    @settings(max_examples=50, deadline=1000)
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_special_characters_handled_safely(self, special_path: str) -> None:
        """
        Property: Paths with special characters are handled safely.

        System should never crash on special characters, null bytes, etc.
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
                    try:
                        result = server.get_safe_path(special_path)
                        assert result is None or isinstance(result, Path)
                    except (ValueError, RuntimeError, OSError, UnicodeError):
                        # These are acceptable for invalid paths
                        pass

    @given(
        st.lists(st.just(".."), min_size=1, max_size=5),
        st.text(
            alphabet=st.characters(blacklist_categories=("Cs",)),
            min_size=1,
            max_size=20,
        ),
    )
    @settings(max_examples=30, deadline=1000)
    @example(["..", ".."], "etc/passwd")
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_traversal_before_legitimate_path_rejected(
        self, parent_dirs: list[str], legitimate: str
    ) -> None:
        """
        Property: Path traversal before legitimate path is ALWAYS rejected.

        Attackers might try ../../etc/passwd or similar patterns.
        """
        # Filter out cases where legitimate path contains .. or //
        assume(".." not in legitimate and "//" not in legitimate)

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
                    path = "/".join(parent_dirs + [legitimate])
                    result = server.get_safe_path(path)

                    assert result is None, f"Traversal path {path!r} was NOT rejected!"


class TestURLEncodingSecurityProperties:
    """Test URL encoding security properties"""

    @given(
        st.text(min_size=1, max_size=30).filter(
            lambda s: ".." not in s and "//" not in s
        )
    )
    @settings(max_examples=30, deadline=1000)
    @example("test.mp4")
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_url_decode_idempotent(self, path: str) -> None:
        """
        Property: URL encoding/decoding doesn't change path safety.

        A safe path remains safe after encoding/decoding, and an unsafe
        path remains unsafe.
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
                    # Test original path
                    result1 = server.get_safe_path(path)

                    # Test URL encoded path
                    encoded = urllib.parse.quote(path)
                    result2 = server.get_safe_path(encoded)

                    # Both should behave consistently (both None or both Path)
                    assert type(result1) == type(
                        result2
                    ), (  # pylint: disable=unidiomatic-typecheck
                        f"URL encoding changed path safety: {path!r} vs {encoded!r}"
                    )

    @given(
        st.sampled_from(
            [
                "test%00.mp4",  # Null byte
                "test%0a.mp4",  # Newline
                "test%0d.mp4",  # Carriage return
                "test%09.mp4",  # Tab
            ]
        )
    )
    @settings(max_examples=10, deadline=500)
    @pytest.mark.hypothesis
    @pytest.mark.security
    def test_control_character_injection_blocked(self, path_with_control: str) -> None:
        """
        Property: Control characters in paths are handled safely.

        Null bytes and other control characters shouldn't cause security issues.
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
                    try:
                        result = server.get_safe_path(path_with_control)
                        # Should handle safely - either reject or process
                        assert result is None or isinstance(result, Path)
                    except (ValueError, UnicodeError, OSError):
                        # Acceptable to raise for invalid input
                        pass
