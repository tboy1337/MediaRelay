"""
Property-based tests for configuration validation using Hypothesis
-----------------------------------------------------------------
Tests that configuration validation maintains critical invariants
across a wide range of inputs and edge cases.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import assume, example, given, settings
from hypothesis import strategies as st

from config import ServerConfig


class TestPortValidationProperties:
    """Property-based tests for port validation"""

    @given(st.integers(max_value=0))
    @settings(max_examples=50, deadline=1000)
    @example(0)
    @example(-1)
    @example(-1000)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_port_below_range_always_rejected(self, invalid_port: int) -> None:
        """
        Property: Ports ≤ 0 are ALWAYS rejected with ValueError.

        Valid ports are 1-65535.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
                ServerConfig(
                    video_directory=temp_dir,
                    password_hash="test_hash",
                    port=invalid_port,
                )

    @given(st.integers(min_value=65536))
    @settings(max_examples=50, deadline=1000)
    @example(65536)
    @example(70000)
    @example(100000)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_port_above_range_always_rejected(self, invalid_port: int) -> None:
        """
        Property: Ports > 65535 are ALWAYS rejected with ValueError.

        Maximum valid port is 65535.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
                ServerConfig(
                    video_directory=temp_dir,
                    password_hash="test_hash",
                    port=invalid_port,
                )

    @given(st.integers(min_value=1, max_value=65535))
    @settings(max_examples=100, deadline=1000)
    @example(1)
    @example(65535)
    @example(5000)
    @example(8080)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_valid_ports_always_accepted(self, valid_port: int) -> None:
        """
        Property: All ports in range [1, 65535] are ALWAYS accepted.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                port=valid_port,
            )
            assert config.port == valid_port


class TestThreadCountValidationProperties:
    """Property-based tests for thread count validation"""

    @given(st.integers(max_value=0))
    @settings(max_examples=50, deadline=1000)
    @example(0)
    @example(-1)
    @example(-100)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_thread_count_below_one_always_rejected(self, invalid_threads: int) -> None:
        """
        Property: Thread counts < 1 are ALWAYS rejected with ValueError.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError, match="Thread count must be at least 1"):
                ServerConfig(
                    video_directory=temp_dir,
                    password_hash="test_hash",
                    threads=invalid_threads,
                )

    @given(st.integers(min_value=1, max_value=1000))
    @settings(max_examples=50, deadline=1000)
    @example(1)
    @example(6)
    @example(100)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_positive_thread_counts_always_accepted(self, valid_threads: int) -> None:
        """
        Property: All thread counts ≥ 1 are ALWAYS accepted.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                threads=valid_threads,
            )
            assert config.threads == valid_threads


class TestFileSizeValidationProperties:
    """Property-based tests for file size validation"""

    @given(st.integers(min_value=-1000000, max_value=0))
    @settings(max_examples=50, deadline=1000)
    @example(0)  # 0 means no limit
    @example(-1)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_zero_and_negative_file_size_accepted(self, file_size: int) -> None:
        """
        Property: File size of 0 or negative disables size limit.

        This is documented behavior - 0 or negative means unlimited.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                max_file_size=file_size,
            )
            assert config.max_file_size == file_size

    @given(st.integers(min_value=1, max_value=10**15))
    @settings(max_examples=50, deadline=1000)
    @example(1024)
    @example(21474836480)  # 20GB default
    @example(10**15)  # Very large
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_positive_file_sizes_always_accepted(self, file_size: int) -> None:
        """
        Property: All positive file sizes are accepted.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                max_file_size=file_size,
            )
            assert config.max_file_size == file_size


class TestBooleanParsingProperties:
    """Property-based tests for boolean environment variable parsing"""

    @given(
        st.sampled_from(
            ["true", "True", "TRUE", "yes", "Yes", "YES", "1", "on", "On", "ON"]
        )
    )
    @settings(max_examples=30, deadline=500)
    @example("true")
    @example("yes")
    @example("1")
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_truthy_strings_parsed_as_true(self, truthy_value: str) -> None:
        """
        Property: All recognized truthy strings are consistently parsed as True.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_DEBUG": truthy_value,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                },
            ):
                config = ServerConfig()
                assert (
                    config.debug is True
                ), f"Truthy value {truthy_value!r} not parsed as True"

    @given(
        st.text(
            min_size=1,
            max_size=20,
            alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
        ).filter(lambda s: s.lower() not in ("true", "yes", "1", "on"))
    )
    @settings(max_examples=50, deadline=1000)
    @example("false")
    @example("no")
    @example("0")
    @example("off")
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_non_truthy_strings_parsed_as_false(self, falsy_value: str) -> None:
        """
        Property: All non-truthy strings are parsed as False.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_DEBUG": falsy_value,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                },
            ):
                config = ServerConfig()
                assert (
                    config.debug is False
                ), f"Non-truthy value {falsy_value!r} not parsed as False"

    @given(st.sampled_from(["true", "false"]))
    @settings(max_examples=10, deadline=500)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_rate_limiting_boolean_parsing(self, bool_value: str) -> None:
        """
        Property: Rate limiting boolean parsing is consistent.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_RATE_LIMIT": bool_value,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                },
            ):
                config = ServerConfig()
                expected = bool_value.lower() == "true"
                assert config.rate_limit_enabled == expected


class TestSessionTimeoutProperties:
    """Property-based tests for session timeout validation"""

    @given(st.integers(min_value=0, max_value=10**10))
    @settings(max_examples=50, deadline=1000)
    @example(0)  # Edge case
    @example(3600)  # Default
    @example(86400)  # 1 day
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_non_negative_timeouts_accepted(self, timeout: int) -> None:
        """
        Property: All non-negative timeout values are accepted.

        0 timeout might be problematic but is accepted by config.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                session_timeout=timeout,
            )
            assert config.session_timeout == timeout

    @given(st.integers(max_value=-1))
    @settings(max_examples=30, deadline=1000)
    @example(-1)
    @example(-3600)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_negative_timeouts_accepted_but_illogical(self, timeout: int) -> None:
        """
        Property: Negative timeouts are accepted (no validation currently).

        Note: This documents current behavior. Ideally negative timeouts
        would be rejected.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                session_timeout=timeout,
            )
            # Currently accepted, though illogical
            assert config.session_timeout == timeout


class TestPasswordHashValidationProperties:
    """Property-based tests for password hash validation"""

    @given(st.just(""))
    @settings(max_examples=5, deadline=500)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_empty_password_hash_always_rejected(self, empty_hash: str) -> None:
        """
        Property: Empty password hash is ALWAYS rejected.

        This is a critical security property.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError, match="PASSWORD_HASH must be set"):
                ServerConfig(
                    video_directory=temp_dir,
                    password_hash=empty_hash,
                )

    @given(
        st.text(
            min_size=1,
            max_size=500,
            alphabet=st.characters(blacklist_categories=("Cs",)),
        )
    )
    @settings(max_examples=50, deadline=1000)
    @example("test_hash")
    @example("pbkdf2:sha256:260000$test$hash")
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_non_empty_password_hash_accepted(self, password_hash: str) -> None:
        """
        Property: Any non-empty string is accepted as password hash.

        Note: No format validation is done on the hash itself.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash=password_hash,
            )
            assert config.password_hash == password_hash


class TestExtensionListParsingProperties:
    """Property-based tests for allowed extensions parsing"""

    @given(
        st.lists(
            st.text(
                min_size=1,
                max_size=10,
                alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
            ),
            min_size=1,
            max_size=10,
        ).map(lambda exts: [f".{ext}" for ext in exts])
    )
    @settings(max_examples=30, deadline=1000)
    @example([".mp4", ".mkv", ".avi"])
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_extension_list_parsing(self, extensions: list[str]) -> None:
        """
        Property: Extension lists are parsed correctly from comma-separated strings.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            extensions_str = ",".join(extensions)
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_ALLOWED_EXTENSIONS": extensions_str,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                },
            ):
                config = ServerConfig()
                # All extensions should be in the config
                for ext in extensions:
                    assert ext in config.allowed_extensions

    @given(
        st.lists(
            st.text(
                min_size=1,
                max_size=10,
                alphabet=st.characters(whitelist_categories=("Lu", "Ll")),
            ),
            min_size=1,
            max_size=5,
        ).map(lambda exts: [f" .{ext} " for ext in exts])
    )
    @settings(max_examples=20, deadline=1000)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_extension_list_whitespace_handling(self, extensions: list[str]) -> None:
        """
        Property: Whitespace in extension lists is handled correctly.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            extensions_str = ",".join(extensions)
            with patch.dict(
                os.environ,
                {
                    "VIDEO_SERVER_ALLOWED_EXTENSIONS": extensions_str,
                    "VIDEO_SERVER_DIRECTORY": temp_dir,
                    "VIDEO_SERVER_PASSWORD_HASH": "test_hash",
                },
            ):
                config = ServerConfig()
                # Stripped extensions should be in config
                for ext in extensions:
                    stripped = ext.strip()
                    assert stripped in config.allowed_extensions


class TestConfigToDictProperties:
    """Property-based tests for config serialization"""

    @given(
        st.integers(min_value=1, max_value=65535),
        st.integers(min_value=1, max_value=100),
        st.booleans(),
    )
    @settings(max_examples=30, deadline=1000)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_to_dict_never_includes_secrets(
        self, port: int, threads: int, debug: bool
    ) -> None:
        """
        Property: to_dict() NEVER includes sensitive data.

        Secret key and password hash must never be in the dictionary.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="secret_hash_value",
                secret_key="secret_key_value",
                port=port,
                threads=threads,
                debug=debug,
            )

            config_dict = config.to_dict()

            # Sensitive fields must NOT be in output
            assert "password_hash" not in config_dict, "Password hash exposed!"
            assert "secret_key" not in config_dict, "Secret key exposed!"

            # Non-sensitive fields should be present
            assert "port" in config_dict
            assert "threads" in config_dict
            assert "debug" in config_dict

    @given(
        st.integers(min_value=1, max_value=65535),
        st.integers(min_value=1, max_value=100),
    )
    @settings(max_examples=30, deadline=1000)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_to_dict_values_match_config(self, port: int, threads: int) -> None:
        """
        Property: to_dict() values always match config values.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                port=port,
                threads=threads,
            )

            config_dict = config.to_dict()

            assert config_dict["port"] == config.port
            assert config_dict["threads"] == config.threads
            assert config_dict["host"] == config.host


class TestVideoDirectoryValidationProperties:
    """Property-based tests for video directory validation"""

    @given(
        st.text(
            min_size=1,
            max_size=100,
            alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
        ).filter(lambda s: not Path(s).exists())
    )
    @settings(max_examples=30, deadline=1000)
    @example("/nonexistent/path")
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_nonexistent_directory_always_rejected(self, nonexistent_path: str) -> None:
        """
        Property: Non-existent video directories are ALWAYS rejected.
        """
        with pytest.raises(ValueError, match="Video directory does not exist"):
            ServerConfig(
                video_directory=nonexistent_path,
                password_hash="test_hash",
            )

    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_file_path_as_directory_rejected(self) -> None:
        """
        Property: File paths (not directories) are ALWAYS rejected.
        """
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
        # File is now closed, safe to use
        try:
            with pytest.raises(ValueError, match="not a directory"):
                ServerConfig(
                    video_directory=temp_path,
                    password_hash="test_hash",
                )
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestRateLimitProperties:
    """Property-based tests for rate limit configuration"""

    @given(st.integers(min_value=1, max_value=10000))
    @settings(max_examples=30, deadline=1000)
    @example(60)
    @example(1)
    @example(1000)
    @pytest.mark.hypothesis
    @pytest.mark.config
    def test_positive_rate_limits_accepted(self, rate_limit: int) -> None:
        """
        Property: All positive rate limits are accepted.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config = ServerConfig(
                video_directory=temp_dir,
                password_hash="test_hash",
                rate_limit_per_minute=rate_limit,
            )
            assert config.rate_limit_per_minute == rate_limit
