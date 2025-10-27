"""
Property-based tests for password generation using Hypothesis
------------------------------------------------------------
Tests that password generation functions maintain critical invariants
across a wide range of inputs.
"""

import string

import pytest
from hypothesis import assume, example, given, settings
from hypothesis import strategies as st

import generate_password


class TestPasswordGenerationProperties:
    """Property-based tests for password generation"""

    @given(st.integers(min_value=10, max_value=1000))
    @settings(max_examples=100, deadline=1000)
    @example(35)  # Default length
    @example(10)  # Minimum reasonable length
    @example(100)  # Longer password
    @pytest.mark.hypothesis
    def test_password_length_invariant(self, length: int) -> None:
        """
        Property: Generated password length always equals requested length.

        This is a critical security property - the password generator must
        produce exactly the length requested, never more or less.
        """
        password = generate_password.generate_strong_password(length)
        assert (
            len(password) == length
        ), f"Password length {len(password)} != requested {length}"

    @given(st.integers(min_value=10, max_value=200))
    @settings(max_examples=50, deadline=2000)
    @example(35)
    @example(20)
    @pytest.mark.hypothesis
    def test_password_strength_requirements_always_met(self, length: int) -> None:
        """
        Property: Generated passwords ALWAYS meet ALL strength requirements.

        Critical security property:
        - At least one lowercase letter
        - At least one uppercase letter
        - At least 3 digits
        - At least 2 punctuation characters

        This must hold for ANY valid password length.
        """
        password = generate_password.generate_strong_password(length)

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        digit_count = sum(c.isdigit() for c in password)
        punct_count = sum(c in string.punctuation for c in password)

        assert has_lower, f"Password missing lowercase: {password!r}"
        assert has_upper, f"Password missing uppercase: {password!r}"
        assert (
            digit_count >= 3
        ), f"Password has {digit_count} digits, need ≥3: {password!r}"
        assert (
            punct_count >= 2
        ), f"Password has {punct_count} punctuation, need ≥2: {password!r}"

    @given(st.integers(min_value=10, max_value=100))
    @settings(max_examples=50, deadline=1000)
    @pytest.mark.hypothesis
    def test_password_uses_only_valid_characters(self, length: int) -> None:
        """
        Property: Generated passwords contain only valid printable ASCII.

        Passwords should never contain:
        - Null bytes
        - Control characters
        - Non-ASCII characters
        """
        password = generate_password.generate_strong_password(length)
        valid_chars = string.ascii_letters + string.digits + string.punctuation

        for char in password:
            assert (
                char in valid_chars
            ), f"Invalid character {char!r} (ord={ord(char)}) in password"
            assert ord(char) >= 33, f"Control/whitespace char {char!r} in password"
            assert ord(char) <= 126, f"Non-ASCII char {char!r} in password"

    @given(st.integers(min_value=10, max_value=100))
    @settings(max_examples=20, deadline=5000)
    @pytest.mark.hypothesis
    def test_passwords_are_unique(self, length: int) -> None:
        """
        Property: Generated passwords are unique (probabilistic).

        While not guaranteed by cryptographic randomness, the probability
        of collision should be astronomically low.
        """
        passwords: set[str] = set()
        num_samples = 10  # Generate 10 passwords

        for _ in range(num_samples):
            password = generate_password.generate_strong_password(length)
            assert (
                password not in passwords
            ), f"Duplicate password generated: {password!r}"
            passwords.add(password)

        assert len(passwords) == num_samples, "Password uniqueness check failed"

    @given(st.integers(min_value=10, max_value=50))
    @settings(max_examples=50, deadline=1000)
    @pytest.mark.hypothesis
    def test_password_character_distribution(self, length: int) -> None:
        """
        Property: Passwords have reasonable character type distribution.

        While not enforcing exact ratios, we ensure that no single
        character type dominates excessively.
        """
        password = generate_password.generate_strong_password(length)

        lower_count = sum(c.islower() for c in password)
        upper_count = sum(c.isupper() for c in password)
        digit_count = sum(c.isdigit() for c in password)
        punct_count = sum(c in string.punctuation for c in password)

        # No single type should be >90% of password
        assert lower_count < length * 0.9, "Password too dominated by lowercase"
        assert upper_count < length * 0.9, "Password too dominated by uppercase"
        assert digit_count < length * 0.9, "Password too dominated by digits"
        assert punct_count < length * 0.9, "Password too dominated by punctuation"


class TestSecretKeyGenerationProperties:
    """Property-based tests for Flask secret key generation"""

    @given(st.integers(min_value=8, max_value=256))
    @settings(max_examples=50, deadline=500)
    @example(32)  # Default length
    @example(16)  # Common alternative
    @pytest.mark.hypothesis
    def test_secret_key_length_invariant(self, byte_length: int) -> None:
        """
        Property: Secret key hex string length is always 2 × byte_length.

        Each byte becomes 2 hex characters, so a 32-byte key becomes
        a 64-character hex string.
        """
        secret_key = generate_password.generate_flask_secret_key(byte_length)
        expected_length = byte_length * 2

        assert (
            len(secret_key) == expected_length
        ), f"Secret key length {len(secret_key)} != expected {expected_length}"

    @given(st.integers(min_value=8, max_value=128))
    @settings(max_examples=50, deadline=500)
    @example(32)
    @pytest.mark.hypothesis
    def test_secret_key_is_valid_hex(self, byte_length: int) -> None:
        """
        Property: Generated secret keys are ALWAYS valid lowercase hexadecimal.

        This is critical for Flask's session management.
        """
        secret_key = generate_password.generate_flask_secret_key(byte_length)
        valid_hex_chars = set("0123456789abcdef")

        for char in secret_key:
            assert (
                char in valid_hex_chars
            ), f"Invalid hex character {char!r} in secret key: {secret_key!r}"

    @given(st.integers(min_value=16, max_value=64))
    @settings(max_examples=20, deadline=1000)
    @pytest.mark.hypothesis
    def test_secret_keys_are_unique(self, byte_length: int) -> None:
        """
        Property: Generated secret keys are unique (probabilistic).

        Collision probability should be negligible for cryptographic randomness.
        """
        secret_keys: set[str] = set()
        num_samples = 10

        for _ in range(num_samples):
            key = generate_password.generate_flask_secret_key(byte_length)
            assert key not in secret_keys, f"Duplicate secret key: {key!r}"
            secret_keys.add(key)

        assert len(secret_keys) == num_samples

    @given(st.integers(min_value=8, max_value=64))
    @settings(max_examples=30, deadline=500)
    @pytest.mark.hypothesis
    def test_secret_key_hex_can_be_decoded(self, byte_length: int) -> None:
        """
        Property: Secret keys are valid hex that can be decoded to bytes.

        Ensures the key is not just hex-like, but actually valid hex encoding.
        """
        secret_key = generate_password.generate_flask_secret_key(byte_length)

        # Should be able to decode without error
        try:
            decoded = bytes.fromhex(secret_key)
            assert (
                len(decoded) == byte_length
            ), f"Decoded length {len(decoded)} != expected {byte_length}"
        except ValueError as e:
            pytest.fail(f"Secret key {secret_key!r} is not valid hex: {e}")

    @given(st.integers(min_value=8, max_value=64))
    @settings(max_examples=50, deadline=500)
    @pytest.mark.hypothesis
    def test_secret_key_entropy_distribution(self, byte_length: int) -> None:
        """
        Property: Secret keys have good character distribution.

        While not enforcing perfect uniformity, we check that no single
        hex digit dominates excessively.
        """
        secret_key = generate_password.generate_flask_secret_key(byte_length)

        # Count frequency of each hex digit
        for hex_char in "0123456789abcdef":
            count = secret_key.count(hex_char)
            # No single hex digit should be >40% of the key
            max_reasonable = len(secret_key) * 0.4
            assert count <= max_reasonable, (
                f"Hex digit {hex_char!r} appears {count} times "
                f"(>{max_reasonable:.0f}) in {secret_key!r}"
            )


class TestPasswordGenerationEdgeCases:
    """Test edge cases and boundary conditions"""

    @pytest.mark.hypothesis
    def test_minimum_practical_password_length(self) -> None:
        """
        Property: Even minimum length passwords meet all requirements.

        The minimum practical length is 10 (1 lower + 1 upper + 3 digits
        + 2 punct + 3 more = 10).
        """
        # The function should handle this and produce valid password
        password = generate_password.generate_strong_password(10)
        assert len(password) == 10
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3
        assert sum(c in string.punctuation for c in password) >= 2

    @given(st.integers(min_value=50, max_value=500))
    @settings(max_examples=20, deadline=3000)
    @pytest.mark.hypothesis
    def test_large_password_generation_performance(self, length: int) -> None:
        """
        Property: Large passwords can be generated in reasonable time.

        Tests that the generation algorithm scales reasonably.
        """
        import time

        start = time.time()
        password = generate_password.generate_strong_password(length)
        duration = time.time() - start

        # Should complete in under 2 seconds even for very long passwords
        assert (
            duration < 2.0
        ), f"Password generation took {duration:.2f}s for length {length}"
        assert len(password) == length

    @given(st.integers(min_value=10, max_value=100))
    @settings(max_examples=30, deadline=1000)
    @pytest.mark.hypothesis
    def test_password_no_null_bytes(self, length: int) -> None:
        """
        Property: Passwords never contain null bytes.

        Null bytes can cause issues with C-based libraries and databases.
        """
        password = generate_password.generate_strong_password(length)
        assert "\x00" not in password, "Password contains null byte"

    @given(st.integers(min_value=10, max_value=100))
    @settings(max_examples=30, deadline=1000)
    @pytest.mark.hypothesis
    def test_password_no_whitespace(self, length: int) -> None:
        """
        Property: Passwords never contain whitespace characters.

        Whitespace can cause parsing issues and user confusion.
        """
        password = generate_password.generate_strong_password(length)
        assert not any(
            c.isspace() for c in password
        ), f"Password contains whitespace: {password!r}"
