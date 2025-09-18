"""
Unit tests for generate_password module
---------------------------------------
Tests for password generation utility functionality.
Includes comprehensive tests for 100% coverage.
"""

import string
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.security import generate_password_hash

import generate_password


class TestSecretKeyGeneration:
    """Test cases for Flask secret key generation"""

    def test_generate_flask_secret_key_default_length(self):
        """Test Flask secret key generation with default length"""
        secret_key = generate_password.generate_flask_secret_key()

        # Default length is 32, which produces 64 hex characters
        assert len(secret_key) == 64
        # Should be valid hex
        assert all(c in "0123456789abcdef" for c in secret_key)

    def test_generate_flask_secret_key_custom_length(self):
        """Test Flask secret key generation with custom length"""
        secret_key = generate_password.generate_flask_secret_key(16)

        # Length of 16 should produce 32 hex characters
        assert len(secret_key) == 32
        assert all(c in "0123456789abcdef" for c in secret_key)

    def test_generate_flask_secret_key_uniqueness(self):
        """Test that generated secret keys are unique"""
        key1 = generate_password.generate_flask_secret_key()
        key2 = generate_password.generate_flask_secret_key()

        assert key1 != key2


class TestPasswordGeneration:
    """Test cases for password generation"""

    def test_generate_strong_password_default_length(self):
        """Test password generation with default length"""
        password = generate_password.generate_strong_password()

        assert len(password) == 35
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3
        assert sum(c in string.punctuation for c in password) >= 2

    def test_generate_strong_password_custom_length(self):
        """Test password generation with custom length"""
        password = generate_password.generate_strong_password(20)

        assert len(password) == 20
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3
        assert sum(c in string.punctuation for c in password) >= 2

    def test_generate_strong_password_uniqueness(self):
        """Test that generated passwords are unique"""
        password1 = generate_password.generate_strong_password()
        password2 = generate_password.generate_strong_password()

        assert password1 != password2

    def test_generate_strong_password_requirements(self):
        """Test password meets all requirements"""
        password = generate_password.generate_strong_password(15)

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        digit_count = sum(c.isdigit() for c in password)
        punct_count = sum(c in string.punctuation for c in password)

        assert has_lower, "Password should contain lowercase letters"
        assert has_upper, "Password should contain uppercase letters"
        assert digit_count >= 3, "Password should contain at least 3 digits"
        assert punct_count >= 2, "Password should contain at least 2 punctuation marks"


class TestGeneratePasswordCompleteCoverage:
    """Tests specifically designed to achieve 100% coverage of generate_password.py"""

    def test_generate_strong_password_all_requirements(self):
        """Test generate_strong_password meets all requirements"""
        password = generate_password.generate_strong_password(25)

        assert len(password) == 25
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3
        assert sum(c in string.punctuation for c in password) >= 2

    def test_generate_strong_password_loop_behavior(self):
        """Test that generate_strong_password loops until requirements are met"""
        # Mock secrets.choice to return predictable sequences
        with patch("generate_password.secrets.choice") as mock_choice:
            # First attempt: no uppercase letters
            # Second attempt: no digits
            # Third attempt: valid password
            mock_choice.side_effect = (
                # First attempt - all lowercase, no digits, no punctuation
                ["a"] * 10
                +
                # Second attempt - has upper/lower but no digits
                ["A", "b", "C", "d"] * 3
                +
                # Third attempt - valid password
                ["A", "b", "1", "2", "3", "!", "@"] * 5
            )

            password = generate_password.generate_strong_password(10)
            assert len(password) == 10

    def test_generate_strong_password_character_distribution(self):
        """Test that generated password has good character distribution"""
        # Generate multiple passwords to test distribution
        passwords = [generate_password.generate_strong_password(20) for _ in range(10)]

        for password in passwords:
            # Each password should have all required character types
            assert any(
                c.islower() for c in password
            ), f"Password missing lowercase: {password}"
            assert any(
                c.isupper() for c in password
            ), f"Password missing uppercase: {password}"
            assert (
                sum(c.isdigit() for c in password) >= 3
            ), f"Password missing digits: {password}"
            assert (
                sum(c in string.punctuation for c in password) >= 2
            ), f"Password missing punctuation: {password}"

    def test_generate_strong_password_direct_function_coverage(self):
        """Test generate_strong_password function with various lengths"""
        password = generate_password.generate_strong_password()
        assert len(password) == 35  # Default length
        assert isinstance(password, str)

        # Test custom length
        password_custom = generate_password.generate_strong_password(24)
        assert len(password_custom) == 24

    def test_password_hashing_integration(self):
        """Test password hashing via werkzeug integration"""
        password = "testpassword123"
        hashed = generate_password_hash(password)
        assert len(hashed) > 50  # Hash should be substantial length


class TestMainFunction:
    """Test cases for the main interactive function"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_generated_password(self, mock_print, mock_input):
        """Test main function with generated password option"""
        mock_input.side_effect = [
            "testuser",
            "y",
        ]  # Username, choose generated password

        with patch("generate_password.generate_strong_password") as mock_gen:
            mock_gen.return_value = "TestPass123!"
            with patch("generate_password.generate_password_hash") as mock_hash:
                mock_hash.return_value = "hashed_password"
                with patch(
                    "generate_password.generate_flask_secret_key"
                ) as mock_secret:
                    mock_secret.return_value = "test_secret_key"

                    generate_password.main()

                    # Verify generate_password_hash was called
                    mock_hash.assert_called_once_with("TestPass123!")
                    # Verify generate_flask_secret_key was called
                    mock_secret.assert_called_once()

                    # Verify appropriate print calls were made
                    mock_print.assert_any_call("\nGenerated password: TestPass123!")
                    mock_print.assert_any_call(
                        "IMPORTANT: Save this password in a secure location!"
                    )
                    mock_print.assert_any_call(
                        "VIDEO_SERVER_SECRET_KEY=test_secret_key"
                    )
                    mock_print.assert_any_call("VIDEO_SERVER_USERNAME=testuser")
                    mock_print.assert_any_call(
                        "VIDEO_SERVER_PASSWORD_HASH=hashed_password"
                    )

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_custom_password_valid_first_try(
        self, mock_print, mock_input
    ):  # pylint: disable=unused-argument
        """Test main function with custom password that's valid on first try"""
        mock_input.side_effect = [
            "customuser",
            "n",
            "MyPassword123!",
            "MyPassword123!",
        ]  # Username, no generated, password, confirm

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"
            with patch("generate_password.generate_flask_secret_key") as mock_secret:
                mock_secret.return_value = "test_secret_key"

                generate_password.main()

                # Verify generate_password_hash was called with custom password
                mock_hash.assert_called_once_with("MyPassword123!")
                mock_secret.assert_called_once()

                # Verify username is printed in config
                mock_print.assert_any_call("VIDEO_SERVER_USERNAME=customuser")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_empty_username(self, mock_print, mock_input):
        """Test main function handles empty username input"""
        mock_input.side_effect = [
            "",  # Empty username first try
            "validuser",  # Valid username second try
            "y",  # Generate password
        ]

        with patch("generate_password.generate_strong_password") as mock_gen:
            mock_gen.return_value = "TestPass123!"
            with patch("generate_password.generate_password_hash") as mock_hash:
                mock_hash.return_value = "hashed_password"
                with patch(
                    "generate_password.generate_flask_secret_key"
                ) as mock_secret:
                    mock_secret.return_value = "test_secret_key"

                    generate_password.main()

                    # Verify error message was printed
                    mock_print.assert_any_call("Username cannot be empty!")
                    # Verify valid username is used
                    mock_print.assert_any_call("VIDEO_SERVER_USERNAME=validuser")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_custom_password_too_short(self, mock_print, mock_input):
        """Test main function with custom password that's too short"""
        mock_input.side_effect = [
            "testuser",  # Username
            "n",  # No generated password
            "short",  # Too short password
            "ValidPass123!",  # Valid password
            "ValidPass123!",  # Confirm password
        ]

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"
            with patch("generate_password.generate_flask_secret_key") as mock_secret:
                mock_secret.return_value = "test_secret_key"

                generate_password.main()

                # Verify error message was printed
                mock_print.assert_any_call(
                    "Password is too short! Use at least 8 characters."
                )
                mock_hash.assert_called_once_with("ValidPass123!")
                mock_secret.assert_called_once()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_with_password_mismatch(self, mock_print, mock_input):
        """Test main function with password confirmation mismatch"""
        mock_input.side_effect = [
            "testuser",  # Username
            "n",  # No generated password
            "MyPassword123!",  # Valid password
            "DifferentPass",  # Mismatched confirmation
            "MyPassword123!",  # Valid password again
            "MyPassword123!",  # Matching confirmation
        ]

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"
            with patch("generate_password.generate_flask_secret_key") as mock_secret:
                mock_secret.return_value = "test_secret_key"

                generate_password.main()

                # Verify error message was printed
                mock_print.assert_any_call("Passwords don't match! Try again.")
                mock_hash.assert_called_once_with("MyPassword123!")
                mock_secret.assert_called_once()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_prints_final_instructions(self, mock_print, mock_input):
        """Test that main function prints final instructions"""
        mock_input.side_effect = [
            "testuser",
            "y",
        ]  # Username, choose generated password

        with patch("generate_password.generate_strong_password"):
            with patch("generate_password.generate_password_hash") as mock_hash:
                mock_hash.return_value = "test_hash_value"
                with patch(
                    "generate_password.generate_flask_secret_key"
                ) as mock_secret:
                    mock_secret.return_value = "test_secret_key"

                    generate_password.main()

                    # Check that important instructions are printed
                    expected_calls = [
                        "Video Streaming Server - Configuration Setup",
                        "1. Copy the .env.example file to .env",
                        "2. Replace the following values in your .env file:",
                        "3. Configure other settings in .env as needed (directories, ports, etc.)",
                        "4. Save the .env file and run: python streaming_server.py",
                        "\nYou'll use the username 'testuser' and your chosen password to log in",
                    ]

                    for expected_call in expected_calls:
                        mock_print.assert_any_call(expected_call)

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_generate_password_flow(self, mock_print, mock_input):
        """Test main function with generated password"""
        mock_input.side_effect = ["testuser", "y"]

        with patch("generate_password.generate_strong_password") as mock_gen:
            mock_gen.return_value = "TestPass123!"
            with patch("generate_password.generate_password_hash") as mock_hash:
                mock_hash.return_value = "hashed_password"
                with patch(
                    "generate_password.generate_flask_secret_key"
                ) as mock_secret:
                    mock_secret.return_value = "test_secret_key"

                    generate_password.main()

                    mock_gen.assert_called_once()
                    mock_hash.assert_called_once_with("TestPass123!")
                    mock_secret.assert_called_once()

                    # Verify key output messages
                    mock_print.assert_any_call(
                        "Video Streaming Server - Configuration Setup"
                    )
                    mock_print.assert_any_call("\nGenerated password: TestPass123!")
                    mock_print.assert_any_call(
                        "IMPORTANT: Save this password in a secure location!"
                    )

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_custom_password_flow(self, mock_print, mock_input):
        """Test main function with custom password"""
        mock_input.side_effect = ["testuser", "n", "MyPassword123!", "MyPassword123!"]

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"
            with patch("generate_password.generate_flask_secret_key") as mock_secret:
                mock_secret.return_value = "test_secret_key"

                generate_password.main()

                mock_hash.assert_called_once_with("MyPassword123!")
                mock_secret.assert_called_once()

                # Verify key output messages
                mock_print.assert_any_call(
                    "Video Streaming Server - Configuration Setup"
                )
                mock_print.assert_any_call("VIDEO_SERVER_PASSWORD_HASH=hashed_password")
                mock_print.assert_any_call("VIDEO_SERVER_USERNAME=testuser")

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_password_too_short_retry(self, mock_print, mock_input):
        """Test main function with password that's too short"""
        mock_input.side_effect = [
            "testuser",  # Username
            "n",  # Don't generate
            "short",  # Too short password
            "ValidPassword123!",  # Valid password
            "ValidPassword123!",  # Confirm password
        ]

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"
            with patch("generate_password.generate_flask_secret_key") as mock_secret:
                mock_secret.return_value = "test_secret_key"

                generate_password.main()

                mock_print.assert_any_call(
                    "Password is too short! Use at least 8 characters."
                )
                mock_hash.assert_called_once_with("ValidPassword123!")
                mock_secret.assert_called_once()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_password_mismatch_retry(self, mock_print, mock_input):
        """Test main function with password confirmation mismatch"""
        mock_input.side_effect = [
            "testuser",  # Username
            "n",  # Don't generate
            "MyPassword123!",  # Valid password
            "DifferentPassword",  # Mismatched confirmation
            "MyPassword123!",  # Valid password again
            "MyPassword123!",  # Matching confirmation
        ]

        with patch("generate_password.generate_password_hash") as mock_hash:
            mock_hash.return_value = "hashed_password"
            with patch("generate_password.generate_flask_secret_key") as mock_secret:
                mock_secret.return_value = "test_secret_key"

                generate_password.main()

                mock_print.assert_any_call("Passwords don't match! Try again.")
                mock_hash.assert_called_once_with("MyPassword123!")
                mock_secret.assert_called_once()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_instructions_printed(self, mock_print, mock_input):
        """Test that main function prints all instructions"""
        mock_input.side_effect = ["testuser", "y"]

        with patch("generate_password.generate_strong_password"):
            with patch("generate_password.generate_password_hash") as mock_hash:
                mock_hash.return_value = "test_hash_value"
                with patch(
                    "generate_password.generate_flask_secret_key"
                ) as mock_secret:
                    mock_secret.return_value = "test_secret_key"

                    generate_password.main()

                    # Check all instruction messages are printed
                    expected_instructions = [
                        "Video Streaming Server - Configuration Setup",
                        "-" * 55,
                        "1. Copy the .env.example file to .env",
                        "2. Replace the following values in your .env file:",
                        "3. Configure other settings in .env as needed (directories, ports, etc.)",
                        "4. Save the .env file and run: python streaming_server.py",
                        "\nYou'll use the username 'testuser' and your chosen password to log in",
                    ]

                    for instruction in expected_instructions:
                        mock_print.assert_any_call(instruction)

    def test_main_function_entry_point(self):
        """Test the main function as entry point"""
        with patch("builtins.input", side_effect=["testuser", "y"]):
            with patch("builtins.print"):
                with patch("generate_password.generate_strong_password"):
                    with patch("generate_password.generate_password_hash"):
                        with patch("generate_password.generate_flask_secret_key"):
                            # This should not raise any exceptions
                            generate_password.main()


class TestGeneratePasswordCompleteEdgeCases:
    """Additional edge case tests for comprehensive coverage"""

    def test_main_function_comprehensive_scenarios(self):
        """Test main function with various comprehensive input scenarios"""

        # Test with automatic password generation (choose option y)
        with patch("builtins.input", side_effect=["testuser", "y"]):
            with patch("builtins.print") as mock_print:
                with patch("generate_password.generate_strong_password") as mock_gen:
                    mock_gen.return_value = "TestPass123!"
                    with patch("generate_password.generate_password_hash") as mock_hash:
                        mock_hash.return_value = "hashed_password"
                        with patch(
                            "generate_password.generate_flask_secret_key"
                        ) as mock_secret:
                            mock_secret.return_value = "test_secret_key"
                            generate_password.main()
                            # Verify it printed the password and hash
                            assert mock_print.call_count >= 4

        # Test with custom password - valid case
        with patch(
            "builtins.input",
            side_effect=[
                "testuser",
                "n",
                "MySecurePassword123!",
                "MySecurePassword123!",
            ],
        ):
            with patch("builtins.print") as mock_print:
                with patch("generate_password.generate_password_hash") as mock_hash:
                    mock_hash.return_value = "hashed_password"
                    with patch(
                        "generate_password.generate_flask_secret_key"
                    ) as mock_secret:
                        mock_secret.return_value = "test_secret_key"
                        generate_password.main()
                        assert mock_print.call_count >= 3

        # Test with mismatched passwords
        with patch(
            "builtins.input",
            side_effect=[
                "testuser",
                "n",
                "password1",
                "password2",
                "password3",
                "password3",
            ],
        ):
            with patch("builtins.print") as mock_print:
                with patch("generate_password.generate_password_hash") as mock_hash:
                    mock_hash.return_value = "hashed_password"
                    with patch(
                        "generate_password.generate_flask_secret_key"
                    ) as mock_secret:
                        mock_secret.return_value = "test_secret_key"
                        generate_password.main()
                        assert mock_print.call_count >= 4

        # Test with password too short
        with patch(
            "builtins.input",
            side_effect=[
                "testuser",
                "n",
                "short",
                "ValidPassword123!",
                "ValidPassword123!",
            ],
        ):
            with patch("builtins.print") as mock_print:
                with patch("generate_password.generate_password_hash") as mock_hash:
                    mock_hash.return_value = "hashed_password"
                    with patch(
                        "generate_password.generate_flask_secret_key"
                    ) as mock_secret:
                        mock_secret.return_value = "test_secret_key"
                        generate_password.main()
                        assert mock_print.call_count >= 4
