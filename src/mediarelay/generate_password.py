"""
Password and Secret Key Generation Utility
------------------------------------------
Utility script for generating secure passwords, their corresponding
Werkzeug password hashes, and Flask secret keys for the Video Streaming Server.

Author: Assistant
License: See LICENSE.md
"""

import secrets
import string
import sys

import click
from werkzeug.security import generate_password_hash


def generate_strong_password(length: int = 35) -> str:
    """Generate a strong random password of specified length"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = "".join(secrets.choice(alphabet) for i in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and sum(c.isdigit() for c in password) >= 3
            and sum(c in string.punctuation for c in password) >= 2
        ):
            return password


def generate_flask_secret_key(length: int = 32) -> str:
    """Generate a secure Flask secret key using cryptographically strong random bytes"""
    return secrets.token_hex(length)


def _print_env_values(username: str, password_hash: str, secret_key: str) -> None:
    """Print environment variable lines for .env configuration."""
    print(f"VIDEO_SERVER_SECRET_KEY={secret_key}")
    print(f"VIDEO_SERVER_USERNAME={username}")
    print(f"VIDEO_SERVER_PASSWORD_HASH={password_hash}")


def _print_setup_instructions(
    username: str, generated_password: str | None = None
) -> None:
    """Print interactive setup instructions."""
    print("\n" + "=" * 60)
    print("SETUP INSTRUCTIONS")
    print("=" * 60)
    print("1. Copy the .env.example file to .env")
    print("2. Replace the following values in your .env file:")
    print("   - VIDEO_SERVER_SECRET_KEY with the generated secret key above")
    print("   - VIDEO_SERVER_USERNAME with your chosen username above")
    print("   - VIDEO_SERVER_PASSWORD_HASH with the generated password hash above")
    print("3. Configure other settings in .env as needed (directories, ports, etc.)")
    print("4. Save the .env file and run: mediarelay")
    print(f"\nYou'll use the username '{username}' and your chosen password to log in")
    if generated_password:
        print(f"\nGenerated password: {generated_password}")
        print("IMPORTANT: Save this password in a secure location!")


def _run_interactive() -> None:
    """Interactive password and secret key generation workflow."""
    print("Video Streaming Server - Configuration Setup")
    print("-" * 55)

    secret_key = generate_flask_secret_key()

    username = input("Enter your preferred username: ").strip()
    while not username:
        print("Username cannot be empty!")
        username = input("Enter your preferred username: ").strip()

    use_generated = input("Generate a strong password? (y/n): ").strip().lower() == "y"

    if use_generated:
        password = generate_strong_password()
        print(f"\nGenerated password: {password}")
        print("IMPORTANT: Save this password in a secure location!")
    else:
        while True:
            password = input("\nEnter your password: ")
            if len(password) < 12:
                print("Password is too short! Use at least 12 characters.")
                continue

            confirm = input("Confirm password: ")
            if password != confirm:
                print("Passwords don't match! Try again.")
                continue
            break

    password_hash = generate_password_hash(password)

    print("\n" + "=" * 60)
    print("CONFIGURATION VALUES FOR .env FILE")
    print("=" * 60)
    _print_env_values(username, password_hash, secret_key)
    _print_setup_instructions(username)


def main() -> None:
    """Console entry point for interactive credential generation."""
    _run_interactive()


@click.command()
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Generate credentials without prompts (for scripted deployment)",
)
@click.option(
    "--username",
    default="tboy1337",
    show_default=True,
    help="Username for non-interactive mode",
)
def cli(non_interactive: bool, username: str) -> None:
    """Generate password hash and Flask secret key for MediaRelay."""
    if non_interactive:
        password = generate_strong_password()
        secret_key = generate_flask_secret_key()
        password_hash = generate_password_hash(password)
        _print_env_values(username, password_hash, secret_key)
        if sys.stdout.isatty():
            _print_setup_instructions(username, password)
        return

    _run_interactive()


if __name__ == "__main__":
    cli()
