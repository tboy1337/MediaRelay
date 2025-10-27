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


def main() -> None:
    """
    Main function to handle password and secret key generation workflow.

    Provides an interactive interface for users to either generate a new
    password or hash their own password, plus generates a Flask secret key
    for use with the streaming server.
    """
    print("Video Streaming Server - Configuration Setup")
    print("-" * 55)

    # Generate Flask secret key
    secret_key = generate_flask_secret_key()

    # Get username preference
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
            if len(password) < 8:
                print("Password is too short! Use at least 8 characters.")
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
    print(f"VIDEO_SERVER_SECRET_KEY={secret_key}")
    print(f"VIDEO_SERVER_USERNAME={username}")
    print(f"VIDEO_SERVER_PASSWORD_HASH={password_hash}")

    print("\n" + "=" * 60)
    print("SETUP INSTRUCTIONS")
    print("=" * 60)
    print("1. Copy the .env.example file to .env")
    print("2. Replace the following values in your .env file:")
    print("   - VIDEO_SERVER_SECRET_KEY with the generated secret key above")
    print("   - VIDEO_SERVER_USERNAME with your chosen username above")
    print("   - VIDEO_SERVER_PASSWORD_HASH with the generated password hash above")
    print("3. Configure other settings in .env as needed (directories, ports, etc.)")
    print("4. Save the .env file and run: python streaming_server.py")
    print(f"\nYou'll use the username '{username}' and your chosen password to log in")


if __name__ == "__main__":
    main()
