"""Shared constants for MediaRelay test suite."""

from werkzeug.security import generate_password_hash

TEST_PASSWORD_HASH = generate_password_hash("testpass")
TEST_PRODUCTION_SECRET_KEY = "test-production-secret-key-32chars-min"
