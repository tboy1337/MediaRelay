#!/usr/bin/env python3
"""
Setup Validation Script for Video Streaming Server
-------------------------------------------------
Validates that the production-ready server is properly configured
and can start up without errors.
"""

import os
import sys
import tempfile
import traceback
from pathlib import Path
from unittest.mock import patch


def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")

    required_modules = ["config", "logging_config", "streaming_server"]

    for module in required_modules:
        try:
            __import__(module)
            print(f"  âœ… {module}")
        except ImportError as e:
            print(f"  âŒ {module}: {e}")
            return False

    return True


def test_configuration():
    """Test configuration loading and validation"""
    print("\nTesting configuration...")

    try:
        from config import ServerConfig, load_config

        # Test with minimal required environment
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["VIDEO_SERVER_PASSWORD_HASH"] = "pbkdf2:sha256:260000$test$hash"
            os.environ["VIDEO_SERVER_DIRECTORY"] = temp_dir
            os.environ["VIDEO_SERVER_LOG_DIR"] = temp_dir

            config = ServerConfig()
            print("  âœ… Configuration validation")

            # Test load_config function
            config = load_config()
            print("  âœ… Configuration loading")

            return True

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"  âŒ Configuration error: {e}")
        return False


def test_logging():
    """Test logging system initialization"""
    print("\nTesting logging system...")

    try:
        from config import ServerConfig
        from logging_config import PerformanceLogger, SecurityEventLogger, setup_logging

        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["VIDEO_SERVER_PASSWORD_HASH"] = "pbkdf2:sha256:260000$test$hash"
            os.environ["VIDEO_SERVER_DIRECTORY"] = temp_dir
            os.environ["VIDEO_SERVER_LOG_DIR"] = temp_dir

            config = ServerConfig()

            # Test logging setup
            components = setup_logging(config)
            print("  âœ… Logging setup")

            # Test security logger
            security_logger = SecurityEventLogger(config)
            security_logger.log_auth_attempt("test", True, "127.0.0.1")
            print("  âœ… Security logging")

            # Test performance logger
            perf_logger = PerformanceLogger(config)
            perf_logger.log_request_duration("/test", 0.1, 200)
            print("  âœ… Performance logging")

            # Clean up loggers to prevent file lock issues on Windows
            import logging

            logging.shutdown()

            return True

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"  âŒ Logging error: {e}")
        traceback.print_exc()
        return False


def test_server_initialization():
    """Test server initialization without starting"""
    print("\nTesting server initialization...")

    temp_dir = None
    try:
        from config import ServerConfig
        from streaming_server import MediaRelayServer

        # Create temporary directory manually to have more control over cleanup
        temp_dir = tempfile.mkdtemp()

        os.environ["VIDEO_SERVER_PASSWORD_HASH"] = "pbkdf2:sha256:260000$test$hash"
        os.environ["VIDEO_SERVER_DIRECTORY"] = temp_dir
        os.environ["VIDEO_SERVER_LOG_DIR"] = temp_dir
        os.environ["VIDEO_SERVER_PORT"] = "5001"  # Use test port
        os.environ["VIDEO_SERVER_RATE_LIMIT"] = "false"  # Disable for testing

        config = ServerConfig()
        server = MediaRelayServer(config)
        print("  âœ… Server initialization")

        # Test Flask app creation
        assert server.app is not None
        print("  âœ… Flask app creation")

        # Test loggers initialization
        assert server.security_logger is not None
        assert server.performance_logger is not None
        print("  âœ… Logger initialization")

        # Clean up loggers to prevent file lock issues on Windows
        import logging

        logging.shutdown()

        return True

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"  âŒ Server initialization error: {e}")
        traceback.print_exc()
        return False

    finally:
        # Clean up temporary directory with better error handling
        if temp_dir and os.path.exists(temp_dir):
            try:
                import logging

                logging.shutdown()  # Ensure all loggers are closed
                import time

                time.sleep(0.1)  # Brief delay for Windows
                import shutil

                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # Ignore cleanup errors in validation


def test_password_generation():
    """Test password generation utility"""
    print("\nTesting password generation...")

    try:
        import generate_password

        # Test password generation function
        password = generate_password.generate_strong_password(20)
        assert len(password) == 20
        print("  âœ… Password generation")

        # Test password validation
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3
        print("  âœ… Password validation")

        return True

    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"  âŒ Password generation error: {e}")
        return False


def test_dependencies():
    """Test that all required dependencies are available"""
    print("\nTesting dependencies...")

    required_packages = [
        "flask",
        "werkzeug",
        "waitress",
        "click",
        "pytest",
        "pylint",
        "black",
        "isort",
        "colorlog",
        "structlog",
    ]

    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            print(f"  âœ… {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"  âŒ {package}")

    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Run: pip install -r requirements-dev.txt")
        return False

    return True


def test_file_structure():
    """Test that all required files exist"""
    print("\nTesting file structure...")

    required_files = [
        "streaming_server.py",
        "config.py",
        "logging_config.py",
        "generate_password.py",
        "requirements.txt",
        "requirements-dev.txt",
        "pytest.ini",
        ".pylintrc",
        ".coveragerc",
        "README.md",
        "LICENSE.txt",
    ]

    required_dirs = ["tests", "docs"]

    missing_files = []

    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
            print(f"  âŒ {file_path}")
        else:
            print(f"  âœ… {file_path}")

    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            missing_files.append(dir_path)
            print(f"  âŒ {dir_path}/")
        else:
            print(f"  âœ… {dir_path}/")

    if missing_files:
        print(f"\nMissing files/directories: {', '.join(missing_files)}")
        return False

    return True


def main():
    """Run all validation tests"""
    print("ðŸ” Video Streaming Server - Production Readiness Validation")
    print("=" * 60)

    tests = [
        ("File Structure", test_file_structure),
        ("Dependencies", test_dependencies),
        ("Imports", test_imports),
        ("Configuration", test_configuration),
        ("Logging System", test_logging),
        ("Password Generation", test_password_generation),
        ("Server Initialization", test_server_initialization),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\nðŸ“‹ {test_name}")
        print("-" * 40)

        try:
            if test_func():
                passed += 1
                print(f"âœ… {test_name} - PASSED")
            else:
                print(f"âŒ {test_name} - FAILED")
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"âŒ {test_name} - ERROR: {e}")
            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"ðŸ“Š VALIDATION SUMMARY: {passed}/{total} tests passed")

    if passed == total:
        print("ðŸŽ‰ ALL TESTS PASSED - Server is ready for production!")
        print("\nðŸš€ Next steps:")
        print("  1. Create your .env configuration file")
        print("  2. Generate password hash: python generate_password.py")
        print("  3. Configure your video directory path")
        print("  4. Start server: python streaming_server.py")
        return True

    print(f"âš ï¸  {total - passed} test(s) failed - Address issues before deployment")
    return False


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nâš ï¸ Validation interrupted by user")
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"\n\nðŸ’¥ Unexpected error during validation: {e}")
        traceback.print_exc()
        sys.exit(1)
