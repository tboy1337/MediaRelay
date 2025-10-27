"""
MediaRelay
----------
Production-ready video streaming server with comprehensive security,
logging, monitoring, and configuration management.

Author: Assistant
License: See LICENSE.txt
"""

import json
import os
import secrets
import sys
import time
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import unquote

import click
from flask import (
    Flask,
    Response,
    g,
    jsonify,
    render_template_string,
    request,
    send_from_directory,
    session,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from waitress import serve
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from config import ServerConfig, load_config
from logging_config import (
    PerformanceLogger,
    SecurityEventLogger,
    log_system_info,
    setup_logging,
)


class MediaRelayServer:
    """Main video streaming server class with comprehensive features"""

    def __init__(self, config: ServerConfig):
        self.config = config
        self.app = self._create_app()
        self.security_logger: Optional[SecurityEventLogger] = None
        self.performance_logger: Optional[PerformanceLogger] = None
        self.limiter: Optional[Limiter] = None
        self._setup_logging()
        self._setup_rate_limiting()
        self._register_routes()
        self._register_error_handlers()

    def _create_app(self) -> Flask:
        """Create and configure Flask application"""
        app = Flask(__name__)
        app.secret_key = self.config.secret_key
        # Set max file size limit (None disables the limit)
        app.config["MAX_CONTENT_LENGTH"] = (
            None if self.config.max_file_size <= 0 else self.config.max_file_size
        )

        # Security configuration
        app.config["SESSION_COOKIE_SECURE"] = self.config.is_production()
        app.config["SESSION_COOKIE_HTTPONLY"] = True
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
        app.config["PERMANENT_SESSION_LIFETIME"] = self.config.session_timeout

        return app

    def _setup_logging(self) -> None:
        """Initialize logging system"""
        logging_components = setup_logging(self.config)  # type: ignore[misc]
        self.security_logger = logging_components["security_logger"]  # type: ignore[misc]
        self.performance_logger = logging_components["performance_logger"]  # type: ignore[misc]

        # Log system information on startup
        log_system_info(self.config)

    def _setup_rate_limiting(self) -> None:
        """Configure rate limiting"""
        if self.config.rate_limit_enabled:
            self.limiter = Limiter(
                app=self.app,
                key_func=get_remote_address,
                default_limits=[f"{self.config.rate_limit_per_minute} per minute"],
            )
        else:
            self.limiter = None

    def _register_routes(self) -> None:
        """Register all application routes"""

        @self.app.before_request
        def before_request() -> None:
            """Process requests before handling"""
            g.start_time = time.time()
            g.request_id = secrets.token_hex(8)

            # Log request details
            self.app.logger.info(
                f"Request {g.request_id}: {request.method} {request.path} "  # type: ignore[misc]
                f"from {request.remote_addr}"
            )

        @self.app.after_request  # type: ignore[misc]
        def after_request(response: Response) -> Response:
            """Process responses and add security headers"""
            # Add security headers
            for header, value in self.config.security_headers.items():
                response.headers[header] = value

            # Log performance metrics
            if hasattr(g, "start_time") and self.performance_logger:
                duration = time.time() - g.start_time  # type: ignore[misc]
                self.performance_logger.log_request_duration(
                    request.endpoint or request.path, duration, response.status_code  # type: ignore[misc]
                )

            return response

        # Health check endpoint
        @self.app.route("/health")
        def health_check() -> Union[Response, tuple[Response, int]]:
            """Health check endpoint for monitoring"""
            health_data = {  # type: ignore[misc]
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "2.0.0",
                "uptime_seconds": time.time()  # type: ignore[misc]
                - getattr(self, "_start_time", time.time()),  # type: ignore[misc]
                "video_directory_accessible": Path(
                    self.config.video_directory
                ).exists(),
                "config_valid": True,
            }

            try:
                # Check video directory access
                test_path = Path(self.config.video_directory)
                if not test_path.exists() or not os.access(test_path, os.R_OK):
                    health_data["video_directory_accessible"] = False  # type: ignore[misc]
                    health_data["status"] = "degraded"  # type: ignore[misc]

            except (OSError, IOError, PermissionError) as e:
                health_data["status"] = "unhealthy"  # type: ignore[misc]
                health_data["error"] = str(e)  # type: ignore[misc]

            status_code = 200 if health_data["status"] == "healthy" else 503  # type: ignore[misc]
            return jsonify(health_data), status_code  # type: ignore[misc]

        # Main application routes
        @self.app.route("/")
        @self.app.route("/<path:subpath>")
        def index(subpath: str = "") -> Union[str, tuple[str, int], Response]:
            """Handle directory listing and video playback pages"""
            return self._handle_index_request(subpath)

        @self.app.route("/stream/<path:video_path>")
        def stream(video_path: str) -> Union[Response, tuple[str, int]]:
            """Stream video files with range support"""
            return self._handle_stream_request(video_path)

        @self.app.route("/api/files")
        def api_files() -> Union[Response, tuple[Response, int]]:
            """API endpoint for file listing"""
            return self._handle_api_files_request()

    def _register_error_handlers(self) -> None:
        """Register custom error handlers"""

        @self.app.errorhandler(400)  # type: ignore[misc]
        def bad_request(error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle bad request errors"""
            self.app.logger.warning(f"Bad request from {request.remote_addr}: {error}")  # type: ignore[misc]
            return "Bad Request - Invalid parameters", 400

        @self.app.errorhandler(401)  # type: ignore[misc]
        def unauthorized(_error: Any) -> tuple[Response, int]:  # type: ignore[misc, explicit-any]
            """Handle unauthorized access"""
            return (
                Response(
                    "Authentication Required",
                    401,
                    {"WWW-Authenticate": 'Basic realm="Video Streaming Server"'},
                ),
                401,
            )

        @self.app.errorhandler(403)  # type: ignore[misc]
        def forbidden(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle forbidden access"""
            if self.security_logger:
                self.security_logger.log_security_violation(
                    "forbidden_access",
                    f"Forbidden access attempt: {request.path}",
                    request.remote_addr or "unknown",
                )
            return "Access Forbidden", 403

        @self.app.errorhandler(404)  # type: ignore[misc]
        def not_found(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle not found errors"""
            return "Resource Not Found", 404

        @self.app.errorhandler(413)  # type: ignore[misc]
        def request_entity_too_large(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle file too large errors"""
            return "File Too Large", 413

        @self.app.errorhandler(429)  # type: ignore[misc]
        def rate_limit_handler(_error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle rate limit exceeded"""
            if self.security_logger:
                self.security_logger.log_rate_limit_exceeded(
                    request.remote_addr or "unknown", request.endpoint or request.path
                )
            return "Rate Limit Exceeded - Too Many Requests", 429

        @self.app.errorhandler(500)  # type: ignore[misc]
        def internal_error(error: Any) -> tuple[str, int]:  # type: ignore[misc, explicit-any]
            """Handle internal server errors"""
            self.app.logger.error(f"Server error: {str(error)}", exc_info=True)  # type: ignore[misc]
            return "Internal Server Error", 500

    def check_auth(self, username: Optional[str], password: Optional[str]) -> bool:
        """Verify username and password against stored credentials"""
        if not username or not password:
            if self.security_logger:
                self.security_logger.log_auth_attempt(
                    username or "empty",
                    False,
                    request.remote_addr or "unknown",
                    request.headers.get("User-Agent", ""),
                )
            return False

        valid = username == self.config.username and check_password_hash(
            self.config.password_hash, password
        )

        if self.security_logger:
            self.security_logger.log_auth_attempt(
                username,
                valid,
                request.remote_addr or "unknown",
                request.headers.get("User-Agent", ""),
            )

        return valid

    def requires_auth(self, f: Callable[..., Any]) -> Callable[..., Any]:  # type: ignore[explicit-any]
        """Decorator to require authentication"""

        @wraps(f)  # type: ignore[misc]
        def decorated(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc, explicit-any]
            # Check session auth first
            current_time = time.time()
            if session.get("authenticated"):  # type: ignore[misc]
                # Check for session timeout
                last_activity = session.get("last_activity", 0)  # type: ignore[misc]
                if current_time - last_activity > self.config.session_timeout:  # type: ignore[misc]
                    session.clear()
                    self.app.logger.info(
                        f"Session expired for user from {request.remote_addr}"
                    )
                else:
                    session["last_activity"] = current_time
                    return f(*args, **kwargs)  # type: ignore[misc]

            # Fall back to HTTP Basic Auth
            auth = request.authorization
            if (
                not auth
                or not auth.username
                or not auth.password
                or not self.check_auth(auth.username, auth.password)
            ):
                return Response(
                    "Authentication Required",
                    401,
                    {"WWW-Authenticate": 'Basic realm="Video Streaming Server"'},
                )

            # Set session on successful auth
            session["authenticated"] = True
            session["username"] = auth.username
            session["last_activity"] = current_time
            session.permanent = True

            return f(*args, **kwargs)  # type: ignore[misc]

        return decorated  # type: ignore[misc]

    def get_safe_path(self, requested_path: str) -> Optional[Path]:
        """Ensure the requested path is within the video directory"""
        if not requested_path:
            return Path(self.config.video_directory)

        # URL decode the path
        requested_path = unquote(requested_path)

        # Sanitize the path - remove any attempts to navigate with ..
        if ".." in requested_path or "//" in requested_path:
            if self.security_logger:
                self.security_logger.log_security_violation(
                    "path_traversal",
                    f"Path traversal attempt: {requested_path}",
                    request.remote_addr or "unknown",
                )
            return None

        full_path = Path(self.config.video_directory) / requested_path

        try:
            # Use absolute path instead of resolve() to avoid symlink hanging issues
            full_path = full_path.absolute()
            video_dir = Path(self.config.video_directory).absolute()

            # Normalize paths to handle . and .. components without resolving symlinks
            full_path_parts: list[str] = []
            for part in full_path.parts:
                if part == "..":
                    if full_path_parts:
                        full_path_parts.pop()
                elif part != ".":
                    full_path_parts.append(part)

            video_dir_parts: list[str] = []
            for part in video_dir.parts:
                if part == "..":
                    if video_dir_parts:
                        video_dir_parts.pop()
                elif part != ".":
                    video_dir_parts.append(part)

            # Reconstruct normalized paths
            if full_path_parts:
                normalized_full = Path(*full_path_parts)
            else:
                normalized_full = Path("/")

            if video_dir_parts:
                normalized_video_dir = Path(*video_dir_parts)
            else:
                normalized_video_dir = Path("/")

            # Check if the path is within VIDEO_DIRECTORY
            if (
                normalized_video_dir in normalized_full.parents
                or normalized_full == normalized_video_dir
            ):
                return full_path

            if self.security_logger:
                self.security_logger.log_security_violation(
                    "path_traversal",
                    f"Path traversal attempt: {requested_path}",
                    request.remote_addr or "unknown",
                )
        except (RuntimeError, OSError, ValueError) as e:
            self.app.logger.error(f"Path error: {str(e)} for path: {requested_path}")

        return None

    def get_breadcrumbs(self, path: Path) -> list[dict[str, str]]:
        """Generate breadcrumb navigation"""
        video_dir = Path(self.config.video_directory)
        crumbs = [{"name": "Home", "path": "/"}]

        try:
            relative_path = path.relative_to(video_dir)
            current_path = ""
            for part in relative_path.parts:
                current_path = f"{current_path}/{part}"
                crumbs.append({"name": part, "path": current_path})
        except ValueError:
            # Path is not relative to video directory
            pass

        return crumbs

    def _handle_index_request(
        self, subpath: str
    ) -> Union[str, tuple[str, int], Response]:
        """Handle index page requests with authentication"""
        if not self._check_authentication():
            return Response(
                "Authentication Required",
                401,
                {"WWW-Authenticate": 'Basic realm="Video Streaming Server"'},
            )

        safe_path = self.get_safe_path(subpath)
        if not safe_path or not safe_path.exists():
            return "Path not found", 404

        if safe_path.is_file():
            # If it's a video file, show the video player
            if safe_path.suffix.lower() in self.config.allowed_extensions:
                relative_path = safe_path.relative_to(Path(self.config.video_directory))
                parent_path = (
                    "/" + str(relative_path.parent)
                    if str(relative_path.parent) != "."
                    else "/"
                )

                if self.security_logger:
                    self.security_logger.log_file_access(
                        str(relative_path),
                        request.remote_addr or "unknown",
                        True,
                        session.get("username", "unknown"),  # type: ignore[misc]
                    )

                return render_template_string(
                    self._get_html_template(),
                    video_file=safe_path.name,
                    video_path=str(relative_path).replace("\\", "/"),
                    parent_path=parent_path,
                )
            return "Not a video file", 400

        # List directory contents
        items = []
        try:
            for item in safe_path.iterdir():
                if (
                    item.is_dir()
                    or item.suffix.lower() in self.config.allowed_extensions
                ):
                    relative_path = item.relative_to(Path(self.config.video_directory))
                    items.append(
                        {
                            "name": item.name,
                            "path": "/" + str(relative_path).replace("\\", "/"),
                            "is_dir": item.is_dir(),
                            "size": item.stat().st_size if item.is_file() else 0,
                            "modified": datetime.fromtimestamp(
                                item.stat().st_mtime
                            ).isoformat(),
                        }
                    )
        except PermissionError:
            return "Access denied to directory", 403
        except (OSError, IOError) as e:
            self.app.logger.error(f"Error reading directory {safe_path}: {str(e)}")
            return "Error reading directory", 500

        is_root = safe_path == Path(self.config.video_directory)
        parent_path = "/"
        if not is_root:
            try:
                parent_path = "/" + str(
                    safe_path.parent.relative_to(Path(self.config.video_directory))
                ).replace("\\", "/")
            except ValueError:
                parent_path = "/"

        return render_template_string(
            self._get_html_template(),
            items=sorted(items, key=lambda x: (not x["is_dir"], x["name"].lower())),  # type: ignore[misc]
            is_root=is_root,
            parent_path=parent_path,
            breadcrumbs=self.get_breadcrumbs(safe_path),
        )

    def _handle_stream_request(
        self, video_path: str
    ) -> Union[Response, tuple[str, int]]:
        """Handle video streaming requests with range support"""
        if not self._check_authentication():
            return Response(
                "Authentication Required",
                401,
                {"WWW-Authenticate": 'Basic realm="Video Streaming Server"'},
            )

        safe_path = self.get_safe_path(video_path)
        if not safe_path or not safe_path.is_file():
            return "Video not found", 404

        # Verify file extension
        if safe_path.suffix.lower() not in self.config.allowed_extensions:
            if self.security_logger:
                self.security_logger.log_security_violation(
                    "unauthorized_file_type",
                    f"Unauthorized file type access: {video_path}",
                    request.remote_addr or "unknown",
                )
            return "File type not allowed", 403

        # Log file access
        if self.security_logger:
            self.security_logger.log_file_access(
                video_path,
                request.remote_addr or "unknown",
                True,
                session.get("username", "unknown"),  # type: ignore[misc]
            )

        # Measure streaming performance
        start_time = time.time()

        try:
            # Use send_from_directory for proper range support
            directory = safe_path.parent
            filename = safe_path.name
            response = send_from_directory(directory, filename)

            # Log streaming performance
            if self.performance_logger:
                duration = time.time() - start_time
                file_size = safe_path.stat().st_size
                self.performance_logger.log_file_serve_time(
                    video_path, file_size, duration
                )

            return response

        except (OSError, IOError, PermissionError, FileNotFoundError) as e:
            self.app.logger.error(f"Error streaming file {video_path}: {str(e)}")
            return "Error streaming file", 500

    def _handle_api_files_request(self) -> Union[Response, tuple[Response, int]]:
        """Handle API files listing request"""
        if not self._check_authentication():
            return jsonify({"error": "Authentication required"}), 401  # type: ignore[misc]

        try:
            path_param = request.args.get("path", "")
            safe_path = self.get_safe_path(path_param)

            if not safe_path or not safe_path.exists():
                return jsonify({"error": "Path not found"}), 404  # type: ignore[misc]

            if not safe_path.is_dir():
                return jsonify({"error": "Path is not a directory"}), 400  # type: ignore[misc]

            files = []
            for item in safe_path.iterdir():
                if (
                    item.is_dir()
                    or item.suffix.lower() in self.config.allowed_extensions
                ):
                    relative_path = item.relative_to(Path(self.config.video_directory))
                    files.append(
                        {
                            "name": item.name,
                            "path": str(relative_path).replace("\\", "/"),
                            "is_directory": item.is_dir(),
                            "size": item.stat().st_size if item.is_file() else 0,
                            "modified": datetime.fromtimestamp(
                                item.stat().st_mtime
                            ).isoformat(),
                        }
                    )

            return jsonify(
                {  # type: ignore[misc]
                    "files": sorted(  # type: ignore[misc]
                        files, key=lambda x: (not x["is_directory"], x["name"].lower())  # type: ignore[misc]
                    ),
                    "path": path_param,
                    "total_files": len(files),
                }
            )

        except (OSError, IOError, PermissionError, ValueError) as e:
            self.app.logger.error(f"API files error: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500  # type: ignore[misc]

    def _check_authentication(self) -> bool:
        """Check if the current request is authenticated"""
        # Check session auth first
        current_time = time.time()
        if session.get("authenticated"):  # type: ignore[misc]
            last_activity = session.get("last_activity", 0)  # type: ignore[misc]
            if current_time - last_activity <= self.config.session_timeout:  # type: ignore[misc]
                session["last_activity"] = current_time
                return True

            session.clear()

        # Check HTTP Basic Auth
        auth = request.authorization
        if (
            auth
            and auth.username
            and auth.password
            and self.check_auth(auth.username, auth.password)
        ):
            # Set session on successful auth
            session["authenticated"] = True
            session["username"] = auth.username
            session["last_activity"] = current_time
            session.permanent = True
            return True

        return False

    def _get_html_template(self) -> str:
        """Get the enhanced HTML template for the video player"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% if video_file %}{{ video_file }} - {% endif %}Video Streaming Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: rgba(255, 255, 255, 0.95);
            min-height: 100vh;
            box-shadow: 0 0 50px rgba(0,0,0,0.1);
        }

        .header {
            background: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .breadcrumb {
            background: #f8f9fa;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #007bff;
        }

        .breadcrumb a {
            color: #007bff;
            text-decoration: none;
            font-weight: 500;
        }

        .breadcrumb a:hover {
            text-decoration: underline;
        }

        .video-player {
            background: #000;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 20px;
        }

        video {
            width: 100%;
            height: auto;
            display: block;
        }

        .file-list {
            list-style: none;
            background: #fff;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .file-item {
            display: flex;
            align-items: center;
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            transition: all 0.3s ease;
            text-decoration: none;
            color: inherit;
        }

        .file-item:hover {
            background: #f8f9fa;
            transform: translateX(5px);
        }

        .file-item:last-child {
            border-bottom: none;
        }

        .file-icon {
            font-size: 1.5em;
            margin-right: 15px;
            min-width: 30px;
        }

        .file-info {
            flex: 1;
        }

        .file-name {
            font-weight: 500;
            color: #2c3e50;
            margin-bottom: 5px;
        }

        .file-meta {
            font-size: 0.9em;
            color: #6c757d;
        }

        .folder {
            color: #ffa500;
        }

        .video-file {
            color: #28a745;
        }

        .back-link {
            display: inline-flex;
            align-items: center;
            padding: 10px 20px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-bottom: 20px;
            transition: background 0.3s ease;
        }

        .back-link:hover {
            background: #0056b3;
            color: white;
        }

        .stats {
            background: #e9ecef;
            padding: 10px 20px;
            border-radius: 5px;
            margin-top: 20px;
            font-size: 0.9em;
            color: #6c757d;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header h1 {
                font-size: 1.8em;
            }

            .file-item {
                padding: 12px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        {% if video_file %}
            <div class="header">
                <a href="{{ parent_path }}" class="back-link">&larr; Back to directory</a>
                <h1>{{ video_file }}</h1>
            </div>

            <div class="video-player">
                <video controls preload="metadata">
                    <source src="/stream/{{ video_path }}" type="video/mp4">
                    Your browser does not support the video tag.
                </video>
            </div>
        {% else %}
            <div class="header">
                <h1>Video Streaming Server</h1>
                <p>Browse and stream your video library</p>
            </div>

            <div class="breadcrumb">
                {% for crumb in breadcrumbs %}
                    {% if not loop.last %}
                        <a href="{{ crumb.path }}">{{ crumb.name }}</a> /
                    {% else %}
                        <strong>{{ crumb.name }}</strong>
                    {% endif %}
                {% endfor %}
            </div>

            <ul class="file-list">
                {% if not is_root %}
                    <li>
                        <a href="{{ parent_path }}" class="file-item">
                            <span class="file-icon folder">&#x1F4C1;</span>
                            <div class="file-info">
                                <div class="file-name">.. (Up to parent directory)</div>
                            </div>
                        </a>
                    </li>
                {% endif %}

                {% for item in items %}
                    <li>
                        <a href="{{ item.path }}" class="file-item">
                            <span class="file-icon {% if item.is_dir %}folder{% else %}video-file{% endif %}">
                                {% if item.is_dir %}&#x1F4C1;{% else %}&#x1F3AC;{% endif %}
                            </span>
                            <div class="file-info">
                                <div class="file-name">{{ item.name }}</div>
                                <div class="file-meta">
                                    {% if not item.is_dir %}
                                        Size: {{ "%.1f"|format(item.size / 1024 / 1024) }} MB |
                                    {% endif %}
                                    Modified: {{ item.modified[:16].replace('T', ' ') }}
                                </div>
                            </div>
                        </a>
                    </li>
                {% endfor %}
            </ul>

            <div class="stats">
                Total items: {{ items|length }} |
                Folders: {{ items|selectattr('is_dir')|list|length }} |
                Files: {{ items|rejectattr('is_dir')|list|length }}
            </div>
        {% endif %}
    </div>
</body>
</html>
        """

    def run(self) -> None:
        """Start the production server"""
        self._start_time = time.time()

        # Verify video directory exists
        video_dir = Path(self.config.video_directory)
        if not video_dir.exists():
            self.app.logger.error(
                f"Video directory does not exist: {self.config.video_directory}"
            )
            raise ValueError(f"Directory {self.config.video_directory} does not exist!")

        self.app.logger.info(f"Starting server with configuration:")
        self.app.logger.info(f"  Video directory: {self.config.video_directory}")
        self.app.logger.info(f"  Host: {self.config.host}")
        self.app.logger.info(f"  Port: {self.config.port}")
        self.app.logger.info(f"  Threads: {self.config.threads}")
        self.app.logger.info(f"  Production mode: {self.config.is_production()}")
        self.app.logger.info(f"  Rate limiting: {self.config.rate_limit_enabled}")

        print(f"Video Streaming Server starting...")
        print(f"Server running on http://{self.config.host}:{self.config.port}")
        print(f"Video directory: {self.config.video_directory}")
        print("Press Ctrl+C to stop the server")

        try:
            # Run production server with Waitress
            serve(
                self.app,
                host=self.config.host,
                port=self.config.port,
                threads=self.config.threads,
                cleanup_interval=30,
                channel_timeout=300,
                connection_limit=1000,
            )
        except KeyboardInterrupt:
            self.app.logger.info("Server shutdown requested by user")
            print("\nServer stopped by user")
        except Exception as e:
            self.app.logger.error(f"Server error: {str(e)}", exc_info=True)
            raise


@click.command()
@click.option("--config-file", "-c", help="Path to configuration file")
@click.option("--host", "-h", help="Host to bind to (overrides config)")
@click.option("--port", "-p", type=int, help="Port to bind to (overrides config)")
@click.option("--debug", "-d", is_flag=True, help="Enable debug mode")
@click.option(
    "--generate-config", is_flag=True, help="Generate sample configuration file"
)
def main(
    config_file: Optional[str],  # pylint: disable=unused-argument
    host: Optional[str],
    port: Optional[int],
    debug: bool,
    generate_config: bool,
) -> None:
    """Enhanced Video Streaming Server - Production Ready"""

    if generate_config:
        from config import create_sample_env_file

        create_sample_env_file()
        return

    try:
        # Load configuration
        config = load_config()

        # Override with command line arguments
        if host:
            config.host = host
        if port:
            config.port = port
        if debug:
            config.debug = True

        # Create and run server
        server = MediaRelayServer(config)
        server.run()

    except ValueError as e:
        print(f"Configuration Error: {e}")
        print("\nTips:")
        print("1. Run 'python generate_password.py' to create a password hash")
        print("2. Set VIDEO_SERVER_PASSWORD_HASH environment variable")
        print("3. Ensure video directory exists and is accessible")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except (RuntimeError, OSError, ImportError) as e:
        print(f"Server Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
