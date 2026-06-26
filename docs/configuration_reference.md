# Configuration Reference

Authoritative reference for all MediaRelay environment variables. Defaults match [`.env.example`](../.env.example) and [`config.py`](../src/mediarelay/config.py).

## Server

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_HOST` | `0.0.0.0` | Bind address. Use `127.0.0.1` when behind a reverse proxy. |
| `VIDEO_SERVER_PORT` | `5000` | TCP port (1–65535). |
| `VIDEO_SERVER_DEBUG` | `false` | Flask debug mode. Must be `false` when `FLASK_ENV=production`. |
| `VIDEO_SERVER_THREADS` | `6` | Waitress worker threads (minimum 1). |
| `VIDEO_SERVER_CHANNEL_TIMEOUT` | `300` | Waitress channel timeout in seconds. |
| `VIDEO_SERVER_CONNECTION_LIMIT` | `1000` | Maximum concurrent connections. |
| `VIDEO_SERVER_CLEANUP_INTERVAL` | `30` | Waitress cleanup interval in seconds. |
| `VIDEO_SERVER_PAGE_SIZE` | `100` | Directory listing page size (1–500). |

## Security

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_SECRET_KEY` | *(auto-generated if unset)* | Flask session signing key. **Required in production** via environment. |
| `VIDEO_SERVER_USERNAME` | `tboy1337` | HTTP Basic Auth username. Must not be empty or whitespace. |
| `VIDEO_SERVER_PASSWORD_HASH` | *(empty)* | Werkzeug PBKDF2 hash. **Required.** Generate with `mediarelay-genpass`. |
| `VIDEO_SERVER_SESSION_TIMEOUT` | `3600` | Session idle timeout in seconds. |
| `VIDEO_SERVER_SESSION_MAX_LIFETIME` | `86400` | Absolute session lifetime in seconds from login (default 24 hours). Must be greater than or equal to `VIDEO_SERVER_SESSION_TIMEOUT`. |
| `VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS` | `5` | Failed logins before lockout. |
| `VIDEO_SERVER_LOCKOUT_DURATION` | `900` | Lockout duration in seconds (minimum 60). |
| `VIDEO_SERVER_SESSION_COOKIE_SECURE` | `true` | Send session cookies only over HTTPS. **Required `true` when `FLASK_ENV=production`.** |
| `VIDEO_SERVER_SESSION_COOKIE_HTTPONLY` | `true` | Prevent JavaScript access to session cookies. |
| `VIDEO_SERVER_SESSION_COOKIE_SAMESITE` | `Strict` | SameSite policy: `Strict`, `Lax`, or `None` (case-insensitive). `None` requires `VIDEO_SERVER_SESSION_COOKIE_SECURE=true`. |
| `VIDEO_SERVER_BEHIND_PROXY` | `false` | Trust `X-Forwarded-*` headers. Enable only behind a trusted reverse proxy. |
| `VIDEO_SERVER_PROXY_TRUSTED` | `false` | Acknowledge that MediaRelay is only reachable through your trusted reverse proxy. Set `true` with `BEHIND_PROXY` in production. |
| `VIDEO_SERVER_HSTS` | `false` | Send `Strict-Transport-Security` on plain HTTP setups. Also sent automatically when `VIDEO_SERVER_BEHIND_PROXY=true`. |
| `FLASK_ENV` | `development` | Set to `production` for deployment validation and stricter startup checks. |

## Directories and files

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_DIRECTORY` | `~/Videos` (or `./videos`) | Root path for media library. Must exist, be a directory, and be readable at startup. |
| `VIDEO_SERVER_LOG_DIR` | `./logs` | Log file directory (created if missing; must be writable). |
| `VIDEO_SERVER_ALLOWED_EXTENSIONS` | *(built-in set)* | Comma-separated extensions. Must be a subset of the built-in media allowlist (video, audio, `.srt`). Invalid values are rejected at startup. |
| `VIDEO_SERVER_MAX_DIRECTORY_ENTRIES` | `10000` | Maximum listable entries per directory request. Exceeding this returns HTTP 413. |
| `VIDEO_SERVER_MAX_FILE_SIZE` | `21474836480` | Maximum file size in bytes for uploads and streaming (`0` disables). Oversized streams return HTTP 413. |

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_LOG_LEVEL` | `INFO` | Root log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Invalid values are rejected at startup. |
| `VIDEO_SERVER_LOG_MAX_BYTES` | `10485760` | Rotating log file size before rollover. |
| `VIDEO_SERVER_LOG_BACKUP_COUNT` | `5` | Number of rotated log backups to keep. |
| `VIDEO_SERVER_LOG_CONSOLE` | `true` | Enable colored console logging. |

## Rate limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_RATE_LIMIT` | `true` | Enable global per-IP rate limiting. |
| `VIDEO_SERVER_RATE_LIMIT_PER_MIN` | `60` | Requests per minute per client IP on browsing and API routes. |
| `VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE` | `600` | Dedicated per-IP limit for `/stream/` (range requests during playback). |

## Production notes

- Restrict `.env` permissions: `chmod 600 .env` (Linux/macOS).
- Generate credentials: `mediarelay-genpass --non-interactive --username tboy1337`
- Validate before deploy: `FLASK_ENV=production mediarelay-validate` (checks log directory, rejects writable video directory, warns on `0.0.0.0` without proxy)
- Production startup requires `VIDEO_SERVER_SECRET_KEY`, a real password hash, `VIDEO_SERVER_DEBUG=false`, and `VIDEO_SERVER_SESSION_COOKIE_SECURE=true`.
- Do not expose plain HTTP to the internet; terminate TLS at a reverse proxy. See [Deployment Guide](deployment_guide.md) and [SECURITY.md](../SECURITY.md).
- Sessions are bound to the client IP at login. VPN or mobile network IP changes invalidate the session and require re-authentication.

## Pagination

Directory listings support the `page` query parameter on HTML routes and `/api/files`:

- `GET /?page=2` — page 2 of the root directory
- `GET /movies?page=3` — page 3 of `movies/`
- `GET /api/files?path=movies&page=2` — API pagination

Invalid `page` values (`0`, non-integers) return HTTP 400. Pages beyond the last page return an empty item list with HTTP 200.
