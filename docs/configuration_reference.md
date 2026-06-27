# Configuration Reference

Authoritative reference for all MediaRelay environment variables. Defaults match [`.env.example`](../.env.example) and [`config.py`](../src/mediarelay/config.py).

## Server

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_HOST` | `0.0.0.0` | Bind address (validated at startup as a valid IP or hostname). Use `127.0.0.1` when behind a reverse proxy. |
| `VIDEO_SERVER_PORT` | `5000` | TCP port (1–65535). |
| `VIDEO_SERVER_DEBUG` | `false` | Flask debug mode. Must be `false` when `VIDEO_SERVER_PRODUCTION=true`. |
| `VIDEO_SERVER_THREADS` | `6` | Waitress worker threads (1–256). |
| `VIDEO_SERVER_CHANNEL_TIMEOUT` | `300` | Waitress channel timeout in seconds (1–86400). |
| `VIDEO_SERVER_CONNECTION_LIMIT` | `1000` | Maximum concurrent connections (1–100000). |
| `VIDEO_SERVER_CLEANUP_INTERVAL` | `30` | Waitress cleanup interval in seconds (1–86400). |
| `VIDEO_SERVER_PAGE_SIZE` | `100` | Directory listing page size (1–500). |

## Security

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_SECRET_KEY` | *(auto-generated if unset)* | Flask session signing key. **Required in production** (minimum 32 characters). |
| `VIDEO_SERVER_USERNAME` | `tboy1337` | HTTP Basic Auth username. Must not be empty, whitespace-only, or longer than 128 characters. |
| `VIDEO_SERVER_PASSWORD_HASH` | *(empty)* | Werkzeug hash (`scrypt:`, `pbkdf2:`, or `argon2:`). **Required.** Generate with `mediarelay-genpass`. |
| `VIDEO_SERVER_SESSION_TIMEOUT` | `3600` | Session idle timeout in seconds (1–2592000). |
| `VIDEO_SERVER_SESSION_MAX_LIFETIME` | `86400` | Absolute session lifetime in seconds from login (default 24 hours; 1–2592000). Must be greater than or equal to `VIDEO_SERVER_SESSION_TIMEOUT`. |
| `VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS` | `5` | Failed logins before lockout (1–100). |
| `VIDEO_SERVER_LOCKOUT_DURATION` | `900` | Lockout duration in seconds (60–86400). Up to 10,000 unique `IP:username` trackers are retained; active lockouts are never evicted; oldest non-locked trackers may be evicted when full; when every slot is an active lockout, new failed attempts are dropped and `lockout_tracker_capacity_exceeded` is logged. |
| `VIDEO_SERVER_USERNAME_LOCKOUT_ENABLED` | `true` | When enabled, failed logins are tracked per username across all client IPs. Disable to avoid username-wide account lockout DoS when the username is known. Empty usernames never populate the username tracker. |
| `VIDEO_SERVER_SESSION_BIND_IP` | `true` | When enabled, sessions are invalidated when the client IP changes after login. Set `false` for mobile or CGNAT clients if you accept the reduced binding. |
| `VIDEO_SERVER_HEALTH_TOKEN` | *(empty)* | Optional secret for detailed `/health` responses via the `X-Health-Token` request header. When unset, detailed health requires an active browser session. **Minimum 32 characters when set in production.** Basic Auth is not accepted on `/health`. |
| `VIDEO_SERVER_SESSION_COOKIE_SECURE` | `true` | Send session cookies only over HTTPS. **Required `true` when `VIDEO_SERVER_PRODUCTION=true`.** |
| `VIDEO_SERVER_SESSION_COOKIE_HTTPONLY` | `true` | Prevent JavaScript access to session cookies. **Required `true` when `VIDEO_SERVER_PRODUCTION=true`.** |
| `VIDEO_SERVER_SESSION_COOKIE_SAMESITE` | `Strict` | SameSite policy: `Strict`, `Lax`, or `None` (case-insensitive). `None` requires `VIDEO_SERVER_SESSION_COOKIE_SECURE=true`. |
| `VIDEO_SERVER_BEHIND_PROXY` | `false` | Trust `X-Forwarded-*` headers. Enable only behind a trusted reverse proxy. |
| `VIDEO_SERVER_PROXY_TRUSTED` | `false` | Acknowledge that MediaRelay is only reachable through your trusted reverse proxy. **Required `true` when `VIDEO_SERVER_BEHIND_PROXY=true` in production** (startup fails otherwise). |
| `VIDEO_SERVER_HSTS` | `false` | Send `Strict-Transport-Security` on plain HTTP setups. Also sent automatically when `VIDEO_SERVER_BEHIND_PROXY=true`. |
| `VIDEO_SERVER_PRODUCTION` | `false` | Set to `true` for deployment validation and stricter startup checks. |

## Directories and files

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_DIRECTORY` | `~/Videos` (or `./videos`) | Root path for media library. Must exist, be a directory, and be readable at startup. **Must be an absolute path in production** (`mediarelay-validate` rejects relative paths). |
| `VIDEO_SERVER_LOG_DIR` | `./logs` | Log file directory (created if missing; must be writable). **Must be an absolute path in production.** |
| `VIDEO_SERVER_ALLOWED_EXTENSIONS` | *(built-in set)* | Comma-separated extensions. Must be a subset of the built-in media allowlist (video, audio, `.srt`, `.vtt`). Invalid values are rejected at startup. |
| `VIDEO_SERVER_MAX_DIRECTORY_ENTRIES` | `10000` | Maximum listable entries per directory request (1–1000000). Exceeding this returns HTTP 413. |
| `VIDEO_SERVER_MAX_FILE_SIZE` | `21474836480` | Maximum file size in bytes for media streaming (`0` disables; production startup logs a warning). Values above `21474836480` (20 GiB) are rejected at startup. Oversized streams return HTTP 413. Subtitle files (`.srt`, `.vtt`) are always capped at **10 MiB** regardless of this setting. |

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_LOG_LEVEL` | `INFO` | Root log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Invalid values are rejected at startup. |
| `VIDEO_SERVER_LOG_MAX_BYTES` | `10485760` | Rotating log file size before rollover (1–1073741824). |
| `VIDEO_SERVER_LOG_BACKUP_COUNT` | `5` | Number of rotated log backups to keep (0–100). |
| `VIDEO_SERVER_LOG_CONSOLE` | `true` | Enable colored console logging. |

## Rate limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `VIDEO_SERVER_RATE_LIMIT` | `true` | Enable global per-IP rate limiting. |
| `VIDEO_SERVER_RATE_LIMIT_PER_MIN` | `60` | Requests per minute per client IP on browsing and API routes (1–10000). |
| `VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE` | `600` | Dedicated per-IP limit for `/stream/` range requests during playback (1–10000). |
| `VIDEO_SERVER_HEALTH_RATE_LIMIT_PER_MIN` | `120` | Dedicated per-IP limit for `/health` liveness probes (1–10000). |

## Production notes

**Minimal local setup (development):**

1. `pip install mediarelay`
2. `mediarelay-genpass > .env` (redirect securely; set `VIDEO_SERVER_DIRECTORY`)
3. `mediarelay`

**Production deploy:** set `VIDEO_SERVER_PRODUCTION=true`, then run `mediarelay-validate` before starting the service.

- Restrict `.env` permissions: `chmod 600 .env` (Linux/macOS).
- Generate credentials: `mediarelay-genpass --non-interactive --username tboy1337`
- Validate before deploy: `VIDEO_SERVER_PRODUCTION=true mediarelay-validate` (checks log directory, rejects writable video directory, rejects relative paths, rejects default username, rejects symlink video directory, rejects `MAX_FILE_SIZE=0`, rejects `BEHIND_PROXY` without `PROXY_TRUSTED`, warns on `0.0.0.0` without proxy)
- Production startup requires: real Werkzeug password hash, `VIDEO_SERVER_SECRET_KEY` (32+ chars), `VIDEO_SERVER_DEBUG=false`, `VIDEO_SERVER_SESSION_COOKIE_SECURE=true`, `VIDEO_SERVER_SESSION_COOKIE_HTTPONLY=true`, and `VIDEO_SERVER_RATE_LIMIT=true`.
- Numeric settings have documented upper bounds (e.g. threads 256, rate limit 10,000/min) to prevent accidental resource exhaustion.
- Do not expose plain HTTP to the internet; terminate TLS at a reverse proxy. See [Deployment Guide](deployment_guide.md) and [SECURITY.md](../SECURITY.md).
- Sessions are bound to the client IP at login. VPN or mobile network IP changes invalidate the session and require re-authentication.

## Pagination

Directory listings support the `page` query parameter on HTML routes and `/api/files`:

- `GET /?page=2` — page 2 of the root directory
- `GET /movies?page=3` — page 3 of `movies/`
- `GET /api/files?path=movies&page=2` — API pagination

Invalid `page` values (`0`, non-integers) return HTTP 400. Pages beyond the last page return an empty item list with HTTP 200.
