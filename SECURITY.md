# Security Policy

## Supported Versions

Security fixes are provided for the latest release published on [PyPI](https://pypi.org/project/mediarelay/) and the `main` branch of this repository.

| Version | Supported |
|---------|-----------|
| Latest PyPI release | Yes |
| Older releases | No |

## Reporting a Vulnerability

If you discover a security vulnerability in MediaRelay:

1. **Do not** open a public GitHub issue for security-sensitive reports.
2. Open a [GitHub Security Advisory](https://github.com/tboy1337/MediaRelay/security/advisories/new) or contact the maintainer through GitHub with:
   - A description of the issue
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if available)

We aim to acknowledge reports within 7 days and provide a fix or mitigation plan as soon as practical.

## Security Model

MediaRelay is a **single-user, read-only** personal media streaming server. It is designed for private use behind TLS with a reverse proxy.

### Authentication

- HTTP Basic Authentication with Werkzeug password hashes (scrypt via `mediarelay-genpass`)
- Session cookies after successful login (HttpOnly, Secure, SameSite configurable)
- Constant-time username comparison (SHA-256 digest compare via `hmac.compare_digest`; does not leak configured username length)
- Password verification on every login attempt, including when already locked out (mitigates username timing enumeration)
- `/health` does not accept HTTP Basic Auth; detailed readiness uses an active session cookie or optional `VIDEO_SERVER_HEALTH_TOKEN` via `X-Health-Token` (prevents password-oracle probing on an unthrottled endpoint)
- Account lockout after repeated failed attempts (per IP + username, and per username across all IPs when `VIDEO_SERVER_USERNAME_LOCKOUT_ENABLED=true`); lockout also terminates active sessions
- Active lockout entries are never evicted from the lockout tracker when at capacity; the oldest non-locked tracker (including those with in-progress failed-attempt counters) may be evicted to make room for new `IP:username` pairs
- When every tracker slot holds an active lockout, new failed attempts are not recorded and new attackers are not locked out; a `lockout_tracker_capacity_exceeded` security event is logged instead
- Empty or whitespace-only usernames do not populate the username-wide lockout tracker
- Session invalidation on client IP change when `VIDEO_SERVER_SESSION_BIND_IP=true` (default); sessions without a bound login IP are rejected
- Session invalidation when username or password hash changes (`credential_epoch` fingerprint)
- Expired sessions fall through to valid HTTP Basic credentials on the same request
- Idle session timeout (`VIDEO_SERVER_SESSION_TIMEOUT`) and absolute max lifetime (`VIDEO_SERVER_SESSION_MAX_LIFETIME`)
- `SameSite=None` requires `VIDEO_SERVER_SESSION_COOKIE_SECURE=true` at startup

### Path Access

- All file access is constrained to the configured video directory jail
- Symlinks are resolved before containment checks
- Hard links whose inode is also linked outside the jail are rejected using a cached inode index (refreshed periodically) with a live directory scan confirmation before allowing access when `st_nlink > 1`
- Path traversal payloads (including multi-pass URL decoding, NFKC normalization, and Unicode control characters) are rejected and logged
- Dotfiles (path segments starting with `.`) are hidden from listings and blocked on direct access
- Custom `VIDEO_SERVER_ALLOWED_EXTENSIONS` must be a subset of the built-in media allowlist

### Network Controls

- Configurable per-IP rate limiting (in-memory, single-process) on browsing and API routes; rate-limit keys use `X-Forwarded-For` only when both `VIDEO_SERVER_BEHIND_PROXY=true` and `VIDEO_SERVER_PROXY_TRUSTED=true`
- `/stream/` uses a separate, higher per-IP rate limit (`VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE`, default 600/min) so range requests are not throttled during normal seeking
- Security headers on all responses (CSP, X-Frame-Options, COOP, CORP, etc.)
- `Cache-Control: no-store` on browsing and API responses; `Cache-Control: private, no-store` on `/stream/` responses
- HSTS when `VIDEO_SERVER_BEHIND_PROXY=true` or `VIDEO_SERVER_HSTS=true`
- HTML UI output uses Jinja2 autoescape for filenames and paths rendered in templates
- Directory listings capped at `VIDEO_SERVER_MAX_DIRECTORY_ENTRIES` (default 10000) using lazy iteration to prevent memory exhaustion
- `VIDEO_SERVER_MAX_FILE_SIZE` enforced on streaming responses (HTTP 413 when exceeded; `0` disables; upper bound 20 GiB at startup validation)
- Lockout tracker bounded at 10000 IP:username entries (active lockouts are never evicted; oldest non-locked trackers may be evicted when full; when every slot is an active lockout, new attackers are not locked out but the event is logged as `lockout_tracker_capacity_exceeded`)

### Audit Logging

Security events are written to `logs/security.log` in JSON format, including authentication attempts, lockout events, path violations, and rate-limit breaches. Each event includes a `request_id` when emitted during an HTTP request. Usernames in auth and file-access logs are truncated to 64 characters; User-Agent strings are truncated to 512 characters. Startup system logs use `to_log_dict()` and always redact the configured username.

Run `python scripts/verify.py` locally before release; it enforces black, isort, mypy, bandit, pylint, pip-audit, and pytest with 90%+ branch coverage.

## Production Deployment Checklist

1. Set `VIDEO_SERVER_PRODUCTION=true`. Deployment checks (writable media root, log directory, bind/proxy warnings) run automatically at `mediarelay` startup. Use `mediarelay-validate` as a pre-deploy dry run without starting the server.
2. Generate credentials with `mediarelay-genpass` (or `mediarelay-genpass --non-interactive` for scripts). Redirect output to `.env`; the password hash must be a Werkzeug `scrypt:`, `pbkdf2:`, or `argon2:` string (validated at startup).
3. Set `VIDEO_SERVER_RATE_LIMIT=true` in production (required at startup).
4. **Terminate TLS** at nginx, Caddy, or another reverse proxy. Do not expose plain HTTP to the internet.
5. Bind to `127.0.0.1` when using a reverse proxy; use firewall rules if binding to `0.0.0.0`. Startup validation warns when `0.0.0.0` is used without `VIDEO_SERVER_BEHIND_PROXY` (LAN binding remains allowed).
6. Keep `VIDEO_SERVER_SESSION_COOKIE_SECURE=true` and `VIDEO_SERVER_SESSION_COOKIE_HTTPONLY=true` when using HTTPS (both required in production).
7. Set `VIDEO_SERVER_SECRET_KEY` to at least 32 characters in production (use `mediarelay-genpass`). An explicit empty or placeholder value is rejected in production; in non-production, empty/placeholder values are replaced with an ephemeral auto-generated key at startup.
8. Set `VIDEO_SERVER_BEHIND_PROXY=true` and `VIDEO_SERVER_PROXY_TRUSTED=true` when MediaRelay is unreachable except through your trusted proxy. Production startup **fails** if `BEHIND_PROXY` is enabled without `PROXY_TRUSTED`.
9. Ensure the video directory is not writable by the server process (enforced at startup in production).
10. Set `VIDEO_SERVER_DIRECTORY` and `VIDEO_SERVER_LOG_DIR` to **absolute paths** in production (relative paths such as `./videos` or `./logs` are rejected by `mediarelay-validate`).
11. Unauthenticated `/health` returns `{"status":"ok"}` (HTTP 200) when runtime health passes (video directory accessible and inode hardlink index ready) or `{"status":"degraded"}` (HTTP 503) when the video directory is inaccessible or the inode index is not ready. Detailed readiness requires an active session cookie or `X-Health-Token` matching `VIDEO_SERVER_HEALTH_TOKEN` when configured. Basic Auth is not accepted on `/health`.
12. Restrict access with firewall rules or VPN where possible.
13. If `VIDEO_SERVER_DIRECTORY` is a symlink, production startup logs a warning with the resolved target path; verify it remains within your intended media storage.

## Known Limitations

| Limitation | Mitigation |
|------------|------------|
| No built-in TLS | Use a reverse proxy with HTTPS |
| In-memory rate limiter | Limits reset on restart; not shared across multiple processes |
| Shared-IP lockout | Lockout is keyed by IP + username; users behind the same NAT may affect each other |
| Single-user model | One username/password pair; no role-based access control |
| Session IP binding | When `VIDEO_SERVER_SESSION_BIND_IP=true` (default), sessions invalidate when the client IP changes (VPN/mobile networks may require re-login or disabling the setting) |
| GET logout disabled | Logout requires `POST /logout` with a valid CSRF token via `X-CSRF-Token` header or `csrf_token` form field (HTML form submit; no inline JavaScript) |
| Basic Auth credential caching | Browsers may re-send cached credentials after `POST /logout`; close the browser or use private browsing |
| Subtitle files (`.srt`, `.vtt`) | Served as `text/plain` with HTML tags and `javascript:`/`data:` URI patterns stripped before delivery; trust only subtitle files you control |
| Distributed brute force | Username-wide lockout (`VIDEO_SERVER_USERNAME_LOCKOUT_ENABLED`) limits cross-IP attacks but allows account DoS if the username is known; disable it or use a strong password and monitor `security.log` |
| Stream rate limit | `/stream/` has a dedicated high limit; tune `VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE` or restrict network access |
| CSP inline styles | Embedded UI template requires `style-src 'unsafe-inline'`; scripts are blocked via `script-src 'none'` |
| Extension-only file filter | No magic-byte content validation; only extension allowlist (custom extensions must match built-in set) |
| Large directories | Listings above `VIDEO_SERVER_MAX_DIRECTORY_ENTRIES` return HTTP 413 |
| Hard links in video directory | Cached inode check plus live scan at serve time blocks files also linked outside the jail; keep the video directory non-writable by untrusted users |
| `mediarelay-genpass` output | Emits secrets to stdout; redirect to a secure file and avoid logging stdout/stderr |
| Intentional `0.0.0.0` bind | Default host binding is audited with bandit `B104` skipped; use `127.0.0.1` behind a reverse proxy in production |

## Responsible Disclosure

We appreciate responsible disclosure. Reporters who follow this policy will be credited in release notes when they wish to be acknowledged.
