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
- Constant-time username comparison (`hmac.compare_digest`)
- Password verification on every login attempt, including when already locked out (mitigates username timing enumeration)
- Account lockout after repeated failed attempts (per IP + username); lockout also terminates active sessions
- Active lockout entries are never evicted from the lockout tracker when at capacity; new attackers receive an emergency lockout when all slots hold active lockouts
- Session invalidation on client IP change; sessions without a bound login IP are rejected
- Session invalidation when username or password hash changes (`credential_epoch` fingerprint)
- Expired sessions fall through to valid HTTP Basic credentials on the same request
- Idle session timeout (`VIDEO_SERVER_SESSION_TIMEOUT`) and absolute max lifetime (`VIDEO_SERVER_SESSION_MAX_LIFETIME`)
- `SameSite=None` requires `VIDEO_SERVER_SESSION_COOKIE_SECURE=true` at startup

### Path Access

- All file access is constrained to the configured video directory jail
- Symlinks are resolved before containment checks
- Hard links whose inode is also linked outside the jail are rejected using a cached inode index (refreshed periodically)
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
- `VIDEO_SERVER_MAX_FILE_SIZE` enforced on streaming responses (HTTP 413 when exceeded; `0` disables)
- Lockout tracker bounded at 10000 IP:username entries (only inactive trackers evicted when full; fail-closed emergency lockout when saturated)

### Audit Logging

Security events are written to `logs/security.log` in JSON format, including authentication attempts, lockout events, path violations, and rate-limit breaches. Each event includes a `request_id` when emitted during an HTTP request. Usernames in auth logs are truncated to 64 characters.

Run `python scripts/verify.py` locally before release; it enforces black, isort, mypy, bandit, pylint, pip-audit, and pytest with 90%+ branch coverage.

## Production Deployment Checklist

1. Set `VIDEO_SERVER_PRODUCTION=true`. Deployment checks (writable media root, log directory, bind/proxy warnings) run automatically at `mediarelay` startup. Use `mediarelay-validate` as a pre-deploy dry run without starting the server.
2. Generate credentials with `mediarelay-genpass` (or `mediarelay-genpass --non-interactive` for scripts).
3. Set `VIDEO_SERVER_RATE_LIMIT=true` in production (required at startup).
4. **Terminate TLS** at nginx, Caddy, or another reverse proxy. Do not expose plain HTTP to the internet.
5. Bind to `127.0.0.1` when using a reverse proxy; use firewall rules if binding to `0.0.0.0`. Startup validation warns when `0.0.0.0` is used without `VIDEO_SERVER_BEHIND_PROXY`.
6. Keep `VIDEO_SERVER_SESSION_COOKIE_SECURE=true` when using HTTPS (required for session cookies over TLS).
7. Set `VIDEO_SERVER_BEHIND_PROXY=true` and `VIDEO_SERVER_PROXY_TRUSTED=true` **only** when MediaRelay is unreachable except through your trusted proxy. Without `PROXY_TRUSTED`, client IP and rate limits use the direct connection address.
8. Ensure the video directory is not writable by the server process (enforced at startup in production).
9. Use authenticated `/health` for readiness monitoring; unauthenticated `/health` returns liveness only (`{"status":"ok"}`).
10. Restrict access with firewall rules or VPN where possible.

## Known Limitations

| Limitation | Mitigation |
|------------|------------|
| No built-in TLS | Use a reverse proxy with HTTPS |
| In-memory rate limiter | Limits reset on restart; not shared across multiple processes |
| Shared-IP lockout | Lockout is keyed by IP + username; users behind the same NAT may affect each other |
| Single-user model | One username/password pair; no role-based access control |
| Session IP binding | Sessions invalidate when the client IP changes (VPN/mobile networks may require re-login) |
| GET logout disabled | Logout requires `POST /logout` to prevent CSRF-forced logout |
| Basic Auth credential caching | Browsers may re-send cached credentials after `POST /logout`; close the browser or use private browsing |
| Distributed brute force | Lockout is per IP + username; use a strong password |
| Stream rate limit | `/stream/` has a dedicated high limit; tune `VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE` or restrict network access |
| CSP inline styles | Embedded UI template requires `style-src 'unsafe-inline'` |
| Extension-only file filter | No magic-byte content validation; only extension allowlist (custom extensions must match built-in set) |
| Large directories | Listings above `VIDEO_SERVER_MAX_DIRECTORY_ENTRIES` return HTTP 413 |
| Hard links in video directory | Cached inode check blocks files also linked outside the jail; keep the video directory non-writable by untrusted users |
| `mediarelay-genpass` output | Emits secrets to stdout; redirect to a secure file and avoid logging stdout/stderr |
| Intentional `0.0.0.0` bind | Default host binding is audited with bandit `B104` skipped; use `127.0.0.1` behind a reverse proxy in production |

## Responsible Disclosure

We appreciate responsible disclosure. Reporters who follow this policy will be credited in release notes when they wish to be acknowledged.
