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

- HTTP Basic Authentication with Werkzeug password hashes (PBKDF2)
- Session cookies after successful login (HttpOnly, Secure, SameSite configurable)
- Constant-time username comparison
- Account lockout after repeated failed attempts (per IP + username)
- Session invalidation on client IP change

### Path Access

- All file access is constrained to the configured video directory jail
- Symlinks are resolved before containment checks
- Path traversal payloads (including URL encoding and null bytes) are rejected and logged

### Network Controls

- Configurable per-IP rate limiting (in-memory, single-process)
- Security headers on all responses (CSP, X-Frame-Options, etc.)
- HSTS when `VIDEO_SERVER_SESSION_COOKIE_SECURE=true`

### Audit Logging

Security events are written to `logs/security.log` in JSON format, including authentication attempts, lockout events, path violations, and rate-limit breaches.

## Production Deployment Checklist

1. Set `FLASK_ENV=production` and run `mediarelay-validate` before going live.
2. Generate credentials with `mediarelay-genpass` (or `mediarelay-genpass --non-interactive` for scripts).
3. **Terminate TLS** at nginx, Caddy, or another reverse proxy. Do not expose plain HTTP to the internet.
4. Bind to `127.0.0.1` when using a reverse proxy; use firewall rules if binding to `0.0.0.0`.
5. Keep `VIDEO_SERVER_SESSION_COOKIE_SECURE=true` when using HTTPS (required for session cookies over TLS).
6. Set `VIDEO_SERVER_BEHIND_PROXY=true` **only** when MediaRelay is unreachable except through your trusted proxy.
7. Restrict access with firewall rules or VPN where possible.

## Known Limitations

| Limitation | Mitigation |
|------------|------------|
| No built-in TLS | Use a reverse proxy with HTTPS |
| In-memory rate limiter | Limits reset on restart; not shared across multiple processes |
| Shared-IP lockout | Lockout is keyed by IP + username; users behind the same NAT may affect each other |
| Single-user model | One username/password pair; no role-based access control |
| Session IP binding | Sessions invalidate when the client IP changes (VPN/mobile networks may require re-login) |
| GET logout disabled | Logout requires `POST /logout` to prevent CSRF-forced logout |
| CSP inline styles | Embedded UI template requires `style-src 'unsafe-inline'` |
| Extension-only file filter | No magic-byte content validation; only extension allowlist |

## Responsible Disclosure

We appreciate responsible disclosure. Reporters who follow this policy will be credited in release notes when they wish to be acknowledged.
