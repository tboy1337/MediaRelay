# MediaRelay - Deployment Guide

## Overview

This guide covers production deployment of the Video Streaming Server with comprehensive security, monitoring, and performance considerations.

## Prerequisites

### System Requirements

- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 20.04+ recommended)
- **Python**: 3.12 or higher
- **Memory**: Minimum 2GB RAM, 4GB+ recommended for production
- **Storage**: 1GB for application, additional space for video content
- **Network**: Stable internet connection for remote access

### Required Software

- Python 3.12+ with pip
- Git (for version control)
- A text editor or IDE
- Web browser for testing

## Installation

### 1. Install from PyPI (recommended)

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

pip install mediarelay
```

Windows users can also download pre-built executables from [GitHub Releases](https://github.com/tboy1337/MediaRelay/releases).

#### Windows executable (GitHub Releases)

1. Download `MediaRelay-v1.0.<run_number>.zip` from [GitHub Releases](https://github.com/tboy1337/MediaRelay/releases) (artifact name includes the CI run number).
2. Extract `MediaRelay-v1.0.<run_number>.exe` to a folder of your choice.
3. Create a `.env` file in the same directory (copy from `.env.example` or run `mediarelay-config` if you have Python installed).
4. Generate credentials with `mediarelay-genpass --non-interactive` (or interactive `mediarelay-genpass`) and update `.env`.
5. Restrict `.env` permissions where supported (`icacls` on Windows, `chmod 600 .env` on Linux/macOS).
6. Run `MediaRelay.exe` from that directory.

The executable bundles the server only. Use `pip install mediarelay` if you need `mediarelay-genpass`, `mediarelay-config`, or `mediarelay-validate` without Python tooling.

**Windows service (executable):**

```cmd
nssm install MediaRelay "C:\path\to\MediaRelay.exe"
nssm set MediaRelay AppDirectory "C:\path\to\MediaRelay"
nssm set MediaRelay AppStdout "C:\path\to\MediaRelay\logs\service.log"
nssm set MediaRelay AppStderr "C:\path\to\MediaRelay\logs\service-error.log"
nssm start MediaRelay
```

Place `.env` in `AppDirectory`. Generate credentials on a machine with Python (`mediarelay-genpass --non-interactive`) and copy the values into `.env` before starting the service.

### 2. Install from source (development)

```bash
git clone https://github.com/tboy1337/MediaRelay.git
cd MediaRelay
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
pip install -e ".[dev]"
```

### 3. Configuration

#### Environment Variables

Create a `.env` file in the project root:

```bash
# Copy the example environment file
mediarelay-config
cp .env.example .env   # Linux/macOS
copy .env.example .env   # Windows
```

Edit `.env` with your configuration:

```bash
# Server Settings
VIDEO_SERVER_HOST=0.0.0.0
VIDEO_SERVER_PORT=5000
VIDEO_SERVER_DEBUG=false
VIDEO_SERVER_THREADS=6

# Security Settings (REQUIRED)
VIDEO_SERVER_SECRET_KEY=your-generated-secret-key-here
VIDEO_SERVER_USERNAME=your-username
VIDEO_SERVER_PASSWORD_HASH=your-password-hash
VIDEO_SERVER_SESSION_TIMEOUT=3600
VIDEO_SERVER_SESSION_MAX_LIFETIME=86400

# Session Cookie Settings
# Requires HTTPS when true; set false only for local HTTP development
VIDEO_SERVER_SESSION_COOKIE_SECURE=true
VIDEO_SERVER_SESSION_COOKIE_HTTPONLY=true
VIDEO_SERVER_SESSION_COOKIE_SAMESITE=Strict

# Directory Settings
VIDEO_SERVER_DIRECTORY=/path/to/your/videos
VIDEO_SERVER_LOG_DIR=./logs

# Performance Settings
VIDEO_SERVER_MAX_FILE_SIZE=21474836480  # 20GB default (max 21474836480; set to 0 to disable limit)
VIDEO_SERVER_MAX_DIRECTORY_ENTRIES=10000
VIDEO_SERVER_PAGE_SIZE=100
VIDEO_SERVER_CHANNEL_TIMEOUT=120
VIDEO_SERVER_CONNECTION_LIMIT=1000
VIDEO_SERVER_CLEANUP_INTERVAL=30

# Logging
VIDEO_SERVER_LOG_LEVEL=INFO
VIDEO_SERVER_LOG_MAX_BYTES=10485760
VIDEO_SERVER_LOG_BACKUP_COUNT=5
VIDEO_SERVER_LOG_CONSOLE=true

# Rate Limiting
VIDEO_SERVER_RATE_LIMIT=true
VIDEO_SERVER_RATE_LIMIT_PER_MIN=60
VIDEO_SERVER_STREAM_RATE_LIMIT_PER_MINUTE=600

# Security
VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS=5
VIDEO_SERVER_LOCKOUT_DURATION=900
VIDEO_SERVER_SESSION_BIND_IP=true
VIDEO_SERVER_USERNAME_LOCKOUT_ENABLED=true
VIDEO_SERVER_HSTS=false

# Reverse Proxy (set true when behind nginx; set PROXY_TRUSTED=true in production)
VIDEO_SERVER_BEHIND_PROXY=false
VIDEO_SERVER_PROXY_TRUSTED=false

# Environment (required for production credential validation)
VIDEO_SERVER_PRODUCTION=true
```

#### Generate Password Hash

```bash
mediarelay-genpass
```

Follow the prompts to generate a secure password hash and update your `.env` file.

#### Pre-Flight Validation

Before starting the server in production, validate your configuration:

```bash
# Validate default .env in current directory
mediarelay-validate

# Or validate a specific config file
mediarelay-validate --config-file /path/to/.env
```

When `VIDEO_SERVER_PRODUCTION=true`, the same deployment checks also run automatically when you start the server with `mediarelay`. Use `mediarelay-validate` to catch configuration errors before a service restart or container rollout.

The validator checks password hash format, secret key presence, video/log directory permissions, rate limiting, and port range. Fix any reported errors before deployment.

**Pre-deploy checklist:**

1. Set `VIDEO_SERVER_PRODUCTION=true`
2. Run `mediarelay-validate` and fix all reported errors
3. Terminate TLS at a reverse proxy (never send Basic Auth over plain HTTP)
4. Set `VIDEO_SERVER_PROXY_TRUSTED=true` only when MediaRelay is exclusively behind your trusted reverse proxy
5. Confirm the video directory is readable and the inode hardlink index builds successfully (production startup fails fast if index build fails)
6. Restrict media directory to read-only for the service account (see below)

Unauthenticated `GET /health` returns minimal readiness (`{"status":"ok"}` when healthy, `{"status":"degraded"}` with HTTP 503 when the video directory is inaccessible or the inode index is unavailable). Use authenticated `/health` for full readiness (disk access, version, uptime).

#### Read-only media directory

Production validation expects the video directory to be read-only for the service account.

**Linux/macOS:**

```bash
chmod -R a-w /path/to/videos
```

**Windows (icacls):**

```cmd
icacls "C:\path\to\videos" /inheritance:r
icacls "C:\path\to\videos" /grant:r "%USERNAME%:(OI)(CI)R"
icacls "C:\path\to\videos" /grant:r "NT SERVICE\MediaRelay:(OI)(CI)R"
```

Adjust the service account name to match your installation.

#### Subtitle streaming limits

Subtitle files (`.srt`, `.vtt`) are capped at **10 MiB** regardless of `VIDEO_SERVER_MAX_FILE_SIZE`. Content is sanitized before serving (HTML tags, dangerous URI schemes, and WEBVTT `STYLE`/`NOTE` blocks are stripped). Oversized subtitles return HTTP 413.

#### Inode hardlink index failure

In production mode, MediaRelay refuses to start if the inode hardlink index cannot be built. This protects against hardlink escape attacks. If startup fails with an inode index error:

1. Verify the service account can read the entire video directory tree
2. Check for permission errors on nested folders
3. Run `mediarelay-validate` with `VIDEO_SERVER_PRODUCTION=true`
4. Review application logs for the underlying `OSError`

Non-production mode continues with degraded health when the index fails to build.

#### Lockout tracker capacity

Account lockout tracks up to **10,000** unique `IP:username` combinations. When the tracker is full, new failed login attempts are not recorded and a `lockout_tracker_capacity_exceeded` event is written to `security.log`. Monitor this event to detect tracker flooding attacks.

### 3. Directory Structure

Ensure your video directory exists and contains your media files:

```
/path/to/videos/
├── movies/
│   ├── action/
│   └── comedy/
├── tv_shows/
│   ├── series1/
│   └── series2/
└── documentaries/
```

Supported formats: MP4, MKV, AVI, MOV, WebM, M4V, FLV, SRT, MP3, AAC, OGG, WAV

## Production Deployment

### 1. Security Configuration

#### Firewall Setup

**Windows Firewall:**
```powershell
# Allow inbound connections on your chosen port
New-NetFirewallRule -DisplayName "Video Server" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

**Linux (UFW):**

When using a reverse proxy, allow only HTTP/HTTPS (443/80) and keep MediaRelay bound to `127.0.0.1:5000`:

```bash
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

Do not expose port 5000 publicly when a reverse proxy terminates TLS.

#### SSL/TLS (Recommended)

For production deployments, use a reverse proxy with SSL:

**Nginx Configuration:**
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeout for large video files
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_buffering off;
    }
}
```

When using nginx (or another reverse proxy), set `VIDEO_SERVER_BEHIND_PROXY=true` and `VIDEO_SERVER_PROXY_TRUSTED=true` in your `.env` file so client IPs, rate limiting, and account lockout use the forwarded address (leftmost `X-Forwarded-For` entry). **Only enable this when MediaRelay is not directly reachable from the internet** — bind to `127.0.0.1` and expose only through the proxy. If `BEHIND_PROXY=true` without `PROXY_TRUSTED=true`, production startup fails; if enabled without a trusted proxy, attackers can spoof client IPs.

Keep `VIDEO_SERVER_SESSION_COOKIE_SECURE=true` when serving over HTTPS. For plain-HTTP local development only, set `VIDEO_SERVER_SESSION_COOKIE_SECURE=false`.

#### Account Lockout

After `VIDEO_SERVER_LOCKOUT_MAX_ATTEMPTS` failed logins (default 5) from the same client IP and username, the account is locked for `VIDEO_SERVER_LOCKOUT_DURATION` seconds (default 900 / 15 minutes). Locked clients receive HTTP 401 responses with a `Retry-After` header. Adjust both values in `.env` if needed.

Set `VIDEO_SERVER_PRODUCTION=true` in production so placeholder secret keys and password hashes are rejected at startup.

### 2. Process Management

#### Systemd Service (Linux)

Create `/etc/systemd/system/mediarelay.service`:

```ini
[Unit]
Description=MediaRelay
After=network.target

[Service]
Type=simple
User=your-user
Group=your-group
WorkingDirectory=/path/to/MediaRelay
Environment=PATH=/path/to/MediaRelay/venv/bin
EnvironmentFile=/path/to/MediaRelay/.env
ExecStart=/path/to/MediaRelay/venv/bin/mediarelay
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/path/to/MediaRelay/logs /path/to/videos

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mediarelay
sudo systemctl start mediarelay
```

#### macOS launchd

Create `~/Library/LaunchAgents/com.mediarelay.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mediarelay</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-lc</string>
        <string>set -a &amp;&amp; source /path/to/MediaRelay/.env &amp;&amp; exec /path/to/MediaRelay/venv/bin/mediarelay</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/path/to/MediaRelay</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/path/to/MediaRelay/venv/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load the agent:

```bash
launchctl load ~/Library/LaunchAgents/com.mediarelay.plist
```

Place your `.env` file in the WorkingDirectory. The wrapper above sources it before launch. Set `VIDEO_SERVER_SESSION_COOKIE_SECURE=true` only when serving over HTTPS.

#### Scripted credential generation

```bash
mediarelay-genpass --non-interactive --username tboy1337
```

Copy the printed `VIDEO_SERVER_*` lines into `.env`. Restrict file permissions: `chmod 600 .env`.

#### Windows Service

Use `nssm` (Non-Sucking Service Manager):

```cmd
# Download and install nssm
nssm install MediaRelay "C:\path\to\MediaRelay\venv\Scripts\mediarelay.exe"
nssm set MediaRelay AppDirectory "C:\path\to\MediaRelay"
nssm start MediaRelay
```

### 3. Monitoring and Logging

#### Log Rotation Setup

The application includes built-in log rotation. Logs are stored in:
- `logs/app.log` - General application logs
- `logs/security.log` - Security events
- `logs/performance.log` - Performance metrics
- `logs/error.log` - Error messages only

#### Health Monitoring

The server provides a health check endpoint:

```bash
curl http://localhost:5000/health
```

Unauthenticated response when healthy (HTTP 200):

```json
{"status": "ok"}
```

When the video directory is inaccessible, unauthenticated `/health` returns HTTP 503:

```json
{"status": "degraded"}
```

Authenticated response includes readiness (`healthy`/`unhealthy`), version, uptime, and configuration details. See [API Documentation](api_documentation.md#1-health-check).

**Probe guidance:**

| Probe type | Endpoint | Auth | Use case |
|------------|----------|------|----------|
| Liveness | `GET /health` | None | Process is up; directory readable |
| Readiness | `GET /health` | Basic Auth | Full status including version and uptime |

Alert when unauthenticated `/health` returns HTTP 503 (`degraded`) or when authenticated `/health` returns `unhealthy`. Ship `security.log` to your SIEM and alert on `lockout_tracker_capacity_exceeded` and repeated `session_invalidated` events.

`/health` is exempt from rate limiting so monitoring probes are not throttled.

### 4. Performance Tuning

#### Resource Allocation

For high-traffic deployments:

```bash
# Increase thread count
VIDEO_SERVER_THREADS=12

# Waitress tuning (optional)
VIDEO_SERVER_CHANNEL_TIMEOUT=300
VIDEO_SERVER_CONNECTION_LIMIT=1000
VIDEO_SERVER_CLEANUP_INTERVAL=30

# Adjust memory limits
VIDEO_SERVER_MAX_FILE_SIZE=21474836480  # 20 GiB (maximum allowed)

# Optimize logging
VIDEO_SERVER_LOG_LEVEL=WARNING
```

#### Graceful Shutdown

MediaRelay runs on Waitress, which stops accepting new connections when it receives `SIGINT` or `SIGTERM` (for example, Ctrl+C or a process manager stop). Waitress does not provide a long connection-drain window; in-flight streams may be interrupted when the process exits. On shutdown, MediaRelay runs cleanup (log handler flush, lockout timer cancellation) before the process exits.

For production, configure your reverse proxy (for example, nginx or Caddy) with reasonable upstream timeouts so clients disconnect cleanly before the MediaRelay process is restarted.

#### Operating System Tuning

**Linux:**
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize network settings
echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 1024" >> /etc/sysctl.conf
sysctl -p
```

## Network Configuration

### Port Forwarding

For external access, **forward ports to your reverse proxy (443/80), not directly to MediaRelay**. MediaRelay should bind to `127.0.0.1:5000` and only be reachable through HTTPS.

If you forward directly to port 5000 without TLS:

- Sessions may fail when `VIDEO_SERVER_SESSION_COOKIE_SECURE=true`
- Credentials and media travel in cleartext

Recommended router setup:

1. Access your router's admin interface
2. Navigate to Port Forwarding settings
3. Add rules for **443** (and **80** if needed) to your proxy host
4. Do **not** expose port 5000 publicly unless it is firewalled to localhost-only

### Dynamic DNS (Optional)

For easier access with changing IP addresses:

1. Sign up for a dynamic DNS service (DuckDNS, No-IP, etc.)
2. Configure your router or install a client
3. Use the provided hostname instead of IP address

## Security Best Practices

### 1. Access Control

- Use strong, unique passwords
- Regularly rotate credentials
- Consider implementing IP whitelisting
- Monitor access logs regularly

### 2. Network Security

- Use VPN for remote access when possible
- Keep router firmware updated
- Disable unnecessary services
- Use non-standard ports if needed

### 3. Application Security

- Keep the application updated
- Monitor security logs
- Use HTTPS with valid certificates
- Implement rate limiting

### 4. System Security

- Keep OS updated
- Use firewall
- Regular security audits
- Backup configuration and logs

## Backup and Recovery

### Configuration Backup

```bash
# Backup configuration files
tar -czf config-backup-$(date +%Y%m%d).tar.gz .env
```

### Application Backup

```bash
# Full application backup
tar -czf app-backup-$(date +%Y%m%d).tar.gz \
    --exclude=venv \
    --exclude=logs \
    --exclude=__pycache__ \
    --exclude=.git \
    .
```

### Recovery Procedure

1. Stop the application service
2. Restore configuration files
3. Reinstall dependencies if needed
4. Verify configuration
5. Restart service
6. Verify functionality

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port
netstat -ano | findstr :5000  # Windows
lsof -i :5000                 # Linux/macOS

# Kill process if needed
taskkill /PID <PID> /F        # Windows
kill -9 <PID>                 # Linux/macOS
```

#### Permission Errors
```bash
# Fix file permissions (Linux/macOS)
# Ensure mediarelay is installed: pip install mediarelay
chown -R user:group /path/to/MediaRelay

# Ensure video directory is accessible
chmod -R 755 /path/to/videos
```

#### Memory Issues
```bash
# Monitor memory usage
top                           # Linux/macOS
tasklist /fi "imagename eq python.exe"  # Windows

# Adjust thread count if needed
VIDEO_SERVER_THREADS=4
```

### Log Analysis

#### Check Application Status
```bash
tail -f logs/app.log
```

#### Monitor Security Events
```bash
tail -f logs/security.log | grep "security_violation"
```

#### Performance Issues
```bash
tail -f logs/performance.log | grep "duration_ms"
```

## Maintenance

### Regular Tasks

1. **Weekly**: Review security logs
2. **Monthly**: Update dependencies
3. **Quarterly**: Security audit
4. **Annually**: Credential rotation (see below)

### Credential rotation

1. Run `mediarelay-genpass --non-interactive` (or interactive `mediarelay-genpass`).
2. Update `VIDEO_SERVER_SECRET_KEY`, `VIDEO_SERVER_PASSWORD_HASH`, and optionally `VIDEO_SERVER_USERNAME` in `.env`.
3. Restart MediaRelay (`systemctl restart mediarelay`, `nssm restart MediaRelay`, or relaunch the executable).
4. Run `mediarelay-validate` and verify login with the new password.
5. Invalidate old sessions (restart clears in-memory sessions; users must log in again).

### Updates

```bash
# Update from PyPI
pip install --upgrade mediarelay

# Or from source
git pull origin main
pip install -e ".[dev]"

# Restart service
sudo systemctl restart mediarelay  # Linux
nssm restart MediaRelay              # Windows
```

### Performance Monitoring

```bash
# Check system resources
htop          # Linux
perfmon       # Windows

# Monitor application logs
tail -f logs/performance.log

# Test health endpoint
curl -o /dev/null -s -w "%{http_code}\n" http://localhost:5000/health
```

## Support and Maintenance

### Log Locations

- Application logs: `logs/app.log`
- Error logs: `logs/error.log`
- Security logs: `logs/security.log`
- Performance logs: `logs/performance.log`

### Configuration Validation

```bash
mediarelay-validate
```

### Health Check

```bash
python -c "
import requests
response = requests.get('http://localhost:5000/health')
print('Health:', response.json()['status'])
"
```

### Platform-specific tests (developers)

Symlink/hardlink jail tests and POSIX `.env` permission checks are skipped on Windows. Run them in WSL or Linux before release:

```bash
wsl -u test -- bash -lc "cd /mnt/c/Users/Laptop/Documents/Git/MediaRelay && py -m pytest tests/test_path_utils.py tests/test_security.py tests/test_config.py -k 'symlink or hardlink or permission'"
```

For additional support, consult the API documentation and user manual in the docs directory.
