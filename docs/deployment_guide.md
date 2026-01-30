# MediaRelay - Deployment Guide

## Overview

This guide covers production deployment of the Video Streaming Server with comprehensive security, monitoring, and performance considerations.

## Prerequisites

### System Requirements

- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 20.04+ recommended)
- **Python**: 3.10 or higher
- **Memory**: Minimum 2GB RAM, 4GB+ recommended for production
- **Storage**: 1GB for application, additional space for video content
- **Network**: Stable internet connection for remote access

### Required Software

- Python 3.10+ with pip
- Git (for version control)
- A text editor or IDE
- Web browser for testing

## Installation

### 1. Download and Setup

```bash
# Clone the repository
git clone https://github.com/tboy1337/MediaRelay.git
cd MediaRelay

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install production dependencies
pip install -r requirements.txt

# For development environment (optional)
pip install -r requirements-dev.txt
```

### 2. Configuration

#### Environment Variables

Create a `.env` file in the project root:

```bash
# Copy the example environment file
python config.py  # This creates .env.example
cp .env.example .env
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

# Directory Settings
VIDEO_SERVER_DIRECTORY=/path/to/your/videos
VIDEO_SERVER_LOG_DIR=./logs

# Performance Settings
VIDEO_SERVER_MAX_FILE_SIZE=21474836480  # 20GB default (set to 0 to disable limit)
VIDEO_SERVER_THREADS=6

# Logging
VIDEO_SERVER_LOG_LEVEL=INFO
VIDEO_SERVER_LOG_MAX_BYTES=10485760
VIDEO_SERVER_LOG_BACKUP_COUNT=5

# Rate Limiting
VIDEO_SERVER_RATE_LIMIT=true
VIDEO_SERVER_RATE_LIMIT_PER_MIN=60

# Environment
FLASK_ENV=production
```

#### Generate Password Hash

```bash
python generate_password.py
```

Follow the prompts to generate a secure password hash and update your `.env` file.

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

Supported formats: MP4, MKV, AVI, MOV, WebM, M4V, FLV, SRT

## Production Deployment

### 1. Security Configuration

#### Firewall Setup

**Windows Firewall:**
```powershell
# Allow inbound connections on your chosen port
New-NetFirewallRule -DisplayName "Video Server" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

**Linux (UFW):**
```bash
sudo ufw allow 5000
sudo ufw enable
```

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
    }
}
```

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
ExecStart=/path/to/MediaRelay/venv/bin/python streaming_server.py
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/path/to/MediaRelay/logs

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mediarelay
sudo systemctl start mediarelay
```

#### Windows Service

Use `nssm` (Non-Sucking Service Manager):

```cmd
# Download and install nssm
nssm install MediaRelay "C:\path\to\python.exe" "C:\path\to\streaming_server.py"
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

Response example:
```json
{
    "status": "healthy",
    "timestamp": "2023-12-01T12:00:00Z",
    "version": "2.0.0",
    "uptime_seconds": 3600,
    "video_directory_accessible": true,
    "config_valid": true
}
```

### 4. Performance Tuning

#### Resource Allocation

For high-traffic deployments:

```bash
# Increase thread count
VIDEO_SERVER_THREADS=12

# Adjust memory limits
VIDEO_SERVER_MAX_FILE_SIZE=53687091200  # 50GB for high-capacity deployments

# Optimize logging
VIDEO_SERVER_LOG_LEVEL=WARNING
```

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

For external access, configure your router:

1. Access your router's admin interface
2. Navigate to Port Forwarding settings
3. Add rule:
   - **External Port**: 5000 (or your custom port)
   - **Internal Port**: 5000
   - **Internal IP**: Your server's local IP
   - **Protocol**: TCP

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
tar -czf config-backup-$(date +%Y%m%d).tar.gz .env config.py .pylintrc
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
chmod +x streaming_server.py
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
4. **Annually**: Credential rotation

### Updates

```bash
# Update application
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

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

# Test endpoint response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:5000/health
```

## Support and Maintenance

### Log Locations

- Application logs: `logs/app.log`
- Error logs: `logs/error.log`
- Security logs: `logs/security.log`
- Performance logs: `logs/performance.log`

### Configuration Validation

```bash
python -c "from config import load_config; print('Config valid:', load_config().to_dict())"
```

### Health Check

```bash
python -c "
import requests
response = requests.get('http://localhost:5000/health')
print('Health:', response.json()['status'])
"
```

For additional support, consult the API documentation and user manual in the docs directory.
