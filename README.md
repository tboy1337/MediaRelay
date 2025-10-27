# MediaRelay

A video streaming server that allows you to securely share your personal video library over the internet. Built with robust security, monitoring, and performance features.

## ✨ Features

### 🔒 Security
- **Multi-layer Authentication**: HTTP Basic Auth + Session Management
- **Path Traversal Protection**: Prevents unauthorized file access
- **Security Headers**: XSS, CSRF, clickjacking protection
- **Rate Limiting**: Configurable request throttling
- **Security Audit Logging**: Comprehensive security event tracking
- **Session Management**: Secure sessions with configurable timeouts

### 🎥 Media Streaming  
- **Universal Format Support**: MP4, MKV, AVI, MOV, WebM, M4V, FLV
- **Subtitle Support**: SRT subtitle files
- **Audio Support**: MP3, AAC, OGG, WAV
- **Range Requests**: Efficient streaming with seek support
- **Mobile Optimized**: Responsive design for all devices

### 📊 Monitoring & Performance
- **Health Check Endpoint**: Real-time server status
- **Performance Metrics**: Request timing and throughput monitoring  
- **Comprehensive Logging**: Application, security, error, and performance logs
- **Multi-threaded**: Configurable concurrency for high performance
- **Resource Monitoring**: Memory and disk usage tracking

### 🛠️ Advanced Features
- **Environment Configuration**: Full environment variable support
- **100% Test Coverage**: Comprehensive test suite with security tests
- **Docker Support**: Easy deployment with Docker
- **Service Management**: System service configurations for Windows and Linux
- **Log Rotation**: Automatic log rotation and archival
- **API Support**: RESTful JSON API for integration

## 📋 Requirements

- **Python**: 3.9 or higher
- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 20.04+ recommended)
- **Memory**: Minimum 2GB RAM, 4GB+ recommended for optimal performance
- **Storage**: 1GB for application, additional space for video content
- **Network**: Stable internet connection for remote access

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/tboy1337/MediaRelay.git
cd MediaRelay

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# For development (includes testing and linting tools)
pip install -r requirements-dev.txt
```

### 2. Configuration

```bash
# Generate sample configuration
python config.py

# Copy and edit configuration
copy .env.example .env
# Edit .env with your settings
```

### 3. Security Setup

Generate required security credentials:

```bash
# Generate Flask secret key and password hash
python generate_password.py
```

The script will:
1. **Ask for your preferred username** (e.g., `admin`, `user`, etc.)
2. **Generate or create your password**:
   - Choose 'y' to generate a secure 35-character password automatically
   - Choose 'n' to enter your own password (minimum 8 characters)
3. **Generate a Flask secret key** (for session security)
4. **Create a password hash** (for secure authentication)

**Example output:**
```
============================================================
CONFIGURATION VALUES FOR .env FILE
============================================================
VIDEO_SERVER_SECRET_KEY=a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890
VIDEO_SERVER_USERNAME=admin
VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:600000$abc123$def456...
```

**Important Security Notes**: 
- **Save your password securely** - you'll need it to log in to the web interface
- **Copy all three generated values** to your `.env` file immediately
- **Never share your secret key or password hash** - treat them like private keys
- **Regenerate credentials** if you suspect they've been compromised
- The script uses **cryptographically secure random generation** for maximum security

### 4. Start the Server

```bash
# Start the server
python streaming_server.py

# Or with custom configuration
python streaming_server.py --host 0.0.0.0 --port 8080
```

Once the server is running, you can access it in your web browser at:
- **Local access**: http://localhost:5000
- **Network access**: http://YOUR_IP_ADDRESS:5000 (if configured with --host 0.0.0.0)

### 🔧 Configuration

#### Step-by-Step Configuration Process

1. **Create your configuration file**:
   ```bash
   copy .env.example .env
   ```

2. **Generate security credentials**:
   ```bash
   python generate_password.py
   ```

3. **Update your `.env` file** with the generated values:
   - Replace `VIDEO_SERVER_SECRET_KEY=your-secret-key-here` with your generated secret key
   - Replace `VIDEO_SERVER_USERNAME=tboy1337` with your chosen username  
   - Replace `VIDEO_SERVER_PASSWORD_HASH=your-password-hash-here` with your generated hash

4. **Configure other settings** as needed (video directory, port, etc.)

#### Key Environment Variables

```bash
# Server Configuration
VIDEO_SERVER_HOST=0.0.0.0
VIDEO_SERVER_PORT=5000  
VIDEO_SERVER_DIRECTORY=/path/to/videos
VIDEO_SERVER_THREADS=6

# Security (Required - Generate using python generate_password.py)
VIDEO_SERVER_USERNAME=your_username                    # Your chosen username
VIDEO_SERVER_PASSWORD_HASH=your_secure_hash            # Generated password hash
VIDEO_SERVER_SECRET_KEY=your_secret_key                # Generated Flask secret key

# Performance
VIDEO_SERVER_RATE_LIMIT_PER_MIN=60
VIDEO_SERVER_SESSION_TIMEOUT=3600
VIDEO_SERVER_MAX_FILE_SIZE=21474836480  # 20GB default, set to 0 to disable

# Logging
VIDEO_SERVER_LOG_LEVEL=INFO
VIDEO_SERVER_LOG_DIR=./logs
```

## 🔒 Security

### Authentication & Authorization

```python
# Multi-layer authentication
HTTP_BASIC_AUTH + SESSION_MANAGEMENT + CSRF_PROTECTION
```

### Security Headers

```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN  
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

### Security Monitoring

All security events are logged:
- Authentication attempts (success/failure)
- Path traversal attempts
- Rate limit violations
- File access attempts
- Security header violations

## 📈 Performance

### Performance Features

- **Multi-threading**: Configurable worker threads
- **Range Requests**: Efficient video streaming
- **HTTP Caching**: Browser caching for static content
- **Connection Pooling**: Supports multiple users simultaneously
- **Memory Management**: Automatic resource cleanup

## 📊 API Usage

### Available Endpoints

```bash
# Health check (no auth required)
GET /health

# Directory listing  
GET /api/files?path=movies

# File streaming
GET /stream/path/to/video.mp4

# Web interface
GET /
GET /path/to/directory/
```

### Using the API

```python
import requests
from requests.auth import HTTPBasicAuth

auth = HTTPBasicAuth('username', 'password')

# Get file listing
response = requests.get(
    'http://localhost:5000/api/files', 
    auth=auth
)
files = response.json()

# Stream video
video_url = 'http://localhost:5000/stream/movie.mp4'
response = requests.get(video_url, auth=auth, stream=True)
```

## 🔧 Troubleshooting

### Common Issues

**Server won't start**: Check logs in `logs/error.log`
**Authentication issues**: 
  - Verify your `.env` file has all three security values from `generate_password.py`
  - Ensure you're using the correct username and password you generated
  - Regenerate credentials if needed: `python generate_password.py`
**Performance problems**: Increase thread count (`VIDEO_SERVER_THREADS`)
**Network access**: Check firewall and port forwarding
**Missing .env file**: Copy `.env.example` to `.env` and configure

### Debug Mode

```bash
VIDEO_SERVER_DEBUG=true
VIDEO_SERVER_LOG_LEVEL=DEBUG
python streaming_server.py
```

### Support

- **Documentation**: Check `docs/` directory
- **Logs**: Review application logs in `logs/`
- **Health Check**: `curl http://localhost:5000/health`
- **Issues**: Create GitHub issue with logs and configuration

## 📄 License

This project is licensed under the CRL License - see the [LICENSE.md](LICENSE.md) file for details.
