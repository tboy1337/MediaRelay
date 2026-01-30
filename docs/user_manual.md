# MediaRelay - User Manual

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Advanced Features](#advanced-features)
5. [Troubleshooting](#troubleshooting)
6. [FAQ](#frequently-asked-questions)

## Getting Started

The Video Streaming Server allows you to share your personal video library over the internet securely. Whether you want to access your movies from anywhere or share them with friends and family, this server provides a secure, easy-to-use solution.

### What You'll Need

- A computer with Python 3.10 or higher
- Your video files organized in folders
- Basic network configuration knowledge (for remote access)
- 30 minutes for initial setup

### Key Features

- **Secure Access**: Password-protected with session management
- **Mobile Friendly**: Responsive design works on phones and tablets
- **Multiple Formats**: Supports MP4, MKV, AVI, MOV, WebM, M4V, FLV
- **Subtitle Support**: SRT subtitle files are supported
- **Directory Navigation**: Browse folders and subfolders easily
- **Streaming Optimization**: Efficient video streaming with range requests
- **Production Ready**: Comprehensive logging, monitoring, and security

## Installation

### Quick Setup

1. **Download the Application**
   ```bash
   git clone https://github.com/tboy1337/MediaRelay.git
   cd MediaRelay
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Your Settings**
   ```bash
   python config.py  # Creates .env.example
   cp .env.example .env
   # Edit .env file with your settings
   ```

4. **Set Up Security**
   ```bash
   python generate_password.py
   # Follow prompts to create secure password
   ```

5. **Start the Server**
   ```bash
   python streaming_server.py
   ```

### Detailed Installation

For detailed installation instructions including system requirements, security setup, and production deployment, see the [Deployment Guide](deployment_guide.md).

## Basic Usage

### First Time Setup

1. **Organize Your Videos**
   
   Create a directory structure like this:
   ```
   Videos/
   ├── Movies/
   │   ├── Action/
   │   ├── Comedy/
   │   └── Drama/
   ├── TV Shows/
   │   ├── Series 1/
   │   └── Series 2/
   └── Documentaries/
   ```

2. **Configure Video Directory**
   
   Edit your `.env` file:
   ```bash
   VIDEO_SERVER_DIRECTORY=/path/to/your/Videos
   ```

3. **Set Username and Password**
   
   Run the password generator:
   ```bash
   python generate_password.py
   ```
   
   Choose a strong password and copy the hash to your `.env` file:
   ```bash
   VIDEO_SERVER_USERNAME=your_username
   VIDEO_SERVER_PASSWORD_HASH=pbkdf2:sha256:...your_hash
   ```

4. **Start the Server**
   ```bash
   python streaming_server.py
   ```

### Accessing Your Videos

#### Local Access

1. Open your web browser
2. Go to `http://localhost:5000`
3. Enter your username and password
4. Browse and play your videos!

#### Remote Access

To access from anywhere on the internet:

1. **Configure Port Forwarding**
   - Access your router's admin panel
   - Forward port 5000 to your computer
   - Save the settings

2. **Find Your Public IP**
   - Visit whatismyip.com
   - Note your public IP address

3. **Access Remotely**
   - Go to `http://your-public-ip:5000`
   - Login with your credentials

### Using the Interface

#### Main Navigation

- **Breadcrumbs**: Shows your current location
- **Folder Icons** (📁): Click to enter directories
- **Video Icons** (🎬): Click to play videos
- **Up Arrow**: Go to parent directory

#### Video Player

- **Controls**: Play, pause, seek, volume, fullscreen
- **Subtitles**: Automatically loaded if .srt file exists
- **Back Button**: Return to directory listing
- **Responsive**: Works on mobile devices

#### Directory Features

- **Sorting**: Folders first, then files alphabetically
- **File Info**: Shows file size and modification date
- **Statistics**: Total files and folder counts

## Advanced Features

### Configuration Options

#### Environment Variables

Edit your `.env` file to customize:

```bash
# Server Configuration
VIDEO_SERVER_HOST=0.0.0.0          # Listen on all interfaces
VIDEO_SERVER_PORT=8080              # Custom port
VIDEO_SERVER_THREADS=12             # More threads for better performance

# Security
VIDEO_SERVER_SESSION_TIMEOUT=7200   # 2 hours
VIDEO_SERVER_RATE_LIMIT_PER_MIN=120 # More requests per minute

# Performance
VIDEO_SERVER_MAX_FILE_SIZE=21474836480  # 20GB max file size (set to 0 to disable limit)

# Logging
VIDEO_SERVER_LOG_LEVEL=DEBUG        # More detailed logs
```

#### Custom Port

To use a different port:

1. Edit `.env`: `VIDEO_SERVER_PORT=8080`
2. Update port forwarding rules
3. Access via `http://localhost:8080`

#### Multiple Users

Currently supports one user account. For multiple users, you can:
- Create separate server instances
- Use different usernames/passwords for each instance
- Run on different ports

### Security Features

#### Session Management

- **Auto-login**: Remembers you after first authentication
- **Timeout**: Sessions expire after inactivity
- **Security**: Session data is encrypted

#### Access Logging

All access is logged in `logs/security.log`:
- Login attempts (successful and failed)
- File access requests
- Security violations

#### Rate Limiting

- **Default**: 60 requests per minute per IP
- **Customizable**: Adjust in configuration
- **Automatic**: Blocks excessive requests

### Performance Optimization

#### For Large Libraries

```bash
# Increase threads for better concurrent access
VIDEO_SERVER_THREADS=16

# Optimize logging for performance
VIDEO_SERVER_LOG_LEVEL=WARNING
VIDEO_SERVER_LOG_MAX_BYTES=50000000
```

#### For Slow Networks

```bash
# Reduce session timeout for mobile users
VIDEO_SERVER_SESSION_TIMEOUT=1800  # 30 minutes

# Enable more aggressive rate limiting
VIDEO_SERVER_RATE_LIMIT_PER_MIN=30
```

### Network Configuration

#### Dynamic IP Address

If your IP changes frequently:

1. **Sign up for Dynamic DNS**
   - Services: DuckDNS, No-IP, Dynu
   - Choose a hostname: `yourname.duckdns.org`

2. **Configure Router**
   - Enable dynamic DNS in router settings
   - Or install client software

3. **Access via Hostname**
   - Use `http://yourname.duckdns.org:5000`
   - Works even when IP changes

#### VPN Access

For maximum security:

1. **Set up VPN server** (OpenVPN, WireGuard)
2. **Connect via VPN** before accessing server
3. **Access via local IP** (`http://192.168.1.100:5000`)

### Mobile Usage

#### Optimizations for Mobile

The interface is mobile-optimized with:
- **Touch-friendly controls**
- **Responsive video player**
- **Optimized layouts**
- **Gesture support**

#### Mobile Browsers

**Best compatibility:**
- Chrome (Android)
- Safari (iOS)
- Firefox Mobile

**Video format support varies by browser:**
- MP4: Universal support
- MKV: Limited support
- AVI: Requires conversion

### API Usage

For developers and advanced users, see [API Documentation](api_documentation.md).

#### Quick API Examples

```bash
# Check server health
curl http://localhost:5000/health

# Get file listing
curl -u username:password http://localhost:5000/api/files

# Download video
curl -u username:password http://localhost:5000/stream/movie.mp4 -o movie.mp4
```

## Troubleshooting

### Common Problems

#### "Cannot Connect to Server"

**Symptoms**: Browser shows "can't reach this page"

**Solutions**:
1. Check server is running: Look for "Server running on..." message
2. Verify address: Use `http://localhost:5000` locally
3. Check firewall: Ensure port 5000 is allowed
4. Try different port: Edit configuration if 5000 is in use

#### "Authentication Required" Loop

**Symptoms**: Keeps asking for password

**Solutions**:
1. Verify credentials: Check username and password
2. Check password hash: Ensure hash in `.env` is correct
3. Try password generator again: `python generate_password.py`
4. Check browser cookies: Clear browser data

#### Videos Won't Play

**Symptoms**: Player shows but video doesn't start

**Solutions**:
1. **Check format**: Ensure browser supports video format
   - Convert to MP4 for best compatibility
2. **Check file integrity**: Verify video file isn't corrupted
3. **Check permissions**: Ensure server can read video files
4. **Try different browser**: Chrome/Edge have best codec support

#### Slow Streaming

**Symptoms**: Videos buffer frequently or take long to start

**Solutions**:
1. **Check network**: Test internet speed
2. **Increase threads**: `VIDEO_SERVER_THREADS=12` in config
3. **Check file size**: Very large files (>4GB) may be slow
4. **Local network**: Use local IP for better speed

#### "Path Not Found" Errors

**Symptoms**: Folders or files show as not found

**Solutions**:
1. **Check video directory**: Ensure path in config is correct
2. **Check permissions**: Server must have read access
3. **Check file names**: Avoid special characters
4. **Refresh browser**: Clear browser cache

### Advanced Troubleshooting

#### Log Analysis

**Application logs**: `logs/app.log`
```bash
tail -f logs/app.log  # Monitor in real-time
```

**Security logs**: `logs/security.log`
```bash
grep "authentication" logs/security.log  # Check login attempts
```

**Error logs**: `logs/error.log`
```bash
tail -20 logs/error.log  # See recent errors
```

#### Debug Mode

Enable debug mode for detailed information:

```bash
# In .env file
VIDEO_SERVER_DEBUG=true
VIDEO_SERVER_LOG_LEVEL=DEBUG
```

**Warning**: Debug mode logs sensitive information. Don't use in production.

#### Network Debugging

```bash
# Check if port is open
netstat -an | grep 5000         # Windows/Linux
lsof -i :5000                   # macOS/Linux

# Test local connectivity
curl http://localhost:5000/health

# Test external connectivity
curl http://your-public-ip:5000/health
```

#### Performance Debugging

```bash
# Monitor resource usage
top                             # Linux/macOS
tasklist | findstr python      # Windows

# Check disk space
df -h                           # Linux/macOS
dir                            # Windows
```

### Getting Help

1. **Check logs**: Always check application logs first
2. **Test locally**: Ensure local access works before remote
3. **Simplify**: Try with minimal configuration
4. **Document**: Note exact error messages and steps to reproduce

## Frequently Asked Questions

### General Questions

**Q: What video formats are supported?**
A: MP4, MKV, AVI, MOV, WebM, M4V, FLV, plus SRT subtitles and audio formats (MP3, AAC, OGG, WAV).

**Q: Can I access this from my phone?**
A: Yes! The interface is mobile-optimized and works on smartphones and tablets.

**Q: Is this secure?**
A: Yes, with password protection, session management, security headers, and comprehensive logging.

**Q: Can multiple people use it at once?**
A: Yes, the server supports concurrent users with configurable performance settings.

### Setup Questions

**Q: Do I need a static IP address?**
A: No, you can use dynamic DNS services like DuckDNS for changing IP addresses.

**Q: Can I use a different port?**
A: Yes, edit `VIDEO_SERVER_PORT` in your `.env` file and update port forwarding.

**Q: How do I add new videos?**
A: Simply copy video files to your video directory. They'll appear immediately (no restart needed).

**Q: Can I organize videos in subfolders?**
A: Yes, create any folder structure you want. The server supports unlimited nesting.

### Security Questions

**Q: How do I change my password?**
A: Run `python generate_password.py` again and update your `.env` file.

**Q: Can I see who accessed my videos?**
A: Yes, check `logs/security.log` for detailed access logs.

**Q: Is traffic encrypted?**
A: By default, no. For encryption, set up HTTPS with a reverse proxy (see deployment guide).

**Q: Can I whitelist IP addresses?**
A: This requires firewall configuration. See deployment guide for details.

### Technical Questions

**Q: How much bandwidth does streaming use?**
A: Depends on video bitrate. Typical 1080p video uses 5-10 Mbps.

**Q: Can I stream 4K videos?**
A: Yes, but ensure your network and device can handle the bandwidth.

**Q: What happens if I lose internet connection?**
A: Local network access continues working. Remote access requires internet.

**Q: Can I run this on a Raspberry Pi?**
A: Yes, but performance may be limited for high-resolution videos.

### Troubleshooting Questions

**Q: Why does my video keep buffering?**
A: Usually network speed or server performance. Try increasing thread count or reducing video quality.

**Q: Browser says "Format not supported"?**
A: Convert videos to MP4 format for best browser compatibility.

**Q: Why can't I access remotely but local works?**
A: Check port forwarding configuration and firewall settings.

**Q: Server stops working after computer sleep?**
A: Set computer to never sleep or use a service manager (see deployment guide).

### Performance Questions

**Q: How many concurrent users can it handle?**
A: Depends on your hardware and network. Start with 6 threads, increase as needed.

**Q: Does it transcode videos?**
A: No, it serves original files. Pre-convert videos to web-compatible formats.

**Q: Can I cache videos for faster access?**
A: The server implements HTTP caching. Browsers will cache viewed portions automatically.

**Q: How do I optimize for mobile users?**
A: Use MP4 format, reasonable bitrates (5-10 Mbps), and ensure good upload speed.

---

For additional help, consult the [API Documentation](api_documentation.md) and [Deployment Guide](deployment_guide.md).

Need more help? Check the application logs and create an issue with detailed information about your problem.
