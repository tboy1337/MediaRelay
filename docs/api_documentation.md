# MediaRelay - API Documentation

## Overview

This document provides comprehensive API documentation for the Video Streaming Server, including all endpoints, authentication requirements, request/response formats, and usage examples.

## Base URL

```
http://localhost:5000
https://your-domain.com  (with SSL)
```

## Authentication

The API uses HTTP Basic Authentication for all protected endpoints.

### Authentication Methods

1. **HTTP Basic Authentication**
   - Username and password sent in Authorization header
   - Base64 encoded: `Basic base64(username:password)`

2. **Session-based Authentication**
   - After successful HTTP Basic Auth, session cookies are set
   - Subsequent requests can use session cookies
   - Sessions expire after configured timeout (default: 1 hour)

### Authentication Headers

```http
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

### Session Management

Sessions are automatically created upon successful authentication and include:
- `authenticated`: Boolean flag
- `username`: Authenticated username
- `last_activity`: Timestamp of last activity
- Automatic timeout after inactivity

## Endpoints

### 1. Health Check

Check server health and status.

**Endpoint**: `GET /health`
**Authentication**: None required
**Rate Limit**: Not limited

#### Request
```http
GET /health HTTP/1.1
Host: localhost:5000
```

#### Response
```json
{
    "status": "healthy",
    "timestamp": "2023-12-01T12:00:00.000Z",
    "version": "2.0.0",
    "uptime_seconds": 3600,
    "video_directory_accessible": true,
    "config_valid": true
}
```

#### Status Codes
- `200 OK`: Server is healthy
- `503 Service Unavailable`: Server has issues

#### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| status | string | "healthy", "degraded", or "unhealthy" |
| timestamp | string | ISO 8601 timestamp |
| version | string | Application version |
| uptime_seconds | number | Server uptime in seconds |
| video_directory_accessible | boolean | Whether video directory is accessible |
| config_valid | boolean | Whether configuration is valid |

### 2. Directory Listing

Browse directories and files in the video library.

**Endpoint**: `GET /` or `GET /<path:subpath>`
**Authentication**: Required
**Rate Limit**: 60 requests/minute

#### Request
```http
GET / HTTP/1.1
Host: localhost:5000
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

#### Response (HTML)
Returns an HTML page with:
- Directory breadcrumb navigation
- List of folders and video files
- Video player for individual files
- Responsive design for mobile/desktop

#### URL Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| subpath | string | Optional path to subdirectory |

#### Examples
```http
GET /                    # Root directory
GET /movies             # Movies subdirectory
GET /tv_shows/series1   # Nested subdirectory
GET /video.mp4          # Individual video file (shows player)
```

#### Status Codes
- `200 OK`: Directory listing or video player page
- `400 Bad Request`: Invalid file type for video player
- `401 Unauthorized`: Authentication required
- `404 Not Found`: Path does not exist

### 3. Video Streaming

Stream video files with range request support.

**Endpoint**: `GET /stream/<path:video_path>`
**Authentication**: Required
**Rate Limit**: 60 requests/minute

#### Request
```http
GET /stream/movies/action/video.mp4 HTTP/1.1
Host: localhost:5000
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
Range: bytes=0-1023
```

#### Response
Returns video file content with appropriate headers for streaming.

#### Headers
```http
Content-Type: video/mp4
Content-Length: 1024
Content-Range: bytes 0-1023/1048576
Accept-Ranges: bytes
```

#### Status Codes
- `200 OK`: Full file content
- `206 Partial Content`: Range request fulfilled
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: File type not allowed
- `404 Not Found`: File does not exist
- `416 Range Not Satisfiable`: Invalid range request

#### Supported File Types
- Video: .mp4, .mkv, .avi, .mov, .webm, .m4v, .flv
- Subtitles: .srt
- Audio: .mp3, .aac, .ogg, .wav

### 4. Files API

RESTful API for file and directory information.

**Endpoint**: `GET /api/files`
**Authentication**: Required
**Rate Limit**: 60 requests/minute

#### Request
```http
GET /api/files?path=movies HTTP/1.1
Host: localhost:5000
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
Accept: application/json
```

#### Query Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| path | string | Optional directory path (default: root) |

#### Response
```json
{
    "files": [
        {
            "name": "action",
            "path": "movies/action",
            "is_directory": true,
            "size": 0,
            "modified": "2023-12-01T12:00:00"
        },
        {
            "name": "comedy.mp4",
            "path": "movies/comedy.mp4",
            "is_directory": false,
            "size": 1048576000,
            "modified": "2023-12-01T11:30:00"
        }
    ],
    "path": "movies",
    "total_files": 2
}
```

#### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| files | array | Array of file/directory objects |
| files[].name | string | File or directory name |
| files[].path | string | Relative path from video root |
| files[].is_directory | boolean | Whether item is a directory |
| files[].size | number | File size in bytes (0 for directories) |
| files[].modified | string | ISO 8601 modified timestamp |
| path | string | Current directory path |
| total_files | number | Total number of items |

#### Status Codes
- `200 OK`: File listing retrieved
- `400 Bad Request`: Path is not a directory
- `401 Unauthorized`: Authentication required
- `404 Not Found`: Path does not exist

## Error Responses

All API endpoints return consistent error responses.

### Error Format
```json
{
    "error": "Error description",
    "code": "ERROR_CODE",
    "timestamp": "2023-12-01T12:00:00.000Z"
}
```

### Common Error Codes

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | BAD_REQUEST | Invalid request parameters |
| 401 | UNAUTHORIZED | Authentication required |
| 403 | FORBIDDEN | Access denied |
| 404 | NOT_FOUND | Resource not found |
| 413 | PAYLOAD_TOO_LARGE | Request entity too large |
| 429 | RATE_LIMIT_EXCEEDED | Too many requests |
| 500 | INTERNAL_ERROR | Server error |

## Rate Limiting

The API implements rate limiting to prevent abuse.

### Default Limits
- **General endpoints**: 60 requests per minute per IP
- **Health endpoint**: Unlimited
- **Streaming endpoints**: 60 requests per minute per IP

### Rate Limit Headers
```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1638360000
```

### Rate Limit Exceeded Response
```json
{
    "error": "Rate limit exceeded",
    "code": "RATE_LIMIT_EXCEEDED",
    "retry_after": 60
}
```

## Security Headers

All API responses include security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; media-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## Request/Response Examples

### 1. Authentication Flow

#### Initial Request (Unauthorized)
```http
GET / HTTP/1.1
Host: localhost:5000
```

#### Response
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Video Streaming Server"
Content-Type: text/plain

Authentication Required
```

#### Authenticated Request
```http
GET / HTTP/1.1
Host: localhost:5000
Authorization: Basic dGJveTEzMzc6bXlwYXNzd29yZA==
```

#### Successful Response
```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: session=...; HttpOnly; SameSite=Lax

<!DOCTYPE html>
<html>...
```

### 2. Directory Navigation

#### List Root Directory
```bash
curl -u username:password http://localhost:5000/api/files
```

```json
{
    "files": [
        {
            "name": "movies",
            "path": "movies",
            "is_directory": true,
            "size": 0,
            "modified": "2023-12-01T12:00:00"
        },
        {
            "name": "intro.mp4",
            "path": "intro.mp4",
            "is_directory": false,
            "size": 52428800,
            "modified": "2023-12-01T11:45:00"
        }
    ],
    "path": "",
    "total_files": 2
}
```

#### Navigate to Subdirectory
```bash
curl -u username:password http://localhost:5000/api/files?path=movies
```

### 3. Video Streaming

#### Stream Video File
```bash
curl -u username:password http://localhost:5000/stream/intro.mp4 \
     -H "Range: bytes=0-1023" \
     -o video_chunk.mp4
```

#### Response Headers
```http
HTTP/1.1 206 Partial Content
Content-Type: video/mp4
Content-Length: 1024
Content-Range: bytes 0-1023/52428800
Accept-Ranges: bytes
```

### 4. Health Monitoring

#### Check Server Health
```bash
curl http://localhost:5000/health
```

```json
{
    "status": "healthy",
    "timestamp": "2023-12-01T12:00:00.000Z",
    "version": "2.0.0",
    "uptime_seconds": 7200,
    "video_directory_accessible": true,
    "config_valid": true
}
```

## Client Libraries

### Python Example
```python
import requests
from requests.auth import HTTPBasicAuth

# Setup authentication
auth = HTTPBasicAuth('username', 'password')
base_url = 'http://localhost:5000'

# Get file listing
response = requests.get(f'{base_url}/api/files', auth=auth)
files = response.json()

# Stream video
video_response = requests.get(
    f'{base_url}/stream/video.mp4', 
    auth=auth,
    stream=True
)

with open('downloaded_video.mp4', 'wb') as f:
    for chunk in video_response.iter_content(chunk_size=8192):
        f.write(chunk)
```

### JavaScript Example
```javascript
// Setup authentication
const credentials = btoa('username:password');
const headers = {
    'Authorization': `Basic ${credentials}`,
    'Accept': 'application/json'
};

// Get file listing
fetch('/api/files', { headers })
    .then(response => response.json())
    .then(data => console.log(data));

// Stream video in HTML5 video element
const video = document.createElement('video');
video.src = '/stream/video.mp4';
video.controls = true;
document.body.appendChild(video);
```

### cURL Examples

#### Basic Operations
```bash
# Health check
curl http://localhost:5000/health

# Authenticated file listing
curl -u username:password http://localhost:5000/api/files

# Stream video with range request
curl -u username:password \
     -H "Range: bytes=0-1023" \
     http://localhost:5000/stream/video.mp4

# Get directory listing as HTML
curl -u username:password http://localhost:5000/movies/
```

## WebSocket Support

Currently not implemented. Future versions may include WebSocket support for:
- Real-time notifications
- Live streaming status
- Progress tracking

## API Versioning

Current API version: **v1** (implicit)
Future versions will be explicitly versioned: `/api/v2/files`

## Performance Considerations

### Caching
- Static assets are cached appropriately
- Video files support HTTP caching headers
- Directory listings are not cached (real-time)

### Streaming Optimization
- Range requests supported for efficient streaming
- Chunked transfer encoding for large files
- Appropriate MIME types set for all content

### Rate Limiting
- Implement client-side request throttling
- Use session cookies to reduce authentication overhead
- Consider connection pooling for multiple requests

## Security Considerations

### Authentication
- Always use HTTPS in production
- Implement strong password policies
- Consider IP whitelisting for sensitive deployments

### Input Validation
- All paths are validated against directory traversal
- File types are validated before serving
- Query parameters are sanitized

### Security Monitoring
- All authentication attempts are logged
- Security violations are logged with details
- Failed requests are monitored and logged

## Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Verify credentials are correct
   - Check password hash configuration
   - Ensure Authorization header format is correct

2. **404 Not Found**
   - Verify file/directory exists
   - Check path formatting (use forward slashes)
   - Ensure video directory is properly configured

3. **403 Forbidden**
   - Check file type is supported
   - Verify file permissions
   - Review security logs for violations

4. **429 Rate Limited**
   - Reduce request frequency
   - Implement client-side rate limiting
   - Check rate limit headers

### Debug Headers

Enable debug headers by setting `VIDEO_SERVER_DEBUG=true`:
```http
X-Debug-Request-ID: abc123
X-Debug-Processing-Time: 0.045
X-Debug-User: username
```

For more troubleshooting information, see the deployment guide and user manual.
