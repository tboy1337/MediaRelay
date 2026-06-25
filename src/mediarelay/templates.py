"""HTML templates for the MediaRelay web UI."""

INDEX_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% if video_file %}{{ video_file }} - {% endif %}Video Streaming Server</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: rgba(255, 255, 255, 0.95);
            min-height: 100vh;
            box-shadow: 0 0 50px rgba(0,0,0,0.1);
        }

        .header {
            background: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .breadcrumb {
            background: #f8f9fa;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #007bff;
        }

        .breadcrumb a {
            color: #007bff;
            text-decoration: none;
            font-weight: 500;
        }

        .breadcrumb a:hover {
            text-decoration: underline;
        }

        .video-player {
            background: #000;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 20px;
        }

        video {
            width: 100%;
            height: auto;
            display: block;
        }

        .file-list {
            list-style: none;
            background: #fff;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .file-item {
            display: flex;
            align-items: center;
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            transition: all 0.3s ease;
            text-decoration: none;
            color: inherit;
        }

        .file-item:hover {
            background: #f8f9fa;
            transform: translateX(5px);
        }

        .file-item:last-child {
            border-bottom: none;
        }

        .file-icon {
            font-size: 1.5em;
            margin-right: 15px;
            min-width: 30px;
        }

        .file-info {
            flex: 1;
        }

        .file-name {
            font-weight: 500;
            color: #2c3e50;
            margin-bottom: 5px;
        }

        .file-meta {
            font-size: 0.9em;
            color: #6c757d;
        }

        .folder {
            color: #ffa500;
        }

        .video-file {
            color: #28a745;
        }

        .back-link {
            display: inline-flex;
            align-items: center;
            padding: 10px 20px;
            background: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin-bottom: 20px;
            transition: background 0.3s ease;
        }

        .back-link:hover {
            background: #0056b3;
            color: white;
        }

        .stats {
            background: #e9ecef;
            padding: 10px 20px;
            border-radius: 5px;
            margin-top: 20px;
            font-size: 0.9em;
            color: #6c757d;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header h1 {
                font-size: 1.8em;
            }

            .file-item {
                padding: 12px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        {% if video_file %}
            <div class="header">
                <a href="{{ parent_path }}" class="back-link">&larr; Back to directory</a>
                <h1>{{ video_file }}</h1>
            </div>

            <div class="video-player">
                <video controls preload="metadata">
                    <source src="/stream/{{ video_path }}" type="{{ video_mime_type }}">
                    Your browser does not support the video tag.
                </video>
            </div>
        {% else %}
            <div class="header">
                <h1>Video Streaming Server</h1>
                <p>Browse and stream your video library</p>
            </div>

            <div class="breadcrumb">
                {% for crumb in breadcrumbs %}
                    {% if not loop.last %}
                        <a href="{{ crumb.path }}">{{ crumb.name }}</a> /
                    {% else %}
                        <strong>{{ crumb.name }}</strong>
                    {% endif %}
                {% endfor %}
            </div>

            <ul class="file-list">
                {% if not is_root %}
                    <li>
                        <a href="{{ parent_path }}" class="file-item">
                            <span class="file-icon folder">&#x1F4C1;</span>
                            <div class="file-info">
                                <div class="file-name">.. (Up to parent directory)</div>
                            </div>
                        </a>
                    </li>
                {% endif %}

                {% for item in items %}
                    <li>
                        <a href="{{ item.path }}" class="file-item">
                            <span class="file-icon {% if item.is_dir %}folder{% else %}video-file{% endif %}">
                                {% if item.is_dir %}&#x1F4C1;{% else %}&#x1F3AC;{% endif %}
                            </span>
                            <div class="file-info">
                                <div class="file-name">{{ item.name }}</div>
                                <div class="file-meta">
                                    {% if not item.is_dir %}
                                        Size: {{ "%.1f"|format(item.size / 1024 / 1024) }} MB |
                                    {% endif %}
                                    Modified: {{ item.modified[:16].replace('T', ' ') }}
                                </div>
                            </div>
                        </a>
                    </li>
                {% endfor %}
            </ul>

            <div class="stats">
                Total items: {{ items|length }} |
                Folders: {{ items|selectattr('is_dir')|list|length }} |
                Files: {{ items|rejectattr('is_dir')|list|length }}
            </div>
        {% endif %}
    </div>
</body>
</html>
"""
