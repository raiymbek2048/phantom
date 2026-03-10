"""SPA (Single Page Application) shell detector.

Detects when an HTTP response is just a frontend HTML shell
(React, Vue, Angular, etc.) rather than actual data.
This prevents false positives where /admin returns index.html
but the actual admin API is protected.
"""
import re

# Indicators that response is an SPA shell, not real data
SPA_INDICATORS = [
    # React
    r'<div\s+id=["\'](?:root|app|__next)["\']',
    r'<script\s+src=["\'][^"\']*(?:bundle|main|app|chunk|vendor)\.[a-f0-9]+\.js',
    r'__NEXT_DATA__',
    r'_app-[a-f0-9]+\.js',
    # Vue
    r'<div\s+id=["\']app["\']',
    r'vue\.(?:runtime|global)',
    # Angular
    r'<app-root',
    r'ng-version=',
    r'angular\.(?:min\.)?js',
    # Generic SPA markers
    r'<noscript>.*(?:enable javascript|requires javascript)',
    r'<script\s+type=["\']module["\']',
    r'manifest\.json',
    r'serviceWorker',
]

_SPA_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in SPA_INDICATORS]

# Indicators that response contains REAL data (not just HTML shell)
REAL_DATA_INDICATORS = [
    # Personal data
    r'"(?:email|phone|address|name|username|password|balance|amount|credit_card)":\s*"[^"]+',
    # Lists of records
    r'\[\s*\{[^}]*"id"',
    # Error messages with real info
    r'"(?:error|message)":\s*"(?!Not Found|Unauthorized|Forbidden)',
    # Table data
    r'<table[^>]*>.*?<td[^>]*>.*?</td>',
]

_REAL_DATA_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in REAL_DATA_INDICATORS]


def is_spa_shell(body: str, content_type: str = "") -> bool:
    """Check if response body is an SPA HTML shell.

    Returns True if the response is just a frontend shell
    (React/Vue/Angular) that doesn't contain real data.
    """
    if not body or len(body) < 50:
        return False

    # JSON responses are never SPA shells
    if "application/json" in content_type:
        return False

    # Must be HTML-like
    if not ("text/html" in content_type or body.strip().startswith(("<!DOCTYPE", "<html", "<!doctype"))):
        return False

    # Check for SPA indicators
    spa_score = 0
    for pattern in _SPA_PATTERNS:
        if pattern.search(body[:5000]):  # Only check first 5KB
            spa_score += 1

    if spa_score == 0:
        return False

    # Check if there's REAL data despite being SPA
    for pattern in _REAL_DATA_PATTERNS:
        if pattern.search(body):
            return False  # Has real data, not just a shell

    # SPA shell: has SPA indicators but no real data
    # If HTML is mostly script tags and minimal content, it's a shell
    text_content = re.sub(r'<script[^>]*>.*?</script>', '', body, flags=re.DOTALL | re.IGNORECASE)
    text_content = re.sub(r'<[^>]+>', '', text_content).strip()

    # If actual text content is very small compared to total body, it's a shell
    if len(text_content) < 200 and len(body) > 500:
        return True

    # Multiple SPA indicators = definitely a shell
    if spa_score >= 2:
        return True

    return False


def is_real_data_response(body: str, content_type: str = "") -> bool:
    """Check if response contains real/sensitive data.

    Returns True if the response has actual data that would
    constitute a real vulnerability if exposed.
    """
    if not body:
        return False

    # JSON with data is always real
    if "application/json" in content_type:
        body_stripped = body.strip()
        if body_stripped.startswith(("{", "[")):
            # Check it's not just an error
            if any(p.search(body) for p in _REAL_DATA_PATTERNS):
                return True
            # JSON with more than just status/message
            if len(body_stripped) > 100 and '"id"' in body:
                return True
        return False

    # HTML with real data patterns
    for pattern in _REAL_DATA_PATTERNS:
        if pattern.search(body):
            return True

    return False


def is_static_asset(url: str) -> bool:
    """Check if URL points to a static asset that shouldn't be vuln-tested."""
    from urllib.parse import urlparse
    path = urlparse(url).path.lower()
    static_exts = (
        '.js', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.ico', '.woff', '.woff2', '.ttf', '.eot', '.webp', '.avif',
        '.mp3', '.mp4', '.webm', '.pdf', '.zip', '.tar', '.gz',
    )
    return path.endswith(static_exts) or '/assets/' in path or '/static/' in path or '/dist/' in path
