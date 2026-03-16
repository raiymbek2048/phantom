"""URL utility functions for filtering and classifying endpoints."""

from urllib.parse import urlparse

STATIC_EXTENSIONS = frozenset({
    ".js", ".mjs", ".css", ".less", ".scss",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".mp4", ".webm", ".mp3", ".ogg",
    ".pdf", ".zip", ".gz", ".tar", ".rar",
})

NON_INJECTABLE_PATHS = (
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/.well-known/", "/manifest.json",
)

STATIC_DIRS = (
    "/resources/", "/assets/", "/static/", "/images/", "/img/",
    "/fonts/", "/media/", "/dist/", "/vendor/", "/node_modules/",
    "/wp-content/uploads/", "/wp-includes/",
)

NON_TRANSACTIONAL_PATHS = (
    "/blog/", "/careers/", "/about", "/contact", "/jobs/",
    "/team/", "/press/", "/faq/", "/help/", "/support/",
    "/feedback", "/newsletter", "/privacy", "/terms",
    "/disclaimer", "/legal/",
)


def is_static_url(url: str) -> bool:
    """Check if URL points to a static asset (JS, CSS, images, fonts, etc.)."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    # Check extension
    dot_idx = path.rfind(".")
    if dot_idx != -1:
        ext = path[dot_idx:]
        if ext in STATIC_EXTENSIONS:
            return True
    # Check known static paths
    if any(path == p or path.startswith(p) for p in NON_INJECTABLE_PATHS):
        return True
    # Check static directories
    if any(d in path for d in STATIC_DIRS):
        return True
    return False


def is_transactional_url(url: str) -> bool:
    """Check if URL is likely a transactional/business endpoint (not informational)."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    if is_static_url(url):
        return False
    if any(p in path for p in NON_TRANSACTIONAL_PATHS):
        return False
    return True


def has_injectable_pattern(url: str) -> bool:
    """Check if URL has patterns suggesting server-side processing with user input."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        has_params = bool(parsed.query)
    except Exception:
        return False

    injectable_patterns = (
        "/search", "/login", "/signin", "/signup", "/register",
        "/comment", "/transfer", "/account", "/profile",
        "/edit", "/update", "/query", "/lookup", "/find",
        "/filter", "/sort", "/bank", "/process", "/submit",
        "/doLogin", "/do_login",
    )

    injectable_extensions = (".jsp", ".asp", ".aspx", ".php", ".do", ".action")

    if has_params:
        return True
    if any(p in path for p in injectable_patterns):
        return True
    if any(path.endswith(ext) for ext in injectable_extensions):
        return True
    # Path ends with numeric segment like /products/123
    segments = [s for s in path.split("/") if s]
    if segments and segments[-1].isdigit():
        return True
    return False
