"""
Shared HTTP client factory for all PHANTOM modules.

Centralizes proxy, custom headers, timeout, and User-Agent rotation
so every module uses consistent settings.
"""
import random
import httpx

# Realistic User-Agent pool — rotated per client creation
USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
    # Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Brave/122",
]


def get_random_ua() -> str:
    """Return a random User-Agent string."""
    return random.choice(USER_AGENTS)


# Module-level defaults (set by pipeline at scan start)
_scan_config = {
    "custom_headers": {},
    "proxy_url": "",
    "timeout": 10.0,
}


def configure(custom_headers: dict = None, proxy_url: str = "", timeout: float = 10.0):
    """Configure shared HTTP settings for the current scan."""
    _scan_config["custom_headers"] = custom_headers or {}
    _scan_config["proxy_url"] = proxy_url
    _scan_config["timeout"] = timeout


def make_client(
    extra_headers: dict = None,
    timeout: float = None,
    follow_redirects: bool = True,
    verify: bool = False,
    **kwargs,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with scan-wide config applied.

    Merges custom_headers, proxy, and timeout from scan config.
    Extra headers override scan-wide headers.
    """
    headers = dict(_scan_config["custom_headers"])
    # Inject random User-Agent if not explicitly set
    if "User-Agent" not in headers:
        headers["User-Agent"] = get_random_ua()
    if extra_headers:
        headers.update(extra_headers)

    proxy = _scan_config["proxy_url"] or kwargs.pop("proxy", None)

    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout or _scan_config["timeout"],
        verify=verify,
        follow_redirects=follow_redirects,
        proxy=proxy or None,
        **kwargs,
    )


def get_custom_headers() -> dict:
    """Get current scan custom headers (for CLI tools -H flags)."""
    return dict(_scan_config["custom_headers"])


def get_proxy_url() -> str:
    """Get current proxy URL (for CLI tools --proxy flags)."""
    return _scan_config["proxy_url"]
