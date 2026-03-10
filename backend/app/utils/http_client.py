"""
Shared HTTP client factory for all PHANTOM modules.

Centralizes proxy, custom headers, and timeout configuration
so every module uses consistent settings.
"""
import httpx

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
