"""
Shared HTTP client factory for all PHANTOM modules.

Centralizes proxy, custom headers, timeout, User-Agent rotation,
and adaptive rate limiting with automatic backoff on 429/503.
"""
import asyncio
import logging
import random
import time
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

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


# ─── Adaptive Rate Limiter (per-domain) ───────────────────────────────

class AdaptiveThrottler:
    """Global adaptive rate limiter that detects 429/503 and backs off per domain.

    Features:
    - Per-domain tracking (different sites have different limits)
    - Exponential backoff on 429/503 (1s → 2s → 4s → 8s → 16s max)
    - Auto-recovery: delay halves every 30s of clean requests
    - Retry-After header support
    - Circuit breaker: after 10 consecutive blocks, pause domain for 60s
    """

    def __init__(self):
        self._domain_state: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    def _get_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc or "unknown"
        except Exception:
            return "unknown"

    def _get_state(self, domain: str) -> dict:
        if domain not in self._domain_state:
            self._domain_state[domain] = {
                "delay": 0.0,          # current delay between requests (seconds)
                "consecutive_blocks": 0,  # consecutive 429/503 count
                "last_block_time": 0.0,
                "last_success_time": 0.0,
                "circuit_open_until": 0.0,  # circuit breaker timestamp
                "total_blocks": 0,
                "total_requests": 0,
            }
        return self._domain_state[domain]

    async def pre_request(self, url: str):
        """Call before making a request. Applies adaptive delay."""
        domain = self._get_domain(url)
        async with self._lock:
            state = self._get_state(domain)
            now = time.time()

            # Circuit breaker: if domain is paused, wait
            if now < state["circuit_open_until"]:
                wait = state["circuit_open_until"] - now
                logger.warning(f"Circuit breaker active for {domain}, waiting {wait:.1f}s")
                await asyncio.sleep(wait)

            # Auto-recovery: if 30s passed since last block with clean requests, halve delay
            if state["delay"] > 0 and state["last_success_time"] > state["last_block_time"]:
                time_since_block = now - state["last_block_time"]
                recovery_steps = int(time_since_block / 30)
                if recovery_steps > 0:
                    old_delay = state["delay"]
                    state["delay"] = max(0, state["delay"] / (2 ** recovery_steps))
                    if old_delay != state["delay"]:
                        logger.info(f"Rate limit recovery for {domain}: {old_delay:.1f}s → {state['delay']:.1f}s")

            # Apply current delay
            if state["delay"] > 0:
                # Add jitter (±20%) to avoid thundering herd
                jitter = state["delay"] * random.uniform(-0.2, 0.2)
                await asyncio.sleep(state["delay"] + jitter)

            state["total_requests"] += 1

    async def post_response(self, url: str, status_code: int, headers: dict = None):
        """Call after receiving a response. Adjusts rate based on status."""
        domain = self._get_domain(url)
        async with self._lock:
            state = self._get_state(domain)
            now = time.time()

            if status_code in (429, 503):
                state["consecutive_blocks"] += 1
                state["total_blocks"] += 1
                state["last_block_time"] = now

                # Check Retry-After header
                retry_after = None
                if headers:
                    ra = headers.get("retry-after") or headers.get("Retry-After")
                    if ra:
                        try:
                            retry_after = float(ra)
                        except (ValueError, TypeError):
                            pass

                if retry_after:
                    state["delay"] = min(retry_after, 30.0)
                else:
                    # Exponential backoff: 1 → 2 → 4 → 8 → 16
                    state["delay"] = min(16.0, max(1.0, state["delay"] * 2) if state["delay"] > 0 else 1.0)

                # Circuit breaker: 10 consecutive blocks → pause 60s
                if state["consecutive_blocks"] >= 10:
                    state["circuit_open_until"] = now + 60.0
                    logger.warning(
                        f"Circuit breaker OPEN for {domain}: "
                        f"{state['consecutive_blocks']} consecutive blocks, pausing 60s"
                    )
                    state["consecutive_blocks"] = 0

                logger.info(
                    f"Rate limited on {domain}: status={status_code}, "
                    f"delay now {state['delay']:.1f}s, "
                    f"blocks={state['consecutive_blocks']}"
                )

            else:
                # Success — reset consecutive counter
                state["consecutive_blocks"] = 0
                state["last_success_time"] = now

    def get_stats(self) -> dict:
        """Get rate limiting statistics per domain."""
        return {
            domain: {
                "delay": s["delay"],
                "total_blocks": s["total_blocks"],
                "total_requests": s["total_requests"],
                "block_rate": f"{s['total_blocks'] / max(1, s['total_requests']) * 100:.1f}%",
            }
            for domain, s in self._domain_state.items()
        }

    def reset(self):
        """Reset all state (call at scan start)."""
        self._domain_state.clear()


# Global throttler instance — shared across all modules in a scan
throttler = AdaptiveThrottler()


# ─── Scan Config ──────────────────────────────────────────────────────

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
    throttler.reset()


async def _on_request(request: httpx.Request):
    """Event hook: apply adaptive delay before each request."""
    await throttler.pre_request(str(request.url))


async def _on_response(response: httpx.Response):
    """Event hook: track response status for adaptive throttling."""
    headers = dict(response.headers) if response.headers else {}
    await throttler.post_response(str(response.request.url), response.status_code, headers)


def make_client(
    extra_headers: dict = None,
    timeout: float = None,
    follow_redirects: bool = True,
    verify: bool = False,
    adaptive_throttle: bool = True,
    **kwargs,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with scan-wide config applied.

    Merges custom_headers, proxy, and timeout from scan config.
    Extra headers override scan-wide headers.
    When adaptive_throttle=True, automatically applies rate limiting.
    """
    headers = dict(_scan_config["custom_headers"])
    # Inject random User-Agent if not explicitly set
    if "User-Agent" not in headers:
        headers["User-Agent"] = get_random_ua()
    if extra_headers:
        headers.update(extra_headers)

    proxy = _scan_config["proxy_url"] or kwargs.pop("proxy", None)

    # Wire up adaptive throttling via httpx event hooks
    event_hooks = {}
    if adaptive_throttle:
        event_hooks = {
            "request": [_on_request],
            "response": [_on_response],
        }

    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout or _scan_config["timeout"],
        verify=verify,
        follow_redirects=follow_redirects,
        proxy=proxy or None,
        event_hooks=event_hooks,
        **kwargs,
    )


async def smart_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_retries: int = 2,
    **kwargs,
) -> httpx.Response | None:
    """Make an HTTP request with adaptive rate limiting and retry on 429/503.

    Usage:
        async with make_client() as client:
            resp = await smart_request(client, "GET", url)
    """
    for attempt in range(max_retries + 1):
        await throttler.pre_request(url)
        try:
            resp = await getattr(client, method.lower())(url, **kwargs)
            resp_headers = dict(resp.headers) if resp.headers else {}
            await throttler.post_response(url, resp.status_code, resp_headers)

            if resp.status_code in (429, 503) and attempt < max_retries:
                continue  # retry after throttler applies backoff

            return resp
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            if attempt < max_retries:
                await asyncio.sleep(1.0 * (attempt + 1))
                continue
            logger.debug(f"Request failed after {max_retries + 1} attempts: {url} - {e}")
            return None
        except Exception as e:
            logger.debug(f"Request error: {url} - {e}")
            return None
    return None


def get_custom_headers() -> dict:
    """Get current scan custom headers (for CLI tools -H flags)."""
    return dict(_scan_config["custom_headers"])


def get_proxy_url() -> str:
    """Get current proxy URL (for CLI tools --proxy flags)."""
    return _scan_config["proxy_url"]


def get_throttle_stats() -> dict:
    """Get adaptive throttling statistics."""
    return throttler.get_stats()
