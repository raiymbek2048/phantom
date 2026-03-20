"""Helper to get Claude API key with automatic OAuth token refresh.

Priority:
1. Redis (UI-configured sk-ant-api key)
2. Redis OAuth token (auto-refreshed from refresh_token)
3. .env fallback

Auto-refresh: When access_token expires, uses refresh_token to get a new one.
Refresh token is rotated on each use (Anthropic OAuth2 rotation policy).
"""
import json
import logging
import time

logger = logging.getLogger(__name__)

REDIS_KEY = "phantom:settings:anthropic_api_key"
REDIS_OAUTH_KEY = "phantom:settings:claude_oauth_token"
REDIS_REFRESH_KEY = "phantom:settings:claude_refresh_token"
REDIS_TOKEN_EXPIRES_KEY = "phantom:settings:claude_token_expires_at"

OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"


def _get_redis():
    """Get Redis connection."""
    import redis as redis_lib
    from app.config import get_settings
    settings = get_settings()
    return redis_lib.from_url(settings.redis_url)


def _refresh_oauth_token() -> str | None:
    """Use refresh_token to get a new access_token from Anthropic.

    Returns new access_token or None on failure.
    Also stores the new refresh_token (rotation).
    """
    try:
        r = _get_redis()
        refresh_token = r.get(REDIS_REFRESH_KEY)
        if not refresh_token:
            return None
        refresh_token = refresh_token.decode() if isinstance(refresh_token, bytes) else refresh_token
        if not refresh_token.startswith("sk-ant-ort"):
            return None

        import httpx
        resp = httpx.post(
            OAUTH_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": OAUTH_CLIENT_ID,
            },
            timeout=15.0,
        )

        if resp.status_code != 200:
            logger.warning(f"OAuth refresh failed: {resp.status_code} {resp.text[:200]}")
            return None

        data = resp.json()
        new_access = data.get("access_token")
        new_refresh = data.get("refresh_token")
        expires_in = data.get("expires_in", 28800)

        if not new_access:
            logger.warning("OAuth refresh returned no access_token")
            return None

        # Store new tokens in Redis
        r.set(REDIS_OAUTH_KEY, new_access)
        if new_refresh:
            r.set(REDIS_REFRESH_KEY, new_refresh)
        r.set(REDIS_TOKEN_EXPIRES_KEY, str(int(time.time()) + expires_in))

        logger.info(
            f"OAuth token refreshed: {new_access[:20]}... "
            f"expires in {expires_in}s ({expires_in // 3600}h)"
        )
        return new_access

    except Exception as e:
        logger.error(f"OAuth refresh error: {e}")
        return None


def _is_token_expired() -> bool:
    """Check if the current OAuth token is expired or about to expire (5 min buffer)."""
    try:
        r = _get_redis()
        expires_at = r.get(REDIS_TOKEN_EXPIRES_KEY)
        if not expires_at:
            return False  # No expiry tracked = assume valid
        expires_at = int(expires_at.decode() if isinstance(expires_at, bytes) else expires_at)
        return time.time() > (expires_at - 300)  # 5 min buffer
    except Exception:
        return False


def get_claude_api_key() -> str | None:
    """Get Claude API key. Priority: Redis API key > Redis OAuth (auto-refresh) > .env"""
    try:
        r = _get_redis()

        # 1. UI-configured API key (never expires)
        key = r.get(REDIS_KEY)
        if key:
            key = key.decode() if isinstance(key, bytes) else key
            if key.startswith("sk-ant-") and not key.startswith("sk-ant-oat"):
                return key

        # 2. OAuth token with auto-refresh
        oauth = r.get(REDIS_OAUTH_KEY)
        if oauth:
            oauth = oauth.decode() if isinstance(oauth, bytes) else oauth
            if oauth.startswith("sk-ant-oat"):
                # Check if expired → auto-refresh
                if _is_token_expired():
                    logger.info("OAuth token expired, refreshing...")
                    new_token = _refresh_oauth_token()
                    if new_token:
                        return new_token
                    # Refresh failed — try existing token anyway (maybe still valid)
                return oauth

        # 3. No OAuth token but have refresh_token → bootstrap
        refresh = r.get(REDIS_REFRESH_KEY)
        if refresh:
            refresh = (refresh.decode() if isinstance(refresh, bytes) else refresh)
            if refresh.startswith("sk-ant-ort"):
                logger.info("No access token but refresh token exists, bootstrapping...")
                new_token = _refresh_oauth_token()
                if new_token:
                    return new_token

    except Exception as e:
        logger.debug(f"Redis key lookup failed: {e}")

    # 4. Fallback to .env
    try:
        from app.config import get_settings
        settings = get_settings()
        if settings.anthropic_api_key and not settings.anthropic_api_key.startswith("your_"):
            return settings.anthropic_api_key
    except Exception:
        pass

    return None


def seed_refresh_token(refresh_token: str) -> bool:
    """Seed the server with a refresh token (one-time setup).

    Call this once with the refresh_token from `claude login`.
    After that, PHANTOM will auto-refresh forever.
    """
    if not refresh_token.startswith("sk-ant-ort"):
        logger.error("Invalid refresh token format (expected sk-ant-ort...)")
        return False
    try:
        r = _get_redis()
        r.set(REDIS_REFRESH_KEY, refresh_token)
        # Immediately get an access token
        new_token = _refresh_oauth_token()
        if new_token:
            logger.info("Refresh token seeded and first access token obtained")
            return True
        else:
            logger.error("Refresh token seeded but initial refresh failed")
            return False
    except Exception as e:
        logger.error(f"Failed to seed refresh token: {e}")
        return False


def is_oauth_token(key: str | None) -> bool:
    """Check if key is an OAuth token (needs Bearer auth, not x-api-key)."""
    return bool(key and key.startswith("sk-ant-oat"))


def make_anthropic_client(sync: bool = False):
    """Create an Anthropic client with correct auth (OAuth Bearer or API key).

    Returns anthropic.AsyncAnthropic (default) or anthropic.Anthropic (sync=True).
    Returns None if no key available.
    """
    import anthropic

    key = get_claude_api_key()
    if not key or key.startswith("your_"):
        return None

    if is_oauth_token(key):
        cls = anthropic.Anthropic if sync else anthropic.AsyncAnthropic
        return cls(
            api_key="sk-ant-dummy00000000000000000000000000000000000000000000",
            default_headers={
                "Authorization": f"Bearer {key}",
                "anthropic-beta": "oauth-2025-04-20",
                "X-Api-Key": "",
            },
        )
    else:
        cls = anthropic.Anthropic if sync else anthropic.AsyncAnthropic
        return cls(api_key=key)


def get_key_source() -> str | None:
    """Return the source of the current key: 'redis', 'max_subscription', 'env', or None."""
    try:
        r = _get_redis()

        key = r.get(REDIS_KEY)
        if key:
            key = key.decode() if isinstance(key, bytes) else key
            if key.startswith("sk-ant-oat"):
                return "max_subscription"
            if key.startswith("sk-ant-"):
                return "redis"

        oauth = r.get(REDIS_OAUTH_KEY)
        if oauth:
            oauth = oauth.decode() if isinstance(oauth, bytes) else oauth
            if oauth.startswith("sk-ant-oat"):
                return "max_subscription"

    except Exception:
        pass

    try:
        from app.config import get_settings
        settings = get_settings()
        if settings.anthropic_api_key and not settings.anthropic_api_key.startswith("your_"):
            return "env"
    except Exception:
        pass

    return None


def get_token_status() -> dict:
    """Get current token status for diagnostics."""
    try:
        r = _get_redis()
        access = r.get(REDIS_OAUTH_KEY)
        refresh = r.get(REDIS_REFRESH_KEY)
        expires = r.get(REDIS_TOKEN_EXPIRES_KEY)

        access = access.decode() if access and isinstance(access, bytes) else access
        refresh = refresh.decode() if refresh and isinstance(refresh, bytes) else refresh
        expires = int(expires.decode() if expires and isinstance(expires, bytes) else expires or 0)

        now = int(time.time())
        return {
            "has_access_token": bool(access and access.startswith("sk-ant-oat")),
            "has_refresh_token": bool(refresh and refresh.startswith("sk-ant-ort")),
            "access_token_prefix": access[:20] + "..." if access else None,
            "expires_at": expires,
            "expires_in_seconds": max(0, expires - now) if expires else None,
            "expires_in_hours": round(max(0, expires - now) / 3600, 1) if expires else None,
            "is_expired": now > expires if expires else None,
            "source": get_key_source(),
        }
    except Exception as e:
        return {"error": str(e)}
