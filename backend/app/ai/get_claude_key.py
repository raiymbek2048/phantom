"""Helper to get Claude API key.

Priority:
1. Redis (UI-configured sk-ant-api key)
2. Redis OAuth token (synced from Claude Code Max subscription via host)
3. .env fallback
"""
import logging

logger = logging.getLogger(__name__)

REDIS_KEY = "phantom:settings:anthropic_api_key"
REDIS_OAUTH_KEY = "phantom:settings:claude_oauth_token"


def get_claude_api_key() -> str | None:
    """Get Claude API key. Priority: Redis API key > Redis OAuth > .env"""
    try:
        import redis as redis_lib
        from app.config import get_settings
        settings = get_settings()
        r = redis_lib.from_url(settings.redis_url)

        # 1. UI-configured API key
        key = r.get(REDIS_KEY)
        if key:
            key = key.decode() if isinstance(key, bytes) else key
            if key.startswith("sk-ant-"):
                return key

        # 2. OAuth token synced from host Keychain
        oauth = r.get(REDIS_OAUTH_KEY)
        if oauth:
            oauth = oauth.decode() if isinstance(oauth, bytes) else oauth
            if oauth.startswith("sk-ant-oat"):
                return oauth

    except Exception as e:
        logger.debug(f"Redis key lookup failed: {e}")

    # 3. Fallback to .env
    try:
        from app.config import get_settings
        settings = get_settings()
        if settings.anthropic_api_key and not settings.anthropic_api_key.startswith("your_"):
            return settings.anthropic_api_key
    except Exception:
        pass

    return None


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
        # OAuth tokens need Bearer auth + beta header, not x-api-key.
        # SDK always sends X-Api-Key from api_key param; we override it
        # in default_headers and provide a dummy api_key to prevent
        # the SDK from reading ANTHROPIC_API_KEY from env.
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
        import redis as redis_lib
        from app.config import get_settings
        settings = get_settings()
        r = redis_lib.from_url(settings.redis_url)

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
