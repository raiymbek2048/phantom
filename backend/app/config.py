from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # App
    app_name: str = "PHANTOM"
    debug: bool = False

    # Database
    database_url: str = "postgresql+asyncpg://phantom:change_me_in_production@db:5432/phantom"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Auth
    secret_key: str = "change_me_to_random_64_char_string"
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 1440

    # AI - Claude (primary)
    anthropic_api_key: str = ""
    claude_model: str = "claude-haiku-4-5-20251001"

    # AI - Fallback LLMs (used when Claude unavailable)
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    openai_base_url: str = "https://api.openai.com/v1"

    # HackerOne
    hackerone_username: str = ""
    hackerone_api_token: str = ""

    # Scanning
    max_concurrent_scans: int = 20
    max_requests_per_second: int = 10
    scan_timeout_minutes: int = 120

    # VPN / Proxy
    vpn_enabled: bool = False
    proxy_url: str = ""

    # External APIs
    shodan_api_key: str = ""
    securitytrails_api_key: str = ""

    model_config = {"env_file": ".env", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
