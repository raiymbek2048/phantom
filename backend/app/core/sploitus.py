"""
Sploitus API Client — Search real CVE exploits and tools.

Used by Attack Planner to find real exploits for discovered technologies.
Results are cached in Redis for 24 hours.
"""
import json
import logging
from typing import Optional

import httpx
import redis as redis_lib

from app.config import get_settings

logger = logging.getLogger(__name__)

SPLOITUS_URL = "https://sploitus.com/search"
CACHE_TTL = 86400  # 24 hours
CACHE_PREFIX = "phantom:sploitus:"


def _get_redis():
    return redis_lib.from_url(get_settings().redis_url, decode_responses=True)


def _cache_key(query: str, result_type: str) -> str:
    safe = query.lower().strip().replace(" ", "_")[:80]
    return f"{CACHE_PREFIX}{result_type}:{safe}"


def _get_cached(key: str) -> Optional[list]:
    try:
        r = _get_redis()
        raw = r.get(key)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


def _set_cached(key: str, data: list):
    try:
        r = _get_redis()
        r.setex(key, CACHE_TTL, json.dumps(data))
    except Exception as e:
        logger.warning("sploitus cache write failed: %s", e)


def _parse_results(raw_items: list) -> list[dict]:
    """Normalize sploitus response items into clean dicts."""
    results = []
    for item in raw_items:
        results.append({
            "title": item.get("title", ""),
            "cve": item.get("cve") or _extract_cve(item.get("title", "")),
            "source_url": item.get("href", ""),
            "description": (item.get("body") or "")[:500],
            "type": item.get("type", "exploits"),
            "score": item.get("score"),
            "published": item.get("published"),
        })
    return results


def _extract_cve(text: str) -> Optional[str]:
    """Pull CVE-YYYY-NNNNN from title if present."""
    import re
    m = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return m.group(0).upper() if m else None


async def search_exploits(
    query: str,
    max_results: int = 10,
    result_type: str = "exploits",
) -> list[dict]:
    """Search sploitus.com for exploits or tools.

    Args:
        query: Free-text search (e.g. "Apache 2.4 RCE")
        max_results: Cap on returned items (max 30)
        result_type: "exploits" or "tools"
    """
    if not query or not query.strip():
        return []

    key = _cache_key(query, result_type)
    cached = _get_cached(key)
    if cached is not None:
        logger.debug("sploitus cache hit: %s", query)
        return cached[:max_results]

    payload = {
        "type": result_type,
        "query": query.strip(),
        "offset": 0,
        "title": False,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(SPLOITUS_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        logger.warning("sploitus HTTP %s for query '%s'", e.response.status_code, query)
        return []
    except Exception as e:
        logger.warning("sploitus request failed for '%s': %s", query, e)
        return []

    raw_items = data.get("exploits") or data.get("tools") or []
    results = _parse_results(raw_items)[:max_results]

    _set_cached(key, results)
    logger.info("sploitus: %d results for '%s'", len(results), query)
    return results


async def search_by_cve(cve_id: str) -> list[dict]:
    """Search for exploits matching a specific CVE ID."""
    return await search_exploits(cve_id, max_results=10)


async def get_exploits_for_tech(
    tech_name: str,
    version: str = "",
) -> list[dict]:
    """Find exploits for a technology + version combo.

    Searches both exploits and tools, merges results.
    """
    query = f"{tech_name} {version}".strip()

    exploits = await search_exploits(query, max_results=10, result_type="exploits")
    tools = await search_exploits(query, max_results=5, result_type="tools")

    return exploits + tools
