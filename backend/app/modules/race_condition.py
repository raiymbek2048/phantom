"""
Race Condition Detection Module

Tests for:
1. TOCTOU (Time-of-check to Time-of-use) — parallel requests to state-changing endpoints
2. Double-spend — concurrent payment/transfer requests
3. Limit bypass — exceed rate limits or quotas via parallel requests
4. Account creation race — duplicate account creation
"""
import asyncio
import logging
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Endpoints likely vulnerable to race conditions
RACE_KEYWORDS = {
    "payment": ("pay", "checkout", "purchase", "buy", "order", "charge", "billing"),
    "transfer": ("transfer", "send", "withdraw", "redeem", "claim"),
    "coupon": ("coupon", "promo", "discount", "voucher", "code", "apply"),
    "vote": ("vote", "like", "upvote", "rate", "review", "favorite"),
    "register": ("register", "signup", "create", "invite"),
    "delete": ("delete", "remove", "cancel"),
}


class RaceConditionModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.concurrency = 10  # Number of parallel requests

    async def check(self, context: dict, db) -> list[dict]:
        """Test endpoints for race condition vulnerabilities."""
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        findings = []

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        # Find race-condition-prone endpoints
        race_targets = self._find_race_targets(endpoints)
        logger.info(f"Race condition: Found {len(race_targets)} potential targets")

        for target in race_targets[:8]:
            async with make_client(extra_headers=headers) as client:
                result = await self._test_race(client, target)
                if result:
                    findings.append(result)

        return findings

    def _find_race_targets(self, endpoints) -> list[dict]:
        """Find endpoints prone to race conditions."""
        targets = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            method = "GET" if isinstance(ep, str) else ep.get("method", "GET")

            url_lower = url.lower()
            for category, keywords in RACE_KEYWORDS.items():
                if any(k in url_lower for k in keywords):
                    targets.append({
                        "url": url,
                        "method": method,
                        "category": category,
                        "form_fields": ep.get("form_fields", []) if isinstance(ep, dict) else [],
                    })
                    break

        # Prioritize POST endpoints
        targets.sort(key=lambda t: 0 if t["method"] == "POST" else 1)
        return targets

    async def _test_race(self, client: httpx.AsyncClient, target: dict) -> dict | None:
        """Send concurrent requests and check for inconsistent behavior."""
        url = target["url"]
        method = target["method"]
        category = target["category"]

        try:
            # Step 1: Make a single request to establish baseline
            if method == "POST":
                baseline = await client.post(url)
            else:
                baseline = await client.get(url)

            if baseline.status_code in (404, 401, 403, 405):
                return None

            baseline_text = baseline.text
            baseline_status = baseline.status_code

            # Step 2: Fire N concurrent requests
            async def send_one(i):
                try:
                    if method == "POST":
                        resp = await client.post(url)
                    else:
                        resp = await client.get(url)
                    return {"status": resp.status_code, "length": len(resp.text), "text": resp.text[:200]}
                except Exception as e:
                    return {"status": 0, "error": str(e)}

            # Send concurrent requests
            tasks = [send_one(i) for i in range(self.concurrency)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Step 3: Analyze results for inconsistency
            valid_results = [r for r in results if isinstance(r, dict) and r.get("status", 0) > 0]

            if len(valid_results) < 3:
                return None

            statuses = [r["status"] for r in valid_results]
            lengths = [r["length"] for r in valid_results]

            # Check for mixed responses (some succeed, some fail)
            unique_statuses = set(statuses)
            unique_lengths = set(lengths)

            # Indicators of race condition:
            # 1. Mixed success/error responses
            has_mixed_status = len(unique_statuses) > 1 and any(s == 200 for s in statuses)
            # 2. Varying response lengths (processing different states)
            length_variance = max(lengths) - min(lengths) if lengths else 0
            has_length_variance = length_variance > 100

            # 3. All succeed when they shouldn't (e.g., multiple coupon applications)
            all_success = all(s in (200, 201, 302) for s in statuses)

            if has_mixed_status or (has_length_variance and category in ("payment", "transfer", "coupon")):
                severity = "high" if category in ("payment", "transfer") else "medium"

                return {
                    "title": f"Race Condition ({category}): {urlparse(url).path}",
                    "url": url,
                    "severity": severity,
                    "vuln_type": "race_condition",
                    "category": category,
                    "concurrent_requests": self.concurrency,
                    "unique_statuses": list(unique_statuses),
                    "length_variance": length_variance,
                    "results_summary": {
                        "total": len(valid_results),
                        "success": sum(1 for s in statuses if s in (200, 201)),
                        "error": sum(1 for s in statuses if s >= 400),
                    },
                    "impact": f"Race condition in {category} endpoint. "
                             f"Concurrent requests produce inconsistent results ({len(unique_statuses)} different status codes, "
                             f"response length varies by {length_variance} bytes). "
                             "May allow double-spending, limit bypass, or state corruption.",
                    "remediation": "Implement proper locking mechanisms (database locks, mutex, atomic operations). "
                                  "Use idempotency keys for financial operations.",
                }

        except Exception as e:
            logger.debug(f"Race condition test error for {url}: {e}")
        return None
