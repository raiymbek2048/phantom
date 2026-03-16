"""
Race Condition Module v2 — Advanced TOCTOU and Concurrency Testing

Tests for:
1. Classic TOCTOU — double-spend, coupon reuse, vote manipulation
2. Multi-step Race — concurrent transfers while monitoring state
3. Limit Bypass — parallel requests to exceed quotas
4. State Confusion — concurrent status/role changes

Techniques:
- Burst: N simultaneous requests via httpx connection pool
- Last-Byte Sync: raw sockets, hold last byte, release simultaneously
- Multi-step: GET state → concurrent mutations → verify state drift
"""
import asyncio
import logging
import ssl
import time
from collections import Counter
from urllib.parse import urlparse

import httpx
from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

RACE_KEYWORDS = {
    "critical": ("payment", "transfer", "withdraw", "purchase", "checkout", "pay",
                 "redeem", "coupon", "voucher", "promo", "gift", "reward", "claim",
                 "refund", "charge", "billing", "deposit"),
    "high": ("vote", "like", "follow", "subscribe", "invite", "register", "signup",
             "verify", "confirm", "approve", "activate", "delete", "remove",
             "unsubscribe", "cancel"),
    "medium": ("update", "edit", "change", "modify", "upload", "submit", "send",
               "post", "create", "add", "assign", "share", "export"),
}
STATE_KEYWORDS = ("balance", "credits", "wallet", "account", "profile", "cart",
                  "quantity", "stock", "inventory", "points", "quota", "limit",
                  "count", "usage", "remaining")
MUTATION_KEYWORDS = ("transfer", "withdraw", "purchase", "buy", "order", "send",
                     "deduct", "spend", "consume", "redeem", "apply", "use")
COMMON_RACE_PATHS = [
    "/api/transfer", "/api/payment", "/api/redeem", "/api/vote",
    "/api/like", "/api/follow", "/api/coupon/apply", "/api/checkout",
    "/api/cart/checkout", "/api/order/create", "/api/points/redeem",
    "/api/wallet/withdraw", "/api/credits/use",
]


class RaceConditionModule:
    """Tests endpoints for race condition vulnerabilities."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(20)
        self._custom_headers: dict = {}
        self._auth_cookie: str | None = None
        self._auth_headers: dict = {}
        self._session_cookies: dict = {}

    async def run(self, context: dict) -> list[dict]:
        base_url = context.get("base_url", "")
        if not base_url:
            return []
        self._setup_auth(context)
        endpoints = context.get("endpoints", [])
        findings: list[dict] = []

        race_targets = self._identify_race_targets(endpoints, base_url)
        logger.info(f"RaceCondition: {len(race_targets)} candidate endpoints")

        for target in race_targets[:15]:
            try:
                findings.extend(await self._test_race(target))
            except Exception as e:
                logger.debug(f"Race test failed for {target.get('url')}: {e}")

        findings.extend(await self._test_multi_step_races(endpoints, base_url))

        # Deduplicate
        seen, deduped = set(), []
        for f in findings:
            key = (f.get("url", ""), f.get("title", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        logger.info(f"RaceCondition: found {len(deduped)} issues")
        return deduped

    async def check(self, context: dict, db=None) -> list[dict]:
        """Backward compat with old pipeline calling check()."""
        return await self.run(context)

    def _setup_auth(self, context: dict):
        self._custom_headers = context.get("custom_headers", {})
        self._auth_cookie = context.get("auth_cookie")
        self._auth_headers = context.get("auth_headers", {})
        self._session_cookies = context.get("session_cookies", {})

    def _build_request_headers(self) -> dict:
        headers = dict(self._custom_headers)
        if self._auth_headers:
            headers.update(self._auth_headers)
        if self._session_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
        elif self._auth_cookie:
            if self._auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {self._auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = self._auth_cookie
        return headers

    # ─── Target Identification ───────────────────────────────────────────

    def _identify_race_targets(self, endpoints: list, base_url: str) -> list[dict]:
        targets, seen_urls = [], set()
        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            method = (ep.get("method", "GET") if isinstance(ep, dict) else "GET").upper()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            url_lower = url.lower()
            for severity, keywords in RACE_KEYWORDS.items():
                if any(kw in url_lower for kw in keywords):
                    targets.append({
                        "url": url, "method": method, "severity": severity,
                        "params": ep.get("params", {}) if isinstance(ep, dict) else {},
                        "form_fields": ep.get("form_fields", []) if isinstance(ep, dict) else [],
                    })
                    break

        sev_order = {"critical": 0, "high": 1, "medium": 2}
        targets.sort(key=lambda x: sev_order.get(x["severity"], 3))

        for path in COMMON_RACE_PATHS:
            full_url = base_url.rstrip("/") + path
            if full_url not in seen_urls:
                targets.append({"url": full_url, "method": "POST", "severity": "high",
                                "params": {}, "form_fields": []})
        return targets

    # ─── Core Race Tests ─────────────────────────────────────────────────

    async def _test_race(self, target: dict) -> list[dict]:
        url, method = target["url"], target["method"]
        headers = self._build_request_headers()

        # Baseline — skip dead endpoints
        try:
            async with make_client(extra_headers=headers) as client:
                baseline = await client.request(method, url, timeout=10)
                if baseline.status_code in (404, 405, 502, 503):
                    return []
        except Exception:
            return []

        findings: list[dict] = []
        async with self.rate_limit:
            r = await self._burst_test(url, method, 15, target)
            if r:
                findings.append(r)
        async with self.rate_limit:
            r = await self._last_byte_sync_test(url, method, 10, target)
            if r:
                findings.append(r)
        return findings

    async def _burst_test(self, url: str, method: str, concurrency: int,
                          target: dict) -> dict | None:
        """Send N concurrent identical requests via connection pool."""
        headers = self._build_request_headers()
        body = target.get("params") or {}

        async def send_one(client: httpx.AsyncClient, idx: int) -> dict:
            try:
                start = time.monotonic()
                resp = await client.request(method, url, headers=headers, json=body, timeout=10)
                return {"status": resp.status_code, "length": len(resp.content),
                        "elapsed": time.monotonic() - start,
                        "body_preview": resp.text[:500], "index": idx}
            except Exception as e:
                return {"status": 0, "error": str(e), "index": idx}

        async with make_client(extra_headers=headers) as client:
            results = await asyncio.gather(*[send_one(client, i) for i in range(concurrency)])
        return self._analyze_race_results(url, method, results, target, "burst")

    async def _last_byte_sync_test(self, url: str, method: str, concurrency: int,
                                   target: dict) -> dict | None:
        """
        Last-byte synchronization: open N connections, send everything except
        the last byte, then release all last bytes simultaneously for a tight
        race window using raw sockets.
        """
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        body = "{}"
        req_headers = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"Content-Type: application/json\r\n"
                       f"Content-Length: {len(body)}\r\nConnection: close\r\n")
        for k, v in self._build_request_headers().items():
            req_headers += f"{k}: {v}\r\n"
        req_headers += "\r\n"

        full_request = (req_headers + body).encode()
        prefix, last_byte = full_request[:-1], full_request[-1:]

        conns: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        try:
            ssl_ctx = None
            if parsed.scheme == "https":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            for _ in range(concurrency):
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=5)
                    writer.write(prefix)
                    await writer.drain()
                    conns.append((reader, writer))
                except Exception:
                    pass

            if len(conns) < 3:
                return None

            async def release(reader, writer, idx):
                try:
                    start = time.monotonic()
                    writer.write(last_byte)
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(8192), timeout=10)
                    elapsed = time.monotonic() - start
                    first_line = data.split(b"\r\n")[0].decode(errors="replace")
                    parts = first_line.split()
                    status = int(parts[1]) if len(parts) > 1 else 0
                    return {"status": status, "length": len(data), "elapsed": elapsed,
                            "index": idx, "body_preview": data[:500].decode(errors="replace")}
                except Exception as e:
                    return {"status": 0, "error": str(e), "index": idx}

            results = await asyncio.gather(
                *[release(r, w, i) for i, (r, w) in enumerate(conns)])
            return self._analyze_race_results(url, method, results, target, "last_byte_sync")
        finally:
            for _, writer in conns:
                try:
                    writer.close()
                except Exception:
                    pass

    # ─── Result Analysis ─────────────────────────────────────────────────

    def _analyze_race_results(self, url: str, method: str, results: list[dict],
                              target: dict, technique: str) -> dict | None:
        valid = [r for r in results if r.get("status", 0) > 0]
        if len(valid) < 3:
            return None

        statuses = Counter(r["status"] for r in valid)
        lengths = [r.get("length", 0) for r in valid]
        times = [r.get("elapsed", 0) for r in valid if r.get("elapsed")]
        success_count = sum(1 for r in valid if 200 <= r["status"] < 300)
        error_count = sum(1 for r in valid if r["status"] >= 400)
        indicators: list[str] = []

        # 1. Mixed success/failure — strongest signal
        if len(statuses) > 1 and success_count >= 2 and error_count >= 1:
            indicators.append(f"Mixed statuses: {dict(statuses)} — "
                              f"{success_count} succeeded, {error_count} failed")

        # 2. All succeed on critical endpoint (should be idempotent)
        if success_count == len(valid) and target.get("severity") == "critical" and len(valid) >= 5:
            indicators.append(f"All {len(valid)} concurrent requests returned success "
                              f"— possible double-spend on critical endpoint")

        # 3. Response length variance (different code paths)
        if len(lengths) >= 3:
            avg_len = sum(lengths) / len(lengths)
            if avg_len > 0:
                std_dev = (sum((l - avg_len) ** 2 for l in lengths) / len(lengths)) ** 0.5
                if std_dev > avg_len * 0.1 and std_dev > 50:
                    indicators.append(f"Response length variance: stddev={std_dev:.0f} (avg {avg_len:.0f})")

        # 4. Timing variance — lock contention / different paths
        if len(times) >= 3 and min(times) > 0:
            ratio = max(times) / min(times)
            if ratio > 4:
                indicators.append(f"Timing variance: {min(times):.3f}s to {max(times):.3f}s ({ratio:.1f}x)")

        # 5. Different bodies among successful responses
        bodies = [r.get("body_preview", "") for r in valid]
        success_bodies = [b for r, b in zip(valid, bodies) if 200 <= r["status"] < 300]
        if len(success_bodies) >= 2:
            unique = set(success_bodies)
            if len(unique) > 1:
                indicators.append(f"Different response bodies among {len(success_bodies)} "
                                  f"successful requests ({len(unique)} variants)")

        if not indicators:
            return None

        severity = target.get("severity", "medium")
        if len(indicators) >= 3 and severity == "medium":
            severity = "high"

        path = urlparse(url).path
        label = "Burst" if technique == "burst" else "Last-Byte Sync"
        return {
            "title": f"Race Condition ({label}) — {path}",
            "url": url,
            "severity": severity,
            "vuln_type": "race_condition",
            "description": (f"Endpoint {method} {url} exhibits race condition behavior "
                            f"under {len(valid)} concurrent requests ({label} technique).\n\n"
                            f"Indicators:\n" + "\n".join(f"- {i}" for i in indicators)),
            "impact": "Possible double-spend, limit bypass, or state corruption via concurrent requests",
            "remediation": ("Implement database-level locking (SELECT FOR UPDATE), idempotency keys, "
                            "or atomic compare-and-swap operations. For financial endpoints, use "
                            "serializable transaction isolation level."),
            "payload": f"{label}: {len(valid)} concurrent {method} requests",
            "proof": f"Status distribution: {dict(statuses)}\n" + "\n".join(indicators),
        }

    # ─── Multi-step Race Tests ───────────────────────────────────────────

    async def _test_multi_step_races(self, endpoints: list, base_url: str) -> list[dict]:
        """Pair state-reading GET endpoints with mutation POST endpoints."""
        findings: list[dict] = []
        state_eps, mutate_eps = [], []

        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            method = (ep.get("method", "GET") if isinstance(ep, dict) else "GET").upper()
            url_lower = url.lower()
            if method == "GET" and any(kw in url_lower for kw in STATE_KEYWORDS):
                state_eps.append(url)
            elif method in ("POST", "PUT") and any(kw in url_lower for kw in MUTATION_KEYWORDS):
                mutate_eps.append(url)

        for state_url in state_eps[:3]:
            for mutate_url in mutate_eps[:3]:
                try:
                    result = await self._test_state_mutation_race(state_url, mutate_url)
                    if result:
                        findings.append(result)
                except Exception as e:
                    logger.debug(f"Multi-step race failed: {e}")
        return findings

    async def _test_state_mutation_race(self, state_url: str, mutate_url: str) -> dict | None:
        """GET state → 5 concurrent POST mutations → GET state, compare."""
        headers = self._build_request_headers()

        async with make_client(extra_headers=headers) as client:
            # Read initial state
            try:
                initial = await client.get(state_url, headers=headers, timeout=10)
                if initial.status_code != 200:
                    return None
                initial_body = initial.text
            except Exception:
                return None

            # Fire concurrent mutations
            async def mutate(idx: int):
                try:
                    resp = await client.post(mutate_url, headers=headers, json={}, timeout=10)
                    return {"status": resp.status_code, "body": resp.text[:300]}
                except Exception:
                    return None

            results = await asyncio.gather(*[mutate(i) for i in range(5)])
            valid = [r for r in results if r and r.get("status")]
            if not valid:
                return None

            # Read final state
            try:
                final = await client.get(state_url, headers=headers, timeout=10)
                final_body = final.text
            except Exception:
                return None

        successes = sum(1 for r in valid if 200 <= r["status"] < 300)
        statuses = Counter(r["status"] for r in valid)

        if successes <= 1 or initial_body == final_body:
            return None

        mutate_path = urlparse(mutate_url).path
        state_path = urlparse(state_url).path
        return {
            "title": f"Multi-step Race Condition — {mutate_path}",
            "url": mutate_url,
            "severity": "high",
            "vuln_type": "race_condition",
            "description": (f"Multi-step race: {successes}/5 concurrent mutations to "
                            f"{mutate_url} succeeded. State endpoint {state_url} changed.\n\n"
                            f"Mutation status distribution: {dict(statuses)}"),
            "impact": ("Multiple state mutations executed concurrently — "
                       "potential double-spend, balance underflow, or data corruption"),
            "remediation": ("Use database transactions with row-level locking (SELECT FOR UPDATE), "
                            "implement idempotency keys, or use optimistic concurrency control "
                            "with version columns"),
            "payload": f"5 concurrent POST to {mutate_url} while monitoring {state_url}",
            "proof": (f"State endpoint: {state_path}\n"
                      f"Initial response length: {len(initial_body)}\n"
                      f"Final response length: {len(final_body)}\n"
                      f"Successful mutations: {successes}/5\nStatuses: {dict(statuses)}"),
        }
