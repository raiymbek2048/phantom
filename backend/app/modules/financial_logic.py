"""
Financial Logic Attack Module — Banking & Fintech specific tests.

Targets business logic flaws common in banking/payment applications:
1. Transfer Amount Tampering — modify amount/currency between multi-step flows
2. Double Spending — concurrent transfers on same balance (race condition variant)
3. Currency Mismatch — switch currency mid-transaction for exchange rate abuse
4. IDOR in Financial Endpoints — access other users' accounts/transactions
5. Negative Balance Exploit — withdrawals below zero
6. Transaction Replay — replay same transaction for duplicate credit
7. Fee/Commission Bypass — skip or zero-out fees
8. Limit Bypass — exceed daily/monthly transaction limits
9. Rounding Exploit — penny-shaving via precision manipulation
10. Payment Status Manipulation — change payment state via parameter tampering
"""
import asyncio
import copy
import hashlib
import json
import logging
import re
import time
from collections import Counter
from urllib.parse import urljoin, urlparse

import httpx
from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# ─── Financial Endpoint Discovery ────────────────────────────────────────
FINANCIAL_KEYWORDS = {
    "transfer": ("transfer", "send", "remit", "wire", "p2p"),
    "payment": ("payment", "pay", "checkout", "charge", "billing", "invoice"),
    "withdraw": ("withdraw", "cashout", "cash-out", "payout"),
    "deposit": ("deposit", "topup", "top-up", "fund", "recharge"),
    "account": ("account", "wallet", "balance", "statement", "card"),
    "transaction": ("transaction", "txn", "history", "movement"),
    "exchange": ("exchange", "convert", "swap", "rate", "currency"),
    "loan": ("loan", "credit", "installment", "emi", "repay"),
}

AMOUNT_FIELDS = (
    "amount", "sum", "total", "value", "price", "quantity",
    "transfer_amount", "payment_amount", "withdrawal_amount",
    "deposit_amount", "summa",  # Russian
)
ACCOUNT_ID_FIELDS = (
    "account_id", "account", "recipient", "sender", "from_account",
    "to_account", "beneficiary", "payee", "receiver", "card_number",
    "iban", "wallet_id", "user_id", "customer_id",
)
CURRENCY_FIELDS = (
    "currency", "cur", "currency_code", "from_currency", "to_currency",
    "source_currency", "target_currency",
)
STATUS_FIELDS = (
    "status", "state", "payment_status", "transaction_status",
    "order_status", "is_paid", "confirmed", "approved",
)
FEE_FIELDS = (
    "fee", "commission", "service_fee", "processing_fee",
    "charge", "tax", "vat",
)

FINANCIAL_API_PATTERNS = [
    "/api/transfer", "/api/transfers", "/api/payment", "/api/payments",
    "/api/withdraw", "/api/deposit", "/api/wallet", "/api/balance",
    "/api/transaction", "/api/transactions", "/api/account",
    "/api/exchange", "/api/convert", "/api/send", "/api/p2p",
    "/api/v1/transfer", "/api/v1/payment", "/api/v1/wallet",
    "/api/v1/transaction", "/api/v1/account", "/api/v1/balance",
    "/api/v2/transfer", "/api/v2/payment",
    "/api/cards", "/api/card", "/api/loan", "/api/credit",
    "/transfer/confirm", "/payment/confirm", "/payment/process",
    "/checkout/complete", "/order/pay",
]

CURRENCIES = ["USD", "EUR", "KZT", "RUB", "GBP", "CNY", "JPY", "KGS", "UZS"]


class FinancialLogicModule:
    """Tests for financial/banking business logic vulnerabilities."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(10)
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

        # Discover financial endpoints
        fin_endpoints = self._discover_financial_endpoints(endpoints, base_url)
        logger.info(f"FinancialLogic: {len(fin_endpoints)} financial endpoints found")

        if not fin_endpoints:
            return []

        # Group by category
        categorized = self._categorize_endpoints(fin_endpoints)

        # Run tests
        tests = [
            ("Amount Tampering", self._test_amount_tampering, categorized),
            ("Double Spending", self._test_double_spending, categorized),
            ("Currency Mismatch", self._test_currency_mismatch, categorized),
            ("Financial IDOR", self._test_financial_idor, categorized),
            ("Negative Balance", self._test_negative_balance, categorized),
            ("Transaction Replay", self._test_transaction_replay, categorized),
            ("Fee Bypass", self._test_fee_bypass, categorized),
            ("Limit Bypass", self._test_limit_bypass, categorized),
            ("Rounding Exploit", self._test_rounding_exploit, categorized),
            ("Status Manipulation", self._test_status_manipulation, categorized),
        ]

        for name, test_fn, cats in tests:
            try:
                results = await test_fn(cats, base_url)
                findings.extend(results)
                if results:
                    logger.info(f"FinancialLogic: {name} — {len(results)} findings")
            except Exception as e:
                logger.debug(f"FinancialLogic: {name} failed: {e}")

        # Dedup
        seen = set()
        deduped = []
        for f in findings:
            key = (f.get("url", ""), f.get("title", "")[:50])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info(f"FinancialLogic: {len(deduped)} total findings")
        return deduped

    # ─── Auth / Headers ──────────────────────────────────────────────────

    def _setup_auth(self, context: dict):
        self._custom_headers = context.get("custom_headers", {})
        self._auth_cookie = context.get("auth_cookie")
        self._auth_headers = context.get("auth_headers", {})
        self._session_cookies = context.get("session_cookies", {})

    def _build_headers(self) -> dict:
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

    # ─── Endpoint Discovery ──────────────────────────────────────────────

    def _discover_financial_endpoints(self, endpoints: list, base_url: str) -> list[dict]:
        found = []
        seen = set()

        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            method = (ep.get("method", "GET") if isinstance(ep, dict) else "GET").upper()
            if not url or url in seen:
                continue

            url_lower = url.lower()
            category = None
            for cat, keywords in FINANCIAL_KEYWORDS.items():
                if any(kw in url_lower for kw in keywords):
                    category = cat
                    break

            if category:
                seen.add(url)
                found.append({
                    "url": url,
                    "method": method,
                    "category": category,
                    "params": ep.get("params", {}) if isinstance(ep, dict) else {},
                    "form_fields": ep.get("form_fields", []) if isinstance(ep, dict) else [],
                })

        # Probe common financial API paths
        for path in FINANCIAL_API_PATTERNS:
            full_url = base_url.rstrip("/") + path
            if full_url not in seen:
                category = "transfer"
                for cat, keywords in FINANCIAL_KEYWORDS.items():
                    if any(kw in path.lower() for kw in keywords):
                        category = cat
                        break
                found.append({
                    "url": full_url, "method": "POST", "category": category,
                    "params": {}, "form_fields": [],
                })
                seen.add(full_url)

        return found

    def _categorize_endpoints(self, endpoints: list) -> dict[str, list[dict]]:
        cats: dict[str, list[dict]] = {}
        for ep in endpoints:
            cat = ep.get("category", "other")
            cats.setdefault(cat, []).append(ep)
        return cats

    # ─── Helpers ─────────────────────────────────────────────────────────

    def _make_finding(self, title: str, url: str, severity: str,
                      description: str, impact: str, remediation: str,
                      payload: str, proof: str = "") -> dict:
        return {
            "title": title,
            "url": url,
            "severity": severity,
            "vuln_type": "business_logic",
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "payload": payload,
            "proof": proof,
        }

    async def _safe_request(self, client: httpx.AsyncClient, method: str,
                            url: str, **kwargs) -> httpx.Response | None:
        try:
            async with self.rate_limit:
                return await client.request(method, url, timeout=12, **kwargs)
        except Exception:
            return None

    def _response_indicates_success(self, resp: httpx.Response) -> bool:
        """Check if response indicates a successful financial operation."""
        if resp.status_code not in (200, 201, 202):
            return False
        body = resp.text.lower()[:2000]
        success_kw = ["success", "completed", "approved", "confirmed", "processed",
                      "accepted", "created", "transferred", "paid"]
        fail_kw = ["error", "failed", "denied", "rejected", "insufficient",
                   "invalid", "forbidden", "unauthorized"]
        has_success = any(kw in body for kw in success_kw)
        has_fail = any(kw in body for kw in fail_kw)
        return has_success and not has_fail

    def _extract_json_field(self, resp: httpx.Response, *field_names: str):
        """Extract a field value from JSON response."""
        try:
            data = resp.json()
            if isinstance(data, dict):
                for name in field_names:
                    if name in data:
                        return data[name]
                    # Nested check
                    for key, val in data.items():
                        if isinstance(val, dict) and name in val:
                            return val[name]
        except Exception:
            pass
        return None

    # ─── 1. Amount Tampering ─────────────────────────────────────────────

    async def _test_amount_tampering(self, cats: dict, base_url: str) -> list[dict]:
        """Test if amount/value can be tampered in transfer/payment endpoints."""
        findings = []
        targets = cats.get("transfer", []) + cats.get("payment", []) + cats.get("withdraw", [])

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:8]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT", "PATCH") else "POST"

                # Baseline with normal amount
                baseline_body = {"amount": "100", "currency": "KZT"}
                # Add account fields if we can guess them
                for field in ACCOUNT_ID_FIELDS[:3]:
                    baseline_body[field] = "self"

                baseline = await self._safe_request(client, method, url, json=baseline_body)
                if not baseline or baseline.status_code in (404, 405, 502, 503):
                    continue

                baseline_text = baseline.text[:2000]
                baseline_status = baseline.status_code

                # Test manipulated amounts
                tamper_tests = [
                    ({"amount": "-100"}, "Negative amount", "critical"),
                    ({"amount": "0"}, "Zero amount", "high"),
                    ({"amount": "0.001"}, "Micro amount (precision)", "medium"),
                    ({"amount": "999999999"}, "Extremely large amount", "high"),
                    ({"amount": "100", "total": "0"}, "Total override to zero", "critical"),
                    ({"amount": "100", "fee": "0"}, "Fee zeroed out", "high"),
                    ({"amount": "100", "discount": "100"}, "100% discount injection", "critical"),
                    ({"amount": "100", "amount_in_cents": "1"}, "Cent vs dollar confusion", "critical"),
                ]

                for tamper, desc, severity in tamper_tests:
                    body = dict(baseline_body)
                    body.update(tamper)
                    resp = await self._safe_request(client, method, url, json=body)
                    if not resp:
                        continue

                    # Different response from baseline = endpoint processes the field
                    if (resp.text[:2000] != baseline_text or
                            resp.status_code != baseline_status):
                        if resp.status_code in (200, 201, 202):
                            body_lower = resp.text.lower()[:2000]
                            if not any(kw in body_lower for kw in
                                       ["error", "invalid", "rejected", "must be positive"]):
                                findings.append(self._make_finding(
                                    title=f"Financial Amount Tampering: {desc}",
                                    url=url,
                                    severity=severity,
                                    description=(
                                        f"Endpoint {method} {url} accepts manipulated "
                                        f"financial values. Tampered: {json.dumps(tamper)}. "
                                        f"Server responded {resp.status_code} without rejection."
                                    ),
                                    impact=(
                                        f"Attacker can manipulate transaction amounts — "
                                        f"potential financial loss via {desc.lower()}."
                                    ),
                                    remediation=(
                                        "Validate all financial values server-side: reject "
                                        "negative amounts, enforce min/max limits, use "
                                        "server-calculated totals, never trust client-side "
                                        "amount/fee/discount fields."
                                    ),
                                    payload=json.dumps(body),
                                    proof=f"Status: {resp.status_code}, Body preview: {resp.text[:300]}",
                                ))
                                break  # One finding per endpoint is enough
        return findings

    # ─── 2. Double Spending (Financial Race Condition) ───────────────────

    async def _test_double_spending(self, cats: dict, base_url: str) -> list[dict]:
        """Concurrent transfers to exploit TOCTOU on balance check."""
        findings = []
        targets = cats.get("transfer", []) + cats.get("withdraw", []) + cats.get("payment", [])

        headers = self._build_headers()

        for ep in targets[:5]:
            url = ep["url"]
            method = ep["method"] if ep["method"] in ("POST", "PUT") else "POST"

            # Build a plausible transfer body
            body = {"amount": "1", "currency": "KZT"}
            for field in ACCOUNT_ID_FIELDS[:2]:
                body[field] = "test"

            async def send_one(idx: int) -> dict:
                try:
                    async with make_client(extra_headers=headers) as c:
                        start = time.monotonic()
                        resp = await c.request(method, url, json=body, timeout=10)
                        elapsed = time.monotonic() - start
                        return {
                            "status": resp.status_code,
                            "body": resp.text[:500],
                            "length": len(resp.content),
                            "elapsed": elapsed,
                            "index": idx,
                        }
                except Exception as e:
                    return {"status": 0, "error": str(e), "index": idx}

            # Fire 10 concurrent identical transfers
            results = await asyncio.gather(*[send_one(i) for i in range(10)])
            valid = [r for r in results if r.get("status", 0) > 0]

            if len(valid) < 5:
                continue

            statuses = Counter(r["status"] for r in valid)
            successes = sum(1 for r in valid if 200 <= r["status"] < 300)

            # Check for race condition indicators
            indicators = []
            if len(statuses) > 1 and successes >= 2:
                indicators.append(
                    f"Mixed statuses under concurrency: {dict(statuses)}"
                )

            # Different bodies among successes
            success_bodies = [r["body"] for r in valid if 200 <= r["status"] < 300]
            if len(set(success_bodies)) > 1:
                indicators.append(
                    f"{len(set(success_bodies))} different response bodies "
                    f"among {successes} successful requests"
                )

            # All succeeded — potential double-spend if no idempotency
            if successes == len(valid) and successes >= 5:
                indicators.append(
                    f"All {successes} concurrent requests succeeded — "
                    f"no idempotency protection"
                )

            if len(indicators) >= 1 and successes >= 2:
                findings.append(self._make_finding(
                    title=f"Double Spend: {successes}/{len(valid)} concurrent "
                          f"transfers succeeded — {urlparse(url).path}",
                    url=url,
                    severity="critical" if successes >= 5 else "high",
                    description=(
                        f"Sent {len(valid)} concurrent {method} requests to {url}. "
                        f"{successes} succeeded.\n\n"
                        + "\n".join(f"- {i}" for i in indicators)
                    ),
                    impact=(
                        "Double-spend vulnerability: attacker can drain account "
                        "balance below zero or duplicate transfers by exploiting "
                        "TOCTOU gap in balance verification."
                    ),
                    remediation=(
                        "Use database-level locking (SELECT ... FOR UPDATE), "
                        "implement idempotency keys per transaction, use "
                        "serializable transaction isolation, add unique "
                        "constraints on transaction references."
                    ),
                    payload=f"{len(valid)} concurrent {method} {url}",
                    proof=f"Status distribution: {dict(statuses)}\n"
                          + "\n".join(indicators),
                ))
                break  # One double-spend finding is enough

        return findings

    # ─── 3. Currency Mismatch ────────────────────────────────────────────

    async def _test_currency_mismatch(self, cats: dict, base_url: str) -> list[dict]:
        """Send different currencies in different fields or mid-flow."""
        findings = []
        targets = (cats.get("transfer", []) + cats.get("payment", []) +
                   cats.get("exchange", []))

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:5]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT") else "POST"

                # Test 1: Different currency codes in different fields
                mismatch_tests = [
                    {"amount": "100", "currency": "KZT", "to_currency": "USD"},
                    {"amount": "100", "currency": "usd", "source_currency": "KZT"},
                    {"amount": "100", "currency": "XXX"},  # Invalid currency
                    {"amount": "100", "currency": "BTC"},  # Crypto confusion
                    {"amount": "100", "currency": "KZT", "display_currency": "USD"},
                ]

                baseline = await self._safe_request(
                    client, method, url,
                    json={"amount": "100", "currency": "KZT"},
                )
                if not baseline or baseline.status_code in (404, 405, 502, 503):
                    continue

                for test_body in mismatch_tests:
                    resp = await self._safe_request(client, method, url, json=test_body)
                    if not resp:
                        continue

                    if resp.status_code in (200, 201, 202):
                        body_lower = resp.text.lower()[:2000]
                        if not any(kw in body_lower for kw in
                                   ["error", "invalid currency", "unsupported"]):
                            # Check if response mentions exchange rate or different amount
                            has_rate = any(kw in body_lower for kw in
                                           ["rate", "exchange", "converted", "conversion"])
                            if has_rate or resp.text[:2000] != baseline.text[:2000]:
                                findings.append(self._make_finding(
                                    title="Currency Mismatch Accepted",
                                    url=url,
                                    severity="high",
                                    description=(
                                        f"Endpoint accepts mismatched currency parameters: "
                                        f"{json.dumps(test_body)}. "
                                        f"This may allow exchange rate manipulation."
                                    ),
                                    impact=(
                                        "Attacker can exploit currency confusion to pay "
                                        "in weaker currency while receiving credit in "
                                        "stronger currency, or bypass amount validation."
                                    ),
                                    remediation=(
                                        "Validate currency fields match on server side. "
                                        "Use server-determined exchange rates. Never "
                                        "trust client-provided currency/rate fields."
                                    ),
                                    payload=json.dumps(test_body),
                                ))
                                break
        return findings

    # ─── 4. Financial IDOR ───────────────────────────────────────────────

    async def _test_financial_idor(self, cats: dict, base_url: str) -> list[dict]:
        """Test IDOR on account/transaction endpoints."""
        findings = []
        targets = (cats.get("account", []) + cats.get("transaction", []) +
                   cats.get("transfer", []))

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:8]:
                url = ep["url"]
                parsed = urlparse(url)
                path = parsed.path

                # Test 1: Sequential ID enumeration in URL path
                # /api/account/123 → try /api/account/124
                id_match = re.search(r'/(\d+)(?:/|$)', path)
                if id_match:
                    original_id = int(id_match.group(1))
                    test_ids = [
                        original_id + 1,
                        original_id - 1,
                        1,  # First record
                        0,  # Edge case
                    ]
                    original_resp = await self._safe_request(client, "GET", url)
                    if not original_resp or original_resp.status_code != 200:
                        continue

                    for test_id in test_ids:
                        test_url = url.replace(f"/{original_id}", f"/{test_id}")
                        if test_url == url:
                            continue
                        resp = await self._safe_request(client, "GET", test_url)
                        if not resp:
                            continue

                        if resp.status_code == 200 and len(resp.text) > 50:
                            # Check it's not the same response
                            if resp.text[:500] != original_resp.text[:500]:
                                # Check for financial data indicators
                                body_lower = resp.text.lower()[:2000]
                                has_financial = any(kw in body_lower for kw in [
                                    "balance", "amount", "transaction", "account",
                                    "card", "payment", "transfer", "name", "email",
                                ])
                                if has_financial:
                                    findings.append(self._make_finding(
                                        title=f"Financial IDOR: Access to "
                                              f"other user's data via ID={test_id}",
                                        url=test_url,
                                        severity="critical",
                                        description=(
                                            f"Changing numeric ID in URL from "
                                            f"{original_id} to {test_id} returns "
                                            f"different user's financial data."
                                        ),
                                        impact=(
                                            "Attacker can access any user's financial "
                                            "data (balance, transactions, account info) "
                                            "by iterating IDs."
                                        ),
                                        remediation=(
                                            "Implement proper authorization checks. "
                                            "Verify the authenticated user owns the "
                                            "requested resource. Use UUIDs instead of "
                                            "sequential IDs."
                                        ),
                                        payload=f"GET {test_url}",
                                        proof=f"Response: {resp.text[:300]}",
                                    ))
                                    break

                # Test 2: Account ID in parameters
                if ep["method"] in ("POST", "PUT", "PATCH", "GET"):
                    for field in ACCOUNT_ID_FIELDS:
                        for test_val in ["1", "0", "admin", "99999"]:
                            body = {"amount": "1", field: test_val}
                            resp = await self._safe_request(
                                client, ep["method"], url, json=body,
                            )
                            if resp and resp.status_code in (200, 201):
                                body_lower = resp.text.lower()[:2000]
                                if not any(kw in body_lower for kw in
                                           ["error", "not found", "invalid", "denied"]):
                                    if any(kw in body_lower for kw in
                                           ["balance", "name", "account", "card"]):
                                        findings.append(self._make_finding(
                                            title=f"Financial IDOR via "
                                                  f"'{field}' parameter",
                                            url=url,
                                            severity="critical",
                                            description=(
                                                f"Setting {field}={test_val} returns "
                                                f"financial data without proper "
                                                f"authorization check."
                                            ),
                                            impact=(
                                                "Attacker can access other users' "
                                                "financial data by manipulating "
                                                "account identifiers."
                                            ),
                                            remediation=(
                                                "Server must verify the authenticated "
                                                "user has permission to access the "
                                                "requested account."
                                            ),
                                            payload=f"{field}={test_val}",
                                            proof=f"Response: {resp.text[:300]}",
                                        ))
                                        break
                        else:
                            continue
                        break  # Found IDOR for this endpoint
        return findings

    # ─── 5. Negative Balance ─────────────────────────────────────────────

    async def _test_negative_balance(self, cats: dict, base_url: str) -> list[dict]:
        """Test if balance can go negative through withdrawal/transfer."""
        findings = []
        targets = cats.get("withdraw", []) + cats.get("transfer", [])

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:5]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT") else "POST"

                # Try to withdraw a very large amount
                large_amounts = ["999999999", "99999999999", "1000000"]
                for amount in large_amounts:
                    body = {"amount": amount, "currency": "KZT"}
                    resp = await self._safe_request(client, method, url, json=body)
                    if not resp:
                        continue

                    if resp.status_code in (200, 201):
                        body_lower = resp.text.lower()[:2000]
                        if not any(kw in body_lower for kw in
                                   ["insufficient", "not enough", "limit",
                                    "exceeded", "error", "denied"]):
                            # Check if balance went negative
                            balance = self._extract_json_field(
                                resp, "balance", "remaining", "available",
                            )
                            if balance is not None:
                                try:
                                    if float(balance) < 0:
                                        findings.append(self._make_finding(
                                            title="Negative Balance: withdrawal "
                                                  "below zero accepted",
                                            url=url,
                                            severity="critical",
                                            description=(
                                                f"Withdrawing {amount} succeeded, "
                                                f"resulting balance: {balance}."
                                            ),
                                            impact=(
                                                "Users can overdraw their account, "
                                                "causing financial loss to the platform."
                                            ),
                                            remediation=(
                                                "Check available balance BEFORE "
                                                "processing withdrawal. Use database "
                                                "constraints (CHECK balance >= 0)."
                                            ),
                                            payload=json.dumps({"amount": amount}),
                                            proof=f"Balance after: {balance}",
                                        ))
                                        break
                                except (ValueError, TypeError):
                                    pass
        return findings

    # ─── 6. Transaction Replay ───────────────────────────────────────────

    async def _test_transaction_replay(self, cats: dict, base_url: str) -> list[dict]:
        """Replay the same transaction to check for idempotency."""
        findings = []
        targets = cats.get("transfer", []) + cats.get("payment", [])

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:5]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT") else "POST"

                # Send the same transaction 3 times
                tx_id = f"phantom_test_{int(time.time())}"
                body = {
                    "amount": "1",
                    "currency": "KZT",
                    "reference": tx_id,
                    "idempotency_key": tx_id,
                    "transaction_id": tx_id,
                }

                responses = []
                for _ in range(3):
                    resp = await self._safe_request(client, method, url, json=body)
                    if resp:
                        responses.append({
                            "status": resp.status_code,
                            "body": resp.text[:500],
                        })

                if len(responses) < 3:
                    continue

                # Check if all 3 returned success (201 Created multiple times = replay)
                all_success = all(
                    200 <= r["status"] < 300 for r in responses
                )
                # Different bodies might indicate different transactions created
                unique_bodies = len(set(r["body"] for r in responses))

                if all_success and unique_bodies > 1:
                    findings.append(self._make_finding(
                        title="Transaction Replay: same request "
                              "processed multiple times",
                        url=url,
                        severity="high",
                        description=(
                            f"Sent identical transaction 3 times with same "
                            f"reference/idempotency key. All returned success "
                            f"with {unique_bodies} different responses — "
                            f"no replay protection."
                        ),
                        impact=(
                            "Attacker can replay payment/transfer requests "
                            "to receive multiple credits or drain funds."
                        ),
                        remediation=(
                            "Implement idempotency keys. Reject duplicate "
                            "transaction references. Use unique constraints "
                            "on transaction IDs."
                        ),
                        payload=json.dumps(body),
                        proof=f"Statuses: {[r['status'] for r in responses]}",
                    ))
        return findings

    # ─── 7. Fee/Commission Bypass ────────────────────────────────────────

    async def _test_fee_bypass(self, cats: dict, base_url: str) -> list[dict]:
        """Test if fees/commissions can be zeroed or removed."""
        findings = []
        targets = (cats.get("transfer", []) + cats.get("payment", []) +
                   cats.get("withdraw", []))

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:5]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT") else "POST"

                # Baseline
                baseline_body = {"amount": "100", "currency": "KZT"}
                baseline = await self._safe_request(
                    client, method, url, json=baseline_body,
                )
                if not baseline or baseline.status_code in (404, 405, 502):
                    continue

                # Try fee manipulation
                fee_tests = [
                    {"amount": "100", "fee": "0"},
                    {"amount": "100", "commission": "0"},
                    {"amount": "100", "service_fee": "0"},
                    {"amount": "100", "fee": "-10"},
                    {"amount": "100", "processing_fee": "0", "tax": "0"},
                    {"amount": "100", "no_fee": "true"},
                    {"amount": "100", "promo_code": "NOFEE"},
                ]

                for test_body in fee_tests:
                    resp = await self._safe_request(
                        client, method, url, json=test_body,
                    )
                    if not resp or resp.status_code not in (200, 201):
                        continue

                    # Compare with baseline
                    if resp.text[:2000] != baseline.text[:2000]:
                        body_lower = resp.text.lower()[:2000]
                        if not any(kw in body_lower for kw in
                                   ["error", "invalid", "not allowed"]):
                            # Check if fee-related fields appear with 0 value
                            fee_val = self._extract_json_field(
                                resp, "fee", "commission", "service_fee",
                            )
                            if fee_val is not None:
                                try:
                                    if float(fee_val) <= 0:
                                        findings.append(self._make_finding(
                                            title="Fee Bypass: commission "
                                                  "zeroed via parameter",
                                            url=url,
                                            severity="high",
                                            description=(
                                                f"Setting fee-related parameters "
                                                f"to 0 was accepted. Fee in "
                                                f"response: {fee_val}."
                                            ),
                                            impact=(
                                                "Attacker can bypass transaction "
                                                "fees, causing revenue loss."
                                            ),
                                            remediation=(
                                                "Calculate fees server-side only. "
                                                "Never accept client-provided "
                                                "fee/commission values."
                                            ),
                                            payload=json.dumps(test_body),
                                        ))
                                        break
                                except (ValueError, TypeError):
                                    pass
        return findings

    # ─── 8. Limit Bypass ─────────────────────────────────────────────────

    async def _test_limit_bypass(self, cats: dict, base_url: str) -> list[dict]:
        """Test if daily/monthly transaction limits can be bypassed."""
        findings = []
        targets = cats.get("transfer", []) + cats.get("withdraw", [])

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:3]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT") else "POST"

                # Test: many small transactions in rapid succession
                successes = 0
                for i in range(15):
                    body = {
                        "amount": "1",
                        "currency": "KZT",
                        "reference": f"phantom_limit_test_{int(time.time())}_{i}",
                    }
                    resp = await self._safe_request(client, method, url, json=body)
                    if resp and 200 <= resp.status_code < 300:
                        successes += 1
                    elif resp and resp.status_code == 429:
                        break  # Rate limited
                    body_text = resp.text.lower()[:500] if resp else ""
                    if any(kw in body_text for kw in
                           ["limit", "exceeded", "maximum", "too many"]):
                        break

                if successes >= 12:
                    findings.append(self._make_finding(
                        title="Transaction Limit Bypass: no rate/frequency limiting",
                        url=url,
                        severity="high",
                        description=(
                            f"Successfully sent {successes}/15 rapid transactions "
                            f"without hitting any rate or frequency limit."
                        ),
                        impact=(
                            "Attacker can bypass daily transaction limits by "
                            "sending many small transactions rapidly."
                        ),
                        remediation=(
                            "Implement per-user transaction rate limits, "
                            "daily/monthly caps, and velocity checks. "
                            "Monitor for rapid small transactions."
                        ),
                        payload=f"{successes} rapid transactions to {url}",
                    ))
        return findings

    # ─── 9. Rounding Exploit ─────────────────────────────────────────────

    async def _test_rounding_exploit(self, cats: dict, base_url: str) -> list[dict]:
        """Test penny-shaving via decimal precision manipulation."""
        findings = []
        targets = (cats.get("transfer", []) + cats.get("exchange", []) +
                   cats.get("payment", []))

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:5]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT") else "POST"

                precision_tests = [
                    "0.009",       # Below minimum unit
                    "0.001",       # Sub-penny
                    "0.0001",      # Micro precision
                    "100.999",     # Extra decimal
                    "100.00000001",  # Many decimals
                    "1e-8",        # Scientific notation
                    "1e10",        # Large via scientific notation
                ]

                baseline = await self._safe_request(
                    client, method, url,
                    json={"amount": "100.00", "currency": "KZT"},
                )
                if not baseline or baseline.status_code in (404, 405, 502):
                    continue

                for amount in precision_tests:
                    body = {"amount": amount, "currency": "KZT"}
                    resp = await self._safe_request(client, method, url, json=body)
                    if not resp:
                        continue

                    if resp.status_code in (200, 201):
                        body_lower = resp.text.lower()[:2000]
                        if not any(kw in body_lower for kw in
                                   ["error", "invalid", "precision"]):
                            # Check if amount was accepted as-is
                            resp_amount = self._extract_json_field(
                                resp, "amount", "total", "value",
                            )
                            if resp_amount is not None:
                                try:
                                    float_amount = float(resp_amount)
                                    float_sent = float(amount)
                                    # If server accepted sub-unit precision
                                    if (float_sent < 1 and float_amount > 0 and
                                            float_amount < 1):
                                        findings.append(self._make_finding(
                                            title="Rounding Exploit: sub-unit "
                                                  "precision accepted",
                                            url=url,
                                            severity="medium",
                                            description=(
                                                f"Endpoint accepts amount={amount}, "
                                                f"processed as {resp_amount}. "
                                                f"Sub-unit precision may enable "
                                                f"penny-shaving attacks."
                                            ),
                                            impact=(
                                                "Repeated micro-transactions can "
                                                "accumulate rounding differences "
                                                "for financial gain."
                                            ),
                                            remediation=(
                                                "Enforce minimum transaction amount. "
                                                "Round to currency's smallest unit. "
                                                "Reject scientific notation."
                                            ),
                                            payload=f"amount={amount}",
                                            proof=f"Accepted as: {resp_amount}",
                                        ))
                                        break
                                except (ValueError, TypeError):
                                    pass
        return findings

    # ─── 10. Payment Status Manipulation ─────────────────────────────────

    async def _test_status_manipulation(self, cats: dict, base_url: str) -> list[dict]:
        """Test if payment/transaction status can be changed via params."""
        findings = []
        targets = (cats.get("payment", []) + cats.get("transaction", []) +
                   cats.get("transfer", []))

        headers = self._build_headers()
        async with make_client(extra_headers=headers) as client:
            for ep in targets[:5]:
                url = ep["url"]
                method = ep["method"] if ep["method"] in ("POST", "PUT", "PATCH") else "POST"

                status_tests = [
                    {"status": "completed"},
                    {"status": "approved"},
                    {"status": "paid"},
                    {"payment_status": "success"},
                    {"is_paid": True},
                    {"confirmed": True},
                    {"verified": True},
                    {"state": "completed"},
                ]

                baseline = await self._safe_request(
                    client, method, url,
                    json={"amount": "100"},
                )
                if not baseline or baseline.status_code in (404, 405, 502):
                    continue

                for test_body in status_tests:
                    body = {"amount": "100", "currency": "KZT"}
                    body.update(test_body)
                    resp = await self._safe_request(client, method, url, json=body)
                    if not resp:
                        continue

                    if resp.status_code in (200, 201):
                        if resp.text[:2000] != baseline.text[:2000]:
                            body_lower = resp.text.lower()[:2000]
                            if any(kw in body_lower for kw in
                                   ["completed", "approved", "success", "paid"]):
                                if not any(kw in body_lower for kw in
                                           ["error", "invalid", "unauthorized"]):
                                    findings.append(self._make_finding(
                                        title=f"Payment Status Manipulation: "
                                              f"'{list(test_body.keys())[0]}' "
                                              f"accepted",
                                        url=url,
                                        severity="critical",
                                        description=(
                                            f"Setting {json.dumps(test_body)} "
                                            f"changes the transaction state. "
                                            f"Server accepted client-provided "
                                            f"payment status."
                                        ),
                                        impact=(
                                            "Attacker can mark unpaid orders as "
                                            "paid, skip payment verification, or "
                                            "approve their own transactions."
                                        ),
                                        remediation=(
                                            "Never accept payment status from "
                                            "client. Status must be set by payment "
                                            "processor callback only. Validate "
                                            "payment server-side."
                                        ),
                                        payload=json.dumps(body),
                                    ))
                                    break
        return findings
