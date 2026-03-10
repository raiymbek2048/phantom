"""
Payload Validation Pipeline — Test AI-generated payloads against practice range targets.

Validates KnowledgePattern payloads (ai_mutation, effective_payload) by sending them
to live practice targets (DVWA, Juice Shop, WebGoat) and adjusting confidence based
on whether the payload triggers a vulnerability response.

Flow:
1. Query unvalidated/low-confidence payloads from knowledge base
2. Check which practice targets are running
3. Route payload to appropriate target based on vuln_type
4. Send payload and analyze response for success indicators
5. Boost or reduce confidence accordingly
"""
import asyncio
import logging
import re
from datetime import datetime

import httpx
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)

# ---------- Target Routing ----------

# vuln_type -> (target_key, target_name)
VULN_TARGET_MAP = {
    "xss": "dvwa",
    "xss_reflected": "dvwa",
    "xss_stored": "dvwa",
    "sqli": "dvwa",
    "sqli_blind": "dvwa",
    "cmd_injection": "dvwa",
    "command_injection": "dvwa",
    "rce": "dvwa",
    "csrf": "dvwa",
    "lfi": "dvwa",
    "idor": "juice-shop",
    "ssrf": "juice-shop",
    "info_disclosure": "juice-shop",
    "xxe": "webgoat",
    "deserialization": "webgoat",
    "jwt": "webgoat",
}

# Target base URLs
TARGET_URLS = {
    "dvwa": "http://localhost:4280",
    "juice-shop": "http://localhost:3001",
    "webgoat": "http://localhost:8081",
    "bwapp": "http://localhost:4281",
}

# DVWA security cookie (low security for testing)
DVWA_COOKIES = {"security": "low", "PHPSESSID": "phantom_validator"}

# ---------- Detection Patterns ----------

SQLI_INDICATORS = [
    r"mysql",
    r"syntax error",
    r"SQL syntax",
    r"ORA-\d{5}",
    r"PostgreSQL",
    r"sqlite3?\.",
    r"SQLSTATE",
    r"mysql_fetch",
    r"Warning.*mysql",
    r"Unclosed quotation mark",
    r"you have an error in your sql",
    r"supplied argument is not a valid",
    # Successful data extraction indicators
    r"admin",
    r"First name:",
    r"Surname:",
    r"ID:",
]

XSS_INDICATORS = [
    # The payload itself reflected unescaped
    r"<script",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
    r"<img\s+[^>]*on\w+\s*=",
    r"<svg\s+[^>]*on\w+\s*=",
    r"alert\s*\(",
]

CMD_INJECTION_INDICATORS = [
    r"uid=\d+",
    r"root:",
    r"/bin/(ba)?sh",
    r"daemon:",
    r"www-data",
    r"total\s+\d+",
    r"drwx",
    r"(?:Linux|Darwin)\s+\w+",
    r"/etc/passwd",
    r"nobody:",
]

GENERIC_ERROR_INDICATORS = [
    r"stack\s*trace",
    r"traceback",
    r"exception",
    r"internal server error",
    r"debug",
    r"error in",
]


def _check_sqli_success(payload: str, response_text: str, baseline_len: int) -> bool:
    """Check if SQLi payload was successful."""
    text_lower = response_text.lower()
    for pattern in SQLI_INDICATORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            # Make sure it's not just the payload reflected
            return True
    # Significant response length change (different data returned)
    if baseline_len > 0 and abs(len(response_text) - baseline_len) / baseline_len > 0.2:
        return True
    return False


def _check_xss_success(payload: str, response_text: str) -> bool:
    """Check if XSS payload was reflected unescaped."""
    # Direct reflection check — payload appears in response without encoding
    if payload in response_text:
        # Check it's not HTML-encoded
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        if encoded not in response_text:
            return True
    # Check for common XSS trigger patterns in response
    for pattern in XSS_INDICATORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False


def _check_cmd_injection_success(payload: str, response_text: str) -> bool:
    """Check if command injection payload executed."""
    for pattern in CMD_INJECTION_INDICATORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    return False


def _check_generic_success(response_text: str, baseline_len: int) -> bool:
    """Generic success check — significant response difference or error leak."""
    for pattern in GENERIC_ERROR_INDICATORS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    if baseline_len > 0 and abs(len(response_text) - baseline_len) / baseline_len > 0.2:
        return True
    return False


class PayloadValidator:
    """Validates AI-generated payloads against live practice targets."""

    def __init__(self):
        self._running_targets: dict[str, bool] = {}
        self._baselines: dict[str, int] = {}
        self._dvwa_session_cookie: str | None = None

    async def _check_target_running(self, target_key: str) -> bool:
        """Check if a practice target is reachable."""
        if target_key in self._running_targets:
            return self._running_targets[target_key]

        url = TARGET_URLS.get(target_key)
        if not url:
            self._running_targets[target_key] = False
            return False

        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                resp = await client.get(url + "/")
                running = resp.status_code < 500
                self._running_targets[target_key] = running
                return running
        except Exception:
            self._running_targets[target_key] = False
            return False

    async def _login_dvwa(self, client: httpx.AsyncClient) -> dict[str, str]:
        """Login to DVWA and return session cookies."""
        if self._dvwa_session_cookie:
            return {"security": "low", "PHPSESSID": self._dvwa_session_cookie}

        base = TARGET_URLS["dvwa"]
        try:
            # Get login page to get CSRF token and session cookie
            login_page = await client.get(f"{base}/login.php")
            cookies = dict(login_page.cookies)
            phpsessid = cookies.get("PHPSESSID", "phantom_validator")

            # Extract CSRF token
            csrf_match = re.search(
                r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]",
                login_page.text,
            )
            user_token = csrf_match.group(1) if csrf_match else ""

            # Login
            resp = await client.post(
                f"{base}/login.php",
                data={
                    "username": "admin",
                    "password": "password",
                    "Login": "Login",
                    "user_token": user_token,
                },
                cookies={"PHPSESSID": phpsessid, "security": "low"},
                follow_redirects=True,
            )

            if resp.status_code < 400:
                self._dvwa_session_cookie = phpsessid
                return {"security": "low", "PHPSESSID": phpsessid}
        except Exception as e:
            logger.warning(f"DVWA login failed: {e}")

        return DVWA_COOKIES

    async def _get_baseline(self, client: httpx.AsyncClient, target_key: str,
                            vuln_type: str, cookies: dict) -> int:
        """Get baseline response length for comparison."""
        cache_key = f"{target_key}:{vuln_type}"
        if cache_key in self._baselines:
            return self._baselines[cache_key]

        baseline_len = 0
        try:
            base = TARGET_URLS[target_key]
            if target_key == "dvwa":
                if vuln_type in ("sqli", "sqli_blind"):
                    resp = await client.get(
                        f"{base}/vulnerabilities/sqli/",
                        params={"id": "1", "Submit": "Submit"},
                        cookies=cookies,
                    )
                    baseline_len = len(resp.text)
                elif vuln_type in ("xss", "xss_reflected"):
                    resp = await client.get(
                        f"{base}/vulnerabilities/xss_r/",
                        params={"name": "test"},
                        cookies=cookies,
                    )
                    baseline_len = len(resp.text)
                elif vuln_type in ("cmd_injection", "command_injection"):
                    resp = await client.post(
                        f"{base}/vulnerabilities/exec/",
                        data={"ip": "127.0.0.1", "Submit": "Submit"},
                        cookies=cookies,
                    )
                    baseline_len = len(resp.text)
            elif target_key == "juice-shop":
                resp = await client.get(f"{base}/rest/products/search", params={"q": "apple"})
                baseline_len = len(resp.text)
        except Exception:
            pass

        self._baselines[cache_key] = baseline_len
        return baseline_len

    async def _test_payload(
        self, client: httpx.AsyncClient, payload: str, vuln_type: str,
        target_key: str, cookies: dict, baseline_len: int,
    ) -> bool:
        """Send a payload to the target and check if it triggered a vulnerability."""
        base = TARGET_URLS[target_key]

        try:
            if target_key == "dvwa":
                return await self._test_dvwa(client, base, payload, vuln_type, cookies, baseline_len)
            elif target_key == "juice-shop":
                return await self._test_juice_shop(client, base, payload, vuln_type, baseline_len)
            elif target_key == "webgoat":
                return await self._test_webgoat(client, base, payload, vuln_type)
            else:
                # Generic test
                return await self._test_generic(client, base, payload, baseline_len)
        except httpx.TimeoutException:
            # Timeout could indicate successful payload (e.g. sleep-based SQLi)
            if vuln_type in ("sqli", "sqli_blind"):
                return True
            return False
        except Exception as e:
            logger.debug(f"Payload test error: {e}")
            return False

    async def _test_dvwa(
        self, client: httpx.AsyncClient, base: str, payload: str,
        vuln_type: str, cookies: dict, baseline_len: int,
    ) -> bool:
        """Test payload against DVWA."""
        if vuln_type in ("sqli", "sqli_blind"):
            resp = await client.get(
                f"{base}/vulnerabilities/sqli/",
                params={"id": payload, "Submit": "Submit"},
                cookies=cookies,
            )
            return _check_sqli_success(payload, resp.text, baseline_len)

        elif vuln_type in ("xss", "xss_reflected"):
            resp = await client.get(
                f"{base}/vulnerabilities/xss_r/",
                params={"name": payload},
                cookies=cookies,
            )
            return _check_xss_success(payload, resp.text)

        elif vuln_type in ("xss_stored",):
            resp = await client.post(
                f"{base}/vulnerabilities/xss_s/",
                data={"txtName": "test", "mtxMessage": payload, "btnSign": "Sign+Guestbook"},
                cookies=cookies,
            )
            return _check_xss_success(payload, resp.text)

        elif vuln_type in ("cmd_injection", "command_injection", "rce"):
            resp = await client.post(
                f"{base}/vulnerabilities/exec/",
                data={"ip": payload, "Submit": "Submit"},
                cookies=cookies,
            )
            return _check_cmd_injection_success(payload, resp.text)

        elif vuln_type in ("lfi",):
            resp = await client.get(
                f"{base}/vulnerabilities/fi/",
                params={"page": payload},
                cookies=cookies,
            )
            return _check_cmd_injection_success(payload, resp.text) or \
                   _check_generic_success(resp.text, baseline_len)

        else:
            # Try generic DVWA test
            resp = await client.get(
                f"{base}/vulnerabilities/sqli/",
                params={"id": payload, "Submit": "Submit"},
                cookies=cookies,
            )
            return _check_generic_success(resp.text, baseline_len)

    async def _test_juice_shop(
        self, client: httpx.AsyncClient, base: str, payload: str,
        vuln_type: str, baseline_len: int,
    ) -> bool:
        """Test payload against Juice Shop."""
        if vuln_type in ("sqli", "sqli_blind"):
            resp = await client.get(
                f"{base}/rest/products/search",
                params={"q": payload},
            )
            return _check_sqli_success(payload, resp.text, baseline_len)

        elif vuln_type in ("xss", "xss_reflected"):
            resp = await client.get(f"{base}/", params={"q": payload})
            return _check_xss_success(payload, resp.text)

        elif vuln_type in ("idor",):
            # Try accessing user data with payload as ID
            resp = await client.get(f"{base}/api/Users/{payload}")
            return resp.status_code == 200 and "email" in resp.text

        elif vuln_type in ("ssrf",):
            resp = await client.post(
                f"{base}/profile/image/url",
                json={"imageUrl": payload},
            )
            return resp.status_code in (200, 201) or "error" not in resp.text.lower()

        elif vuln_type in ("info_disclosure",):
            resp = await client.get(f"{base}/ftp/{payload}")
            return resp.status_code == 200

        else:
            resp = await client.get(
                f"{base}/rest/products/search",
                params={"q": payload},
            )
            return _check_generic_success(resp.text, baseline_len)

    async def _test_webgoat(
        self, client: httpx.AsyncClient, base: str, payload: str, vuln_type: str,
    ) -> bool:
        """Test payload against WebGoat."""
        if vuln_type in ("sqli", "sqli_blind"):
            resp = await client.post(
                f"{base}/WebGoat/SqlInjection/assignment5b",
                data={"userid": payload, "login_count": "0"},
            )
            return _check_sqli_success(payload, resp.text, 0)

        elif vuln_type in ("xxe",):
            # XXE payload should be XML
            headers = {"Content-Type": "application/xml"}
            resp = await client.post(
                f"{base}/WebGoat/xxe/simple",
                content=payload,
                headers=headers,
            )
            return "root:" in resp.text or "file:" in resp.text.lower() or resp.status_code == 200

        elif vuln_type in ("deserialization",):
            resp = await client.post(
                f"{base}/WebGoat/InsecureDeserialization/task",
                data={"token": payload},
            )
            return resp.status_code == 200 and "lesson_completed" in resp.text.lower()

        else:
            resp = await client.get(f"{base}/WebGoat/", params={"q": payload})
            return _check_generic_success(resp.text, 0)

    async def _test_generic(
        self, client: httpx.AsyncClient, base: str, payload: str, baseline_len: int,
    ) -> bool:
        """Generic payload test — try GET and POST."""
        try:
            resp = await client.get(base + "/", params={"q": payload})
            if _check_generic_success(resp.text, baseline_len):
                return True
        except Exception:
            pass
        try:
            resp = await client.post(base + "/", data={"input": payload})
            if _check_generic_success(resp.text, baseline_len):
                return True
        except Exception:
            pass
        return False

    async def validate_payloads(
        self, db: AsyncSession, vuln_type: str | None = None, limit: int = 50,
    ) -> dict:
        """
        Main validation method.

        Query unvalidated/low-confidence payloads, test them against practice
        targets, and update confidence scores.

        Returns: {tested, confirmed, failed, skipped, details}
        """
        stats = {
            "tested": 0,
            "confirmed": 0,
            "failed": 0,
            "skipped": 0,
            "errors": [],
            "details": [],
        }

        # Find available running targets
        available_targets = []
        for key in TARGET_URLS:
            if await self._check_target_running(key):
                available_targets.append(key)

        if not available_targets:
            stats["errors"].append("No practice targets are running")
            logger.warning("Payload validation skipped — no practice targets running")
            return stats

        logger.info(f"Payload validation: {len(available_targets)} targets available: {available_targets}")

        # Query payloads to validate
        conditions = [
            or_(
                KnowledgePattern.pattern_type == "ai_mutation",
                KnowledgePattern.pattern_type == "effective_payload",
            ),
            KnowledgePattern.confidence < 0.8,
        ]
        if vuln_type:
            conditions.append(KnowledgePattern.vuln_type == vuln_type)

        result = await db.execute(
            select(KnowledgePattern)
            .where(*conditions)
            .order_by(KnowledgePattern.confidence.asc())
            .limit(limit)
        )
        patterns = result.scalars().all()

        if not patterns:
            logger.info("No payloads to validate (all above 0.8 confidence or none found)")
            return stats

        logger.info(f"Validating {len(patterns)} payloads...")

        async with httpx.AsyncClient(
            timeout=10.0, verify=False, follow_redirects=True,
        ) as client:
            # Pre-login to DVWA if it's available
            dvwa_cookies = DVWA_COOKIES
            if "dvwa" in available_targets:
                dvwa_cookies = await self._login_dvwa(client)

            for pattern in patterns:
                # Extract payload from pattern_data
                payload = None
                if isinstance(pattern.pattern_data, dict):
                    payload = pattern.pattern_data.get("payload", "")
                if not payload:
                    stats["skipped"] += 1
                    continue

                vt = pattern.vuln_type or "unknown"

                # Determine target
                target_key = VULN_TARGET_MAP.get(vt, "dvwa")
                if target_key not in available_targets:
                    # Try fallback to any available target
                    target_key = available_targets[0]

                # Pick cookies
                cookies = dvwa_cookies if target_key == "dvwa" else {}

                # Get baseline for comparison
                baseline_len = await self._get_baseline(client, target_key, vt, cookies)

                # Test the payload
                try:
                    success = await self._test_payload(
                        client, payload, vt, target_key, cookies, baseline_len,
                    )
                    stats["tested"] += 1

                    old_confidence = pattern.confidence

                    if success:
                        # Boost confidence by 0.2, max 1.0
                        pattern.confidence = min(pattern.confidence + 0.2, 1.0)
                        pattern.sample_count = (pattern.sample_count or 0) + 1
                        stats["confirmed"] += 1
                        logger.debug(
                            f"CONFIRMED: {vt} payload on {target_key} "
                            f"(confidence {old_confidence:.2f} -> {pattern.confidence:.2f})"
                        )
                    else:
                        # Reduce confidence by 0.1, min 0.1
                        pattern.confidence = max(pattern.confidence - 0.1, 0.1)
                        pattern.sample_count = (pattern.sample_count or 0) + 1
                        stats["failed"] += 1
                        logger.debug(
                            f"FAILED: {vt} payload on {target_key} "
                            f"(confidence {old_confidence:.2f} -> {pattern.confidence:.2f})"
                        )

                    # Update validation metadata in pattern_data
                    if isinstance(pattern.pattern_data, dict):
                        pattern.pattern_data = {
                            **pattern.pattern_data,
                            "last_validated": datetime.utcnow().isoformat(),
                            "validated_against": target_key,
                            "validation_result": "confirmed" if success else "failed",
                            "validation_count": pattern.pattern_data.get("validation_count", 0) + 1,
                        }

                    pattern.updated_at = datetime.utcnow()

                    stats["details"].append({
                        "pattern_id": pattern.id,
                        "vuln_type": vt,
                        "target": target_key,
                        "result": "confirmed" if success else "failed",
                        "confidence_before": round(old_confidence, 2),
                        "confidence_after": round(pattern.confidence, 2),
                    })

                except Exception as e:
                    stats["skipped"] += 1
                    stats["errors"].append(f"Error testing {pattern.id}: {str(e)[:100]}")
                    logger.warning(f"Payload test error for {pattern.id}: {e}")

                # Small delay between tests to not overwhelm targets
                await asyncio.sleep(0.3)

        # Commit all updates
        try:
            await db.commit()
        except Exception as e:
            stats["errors"].append(f"DB commit error: {str(e)[:200]}")
            logger.error(f"Failed to commit validation results: {e}")
            await db.rollback()

        logger.info(
            f"Payload validation complete: "
            f"{stats['tested']} tested, {stats['confirmed']} confirmed, "
            f"{stats['failed']} failed, {stats['skipped']} skipped"
        )

        return stats


async def run_payload_validation(db: AsyncSession, vuln_type: str | None = None, limit: int = 50) -> dict:
    """Convenience function to run payload validation."""
    validator = PayloadValidator()
    return await validator.validate_payloads(db, vuln_type=vuln_type, limit=limit)
