"""
Insecure Deserialization Detection Module

Tests for:
1. Java deserialization (ysoserial-style gadget chains via HTTP)
2. PHP object injection (O: serialized objects)
3. Python pickle injection
4. .NET ViewState deserialization
5. Cookie/header-based deserialization vectors
"""
import asyncio
import base64
import logging
import re
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Java serialized object magic bytes (AC ED 00 05)
JAVA_MAGIC = b"\xac\xed\x00\x05"
JAVA_MAGIC_B64 = base64.b64encode(JAVA_MAGIC).decode()  # rO0ABQ==

# PHP serialized object patterns
PHP_PAYLOADS = [
    # Attempt to trigger __wakeup / __destruct
    'O:8:"stdClass":0:{}',
    'a:1:{s:4:"test";O:8:"stdClass":0:{}}',
    # Timing-based: trigger error with non-existent class
    'O:21:"PhantomDeserialTest":0:{}',
    # Nested object
    'O:8:"stdClass":1:{s:4:"data";O:8:"stdClass":0:{}}',
]

# Python pickle payloads (safe — just trigger identifiable response)
# These are NOT executing code — just testing if pickle.loads is called
PYTHON_PICKLE_MARKERS = [
    # cos\nsystem\n marker — if deserialized, triggers identifiable error
    base64.b64encode(b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x8c\x04repr\x93\x8c\x05pHnT0\x85R.").decode(),
]

# .NET ViewState indicators
VIEWSTATE_INDICATORS = [
    "__VIEWSTATE",
    "__VIEWSTATEGENERATOR",
    "__EVENTVALIDATION",
]

# Headers/cookies that may contain serialized data
DESER_VECTORS = [
    "Cookie",
    "X-Session",
    "X-Token",
    "Authorization",
]

# Java deserialization error indicators
JAVA_DESER_ERRORS = [
    "java.io.InvalidClassException",
    "java.io.StreamCorruptedException",
    "java.lang.ClassNotFoundException",
    "ClassCastException",
    "ObjectInputStream",
    "java.io.NotSerializableException",
    "readObject",
    "InvalidObjectException",
    "java.rmi",
    "org.apache.commons.collections",
    "InvocationTargetException",
]

PHP_DESER_ERRORS = [
    "unserialize()",
    "__PHP_Incomplete_Class",
    "Notice: unserialize",
    "Warning: unserialize",
    "Object of class __PHP_Incomplete_Class",
    "allowed_classes",
]

PYTHON_DESER_ERRORS = [
    "pickle.UnpicklingError",
    "unpickling",
    "_pickle.UnpicklingError",
    "can't pickle",
    "ModuleNotFoundError",
    "ImportError",
]


class DeserializationModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        endpoints = context.get("endpoints", [])
        base_url = context.get("base_url", "")
        auth_cookie = context.get("auth_cookie")
        technologies = context.get("technologies", {})
        findings = []

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        # Detect tech stack to prioritize checks
        tech_summary = technologies.get("summary", {})
        tech_str = " ".join(str(k).lower() for k in tech_summary.keys())

        async with make_client(extra_headers=headers) as client:
            # Check for Java deserialization
            if any(t in tech_str for t in ("java", "tomcat", "spring", "jboss", "weblogic", "websphere")):
                java_findings = await self._check_java_deser(client, base_url, endpoints)
                findings.extend(java_findings)

            # Check for PHP deserialization
            if any(t in tech_str for t in ("php", "laravel", "wordpress", "drupal", "symfony")):
                php_findings = await self._check_php_deser(client, base_url, endpoints)
                findings.extend(php_findings)

            # Always check for Python deserialization
            python_findings = await self._check_python_deser(client, base_url, endpoints)
            findings.extend(python_findings)

            # Check for .NET ViewState
            viewstate_findings = await self._check_viewstate(client, base_url, endpoints)
            findings.extend(viewstate_findings)

            # Check cookies for serialized data
            cookie_findings = await self._check_cookie_deser(client, base_url, endpoints)
            findings.extend(cookie_findings)

        return findings

    async def _check_java_deser(self, client, base_url, endpoints) -> list[dict]:
        """Send Java serialized magic bytes to detect deserialization endpoints."""
        findings = []
        # Target endpoints that accept binary/octet-stream data
        test_urls = [base_url]
        for ep in endpoints[:20]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url:
                test_urls.append(url)

        # Send serialized Java object marker
        java_payload = JAVA_MAGIC + b"\x73\x72\x00\x11PhantomDeserTest"
        java_b64 = base64.b64encode(java_payload).decode()

        for url in test_urls[:10]:
            try:
                # Test via POST body
                async with self.rate_limit:
                    resp = await client.post(
                        url,
                        content=java_payload,
                        headers={"Content-Type": "application/x-java-serialized-object"},
                    )
                    body = resp.text
                    if any(err in body for err in JAVA_DESER_ERRORS):
                        findings.append({
                            "title": f"Java Deserialization: {urlparse(url).path}",
                            "url": url,
                            "severity": "critical",
                            "vuln_type": "rce",
                            "payload": "Java serialized object (AC ED 00 05)",
                            "error_indicator": next(e for e in JAVA_DESER_ERRORS if e in body),
                            "impact": "Server deserializes Java objects. "
                                     "Attacker can craft gadget chains for Remote Code Execution.",
                            "remediation": "Never deserialize untrusted data. Use allowlists for permitted classes. "
                                          "Consider using JSON instead of Java serialization.",
                        })
                        break

                # Test via cookie/header with base64
                async with self.rate_limit:
                    resp2 = await client.get(
                        url,
                        headers={"X-Session-Data": java_b64},
                        cookies={"session": java_b64},
                    )
                    body2 = resp2.text
                    if any(err in body2 for err in JAVA_DESER_ERRORS):
                        findings.append({
                            "title": f"Java Deserialization via Cookie/Header: {urlparse(url).path}",
                            "url": url,
                            "severity": "critical",
                            "vuln_type": "rce",
                            "payload": f"Base64 Java object in cookie: {java_b64[:30]}...",
                            "impact": "Server deserializes Java objects from cookies/headers. "
                                     "Critical RCE vector via gadget chains.",
                            "remediation": "Do not deserialize user-controlled data.",
                        })
                        break

            except Exception:
                continue

        return findings

    async def _check_php_deser(self, client, base_url, endpoints) -> list[dict]:
        """Test for PHP unserialize() vulnerabilities."""
        findings = []

        # Find endpoints that accept data via POST or have interesting params
        test_targets = []
        for ep in endpoints[:20]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            method = "GET" if isinstance(ep, str) else ep.get("method", "GET")
            if url:
                test_targets.append({"url": url, "method": method})

        for target in test_targets[:10]:
            url = target["url"]
            for payload in PHP_PAYLOADS:
                try:
                    # Test via query parameter
                    async with self.rate_limit:
                        resp = await client.get(url, params={"data": payload})
                        body = resp.text
                        if any(err in body for err in PHP_DESER_ERRORS):
                            findings.append({
                                "title": f"PHP Object Injection: {urlparse(url).path}",
                                "url": url,
                                "severity": "high",
                                "vuln_type": "rce",
                                "payload": payload,
                                "error_indicator": next(e for e in PHP_DESER_ERRORS if e in body),
                                "impact": "Server calls unserialize() on user input. "
                                         "Attacker can exploit magic methods (__wakeup, __destruct) for RCE.",
                                "remediation": "Use json_decode() instead of unserialize(). "
                                              "If unserialize is needed, use allowed_classes option.",
                            })
                            return findings  # One proof is enough

                    # Test via POST body
                    if target["method"] in ("POST", "PUT"):
                        async with self.rate_limit:
                            resp2 = await client.post(url, data={"data": payload})
                            body2 = resp2.text
                            if any(err in body2 for err in PHP_DESER_ERRORS):
                                findings.append({
                                    "title": f"PHP Object Injection (POST): {urlparse(url).path}",
                                    "url": url,
                                    "severity": "high",
                                    "vuln_type": "rce",
                                    "payload": payload,
                                    "impact": "PHP unserialize() called on POST data.",
                                    "remediation": "Replace unserialize() with json_decode().",
                                })
                                return findings

                except Exception:
                    continue

        return findings

    async def _check_python_deser(self, client, base_url, endpoints) -> list[dict]:
        """Test for Python pickle deserialization."""
        findings = []

        for ep in endpoints[:10]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if not url:
                continue

            for pickle_b64 in PYTHON_PICKLE_MARKERS:
                try:
                    # Via POST body
                    async with self.rate_limit:
                        resp = await client.post(
                            url,
                            content=base64.b64decode(pickle_b64),
                            headers={"Content-Type": "application/octet-stream"},
                        )
                        body = resp.text
                        if any(err in body for err in PYTHON_DESER_ERRORS):
                            findings.append({
                                "title": f"Python Pickle Deserialization: {urlparse(url).path}",
                                "url": url,
                                "severity": "critical",
                                "vuln_type": "rce",
                                "payload": f"Pickle payload (base64): {pickle_b64[:30]}...",
                                "impact": "Server deserializes Python pickle data. "
                                         "pickle.loads() allows arbitrary code execution.",
                                "remediation": "Never use pickle with untrusted data. Use JSON instead.",
                            })
                            return findings

                    # Via cookie
                    async with self.rate_limit:
                        resp2 = await client.get(
                            url,
                            cookies={"session": pickle_b64},
                        )
                        body2 = resp2.text
                        if any(err in body2 for err in PYTHON_DESER_ERRORS):
                            findings.append({
                                "title": f"Python Pickle via Cookie: {urlparse(url).path}",
                                "url": url,
                                "severity": "critical",
                                "vuln_type": "rce",
                                "payload": "Pickle payload in session cookie",
                                "impact": "Session cookie deserialized via pickle.loads(). "
                                         "Direct RCE vector.",
                                "remediation": "Use signed/encrypted JSON sessions instead of pickle.",
                            })
                            return findings

                except Exception:
                    continue

        return findings

    async def _check_viewstate(self, client, base_url, endpoints) -> list[dict]:
        """Check for .NET ViewState deserialization issues."""
        findings = []

        test_urls = [base_url]
        for ep in endpoints[:15]:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if url and url.lower().endswith((".aspx", ".asp")):
                test_urls.append(url)

        for url in test_urls[:10]:
            try:
                async with self.rate_limit:
                    resp = await client.get(url)
                    body = resp.text

                    has_viewstate = "__VIEWSTATE" in body
                    has_mac = "__VIEWSTATEGENERATOR" in body

                    if has_viewstate:
                        # Extract ViewState value
                        vs_match = re.search(
                            r'__VIEWSTATE[^>]*value="([^"]*)"', body
                        )
                        vs_value = vs_match.group(1) if vs_match else ""

                        # Check if ViewState MAC is disabled
                        # (unprotected ViewState is exploitable)
                        if vs_value:
                            try:
                                decoded = base64.b64decode(vs_value)
                                # If it starts with 0xFF 0x01, MAC validation may be disabled
                                if decoded[:2] == b"\xff\x01":
                                    findings.append({
                                        "title": f"ViewState MAC Disabled: {urlparse(url).path}",
                                        "url": url,
                                        "severity": "critical",
                                        "vuln_type": "rce",
                                        "impact": "ViewState MAC validation is disabled. "
                                                 "Attacker can craft malicious ViewState for RCE "
                                                 "via ObjectStateFormatter deserialization.",
                                        "remediation": "Enable ViewState MAC validation: "
                                                      "set enableViewStateMac='true' in web.config.",
                                    })
                            except Exception:
                                pass

                        # ViewState present without encryption is still noteworthy
                        if not any(f["url"] == url for f in findings):
                            # Check if ViewState contains sensitive-looking data
                            if vs_value and len(vs_value) > 100:
                                findings.append({
                                    "title": f"ViewState Present: {urlparse(url).path}",
                                    "url": url,
                                    "severity": "low",
                                    "vuln_type": "info_disclosure",
                                    "viewstate_size": len(vs_value),
                                    "impact": "ASP.NET ViewState is present. While MAC may be enabled, "
                                             "ViewState can leak internal state if not encrypted.",
                                    "remediation": "Enable ViewState encryption in addition to MAC validation.",
                                })

            except Exception:
                continue

        return findings

    async def _check_cookie_deser(self, client, base_url, endpoints) -> list[dict]:
        """Check if cookies contain serialized data (base64-encoded objects)."""
        findings = []

        try:
            async with self.rate_limit:
                resp = await client.get(base_url)
                for cookie_header in resp.headers.get_list("set-cookie"):
                    name = cookie_header.split("=")[0].strip()
                    value = cookie_header.split("=", 1)[1].split(";")[0].strip()

                    if not value or len(value) < 20:
                        continue

                    # Try base64 decode
                    try:
                        decoded = base64.b64decode(value)

                        # Check for Java serialization
                        if decoded[:4] == JAVA_MAGIC:
                            findings.append({
                                "title": f"Java Serialized Cookie: {name}",
                                "url": base_url,
                                "severity": "high",
                                "vuln_type": "rce",
                                "cookie_name": name,
                                "impact": f"Cookie '{name}' contains Java serialized data. "
                                         "Potential deserialization RCE vector.",
                                "remediation": "Do not store serialized Java objects in cookies.",
                            })

                        # Check for PHP serialized data
                        decoded_str = decoded.decode("utf-8", errors="ignore")
                        if re.match(r'^[aOsbi]:\d+', decoded_str):
                            findings.append({
                                "title": f"PHP Serialized Cookie: {name}",
                                "url": base_url,
                                "severity": "medium",
                                "vuln_type": "rce",
                                "cookie_name": name,
                                "impact": f"Cookie '{name}' contains PHP serialized data. "
                                         "If unserialize() is used, object injection possible.",
                                "remediation": "Use JSON for cookie data instead of PHP serialize().",
                            })

                        # Check for Python pickle
                        if decoded[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
                            findings.append({
                                "title": f"Python Pickle Cookie: {name}",
                                "url": base_url,
                                "severity": "critical",
                                "vuln_type": "rce",
                                "cookie_name": name,
                                "impact": f"Cookie '{name}' contains Python pickle data. "
                                         "Direct RCE via crafted pickle payload.",
                                "remediation": "Never use pickle for cookies. Use signed JSON (itsdangerous/JWT).",
                            })

                    except Exception:
                        pass

                    # Check raw value for PHP serialization
                    if re.match(r'^[aOsbi]:\d+', value):
                        findings.append({
                            "title": f"PHP Serialized Cookie (raw): {name}",
                            "url": base_url,
                            "severity": "medium",
                            "vuln_type": "rce",
                            "cookie_name": name,
                            "impact": f"Cookie '{name}' contains raw PHP serialized data.",
                            "remediation": "Use JSON for cookie data.",
                        })

        except Exception as e:
            logger.debug(f"Cookie deserialization check error: {e}")

        return findings
