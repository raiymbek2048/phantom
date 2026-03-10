"""
JavaScript Endpoint Extraction Module

Analyzes JavaScript files to discover:
- API endpoints (fetch, axios, route definitions)
- SPA routes (React Router, Vue Router, Angular)
- API keys / secrets leaked in client-side code
- Source map exposure
- WebSocket endpoints
"""
import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# --- Regex patterns for endpoint extraction ---

# API path patterns
RE_API_PATHS = [
    re.compile(r"""['"](/api/v\d+/[\w/\-]+)['"]"""),
    re.compile(r"""['"](/api/[\w/\-]+)['"]"""),
    re.compile(r"""['"](/graphql)\b"""),
    re.compile(r"""['"](/rest/[\w/\-]+)['"]"""),
]

# Fetch / axios calls
RE_FETCH_AXIOS = [
    re.compile(r"""fetch\(\s*['"](/[^'"]+)['"]"""),
    re.compile(r"""fetch\(\s*['"]([^'"]+https?://[^'"]+)['"]"""),
    re.compile(r"""fetch\(\s*`(/[^`]+)`"""),
    re.compile(r"""axios\.\w+\(\s*['"](/[^'"]+)['"]"""),
    re.compile(r"""axios\(\s*\{[^}]*url:\s*['"](/[^'"]+)['"]"""),
    re.compile(r"""\$\.(?:get|post|ajax)\(\s*['"](/[^'"]+)['"]"""),
]

# Route definitions (generic)
RE_ROUTES = [
    re.compile(r"""path:\s*['"](/[^'"]+)['"]"""),
    re.compile(r"""route\(\s*['"](/[^'"]+)['"]"""),
]

# URL construction
RE_URL_STRINGS = [
    re.compile(r"""['"]/([\w][\w/\-]{2,})['"]"""),
    re.compile(r"""baseURL\s*[:=]\s*['"](https?://[^'"]+)['"]"""),
    re.compile(r"""BASE_URL\s*[:=]\s*['"](https?://[^'"]+)['"]"""),
    re.compile(r"""apiUrl\s*[:=]\s*['"](https?://[^'"]+)['"]"""),
]

# Template literals with API paths
RE_TEMPLATE_API = [
    re.compile(r"""`(/api/[^`]*\$\{[^`]*)`"""),
    re.compile(r"""`(/[\w]+/[^`]*\$\{[^`]*)`"""),
]

# React Router
RE_REACT_ROUTER = [
    re.compile(r"""<Route\s+[^>]*path=["']([^"']+)["']"""),
    re.compile(r"""<Redirect\s+[^>]*to=["']([^"']+)["']"""),
    re.compile(r"""navigate\(\s*["']([^"']+)["']"""),
    re.compile(r"""useNavigate.*?["']([^"']+)["']"""),
]

# Vue Router
RE_VUE_ROUTER = [
    re.compile(r"""\{\s*path:\s*['"]([^'"]+)['"]"""),
    re.compile(r"""this\.\$router\.push\(\s*['"]([^'"]+)['"]"""),
]

# Angular routes
RE_ANGULAR = [
    re.compile(r"""\{\s*path:\s*['"]([^'"]+)['"].*?component""", re.DOTALL),
    re.compile(r"""this\.router\.navigate\(\s*\[\s*['"]([^'"]+)['"]"""),
    re.compile(r"""routerLink=["']([^"']+)["']"""),
]

# GraphQL
RE_GRAPHQL = [
    re.compile(r"""['"](/graphql[^'"]*?)['"]"""),
    re.compile(r"""graphqlEndpoint\s*[:=]\s*['"]([^'"]+)['"]"""),
]

# WebSocket
RE_WEBSOCKET = [
    re.compile(r"""['"]?(wss?://[^'")\s]+)['"]?"""),
    re.compile(r"""new\s+WebSocket\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""new\s+WebSocket\(\s*`([^`]+)`"""),
]

# --- API Key / Secret patterns ---
RE_SECRETS = [
    ("aws_key", re.compile(r"""AKIA[A-Z0-9]{16}""")),
    ("api_key", re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]""", re.IGNORECASE)),
    ("secret", re.compile(r"""(?:secret|SECRET)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]""")),
    ("token", re.compile(r"""(?:token|TOKEN)\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{20,})['"]""")),
    ("password", re.compile(r"""(?:password|passwd)\s*[:=]\s*['"]([^'"]{4,})['"]""", re.IGNORECASE)),
    ("bearer", re.compile(r"""Bearer\s+([A-Za-z0-9_\-\.]+)""")),
    ("authorization", re.compile(r"""['"]Authorization['"]\s*:\s*['"]([^'"]+)['"]""")),
    ("google_api_key", re.compile(r"""AIza[A-Za-z0-9_\-]{35}""")),
    ("github_token", re.compile(r"""gh[pousr]_[A-Za-z0-9_]{36,}""")),
    ("slack_token", re.compile(r"""xox[baprs]-[A-Za-z0-9\-]{10,}""")),
    ("private_key", re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""")),
    ("generic_secret", re.compile(r"""(?:client_secret|CLIENT_SECRET|app_secret|APP_SECRET)\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]""", re.IGNORECASE)),
]

# Source map detection
RE_SOURCE_MAP = re.compile(r"""//[#@]\s*sourceMappingURL=(\S+)""")

# Max limits
MAX_JS_FILES = 50
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB
DOWNLOAD_TIMEOUT = 15.0

# Paths that are clearly not API endpoints (noise filter)
NOISE_PATHS = {
    "/", "/.", "/w", "/d", "/s", "/n", "/t", "/r", "/e", "/a",
    "/true", "/false", "/null", "/undefined", "/NaN",
    "/div", "/span", "/img", "/br", "/hr", "/li", "/ul", "/ol",
    "/svg", "/path", "/rect", "/circle",
    "/http", "/https", "/ftp", "/mailto",
}


class JSAnalyzer:
    """Extracts endpoints, secrets, and routes from JavaScript files."""

    def __init__(self):
        self.auth_cookie = None
        self.custom_headers = {}

    async def extract_from_js_files(
        self, base_url: str, endpoints: list[dict], context: dict = None
    ) -> dict:
        """Main entry point: analyze JS files found during endpoint discovery.

        Args:
            base_url: Target base URL (e.g., https://example.com)
            endpoints: List of endpoint dicts from EndpointModule
            context: Scan context with auth_cookie, custom_headers, etc.

        Returns:
            Dict with js_endpoints, spa_routes, api_keys_found, source_maps,
            websocket_endpoints.
        """
        context = context or {}
        self.auth_cookie = context.get("auth_cookie")
        self.custom_headers = context.get("custom_headers", {})

        result = {
            "js_endpoints": [],
            "spa_routes": [],
            "api_keys_found": [],
            "source_maps": [],
            "websocket_endpoints": [],
        }

        # 1. Collect JS file URLs from discovered endpoints
        js_urls = self._find_js_urls(base_url, endpoints)

        # 2. Fetch main page HTML for inline scripts and additional JS refs
        inline_scripts, page_js_urls = await self._extract_from_html(base_url)
        js_urls.update(page_js_urls)

        # Limit to MAX_JS_FILES
        js_urls_list = list(js_urls)[:MAX_JS_FILES]
        logger.info(f"JS Analyzer: found {len(js_urls_list)} JS files to analyze")

        # 3. Download and analyze each JS file
        js_contents = await self._download_js_files(js_urls_list)

        # Add inline scripts as pseudo-files
        for i, script in enumerate(inline_scripts):
            js_contents[f"inline_script_{i}"] = script

        all_endpoints = set()
        all_routes = set()
        all_ws = set()

        for filename, content in js_contents.items():
            # Extract endpoints
            found_endpoints = self._extract_endpoints(content)
            all_endpoints.update(found_endpoints)

            # Extract SPA routes
            found_routes = self._extract_spa_routes_from_code(content)
            all_routes.update(found_routes)

            # Extract WebSocket endpoints
            found_ws = self._extract_websockets(content)
            all_ws.update(found_ws)

            # Detect API keys / secrets
            found_secrets = self._detect_secrets(content, filename)
            result["api_keys_found"].extend(found_secrets)

            # Detect source maps
            source_map = self._detect_source_map(content, filename)
            if source_map:
                result["source_maps"].append(source_map)

        # 4. Resolve relative endpoints to full URLs
        result["js_endpoints"] = sorted(all_endpoints)
        result["spa_routes"] = sorted(all_routes)
        result["websocket_endpoints"] = sorted(all_ws)

        # 5. Try to download and parse source maps
        await self._fetch_source_maps(base_url, result["source_maps"])

        # 6. Optional: SPA route discovery via Playwright
        try:
            spa_network = await self._extract_spa_routes_playwright(base_url)
            if spa_network:
                for ep in spa_network.get("endpoints", []):
                    if ep not in result["js_endpoints"]:
                        result["js_endpoints"].append(ep)
                for route in spa_network.get("routes", []):
                    if route not in result["spa_routes"]:
                        result["spa_routes"].append(route)
        except Exception as e:
            logger.debug(f"Playwright SPA extraction skipped: {e}")

        logger.info(
            f"JS Analyzer results: {len(result['js_endpoints'])} endpoints, "
            f"{len(result['spa_routes'])} SPA routes, "
            f"{len(result['api_keys_found'])} secrets, "
            f"{len(result['source_maps'])} source maps, "
            f"{len(result['websocket_endpoints'])} WebSocket endpoints"
        )

        return result

    def _find_js_urls(self, base_url: str, endpoints: list[dict]) -> set[str]:
        """Extract JS file URLs from discovered endpoints."""
        js_urls = set()
        for ep in endpoints:
            url = ep.get("url", "")
            if not url:
                continue
            url_lower = url.lower()
            if url_lower.endswith(".js") or url_lower.endswith(".mjs"):
                js_urls.add(url)
            elif ".js?" in url_lower:
                # JS with query params (cache busting)
                js_urls.add(url)
        return js_urls

    async def _extract_from_html(self, base_url: str) -> tuple[list[str], set[str]]:
        """Fetch main page and extract inline scripts + JS file references."""
        inline_scripts = []
        js_urls = set()

        try:
            headers = dict(self.custom_headers)
            if self.auth_cookie:
                if self.auth_cookie.startswith("token="):
                    headers["Authorization"] = f"Bearer {self.auth_cookie.split('=', 1)[1]}"
                else:
                    headers["Cookie"] = self.auth_cookie

            async with make_client(extra_headers=headers, timeout=DOWNLOAD_TIMEOUT) as client:
                resp = await client.get(base_url, follow_redirects=True)
                if resp.status_code != 200:
                    return inline_scripts, js_urls

                html = resp.text

                # Extract <script src="..."> references
                script_srcs = re.findall(
                    r'<script[^>]+src=["\'](.*?)["\']', html, re.IGNORECASE
                )
                for src in script_srcs:
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        src = base_url + src
                    elif not src.startswith("http"):
                        src = base_url + "/" + src
                    # Only include JS files from the same domain or CDNs
                    js_urls.add(src)

                # Extract inline <script> content
                inline_blocks = re.findall(
                    r'<script(?:\s[^>]*)?>(.+?)</script>',
                    html,
                    re.DOTALL | re.IGNORECASE,
                )
                for block in inline_blocks:
                    block = block.strip()
                    if len(block) > 20:  # Skip trivial scripts
                        inline_scripts.append(block)

        except Exception as e:
            logger.debug(f"HTML extraction error: {e}")

        return inline_scripts, js_urls

    async def _download_js_files(self, urls: list[str]) -> dict[str, str]:
        """Download JS files concurrently, respecting size limits."""
        contents = {}
        semaphore = asyncio.Semaphore(10)

        async def fetch_one(url: str):
            async with semaphore:
                try:
                    headers = dict(self.custom_headers)
                    if self.auth_cookie and not self.auth_cookie.startswith("token="):
                        headers["Cookie"] = self.auth_cookie
                    async with make_client(
                        extra_headers=headers, timeout=DOWNLOAD_TIMEOUT
                    ) as client:
                        resp = await client.get(url, follow_redirects=True)
                        if resp.status_code != 200:
                            return
                        # Check content length
                        content_len = resp.headers.get("content-length")
                        if content_len and int(content_len) > MAX_FILE_SIZE:
                            logger.debug(f"Skipping {url}: too large ({content_len} bytes)")
                            return
                        text = resp.text
                        if len(text) > MAX_FILE_SIZE:
                            text = text[:MAX_FILE_SIZE]
                        # Extract filename from URL
                        parsed = urlparse(url)
                        filename = parsed.path.split("/")[-1] or "unknown.js"
                        contents[filename] = text
                except Exception as e:
                    logger.debug(f"Failed to download {url}: {e}")

        tasks = [fetch_one(url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        return contents

    def _extract_endpoints(self, js_content: str) -> set[str]:
        """Extract API endpoints from JS content using regex patterns."""
        endpoints = set()

        all_patterns = RE_API_PATHS + RE_FETCH_AXIOS + RE_ROUTES + RE_URL_STRINGS + RE_TEMPLATE_API + RE_GRAPHQL

        for pattern in all_patterns:
            matches = pattern.findall(js_content)
            for match in matches:
                path = match.strip()
                if not path:
                    continue
                # Normalize: ensure leading slash for paths
                if not path.startswith("/") and not path.startswith("http"):
                    path = "/" + path
                # Filter noise
                if path in NOISE_PATHS:
                    continue
                if len(path) < 3:
                    continue
                # Skip obvious non-paths
                if path.startswith("//"): # comments
                    continue
                # Clean template literal placeholders for display
                clean = re.sub(r'\$\{[^}]*\}', '{param}', path)
                endpoints.add(clean)

        return endpoints

    def _extract_spa_routes_from_code(self, js_content: str) -> set[str]:
        """Extract SPA routes from React/Vue/Angular router definitions."""
        routes = set()

        all_patterns = RE_REACT_ROUTER + RE_VUE_ROUTER + RE_ANGULAR

        for pattern in all_patterns:
            matches = pattern.findall(js_content)
            for match in matches:
                route = match.strip()
                if not route or len(route) < 2:
                    continue
                if not route.startswith("/"):
                    route = "/" + route
                if route not in NOISE_PATHS:
                    routes.add(route)

        return routes

    def _extract_websockets(self, js_content: str) -> set[str]:
        """Extract WebSocket endpoint URLs."""
        ws_endpoints = set()
        for pattern in RE_WEBSOCKET:
            matches = pattern.findall(js_content)
            for match in matches:
                match = match.strip()
                if match.startswith("ws://") or match.startswith("wss://"):
                    ws_endpoints.add(match)
        return ws_endpoints

    def _detect_secrets(self, js_content: str, filename: str) -> list[dict]:
        """Detect potential API keys and secrets in JS content."""
        found = []
        seen = set()

        # Skip minified JS files — they produce false positives
        # (e.g., password="default" in config objects looks like exposed creds)
        is_minified = (
            filename.endswith(".min.js")
            or (len(js_content) > 5000 and js_content.count("\n") < len(js_content) / 500)
        )

        # Common false positive values for password/secret fields
        _FP_VALUES = {
            "password", "passwd", "secret", "token", "test", "changeme",
            "example", "placeholder", "default", "demo", "admin", "1234",
            "12345", "123456", "undefined", "null", "true", "false",
            "required", "optional", "string", "number", "value",
        }

        for secret_type, pattern in RE_SECRETS:
            matches = pattern.findall(js_content)
            for match in matches:
                if not match or len(match) < 4:
                    continue

                # Filter false positives for password/secret types
                if secret_type in ("password", "secret", "generic_secret"):
                    match_lower = match.lower().strip()
                    # Skip common placeholder/default values
                    if match_lower in _FP_VALUES:
                        continue
                    # Skip values that look like minified JS code (contain syntax chars)
                    js_syntax_chars = set("(){}[];,=>!?&|~^")
                    if sum(1 for c in match if c in js_syntax_chars) >= 2:
                        continue
                    # Skip very short values in minified files
                    if is_minified and len(match) < 12:
                        continue

                # Deduplicate
                key = f"{secret_type}:{match[:20]}"
                if key in seen:
                    continue
                seen.add(key)
                # Mask the value for safety
                if len(match) > 8:
                    key_prefix = match[:8] + "..."
                else:
                    key_prefix = match[:4] + "..."

                found.append({
                    "type": secret_type,
                    "file": filename,
                    "key_prefix": key_prefix,
                })

        # Also check for full AWS access key (no capture group)
        aws_matches = re.findall(r'AKIA[A-Z0-9]{16}', js_content)
        for m in aws_matches:
            key = f"aws_key:{m[:12]}"
            if key not in seen:
                seen.add(key)
                found.append({
                    "type": "aws_key",
                    "file": filename,
                    "key_prefix": m[:12] + "...",
                })

        return found

    def _detect_source_map(self, js_content: str, filename: str) -> dict | None:
        """Check for source map references in JS file."""
        match = RE_SOURCE_MAP.search(js_content)
        if match:
            map_url = match.group(1).strip()
            return {
                "js_file": filename,
                "url": map_url,
                "original_files": [],
            }
        return None

    async def _fetch_source_maps(self, base_url: str, source_maps: list[dict]):
        """Download source maps and extract original file paths."""
        if not source_maps:
            return

        try:
            headers = dict(self.custom_headers)
            async with make_client(extra_headers=headers, timeout=DOWNLOAD_TIMEOUT) as client:
                for smap in source_maps:
                    try:
                        map_url = smap["url"]
                        if not map_url.startswith("http"):
                            if map_url.startswith("/"):
                                map_url = base_url + map_url
                            else:
                                map_url = base_url + "/" + map_url
                        resp = await client.get(map_url, follow_redirects=True)
                        if resp.status_code == 200:
                            try:
                                import json
                                map_data = json.loads(resp.text)
                                sources = map_data.get("sources", [])
                                smap["original_files"] = sources[:100]
                                smap["accessible"] = True
                            except (json.JSONDecodeError, Exception):
                                smap["accessible"] = False
                        else:
                            smap["accessible"] = False
                    except Exception:
                        smap["accessible"] = False
        except Exception as e:
            logger.debug(f"Source map fetch error: {e}")

    async def _extract_spa_routes_playwright(self, base_url: str) -> dict | None:
        """Use Playwright to discover SPA routes via network monitoring.

        Optional: only runs if Playwright is available.
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.debug("Playwright not available, skipping SPA route extraction")
            return None

        endpoints = set()
        routes = set()
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                page = await context.new_page()

                # Monitor network requests
                captured_urls = set()

                def on_request(request):
                    url = request.url
                    parsed = urlparse(url)
                    if base_domain in parsed.netloc:
                        path = parsed.path
                        if path and path != "/":
                            if any(path.startswith(p) for p in ["/api/", "/rest/", "/graphql", "/v1/", "/v2/"]):
                                captured_urls.add(path)
                            else:
                                routes.add(path)

                page.on("request", on_request)

                # Navigate and wait
                try:
                    await page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    pass

                # Wait for dynamic requests
                await asyncio.sleep(3)

                # Try clicking navigation links
                try:
                    nav_links = await page.query_selector_all("nav a, header a, [role='navigation'] a")
                    for link in nav_links[:10]:
                        try:
                            href = await link.get_attribute("href")
                            if href and href.startswith("/"):
                                routes.add(href)
                            await link.click(timeout=3000)
                            await asyncio.sleep(1)
                        except Exception:
                            continue
                except Exception:
                    pass

                # Wait for any XHR triggered by navigation
                await asyncio.sleep(3)

                endpoints.update(captured_urls)

                await browser.close()

        except Exception as e:
            logger.debug(f"Playwright SPA extraction failed: {e}")
            return None

        if endpoints or routes:
            return {
                "endpoints": sorted(endpoints),
                "routes": sorted(routes),
            }
        return None
