"""
Headless Browser Module — Playwright-based SPA crawler and DOM XSS detector.

Capabilities:
1. SPA Crawling — renders JavaScript, extracts dynamic links/forms
2. DOM XSS Detection — injects payloads and checks DOM sinks
3. Client-side JS Analysis — detects dangerous patterns (eval, innerHTML, etc.)
4. Screenshot Evidence — captures proof of vulnerabilities
5. Authentication — handles login flows with real browser
"""
import asyncio
import hashlib
import logging
import re
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

# DOM XSS sources and sinks
DOM_SOURCES = [
    "location.hash", "location.href", "location.search", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "document.cookie",
    "postMessage", "localStorage", "sessionStorage",
]

DOM_SINKS = [
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write(", "document.writeln(",
    ".src=", ".href=", ".action=",
    "jQuery.html(", "$.html(", ".append(",
    "React.dangerouslySetInnerHTML",
]

# XSS payloads for DOM injection
DOM_XSS_PAYLOADS = [
    '<img src=x onerror=alert("PHTM_XSS")>',
    '"><svg/onload=alert("PHTM_XSS")>',
    "javascript:alert('PHTM_XSS')",
    "'-alert('PHTM_XSS')-'",
    '{{constructor.constructor("alert(1)")()}}',
]

# Dangerous JS patterns in client code
DANGEROUS_PATTERNS = [
    (r'eval\s*\(', "eval() usage", "high"),
    (r'document\.write\s*\(', "document.write() usage", "high"),
    (r'innerHTML\s*=\s*[^"\'`]', "Dynamic innerHTML assignment", "high"),
    (r'outerHTML\s*=', "Dynamic outerHTML assignment", "high"),
    (r'insertAdjacentHTML\s*\(', "insertAdjacentHTML usage", "medium"),
    (r'setTimeout\s*\(\s*["\']', "setTimeout with string argument", "medium"),
    (r'setInterval\s*\(\s*["\']', "setInterval with string argument", "medium"),
    (r'\.src\s*=\s*[^"\'`]', "Dynamic src assignment", "medium"),
    (r'postMessage\s*\(', "postMessage usage (check origin validation)", "low"),
    (r'window\.open\s*\(', "window.open (potential redirect)", "low"),
    (r'location\s*=', "Direct location assignment", "medium"),
    (r'location\.href\s*=', "Dynamic location.href", "medium"),
]


class BrowserModule:
    """Playwright-based headless browser for SPA testing."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(3)
        self._browser = None
        self._playwright = None

    async def _get_browser(self):
        """Lazy-init Playwright browser."""
        if self._browser:
            return self._browser

        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            return self._browser
        except Exception as e:
            logger.error(f"Failed to start Playwright browser: {e}")
            raise

    async def close(self):
        """Close browser and Playwright."""
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def crawl_spa(self, base_url: str, auth_cookie: str = None, max_pages: int = 50) -> dict:
        """Crawl a JavaScript-heavy SPA, extracting dynamic content."""
        browser = await self._get_browser()
        context = await browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 720},
        )

        if auth_cookie:
            parsed = urlparse(base_url)
            cookies = []
            for part in auth_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    cookies.append({
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": parsed.hostname,
                        "path": "/",
                    })
            if cookies:
                await context.add_cookies(cookies)

        visited = set()
        to_visit = [base_url]
        all_links = set()
        all_forms = []
        js_files = set()
        api_calls = set()
        findings = []

        page = await context.new_page()

        # Intercept network requests to capture API calls
        async def on_request(request):
            url = request.url
            if any(p in url for p in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/")):
                api_calls.add(f"{request.method} {url}")

        page.on("request", on_request)

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue

            # Stay within same origin
            if urlparse(url).netloc != urlparse(base_url).netloc:
                continue

            visited.add(url)

            try:
                async with self.rate_limit:
                    resp = await page.goto(url, wait_until="networkidle", timeout=15000)
                    if not resp or resp.status >= 400:
                        continue

                    # Wait for JS rendering
                    await page.wait_for_timeout(1000)

                    # Extract links (including JS-generated ones)
                    links = await page.evaluate("""
                        () => {
                            const links = new Set();
                            document.querySelectorAll('a[href]').forEach(a => links.add(a.href));
                            document.querySelectorAll('[onclick]').forEach(el => {
                                const match = el.getAttribute('onclick').match(/['"]([^'"]*\\/[^'"]*)['"]/);
                                if (match) links.add(match[1]);
                            });
                            return [...links];
                        }
                    """)
                    for link in links:
                        abs_link = urljoin(url, link)
                        if urlparse(abs_link).netloc == urlparse(base_url).netloc:
                            all_links.add(abs_link)
                            if abs_link not in visited:
                                to_visit.append(abs_link)

                    # Extract forms
                    forms = await page.evaluate("""
                        () => {
                            const forms = [];
                            document.querySelectorAll('form').forEach(form => {
                                const fields = [];
                                form.querySelectorAll('input, textarea, select').forEach(el => {
                                    fields.push({
                                        name: el.name || el.id || '',
                                        type: el.type || 'text',
                                        value: el.value || '',
                                    });
                                });
                                forms.push({
                                    action: form.action || '',
                                    method: (form.method || 'GET').toUpperCase(),
                                    fields: fields.filter(f => f.name),
                                });
                            });
                            return forms;
                        }
                    """)
                    all_forms.extend(forms)

                    # Collect JS file URLs
                    scripts = await page.evaluate("""
                        () => {
                            const scripts = [];
                            document.querySelectorAll('script[src]').forEach(s => scripts.push(s.src));
                            return scripts;
                        }
                    """)
                    js_files.update(scripts)

            except Exception as e:
                logger.debug(f"Browser crawl error on {url}: {e}")

        await page.close()
        await context.close()

        return {
            "pages_visited": len(visited),
            "links_found": list(all_links)[:200],
            "forms": all_forms[:50],
            "js_files": list(js_files)[:100],
            "api_calls": list(api_calls)[:100],
        }

    async def check_dom_xss(self, base_url: str, endpoints: list[str],
                            auth_cookie: str = None) -> list[dict]:
        """Test for DOM-based XSS by injecting payloads via URL fragments/params."""
        findings = []
        browser = await self._get_browser()
        context = await browser.new_context(ignore_https_errors=True)

        if auth_cookie:
            parsed = urlparse(base_url)
            for part in auth_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    await context.add_cookies([{
                        "name": name.strip(), "value": value.strip(),
                        "domain": parsed.hostname, "path": "/",
                    }])

        page = await context.new_page()

        # Capture alerts
        alerts = []
        page.on("dialog", lambda dialog: (alerts.append(dialog.message), dialog.dismiss()))

        test_urls = [base_url] + endpoints[:10]

        for url in test_urls:
            for payload in DOM_XSS_PAYLOADS:
                alerts.clear()
                try:
                    # Test via hash fragment
                    test_url = f"{url}#/{payload}"
                    async with self.rate_limit:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        await page.wait_for_timeout(1500)

                    if any("PHTM_XSS" in a for a in alerts):
                        findings.append({
                            "title": f"DOM XSS via URL Hash: {urlparse(url).path}",
                            "url": url,
                            "severity": "high",
                            "vuln_type": "xss_dom",
                            "payload": payload,
                            "injection_point": "hash",
                            "impact": f"DOM-based XSS triggered via URL hash fragment. "
                                     f"Payload: {payload[:50]}... executed in the browser.",
                            "remediation": "Sanitize URL hash values before using them in DOM sinks. "
                                          "Use textContent instead of innerHTML.",
                        })
                        break  # One finding per URL is enough

                    # Test via query parameter
                    alerts.clear()
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?q={payload}"
                    async with self.rate_limit:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        await page.wait_for_timeout(1500)

                    if any("PHTM_XSS" in a for a in alerts):
                        findings.append({
                            "title": f"DOM XSS via Query Parameter: {parsed.path}",
                            "url": url,
                            "severity": "high",
                            "vuln_type": "xss_dom",
                            "payload": payload,
                            "injection_point": "query",
                            "impact": f"DOM-based XSS triggered via query parameter. "
                                     f"Payload: {payload[:50]}... executed in the browser.",
                            "remediation": "Sanitize all user-controlled URL parameters before "
                                          "inserting into DOM. Use DOMPurify or similar library.",
                        })
                        break

                except Exception:
                    continue

        await page.close()
        await context.close()
        return findings

    async def analyze_client_js(self, base_url: str, js_urls: list[str] = None) -> list[dict]:
        """Analyze client-side JavaScript for dangerous patterns."""
        findings = []

        if not js_urls:
            # Crawl to discover JS files first
            browser = await self._get_browser()
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            try:
                await page.goto(base_url, wait_until="networkidle", timeout=15000)
                js_urls = await page.evaluate("""
                    () => {
                        const scripts = [];
                        document.querySelectorAll('script[src]').forEach(s => scripts.push(s.src));
                        return scripts;
                    }
                """)
            except Exception:
                js_urls = []
            finally:
                await page.close()
                await context.close()

        # Also get inline scripts
        from app.utils.http_client import make_client
        async with make_client() as client:
            # Analyze inline scripts from main page
            try:
                resp = await client.get(base_url)
                inline_scripts = re.findall(
                    r'<script[^>]*>([^<]+)</script>', resp.text, re.IGNORECASE | re.DOTALL
                )
                for i, script in enumerate(inline_scripts):
                    if len(script.strip()) > 20:
                        script_findings = self._analyze_js_code(
                            script, f"{base_url}#inline-{i}"
                        )
                        findings.extend(script_findings)
            except Exception:
                pass

            # Analyze external JS files
            for js_url in (js_urls or [])[:20]:
                try:
                    async with self.rate_limit:
                        resp = await client.get(js_url)
                        if resp.status_code == 200 and len(resp.text) > 50:
                            script_findings = self._analyze_js_code(resp.text, js_url)
                            findings.extend(script_findings)
                except Exception:
                    continue

        return findings

    def _analyze_js_code(self, code: str, source_url: str) -> list[dict]:
        """Analyze a JavaScript code block for security issues."""
        findings = []
        seen = set()

        for pattern_str, description, severity in DANGEROUS_PATTERNS:
            matches = re.finditer(pattern_str, code)
            for match in matches:
                # Get context (surrounding code)
                start = max(0, match.start() - 50)
                end = min(len(code), match.end() + 50)
                context = code[start:end].strip()

                # Deduplicate
                dedup_key = f"{source_url}|{pattern_str}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Check for source → sink flow
                has_source = any(src in context for src in DOM_SOURCES)

                # Source → sink flow detected, but this is static analysis only.
                # Mark as info_disclosure (not vuln) — real DOM XSS is confirmed
                # only by browser-based check_dom_xss() which tests actual execution.
                report_severity = "info" if not has_source else "low"

                findings.append({
                    "title": f"JS Pattern: {description}",
                    "url": source_url,
                    "severity": report_severity,
                    "vuln_type": "info_disclosure",  # Never xss_dom without execution proof
                    "pattern": description,
                    "context": context[:150],
                    "has_source_flow": False,  # Static analysis alone is NOT proof
                    "impact": f"Static analysis found {description} in {urlparse(source_url).path}. "
                             f"{'User-controlled data may flow into this sink — verify manually.' if has_source else 'Review for potential security impact.'}",
                    "remediation": "Avoid using dangerous DOM APIs with user-controlled data. "
                                  "Use textContent, setAttribute, or DOMPurify for sanitization.",
                })

        return findings[:10]  # Max 10 findings per file

    async def take_screenshot(self, url: str, auth_cookie: str = None) -> bytes | None:
        """Take a screenshot of a page (for evidence)."""
        try:
            browser = await self._get_browser()
            context = await browser.new_context(ignore_https_errors=True)

            if auth_cookie:
                parsed = urlparse(url)
                for part in auth_cookie.split(";"):
                    part = part.strip()
                    if "=" in part:
                        name, value = part.split("=", 1)
                        await context.add_cookies([{
                            "name": name.strip(), "value": value.strip(),
                            "domain": parsed.hostname, "path": "/",
                        }])

            page = await context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=15000)
            screenshot = await page.screenshot(full_page=False)
            await page.close()
            await context.close()
            return screenshot
        except Exception as e:
            logger.debug(f"Screenshot error: {e}")
            return None
