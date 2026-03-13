"""
Stateful Crawler Module — Deep multi-step navigation with session/cookie management.

A real pentester doesn't just hit single URLs — they:
1. Maintain sessions across requests (cookies, tokens)
2. Discover and map HTML forms (fields, actions, CSRF tokens)
3. Follow multi-step flows: login → navigate → interact → extract
4. Track state changes between requests (new cookies, tokens, IDs)
5. Harvest IDs/tokens from responses for IDOR and auth bypass attacks
"""
import asyncio
import json
import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for token / ID / secret extraction
# ---------------------------------------------------------------------------

CSRF_META_RE = re.compile(
    r'<meta\s+[^>]*name=["\']csrf[_-]?token["\'][^>]*content=["\']([^"\']+)["\']',
    re.I,
)
CSRF_META_ALT_RE = re.compile(
    r'<meta\s+[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf[_-]?token["\']',
    re.I,
)

# Tokens and secrets in HTML / JSON responses
TOKEN_PATTERNS = {
    "csrf_token": re.compile(
        r'(?:csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)'
        r'[\s]*[=:]\s*["\']([a-zA-Z0-9_\-/+=]{16,128})["\']',
        re.I,
    ),
    "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
    "api_key": re.compile(
        r'(?:api[_-]?key|apikey|x-api-key|authorization)[\s]*[=:"\']\s*([a-zA-Z0-9_\-]{20,64})',
        re.I,
    ),
    "bearer_token": re.compile(r'[Bb]earer\s+([a-zA-Z0-9_\-./+=]{20,})'),
}

# Numeric and UUID IDs in URLs and responses
NUMERIC_ID_RE = re.compile(r'/(?:id|user|account|order|item|product|profile|post|comment|ticket)[s]?/(\d{1,10})(?:[/?#]|$)', re.I)
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
JSON_ID_RE = re.compile(r'"(?:id|userId|user_id|accountId|account_id|orderId|order_id)":\s*(\d{1,10})')

# Link extraction
HREF_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\'#]+)["\']', re.I)


# ---------------------------------------------------------------------------
# HTML form parser
# ---------------------------------------------------------------------------

class FormParser(HTMLParser):
    """Extract forms and their fields from HTML."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attrs_dict = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": (attrs_dict.get("method", "GET")).upper(),
                "fields": [],
                "enctype": attrs_dict.get("enctype", ""),
                "id": attrs_dict.get("id", ""),
                "class": attrs_dict.get("class", ""),
            }
        elif self._current_form is not None:
            if tag == "input":
                self._current_form["fields"].append({
                    "name": attrs_dict.get("name", ""),
                    "type": attrs_dict.get("type", "text"),
                    "value": attrs_dict.get("value", ""),
                    "placeholder": attrs_dict.get("placeholder", ""),
                    "required": "required" in attrs_dict,
                })
            elif tag == "select":
                self._current_form["fields"].append({
                    "name": attrs_dict.get("name", ""),
                    "type": "select",
                    "value": "",
                })
            elif tag == "textarea":
                self._current_form["fields"].append({
                    "name": attrs_dict.get("name", ""),
                    "type": "textarea",
                    "value": "",
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# Stateful Crawler
# ---------------------------------------------------------------------------

class StatefulCrawler:
    """Deep stateful crawling with session management and multi-step flow tracking."""

    def __init__(self, context: dict):
        self.context = context
        self.base_url: str = context.get("base_url", "").rstrip("/")
        self.rate_limit: int = context.get("rate_limit") or 5
        self.semaphore = asyncio.Semaphore(self.rate_limit)

        # Crawl state
        self.visited: set[str] = set()
        self.max_depth: int = 3
        self.max_pages: int = 100
        self.pages_crawled: int = 0

        # Discovered data
        self.forms_found: list[dict] = []
        self.links_found: set[str] = set()
        self.state_transitions: list[dict] = []
        self.harvested_ids: dict[str, set] = {}
        self.harvested_tokens: dict[str, str] = {}
        self.authenticated_endpoints: list[dict] = []
        self.multi_step_flows: list[dict] = []

        # Session
        self.session_cookies: dict[str, str] = {}
        self.auth_headers: dict[str, str] = {}
        self.authenticated: bool = False

        # Results accumulator
        self.results: dict = {
            "forms": [],
            "state_transitions": [],
            "harvested_ids": {},
            "harvested_tokens": {},
            "authenticated_endpoints": [],
            "multi_step_flows": [],
        }

    async def crawl(self) -> dict:
        """Run full stateful crawl pipeline."""
        if not self.base_url:
            logger.warning("StatefulCrawler: no base_url provided")
            return self.results

        logger.info(f"StatefulCrawler: starting crawl of {self.base_url}")

        try:
            # Phase 1: Discover forms & extract initial state (unauthenticated)
            await self._phase_discover_forms()

            # Phase 2: Attempt authentication using known creds
            await self._phase_authenticate()

            # Phase 3: Deep crawl authenticated areas
            if self.authenticated:
                await self._phase_authenticated_crawl()

            # Phase 4: Map multi-step flows
            await self._phase_map_flows()

            # Phase 5: Harvest IDs and tokens
            await self._phase_harvest()

        except Exception as exc:
            logger.error(f"StatefulCrawler: crawl failed: {exc}", exc_info=True)

        self._build_results()
        logger.info(
            f"StatefulCrawler: done — {len(self.forms_found)} forms, "
            f"{len(self.state_transitions)} transitions, "
            f"{sum(len(v) for v in self.harvested_ids.values())} IDs, "
            f"{len(self.harvested_tokens)} tokens, "
            f"{len(self.authenticated_endpoints)} auth endpoints"
        )
        return self.results

    # ------------------------------------------------------------------
    # Phase 1: Form discovery & initial state extraction
    # ------------------------------------------------------------------

    async def _phase_discover_forms(self):
        """Visit known endpoints and discover forms + CSRF tokens + cookies."""
        endpoints = self._get_seed_urls()
        logger.info(f"Phase 1: discovering forms from {len(endpoints)} seed URLs")

        tasks = [self._visit_and_parse(url, depth=0) for url in endpoints[:self.max_pages]]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Phase 1: found {len(self.forms_found)} forms from {self.pages_crawled} pages")

    async def _visit_and_parse(self, url: str, depth: int):
        """Fetch a URL, parse forms, extract tokens, discover links."""
        normalized = self._normalize_url(url)
        if normalized in self.visited or depth > self.max_depth:
            return
        if self.pages_crawled >= self.max_pages:
            return
        if not self._is_in_scope(normalized):
            return

        self.visited.add(normalized)
        self.pages_crawled += 1

        async with self.semaphore:
            try:
                async with make_client(timeout=15.0, follow_redirects=True) as client:
                    # Apply session cookies
                    for k, v in self.session_cookies.items():
                        client.cookies.set(k, v)
                    for k, v in self.auth_headers.items():
                        client.headers[k] = v

                    cookies_before = dict(client.cookies)
                    resp = await client.get(normalized)

                    # Record cookies gained
                    cookies_after = dict(resp.cookies)
                    new_cookies = {k: v for k, v in cookies_after.items() if k not in cookies_before}
                    if new_cookies:
                        self.session_cookies.update(new_cookies)

                    body = resp.text
                    content_type = resp.headers.get("content-type", "")

                    # Extract tokens from response
                    tokens = self._extract_tokens(body)
                    if tokens:
                        self.harvested_tokens.update(tokens)

                    # Extract IDs from URL and body
                    self._extract_ids_from_url(normalized)
                    self._extract_ids_from_body(body)

                    # Record state transition
                    if new_cookies or tokens:
                        self.state_transitions.append({
                            "url": normalized,
                            "status": resp.status_code,
                            "cookies_gained": new_cookies,
                            "tokens_found": list(tokens.keys()) if tokens else [],
                            "ids_found": self._extract_ids_from_url(normalized),
                        })

                    # Parse HTML forms
                    if "text/html" in content_type:
                        forms = self._parse_forms(body, normalized)
                        self.forms_found.extend(forms)

                        # Discover new links for recursive crawl
                        if depth < self.max_depth:
                            new_links = self._extract_links(body, normalized)
                            crawl_tasks = []
                            for link in new_links:
                                if link not in self.visited and self.pages_crawled < self.max_pages:
                                    crawl_tasks.append(self._visit_and_parse(link, depth + 1))
                            if crawl_tasks:
                                await asyncio.gather(*crawl_tasks[:20], return_exceptions=True)

            except httpx.TimeoutException:
                logger.debug(f"Timeout fetching {normalized}")
            except Exception as exc:
                logger.debug(f"Error fetching {normalized}: {exc}")

    # ------------------------------------------------------------------
    # Phase 2: Authentication
    # ------------------------------------------------------------------

    async def _phase_authenticate(self):
        """Try to establish an authenticated session using known credentials."""
        # Check if auth_attack already found valid creds
        valid_creds = self.context.get("valid_credentials", [])
        if not valid_creds:
            # Check scan results for auth_attack findings
            scan_results = self.context.get("scan_results", {})
            auth_results = scan_results.get("auth_attack", [])
            for finding in auth_results:
                if isinstance(finding, dict) and finding.get("valid_credentials"):
                    valid_creds = finding["valid_credentials"]
                    break

        if not valid_creds:
            logger.info("Phase 2: no known credentials, skipping authentication")
            return

        logger.info(f"Phase 2: attempting authentication with {len(valid_creds)} credential set(s)")

        # Find login forms
        login_forms = [
            f for f in self.forms_found
            if self._is_login_form(f)
        ]

        # Also try common login endpoints
        login_endpoints = [
            "/login", "/signin", "/auth/login", "/api/login",
            "/api/auth/login", "/api/v1/auth/login", "/api/sessions",
        ]

        for cred in valid_creds[:3]:  # Try top 3 credential sets
            username = cred.get("username", "")
            password = cred.get("password", "")
            if not username:
                continue

            # Try via discovered login forms
            for form in login_forms:
                success = await self._submit_login_form(form, username, password)
                if success:
                    self.authenticated = True
                    logger.info(f"Phase 2: authenticated via form at {form.get('action_url', '')}")
                    return

            # Try via API endpoints (JSON POST)
            for path in login_endpoints:
                success = await self._try_api_login(path, username, password)
                if success:
                    self.authenticated = True
                    logger.info(f"Phase 2: authenticated via API at {path}")
                    return

        logger.info("Phase 2: authentication attempts exhausted")

    async def _submit_login_form(self, form: dict, username: str, password: str) -> bool:
        """Submit a login form with credentials, check for successful auth."""
        action_url = form.get("action_url", "")
        method = form.get("method", "POST")
        fields = form.get("fields", [])

        # Build form data
        data = {}
        for field in fields:
            name = field.get("name", "")
            if not name:
                continue
            ftype = field.get("type", "text").lower()
            if ftype in ("text", "email") or "user" in name.lower() or "email" in name.lower():
                data[name] = username
            elif ftype == "password" or "pass" in name.lower():
                data[name] = password
            elif ftype == "hidden":
                data[name] = field.get("value", "")
            elif name.lower() in ("remember", "remember_me", "rememberme"):
                data[name] = "1"

        if not data:
            return False

        async with self.semaphore:
            try:
                async with make_client(timeout=15.0, follow_redirects=True) as client:
                    for k, v in self.session_cookies.items():
                        client.cookies.set(k, v)

                    if method == "GET":
                        resp = await client.get(action_url, params=data)
                    else:
                        resp = await client.post(action_url, data=data)

                    return self._check_auth_success(resp)
            except Exception as exc:
                logger.debug(f"Login form submission failed: {exc}")
                return False

    async def _try_api_login(self, path: str, username: str, password: str) -> bool:
        """Try JSON API login at common endpoints."""
        url = urljoin(self.base_url, path)

        payloads = [
            {"username": username, "password": password},
            {"email": username, "password": password},
            {"user": username, "pass": password},
        ]

        async with self.semaphore:
            for payload in payloads:
                try:
                    async with make_client(timeout=15.0, follow_redirects=True) as client:
                        for k, v in self.session_cookies.items():
                            client.cookies.set(k, v)

                        resp = await client.post(
                            url,
                            json=payload,
                            headers={"Content-Type": "application/json"},
                        )

                        if self._check_auth_success(resp):
                            # Extract auth token from JSON response
                            try:
                                body = resp.json()
                                for key in ("token", "access_token", "accessToken", "jwt", "session_token", "auth_token"):
                                    if key in body:
                                        self.auth_headers["Authorization"] = f"Bearer {body[key]}"
                                        self.harvested_tokens["auth_bearer"] = body[key]
                                        break
                            except (json.JSONDecodeError, ValueError):
                                pass
                            # Capture session cookies
                            self.session_cookies.update(dict(resp.cookies))
                            return True

                except Exception:
                    continue

        return False

    def _check_auth_success(self, resp: httpx.Response) -> bool:
        """Heuristic: did the login succeed?"""
        # Success indicators
        if resp.status_code in (200, 201, 302, 303):
            body = resp.text.lower()
            # Failure indicators — if present, login failed
            fail_markers = [
                "invalid credentials", "login failed", "incorrect password",
                "invalid username", "authentication failed", "wrong password",
                "bad credentials", "unauthorized", "invalid email or password",
                "account not found", "invalid login",
            ]
            for marker in fail_markers:
                if marker in body:
                    return False

            # Check for session cookie being set
            if resp.cookies:
                session_keys = [k for k in resp.cookies.keys() if any(
                    s in k.lower() for s in ("session", "token", "auth", "sid", "jwt")
                )]
                if session_keys:
                    self.session_cookies.update(dict(resp.cookies))
                    return True

            # Check for token in JSON response
            try:
                data = resp.json()
                if isinstance(data, dict):
                    if any(k in data for k in ("token", "access_token", "accessToken", "jwt")):
                        return True
                    if data.get("success") is True or data.get("authenticated") is True:
                        return True
            except (json.JSONDecodeError, ValueError):
                pass

            # Redirect to dashboard/home after login = likely success
            final_url = str(resp.url).lower()
            if any(p in final_url for p in ("dashboard", "home", "admin", "panel", "profile", "account")):
                return True

        return False

    # ------------------------------------------------------------------
    # Phase 3: Authenticated crawl
    # ------------------------------------------------------------------

    async def _phase_authenticated_crawl(self):
        """Re-crawl with authenticated session to discover protected content."""
        logger.info("Phase 3: starting authenticated crawl")

        # Reset visit tracking for authenticated pass
        unauthenticated_visited = set(self.visited)
        self.visited.clear()
        self.pages_crawled = 0

        # Seed URLs: original endpoints + common protected paths
        protected_paths = [
            "/admin", "/dashboard", "/panel", "/settings", "/profile",
            "/account", "/users", "/api/admin", "/api/users", "/api/me",
            "/api/settings", "/manage", "/internal", "/reports",
            "/api/v1/users", "/api/v1/admin", "/api/v1/me",
        ]
        seed_urls = self._get_seed_urls() + [
            urljoin(self.base_url, p) for p in protected_paths
        ]

        tasks = [self._visit_and_parse(url, depth=0) for url in seed_urls[:self.max_pages]]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Identify endpoints only accessible when authenticated
        new_pages = self.visited - unauthenticated_visited
        for page in new_pages:
            self.authenticated_endpoints.append({
                "url": page,
                "requires_auth": True,
            })

        logger.info(
            f"Phase 3: found {len(new_pages)} new authenticated-only endpoints"
        )

    # ------------------------------------------------------------------
    # Phase 4: Multi-step flow mapping
    # ------------------------------------------------------------------

    async def _phase_map_flows(self):
        """Detect and map multi-step workflows (wizards, checkout, form chains)."""
        logger.info("Phase 4: mapping multi-step flows")

        # Identify form chains: forms whose action leads to another page with a form
        form_chains = await self._detect_form_chains()
        self.multi_step_flows.extend(form_chains)

        # Identify step-based URLs (step=1, step=2 or /step1, /step2)
        step_flows = self._detect_step_urls()
        self.multi_step_flows.extend(step_flows)

        logger.info(f"Phase 4: mapped {len(self.multi_step_flows)} multi-step flows")

    async def _detect_form_chains(self) -> list[dict]:
        """Follow form submissions to detect multi-step form chains."""
        chains: list[dict] = []

        # Look for forms that submit to pages with more forms
        for form in self.forms_found:
            action_url = form.get("action_url", "")
            if not action_url or not self._is_in_scope(action_url):
                continue

            # Check if we already know the target has a form
            target_forms = [
                f for f in self.forms_found
                if self._normalize_url(f.get("source_url", "")) == self._normalize_url(action_url)
            ]
            if target_forms:
                chains.append({
                    "type": "form_chain",
                    "steps": [
                        {"url": form.get("source_url", ""), "form_action": action_url, "method": form.get("method")},
                        {"url": action_url, "form_action": target_forms[0].get("action_url", ""), "method": target_forms[0].get("method")},
                    ],
                })

        return chains

    def _detect_step_urls(self) -> list[dict]:
        """Detect wizard/step-based URL patterns from visited pages."""
        flows: list[dict] = []
        step_groups: dict[str, list[tuple[int, str]]] = {}

        # Group URLs by base path, extract step numbers
        step_re = re.compile(r'(.+?)(?:/step[_-]?|[?&]step=)(\d+)', re.I)
        for url in self.visited:
            m = step_re.search(url)
            if m:
                base, step_num = m.group(1), int(m.group(2))
                step_groups.setdefault(base, []).append((step_num, url))

        for base, steps in step_groups.items():
            if len(steps) >= 2:
                steps.sort(key=lambda x: x[0])
                flows.append({
                    "type": "wizard",
                    "base_path": base,
                    "steps": [{"step": s[0], "url": s[1]} for s in steps],
                })

        return flows

    # ------------------------------------------------------------------
    # Phase 5: ID & token harvesting
    # ------------------------------------------------------------------

    async def _phase_harvest(self):
        """
        Final pass: visit high-value endpoints to harvest IDs and tokens
        that can be used in IDOR and auth bypass attacks.
        """
        logger.info("Phase 5: harvesting IDs and tokens")

        # Hit API endpoints that typically list resources with IDs
        api_list_paths = [
            "/api/users", "/api/v1/users", "/api/v2/users",
            "/api/products", "/api/orders", "/api/accounts",
            "/api/posts", "/api/comments", "/api/tickets",
            "/api/items", "/api/invoices", "/api/files",
        ]

        tasks = []
        for path in api_list_paths:
            url = urljoin(self.base_url, path)
            if url not in self.visited:
                tasks.append(self._fetch_and_extract_ids(url))

        if tasks:
            await asyncio.gather(*tasks[:20], return_exceptions=True)

        logger.info(
            f"Phase 5: harvested {sum(len(v) for v in self.harvested_ids.values())} IDs, "
            f"{len(self.harvested_tokens)} tokens"
        )

    async def _fetch_and_extract_ids(self, url: str):
        """Fetch a URL and extract IDs/tokens from the response."""
        async with self.semaphore:
            try:
                async with make_client(timeout=15.0, follow_redirects=True) as client:
                    for k, v in self.session_cookies.items():
                        client.cookies.set(k, v)
                    for k, v in self.auth_headers.items():
                        client.headers[k] = v

                    resp = await client.get(url)
                    if resp.status_code < 400:
                        body = resp.text
                        self._extract_ids_from_body(body)
                        tokens = self._extract_tokens(body)
                        if tokens:
                            self.harvested_tokens.update(tokens)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Parsing / extraction helpers
    # ------------------------------------------------------------------

    def _parse_forms(self, html: str, source_url: str) -> list[dict]:
        """Parse all forms from HTML and resolve action URLs."""
        parser = FormParser()
        try:
            parser.feed(html)
        except Exception:
            return []

        forms = []
        for form in parser.forms:
            action = form["action"]
            if action:
                action_url = urljoin(source_url, action)
            else:
                action_url = source_url  # Form posts to itself

            # Extract CSRF token from hidden fields
            csrf_token = ""
            csrf_field = ""
            for field in form["fields"]:
                if field["type"] == "hidden" and any(
                    t in (field.get("name") or "").lower()
                    for t in ("csrf", "token", "_token", "authenticity", "verification", "xsrf")
                ):
                    csrf_token = field.get("value", "")
                    csrf_field = field.get("name", "")
                    break

            form_data = {
                "source_url": source_url,
                "action_url": action_url,
                "method": form["method"],
                "enctype": form["enctype"],
                "fields": form["fields"],
                "field_names": [f["name"] for f in form["fields"] if f.get("name")],
                "csrf_token": csrf_token,
                "csrf_field": csrf_field,
                "is_login": self._is_login_form(form),
                "is_search": self._is_search_form(form),
                "is_upload": form["enctype"] == "multipart/form-data",
            }
            forms.append(form_data)

        # Also extract CSRF tokens from meta tags
        for pattern in (CSRF_META_RE, CSRF_META_ALT_RE):
            m = pattern.search(html)
            if m:
                self.harvested_tokens["csrf_meta"] = m.group(1)
                break

        return forms

    def _extract_tokens(self, body: str) -> dict[str, str]:
        """Extract security tokens from response body."""
        tokens = {}
        for token_type, pattern in TOKEN_PATTERNS.items():
            matches = pattern.findall(body)
            if matches:
                # Take the first match; for JWT take the longest
                if token_type == "jwt":
                    value = max(matches, key=len)
                else:
                    value = matches[0]
                tokens[token_type] = value
        return tokens

    def _extract_ids_from_url(self, url: str) -> list[str]:
        """Extract IDs from URL path and query parameters."""
        found = []

        # Numeric IDs in path
        for m in NUMERIC_ID_RE.finditer(url):
            id_val = m.group(1)
            param = m.group(0).split("/")[1] if "/" in m.group(0) else "id"
            self.harvested_ids.setdefault(param, set()).add(id_val)
            found.append(f"{param}={id_val}")

        # UUIDs in path
        for m in UUID_RE.finditer(url):
            self.harvested_ids.setdefault("uuid", set()).add(m.group(0))
            found.append(f"uuid={m.group(0)}")

        # Query parameter IDs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for key, values in params.items():
            if any(t in key.lower() for t in ("id", "uid", "user", "account", "order", "token")):
                for v in values:
                    self.harvested_ids.setdefault(key, set()).add(v)
                    found.append(f"{key}={v}")

        return found

    def _extract_ids_from_body(self, body: str):
        """Extract IDs from response body (JSON, HTML)."""
        # JSON numeric IDs
        for m in JSON_ID_RE.finditer(body):
            field_match = re.search(r'"(\w+)":', body[max(0, m.start() - 30):m.start() + 1])
            key = field_match.group(1) if field_match else "id"
            self.harvested_ids.setdefault(key, set()).add(m.group(1))

        # UUIDs (limit to avoid noise)
        uuids = UUID_RE.findall(body)
        for uuid_val in uuids[:50]:
            self.harvested_ids.setdefault("uuid", set()).add(uuid_val)

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract in-scope links from HTML."""
        links = []
        for m in HREF_RE.finditer(html):
            href = m.group(1).strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            full_url = urljoin(base_url, href)
            normalized = self._normalize_url(full_url)
            if self._is_in_scope(normalized) and normalized not in self.visited:
                links.append(normalized)
                self.links_found.add(normalized)
        return links

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_login_form(form: dict) -> bool:
        """Check if a form looks like a login form."""
        fields = form.get("fields", [])
        has_password = any(f.get("type") == "password" for f in fields)
        if not has_password:
            return False
        field_names = [f.get("name", "").lower() for f in fields]
        has_username = any(
            any(t in name for t in ("user", "email", "login", "name", "account"))
            for name in field_names
        )
        return has_username

    @staticmethod
    def _is_search_form(form: dict) -> bool:
        """Check if a form is a search form."""
        fields = form.get("fields", [])
        field_names = [f.get("name", "").lower() for f in fields]
        return any("search" in name or "query" in name or "q" == name for name in field_names)

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _normalize_url(self, url: str) -> str:
        """Normalize URL: strip fragment, trailing slash."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within the target scope."""
        if not self.base_url:
            return False
        try:
            base_parsed = urlparse(self.base_url)
            url_parsed = urlparse(url)
            return url_parsed.netloc == base_parsed.netloc and url_parsed.scheme in ("http", "https")
        except Exception:
            return False

    def _get_seed_urls(self) -> list[str]:
        """Build seed URL list from context endpoints and common paths."""
        urls = [self.base_url]

        # From endpoint discovery
        endpoints = self.context.get("endpoints", [])
        for ep in endpoints:
            if isinstance(ep, dict):
                url = ep.get("url", "")
            elif isinstance(ep, str):
                url = ep
            else:
                continue
            if url:
                full = urljoin(self.base_url, url) if not url.startswith("http") else url
                if self._is_in_scope(full):
                    urls.append(full)

        # From scan results
        scan_results = self.context.get("scan_results", {})
        for phase_key in ("endpoint", "sensitive_files"):
            phase_results = scan_results.get(phase_key, [])
            if isinstance(phase_results, list):
                for item in phase_results:
                    if isinstance(item, dict) and item.get("url"):
                        url = item["url"]
                        full = urljoin(self.base_url, url) if not url.startswith("http") else url
                        if self._is_in_scope(full):
                            urls.append(full)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for u in urls:
            n = self._normalize_url(u)
            if n not in seen:
                seen.add(n)
                unique.append(n)

        return unique

    # ------------------------------------------------------------------
    # Build final results
    # ------------------------------------------------------------------

    def _build_results(self):
        """Compile all findings into the results dict."""
        self.results["forms"] = self.forms_found
        self.results["state_transitions"] = self.state_transitions
        self.results["harvested_ids"] = {
            k: sorted(v) for k, v in self.harvested_ids.items()
        }
        self.results["harvested_tokens"] = self.harvested_tokens
        self.results["authenticated_endpoints"] = self.authenticated_endpoints
        self.results["multi_step_flows"] = self.multi_step_flows
        self.results["stats"] = {
            "pages_crawled": self.pages_crawled,
            "forms_found": len(self.forms_found),
            "login_forms": sum(1 for f in self.forms_found if f.get("is_login")),
            "upload_forms": sum(1 for f in self.forms_found if f.get("is_upload")),
            "unique_ids": sum(len(v) for v in self.harvested_ids.values()),
            "tokens_found": len(self.harvested_tokens),
            "authenticated": self.authenticated,
        }
