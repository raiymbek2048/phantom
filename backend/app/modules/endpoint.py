"""
Endpoint Discovery Module

Discovers URLs, API endpoints, parameters, hidden paths.
Tools: katana (crawler), ffuf (fuzzer), gau (known URLs)
"""
import asyncio
import tempfile
import os

import httpx

from app.utils.tool_runner import run_command
from app.utils.http_client import make_client


# Common wordlists for directory/file fuzzing
COMMON_DIRS = [
    # Core admin/config
    "admin", "administrator", "api", "backup", "config", "configuration",
    "dashboard", "db", "debug", "dev", "development", "docs", "download",
    "dump", "env", "graphql", "health", "info", "internal", "login",
    "logout", "logs", "metrics", "panel", "phpinfo", "private",
    "register", "robots.txt", "server-status", "sitemap.xml", "staging",
    "status", "swagger", "test", "testing", "upload", "uploads",
    "v1", "v2", "v3", "wp-admin", "wp-login.php",
    # Sensitive files
    ".env", ".env.local", ".env.production", ".env.staging", ".env.backup",
    ".git", ".git/config", ".git/HEAD", ".git/logs/HEAD",
    ".htaccess", ".htpasswd", ".svn", ".svn/entries",
    ".DS_Store", "Thumbs.db", ".idea/workspace.xml",
    # Spring Boot Actuator (critical for Java apps)
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "actuator/mappings", "actuator/configprops", "actuator/heapdump",
    "actuator/threaddump", "actuator/loggers", "actuator/httptrace",
    "actuator/metrics", "actuator/info", "actuator/scheduledtasks",
    "actuator/jolokia", "actuator/gateway/routes",
    # API documentation (Swagger/OpenAPI)
    "api/docs", "api/swagger", "api/v1", "api/v2", "api/v3",
    "swagger-ui.html", "swagger-ui/", "swagger/v1/swagger.json",
    "api-docs", "v2/api-docs", "v3/api-docs", "openapi.json",
    "redoc", "api/openapi", "api/schema",
    # GraphQL
    "graphql", "graphiql", "playground", "graphql/console",
    "api/graphql", "v1/graphql",
    # Common web files
    "crossdomain.xml", "clientaccesspolicy.xml", "elmah.axd",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "server-info", "trace", "web.config", "heapdump",
    # REST API patterns
    "rest/admin/application-version", "rest/admin/application-configuration",
    "rest/products/search", "rest/user/login", "rest/user/whoami",
    "rest/saveLoginIp", "rest/basket", "rest/wallet/balance",
    "api/Users", "api/Products", "api/Feedbacks", "api/Complaints",
    "api/Recycles", "api/SecurityQuestions", "api/Challenges",
    # Common API endpoints
    "api/user", "api/users", "api/auth", "api/admin", "api/account",
    "api/profile", "api/settings", "api/orders", "api/config",
    "api/health", "api/status", "api/version", "api/me", "api/token",
    "api/search", "api/upload", "api/download", "api/export",
    "api/import", "api/webhook", "api/webhooks", "api/callback",
    "api/internal", "api/debug", "api/test", "api/keys", "api/secrets",
    # Auth/OAuth
    ".well-known/openid-configuration", ".well-known/jwks.json",
    ".well-known/security.txt", ".well-known/assetlinks.json",
    "oauth/authorize", "oauth/token", "oauth2/authorize",
    "auth/login", "auth/register", "auth/callback", "auth/token",
    "sso/login", "saml/login", "saml/metadata",
    # WebGoat / Java apps
    "WebGoat", "WebGoat/login", "WebGoat/service",
    "WebWolf", "console",
    # WordPress specific
    "wp-json/wp/v2/users", "wp-json/wp/v2/posts", "wp-json/",
    "wp-content/debug.log", "wp-config.php.bak", "xmlrpc.php",
    # Firebase / Cloud
    "firebase.json", "__/firebase/init.js",
    # Common backup patterns
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "database.sql", "db.sql", "site.zip", "www.zip",
    "backup.sql.gz", "data.json", "export.json",
    # PHP-specific
    "info.php", "phpinfo.php", "test.php", "debug.php",
    "adminer.php", "phpmyadmin",
    # Node.js
    "node_modules", ".npmrc", "npm-debug.log", "yarn.lock",
    # CI/CD
    ".github/workflows", ".gitlab-ci.yml", ".circleci/config.yml",
    "Jenkinsfile", ".travis.yml", "Dockerfile", "docker-compose.yml",
    # Other
    "ftp", "encryptionkeys", "support/logs", "cgi-bin",
    "server-info", "jmx-console", "manager/html", "solr",
    "jenkins", "nagios", "kibana", "grafana",
    "_debug_toolbar", "__debug__",
]


class EndpointModule:
    async def run(self, domain: str, subdomains: list[str], base_url: str = None, context: dict = None) -> list[dict]:
        """Discover endpoints across domain and subdomains."""
        all_endpoints = []
        if base_url is None:
            base_url = f"https://{domain}"
        self._base_url = base_url
        self._auth_cookie = None
        self._custom_headers = (context or {}).get("custom_headers", {})

        # Try to get auth cookie (for apps that require login like DVWA)
        self._auth_cookie = await self._try_auto_login(base_url)

        targets = [domain] + subdomains[:5]

        # Run different discovery methods in parallel
        tasks = [
            self._crawl(domain, base_url),
            self._gau_urls(domain),
            self._fuzz_common_paths(domain, base_url),
            self._extract_js_endpoints(base_url),
            self._check_graphql(base_url),
            self._check_http_methods(base_url),
            self._spa_render_discovery(base_url),
        ]

        # Also crawl top subdomains
        for sub in subdomains[:3]:
            tasks.append(self._crawl(sub))

        task_names = [
            "crawl", "gau", "fuzz", "js_extract", "graphql",
            "http_methods", "spa_render",
        ] + [f"crawl_{sub}" for sub in subdomains[:3]]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen_urls = set()
        failed_tasks = []
        for i, result in enumerate(results):
            name = task_names[i] if i < len(task_names) else f"task_{i}"
            if isinstance(result, Exception):
                failed_tasks.append(f"{name}: {type(result).__name__}: {str(result)[:100]}")
            elif isinstance(result, list):
                for endpoint in result:
                    url = endpoint.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        all_endpoints.append(endpoint)

        if failed_tasks:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Endpoint discovery: {len(failed_tasks)} tasks failed: {'; '.join(failed_tasks)}")

        # Always run link extraction as fallback (even without auth)
        # This catches endpoints when external tools (katana/gau/ffuf) all fail
        if len(all_endpoints) < 10:
            link_endpoints = await self._extract_links_with_auth(base_url)
            for endpoint in link_endpoints:
                url = endpoint.get("url", "")
                if not url:
                    continue
                if endpoint.get("type") == "form":
                    all_endpoints.append(endpoint)
                elif url not in seen_urls:
                    seen_urls.add(url)
                    all_endpoints.append(endpoint)
        elif self._auth_cookie:
            link_endpoints = await self._extract_links_with_auth(base_url)
            for endpoint in link_endpoints:
                url = endpoint.get("url", "")
                if not url:
                    continue
                if endpoint.get("type") == "form":
                    all_endpoints.append(endpoint)
                elif url not in seen_urls:
                    seen_urls.add(url)
                    all_endpoints.append(endpoint)

        return all_endpoints

    async def _extract_links_with_auth(self, base_url: str) -> list[dict]:
        """Crawl pages with auth cookie to extract links (fallback when katana fails)."""
        import re
        endpoints = []
        visited = set()
        to_visit = [base_url + "/"]

        try:
            headers = dict(self._custom_headers)
            if self._auth_cookie:
                if self._auth_cookie.startswith("token="):
                    headers["Authorization"] = f"Bearer {self._auth_cookie.split('=', 1)[1]}"
                else:
                    headers["Cookie"] = self._auth_cookie
            async with make_client(extra_headers=headers) as client:
                # BFS crawl up to 2 levels deep
                for depth in range(3):
                    next_level = []
                    for page_url in to_visit:
                        if page_url in visited:
                            continue
                        visited.add(page_url)
                        try:
                            resp = await client.get(page_url)
                            if resp.status_code != 200:
                                continue
                            # Skip non-HTML responses
                            content_type = resp.headers.get("content-type", "")
                            if "text/html" not in content_type and "text/plain" not in content_type:
                                continue

                            # Extract href links
                            links = re.findall(r'href=["\']([^"\'#]+)', resp.text)
                            skip_exts = (".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".ttf")
                            for link in links:
                                if any(link.lower().endswith(ext) for ext in skip_exts):
                                    continue
                                if link.startswith("http"):
                                    full_url = link
                                elif link.startswith("/"):
                                    full_url = base_url + link
                                else:
                                    full_url = page_url.rstrip("/") + "/" + link
                                if base_url in full_url and full_url not in visited:
                                    next_level.append(full_url)
                                    endpoints.append(self._classify_endpoint(full_url))

                            # Extract HTML forms (POST targets with fields)
                            forms = self._extract_forms(page_url, base_url, resp.text)
                            endpoints.extend(forms)
                        except Exception:
                            continue
                    to_visit = next_level[:50]
        except Exception:
            pass
        return endpoints

    async def _try_auto_login(self, base_url: str) -> str | None:
        """Try common default credentials to get a session cookie or JWT token.

        Supports: DVWA (PHP session), bWAPP, Juice Shop (JWT), generic form login.
        """
        import re

        # --- Try JWT-based login (Juice Shop, Node.js apps) ---
        jwt_creds = [
            # Juice Shop
            {"endpoint": "/rest/user/login", "body": {"email": "admin@juice-sh.op", "password": "admin123"}},
            {"endpoint": "/rest/user/login", "body": {"email": "admin@juice-sh.op", "password": "admin123"}},
            {"endpoint": "/api/auth/login", "body": {"username": "admin", "password": "admin"}},
            {"endpoint": "/auth/login", "body": {"username": "admin", "password": "admin"}},
        ]
        try:
            async with make_client(extra_headers=dict(self._custom_headers)) as client:
                for cred in jwt_creds:
                    url = f"{base_url}{cred['endpoint']}"
                    try:
                        resp = await client.post(url, json=cred["body"])
                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                token = None
                                # Juice Shop: {"authentication": {"token": "..."}}
                                if isinstance(data, dict):
                                    if data.get("authentication", {}).get("token"):
                                        token = data["authentication"]["token"]
                                    elif data.get("token"):
                                        token = data["token"]
                                    elif data.get("access_token"):
                                        token = data["access_token"]
                                if token:
                                    self._jwt_token = token
                                    return f"token={token}"
                            except Exception:
                                pass
                    except Exception:
                        continue
        except Exception:
            pass

        # --- Try form-based login (DVWA, bWAPP) ---
        default_creds = [
            {"username": "admin", "password": "password", "Login": "Login"},
            {"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
        ]
        login_paths = ["/login.php", "/login", "/auth/login"]

        try:
            async with make_client(extra_headers=dict(self._custom_headers)) as client:
                for path in login_paths:
                    url = f"{base_url}{path}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            continue

                        csrf_token = None
                        csrf_field = None
                        for pattern, field in [
                            (r"name=['\"]user_token['\"] value=['\"]([^'\"]+)['\"]", "user_token"),
                            (r"name=['\"]csrf_token['\"] value=['\"]([^'\"]+)['\"]", "csrf_token"),
                            (r"name=['\"]_token['\"] value=['\"]([^'\"]+)['\"]", "_token"),
                        ]:
                            match = re.search(pattern, resp.text)
                            if match:
                                csrf_token = match.group(1)
                                csrf_field = field
                                break

                        for creds in default_creds:
                            post_data = dict(creds)
                            if csrf_token and csrf_field:
                                post_data[csrf_field] = csrf_token

                            resp = await client.post(url, data=post_data, follow_redirects=False)

                            location = resp.headers.get("location", "")
                            if resp.status_code in (301, 302, 303) and "login" not in location.lower():
                                all_cookies = dict(client.cookies)
                                all_cookies.update(dict(resp.cookies))

                                if all_cookies:
                                    if "PHPSESSID" in all_cookies:
                                        async with make_client(
                                            cookies=all_cookies
                                        ) as auth_client:
                                            await auth_client.post(
                                                f"{base_url}/security.php",
                                                data={"security": "low", "seclev_submit": "Submit"},
                                            )
                                    return "; ".join(f"{k}={v}" for k, v in all_cookies.items())
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    async def _crawl(self, target: str, url: str = None) -> list[dict]:
        """Crawl target with katana."""
        crawl_url = url or f"https://{target}"
        cmd = [
            "katana",
            "-u", crawl_url,
            "-d", "3",        # depth
            "-jc",             # JavaScript crawling
            "-kf", "all",     # known files
            "-silent",
            "-nc",
            "-timeout", "10",
        ]
        if self._auth_cookie:
            cmd.extend(["-H", f"Cookie: {self._auth_cookie}"])
        for hk, hv in self._custom_headers.items():
            cmd.extend(["-H", f"{hk}: {hv}"])
        from app.utils.http_client import get_proxy_url
        proxy_url = get_proxy_url()
        if proxy_url:
            cmd.extend(["-proxy", proxy_url])
        output = await run_command(cmd, timeout=180)

        endpoints = []
        if output:
            for line in output.strip().split("\n"):
                url = line.strip()
                if url:
                    endpoints.append(self._classify_endpoint(url))

        # Retry with longer timeout if katana found nothing
        if not endpoints:
            cmd_retry = [
                "katana", "-u", crawl_url, "-d", "5", "-jc", "-kf", "all",
                "-silent", "-nc", "-timeout", "15",
            ]
            if self._auth_cookie:
                cmd_retry.extend(["-H", f"Cookie: {self._auth_cookie}"])
            for hk, hv in self._custom_headers.items():
                cmd_retry.extend(["-H", f"{hk}: {hv}"])
            from app.utils.http_client import get_proxy_url
            proxy_url = get_proxy_url()
            if proxy_url:
                cmd_retry.extend(["-proxy", proxy_url])
            output = await run_command(cmd_retry, timeout=300)
            if output:
                for line in output.strip().split("\n"):
                    url = line.strip()
                    if url:
                        endpoints.append(self._classify_endpoint(url))

        return endpoints

    async def _gau_urls(self, domain: str) -> list[dict]:
        """Get known URLs from various sources (Wayback, Common Crawl, etc.)."""
        output = await run_command(
            ["gau", "--threads", "5", domain],
            timeout=120,
        )

        endpoints = []
        if output:
            for line in output.strip().split("\n")[:300]:
                url = line.strip()
                if url and not any(ext in url for ext in [".jpg", ".png", ".gif", ".css", ".woff"]):
                    endpoints.append(self._classify_endpoint(url))
        return endpoints

    async def _fuzz_common_paths(self, target: str, base_url: str = None) -> list[dict]:
        """Fuzz common paths and files."""
        fuzz_base = base_url or f"https://{target}"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(COMMON_DIRS))
            wordlist_path = f.name

        try:
            cmd = [
                "ffuf",
                "-u", f"{fuzz_base}/FUZZ",
                "-w", wordlist_path,
                "-mc", "200,201,301,302,307,401,403,405,500",
                "-t", "20",
                "-timeout", "5",
                "-s",  # silent
            ]
            if self._auth_cookie:
                cmd.extend(["-H", f"Cookie: {self._auth_cookie}"])
            for hk, hv in self._custom_headers.items():
                cmd.extend(["-H", f"{hk}: {hv}"])
            from app.utils.http_client import get_proxy_url
            proxy_url = get_proxy_url()
            if proxy_url:
                cmd.extend(["-x", proxy_url])
            output = await run_command(cmd, timeout=60)

            endpoints = []
            if output:
                for line in output.strip().split("\n"):
                    path = line.strip()
                    if path:
                        url = f"{fuzz_base}/{path}"
                        endpoint = self._classify_endpoint(url)
                        endpoint["discovery"] = "fuzzing"
                        endpoints.append(endpoint)
            return endpoints
        finally:
            os.unlink(wordlist_path)

    def _extract_forms(self, page_url: str, base_url: str, html: str) -> list[dict]:
        """Extract HTML forms with their fields for POST-based testing."""
        import re
        forms = []
        # Find all <form> blocks
        form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        form_attrs = re.findall(r'<form([^>]*)>', html, re.IGNORECASE)

        for i, (attrs, body) in enumerate(zip(form_attrs, form_blocks)):
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""

            # Resolve action URL
            if not action or action == "#":
                form_url = page_url
            elif action.startswith("http"):
                form_url = action
            elif action.startswith("/"):
                form_url = base_url + action
            else:
                form_url = page_url.rstrip("/") + "/" + action

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            method = (method_match.group(1).upper() if method_match else "GET")

            # Extract input fields
            fields = []
            inputs = re.findall(r'<input[^>]*>', body, re.IGNORECASE)
            for inp in inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                if name_match:
                    field_name = name_match.group(1)
                    field_type = type_match.group(1).lower() if type_match else "text"
                    field_value = value_match.group(1) if value_match else ""
                    # Skip submit buttons and hidden CSRF tokens for injection
                    if field_type not in ("submit", "hidden", "button"):
                        fields.append({"name": field_name, "type": field_type, "value": field_value})

            # Also extract textarea and select
            textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            for ta in textareas:
                fields.append({"name": ta, "type": "textarea", "value": ""})

            selects = re.findall(r'<select[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            for sel in selects:
                fields.append({"name": sel, "type": "select", "value": ""})

            # Extract hidden fields and submit buttons (needed for CSRF tokens, submit values)
            hidden_fields = {}
            for inp in inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', inp, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                if name_match and type_match and type_match.group(1).lower() in ("hidden", "submit"):
                    hidden_fields[name_match.group(1)] = value_match.group(1) if value_match else ""

            if fields:
                endpoint = {
                    "url": form_url,
                    "type": "form",
                    "interest": "high",
                    "method": method,
                    "fields": [f["name"] for f in fields],
                    "field_details": fields,
                    "hidden_fields": hidden_fields,
                    "source_page": page_url,
                    "params": [f["name"] for f in fields],
                }
                forms.append(endpoint)

        return forms

    async def _extract_js_endpoints(self, base_url: str) -> list[dict]:
        """Extract API endpoints, URLs, and secrets from JavaScript files."""
        import re
        endpoints = []

        try:
            headers = dict(self._custom_headers)
            if self._auth_cookie:
                if self._auth_cookie.startswith("token="):
                    headers["Authorization"] = f"Bearer {self._auth_cookie.split('=', 1)[1]}"
                else:
                    headers["Cookie"] = self._auth_cookie

            async with make_client(extra_headers=headers) as client:
                # Fetch main page to find JS files
                resp = await client.get(base_url + "/")
                if resp.status_code != 200:
                    return []

                # Find all script sources
                js_urls = set()
                for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I):
                    src = match.group(1)
                    if src.startswith("http"):
                        js_urls.add(src)
                    elif src.startswith("//"):
                        js_urls.add("https:" + src)
                    elif src.startswith("/"):
                        js_urls.add(base_url + src)

                # Fetch and analyze each JS file
                url_pattern = re.compile(
                    r'["\'](/(?:api|v[0-9]|rest|auth|admin|user|internal|graphql)'
                    r'[/a-zA-Z0-9_\-\.]*)["\']'
                )
                full_url_pattern = re.compile(
                    r'["\']https?://[a-zA-Z0-9\-\.]+\.[a-z]{2,}/[a-zA-Z0-9/_\-\.?&=]*["\']'
                )
                secret_pattern = re.compile(
                    r'(?:api[_-]?key|apikey|secret|token|password|auth|bearer)'
                    r'[\s]*[:=]\s*["\']([^"\']{8,})["\']',
                    re.I,
                )

                for js_url in list(js_urls)[:15]:
                    try:
                        js_resp = await client.get(js_url)
                        if js_resp.status_code != 200 or len(js_resp.text) > 2_000_000:
                            continue
                        js_text = js_resp.text

                        # Extract relative API paths
                        for m in url_pattern.finditer(js_text):
                            path = m.group(1)
                            full = base_url + path
                            ep = self._classify_endpoint(full)
                            ep["discovery"] = "js_extraction"
                            ep["source_js"] = js_url
                            endpoints.append(ep)

                        # Extract full URLs
                        for m in full_url_pattern.finditer(js_text):
                            url = m.group(0).strip("\"'")
                            ep = self._classify_endpoint(url)
                            ep["discovery"] = "js_extraction"
                            endpoints.append(ep)

                        # Extract potential secrets/API keys
                        for m in secret_pattern.finditer(js_text):
                            secret_val = m.group(1)
                            if len(secret_val) > 100:
                                continue
                            endpoints.append({
                                "url": js_url,
                                "type": "sensitive",
                                "interest": "critical",
                                "params": [],
                                "discovery": "js_secret",
                                "secret_hint": secret_val[:20] + "...",
                            })

                    except Exception:
                        continue

        except Exception:
            pass

        return endpoints

    async def _check_graphql(self, base_url: str) -> list[dict]:
        """Detect GraphQL endpoints and attempt introspection."""
        endpoints = []
        graphql_paths = [
            "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
            "/playground", "/graphql/console", "/gql",
        ]

        introspection_query = {
            "query": '{ __schema { types { name kind description fields { name type { name } } } } }'
        }

        try:
            headers = dict(self._custom_headers)
            if self._auth_cookie:
                if self._auth_cookie.startswith("token="):
                    headers["Authorization"] = f"Bearer {self._auth_cookie.split('=', 1)[1]}"
                else:
                    headers["Cookie"] = self._auth_cookie

            async with make_client(extra_headers=headers) as client:
                for path in graphql_paths:
                    url = base_url + path
                    try:
                        resp = await client.post(
                            url,
                            json=introspection_query,
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                if data.get("data", {}).get("__schema"):
                                    # Introspection succeeded — extract types/fields
                                    schema = data["data"]["__schema"]
                                    types = schema.get("types", [])
                                    user_types = [
                                        t for t in types
                                        if t.get("name") and not t["name"].startswith("__")
                                        and t.get("kind") in ("OBJECT",)
                                    ]

                                    endpoints.append({
                                        "url": url,
                                        "type": "api",
                                        "interest": "critical",
                                        "params": [],
                                        "discovery": "graphql_introspection",
                                        "graphql_types": [t["name"] for t in user_types[:20]],
                                    })

                                    # Generate query endpoints for each type
                                    for t in user_types[:10]:
                                        fields = t.get("fields", [])
                                        field_names = [f["name"] for f in (fields or [])[:5]]
                                        if field_names:
                                            endpoints.append({
                                                "url": url,
                                                "type": "api",
                                                "interest": "high",
                                                "params": field_names,
                                                "discovery": "graphql_type",
                                                "graphql_type": t["name"],
                                            })
                            except Exception:
                                pass
                    except Exception:
                        continue

        except Exception:
            pass

        return endpoints

    async def _check_http_methods(self, base_url: str) -> list[dict]:
        """Test interesting endpoints for unexpected HTTP methods (PUT, DELETE, PATCH)."""
        endpoints = []
        test_paths = [
            "/api/users", "/api/admin", "/api/user", "/api/config",
            "/api/settings", "/api/account", "/api/v1/users",
        ]

        try:
            headers = dict(self._custom_headers)
            if self._auth_cookie:
                if self._auth_cookie.startswith("token="):
                    headers["Authorization"] = f"Bearer {self._auth_cookie.split('=', 1)[1]}"
                else:
                    headers["Cookie"] = self._auth_cookie

            async with make_client(extra_headers=headers) as client:
                for path in test_paths:
                    url = base_url + path
                    try:
                        # OPTIONS reveals allowed methods
                        resp = await client.options(url)
                        allow = resp.headers.get("allow", "")
                        if allow:
                            methods = [m.strip().upper() for m in allow.split(",")]
                            dangerous = {"PUT", "DELETE", "PATCH"} & set(methods)
                            if dangerous:
                                endpoints.append({
                                    "url": url,
                                    "type": "api",
                                    "interest": "high",
                                    "params": [],
                                    "discovery": "http_methods",
                                    "allowed_methods": methods,
                                    "dangerous_methods": list(dangerous),
                                })

                        # TRACE can leak headers
                        resp = await client.request("TRACE", url)
                        if resp.status_code == 200 and "TRACE" in resp.text:
                            endpoints.append({
                                "url": url,
                                "type": "sensitive",
                                "interest": "high",
                                "params": [],
                                "discovery": "trace_enabled",
                            })
                    except Exception:
                        continue

        except Exception:
            pass

        return endpoints

    # Static file extensions — not useful for exploit testing
    _STATIC_EXTS = frozenset([
        ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
        ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz", ".br",
    ])

    async def _spa_render_discovery(self, base_url: str) -> list[dict]:
        """Use Playwright to render SPA pages and intercept API calls + discover routes."""
        import re
        endpoints = []

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    ignore_https_errors=True,
                )

                # Intercept network requests to capture API calls
                api_calls = []

                async def on_request(request):
                    url = request.url
                    if any(p in url for p in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
                        api_calls.append({
                            "url": url,
                            "method": request.method,
                        })

                page = await context.new_page()
                page.on("request", on_request)

                # Set auth if available
                if self._auth_cookie:
                    if self._auth_cookie.startswith("token="):
                        token = self._auth_cookie.split("=", 1)[1]
                        await context.set_extra_http_headers({"Authorization": f"Bearer {token}"})
                    else:
                        cookies = []
                        from urllib.parse import urlparse
                        domain = urlparse(base_url).hostname
                        for part in self._auth_cookie.split(";"):
                            part = part.strip()
                            if "=" in part:
                                k, v = part.split("=", 1)
                                cookies.append({"name": k.strip(), "value": v.strip(), "domain": domain, "path": "/"})
                        if cookies:
                            await context.add_cookies(cookies)

                # Visit main page and wait for SPA to render
                try:
                    await page.goto(base_url, wait_until="networkidle", timeout=30000)
                    await page.wait_for_timeout(3000)  # Extra wait for lazy-loaded content
                except Exception:
                    try:
                        await page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
                        await page.wait_for_timeout(2000)
                    except Exception:
                        await browser.close()
                        return []

                # Extract all links from rendered DOM (SPA routes)
                rendered_links = await page.evaluate("""() => {
                    const links = new Set();
                    // href links
                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.getAttribute('href');
                        if (href && !href.startsWith('javascript:') && !href.startsWith('#'))
                            links.add(href);
                    });
                    // React Router / Vue Router: data-href, to attributes
                    document.querySelectorAll('[data-href], [to]').forEach(el => {
                        const val = el.getAttribute('data-href') || el.getAttribute('to');
                        if (val) links.add(val);
                    });
                    // Buttons with onclick navigation
                    document.querySelectorAll('[onclick]').forEach(el => {
                        const onclick = el.getAttribute('onclick');
                        const match = onclick.match(/(?:location|href|navigate|push).*?['"](\/[^'"]+)['"]/);
                        if (match) links.add(match[1]);
                    });
                    return [...links];
                }""")

                for link in rendered_links:
                    if link.startswith("http"):
                        full_url = link
                    elif link.startswith("/"):
                        full_url = base_url.rstrip("/") + link
                    else:
                        continue
                    ep = self._classify_endpoint(full_url)
                    ep["discovery"] = "spa_render"
                    endpoints.append(ep)

                # Extract forms from rendered DOM
                forms_data = await page.evaluate("""() => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(form => {
                        const fields = [];
                        form.querySelectorAll('input, textarea, select').forEach(inp => {
                            const name = inp.getAttribute('name') || inp.getAttribute('id');
                            const type = inp.getAttribute('type') || inp.tagName.toLowerCase();
                            if (name && type !== 'submit' && type !== 'hidden')
                                fields.push({name, type});
                        });
                        if (fields.length > 0) {
                            forms.push({
                                action: form.getAttribute('action') || '',
                                method: (form.getAttribute('method') || 'GET').toUpperCase(),
                                fields: fields,
                            });
                        }
                    });
                    return forms;
                }""")

                for form in forms_data:
                    action = form["action"]
                    if not action or action == "#":
                        form_url = base_url
                    elif action.startswith("http"):
                        form_url = action
                    elif action.startswith("/"):
                        form_url = base_url.rstrip("/") + action
                    else:
                        form_url = base_url.rstrip("/") + "/" + action

                    endpoints.append({
                        "url": form_url,
                        "type": "form",
                        "interest": "high",
                        "method": form["method"],
                        "fields": [f["name"] for f in form["fields"]],
                        "field_details": form["fields"],
                        "params": [f["name"] for f in form["fields"]],
                        "discovery": "spa_render",
                    })

                # Add intercepted API calls
                for call in api_calls:
                    ep = self._classify_endpoint(call["url"])
                    ep["discovery"] = "spa_api_intercept"
                    ep["method"] = call["method"]
                    endpoints.append(ep)

                # Try clicking navigation elements to discover more routes
                try:
                    nav_links = await page.query_selector_all("nav a, [role='navigation'] a, .sidebar a, .menu a")
                    for link in nav_links[:10]:
                        try:
                            href = await link.get_attribute("href")
                            if href and href.startswith("/"):
                                full_url = base_url.rstrip("/") + href
                                ep = self._classify_endpoint(full_url)
                                ep["discovery"] = "spa_nav"
                                endpoints.append(ep)
                        except Exception:
                            continue
                except Exception:
                    pass

                await browser.close()

        except ImportError:
            pass  # Playwright not installed
        except Exception:
            pass

        return endpoints

    def _classify_endpoint(self, url: str) -> dict:
        """Classify an endpoint by type and interest level."""
        endpoint = {
            "url": url,
            "type": "page",
            "interest": "low",
            "params": [],
        }

        url_lower = url.lower()
        # Strip query string for extension check
        path_lower = url_lower.split("?")[0]

        # Skip static assets — never useful for exploitation
        if any(path_lower.endswith(ext) for ext in self._STATIC_EXTS):
            endpoint["type"] = "static"
            endpoint["interest"] = "none"
            return endpoint

        # Classify type
        if "/api/" in url_lower or "/rest/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower or "/graphql" in url_lower:
            endpoint["type"] = "api"
            endpoint["interest"] = "high"
        elif any(p in url_lower for p in ["/admin", "/panel", "/dashboard", "/login"]):
            endpoint["type"] = "admin"
            endpoint["interest"] = "high"
        elif any(p in url_lower for p in ["/upload", "/import", "/file"]):
            endpoint["type"] = "upload"
            endpoint["interest"] = "high"
        elif any(p in url_lower for p in [".env", ".git", "config", "backup", "dump"]):
            endpoint["type"] = "sensitive"
            endpoint["interest"] = "critical"
        elif any(p in url_lower for p in ["/search", "/redirect", "/callback", "/proxy"]):
            endpoint["type"] = "injectable"
            endpoint["interest"] = "high"
        elif "?" in url:
            endpoint["type"] = "parameterized"
            endpoint["interest"] = "medium"
            # Extract parameters
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            endpoint["params"] = list(parse_qs(parsed.query).keys())

        return endpoint
