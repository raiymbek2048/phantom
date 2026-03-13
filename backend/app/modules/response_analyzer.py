"""
Response Analyzer — extracts intelligence from HTTP responses.

Pure analysis module, no HTTP requests. Used by other attack modules
to understand server responses: WAF detection, tech fingerprinting,
secret extraction, reflection analysis, CORS misconfiguration.
"""

import logging
import re
import json
from typing import Optional

logger = logging.getLogger(__name__)


class ResponseAnalyzer:
    """Stateless HTTP response analysis utility."""

    # ------------------------------------------------------------------ #
    # 1. WAF Detection
    # ------------------------------------------------------------------ #

    # Header signatures: header_name_lower -> [(value_substring, waf_name)]
    _WAF_HEADER_SIGNATURES = {
        "server": [
            ("cloudflare", "Cloudflare"),
            ("akamaighost", "Akamai"),
            ("sucuri", "Sucuri"),
            ("barracuda", "Barracuda"),
            ("bigip", "F5 BIG-IP"),
            ("incapsula", "Imperva Incapsula"),
            ("safedog", "SafeDog"),
            ("naxsi", "NAXSI"),
            ("webknight", "WebKnight"),
            ("dosarrest", "DOSArrest"),
        ],
        "x-cdn": [
            ("incapsula", "Imperva Incapsula"),
            ("akamai", "Akamai"),
            ("fastly", "Fastly"),
        ],
        "x-sucuri-id": [("", "Sucuri")],
        "cf-ray": [("", "Cloudflare")],
        "x-powered-by": [
            ("aspnet", "ASP.NET"),
        ],
        "via": [
            ("varnish", "Varnish"),
        ],
        "x-cache": [
            ("varnish", "Varnish"),
        ],
    }

    # Akamai uses multiple X-Akamai-* headers
    _WAF_HEADER_PREFIXES = [
        ("x-akamai-", "Akamai"),
        ("x-distil-", "Distil Networks"),
        ("x-sucuri-", "Sucuri"),
    ]

    # Body patterns: (regex, waf_name, confidence)
    _WAF_BODY_PATTERNS = [
        (re.compile(r"Attention Required\!.*Cloudflare", re.I | re.S), "Cloudflare", 0.95),
        (re.compile(r"cf-browser-verification", re.I), "Cloudflare", 0.90),
        (re.compile(r"jschl-answer|__cf_chl_jschl_tk__", re.I), "Cloudflare", 0.95),
        (re.compile(r"<title>Access Denied.*Akamai</title>", re.I | re.S), "Akamai", 0.90),
        (re.compile(r"AkamaiGHost", re.I), "Akamai", 0.85),
        (re.compile(r"Reference\s*#\s*[\d.]+", re.I), "Akamai", 0.60),
        (re.compile(r"aws[_\s-]?waf", re.I), "AWS WAF", 0.90),
        (re.compile(r"<h1>403 Forbidden</h1>.*awselb", re.I | re.S), "AWS WAF", 0.80),
        (re.compile(r"mod_security|modsecurity|NOYB", re.I), "ModSecurity", 0.90),
        (re.compile(r"sucuri\.net|access denied.*sucuri", re.I), "Sucuri", 0.90),
        (re.compile(r"incapsula incident", re.I), "Imperva Incapsula", 0.95),
        (re.compile(r"_Incapsula_Resource", re.I), "Imperva Incapsula", 0.90),
        (re.compile(r"visid_incap_", re.I), "Imperva Incapsula", 0.85),
        (re.compile(r"BigIP|BIGipServer", re.I), "F5 BIG-IP", 0.85),
        (re.compile(r"barracuda[_\s]", re.I), "Barracuda", 0.85),
        (re.compile(r"blocked by.*Wordfence", re.I), "Wordfence", 0.95),
        (re.compile(r"this has been blocked by.*DenyAll", re.I), "DenyAll", 0.85),
        (re.compile(r"Protected by.*SiteLock", re.I), "SiteLock", 0.85),
        (re.compile(r"fortigate|fortiweb", re.I), "FortiWeb", 0.85),
        (re.compile(r"comodo\s?waf", re.I), "Comodo WAF", 0.85),
    ]

    @staticmethod
    def detect_waf(headers: dict, body: str, status_code: int) -> dict:
        """
        Detect Web Application Firewall from response characteristics.

        Returns:
            {"detected": bool, "waf_name": str, "confidence": float, "evidence": str}
        """
        best = {"detected": False, "waf_name": "", "confidence": 0.0, "evidence": ""}

        def _update(name: str, conf: float, evidence: str):
            if conf > best["confidence"]:
                best["detected"] = True
                best["waf_name"] = name
                best["confidence"] = conf
                best["evidence"] = evidence

        headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

        # --- Header-based detection ---
        for hdr, signatures in ResponseAnalyzer._WAF_HEADER_SIGNATURES.items():
            val = headers_lower.get(hdr, "")
            if not val:
                continue
            val_lower = val.lower()
            for substr, waf_name in signatures:
                if substr == "" or substr in val_lower:
                    _update(waf_name, 0.85, f"Header {hdr}: {val}")

        for prefix, waf_name in ResponseAnalyzer._WAF_HEADER_PREFIXES:
            for hdr in headers_lower:
                if hdr.startswith(prefix):
                    _update(waf_name, 0.80, f"Header prefix {prefix}: {hdr}={headers_lower[hdr]}")

        # --- Body-based detection ---
        body = body or ""
        for pattern, waf_name, conf in ResponseAnalyzer._WAF_BODY_PATTERNS:
            m = pattern.search(body[:50000])  # limit scan length
            if m:
                _update(waf_name, conf, f"Body match: {m.group()[:120]}")

        # --- Status-code heuristics ---
        if status_code == 406:
            _update(best.get("waf_name") or "Unknown WAF", max(best["confidence"], 0.50),
                    "HTTP 406 Not Acceptable — typical WAF rejection")
        if status_code == 429:
            _update(best.get("waf_name") or "Rate Limiter", max(best["confidence"], 0.40),
                    "HTTP 429 Too Many Requests")
        if status_code == 403 and not best["detected"]:
            # Generic 403 without a known WAF body — low-confidence guess
            if any(kw in body.lower() for kw in ["blocked", "denied", "forbidden", "firewall"]):
                _update("Unknown WAF", 0.45, "HTTP 403 with blocking keywords in body")

        return best

    # ------------------------------------------------------------------ #
    # 2. Technology Leak Extraction
    # ------------------------------------------------------------------ #

    _COOKIE_FRAMEWORKS = {
        "jsessionid": ("Java (Servlet/Spring)", "framework"),
        "phpsessid": ("PHP", "framework"),
        "asp.net_sessionid": ("ASP.NET", "framework"),
        "aspsessionid": ("Classic ASP", "framework"),
        "csrftoken": ("Django", "framework"),
        "_rails_session": ("Ruby on Rails", "framework"),
        "laravel_session": ("Laravel (PHP)", "framework"),
        "ci_session": ("CodeIgniter (PHP)", "framework"),
        "cakephp": ("CakePHP", "framework"),
        "_flask_session": ("Flask (Python)", "framework"),
        "connect.sid": ("Express.js (Node)", "framework"),
        "rack.session": ("Rack (Ruby)", "framework"),
        "mojolicious": ("Mojolicious (Perl)", "framework"),
        "play_session": ("Play Framework (Scala/Java)", "framework"),
        "symfony": ("Symfony (PHP)", "framework"),
        "wp_settings": ("WordPress", "framework"),
        "joomla_user_state": ("Joomla", "framework"),
        "drupal.visitor": ("Drupal", "framework"),
    }

    _DEBUG_PATTERNS = [
        (re.compile(r"Traceback \(most recent call last\)", re.I), "Python traceback", "debug"),
        (re.compile(r"at\s+[\w.]+\([\w]+\.java:\d+\)", re.I), "Java stack trace", "debug"),
        (re.compile(r"You're seeing this error because you have <code>DEBUG\s*=\s*True</code>", re.I),
         "Django debug page", "debug"),
        (re.compile(r"<b>(?:Fatal|Parse|Notice|Warning) error</b>:.*in <b>(.*?)</b> on line <b>(\d+)</b>", re.I),
         "PHP error", "debug"),
        (re.compile(r"Parse error:.*\.php", re.I), "PHP parse error", "debug"),
        (re.compile(r"(?:TypeError|ReferenceError|SyntaxError):.*\n\s+at\s+", re.I),
         "Node.js/Express error", "debug"),
        (re.compile(r"Microsoft \.NET Framework.*Version:\d", re.I), "ASP.NET error page", "debug"),
        (re.compile(r"<title>Error - Application is not available</title>", re.I),
         "Spring Boot Whitelabel error", "debug"),
        (re.compile(r"ActionController::RoutingError", re.I), "Rails routing error", "debug"),
        (re.compile(r"RuntimeError at /", re.I), "Django RuntimeError", "debug"),
        (re.compile(r"SQLSTATE\[\w+\]", re.I), "PDO/SQL error", "debug"),
        (re.compile(r"pg_query\(\): ERROR", re.I), "PostgreSQL raw error", "debug"),
        (re.compile(r"mysql_fetch|mysqli_", re.I), "MySQL raw error", "debug"),
    ]

    _VERSION_HEADERS = [
        ("server", "version"),
        ("x-powered-by", "version"),
        ("x-aspnet-version", "version"),
        ("x-aspnetmvc-version", "version"),
        ("x-generator", "version"),
        ("x-drupal-cache", "version"),
        ("x-varnish", "version"),
        ("x-runtime", "version"),
    ]

    @staticmethod
    def extract_tech_leaks(headers: dict, body: str) -> list:
        """
        Extract technology and version information leaked in response.

        Returns:
            List of {"type": "version|framework|debug", "name": str, "value": str, "source": str}
        """
        results = []
        seen = set()
        headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

        # --- Version headers ---
        for hdr, leak_type in ResponseAnalyzer._VERSION_HEADERS:
            val = headers_lower.get(hdr, "")
            if val:
                key = (leak_type, hdr, val)
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": leak_type,
                        "name": hdr,
                        "value": val,
                        "source": f"header:{hdr}",
                    })

        # --- Cookie-based framework detection ---
        set_cookie = headers_lower.get("set-cookie", "")
        cookie_str = set_cookie.lower() if isinstance(set_cookie, str) else ""
        # Handle list of Set-Cookie headers (some HTTP libs return lists)
        if isinstance(set_cookie, list):
            cookie_str = " ".join(c.lower() for c in set_cookie)

        for cookie_name, (framework, leak_type) in ResponseAnalyzer._COOKIE_FRAMEWORKS.items():
            if cookie_name in cookie_str:
                key = ("framework", framework)
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": leak_type,
                        "name": framework,
                        "value": cookie_name,
                        "source": "cookie",
                    })

        # --- Debug / error pattern detection in body ---
        body = body or ""
        for pattern, name, leak_type in ResponseAnalyzer._DEBUG_PATTERNS:
            m = pattern.search(body[:100000])
            if m:
                key = ("debug", name)
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": leak_type,
                        "name": name,
                        "value": m.group()[:200],
                        "source": "body",
                    })

        return results

    # ------------------------------------------------------------------ #
    # 3. Error Pattern Analysis
    # ------------------------------------------------------------------ #

    _INTERNAL_IP_RE = re.compile(
        r"(?:^|[^\d])((?:10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})(?:[^\d]|$)"
    )
    _FILE_PATH_RE = re.compile(
        r"(?:/(?:var|home|usr|opt|etc|srv|tmp|www|app|root)/[\w./-]{3,120})"
        r"|(?:[A-Z]:\\[\w\\. -]{3,120})"
    )
    _DB_NAME_RE = re.compile(
        r"(?:database|schema|catalog)\s*[=:\"']\s*([\w.-]+)", re.I
    )
    _USERNAME_RE = re.compile(
        r"(?:user(?:name)?|login|acct)\s*[=:\"']\s*([\w@.\-]+)", re.I
    )
    _STACK_FRAME_RE = re.compile(
        r"(?:at\s+[\w.$<>]+\([\w.]+:\d+\))"
        r"|(?:File \"[^\"]+\", line \d+)"
        r"|(?:#\d+\s+[\w\\/:]+\.php\(\d+\))"
        r"|(?:in\s+/[\w/.-]+\.(?:rb|py|php|java|go|rs|js|ts):\d+)"
    )

    _DEFAULT_ERROR_SIGS = [
        (re.compile(r"<title>404 Not Found</title>", re.I), True),
        (re.compile(r"<center>nginx", re.I), True),
        (re.compile(r"<address>Apache/", re.I), True),
        (re.compile(r"<h1>Not Found</h1>\s*<p>The requested URL", re.I | re.S), True),
        (re.compile(r"<title>403 Forbidden</title>", re.I), True),
        (re.compile(r"IIS.*Microsoft", re.I), True),
        (re.compile(r"<title>502 Bad Gateway</title>", re.I), True),
    ]

    @staticmethod
    def analyze_error(status_code: int, headers: dict, body: str) -> dict:
        """
        Classify error responses and extract leaked information.

        Returns:
            {"error_type": str, "is_custom_page": bool, "leaked_info": list[str], "suggests_auth": bool}
        """
        body = body or ""
        body_lower = body.lower()

        # --- Classify error type ---
        error_type = "unknown"
        suggests_auth = False

        if status_code == 401 or (status_code == 403 and "login" in body_lower):
            error_type = "auth_required"
            suggests_auth = True
        elif status_code == 403:
            # Disambiguate WAF block from plain forbidden
            waf_kw = ["blocked", "firewall", "security", "waf", "captcha", "challenge"]
            if any(kw in body_lower for kw in waf_kw):
                error_type = "waf_blocked"
            else:
                error_type = "forbidden"
        elif status_code == 404:
            error_type = "not_found"
        elif status_code == 405:
            error_type = "method_not_allowed"
        elif status_code == 429:
            error_type = "rate_limited"
        elif status_code == 503 and any(kw in body_lower for kw in ["maintenance", "temporarily", "upgrade"]):
            error_type = "maintenance"
        elif 500 <= status_code < 600:
            error_type = "server_error"
        elif status_code in (301, 302, 307, 308):
            location = (headers or {}).get("Location", (headers or {}).get("location", ""))
            if location and any(kw in location.lower() for kw in ["login", "auth", "signin", "sso"]):
                error_type = "auth_required"
                suggests_auth = True
            else:
                error_type = "redirect"

        # --- Detect custom vs default error page ---
        is_custom = True
        for sig, is_default_flag in ResponseAnalyzer._DEFAULT_ERROR_SIGS:
            if sig.search(body[:10000]):
                is_custom = False
                break
        # Very short bodies are likely default
        stripped = body.strip()
        if len(stripped) < 50 and status_code >= 400:
            is_custom = False

        # --- Extract leaked info ---
        leaked = []
        search_body = body[:200000]

        for m in ResponseAnalyzer._INTERNAL_IP_RE.finditer(search_body):
            leaked.append(f"internal_ip:{m.group(1)}")

        for m in ResponseAnalyzer._FILE_PATH_RE.finditer(search_body):
            leaked.append(f"file_path:{m.group()}")

        for m in ResponseAnalyzer._DB_NAME_RE.finditer(search_body):
            leaked.append(f"db_name:{m.group(1)}")

        for m in ResponseAnalyzer._USERNAME_RE.finditer(search_body):
            leaked.append(f"username:{m.group(1)}")

        frames = ResponseAnalyzer._STACK_FRAME_RE.findall(search_body)
        if frames:
            leaked.append(f"stack_frames:{len(frames)}")

        # Deduplicate
        leaked = list(dict.fromkeys(leaked))

        return {
            "error_type": error_type,
            "is_custom_page": is_custom,
            "leaked_info": leaked,
            "suggests_auth": suggests_auth,
        }

    # ------------------------------------------------------------------ #
    # 4. Token / Secret Detection
    # ------------------------------------------------------------------ #

    _SECRET_PATTERNS = [
        # (name, regex, severity)
        ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "high"),
        ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
        ("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I), "critical"),
        ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "high"),
        ("Google OAuth", re.compile(r"\d+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"), "high"),
        ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical"),
        ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "medium"),
        ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "critical"),
        ("GitHub Classic Token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "critical"),
        ("Slack Bot Token", re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}"), "critical"),
        ("Slack User Token", re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}"), "critical"),
        ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}"), "high"),
        ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "critical"),
        ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), "high"),
        ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "high"),
        ("Heroku API Key", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.I), "medium"),
        ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
        ("Database URL (Postgres)", re.compile(r"postgres(?:ql)?://[^\s\"'<>]{10,}"), "critical"),
        ("Database URL (MySQL)", re.compile(r"mysql://[^\s\"'<>]{10,}"), "critical"),
        ("Database URL (MongoDB)", re.compile(r"mongodb(?:\+srv)?://[^\s\"'<>]{10,}"), "critical"),
        ("Database URL (Redis)", re.compile(r"redis://[^\s\"'<>]{10,}"), "high"),
        ("Hardcoded Password", re.compile(
            r"""(?:password|passwd|pwd|secret|token|api_?key|auth_?token|access_?token)\s*[=:]\s*['"]([^'"]{6,80})['"]""",
            re.I
        ), "high"),
        ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}"), "high"),
        ("Basic Auth", re.compile(r"Basic\s+[A-Za-z0-9+/=]{10,}"), "high"),
        ("Azure Storage Key", re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}"), "critical"),
        ("Firebase URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "medium"),
        ("Telegram Bot Token", re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"), "high"),
        ("Square Access Token", re.compile(r"sq0atp-[0-9A-Za-z_-]{22}"), "high"),
        ("Shopify Token", re.compile(r"shpat_[a-fA-F0-9]{32}"), "high"),
    ]

    @staticmethod
    def find_secrets(body: str) -> list:
        """
        Scan response body for leaked secrets, tokens, and credentials.

        Returns:
            List of {"type": str, "value": str (truncated), "full_value": str, "severity": str}
        """
        if not body:
            return []

        results = []
        seen_values = set()
        search_body = body[:500000]  # limit scan scope

        for name, pattern, severity in ResponseAnalyzer._SECRET_PATTERNS:
            for m in pattern.finditer(search_body):
                full = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group()
                if full in seen_values:
                    continue
                seen_values.add(full)

                truncated = full[:20] + "..." if len(full) > 20 else full
                results.append({
                    "type": name,
                    "value": truncated,
                    "full_value": full,
                    "severity": severity,
                })

        return results

    # ------------------------------------------------------------------ #
    # 5. Input Reflection Analysis
    # ------------------------------------------------------------------ #

    @staticmethod
    def detect_reflection(body: str, inputs: list) -> list:
        """
        Check if input strings are reflected in the response and determine context.

        Args:
            body: Response body to search.
            inputs: List of input strings to look for.

        Returns:
            List of {"input": str, "context": str, "encoded": bool, "breakout_possible": bool}
        """
        if not body or not inputs:
            return []

        results = []

        for inp in inputs:
            if not inp or len(inp) < 2:
                continue

            # Check for raw reflection
            raw_found = inp in body
            # Check for common encodings
            import html as html_mod
            import urllib.parse

            html_encoded = html_mod.escape(inp)
            url_encoded = urllib.parse.quote(inp)
            unicode_escaped = inp.encode("unicode_escape").decode("ascii")

            encoded = False
            if not raw_found:
                if html_encoded != inp and html_encoded in body:
                    encoded = True
                elif url_encoded != inp and url_encoded in body:
                    encoded = True
                elif unicode_escaped != inp and unicode_escaped in body:
                    encoded = True
                else:
                    # Not reflected at all
                    continue
            else:
                # Raw reflection exists — check if encoded version also exists
                # (some apps encode in some contexts but not others)
                pass

            # Determine reflection context
            context = ResponseAnalyzer._determine_context(body, inp, raw_found)
            breakout = ResponseAnalyzer._can_break_out(context, encoded)

            results.append({
                "input": inp,
                "context": context,
                "encoded": encoded,
                "breakout_possible": breakout,
            })

        return results

    @staticmethod
    def _determine_context(body: str, inp: str, raw: bool) -> str:
        """Identify the HTML/JS context where the input is reflected."""
        if not raw:
            return "encoded"

        idx = body.find(inp)
        if idx == -1:
            return "unknown"

        # Look at surrounding text (512 chars before and after)
        before = body[max(0, idx - 512):idx]
        after = body[idx + len(inp):idx + len(inp) + 512]

        # --- JavaScript context ---
        # Inside <script>...</script>
        last_script_open = before.rfind("<script")
        last_script_close = before.rfind("</script")
        if last_script_open > last_script_close:
            # Inside a script block — check if in a string
            for q in ['"', "'", "`"]:
                # Count unescaped quotes
                segment = before[last_script_open:]
                count = len(re.findall(r'(?<!\\)' + re.escape(q), segment))
                if count % 2 == 1:
                    return "javascript_string"
            return "javascript"

        # --- HTML attribute context ---
        # Find last unclosed tag
        last_open = max(before.rfind("<"), -1)
        last_close = max(before.rfind(">"), -1)
        if last_open > last_close:
            # We're inside a tag — check for attribute
            tag_content = before[last_open:]
            for q in ['"', "'"]:
                # Check if inside a quoted attribute value
                attr_match = re.search(r'[\w-]+\s*=\s*' + re.escape(q) + r'[^' + re.escape(q) + r']*$', tag_content)
                if attr_match:
                    return "html_attribute"
            # Inside tag but not in quoted attribute
            return "html_tag"

        # --- CSS context ---
        last_style_open = before.rfind("<style")
        last_style_close = before.rfind("</style")
        if last_style_open > last_style_close:
            return "css"

        # --- HTML comment ---
        last_comment_open = before.rfind("<!--")
        last_comment_close = before.rfind("-->")
        if last_comment_open > last_comment_close:
            return "comment"

        # --- JSON context ---
        # Rough check: surrounding braces and quotes
        stripped_before = before.rstrip()
        if stripped_before.endswith(":") or stripped_before.endswith(':"') or stripped_before.endswith(":'"):
            return "json_value"

        # --- URL context ---
        url_pattern = re.compile(r'(?:href|src|action|url)\s*=\s*["\']?[^"\'>\s]*$', re.I)
        if url_pattern.search(before[-200:]):
            return "url"

        # Default — HTML body text
        return "html_body"

    @staticmethod
    def _can_break_out(context: str, encoded: bool) -> bool:
        """Determine if breakout from the current context is likely possible."""
        if encoded:
            return False

        breakout_contexts = {
            "html_body": True,         # Can inject tags
            "html_attribute": True,    # Can close attribute + inject
            "html_tag": True,          # Can close tag
            "javascript_string": True, # Can close string + inject
            "javascript": True,        # Direct JS injection
            "url": True,               # javascript: protocol possible
            "json_value": True,        # May escape JSON context
            "comment": True,           # Can close comment -->
            "css": True,               # expression() or url() injection
            "encoded": False,
            "unknown": False,
        }
        return breakout_contexts.get(context, False)

    # ------------------------------------------------------------------ #
    # 6. CORS Analysis
    # ------------------------------------------------------------------ #

    @staticmethod
    def analyze_cors(headers: dict, origin_tested: str) -> dict:
        """
        Analyze CORS headers for misconfigurations.

        Args:
            headers: Response headers.
            origin_tested: The Origin header value that was sent in the request.

        Returns:
            {"misconfigured": bool, "type": str, "allows_credentials": bool, "details": str}
        """
        headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "").lower() == "true"
        acam = headers_lower.get("access-control-allow-methods", "")
        acah = headers_lower.get("access-control-allow-headers", "")

        if not acao:
            return {
                "misconfigured": False,
                "type": "no_cors",
                "allows_credentials": False,
                "details": "No CORS headers present",
            }

        result = {
            "misconfigured": False,
            "type": "safe",
            "allows_credentials": acac,
            "details": "",
        }

        # --- Wildcard with credentials ---
        if acao == "*" and acac:
            # Browsers block this, but it signals dev confusion
            result["misconfigured"] = True
            result["type"] = "wildcard_with_credentials"
            result["details"] = (
                "Access-Control-Allow-Origin: * with credentials=true. "
                "Browsers reject this, but it indicates misconfiguration."
            )
            return result

        # --- Wildcard (no credentials) ---
        if acao == "*":
            result["type"] = "wildcard"
            result["details"] = "Wildcard origin allowed (no credentials, lower risk)"
            return result

        # --- Null origin ---
        if acao.lower() == "null":
            result["misconfigured"] = True
            result["type"] = "null_origin"
            result["details"] = (
                "Access-Control-Allow-Origin: null — exploitable via sandboxed iframe. "
                f"Credentials: {acac}"
            )
            return result

        # --- Origin reflection ---
        if origin_tested and acao == origin_tested:
            if acac:
                result["misconfigured"] = True
                result["type"] = "origin_reflection_with_credentials"
                result["details"] = (
                    f"Server reflects Origin header ({origin_tested}) with credentials=true. "
                    "Any origin can steal authenticated data."
                )
            else:
                result["type"] = "origin_reflection"
                result["details"] = (
                    f"Server reflects Origin header ({origin_tested}) without credentials. "
                    "Lower risk but still a misconfiguration."
                )
                result["misconfigured"] = True
            return result

        # --- Subdomain matching (prefix/suffix check) ---
        if origin_tested:
            # Check if server allows subdomains too loosely
            # e.g., origin evil.example.com reflected for example.com
            tested_parts = origin_tested.split("://", 1)
            acao_parts = acao.split("://", 1)
            if len(tested_parts) == 2 and len(acao_parts) == 2:
                tested_domain = tested_parts[1].lower().rstrip("/")
                acao_domain = acao_parts[1].lower().rstrip("/")
                if tested_domain != acao_domain:
                    if tested_domain.endswith("." + acao_domain) or acao_domain.endswith("." + tested_domain):
                        result["type"] = "subdomain_match"
                        result["details"] = (
                            f"CORS allows subdomain: tested={origin_tested}, allowed={acao}. "
                            f"Credentials: {acac}"
                        )
                        if acac:
                            result["misconfigured"] = True
                        return result

        # --- Specific allowed origin (probably fine) ---
        result["details"] = f"Specific origin allowed: {acao}. Credentials: {acac}"
        return result
