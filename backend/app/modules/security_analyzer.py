"""
Deep Security Header Analyzer

Performs in-depth analysis of CSP, CORS, cookies, and security headers
beyond simple existence checks. Identifies misconfigurations with
severity ratings, exploitability notes, and remediation guidance.
"""
import asyncio
import re
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client


# ---------------------------------------------------------------------------
# Known JSONP-capable CDN domains that can bypass CSP
# ---------------------------------------------------------------------------
JSONP_BYPASS_DOMAINS = [
    "*.googleapis.com",
    "*.google.com",
    "*.cloudflare.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "accounts.google.com",
    "*.gstatic.com",
    "*.facebook.com",
    "*.fbcdn.net",
    "*.yandex.ru",
    "*.yandex.net",
    "*.yahoo.com",
]

# Session cookie name patterns
SESSION_COOKIE_NAMES = {
    "sessionid", "session", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "aspsessionid", "token", "jwt",
    "access_token", "auth_token", "csrf_token", "xsrf-token",
    "_session", "connect.sid", "laravel_session", "ci_session",
}


# ===================================================================
# 1. CSP Deep Analysis
# ===================================================================

def _parse_csp(csp_header: str) -> dict[str, list[str]]:
    """Parse a CSP header into {directive: [values]} map."""
    directives: dict[str, list[str]] = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            name = tokens[0].lower()
            values = [t.lower() for t in tokens[1:]]
            directives[name] = values
    return directives


def _domain_matches_jsonp(src: str) -> str | None:
    """Check if a CSP source matches a known JSONP-capable domain."""
    src_clean = src.strip("'\"")
    for pattern in JSONP_BYPASS_DOMAINS:
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .googleapis.com
            if src_clean.endswith(suffix) or src_clean == pattern[2:]:
                return pattern
        elif src_clean == pattern:
            return pattern
    return None


def analyze_csp(csp_header: str, url: str) -> dict:
    """Analyze a Content-Security-Policy header for weaknesses.

    Returns:
        {
            "grade": "A" .. "F",
            "weaknesses": [{"issue": ..., "severity": ..., "detail": ..., "remediation": ...}],
            "directives": {parsed directives},
            "summary": str,
        }
    """
    if not csp_header:
        return {
            "grade": "F",
            "weaknesses": [{
                "issue": "No Content-Security-Policy header",
                "severity": "medium",
                "detail": "The site has no CSP at all, offering zero protection against XSS and data injection.",
                "remediation": "Implement a strict CSP. Start with: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self'; base-uri 'self'",
            }],
            "directives": {},
            "summary": "No CSP header present",
        }

    directives = _parse_csp(csp_header)
    weaknesses: list[dict] = []
    penalty = 0  # higher = worse grade

    # --- Analyze script-src (most security-critical) ---
    script_src = directives.get("script-src", directives.get("default-src", []))

    if "'unsafe-inline'" in script_src:
        weaknesses.append({
            "issue": "unsafe-inline in script-src",
            "severity": "low",
            "detail": "Allows inline <script> tags and event handlers to execute. Attackers can inject XSS payloads that run despite CSP.",
            "remediation": "Remove 'unsafe-inline' from script-src. Use nonces (script-src 'nonce-<random>') or hashes for inline scripts.",
        })
        penalty += 30

    if "'unsafe-eval'" in script_src:
        weaknesses.append({
            "issue": "unsafe-eval in script-src",
            "severity": "low",
            "detail": "Allows eval(), Function(), and setTimeout(string) execution. Attackers can compile and run arbitrary code.",
            "remediation": "Remove 'unsafe-eval'. Refactor code to avoid eval(). Use strict CSP with nonces.",
        })
        penalty += 25

    if "*" in script_src:
        weaknesses.append({
            "issue": "Wildcard (*) in script-src",
            "severity": "critical",
            "detail": "Any domain can serve scripts. CSP provides no meaningful XSS protection.",
            "remediation": "Replace wildcard with specific trusted domains. Use 'self' plus only necessary CDN origins.",
        })
        penalty += 40

    if "data:" in script_src:
        weaknesses.append({
            "issue": "data: URI in script-src",
            "severity": "medium",
            "detail": "Allows script execution via data:text/html or data:application/javascript URIs. Bypasses CSP intent.",
            "remediation": "Remove 'data:' from script-src. Only allow data: in img-src if needed for inline images.",
        })
        penalty += 25

    if "blob:" in script_src:
        weaknesses.append({
            "issue": "blob: URI in script-src",
            "severity": "medium",
            "detail": "Allows script execution via Blob URLs. Can be chained with other vulnerabilities for CSP bypass.",
            "remediation": "Remove 'blob:' from script-src unless required by application architecture (e.g., Web Workers).",
        })
        penalty += 15

    if "https:" in script_src and len(script_src) == 1:
        weaknesses.append({
            "issue": "Scheme-only source (https:) in script-src",
            "severity": "medium",
            "detail": "Allows loading scripts from any HTTPS host. Attacker can host malicious scripts on any HTTPS domain.",
            "remediation": "Replace 'https:' with specific trusted origins.",
        })
        penalty += 20
    elif "https:" in script_src:
        weaknesses.append({
            "issue": "Scheme-only source (https:) in script-src alongside other sources",
            "severity": "medium",
            "detail": "The https: scheme source effectively overrides other restrictions, allowing any HTTPS host.",
            "remediation": "Remove 'https:' and keep only specific trusted origins.",
        })
        penalty += 15

    # JSONP-capable domains
    for src in script_src:
        matched_pattern = _domain_matches_jsonp(src)
        if matched_pattern:
            weaknesses.append({
                "issue": f"JSONP-capable domain in script-src: {src}",
                "severity": "high",
                "detail": f"The domain {src} (matches {matched_pattern}) is known to host JSONP endpoints. "
                          "Attackers can use JSONP callbacks to bypass CSP and execute arbitrary JavaScript.",
                "remediation": f"If possible, remove {src} from script-src or use a more specific path restriction. "
                               "Consider using subresource integrity (SRI) for scripts loaded from CDNs.",
            })
            penalty += 20

    # --- Check for missing directives ---
    if "default-src" not in directives:
        weaknesses.append({
            "issue": "Missing default-src directive",
            "severity": "medium",
            "detail": "Without default-src, any directive not explicitly set has no restriction. "
                     "Unlisted resource types (fonts, media, etc.) can be loaded from anywhere.",
            "remediation": "Add default-src 'self' as a baseline fallback for all resource types.",
        })
        penalty += 15

    if "frame-ancestors" not in directives:
        weaknesses.append({
            "issue": "Missing frame-ancestors directive",
            "severity": "medium",
            "detail": "Without frame-ancestors, the page can be embedded in iframes on any domain, enabling clickjacking attacks.",
            "remediation": "Add frame-ancestors 'self' (or 'none' if framing is not needed).",
        })
        penalty += 10

    if "form-action" not in directives:
        weaknesses.append({
            "issue": "Missing form-action directive",
            "severity": "low",
            "detail": "Forms on the page can submit data to any URL. An attacker who injects HTML could redirect form submissions.",
            "remediation": "Add form-action 'self' to restrict form targets.",
        })
        penalty += 5

    if "base-uri" not in directives:
        weaknesses.append({
            "issue": "Missing base-uri directive",
            "severity": "low",
            "detail": "Without base-uri, an attacker who can inject a <base> tag can redirect relative URLs to a malicious host.",
            "remediation": "Add base-uri 'self' (or 'none').",
        })
        penalty += 5

    if "object-src" not in directives and "default-src" not in directives:
        weaknesses.append({
            "issue": "Missing object-src directive",
            "severity": "medium",
            "detail": "Allows loading of plugins (Flash, Java applets) from any source. Plugins can execute arbitrary code.",
            "remediation": "Add object-src 'none' to block all plugin content.",
        })
        penalty += 10

    # --- Check style-src ---
    style_src = directives.get("style-src", directives.get("default-src", []))
    if "'unsafe-inline'" in style_src:
        weaknesses.append({
            "issue": "unsafe-inline in style-src",
            "severity": "low",
            "detail": "Allows inline styles. While less dangerous than script-src unsafe-inline, "
                     "it can enable CSS-based data exfiltration attacks.",
            "remediation": "Remove 'unsafe-inline' from style-src. Use nonces or hashes for inline styles.",
        })
        penalty += 5

    # --- Wildcard in default-src ---
    default_src = directives.get("default-src", [])
    if "*" in default_src:
        weaknesses.append({
            "issue": "Wildcard (*) in default-src",
            "severity": "critical",
            "detail": "Default fallback allows loading any resource from any domain. CSP is effectively disabled.",
            "remediation": "Set default-src 'self' and explicitly whitelist needed origins per directive.",
        })
        penalty += 40

    # --- report-uri / report-to (informational) ---
    if "report-uri" in directives or "report-to" in directives:
        weaknesses.append({
            "issue": "CSP reporting enabled",
            "severity": "info",
            "detail": "CSP violations are reported. This is a good practice for monitoring policy effectiveness.",
            "remediation": "No action needed. Ensure reports are monitored and acted upon.",
        })

    # --- Calculate grade ---
    if penalty == 0:
        grade = "A"
    elif penalty <= 10:
        grade = "B"
    elif penalty <= 25:
        grade = "C"
    elif penalty <= 45:
        grade = "D"
    else:
        grade = "F"

    high_count = sum(1 for w in weaknesses if w["severity"] in ("critical", "high"))
    med_count = sum(1 for w in weaknesses if w["severity"] == "medium")
    summary = (
        f"CSP Grade: {grade} | "
        f"{high_count} critical/high issues, {med_count} medium issues, "
        f"{len(weaknesses)} total findings"
    )

    return {
        "grade": grade,
        "weaknesses": weaknesses,
        "directives": directives,
        "summary": summary,
        "raw": csp_header,
    }


# ===================================================================
# 2. CORS Deep Analysis
# ===================================================================

async def analyze_cors(url: str, context: dict) -> list[dict]:
    """Test a URL for CORS misconfigurations with multiple attack vectors.

    Returns list of finding dicts.
    """
    parsed = urlparse(url)
    target_domain = parsed.hostname or ""
    custom_headers = context.get("custom_headers", {})
    findings: list[dict] = []

    test_origins = [
        ("https://evil.com", "arbitrary_origin", "Arbitrary external origin accepted"),
        (f"https://sub.{target_domain}", "subdomain", "Subdomain origin accepted"),
        ("null", "null_origin", "Null origin accepted"),
        (f"https://{target_domain}.evil.com", "prefix_bypass", "Prefix-match bypass — attacker domain with target as prefix"),
        (f"https://evil{target_domain}", "suffix_bypass", "Suffix-match bypass — attacker domain with target as suffix"),
    ]

    async with make_client(extra_headers=dict(custom_headers), timeout=10) as client:
        for origin, test_type, label in test_origins:
            try:
                resp = await client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()
                acam = resp.headers.get("access-control-allow-methods", "")
                aceh = resp.headers.get("access-control-expose-headers", "")

                if not acao:
                    continue

                reflected = (acao == origin)
                wildcard = (acao == "*")
                with_creds = (acac == "true")

                if reflected and test_type == "arbitrary_origin":
                    severity = "critical" if with_creds else "high"
                    findings.append({
                        "title": f"CORS Origin Reflection — {label}",
                        "url": url,
                        "severity": severity,
                        "vuln_type": "cors_misconfiguration",
                        "payload": f"Origin: {origin}",
                        "impact": (
                            "The server reflects any Origin in Access-Control-Allow-Origin. "
                            "Any website can read authenticated responses from this endpoint"
                            + (" including credentials/cookies" if with_creds else "")
                            + "."
                        ),
                        "remediation": "Validate Origin against a strict whitelist. Never reflect arbitrary origins.",
                        "details": {"acao": acao, "acac": acac, "test_type": test_type},
                    })
                elif reflected and test_type == "null_origin":
                    severity = "high" if with_creds else "medium"
                    findings.append({
                        "title": "CORS Null Origin Allowed",
                        "url": url,
                        "severity": severity,
                        "vuln_type": "cors_misconfiguration",
                        "payload": "Origin: null",
                        "impact": (
                            "The server accepts 'null' as an origin. Sandboxed iframes and data: URIs send null origin, "
                            "allowing attackers to read responses"
                            + (" with credentials" if with_creds else "")
                            + "."
                        ),
                        "remediation": "Do not allow 'null' as a valid origin in CORS configuration.",
                        "details": {"acao": acao, "acac": acac, "test_type": test_type},
                    })
                elif reflected and test_type in ("prefix_bypass", "suffix_bypass"):
                    severity = "high" if with_creds else "medium"
                    findings.append({
                        "title": f"CORS {test_type.replace('_', ' ').title()} — {label}",
                        "url": url,
                        "severity": severity,
                        "vuln_type": "cors_misconfiguration",
                        "payload": f"Origin: {origin}",
                        "impact": (
                            f"The server accepted {origin} as a valid origin. "
                            "This suggests regex-based origin validation with insufficient anchoring. "
                            "An attacker can register a matching domain to bypass CORS."
                        ),
                        "remediation": "Use exact string matching for allowed origins. Ensure regex anchors (^ and $) are correct.",
                        "details": {"acao": acao, "acac": acac, "test_type": test_type},
                    })
                elif wildcard and with_creds:
                    findings.append({
                        "title": "CORS Wildcard with Credentials",
                        "url": url,
                        "severity": "high",
                        "vuln_type": "cors_misconfiguration",
                        "payload": f"Origin: {origin}",
                        "impact": (
                            "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. "
                            "Browsers block this combination, but it reveals a server misconfiguration "
                            "that could be exploited if the CORS implementation changes."
                        ),
                        "remediation": "Fix server CORS configuration. Wildcard and credentials are mutually exclusive per the spec.",
                        "details": {"acao": acao, "acac": acac, "test_type": test_type},
                    })
                elif wildcard and test_type == "arbitrary_origin":
                    findings.append({
                        "title": "CORS Wildcard Origin (no credentials)",
                        "url": url,
                        "severity": "low",
                        "vuln_type": "cors_misconfiguration",
                        "payload": f"Origin: {origin}",
                        "impact": (
                            "Access-Control-Allow-Origin: * allows any site to read responses (without credentials). "
                            "Acceptable for public APIs, but risky if endpoint returns user-specific data."
                        ),
                        "remediation": "If endpoint returns user-specific data, restrict Origin to trusted domains.",
                        "details": {"acao": acao, "acac": acac, "test_type": test_type},
                    })

                # Check dangerous methods
                if acam:
                    dangerous = [m.strip() for m in acam.split(",") if m.strip().upper() in ("PUT", "DELETE", "PATCH")]
                    if dangerous and (reflected or wildcard):
                        findings.append({
                            "title": f"CORS allows dangerous methods: {', '.join(dangerous)}",
                            "url": url,
                            "severity": "medium",
                            "vuln_type": "cors_misconfiguration",
                            "payload": f"Access-Control-Allow-Methods: {acam}",
                            "impact": f"Combined with permissive Origin, methods {dangerous} allow cross-origin state changes.",
                            "remediation": "Restrict allowed methods to only those needed (typically GET, POST).",
                            "details": {"acao": acao, "acam": acam, "test_type": test_type},
                        })

                # Check exposed sensitive headers
                if aceh and (reflected or wildcard):
                    sensitive = [h.strip() for h in aceh.split(",")
                                 if h.strip().lower() in ("authorization", "x-csrf-token", "set-cookie", "x-api-key")]
                    if sensitive:
                        findings.append({
                            "title": f"CORS exposes sensitive headers: {', '.join(sensitive)}",
                            "url": url,
                            "severity": "medium",
                            "vuln_type": "cors_misconfiguration",
                            "payload": f"Access-Control-Expose-Headers: {aceh}",
                            "impact": f"Sensitive headers ({', '.join(sensitive)}) are readable cross-origin.",
                            "remediation": "Remove sensitive headers from Access-Control-Expose-Headers.",
                            "details": {"acao": acao, "aceh": aceh, "test_type": test_type},
                        })

            except Exception:
                continue

        # --- Test origin reflection (send unique origin, check if echoed) ---
        try:
            reflection_origin = f"https://corstest-{target_domain}"
            resp = await client.get(url, headers={"Origin": reflection_origin})
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == reflection_origin:
                acac = resp.headers.get("access-control-allow-credentials", "").lower()
                # Only add if we didn't already find arbitrary origin reflection
                already_found = any(f.get("details", {}).get("test_type") == "arbitrary_origin" for f in findings)
                if not already_found:
                    severity = "critical" if acac == "true" else "high"
                    findings.append({
                        "title": "CORS Origin Reflection Detected",
                        "url": url,
                        "severity": severity,
                        "vuln_type": "cors_misconfiguration",
                        "payload": f"Origin: {reflection_origin}",
                        "impact": (
                            "The server blindly reflects the Origin header in ACAO. "
                            "Any website can make authenticated cross-origin requests."
                        ),
                        "remediation": "Implement a strict origin whitelist. Never echo the Origin header.",
                        "details": {"acao": acao, "acac": acac, "test_type": "reflection"},
                    })
        except Exception:
            pass

    # Deduplicate by title+url
    seen = set()
    deduped = []
    for f in findings:
        key = (f["title"], f["url"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


# ===================================================================
# 3. Cookie Security Analysis
# ===================================================================

def analyze_cookies(response_headers: dict, url: str) -> list[dict]:
    """Analyze Set-Cookie headers for security weaknesses.

    Accepts a dict of headers (may have multiple Set-Cookie via httpx's multi-value).
    """
    findings: list[dict] = []
    is_https = url.lower().startswith("https")
    parsed = urlparse(url)
    target_domain = parsed.hostname or ""

    # httpx stores multiple set-cookie headers — get raw from headers
    cookies_raw: list[str] = []
    if isinstance(response_headers, httpx.Headers):
        cookies_raw = response_headers.get_list("set-cookie")
    else:
        # Dict fallback — may only have last value
        sc = response_headers.get("set-cookie", "")
        if sc:
            cookies_raw = [sc]

    for cookie_str in cookies_raw:
        if not cookie_str:
            continue

        # Parse cookie name and attributes
        parts = cookie_str.split(";")
        name_value = parts[0].strip()
        cookie_name = name_value.split("=", 1)[0].strip().lower()

        attrs = {}
        for part in parts[1:]:
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[part.lower()] = True

        is_session = cookie_name in SESSION_COOKIE_NAMES or any(
            kw in cookie_name for kw in ("sess", "token", "auth", "jwt", "sid", "login")
        )
        label = f"session cookie '{cookie_name}'" if is_session else f"cookie '{cookie_name}'"

        # Check Secure flag
        if is_https and "secure" not in attrs:
            severity = "medium" if is_session else "low"
            findings.append({
                "title": f"Missing Secure flag on {label}",
                "url": url,
                "severity": severity,
                "vuln_type": "misconfiguration",
                "payload": f"Set-Cookie: {cookie_str}",
                "impact": (
                    f"The {label} can be transmitted over unencrypted HTTP connections, "
                    "allowing interception via network sniffing (MITM)."
                ),
                "remediation": "Add the Secure flag to all cookies on HTTPS sites.",
            })

        # Check HttpOnly flag
        if "httponly" not in attrs and is_session:
            findings.append({
                "title": f"Missing HttpOnly flag on {label}",
                "url": url,
                "severity": "medium",
                "vuln_type": "misconfiguration",
                "payload": f"Set-Cookie: {cookie_str}",
                "impact": (
                    f"The {label} is accessible via JavaScript (document.cookie). "
                    "XSS attacks can steal the session cookie."
                ),
                "remediation": "Add the HttpOnly flag to session cookies.",
            })

        # Check SameSite
        samesite = attrs.get("samesite", "")
        if not samesite:
            findings.append({
                "title": f"Missing SameSite attribute on {label}",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": f"Set-Cookie: {cookie_str}",
                "impact": (
                    f"The {label} has no SameSite attribute. Browsers default to Lax, but "
                    "explicit SameSite=Strict or Lax is recommended for defense-in-depth against CSRF."
                ),
                "remediation": "Add SameSite=Lax (or Strict) to the cookie.",
            })
        elif samesite.lower() == "none" and "secure" not in attrs:
            findings.append({
                "title": f"SameSite=None without Secure on {label}",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": f"Set-Cookie: {cookie_str}",
                "impact": "Browsers reject SameSite=None cookies without the Secure flag. The cookie will be ignored.",
                "remediation": "Add the Secure flag when using SameSite=None.",
            })

        # Check domain scope
        cookie_domain = attrs.get("domain", "")
        if cookie_domain:
            # Strip leading dot
            cd = cookie_domain.lstrip(".")
            # Count domain levels in target vs cookie domain
            target_parts = target_domain.split(".")
            cookie_parts = cd.split(".")
            if len(cookie_parts) < len(target_parts) and target_domain.endswith(cd):
                findings.append({
                    "title": f"Broad domain scope on {label}: domain=.{cd}",
                    "url": url,
                    "severity": "low",
                    "vuln_type": "misconfiguration",
                    "payload": f"Set-Cookie: {cookie_str}",
                    "impact": (
                        f"Cookie domain .{cd} makes the cookie accessible to all subdomains. "
                        "A compromised subdomain can steal or manipulate the cookie."
                    ),
                    "remediation": "Scope cookies to the most specific domain possible. Avoid wildcard domain attributes.",
                })

    return findings


# ===================================================================
# 4. Additional Security Headers Analysis
# ===================================================================

def analyze_headers(headers: dict, url: str) -> list[dict]:
    """Analyze security header values (not just presence) for weaknesses."""
    findings: list[dict] = []
    h = {k.lower(): v for k, v in headers.items()}

    # --- X-Frame-Options ---
    xfo = h.get("x-frame-options", "").upper()
    if xfo:
        if "ALLOW-FROM" in xfo:
            findings.append({
                "title": "X-Frame-Options uses deprecated ALLOW-FROM",
                "url": url,
                "severity": "medium",
                "vuln_type": "misconfiguration",
                "payload": f"X-Frame-Options: {xfo}",
                "impact": "ALLOW-FROM is not supported by modern browsers. The page may be frameable (clickjacking).",
                "remediation": "Use CSP frame-ancestors instead of X-Frame-Options ALLOW-FROM.",
            })
    else:
        # Missing — only flag if CSP frame-ancestors also missing
        csp = h.get("content-security-policy", "")
        if "frame-ancestors" not in csp:
            findings.append({
                "title": "No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": "",
                "impact": "The page can be embedded in iframes on any domain, enabling clickjacking attacks.",
                "remediation": "Add X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors 'self'.",
            })

    # --- Strict-Transport-Security ---
    hsts = h.get("strict-transport-security", "")
    if hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_subdomains = "includesubdomains" in hsts.lower()
        has_preload = "preload" in hsts.lower()

        if max_age < 31536000:  # 1 year
            findings.append({
                "title": f"HSTS max-age too short: {max_age} seconds",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": f"Strict-Transport-Security: {hsts}",
                "impact": f"HSTS max-age is {max_age}s ({max_age // 86400} days). "
                          "Recommended minimum is 31536000 (1 year) for browser preload lists.",
                "remediation": "Set max-age=31536000 (1 year) or higher.",
            })

        if not has_subdomains:
            findings.append({
                "title": "HSTS missing includeSubDomains",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": f"Strict-Transport-Security: {hsts}",
                "impact": "HSTS does not cover subdomains. Subdomains can still be accessed over HTTP.",
                "remediation": "Add includeSubDomains to the HSTS header.",
            })
    else:
        if url.startswith("https"):
            findings.append({
                "title": "Missing Strict-Transport-Security (HSTS) header",
                "url": url,
                "severity": "medium",
                "vuln_type": "misconfiguration",
                "payload": "",
                "impact": "Without HSTS, browsers allow HTTP connections. Users are vulnerable to SSL-stripping attacks.",
                "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })

    # --- X-Content-Type-Options ---
    xcto = h.get("x-content-type-options", "")
    if xcto and xcto.lower().strip() != "nosniff":
        findings.append({
            "title": f"X-Content-Type-Options has invalid value: {xcto}",
            "url": url,
            "severity": "low",
            "vuln_type": "misconfiguration",
            "payload": f"X-Content-Type-Options: {xcto}",
            "impact": "The header value must be exactly 'nosniff'. Invalid values are ignored by browsers.",
            "remediation": "Set X-Content-Type-Options: nosniff",
        })
    elif not xcto:
        findings.append({
            "title": "Missing X-Content-Type-Options header",
            "url": url,
            "severity": "low",
            "vuln_type": "misconfiguration",
            "payload": "",
            "impact": "Without nosniff, browsers may MIME-sniff responses, potentially executing scripts disguised as other content types.",
            "remediation": "Add X-Content-Type-Options: nosniff",
        })

    # --- Referrer-Policy ---
    rp = h.get("referrer-policy", "").lower()
    if rp:
        bad_policies = ("unsafe-url", "no-referrer-when-downgrade")
        if rp in bad_policies:
            findings.append({
                "title": f"Referrer-Policy set to {rp}",
                "url": url,
                "severity": "medium",
                "vuln_type": "misconfiguration",
                "payload": f"Referrer-Policy: {rp}",
                "impact": "Full URLs (including query parameters with tokens/secrets) are sent in the Referer header to third-party sites.",
                "remediation": "Use 'strict-origin-when-cross-origin' or 'strict-origin' instead.",
            })

    # --- Permissions-Policy ---
    pp = h.get("permissions-policy", "")
    if not pp:
        fp = h.get("feature-policy", "")
        if not fp:
            findings.append({
                "title": "Missing Permissions-Policy header",
                "url": url,
                "severity": "low",
                "vuln_type": "misconfiguration",
                "payload": "",
                "impact": "Browser features (camera, microphone, geolocation, payment) are not restricted. "
                          "Embedded third-party content can request sensitive permissions.",
                "remediation": "Add Permissions-Policy to restrict unnecessary browser features: "
                               "camera=(), microphone=(), geolocation=(), payment=()",
            })

    # --- Cross-Origin-Opener-Policy ---
    coop = h.get("cross-origin-opener-policy", "")
    if not coop:
        findings.append({
            "title": "Missing Cross-Origin-Opener-Policy",
            "url": url,
            "severity": "info",
            "vuln_type": "misconfiguration",
            "payload": "",
            "impact": "Without COOP, the page shares a browsing context group with cross-origin popups, "
                     "potentially allowing Spectre-type side-channel attacks.",
            "remediation": "Add Cross-Origin-Opener-Policy: same-origin",
        })

    # --- Cross-Origin-Embedder-Policy ---
    coep = h.get("cross-origin-embedder-policy", "")
    if not coep:
        findings.append({
            "title": "Missing Cross-Origin-Embedder-Policy",
            "url": url,
            "severity": "info",
            "vuln_type": "misconfiguration",
            "payload": "",
            "impact": "Without COEP, the page cannot use SharedArrayBuffer and high-resolution timers, "
                     "and is not fully isolated from cross-origin resources.",
            "remediation": "Add Cross-Origin-Embedder-Policy: require-corp",
        })

    # --- Server version disclosure ---
    server = h.get("server", "")
    if server:
        # Check for version numbers
        version_match = re.search(r"[\d]+\.[\d]+", server)
        if version_match:
            findings.append({
                "title": f"Server version disclosed: {server}",
                "url": url,
                "severity": "low",
                "vuln_type": "info_disclosure",
                "payload": f"Server: {server}",
                "impact": f"The server header reveals software and version ({server}). "
                          "Attackers can search for known vulnerabilities in this specific version.",
                "remediation": "Remove or obfuscate the Server header. Configure the web server to suppress version information.",
            })

    # --- X-Powered-By ---
    xpb = h.get("x-powered-by", "")
    if xpb:
        findings.append({
            "title": f"Technology disclosed via X-Powered-By: {xpb}",
            "url": url,
            "severity": "low",
            "vuln_type": "info_disclosure",
            "payload": f"X-Powered-By: {xpb}",
            "impact": f"The X-Powered-By header reveals the backend technology ({xpb}). "
                      "This aids attackers in choosing targeted exploits.",
            "remediation": "Remove the X-Powered-By header.",
        })

    return findings


# ===================================================================
# 5. Main entry point
# ===================================================================

async def run_security_analysis(base_url: str, endpoints: list[dict], context: dict) -> list[dict]:
    """Run comprehensive security header analysis on a target.

    Checks the main page and key API/page endpoints.
    Returns a flat list of finding dicts ready for Vulnerability DB records.
    """
    findings: list[dict] = []
    custom_headers = context.get("custom_headers", {})

    # Select endpoints to test: root + up to 10 API/page endpoints
    urls_to_check = [base_url]
    for ep in endpoints:
        if ep.get("type") in ("api", "page") and ep.get("url"):
            urls_to_check.append(ep["url"])
        if len(urls_to_check) >= 10:
            break

    # --- Fetch headers from main page for CSP, cookie, and header analysis ---
    main_headers = None
    async with make_client(extra_headers=dict(custom_headers), timeout=15) as client:
        try:
            resp = await client.get(base_url)
            main_headers = resp.headers
        except Exception:
            pass

    if main_headers:
        # CSP analysis (on main page only)
        csp_header = main_headers.get("content-security-policy", "")
        csp_result = analyze_csp(csp_header, base_url)
        context["csp_analysis"] = csp_result  # Store for Claude reference

        for weakness in csp_result["weaknesses"]:
            if weakness["severity"] == "info":
                continue  # Skip informational CSP notes as vulnerability records
            findings.append({
                "title": f"CSP: {weakness['issue']}",
                "url": base_url,
                "severity": weakness["severity"],
                "vuln_type": "misconfiguration",
                "payload": f"Content-Security-Policy: {csp_header}" if csp_header else "",
                "impact": weakness["detail"],
                "remediation": weakness["remediation"],
                "csp_grade": csp_result["grade"],
            })

        # Cookie analysis (on main page)
        cookie_findings = analyze_cookies(main_headers, base_url)
        findings.extend(cookie_findings)

        # Header analysis (on main page)
        header_findings = analyze_headers(dict(main_headers), base_url)
        findings.extend(header_findings)

    # --- CORS analysis on multiple endpoints ---
    cors_tasks = [analyze_cors(u, context) for u in urls_to_check[:5]]
    cors_results = await asyncio.gather(*cors_tasks, return_exceptions=True)

    # Deduplicate CORS findings across endpoints (keep unique title+severity combos)
    seen_cors: set[str] = set()
    for result in cors_results:
        if isinstance(result, list):
            for f in result:
                key = f"{f['title']}|{f['severity']}"
                if key not in seen_cors:
                    seen_cors.add(key)
                    findings.append(f)

    # Store CORS analysis summary in context for Claude
    cors_finding_count = sum(1 for f in findings if f.get("vuln_type") == "cors_misconfiguration")
    context["cors_analysis"] = {
        "endpoints_tested": len(urls_to_check[:5]),
        "findings_count": cors_finding_count,
        "findings": [f for f in findings if f.get("vuln_type") == "cors_misconfiguration"],
    }

    return findings
