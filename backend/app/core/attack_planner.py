"""
AI Attack Planner — Claude-as-Brain reasoning loop.

Unlike the fixed 24-phase pipeline where each module runs independently,
the Attack Planner gives Claude full control to:
1. See ALL findings from the pipeline
2. Build attack trees (chained multi-step attacks)
3. Execute arbitrary HTTP requests to prove exploitation
4. Reason about what to try next based on results
5. Chain vulnerabilities together (e.g., SSRF → credential leak → admin access)

This is the "senior hacker brain" that thinks strategically about the target.
"""
import asyncio
import json
import logging
import re
import secrets
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode

import anthropic
import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

BODY_LIMIT = 12000

PLANNER_SYSTEM = """You are an elite penetration tester with 15+ years of experience. You are the BRAIN of PHANTOM — an autonomous pentesting platform.

The automated pipeline already ran and found some results. Now it's YOUR turn to think like a real hacker.

## YOUR MISSION
Find vulnerabilities that automated scanners MISS. Think creatively. Chain findings together.

## WHAT MAKES YOU DIFFERENT FROM THE SCANNER
- You can CHAIN attacks: use finding A to exploit finding B
- You can REASON about business logic, not just inject payloads
- You understand context: JWT algorithm tells you what to forge, tech stack tells you what exploits exist
- You try the NON-OBVIOUS: parameter pollution, HTTP verb tampering, race conditions, deserialization

## AVAILABLE TOOLS

Execute these by writing ```action blocks:

### HTTP Requests
```action
{"tool": "http", "method": "GET", "url": "https://...", "headers": {}, "body": null}
```
```action
{"tool": "http", "method": "POST", "url": "https://...", "headers": {"Content-Type": "application/json"}, "body": {"key": "value"}}
```
```action
{"tool": "http", "method": "PUT", "url": "https://...", "headers": {}, "body": {"role": "admin"}}
```
```action
{"tool": "http", "method": "DELETE", "url": "https://..."}
```

### JWT Operations
```action
{"tool": "jwt_decode", "token": "eyJ..."}
```
```action
{"tool": "jwt_forge", "payload": {"sub": "admin", "role": "admin"}, "algorithm": "none"}
```
```action
{"tool": "jwt_forge", "payload": {"sub": "1", "role": "admin"}, "algorithm": "HS256", "secret": "secret"}
```

### Diff Two Responses (detect IDOR, auth bypass)
```action
{"tool": "diff", "request_a": {"method": "GET", "url": "https://.../api/user/1"}, "request_b": {"method": "GET", "url": "https://.../api/user/2"}}
```

### Auth-as-user (login and save session)
```action
{"tool": "login", "url": "https://.../api/login", "body": {"email": "test@test.com", "password": "password123"}, "extract_token": true}
```

### Fuzz a parameter with multiple values
```action
{"tool": "fuzz", "url": "https://.../search", "param": "q", "method": "GET", "values": ["'", "\"", "<script>", "{{7*7}}", "${7*7}", "../etc/passwd", "1 OR 1=1--"]}
```

### Extract page structure (forms, hidden inputs, scripts, links)
```action
{"tool": "extract", "url": "https://.../login"}
```

### Report a confirmed vulnerability
```action
{"tool": "report_vuln", "title": "JWT Algorithm None Bypass", "vuln_type": "jwt", "severity": "critical", "url": "https://.../api/profile", "description": "Server accepts JWT with algorithm=none, allowing authentication bypass", "payload": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", "evidence": "Response returned admin user data with forged token", "chain": "JWT None → Admin Access → Full User Data Leak"}
```

### Mark task complete
```action
{"tool": "done", "summary": "Tested X attack paths, found Y confirmed vulnerabilities"}
```

## THINKING FRAMEWORK

For each target, follow this mental model:

1. **Understand the app**: What does it do? What's the tech stack? What auth mechanism?
2. **Map the attack surface**: What endpoints exist? What parameters accept input? What's behind auth?
3. **Identify high-value targets**: Admin panels, payment flows, file uploads, API keys
4. **Build attack hypotheses**: "If JWT uses HS256, I should try known weak secrets"
5. **Execute and verify**: Send the actual requests, verify the response shows real data
6. **Chain findings**: "I found IDOR on /api/users/ID → now let me get admin's ID → access admin data"

## CRITICAL RULES

1. **VERIFY EVERYTHING**: Don't report a vuln unless you see REAL evidence in the response (actual data, not HTML shells)
2. **SPA AWARENESS**: React/Vue/Angular apps serve the same HTML for ALL routes. /admin returning 200 with `<div id="root">` is NOT a vuln — test the API layer
3. **NO DUPLICATES**: Don't report vulns that the scanner already found (listed below)
4. **STAY IN SCOPE**: Only test the target domain and its subdomains
5. **BE CREATIVE**: The whole point is to find what scanners miss. Think laterally.
6. **CHAIN ATTACKS**: A single IDOR is medium. IDOR → admin data → account takeover is critical.
7. **USE CONTEXT**: If you see "Django" in headers, try Django-specific exploits. If you see "Express", try prototype pollution.

You can include multiple ```action blocks in a single response. I'll execute them all and show you results.
Keep going until you've exhausted all promising attack paths, then use the "done" tool."""


class AttackPlanner:
    """Claude-driven attack planning and execution engine."""

    def __init__(self):
        self.client = None
        from app.ai.get_claude_key import make_anthropic_client
        self.client = make_anthropic_client(sync=False)
        self.model = settings.claude_model
        self.conversation: list[dict] = []
        self.findings: list[dict] = []
        self.rounds = 0
        self.max_rounds = 20
        self._session_cookies: dict = {}  # Cookies from login actions
        self._session_token: str | None = None  # JWT/Bearer token from login
        self._action_log: list[dict] = []

    async def run(self, context: dict, on_event=None) -> dict:
        """
        Run the AI Attack Planner loop.

        Args:
            context: Full scan context with all findings, endpoints, technologies
            on_event: Optional async callback for WebSocket events
        """
        if not self.client:
            logger.warning("Attack Planner: no Claude API key")
            return {"findings": [], "rounds": 0, "error": "no_api_key"}

        domain = context.get("domain", "unknown")
        logger.info(f"Attack Planner: starting on {domain}")

        async def _emit(event: dict):
            if on_event:
                try:
                    await on_event(event)
                except Exception:
                    pass

        initial_message = self._build_briefing(context)
        self.conversation = [{"role": "user", "content": initial_message}]

        http_client = None
        try:
            http_client = httpx.AsyncClient(
                timeout=25.0,
                follow_redirects=True,
                verify=False,
                headers=self._get_rotating_ua(),
            )

            consecutive_empty = 0
            consecutive_no_response = 0

            while self.rounds < self.max_rounds:
                self.rounds += 1
                logger.info(f"Attack Planner round {self.rounds}/{self.max_rounds} on {domain}")

                await _emit({
                    "type": "planner_thinking",
                    "round": self.rounds,
                    "message": f"Attack Planner thinking (round {self.rounds})...",
                })

                response = await self._ask_claude()
                if not response:
                    consecutive_no_response += 1
                    if consecutive_no_response >= 3:
                        logger.warning("Attack Planner: 3 consecutive API failures, aborting")
                        break
                    self.conversation.append({
                        "role": "user",
                        "content": "No response received. Please provide actions or use the done tool."
                    })
                    continue
                consecutive_no_response = 0

                actions = self._parse_actions(response)

                # Check for done
                done_actions = [a for a in actions if a.get("tool") == "done"]
                if done_actions:
                    logger.info(f"Attack Planner done after {self.rounds} rounds: {done_actions[0].get('summary', '')}")
                    break

                # Check for reported vulns
                vuln_reports = [a for a in actions if a.get("tool") == "report_vuln"]
                for vr in vuln_reports:
                    self.findings.append(vr)
                    await _emit({
                        "type": "planner_finding",
                        "finding": vr,
                    })

                # Execute non-report actions
                executable = [a for a in actions if a.get("tool") not in ("report_vuln", "done")]

                if not executable and not vuln_reports:
                    consecutive_empty += 1
                    if consecutive_empty >= 2:
                        break
                    self.conversation.append({
                        "role": "user",
                        "content": "I need concrete ```action blocks. Give me specific tests to run, or use the done tool."
                    })
                    continue
                else:
                    consecutive_empty = 0

                if executable:
                    results = await self._execute_actions(executable, http_client, domain)

                    results_text = self._format_results(results)
                    # Add action log summary
                    if len(self._action_log) > 5:
                        results_text += f"\n\n[{len(self._action_log)} actions executed so far. Avoid repeating tested URLs/payloads.]"

                    self.conversation.append({"role": "user", "content": results_text})
                elif vuln_reports:
                    self.conversation.append({
                        "role": "user",
                        "content": f"Recorded {len(vuln_reports)} vulnerability report(s). Continue testing or use done tool."
                    })

        except Exception as e:
            logger.error(f"Attack Planner error: {e}", exc_info=True)
            return {
                "domain": domain,
                "rounds": self.rounds,
                "findings": self.findings,
                "error": str(e),
            }
        finally:
            if http_client:
                await http_client.aclose()

        return {
            "domain": domain,
            "rounds": self.rounds,
            "findings": self.findings,
            "actions_executed": len(self._action_log),
        }

    def _build_briefing(self, context: dict) -> str:
        """Build comprehensive briefing for Claude from all scan data."""
        domain = context.get("domain", "unknown")
        base_url = context.get("base_url", f"https://{domain}")
        technologies = context.get("technologies", {})
        endpoints = context.get("endpoints", [])
        vulns = context.get("vulnerabilities", [])
        subdomains = context.get("subdomains", [])
        ports = context.get("ports", context.get("open_ports", {}))
        recon_data = context.get("recon_data", {})
        waf_info = context.get("waf_info", {})
        app_graph = context.get("application_graph", {})
        crawl_data = context.get("stateful_crawl", {})
        auto_reg = context.get("auto_register_result", {})
        auth_cookie = context.get("auth_cookie", "")
        rag_context = context.get("_rag_context", "")

        # Build endpoint summary grouped by type
        ep_by_type = {}
        for ep in endpoints:
            etype = ep.get("type", "unknown")
            ep_by_type.setdefault(etype, []).append(ep)

        ep_summary = ""
        for etype, eps in sorted(ep_by_type.items()):
            ep_summary += f"\n  {etype} ({len(eps)}):"
            for ep in eps[:15]:
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                interest = ep.get("interest", "")
                params = ep.get("params", ep.get("parameters", []))
                param_str = ""
                if params:
                    if isinstance(params, list):
                        param_str = f" params=[{', '.join(str(p) for p in params[:5])}]"
                    elif isinstance(params, dict):
                        param_str = f" params=[{', '.join(params.keys())}]"
                ep_summary += f"\n    {method} {url}{param_str}"
                if interest:
                    ep_summary += f" [{interest}]"

        # Build vuln summary
        vuln_summary = ""
        if vulns:
            vuln_summary = "\n  Already found (DO NOT re-report these):"
            for v in vulns[:30]:
                vtype = v.get("vuln_type", "")
                severity = v.get("severity", "")
                vurl = v.get("url", "")
                title = v.get("title", "")
                param = v.get("parameter", "")
                vuln_summary += f"\n    [{severity}] {vtype}: {title}"
                if vurl:
                    vuln_summary += f" @ {vurl}"
                if param:
                    vuln_summary += f" (param: {param})"

        # Subdomain list
        sub_str = ", ".join(subdomains[:20]) if subdomains else "(none found)"

        # Ports
        port_str = json.dumps(ports, default=str)[:500] if ports else "(none scanned)"

        # WAF info
        waf_str = "None detected"
        if waf_info and waf_info.get("detected"):
            waf_str = f"{waf_info.get('waf_name', 'Unknown')} — {waf_info.get('confidence', 'N/A')} confidence"

        # Auth state
        auth_str = "No authentication"
        if auth_cookie:
            auth_str = f"Session cookie available: {auth_cookie[:50]}..."
            self._session_token = auth_cookie
        if auto_reg:
            auth_str += f"\nAuto-registered account: {json.dumps(auto_reg, default=str)[:300]}"
            if auto_reg.get("token"):
                self._session_token = auto_reg["token"]

        # App graph attack paths
        attack_paths_str = ""
        if app_graph:
            paths = app_graph.get("attack_paths", [])
            if paths:
                attack_paths_str = "\n\n## ATTACK PATHS IDENTIFIED BY APP GRAPH"
                for i, path in enumerate(paths[:10], 1):
                    if isinstance(path, str):
                        attack_paths_str += f"\n  {i}. {path}"
                        continue
                    risk = path.get("risk", path.get("risk_level", "medium"))
                    desc = path.get("description", path.get("name", "?"))
                    steps = path.get("steps", [])
                    step_strs = []
                    for s in steps[:6]:
                        if isinstance(s, str):
                            step_strs.append(s)
                        elif isinstance(s, dict):
                            step_strs.append(f"{s.get('method', 'GET')} {s.get('url', s.get('endpoint', ''))}")
                    attack_paths_str += f"\n  {i}. [{risk.upper()}] {desc}"
                    if step_strs:
                        attack_paths_str += f"\n     Steps: {' → '.join(step_strs)}"

        # Forms from crawl
        forms_str = ""
        if crawl_data:
            forms = crawl_data.get("forms", [])
            if forms:
                forms_str = "\n\n## FORMS FOUND"
                for f in forms[:10]:
                    action = f.get("action", f.get("url", "?"))
                    method = f.get("method", "POST")
                    fields = f.get("fields", f.get("inputs", []))
                    field_names = [fd.get("name", "?") if isinstance(fd, dict) else str(fd) for fd in fields[:10]]
                    forms_str += f"\n  {method} {action} → fields: {', '.join(field_names)}"

        return f"""## TARGET BRIEFING

**Domain**: {domain}
**Base URL**: {base_url}
**WAF**: {waf_str}
**Subdomains**: {sub_str}
**Open Ports**: {port_str}
**Auth State**: {auth_str}

## TECHNOLOGY STACK
{json.dumps(technologies, indent=2, default=str)[:2000]}

## ENDPOINTS ({len(endpoints)} total)
{ep_summary or "  (none found)"}

## EXISTING VULNERABILITIES ({len(vulns)} found by scanner)
{vuln_summary or "  (none yet — fresh target!)"}
{attack_paths_str}
{forms_str}

{rag_context}

## YOUR TASK
1. Analyze what the scanner found and what it MISSED
2. Build attack hypotheses based on the tech stack and endpoints
3. Execute tests to prove or disprove each hypothesis
4. Chain findings into high-impact attack paths
5. Report confirmed vulnerabilities using report_vuln tool

Think step by step. Start with the most promising attack vector.
What do you want to test first?"""

    def _get_rotating_ua(self) -> dict:
        """Return headers with a random realistic User-Agent."""
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ]
        import random
        return {"User-Agent": random.choice(uas)}

    async def _ask_claude(self) -> str | None:
        """Send conversation to Claude."""
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    from app.ai.get_claude_key import make_anthropic_client
                    self.client = make_anthropic_client(sync=False)
                    if not self.client:
                        return None

                message = await self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=PLANNER_SYSTEM,
                    messages=self.conversation,
                )
                text = message.content[0].text
                self.conversation.append({"role": "assistant", "content": text})
                return text
            except anthropic.AuthenticationError:
                if attempt == max_retries:
                    return None
                await asyncio.sleep(2)
            except (anthropic.RateLimitError, anthropic.APIStatusError) as e:
                logger.warning(f"Attack Planner API error (attempt {attempt + 1}): {e}")
                if attempt == max_retries:
                    return None
                await asyncio.sleep(5 * (attempt + 1))
            except Exception as e:
                logger.error(f"Attack Planner API error: {e}")
                return None

    def _parse_actions(self, response: str) -> list[dict]:
        """Extract ```action blocks from Claude's response."""
        actions = []
        parts = response.split("```action")
        for part in parts[1:]:
            try:
                json_str = part.split("```")[0].strip()
                action = json.loads(json_str)
                actions.append(action)
            except (json.JSONDecodeError, IndexError):
                try:
                    cleaned = re.sub(r',\s*([}\]])', r'\1', json_str)
                    action = json.loads(cleaned)
                    actions.append(action)
                except Exception:
                    logger.warning(f"Attack Planner: unparseable action: {json_str[:200]}")

        # Also try ```json blocks
        if not actions and "```json" in response:
            for part in response.split("```json")[1:]:
                try:
                    json_str = part.split("```")[0].strip()
                    action = json.loads(json_str)
                    if isinstance(action, dict) and "tool" in action:
                        actions.append(action)
                except Exception:
                    pass

        return actions

    async def _execute_actions(self, actions: list[dict], http_client: httpx.AsyncClient, domain: str) -> list[dict]:
        """Execute all actions and return results."""
        results = []
        for action in actions:
            tool = action.get("tool", "")
            timeout = 60.0 if tool in ("fuzz", "login") else 30.0

            try:
                coro = None
                if tool == "http":
                    coro = self._exec_http(action, http_client, domain)
                elif tool == "jwt_decode":
                    result = self._exec_jwt_decode(action)
                    results.append(result)
                    continue
                elif tool == "jwt_forge":
                    result = self._exec_jwt_forge(action)
                    results.append(result)
                    continue
                elif tool == "diff":
                    coro = self._exec_diff(action, http_client, domain)
                elif tool == "login":
                    coro = self._exec_login(action, http_client, domain)
                elif tool == "fuzz":
                    coro = self._exec_fuzz(action, http_client, domain)
                elif tool == "extract":
                    coro = self._exec_extract(action, http_client, domain)
                else:
                    results.append({"tool": tool, "error": f"Unknown tool: {tool}"})
                    continue

                result = await asyncio.wait_for(coro, timeout=timeout)
                results.append(result)
                self._action_log.append({"tool": tool, "round": self.rounds})

            except asyncio.TimeoutError:
                results.append({"tool": tool, "error": f"Timed out after {timeout:.0f}s"})
            except Exception as e:
                results.append({"tool": tool, "error": str(e)})

        return results

    def _is_in_scope(self, url: str, domain: str) -> bool:
        """Check if URL is within the target domain scope."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            return host == domain or host.endswith(f".{domain}")
        except Exception:
            return False

    def _add_auth_headers(self, headers: dict) -> dict:
        """Add session token/cookies to request headers if available."""
        if self._session_token:
            if self._session_token.startswith("eyJ"):
                headers.setdefault("Authorization", f"Bearer {self._session_token}")
            else:
                headers.setdefault("Cookie", self._session_token)
        if self._session_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
            existing = headers.get("Cookie", "")
            if existing:
                headers["Cookie"] = f"{existing}; {cookie_str}"
            else:
                headers["Cookie"] = cookie_str
        return headers

    async def _exec_http(self, action: dict, client: httpx.AsyncClient, domain: str) -> dict:
        """Execute arbitrary HTTP request."""
        method = action.get("method", "GET").upper()
        url = action.get("url", "")
        if not url or not self._is_in_scope(url, domain):
            return {"tool": "http", "error": f"URL not in scope: {url}"}

        headers = dict(action.get("headers", {}))
        headers = self._add_auth_headers(headers)
        # Rotate UA per request
        headers.update(self._get_rotating_ua())

        body = action.get("body")

        try:
            if method == "GET":
                resp = await client.get(url, headers=headers)
            elif method == "POST":
                if isinstance(body, dict):
                    if "json" in headers.get("Content-Type", "application/json").lower():
                        resp = await client.post(url, json=body, headers=headers)
                    else:
                        headers.setdefault("Content-Type", "application/json")
                        resp = await client.post(url, json=body, headers=headers)
                else:
                    resp = await client.post(url, content=str(body) if body else "", headers=headers)
            elif method == "PUT":
                if isinstance(body, dict):
                    headers.setdefault("Content-Type", "application/json")
                    resp = await client.put(url, json=body, headers=headers)
                else:
                    resp = await client.put(url, content=str(body) if body else "", headers=headers)
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            elif method == "PATCH":
                if isinstance(body, dict):
                    headers.setdefault("Content-Type", "application/json")
                    resp = await client.patch(url, json=body, headers=headers)
                else:
                    resp = await client.patch(url, content=str(body) if body else "", headers=headers)
            elif method == "OPTIONS":
                resp = await client.options(url, headers=headers)
            elif method == "HEAD":
                resp = await client.head(url, headers=headers)
            else:
                return {"tool": "http", "error": f"Unsupported method: {method}"}

            return {
                "tool": "http",
                "method": method,
                "url": str(resp.url),
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:BODY_LIMIT],
                "body_length": len(resp.text),
            }
        except httpx.ConnectError as e:
            return {"tool": "http", "error": f"Connection failed: {e}"}

    def _exec_jwt_decode(self, action: dict) -> dict:
        """Decode JWT without verification."""
        import base64
        token = action.get("token", "")
        parts = token.split(".")
        if len(parts) < 2:
            return {"tool": "jwt_decode", "error": "Invalid JWT format"}

        try:
            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            return {
                "tool": "jwt_decode",
                "header": header,
                "payload": payload,
                "algorithm": header.get("alg", "unknown"),
                "has_signature": len(parts) > 2 and len(parts[2]) > 0,
            }
        except Exception as e:
            return {"tool": "jwt_decode", "error": str(e)}

    def _exec_jwt_forge(self, action: dict) -> dict:
        """Forge a JWT with specified algorithm and payload."""
        import base64

        payload = action.get("payload", {})
        algorithm = action.get("algorithm", "none")
        secret = action.get("secret", "")

        try:
            # Build header
            header = {"typ": "JWT", "alg": algorithm}
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(',', ':')).encode()
            ).rstrip(b'=').decode()

            if algorithm.lower() == "none":
                token = f"{header_b64}.{payload_b64}."
            elif algorithm.upper().startswith("HS"):
                import hmac
                import hashlib
                hash_func = {
                    "HS256": hashlib.sha256,
                    "HS384": hashlib.sha384,
                    "HS512": hashlib.sha512,
                }.get(algorithm.upper(), hashlib.sha256)

                signing_input = f"{header_b64}.{payload_b64}"
                signature = hmac.new(
                    secret.encode(), signing_input.encode(), hash_func
                ).digest()
                sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
                token = f"{header_b64}.{payload_b64}.{sig_b64}"
            else:
                return {"tool": "jwt_forge", "error": f"Unsupported algorithm: {algorithm}"}

            return {
                "tool": "jwt_forge",
                "token": token,
                "algorithm": algorithm,
                "payload": payload,
            }
        except Exception as e:
            return {"tool": "jwt_forge", "error": str(e)}

    async def _exec_diff(self, action: dict, client: httpx.AsyncClient, domain: str) -> dict:
        """Compare two HTTP responses to detect IDOR/auth bypass."""
        req_a = action.get("request_a", {})
        req_b = action.get("request_b", {})

        async def _do_request(req: dict) -> dict:
            url = req.get("url", "")
            method = req.get("method", "GET").upper()
            headers = dict(req.get("headers", {}))
            headers = self._add_auth_headers(headers)
            headers.update(self._get_rotating_ua())

            if method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                body = req.get("body")
                if isinstance(body, dict):
                    resp = await client.post(url, json=body, headers=headers)
                else:
                    resp = await client.post(url, content=str(body or ""), headers=headers)
            return {
                "status": resp.status_code,
                "body": resp.text[:BODY_LIMIT],
                "body_length": len(resp.text),
                "headers": dict(resp.headers),
            }

        try:
            resp_a = await _do_request(req_a)
            resp_b = await _do_request(req_b)

            return {
                "tool": "diff",
                "request_a": {"url": req_a.get("url"), "status": resp_a["status"], "body_length": resp_a["body_length"]},
                "request_b": {"url": req_b.get("url"), "status": resp_b["status"], "body_length": resp_b["body_length"]},
                "same_status": resp_a["status"] == resp_b["status"],
                "same_length": abs(resp_a["body_length"] - resp_b["body_length"]) < 50,
                "body_a": resp_a["body"][:4000],
                "body_b": resp_b["body"][:4000],
                "different_data": resp_a["body"] != resp_b["body"],
            }
        except Exception as e:
            return {"tool": "diff", "error": str(e)}

    async def _exec_login(self, action: dict, client: httpx.AsyncClient, domain: str) -> dict:
        """Login and store session for subsequent requests."""
        url = action.get("url", "")
        if not url or not self._is_in_scope(url, domain):
            return {"tool": "login", "error": "URL not in scope"}

        body = action.get("body", {})
        headers = dict(action.get("headers", {}))
        headers.setdefault("Content-Type", "application/json")
        headers.update(self._get_rotating_ua())

        try:
            resp = await client.post(url, json=body, headers=headers)

            # Extract cookies
            for cookie_name, cookie_value in resp.cookies.items():
                self._session_cookies[cookie_name] = cookie_value

            # Extract token from response body
            token = None
            if action.get("extract_token"):
                try:
                    data = resp.json()
                    for key in ("token", "access_token", "jwt", "accessToken", "auth_token", "id_token"):
                        if key in data:
                            token = data[key]
                            break
                        # Check nested
                        if isinstance(data.get("data"), dict) and key in data["data"]:
                            token = data["data"][key]
                            break
                except Exception:
                    pass

            if token:
                self._session_token = token

            # Extract from Set-Cookie header
            set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []
            if not set_cookies:
                sc = resp.headers.get("set-cookie", "")
                if sc:
                    set_cookies = [sc]

            return {
                "tool": "login",
                "status": resp.status_code,
                "body": resp.text[:BODY_LIMIT],
                "token_extracted": token is not None,
                "token_preview": f"{token[:50]}..." if token else None,
                "cookies": dict(self._session_cookies),
                "set_cookies": set_cookies[:5],
            }
        except Exception as e:
            return {"tool": "login", "error": str(e)}

    async def _exec_fuzz(self, action: dict, client: httpx.AsyncClient, domain: str) -> dict:
        """Fuzz a parameter with multiple values."""
        url = action.get("url", "")
        if not url or not self._is_in_scope(url, domain):
            return {"tool": "fuzz", "error": "URL not in scope"}

        param = action.get("param", "")
        values = action.get("values", [])
        method = action.get("method", "GET").upper()

        results = []
        for val in values[:30]:  # Limit to 30 values
            try:
                headers = self._add_auth_headers({})
                headers.update(self._get_rotating_ua())

                if method == "GET":
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={val}"
                    resp = await client.get(test_url, headers=headers)
                else:
                    resp = await client.post(url, data={param: val}, headers=headers)

                reflected = str(val) in resp.text if val else False
                results.append({
                    "value": str(val)[:100],
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "reflected": reflected,
                    "snippet": resp.text[:500] if reflected else "",
                })
                await asyncio.sleep(0.1)  # Rate limiting
            except Exception as e:
                results.append({"value": str(val)[:100], "error": str(e)})

        # Summary
        statuses = {}
        for r in results:
            s = r.get("status", "error")
            statuses[s] = statuses.get(s, 0) + 1

        reflected_count = sum(1 for r in results if r.get("reflected"))

        return {
            "tool": "fuzz",
            "param": param,
            "total": len(results),
            "status_distribution": statuses,
            "reflected_count": reflected_count,
            "results": results,
        }

    async def _exec_extract(self, action: dict, client: httpx.AsyncClient, domain: str) -> dict:
        """Extract page structure: forms, hidden inputs, scripts, links, comments."""
        url = action.get("url", "")
        if not url or not self._is_in_scope(url, domain):
            return {"tool": "extract", "error": "URL not in scope"}

        headers = self._add_auth_headers({})
        headers.update(self._get_rotating_ua())

        try:
            resp = await client.get(url, headers=headers)
            text = resp.text

            # Extract forms
            forms = []
            form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
            for match in form_pattern.finditer(text):
                form_html = match.group(0)
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                selects = re.findall(r'<select[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)

                forms.append({
                    "action": action_match.group(1) if action_match else "",
                    "method": method_match.group(1) if method_match else "GET",
                    "fields": inputs + textareas + selects,
                })

            # Hidden inputs
            hidden = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
                text, re.IGNORECASE
            )

            # Script sources
            scripts = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', text, re.IGNORECASE)

            # Links
            links = re.findall(r'<a[^>]*href=["\']([^"\']*)["\']', text, re.IGNORECASE)
            # Filter to same domain
            in_scope_links = [l for l in links if domain in l or l.startswith("/")]

            # HTML comments
            comments = re.findall(r'<!--(.*?)-->', text, re.DOTALL)
            comments = [c.strip()[:200] for c in comments if c.strip() and len(c.strip()) > 5]

            # Meta tags
            metas = re.findall(r'<meta[^>]*>', text, re.IGNORECASE)

            # API endpoints in JS
            api_endpoints = re.findall(r'["\'](/api/[^"\']+)["\']', text)

            return {
                "tool": "extract",
                "url": url,
                "status": resp.status_code,
                "forms": forms[:10],
                "hidden_inputs": [{"name": h[0], "value": h[1]} for h in hidden[:20]],
                "scripts": scripts[:20],
                "links": in_scope_links[:30],
                "comments": comments[:10],
                "meta_tags": metas[:10],
                "api_endpoints": list(set(api_endpoints))[:20],
                "response_headers": {
                    k: v for k, v in resp.headers.items()
                    if k.lower() in (
                        "server", "x-powered-by", "content-security-policy",
                        "x-frame-options", "strict-transport-security",
                        "access-control-allow-origin", "set-cookie",
                        "x-content-type-options", "x-xss-protection",
                    )
                },
            }
        except Exception as e:
            return {"tool": "extract", "error": str(e)}

    def _format_results(self, results: list[dict]) -> str:
        """Format execution results for Claude."""
        parts = [f"## Execution Results ({len(results)} actions)\n"]

        for i, result in enumerate(results, 1):
            tool = result.get("tool", "?")
            parts.append(f"### Action {i}: {tool}")

            if "error" in result:
                parts.append(f"**ERROR**: {result['error']}")
                continue

            if tool == "http":
                parts.append(f"**{result.get('method', '?')} {result.get('url', '?')}**")
                parts.append(f"Status: {result.get('status', '?')}")
                parts.append(f"Body length: {result.get('body_length', '?')}")

                # Show security-relevant headers
                headers = result.get("headers", {})
                sec_headers = {k: v for k, v in headers.items() if k.lower() in (
                    "server", "x-powered-by", "content-type", "set-cookie",
                    "access-control-allow-origin", "content-security-policy",
                    "x-frame-options", "authorization", "www-authenticate",
                )}
                if sec_headers:
                    parts.append(f"Security headers: {json.dumps(sec_headers, default=str)}")

                body = result.get("body", "")
                if len(body) > 3000:
                    parts.append(f"Body (first 3000 chars):\n```\n{body[:3000]}\n```")
                else:
                    parts.append(f"Body:\n```\n{body}\n```")

            elif tool == "jwt_decode":
                parts.append(f"Algorithm: {result.get('algorithm', '?')}")
                parts.append(f"Header: {json.dumps(result.get('header', {}))}")
                parts.append(f"Payload: {json.dumps(result.get('payload', {}))}")
                parts.append(f"Has signature: {result.get('has_signature', '?')}")

            elif tool == "jwt_forge":
                parts.append(f"Forged token: {result.get('token', '?')}")

            elif tool == "diff":
                parts.append(f"Request A: {result.get('request_a', {}).get('url')} → {result.get('request_a', {}).get('status')}")
                parts.append(f"Request B: {result.get('request_b', {}).get('url')} → {result.get('request_b', {}).get('status')}")
                parts.append(f"Same status: {result.get('same_status')}")
                parts.append(f"Same length: {result.get('same_length')}")
                parts.append(f"Different data: {result.get('different_data')}")
                if result.get("different_data"):
                    parts.append(f"Body A:\n```\n{result.get('body_a', '')[:2000]}\n```")
                    parts.append(f"Body B:\n```\n{result.get('body_b', '')[:2000]}\n```")

            elif tool == "login":
                parts.append(f"Status: {result.get('status')}")
                parts.append(f"Token extracted: {result.get('token_extracted')}")
                if result.get("token_preview"):
                    parts.append(f"Token: {result['token_preview']}")
                parts.append(f"Body:\n```\n{result.get('body', '')[:2000]}\n```")

            elif tool == "fuzz":
                parts.append(f"Parameter: {result.get('param')}")
                parts.append(f"Status distribution: {result.get('status_distribution')}")
                parts.append(f"Reflected: {result.get('reflected_count')}/{result.get('total')}")
                for r in result.get("results", []):
                    if r.get("reflected") or r.get("status") != 200:
                        parts.append(f"  [{r.get('status')}] {r.get('value')} reflected={r.get('reflected')} len={r.get('length')}")

            elif tool == "extract":
                parts.append(f"URL: {result.get('url')}")
                parts.append(f"Forms: {json.dumps(result.get('forms', []), default=str)[:1000]}")
                parts.append(f"Hidden inputs: {json.dumps(result.get('hidden_inputs', []))}")
                parts.append(f"Scripts: {json.dumps(result.get('scripts', []))[:500]}")
                parts.append(f"API endpoints: {json.dumps(result.get('api_endpoints', []))}")
                parts.append(f"Comments: {json.dumps(result.get('comments', []))[:500]}")
                parts.append(f"Security headers: {json.dumps(result.get('response_headers', {}))}")

            parts.append("")  # blank line

        return "\n".join(parts)
