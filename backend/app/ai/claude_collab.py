"""
Claude Collaboration — Deep iterative dialogue between Phantom and Claude.

Instead of one-shot queries, Phantom and Claude work together:
1. Phantom shares what it found
2. Claude analyzes and suggests what to investigate next
3. Phantom executes, shares results
4. Claude refines analysis
5. Repeat until they reach a conclusion

This is how the article described: Claude found 22 Firefox vulns not by
running a single query, but by deeply analyzing code patterns iteratively.

Extended actions: generate_payload, chain_attack, fuzz_parameter,
extract_info, compare_responses — giving Claude advanced pentesting tools.
"""
import asyncio
import json
import logging
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin

import anthropic
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# Response body limit (increased from 5000 to 10000)
BODY_LIMIT = 10000

COLLAB_SYSTEM = """You are Claude, working as a partner with PHANTOM — an autonomous penetration testing AI.

You are NOT just answering questions. You are ACTIVELY collaborating on a security assessment.

Your role in this partnership:
- Analyze what Phantom found and identify what it MISSED
- Suggest specific next steps: what URLs to test, what payloads to try, what patterns to look for
- Think like the best bug bounty hunter in the world
- If you see something suspicious, say EXACTLY what to test and how
- If Phantom found a vuln, help confirm it and find related vulns (attack chains)
- Be specific: give exact URLs, exact payloads, exact headers to send
- Think about what a human hacker would notice that automated tools miss

AVAILABLE ACTIONS:

1. HTTP requests:
```action
{"type": "http_get", "url": "https://...", "headers": {...}}
```
```action
{"type": "http_post", "url": "https://...", "body": "...", "headers": {...}}
```

2. Test a specific payload against a parameter:
```action
{"type": "test_payload", "url": "https://...", "param": "q", "payload": "' OR 1=1--"}
```

3. Generate WAF-bypass or context-specific payloads using AI mutation engine:
```action
{"type": "generate_payload", "vuln_type": "sqli", "context": "MySQL, WAF: Cloudflare, login form", "evasion": "unicode encoding, comment injection"}
```
Use this when you need creative payloads that bypass WAFs or target specific technologies.

4. Chain multi-step attacks (session hijacking, privilege escalation, IDOR chains):
```action
{"type": "chain_attack", "steps": [
  {"method": "POST", "url": "https://target.com/login", "body": {"user": "admin", "pass": "test"}},
  {"method": "GET", "url": "https://target.com/admin/users", "use_cookies_from": "step_1"},
  {"method": "GET", "url": "https://target.com/admin/export", "use_cookies_from": "step_1"}
]}
```
Each step can use cookies from a previous step. Great for testing auth flows and IDOR.

5. Fuzz a parameter with multiple payloads at once:
```action
{"type": "fuzz_parameter", "url": "https://target.com/search", "param": "q", "method": "GET", "payloads": ["'", "\"", "<script>", "{{7*7}}", "${7*7}", "`", "%00", "../"]}
```
Returns a summary of which payloads triggered different status codes, lengths, or reflections.

6. Extract structured info from a page (forms, comments, scripts, meta, hidden inputs, links):
```action
{"type": "extract_info", "url": "https://target.com/login", "extract": ["forms", "comments", "scripts", "meta", "hidden_inputs", "links"]}
```

7. Compare two responses to detect IDOR, auth bypass, or behavior differences:
```action
{"type": "compare_responses", "request_a": {"method": "GET", "url": "https://target.com/api/user/1"}, "request_b": {"method": "GET", "url": "https://target.com/api/user/2"}}
```
Shows status diff, header diff, body length diff, and content diff.

8. Analyze previous results more deeply:
```action
{"type": "analyze_response", "focus": "look for X pattern in the response"}
```

9. Reach a conclusion:
```action
{"type": "conclusion", "verdict": "vulnerable/not_vulnerable/needs_more_testing", "findings": [...]}
```

ATTACK PATH INTELLIGENCE:
You have access to an Application Graph with identified attack paths.
For each HIGH or CRITICAL risk attack path, you SHOULD generate specific test actions.
Priority order: admin_takeover > payment_manipulation > idor_chain > file_upload_rce > api_key_exposure > privilege_escalation > mass_assignment

When attack paths are provided:
- Use chain_attack to walk through each path step-by-step
- Use compare_responses on IDOR paths to prove data differs between users
- Use extract_info on the first endpoint of each path to understand inputs/tokens needed
- Tag your actions with the attack path name using the "attack_path" field, e.g.:
```action
{"type": "chain_attack", "attack_path": "admin_takeover", "steps": [...]}
```
This helps Phantom track which paths have been tested and which still need attention.

STRATEGIC GUIDANCE:
- Use generate_payload to create WAF-bypass payloads when standard payloads get blocked
- Use fuzz_parameter to quickly test multiple injection types on a single endpoint
- Use compare_responses to detect IDOR by comparing authenticated vs unauthenticated requests
- Use chain_attack to test auth bypass: login \u2192 access admin \u2192 exfiltrate data
- Use extract_info to find hidden inputs, CSRF tokens, and JS endpoints before attacking
- Think in attack chains: find IDOR first, then escalate to data exfiltration
- If a WAF blocks you, use generate_payload with evasion techniques specific to that WAF

You can include multiple action blocks. Phantom will execute them and share results.
Keep going until you reach a CONCLUSION. Don't stop after one round.

IMPORTANT: Phantom tracks everything you've tried. Avoid repeating the same actions.
If something didn't work, try a DIFFERENT approach — don't retry the same thing.

CRITICAL VERIFICATION RULES — NEVER VIOLATE:
1. RESPONSE VALIDATION: Before reporting ANY finding, verify the response contains REAL DATA (JSON with records, actual credentials, PII), not just an HTML shell. If /admin returns HTML with <div id="root"> and JavaScript bundles, it's a React/Vue/Angular SPA shell — the frontend routing returns index.html for ALL routes. This is NOT an access control bypass.
2. ATTACK CHAIN LOGIC: Never claim race condition or double-spend on GET endpoints — GET is read-only. Only POST/PUT/DELETE with financial operations can have race conditions. Never invent exploit chains that are physically impossible.
3. STATIC ASSETS: Files ending in .js, .css, .png, .jpg, .svg, .woff are static assets. They don't need rate limiting, don't contain XSS (unless they're user-uploaded), and are NOT vulnerabilities.
4. EVIDENCE REQUIRED: Every finding MUST have concrete evidence — actual response data showing the leak/vulnerability. "Potential" without proof is NOT a finding. If you can't show the actual leaked data in the response, don't report it.
5. SPA vs API: Modern web apps serve the same HTML shell for ALL routes (/, /admin, /settings). The REAL security boundary is the API layer (/api/*). Test API endpoints with actual data, not HTML pages.
6. FALSE POSITIVE CHECK: Before reporting, ask yourself: "Is this response actual sensitive data, or just a frontend page?" If the response is HTML with script tags and no real data, it's NOT a vulnerability."""


class ClaudeCollaboration:
    """Iterative collaboration session between Phantom and Claude."""

    def __init__(self):
        self.client = None
        from app.ai.get_claude_key import get_claude_api_key
        api_key = get_claude_api_key()
        if api_key:
            self.client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = settings.claude_model
        self.conversation: list[dict] = []
        self.actions_taken: list[dict] = []
        self.findings: list[dict] = []
        self.rounds = 0
        self.max_rounds = 15  # Safety limit
        # Attack chain tracking — prevents infinite loops
        self._action_history: list[dict] = []
        # Evidence tracking — stores actual request/response data keyed by URL
        self._action_evidence: dict[str, dict] = {}

    def _track_action(self, action: dict):
        """Record an action in history for loop prevention."""
        entry = {
            "type": action.get("type"),
            "round": self.rounds,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        # Track key identifying fields per action type
        atype = action.get("type", "")
        if atype in ("http_get", "http_post"):
            entry["url"] = action.get("url", "")
        elif atype == "test_payload":
            entry["url"] = action.get("url", "")
            entry["param"] = action.get("param", "")
            entry["payload"] = action.get("payload", "")[:80]
        elif atype == "fuzz_parameter":
            entry["url"] = action.get("url", "")
            entry["param"] = action.get("param", "")
            entry["payload_count"] = len(action.get("payloads", []))
        elif atype == "chain_attack":
            entry["step_count"] = len(action.get("steps", []))
        elif atype == "generate_payload":
            entry["vuln_type"] = action.get("vuln_type", "")
        elif atype == "extract_info":
            entry["url"] = action.get("url", "")
            entry["extract"] = action.get("extract", [])
        elif atype == "compare_responses":
            entry["url_a"] = action.get("request_a", {}).get("url", "")
            entry["url_b"] = action.get("request_b", {}).get("url", "")
        # Track attack path association
        if action.get("attack_path"):
            entry["attack_path"] = action["attack_path"]
        self._action_history.append(entry)

    def _get_history_summary(self) -> str:
        """Build a summary of actions tried so far for Claude's context."""
        if not self._action_history:
            return ""
        lines = [f"\n--- ACTIONS TRIED SO FAR ({len(self._action_history)} total) ---"]
        for i, h in enumerate(self._action_history, 1):
            atype = h.get("type", "?")
            detail = ""
            if "url" in h:
                detail += f" url={h['url']}"
            if "param" in h:
                detail += f" param={h['param']}"
            if "payload" in h:
                detail += f" payload={h['payload']}"
            if "vuln_type" in h:
                detail += f" vuln_type={h['vuln_type']}"
            if "step_count" in h:
                detail += f" steps={h['step_count']}"
            if "payload_count" in h:
                detail += f" payloads={h['payload_count']}"
            if "attack_path" in h:
                detail += f" [path:{h['attack_path']}]"
            lines.append(f"  {i}. [R{h.get('round', '?')}] {atype}{detail}")

        # Summarize attack path coverage
        tested_paths = set(h["attack_path"] for h in self._action_history if h.get("attack_path"))
        if tested_paths:
            lines.append(f"\nAttack paths tested so far: {', '.join(sorted(tested_paths))}")
            lines.append("Focus on untested paths or dig deeper into partially tested ones.")

        lines.append("Avoid repeating these. Try different approaches.\n")
        return "\n".join(lines)

    async def start_analysis(self, context: dict, on_event=None) -> dict:
        """
        Start a collaborative analysis session.
        Phantom shares initial data, Claude analyzes and directs.
        Loop continues until Claude reaches a conclusion.

        Args:
            context: Scan context dict with domain, endpoints, vulns, etc.
            on_event: Optional async callback(event_dict) for live WebSocket events.
        """
        if not self.client:
            logger.warning("Claude API not available for collaboration")
            return {"findings": [], "rounds": 0, "error": "no_api_key"}

        domain = context.get("domain", "unknown")
        logger.info(f"Claude collab: starting analysis of {domain}")

        # Helper to emit events safely
        async def _emit(event: dict):
            if on_event:
                try:
                    await on_event(event)
                except Exception:
                    pass

        # Build initial context for Claude
        initial_message = self._build_initial_message(context)
        self.conversation = [{"role": "user", "content": initial_message}]

        http_client = None
        consecutive_empty = 0  # Track rounds with no actions
        try:
            import httpx
            http_client = httpx.AsyncClient(
                timeout=25.0,
                follow_redirects=True,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                },
            )

            while self.rounds < self.max_rounds:
                self.rounds += 1
                logger.info(f"Claude collab round {self.rounds}/{self.max_rounds} for {domain}")

                await _emit({
                    "type": "claude_thinking",
                    "round": self.rounds,
                    "message": f"Claude is analyzing (round {self.rounds}/{self.max_rounds})...",
                })

                # Ask Claude
                response = await self._ask_claude()
                if not response:
                    logger.warning(f"Claude collab: no response in round {self.rounds}, retrying...")
                    if self.rounds < self.max_rounds:
                        # Remove failed assistant message if any, nudge again
                        self.conversation.append({
                            "role": "user",
                            "content": "I didn't get your response. Please try again — "
                                       "give me specific actions or a conclusion."
                        })
                        continue
                    break

                # Parse actions from Claude's response
                actions = self._parse_actions(response)

                # Check if Claude reached a conclusion
                conclusions = [a for a in actions if a.get("type") == "conclusion"]
                if conclusions:
                    # Collect attack paths tested so far for tagging findings
                    tested_paths = set(
                        h["attack_path"] for h in self._action_history if h.get("attack_path")
                    )
                    for c in conclusions:
                        new_findings = c.get("findings", [])
                        # Tag each finding with its attack_path if the conclusion has one,
                        # or if the finding's URL matches a tested attack path
                        conclusion_path = c.get("attack_path", "")
                        for finding in new_findings:
                            if conclusion_path and not finding.get("attack_path"):
                                finding["attack_path"] = conclusion_path
                            elif not finding.get("attack_path") and tested_paths:
                                # Try to associate finding with a tested path
                                finding_url = (finding.get("url") or "").lower()
                                for h in self._action_history:
                                    if h.get("attack_path") and h.get("url", "").lower() in finding_url:
                                        finding["attack_path"] = h["attack_path"]
                                        break
                        self.findings.extend(new_findings)
                        for finding in new_findings:
                            await _emit({
                                "type": "claude_finding",
                                "finding": finding,
                            })
                    logger.info(
                        f"Claude collab: reached conclusion after {self.rounds} rounds. "
                        f"Verdict: {conclusions[0].get('verdict', '?')}"
                    )
                    break

                # No actions = Claude is done talking
                if not actions:
                    consecutive_empty += 1
                    # Give Claude up to 2 chances to produce actions before giving up
                    if consecutive_empty <= 2:
                        nudge = (
                            "You didn't provide any action blocks. I need concrete actions "
                            "in ```action ... ``` format. Either:\n"
                            "1. Give me URLs to test with http_get/http_post/test_payload\n"
                            "2. Use fuzz_parameter to test injection points\n"
                            "3. Use extract_info to analyze a page\n"
                            "4. Or give a conclusion if you've seen enough.\n\n"
                            "Remember: wrap each action in ```action\\n{...}\\n```"
                        )
                        self.conversation.append({"role": "user", "content": nudge})
                        continue
                    break
                else:
                    consecutive_empty = 0  # Reset on successful actions

                # Emit events for each action Claude wants to execute
                for action in actions:
                    await _emit({
                        "type": "claude_action",
                        "round": self.rounds,
                        "action": action,
                    })

                # Execute actions and collect results
                results = await self._execute_actions(actions, http_client, domain)

                # Share results with Claude (include action history)
                results_message = self._format_results(results)
                self.conversation.append({
                    "role": "user",
                    "content": results_message
                })

        except Exception as e:
            logger.error(f"Claude collab error for {domain}: {type(e).__name__}: {e}", exc_info=True)
            return {
                "domain": domain,
                "rounds": self.rounds,
                "findings": self.findings,
                "action_evidence": self._action_evidence,
                "actions_taken": len(self.actions_taken),
                "conversation_length": len(self.conversation),
                "error": f"{type(e).__name__}: {e}",
            }
        finally:
            if http_client:
                await http_client.aclose()

        # Build attack path coverage summary
        tested_paths = {}
        for h in self._action_history:
            ap = h.get("attack_path")
            if ap:
                tested_paths.setdefault(ap, 0)
                tested_paths[ap] += 1

        return {
            "domain": domain,
            "rounds": self.rounds,
            "findings": self.findings,
            "action_evidence": self._action_evidence,
            "actions_taken": len(self.actions_taken),
            "conversation_length": len(self.conversation),
            "attack_paths_tested": tested_paths,
        }

    async def analyze_finding(self, vuln_data: dict, context: dict) -> dict:
        """
        Deep-dive a specific finding with Claude.
        Iteratively test and confirm/deny the vulnerability.
        """
        if not self.client:
            return vuln_data

        domain = context.get("domain", "unknown")
        self.conversation = [{
            "role": "user",
            "content": f"""I found a potential vulnerability. Let's investigate together.

Target: {domain}
Finding: {json.dumps(vuln_data, indent=2, default=str)[:3000]}

Full context:
- Technologies: {json.dumps(context.get('technologies', {}), indent=2)[:1000]}
- Endpoints found: {len(context.get('endpoints', []))}
- WAF detected: {context.get('waf_info', 'none')}

Is this a real vulnerability or false positive?
What should I test to confirm? Give me specific actions."""
        }]

        http_client = None
        try:
            import httpx
            http_client = httpx.AsyncClient(
                timeout=25.0, follow_redirects=True, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )

            while self.rounds < self.max_rounds:
                self.rounds += 1
                response = await self._ask_claude()
                if not response:
                    break

                actions = self._parse_actions(response)
                conclusions = [a for a in actions if a.get("type") == "conclusion"]
                if conclusions:
                    for c in conclusions:
                        self.findings.extend(c.get("findings", []))
                    break

                if not actions:
                    break

                results = await self._execute_actions(actions, http_client, domain)
                self.conversation.append({
                    "role": "user",
                    "content": self._format_results(results)
                })

        except Exception as e:
            logger.error(f"Claude finding analysis error: {e}")
        finally:
            if http_client:
                await http_client.aclose()

        return {
            "original": vuln_data,
            "claude_analysis": self.findings,
            "rounds": self.rounds,
            "confirmed": any(
                f.get("confirmed", False) or f.get("verdict") == "vulnerable"
                for f in self.findings
            ),
        }

    async def _ask_claude(self) -> str | None:
        """Send conversation to Claude and get response, with retry on transient errors."""
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                # Re-fetch API key on retry (handles token refresh)
                if attempt > 0:
                    from app.ai.get_claude_key import get_claude_api_key
                    api_key = get_claude_api_key()
                    if api_key:
                        self.client = anthropic.AsyncAnthropic(api_key=api_key)
                    else:
                        logger.error("Claude API key unavailable on retry")
                        return None

                message = await self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=COLLAB_SYSTEM,
                    messages=self.conversation,
                )
                response_text = message.content[0].text
                self.conversation.append({
                    "role": "assistant",
                    "content": response_text
                })
                return response_text
            except anthropic.AuthenticationError:
                logger.warning(f"Claude API 401 (attempt {attempt + 1}/{max_retries + 1}), refreshing key...")
                if attempt == max_retries:
                    logger.error("Claude API auth failed after retries")
                    return None
                await asyncio.sleep(2)
            except (anthropic.RateLimitError, anthropic.APIStatusError) as e:
                logger.warning(f"Claude API error (attempt {attempt + 1}): {e}")
                if attempt == max_retries:
                    logger.error(f"Claude API failed after {max_retries + 1} attempts: {e}")
                    return None
                await asyncio.sleep(5 * (attempt + 1))
            except Exception as e:
                logger.error(f"Claude API unexpected error: {e}")
                return None

    def _parse_actions(self, response: str) -> list[dict]:
        """Extract action blocks from Claude's response."""
        actions = []

        # Primary: ```action blocks
        parts = response.split("```action")
        for part in parts[1:]:
            try:
                json_str = part.split("```")[0].strip()
                action = json.loads(json_str)
                actions.append(action)
            except (json.JSONDecodeError, IndexError):
                # Try fixing common JSON issues (trailing commas)
                try:
                    cleaned = re.sub(r',\s*([}\]])', r'\1', json_str)
                    action = json.loads(cleaned)
                    actions.append(action)
                except Exception:
                    logger.warning(f"Claude collab: unparseable action block: {json_str[:200]}")

        # Fallback: try ```json blocks if no ```action found
        if not actions and "```json" in response:
            for part in response.split("```json")[1:]:
                try:
                    json_str = part.split("```")[0].strip()
                    action = json.loads(json_str)
                    if isinstance(action, dict) and "type" in action:
                        actions.append(action)
                except (json.JSONDecodeError, IndexError):
                    pass

        # Infer attack_path from surrounding text when not explicitly set
        actions = self._tag_actions_with_attack_paths(actions, response)

        return actions

    def _tag_actions_with_attack_paths(self, actions: list[dict], response: str) -> list[dict]:
        """Tag parsed actions with attack path names based on response context.

        If Claude explicitly set "attack_path" in the action JSON, keep it.
        Otherwise, try to infer from the surrounding prose in the response.
        """
        if not actions:
            return actions

        # Keywords that map to attack path names
        _path_keywords = {
            "admin_takeover": ["admin takeover", "admin access", "admin panel", "admin dashboard", "admin endpoint"],
            "payment_manipulation": ["payment", "checkout", "price manipulation", "cart", "billing"],
            "idor_chain": ["idor", "insecure direct object", "sequential id", "user enumeration"],
            "file_upload_rce": ["file upload", "upload rce", "shell upload", "webshell"],
            "api_key_exposure": ["api key", "key exposure", "leaked key", "secret key", "api token"],
            "privilege_escalation": ["privilege escalation", "role escalation", "elevat"],
            "mass_assignment": ["mass assignment", "parameter pollution", "extra field"],
            "auth_bypass": ["auth bypass", "authentication bypass", "without auth", "skip auth"],
        }
        response_lower = response.lower()

        for action in actions:
            if action.get("attack_path"):
                continue  # Already tagged by Claude

            # Check action URLs against known path patterns
            action_url = ""
            if action.get("url"):
                action_url = action["url"].lower()
            elif action.get("steps"):
                action_url = " ".join(
                    (s.get("url", "") if isinstance(s, dict) else str(s))
                    for s in action["steps"]
                ).lower()

            # Try to match against known path keywords in the prose or URL
            for path_name, keywords in _path_keywords.items():
                for kw in keywords:
                    if kw in action_url or kw in response_lower:
                        action["attack_path"] = path_name
                        break
                if action.get("attack_path"):
                    break

        return actions

    async def _execute_actions(
        self, actions: list[dict], http_client, domain: str
    ) -> list[dict]:
        """Execute actions requested by Claude with per-action timeout."""
        results = []

        for action in actions:
            atype = action.get("type", "")
            self._track_action(action)

            # Per-action timeout: fuzz/chain get more time
            timeout = 60.0 if atype in ("fuzz_parameter", "chain_attack") else 30.0

            try:
                coro = None
                if atype == "http_get":
                    coro = self._exec_http_get(action, http_client, domain)
                elif atype == "http_post":
                    coro = self._exec_http_post(action, http_client, domain)
                elif atype == "test_payload":
                    coro = self._exec_test_payload(action, http_client, domain)
                elif atype == "generate_payload":
                    coro = self._exec_generate_payload(action)
                elif atype == "chain_attack":
                    coro = self._exec_chain_attack(action, http_client, domain)
                elif atype == "fuzz_parameter":
                    coro = self._exec_fuzz_parameter(action, http_client, domain)
                elif atype == "extract_info":
                    coro = self._exec_extract_info(action, http_client, domain)
                elif atype == "compare_responses":
                    coro = self._exec_compare_responses(action, http_client, domain)
                elif atype == "analyze_response":
                    results.append({
                        "action": action,
                        "note": "Analysis requested — review previous results above",
                    })
                    continue
                elif atype == "conclusion":
                    continue
                else:
                    results.append({"action": action, "error": f"Unknown action type: {atype}"})
                    continue

                result = await asyncio.wait_for(coro, timeout=timeout)
                results.append(result)

            except asyncio.TimeoutError:
                logger.warning(f"Claude collab: action {atype} timed out after {timeout}s")
                results.append({"action": action, "error": f"Action timed out after {timeout:.0f}s"})
            except Exception as e:
                results.append({"action": action, "error": str(e)})

        return results

    # ── Existing action executors ──────────────────────────────────────

    async def _exec_http_get(self, action: dict, http_client, domain: str) -> dict:
        """Execute http_get action."""
        url = action.get("url", "")
        if not url or not self._is_safe_url(url, domain):
            return {"action": action, "error": "URL not in scope"}

        headers = action.get("headers", {})
        resp = await http_client.get(url, headers=headers)
        self._store_evidence(url, "GET", resp, request_headers=headers)
        self.actions_taken.append(action)
        return {
            "action": action,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:BODY_LIMIT],
            "url_final": str(resp.url),
        }

    async def _exec_http_post(self, action: dict, http_client, domain: str) -> dict:
        """Execute http_post action."""
        url = action.get("url", "")
        if not url or not self._is_safe_url(url, domain):
            return {"action": action, "error": "URL not in scope"}

        body = action.get("body", "")
        headers = action.get("headers", {})
        content_type = action.get("content_type", "application/x-www-form-urlencoded")
        if "content-type" not in {k.lower() for k in headers}:
            headers["Content-Type"] = content_type

        # Support dict body as JSON
        if isinstance(body, dict):
            if "json" in content_type.lower():
                resp = await http_client.post(url, json=body, headers=headers)
            else:
                resp = await http_client.post(url, data=body, headers=headers)
        else:
            resp = await http_client.post(url, content=body, headers=headers)

        body_str = json.dumps(body, default=str) if isinstance(body, dict) else str(body)
        self._store_evidence(url, "POST", resp, request_headers=headers, request_body=body_str)
        self.actions_taken.append(action)
        return {
            "action": action,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:BODY_LIMIT],
        }

    async def _exec_test_payload(self, action: dict, http_client, domain: str) -> dict:
        """Execute test_payload action."""
        url = action.get("url", "")
        if not url or not self._is_safe_url(url, domain):
            return {"action": action, "error": "URL not in scope"}

        param = action.get("param", "")
        payload = action.get("payload", "")
        method = action.get("method", "GET").upper()

        if method == "GET":
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={payload}"
            resp = await http_client.get(test_url)
            self._store_evidence(test_url, "GET", resp)
        else:
            resp = await http_client.post(
                url,
                data={param: payload},
            )
            self._store_evidence(url, "POST", resp, request_body=f"{param}={payload}")

        reflected = payload in resp.text if payload else False
        self.actions_taken.append(action)
        return {
            "action": action,
            "status_code": resp.status_code,
            "reflected": reflected,
            "body": resp.text[:BODY_LIMIT],
            "headers": dict(resp.headers),
        }

    # ── New action executors ───────────────────────────────────────────

    async def _exec_generate_payload(self, action: dict) -> dict:
        """Generate payloads using LLM/mutation engine based on Claude's specs."""
        vuln_type = action.get("vuln_type", "xss")
        context_desc = action.get("context", "")
        evasion = action.get("evasion", "")

        try:
            from app.ai.llm_engine import LLMEngine
            engine = LLMEngine()

            tech_context = {
                "technology": context_desc,
                "waf": "unknown",
                "param_type": "string",
                "injection_point": "parameter",
            }

            # Parse WAF from context if mentioned
            context_lower = context_desc.lower()
            for waf_name in ("cloudflare", "akamai", "imperva", "modsecurity",
                             "aws waf", "f5", "sucuri", "barracuda"):
                if waf_name in context_lower:
                    tech_context["waf"] = waf_name
                    break

            if evasion:
                tech_context["evasion_techniques"] = evasion

            # Try LLM generation first
            if await engine.is_available():
                prompt = (
                    f"Generate 10 advanced {vuln_type} payloads for penetration testing.\n\n"
                    f"Context: {context_desc}\n"
                    f"Evasion techniques to apply: {evasion}\n\n"
                    "Requirements:\n"
                    "- Each payload must be on its own line\n"
                    "- Include WAF bypass variants\n"
                    "- Apply the specified evasion techniques\n"
                    "- Focus on payloads that would bypass modern security filters\n"
                    "- No explanations, just the raw payloads, one per line"
                )
                raw = await engine.query(prompt)
                ai_payloads = [
                    line.strip().lstrip("0123456789.-) ")
                    for line in raw.strip().split("\n")
                    if line.strip() and not line.strip().startswith("#")
                ]
                # Remove empty after stripping
                ai_payloads = [p for p in ai_payloads if p][:15]
            else:
                ai_payloads = []

            # Always include fallback payloads
            fallback = engine._fallback_payloads(vuln_type)

            # Merge: AI payloads first, then fallback for coverage
            seen = set()
            merged = []
            for p in ai_payloads + fallback:
                if p not in seen:
                    seen.add(p)
                    merged.append(p)

            self.actions_taken.append(action)
            return {
                "action": action,
                "payloads": merged[:20],
                "count": len(merged[:20]),
                "source": "llm" if ai_payloads else "fallback",
                "vuln_type": vuln_type,
            }

        except Exception as e:
            logger.error(f"generate_payload error: {e}")
            # Return basic fallback payloads
            from app.ai.llm_engine import LLMEngine
            engine = LLMEngine()
            fallback = engine._fallback_payloads(vuln_type)
            return {
                "action": action,
                "payloads": fallback[:10],
                "count": len(fallback[:10]),
                "source": "fallback",
                "error": str(e),
            }

    async def _exec_chain_attack(self, action: dict, http_client, domain: str) -> dict:
        """Execute a multi-step attack chain, passing cookies between steps."""
        steps = action.get("steps", [])
        attack_path = action.get("attack_path", "")
        if not steps:
            return {"action": action, "error": "No steps provided"}
        if len(steps) > 10:
            return {"action": action, "error": "Too many steps (max 10)"}
        if attack_path:
            logger.info(f"Claude collab: executing chain_attack for attack path '{attack_path}' ({len(steps)} steps)")

        step_results = []
        # Cookie jars per step — accumulated cookies from responses
        step_cookies: dict[int, dict] = {}

        for idx, step in enumerate(steps):
            step_num = idx + 1
            method = step.get("method", "GET").upper()
            url = step.get("url", "")
            body = step.get("body", "")
            headers = dict(step.get("headers", {}))

            if not url or not self._is_safe_url(url, domain):
                step_results.append({
                    "step": step_num,
                    "error": f"URL not in scope: {url}",
                })
                continue

            # Inject cookies from a previous step if requested
            use_cookies_from = step.get("use_cookies_from", "")
            if use_cookies_from:
                # Parse "step_N" format
                try:
                    ref_step = int(str(use_cookies_from).replace("step_", ""))
                    if ref_step in step_cookies:
                        cookie_header = "; ".join(
                            f"{k}={v}" for k, v in step_cookies[ref_step].items()
                        )
                        headers["Cookie"] = cookie_header
                except (ValueError, KeyError):
                    pass

            try:
                if method == "GET":
                    resp = await http_client.get(url, headers=headers)
                elif method == "POST":
                    if isinstance(body, dict):
                        content_type = headers.get("Content-Type", headers.get("content-type", ""))
                        if "json" in content_type:
                            resp = await http_client.post(url, json=body, headers=headers)
                        else:
                            resp = await http_client.post(url, data=body, headers=headers)
                    else:
                        resp = await http_client.post(url, content=str(body), headers=headers)
                elif method == "PUT":
                    if isinstance(body, dict):
                        resp = await http_client.put(url, json=body, headers=headers)
                    else:
                        resp = await http_client.put(url, content=str(body), headers=headers)
                elif method == "DELETE":
                    resp = await http_client.delete(url, headers=headers)
                else:
                    step_results.append({"step": step_num, "error": f"Unsupported method: {method}"})
                    continue

                # Extract Set-Cookie headers for chaining
                cookies = {}
                for cookie_val in resp.headers.get_list("set-cookie"):
                    # Parse "name=value; ..." format
                    if "=" in cookie_val:
                        parts = cookie_val.split(";")[0]
                        name, _, value = parts.partition("=")
                        cookies[name.strip()] = value.strip()
                # Merge with any inherited cookies
                if use_cookies_from:
                    try:
                        ref = int(str(use_cookies_from).replace("step_", ""))
                        if ref in step_cookies:
                            merged = dict(step_cookies[ref])
                            merged.update(cookies)
                            cookies = merged
                    except (ValueError, KeyError):
                        pass
                step_cookies[step_num] = cookies

                body_str = json.dumps(body, default=str) if isinstance(body, dict) else str(body) if body else None
                self._store_evidence(url, method, resp, request_headers=headers, request_body=body_str)

                step_results.append({
                    "step": step_num,
                    "method": method,
                    "url": url,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:BODY_LIMIT],
                    "cookies_received": cookies,
                })

            except Exception as e:
                step_results.append({"step": step_num, "error": str(e)})

        self.actions_taken.append(action)
        result = {
            "action": action,
            "chain_results": step_results,
            "steps_executed": len(step_results),
            "steps_succeeded": sum(1 for s in step_results if "status_code" in s),
        }
        if attack_path:
            result["attack_path"] = attack_path
            result["attack_path_context"] = f"Testing as part of {attack_path} attack path"
        return result

    async def _exec_fuzz_parameter(self, action: dict, http_client, domain: str) -> dict:
        """Fuzz a single parameter with multiple payloads."""
        url = action.get("url", "")
        if not url or not self._is_safe_url(url, domain):
            return {"action": action, "error": "URL not in scope"}

        param = action.get("param", "")
        payloads = action.get("payloads", [])
        method = action.get("method", "GET").upper()

        if not param:
            return {"action": action, "error": "No param specified"}
        if not payloads:
            return {"action": action, "error": "No payloads specified"}
        if len(payloads) > 50:
            payloads = payloads[:50]  # Safety cap

        fuzz_results = []
        baseline_status = None
        baseline_length = None

        for payload in payloads:
            try:
                if method == "GET":
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={payload}"
                    resp = await http_client.get(test_url)
                else:
                    resp = await http_client.post(url, data={param: payload})

                status = resp.status_code
                body_len = len(resp.text)
                reflected = payload in resp.text if payload else False

                # Detect anomalies vs baseline
                if baseline_status is None:
                    baseline_status = status
                    baseline_length = body_len

                anomaly = (
                    status != baseline_status
                    or abs(body_len - baseline_length) > 100
                    or reflected
                )

                # Store evidence for anomalous fuzz results
                if anomaly:
                    fuzz_url = test_url if method == "GET" else url
                    self._store_evidence(fuzz_url, method, resp, request_body=f"{param}={payload}")

                fuzz_results.append({
                    "payload": payload,
                    "status": status,
                    "length": body_len,
                    "reflected": reflected,
                    "anomaly": anomaly,
                    # Include body snippet only for anomalous responses
                    "body_snippet": resp.text[:500] if anomaly else None,
                })

            except Exception as e:
                fuzz_results.append({
                    "payload": payload,
                    "error": str(e),
                    "anomaly": True,
                })

        # Build summary
        anomalies = [r for r in fuzz_results if r.get("anomaly")]
        reflected = [r for r in fuzz_results if r.get("reflected")]

        self.actions_taken.append(action)
        return {
            "action": action,
            "url": url,
            "param": param,
            "total_payloads": len(payloads),
            "anomalies_found": len(anomalies),
            "reflections_found": len(reflected),
            "baseline_status": baseline_status,
            "baseline_length": baseline_length,
            "results": fuzz_results,
            "summary": (
                f"Fuzzed {param} with {len(payloads)} payloads. "
                f"{len(anomalies)} anomalies, {len(reflected)} reflections."
            ),
        }

    async def _exec_extract_info(self, action: dict, http_client, domain: str) -> dict:
        """Extract structured information from a page."""
        url = action.get("url", "")
        if not url or not self._is_safe_url(url, domain):
            return {"action": action, "error": "URL not in scope"}

        extract_types = action.get("extract", ["forms", "links", "scripts", "comments", "meta"])

        try:
            resp = await http_client.get(url)
            self._store_evidence(url, "GET", resp)
            html = resp.text
            extracted = {}

            if "forms" in extract_types:
                extracted["forms"] = self._extract_forms(html, url)

            if "comments" in extract_types:
                comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
                extracted["comments"] = [c.strip() for c in comments if c.strip()][:20]

            if "scripts" in extract_types:
                # Extract script src attributes and inline script content
                src_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
                inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
                extracted["scripts"] = {
                    "external": src_scripts[:20],
                    "inline_count": len(inline_scripts),
                    "inline_snippets": [s.strip()[:200] for s in inline_scripts if s.strip()][:10],
                }

            if "meta" in extract_types:
                meta_tags = re.findall(
                    r'<meta\s+([^>]+)/?>', html, re.IGNORECASE
                )
                parsed_meta = []
                for m in meta_tags[:20]:
                    attrs = {}
                    for match in re.finditer(r'(\w+)=["\']([^"\']*)["\']', m):
                        attrs[match.group(1)] = match.group(2)
                    if attrs:
                        parsed_meta.append(attrs)
                extracted["meta"] = parsed_meta

            if "hidden_inputs" in extract_types:
                hidden = re.findall(
                    r'<input[^>]*type=["\']hidden["\'][^>]*>', html, re.IGNORECASE
                )
                parsed_hidden = []
                for h in hidden:
                    name = re.search(r'name=["\']([^"\']+)["\']', h)
                    value = re.search(r'value=["\']([^"\']*)["\']', h)
                    parsed_hidden.append({
                        "name": name.group(1) if name else "",
                        "value": value.group(1)[:100] if value else "",
                    })
                extracted["hidden_inputs"] = parsed_hidden

            if "links" in extract_types:
                links = re.findall(r'<a[^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE)
                # Resolve relative URLs
                resolved = []
                for link in links[:30]:
                    if link.startswith("http"):
                        resolved.append(link)
                    elif link.startswith("/"):
                        parsed = urlparse(url)
                        resolved.append(f"{parsed.scheme}://{parsed.netloc}{link}")
                    elif not link.startswith(("#", "javascript:", "mailto:")):
                        resolved.append(urljoin(url, link))
                extracted["links"] = resolved

            if "headers" in extract_types:
                extracted["response_headers"] = dict(resp.headers)

            self.actions_taken.append(action)
            return {
                "action": action,
                "url": url,
                "status_code": resp.status_code,
                "extracted": extracted,
            }

        except Exception as e:
            return {"action": action, "error": str(e)}

    async def _exec_compare_responses(self, action: dict, http_client, domain: str) -> dict:
        """Compare two HTTP responses for differences (IDOR detection, auth bypass)."""
        req_a = action.get("request_a", {})
        req_b = action.get("request_b", {})

        url_a = req_a.get("url", "")
        url_b = req_b.get("url", "")

        if not url_a or not self._is_safe_url(url_a, domain):
            return {"action": action, "error": f"URL A not in scope: {url_a}"}
        if not url_b or not self._is_safe_url(url_b, domain):
            return {"action": action, "error": f"URL B not in scope: {url_b}"}

        try:
            # Execute both requests
            async def _make_request(req_spec):
                url = req_spec.get("url", "")
                method = req_spec.get("method", "GET").upper()
                headers = req_spec.get("headers", {})
                body = req_spec.get("body", "")

                if method == "GET":
                    return await http_client.get(url, headers=headers)
                elif method == "POST":
                    if isinstance(body, dict):
                        return await http_client.post(url, data=body, headers=headers)
                    return await http_client.post(url, content=str(body), headers=headers)
                else:
                    return await http_client.get(url, headers=headers)

            resp_a, resp_b = await asyncio.gather(
                _make_request(req_a),
                _make_request(req_b),
            )

            # Store evidence for both requests
            self._store_evidence(url_a, req_a.get("method", "GET").upper(), resp_a)
            self._store_evidence(url_b, req_b.get("method", "GET").upper(), resp_b)

            # Compare
            status_diff = resp_a.status_code != resp_b.status_code
            length_a = len(resp_a.text)
            length_b = len(resp_b.text)
            length_diff = abs(length_a - length_b)

            # Header diff — compare security-relevant headers
            interesting_keys = {
                "content-type", "set-cookie", "x-powered-by", "server",
                "access-control-allow-origin", "content-security-policy",
                "location", "x-frame-options", "www-authenticate",
            }
            headers_a = {k: v for k, v in resp_a.headers.items() if k.lower() in interesting_keys}
            headers_b = {k: v for k, v in resp_b.headers.items() if k.lower() in interesting_keys}
            header_diffs = {}
            all_keys = set(headers_a.keys()) | set(headers_b.keys())
            for k in all_keys:
                va = headers_a.get(k)
                vb = headers_b.get(k)
                if va != vb:
                    header_diffs[k] = {"a": va, "b": vb}

            # Content similarity check
            body_a = resp_a.text[:BODY_LIMIT]
            body_b = resp_b.text[:BODY_LIMIT]
            bodies_identical = body_a == body_b

            self.actions_taken.append(action)
            return {
                "action": action,
                "response_a": {
                    "url": url_a,
                    "status": resp_a.status_code,
                    "length": length_a,
                    "body": body_a[:3000],
                },
                "response_b": {
                    "url": url_b,
                    "status": resp_b.status_code,
                    "length": length_b,
                    "body": body_b[:3000],
                },
                "comparison": {
                    "status_different": status_diff,
                    "length_diff": length_diff,
                    "bodies_identical": bodies_identical,
                    "header_diffs": header_diffs,
                    "potential_idor": (
                        not bodies_identical
                        and not status_diff
                        and resp_a.status_code == 200
                    ),
                },
            }

        except Exception as e:
            return {"action": action, "error": str(e)}

    # ── Evidence collection ──────────────────────────────────────────────

    def _store_evidence(self, url: str, method: str, resp, request_headers: dict | None = None, request_body: str | None = None):
        """Store HTTP request/response evidence for a URL."""
        evidence = {
            "request": {
                "url": url,
                "method": method,
                "headers": dict(resp.request.headers) if hasattr(resp, 'request') and resp.request else (request_headers or {}),
            },
            "response": {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:5000],
            },
        }
        if request_body:
            evidence["request"]["body"] = request_body[:5000]
        self._action_evidence[url] = evidence

    def _get_evidence_for_finding(self, finding: dict) -> tuple[dict | None, dict | None]:
        """Look up stored HTTP evidence for a finding.

        Returns (request_data, response_data) or (None, None) if no evidence found.
        Matches by finding URL, endpoint, or any URL mentioned in finding fields.
        """
        # Try direct URL match
        url = finding.get("url", "")
        if url and url in self._action_evidence:
            ev = self._action_evidence[url]
            return ev["request"], ev["response"]

        # Try endpoint field
        endpoint = finding.get("endpoint", "")
        if endpoint and endpoint in self._action_evidence:
            ev = self._action_evidence[endpoint]
            return ev["request"], ev["response"]

        # Try partial URL match (finding URL might be a path, evidence key is full URL)
        if url:
            for ev_url, ev in self._action_evidence.items():
                if url in ev_url or ev_url.endswith(url):
                    return ev["request"], ev["response"]

        # Try matching any URL-like value in the finding dict
        for key in ("location", "target", "affected_url"):
            val = finding.get(key, "")
            if val and val in self._action_evidence:
                ev = self._action_evidence[val]
                return ev["request"], ev["response"]

        return None, None

    # ── Helper methods ─────────────────────────────────────────────────

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        """Extract form details from HTML."""
        forms = []
        form_pattern = re.compile(
            r'<form([^>]*)>(.*?)</form>', re.DOTALL | re.IGNORECASE
        )
        for attrs_str, form_body in form_pattern.findall(html):
            form = {}
            # Parse form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs_str)
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
            form["action"] = action_match.group(1) if action_match else ""
            form["method"] = method_match.group(1).upper() if method_match else "GET"

            # Resolve action URL
            if form["action"] and not form["action"].startswith("http"):
                form["action"] = urljoin(base_url, form["action"])

            # Extract inputs
            inputs = []
            for input_match in re.finditer(r'<input([^>]*)/?>', form_body, re.IGNORECASE):
                input_attrs = input_match.group(1)
                inp = {}
                for a in ("type", "name", "value", "id", "placeholder"):
                    m = re.search(rf'{a}=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE)
                    if m:
                        inp[a] = m.group(1)
                if inp.get("name"):
                    inputs.append(inp)

            # Extract textareas and selects
            for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE):
                inputs.append({"type": "textarea", "name": ta.group(1)})
            for sel in re.finditer(r'<select[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE):
                inputs.append({"type": "select", "name": sel.group(1)})

            form["inputs"] = inputs
            forms.append(form)

        return forms[:10]

    def _is_safe_url(self, url: str, domain: str) -> bool:
        """Ensure URL belongs to the target domain (stay in scope)."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Allow target domain and its subdomains
        return host == domain or host.endswith(f".{domain}")

    def _build_initial_message(self, context: dict) -> str:
        """Build the initial message from scan context."""
        domain = context.get("domain", "unknown")
        endpoints = context.get("endpoints", [])
        vulns = context.get("vulnerabilities", [])
        technologies = context.get("technologies", {})
        subdomains = context.get("subdomains", [])
        ports = context.get("ports", {})
        scan_results = context.get("scan_results", [])
        knowledge_context = context.get("_rag_context", "")
        application_graph = context.get("application_graph", {})
        stateful_crawl = context.get("stateful_crawl", {})

        # Format endpoints — show all when few, only high-interest when many
        endpoint_list = ""
        high_interest = [
            ep for ep in endpoints
            if ep.get("interest") in ("high", "critical") or ep.get("type") in ("form", "api", "auth")
        ]
        # If we have few endpoints or few high-interest ones, show everything
        show_all = len(endpoints) < 50 or len(high_interest) < 10
        display_eps = endpoints[:60] if show_all else high_interest[:40]
        for ep in display_eps:
            url = ep.get("url", "")
            etype = ep.get("type", "")
            interest = ep.get("interest", "")
            endpoint_list += f"\n  - [{interest}] {etype}: {url}"

        # Format existing vulns
        vuln_list = ""
        for v in vulns[:20]:
            vtype = v.get("vuln_type", v.get("type", ""))
            vurl = v.get("url", "")
            severity = v.get("severity", "")
            vuln_list += f"\n  - [{severity}] {vtype}: {vurl}"

        # Format application graph (entities, attack paths, auth flows)
        graph_section = ""
        if application_graph:
            graph_parts = []
            # Entities summary — top entities with endpoint counts and methods
            entities = application_graph.get("entities", [])
            if not isinstance(entities, list):
                entities = list(entities.values()) if isinstance(entities, dict) else []
            if entities:
                graph_parts.append("Entities:")
                for ent in entities[:15]:
                    name = ent.get("name", ent.get("id", "?"))
                    eps = ent.get("endpoints", [])
                    methods = sorted(set(
                        m for ep in eps for m in (
                            [ep.get("method", "GET")] if isinstance(ep.get("method"), str)
                            else ep.get("methods", ["GET"])
                        )
                    ))
                    graph_parts.append(f"  - {name}: {len(eps)} endpoints, methods: {', '.join(methods)}")

            # Attack paths — all paths with risk and steps, sorted by priority
            attack_paths = application_graph.get("attack_paths", [])
            if not isinstance(attack_paths, list):
                attack_paths = list(attack_paths.values()) if isinstance(attack_paths, dict) else []
            if attack_paths:
                # Priority ordering for attack path types
                _path_priority = {
                    "admin_takeover": 0, "payment_manipulation": 1, "idor_chain": 2,
                    "file_upload_rce": 3, "api_key_exposure": 4, "privilege_escalation": 5,
                    "mass_assignment": 6,
                }
                _risk_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}

                def _ap_sort_key(ap):
                    name = (ap.get("name") or ap.get("description") or "").lower().replace(" ", "_")
                    risk = (ap.get("risk") or ap.get("risk_level") or "medium").lower()
                    type_score = min((_path_priority.get(t, 99) for t in _path_priority if t in name), default=99)
                    return (_risk_priority.get(risk, 99), type_score)

                sorted_paths = sorted(attack_paths, key=_ap_sort_key)

                graph_parts.append("\n## Priority Attack Paths (TEST THESE)")
                for idx, ap in enumerate(sorted_paths[:10], 1):
                    risk = (ap.get("risk") or ap.get("risk_level") or "?").upper()
                    desc = ap.get("description") or ap.get("name") or "?"
                    path_name = ap.get("name") or ap.get("id") or desc
                    steps = ap.get("steps", [])
                    # Build step chain with URLs
                    step_parts = []
                    for s in steps[:8]:
                        if isinstance(s, str):
                            step_parts.append(s)
                        elif isinstance(s, dict):
                            url = s.get("url") or s.get("endpoint") or s.get("action") or str(s)
                            method = s.get("method", "")
                            step_parts.append(f"{method} {url}".strip() if method else url)
                    steps_str = " → ".join(step_parts)
                    graph_parts.append(f"  {idx}. [{risk}] {desc}: {steps_str}")
                    # Add test suggestion based on path type
                    name_lower = (path_name).lower().replace(" ", "_")
                    if "admin" in name_lower or "takeover" in name_lower:
                        graph_parts.append(f"     → Test: register user, login, try accessing admin endpoints")
                    elif "idor" in name_lower:
                        graph_parts.append(f"     → Test: access sequential IDs (1, 2, 3...), check if data differs")
                    elif "payment" in name_lower or "checkout" in name_lower:
                        graph_parts.append(f"     → Test: modify price parameter, add negative quantities, replay requests")
                    elif "upload" in name_lower or "rce" in name_lower:
                        graph_parts.append(f"     → Test: upload .php/.jsp shell, bypass extension filter, check execution")
                    elif "api_key" in name_lower or "exposure" in name_lower:
                        graph_parts.append(f"     → Test: access key endpoints without auth, check for leaked secrets")
                    elif "privilege" in name_lower or "escalat" in name_lower:
                        graph_parts.append(f"     → Test: change role parameter, access higher-privilege endpoints")
                    elif "mass_assign" in name_lower:
                        graph_parts.append(f"     → Test: add role/admin/is_staff fields to registration/update requests")
                    elif "auth" in name_lower or "bypass" in name_lower:
                        graph_parts.append(f"     → Test: access protected endpoints without token, with expired token")
                    else:
                        graph_parts.append(f"     → Test: use chain_attack to walk through steps, verify each transition")
                    graph_parts.append(f"     (tag actions with attack_path: \"{path_name}\")")

            # Auth flows
            auth_flows = application_graph.get("auth_flows", [])
            if auth_flows:
                graph_parts.append("Auth Flows:")
                for af in auth_flows[:5]:
                    flow_type = af.get("type", af.get("name", "?"))
                    login_url = af.get("login_url", af.get("url", "?"))
                    token_type = af.get("token_type", af.get("mechanism", "?"))
                    graph_parts.append(f"  - {flow_type}: {login_url} (token: {token_type})")

            if graph_parts:
                graph_section = "\n## Application Graph\n" + "\n".join(graph_parts)

        # Format stateful crawl results (forms, multi-step flows, harvested IDs)
        crawl_section = ""
        if stateful_crawl:
            crawl_parts = []

            # Forms found
            forms = stateful_crawl.get("forms", [])
            if not isinstance(forms, list):
                forms = list(forms.values()) if isinstance(forms, dict) else []
            if forms:
                crawl_parts.append("Forms Found:")
                for f in forms[:15]:
                    action = f.get("action", f.get("url", "?"))
                    method = f.get("method", "POST")
                    fields = f.get("fields", f.get("inputs", []))
                    field_names = [
                        (fd.get("name", "?") if isinstance(fd, dict) else str(fd))
                        for fd in fields[:8]
                    ]
                    crawl_parts.append(f"  - {method} {action} fields: {', '.join(field_names)}")

            # Multi-step flows
            flows = stateful_crawl.get("multi_step_flows", stateful_crawl.get("flows", []))
            if flows:
                crawl_parts.append("Multi-Step Flows:")
                for fl in flows[:5]:
                    name = fl.get("name", fl.get("description", "?"))
                    step_count = len(fl.get("steps", []))
                    crawl_parts.append(f"  - {name} ({step_count} steps)")

            # Harvested IDs/tokens
            harvested = stateful_crawl.get("harvested", stateful_crawl.get("tokens", stateful_crawl.get("ids", {})))
            if harvested:
                crawl_parts.append("Harvested IDs/Tokens:")
                items = harvested.items() if isinstance(harvested, dict) else [(str(i), h) for i, h in enumerate(harvested)]
                for key, val in list(items)[:10]:
                    val_str = str(val)[:80]
                    crawl_parts.append(f"  - {key}: {val_str}")

            if crawl_parts:
                crawl_section = "\n## Stateful Crawl Results\n" + "\n".join(crawl_parts)

        return f"""I'm PHANTOM, your AI hacking partner. Let's analyze this target together.

TARGET: {domain}
PROGRAM: Bug bounty (authorized testing)

RECONNAISSANCE:
- Subdomains: {json.dumps(subdomains[:20], default=str)}
- Open ports: {json.dumps(ports, default=str)[:1000]}
- Technologies: {json.dumps(technologies, indent=2, default=str)[:2000]}

ENDPOINTS ({len(endpoints)} total, showing high-interest):
{endpoint_list or "  (none marked high-interest yet)"}

SCANNER FINDINGS ({len(scan_results)} raw results):
{json.dumps(scan_results[:20], indent=2, default=str)[:5000]}

VULNERABILITIES FOUND SO FAR ({len(vulns)}):
{vuln_list or "  (none yet)"}

{knowledge_context}
{graph_section}
{crawl_section}
Based on everything above:
1. What do you see that looks promising?
2. What should I test that I might have missed?
3. Give me specific URLs and payloads to try.
4. What attack chains could we build?

You have powerful actions available: generate_payload, chain_attack, fuzz_parameter, extract_info, compare_responses.
Use them strategically. Let's find everything. Give me actions to execute."""

    def _format_results(self, results: list[dict]) -> str:
        """Format action results to share with Claude."""
        parts = [f"Here are the results of {len(results)} actions:\n"]

        for i, r in enumerate(results, 1):
            action = r.get("action", {})
            atype = action.get("type", "?")
            attack_path = action.get("attack_path", "")
            path_label = f" [attack_path: {attack_path}]" if attack_path else ""
            parts.append(f"--- Action {i}: {atype}{path_label} ---")
            if attack_path:
                parts.append(f"(Testing as part of {attack_path} attack path)")

            if "error" in r:
                parts.append(f"ERROR: {r['error']}")

            elif atype == "generate_payload":
                payloads = r.get("payloads", [])
                source = r.get("source", "unknown")
                parts.append(f"Generated {len(payloads)} {r.get('vuln_type', '?')} payloads (source: {source}):")
                for j, p in enumerate(payloads, 1):
                    parts.append(f"  {j}. {p}")

            elif atype == "chain_attack":
                chain = r.get("chain_results", [])
                parts.append(
                    f"Chain: {r.get('steps_succeeded', 0)}/{r.get('steps_executed', 0)} steps succeeded"
                )
                for step_r in chain:
                    sn = step_r.get("step", "?")
                    if "error" in step_r:
                        parts.append(f"  Step {sn}: ERROR — {step_r['error']}")
                    else:
                        parts.append(
                            f"  Step {sn}: {step_r.get('method', '?')} {step_r.get('url', '?')} "
                            f"→ {step_r.get('status_code', '?')} "
                            f"(cookies: {list(step_r.get('cookies_received', {}).keys())})"
                        )
                        body = step_r.get("body", "")
                        if body:
                            parts.append(f"    Body ({len(body)} chars):\n{body[:2000]}")

            elif atype == "fuzz_parameter":
                parts.append(r.get("summary", ""))
                anomalies = [x for x in r.get("results", []) if x.get("anomaly")]
                if anomalies:
                    parts.append("Anomalous responses:")
                    for a in anomalies:
                        line = f"  payload={a.get('payload', '?')} status={a.get('status', '?')} len={a.get('length', '?')}"
                        if a.get("reflected"):
                            line += " REFLECTED!"
                        if a.get("error"):
                            line += f" error={a['error']}"
                        parts.append(line)
                        if a.get("body_snippet"):
                            parts.append(f"    snippet: {a['body_snippet'][:300]}")
                else:
                    parts.append("No anomalies detected — all responses matched baseline.")

            elif atype == "extract_info":
                extracted = r.get("extracted", {})
                parts.append(f"Extracted from {r.get('url', '?')} (status {r.get('status_code', '?')}):")
                for key, val in extracted.items():
                    parts.append(f"  {key}: {json.dumps(val, default=str)[:2000]}")

            elif atype == "compare_responses":
                comp = r.get("comparison", {})
                ra = r.get("response_a", {})
                rb = r.get("response_b", {})
                parts.append(f"Response A: {ra.get('url', '?')} → {ra.get('status', '?')} ({ra.get('length', '?')} bytes)")
                parts.append(f"Response B: {rb.get('url', '?')} → {rb.get('status', '?')} ({rb.get('length', '?')} bytes)")
                parts.append(f"Status different: {comp.get('status_different', False)}")
                parts.append(f"Length diff: {comp.get('length_diff', 0)} bytes")
                parts.append(f"Bodies identical: {comp.get('bodies_identical', True)}")
                if comp.get("header_diffs"):
                    parts.append(f"Header diffs: {json.dumps(comp['header_diffs'])}")
                if comp.get("potential_idor"):
                    parts.append("*** POTENTIAL IDOR DETECTED — different content with same status 200 ***")
                # Show body snippets for comparison
                if ra.get("body"):
                    parts.append(f"Body A ({ra.get('length', '?')} chars):\n{ra['body'][:1500]}")
                if rb.get("body"):
                    parts.append(f"Body B ({rb.get('length', '?')} chars):\n{rb['body'][:1500]}")

            else:
                # Default formatting for http_get, http_post, test_payload, analyze_response
                parts.append(f"Status: {r.get('status_code', '?')}")
                if r.get("reflected"):
                    parts.append("PAYLOAD REFLECTED IN RESPONSE!")
                if r.get("note"):
                    parts.append(r["note"])
                if r.get("headers"):
                    interesting = {
                        k: v for k, v in r["headers"].items()
                        if k.lower() in (
                            "content-type", "set-cookie", "x-powered-by",
                            "server", "access-control-allow-origin",
                            "content-security-policy", "location",
                            "x-frame-options", "strict-transport-security",
                        )
                    }
                    if interesting:
                        parts.append(f"Interesting headers: {json.dumps(interesting)}")
                if r.get("body"):
                    body = r["body"]
                    parts.append(f"Body ({len(body)} chars):\n{body[:5000]}")

            parts.append("")

        # Append action history summary so Claude knows what was tried
        history = self._get_history_summary()
        if history:
            parts.append(history)

        parts.append(
            "What do you see? What should I try next? "
            "Or give a conclusion if you've seen enough."
        )
        return "\n".join(parts)
