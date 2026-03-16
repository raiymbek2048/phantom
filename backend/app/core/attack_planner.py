"""
AI Attack Planner v2 — Multi-agent reasoning loop with smart context management.

Upgrades over v1:
- Reflector: forces Claude back into tool-call format when it outputs plain text
- Execution Monitor: detects loops (repeated URLs/tools) and pivots strategy
- Context compression: summarizes large responses, compresses old conversation
- Sploitus integration: searches real CVE exploits for discovered tech stack
- Sensitive data anonymization for KB storage
- Better briefing with exploit intelligence
"""
import asyncio
import json
import logging
import re
import secrets
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode

import anthropic
import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

BODY_LIMIT = 12000

# ──────────────────────────────────────────
# Native Anthropic tool definitions
# ──────────────────────────────────────────

PLANNER_TOOLS = [
    {
        "name": "http_request",
        "description": "Send an HTTP request to the target. Use this to test endpoints, inject payloads, check responses. Supports all HTTP methods.",
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"], "description": "HTTP method"},
                "url": {"type": "string", "description": "Full URL to request"},
                "headers": {"type": "object", "description": "Optional custom headers"},
                "body": {"description": "Request body (object for JSON, string for raw)"},
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": "jwt_decode",
        "description": "Decode a JWT token without verification. Shows header (algorithm) and payload (claims).",
        "input_schema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "JWT token to decode"},
            },
            "required": ["token"],
        },
    },
    {
        "name": "jwt_forge",
        "description": "Forge a JWT with specified algorithm and payload. Use 'none' algorithm for alg:none attack.",
        "input_schema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "enum": ["none", "HS256", "HS384", "HS512"], "description": "JWT algorithm"},
                "payload": {"type": "object", "description": "JWT payload claims"},
                "secret": {"type": "string", "description": "HMAC secret (empty for none)"},
            },
            "required": ["algorithm", "payload"],
        },
    },
    {
        "name": "diff_requests",
        "description": "Compare two HTTP responses side by side. Use for IDOR testing (same endpoint, different auth) or auth bypass (with/without auth).",
        "input_schema": {
            "type": "object",
            "properties": {
                "request_a": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "headers": {"type": "object"},
                        "body": {},
                    },
                    "required": ["url"],
                },
                "request_b": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "headers": {"type": "object"},
                        "body": {},
                    },
                    "required": ["url"],
                },
            },
            "required": ["request_a", "request_b"],
        },
    },
    {
        "name": "login",
        "description": "Attempt login and store session cookies/tokens for subsequent requests. Auto-extracts JWT/session tokens.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Login endpoint URL"},
                "body": {"type": "object", "description": "Login credentials"},
                "headers": {"type": "object"},
                "extract_token": {"type": "boolean", "default": True, "description": "Auto-extract token from response"},
            },
            "required": ["url", "body"],
        },
    },
    {
        "name": "fuzz",
        "description": "Fuzz a parameter with multiple values. Tests each value and reports which ones caused different behavior.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fuzz"},
                "param": {"type": "string", "description": "Parameter name to fuzz"},
                "values": {"type": "array", "items": {"type": "string"}, "description": "Values to test"},
                "method": {"type": "string", "default": "GET"},
            },
            "required": ["url", "param", "values"],
        },
    },
    {
        "name": "extract_page",
        "description": "Extract page structure: forms, hidden inputs, scripts, links, comments, API endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to extract from"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "search_exploits",
        "description": "Search Sploitus for real CVE exploits and tools matching a technology or vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g. 'Apache 2.4.49 RCE', 'CVE-2021-44228')"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "report_vuln",
        "description": "Report a confirmed vulnerability. Only use when you have PROOF from actual HTTP responses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Vulnerability title"},
                "vuln_type": {"type": "string", "enum": [
                    "sqli", "xss", "ssrf", "idor", "auth_bypass", "rce", "ssti",
                    "lfi", "cors", "info_disclosure", "business_logic", "misconfiguration",
                    "cmd_injection", "xxe", "open_redirect", "path_traversal", "jwt",
                    "race_condition", "deserialization",
                ]},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "url": {"type": "string"},
                "parameter": {"type": "string"},
                "description": {"type": "string"},
                "impact": {"type": "string"},
                "payload": {"type": "string", "description": "The payload that proved the vulnerability"},
                "proof": {"type": "string", "description": "Explain what in the response proves exploitation"},
            },
            "required": ["title", "vuln_type", "severity", "url", "description", "proof"],
        },
    },
    {
        "name": "done",
        "description": "Signal that testing is complete. Use when you've exhausted all promising attack vectors.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Summary of what was tested and found"},
            },
            "required": ["summary"],
        },
    },
]

PLANNER_SYSTEM = """You are an elite penetration tester with 15+ years of experience. You are the BRAIN of PHANTOM — an autonomous pentesting platform.

The automated pipeline already ran and found some results. Now it's YOUR turn to think like a real hacker.

## YOUR MISSION
Find vulnerabilities that automated scanners MISS. Think creatively. Chain findings together.

## WHAT MAKES YOU DIFFERENT FROM THE SCANNER
- You can CHAIN attacks: use finding A to exploit finding B
- You can REASON about business logic, not just inject payloads
- You understand context: JWT algorithm tells you what to forge, tech stack tells you what exploits exist
- You try the NON-OBVIOUS: parameter pollution, HTTP verb tampering, race conditions, deserialization

## RULES
1. ALWAYS use tools — never just describe what you'd do
2. You can call MULTIPLE tools in ONE response
3. After seeing results, analyze them and decide next steps
4. Report ONLY vulnerabilities you PROVED with actual HTTP responses
5. Don't re-report vulnerabilities already found by the scanner
6. Stay in scope (target domain and subdomains only)
7. When stuck, try a completely different attack vector instead of repeating
8. Use search_exploits to find real CVE exploits when you identify specific tech versions

Think step by step. Call tools to test your hypotheses. Keep going until you've exhausted all promising attack paths, then use the done tool."""

# Reflector prompt — forces Claude back into tool-call format
REFLECTOR_PROMPT = "You must use the provided tools. Call http_request, fuzz, extract_page, search_exploits, or done."

# Execution monitor prompt — injected when loop is detected
MONITOR_PROMPT = """⚠️ EXECUTION MONITOR: Possible repetition detected.

Actions so far: {action_count}
Most repeated: {repeated}
Unique URLs tested: {unique_urls}

This is a nudge to diversify, NOT a stop signal. You still have budget.

SUGGESTIONS — pick a DIFFERENT endpoint or attack vector:
1. Switch to an UNTESTED endpoint from the target's endpoint list
2. Try a completely different vulnerability class:
   - XSS → IDOR / auth bypass / business logic
   - SQLi → path traversal / SSRF / SSTI
   - API testing → file upload / race condition / HTTP verb tampering
   - Parameter pollution (?param=a&param=b), mass assignment, JWT manipulation
3. Test admin/internal paths you haven't touched yet
4. If you genuinely believe all vectors are exhausted, use the done tool

Pick a new target endpoint + attack vector and go."""


class AttackPlanner:
    """Claude-driven attack planning and execution engine with smart loop detection."""

    def __init__(self):
        self.client = None
        from app.ai.get_claude_key import make_anthropic_client
        self.client = make_anthropic_client(sync=False)
        self.model = settings.claude_model
        self.conversation: list[dict] = []
        self.findings: list[dict] = []
        self.rounds = 0
        self.max_rounds = 20
        self._session_cookies: dict = {}
        self._session_token: str | None = None
        self._action_log: list[dict] = []
        # Loop detection
        self._url_counter: Counter = Counter()
        self._tool_counter: Counter = Counter()
        self._reflector_uses = 0
        self._monitor_triggers = 0
        # Context management
        self._llm = None

    async def run(self, context: dict, on_event=None) -> dict:
        """Run the AI Attack Planner loop with all smart features."""
        if not self.client:
            logger.warning("Attack Planner: no Claude API key")
            return {"findings": [], "rounds": 0, "error": "no_api_key"}

        domain = context.get("domain", "unknown")
        logger.info(f"Attack Planner v2: starting on {domain}")

        async def _emit(event: dict):
            if on_event:
                try:
                    await on_event(event)
                except Exception:
                    pass

        # Enrich briefing with exploit intelligence
        briefing = await self._build_enriched_briefing(context)
        self.conversation = [{"role": "user", "content": briefing}]

        http_client = None
        try:
            http_client = httpx.AsyncClient(
                timeout=25.0,
                follow_redirects=True,
                verify=False,
                headers=self._get_rotating_ua(),
            )

            consecutive_no_response = 0

            while self.rounds < self.max_rounds:
                self.rounds += 1
                logger.info(f"Attack Planner round {self.rounds}/{self.max_rounds} on {domain}")

                await _emit({
                    "type": "planner_thinking",
                    "round": self.rounds,
                    "message": f"Attack Planner thinking (round {self.rounds})...",
                })

                # Context compression before sending to Claude
                self._maybe_compress_context()

                message = await self._ask_claude()
                if not message:
                    consecutive_no_response += 1
                    if consecutive_no_response >= 3:
                        logger.warning("Attack Planner: 3 consecutive API failures, aborting")
                        break
                    self.conversation.append({
                        "role": "user",
                        "content": "No response received. Please use tools to continue testing or call done."
                    })
                    continue
                consecutive_no_response = 0

                # Extract tool_use blocks from native response
                tool_calls = []
                text_parts = []
                for block in message.content:
                    if block.type == "tool_use":
                        tool_calls.append(block)
                    elif block.type == "text":
                        text_parts.append(block.text)

                # If no tool calls, check for legacy ```action format in text
                if not tool_calls and text_parts:
                    full_text = "\n".join(text_parts)
                    legacy_actions = self._parse_actions(full_text)
                    if legacy_actions:
                        # Convert legacy actions to pseudo tool calls
                        tool_calls = legacy_actions
                        logger.info("Using legacy ```action parsing (fallback)")

                # If still no tool calls — reflector
                if not tool_calls and self._reflector_uses < 3:
                    self._reflector_uses += 1
                    logger.info(f"Reflector triggered ({self._reflector_uses}/3)")
                    self.conversation.append({
                        "role": "user",
                        "content": "You must use the provided tools. Call http_request, fuzz, extract_page, or done."
                    })
                    continue

                if not tool_calls:
                    break  # Exhausted reflector retries

                # Process tool calls
                should_stop = False
                tool_results = []

                for tc in tool_calls:
                    # Handle both native ToolUseBlock and legacy dict
                    if isinstance(tc, dict):
                        tool_name = tc.get("tool", "")
                        tool_input = tc
                        tool_id = f"legacy_{self.rounds}_{len(tool_results)}"
                    else:
                        tool_name = tc.name
                        tool_input = tc.input
                        tool_id = tc.id

                    # Map native tool names to executor methods
                    TOOL_MAP = {
                        "http_request": "http",
                        "jwt_decode": "jwt_decode",
                        "jwt_forge": "jwt_forge",
                        "diff_requests": "diff",
                        "login": "login",
                        "fuzz": "fuzz",
                        "extract_page": "extract",
                        "search_exploits": "search_exploits",
                        "report_vuln": "report_vuln",
                        "done": "done",
                        # Legacy names from ```action
                        "http": "http",
                        "diff": "diff",
                        "extract": "extract",
                    }
                    internal_name = TOOL_MAP.get(tool_name, tool_name)

                    if internal_name == "done":
                        summary = tool_input.get("summary", "") if isinstance(tool_input, dict) else ""
                        logger.info(f"Attack Planner done after {self.rounds} rounds: {summary}")
                        tool_results.append({
                            "tool_use_id": tool_id,
                            "content": json.dumps({"status": "done", "summary": summary}),
                        })
                        should_stop = True
                        continue

                    if internal_name == "report_vuln":
                        finding = tool_input if isinstance(tool_input, dict) else {}
                        self.findings.append(finding)
                        await _emit({"type": "planner_finding", "finding": finding})
                        tool_results.append({
                            "tool_use_id": tool_id,
                            "content": json.dumps({"status": "recorded", "title": finding.get("title", "")}),
                        })
                        continue

                    # Execute the tool
                    action = dict(tool_input) if isinstance(tool_input, dict) else {}
                    action["tool"] = internal_name
                    self._track_actions([action])

                    try:
                        results = await self._execute_actions([action], http_client, domain)
                        result = results[0] if results else {"error": "no result"}
                    except Exception as e:
                        result = {"error": str(e)}

                    self._action_log.append({"tool": internal_name, "round": self.rounds})

                    # Auto-summarize large bodies
                    result_str = json.dumps(result, default=str)
                    if len(result_str) > 8000:
                        from app.core.context_manager import summarize_large_response
                        result_str = await summarize_large_response(result_str, max_chars=6000, llm=self._llm)

                    tool_results.append({
                        "tool_use_id": tool_id,
                        "content": result_str,
                    })

                # Send tool results back to Claude
                if tool_results:
                    # Build tool_result messages
                    result_content = []
                    for tr in tool_results:
                        result_content.append({
                            "type": "tool_result",
                            "tool_use_id": tr["tool_use_id"],
                            "content": tr["content"],
                        })

                    # Add monitor warning if needed
                    monitor_msg = self._check_for_loops()
                    if monitor_msg:
                        self._monitor_triggers += 1
                        logger.info(f"Execution Monitor triggered ({self._monitor_triggers})")
                        if self._monitor_triggers >= 5:
                            logger.warning("Attack Planner: too many loop detections, stopping")
                            break
                        result_content.append({
                            "type": "text",
                            "text": monitor_msg,
                        })
                    elif len(self._action_log) > 5:
                        result_content.append({
                            "type": "text",
                            "text": f"[{len(self._action_log)} actions so far. Avoid repeating tested URLs/payloads.]",
                        })

                    self.conversation.append({
                        "role": "user",
                        "content": result_content,
                    })

                if should_stop:
                    break

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
            "reflector_uses": self._reflector_uses,
            "monitor_triggers": self._monitor_triggers,
        }

    # ──────────────────────────────────────────
    # Briefing with exploit intelligence
    # ──────────────────────────────────────────

    async def _build_enriched_briefing(self, context: dict) -> str:
        """Build briefing enriched with Sploitus exploit data and Knowledge Graph intelligence."""
        base_briefing = self._build_briefing(context)

        # Search for exploits based on detected technologies
        exploit_section = await self._gather_exploit_intelligence(context)
        if exploit_section:
            base_briefing += f"\n\n{exploit_section}"

        # Inject Knowledge Graph exploit chain intelligence
        graph_section = self._build_graph_intelligence_section(context)
        if graph_section:
            base_briefing += f"\n\n{graph_section}"

        return base_briefing

    def _build_graph_intelligence_section(self, context: dict) -> str:
        """Build exploit chain intelligence section from Knowledge Graph data."""
        graph_attack_surface = context.get("graph_attack_surface")
        graph_similar_targets = context.get("graph_similar_targets")

        if not graph_attack_surface and not graph_similar_targets:
            return ""

        lines = ["## Exploit Chain Intelligence (from Knowledge Graph)"]

        # Known attack surface for tech stack
        if graph_attack_surface:
            vulns = graph_attack_surface.get("vulnerabilities", [])
            techniques = graph_attack_surface.get("techniques", [])
            waf_bypasses = graph_attack_surface.get("waf_bypasses", [])

            if vulns:
                lines.append("\n### Known Attack Surface for Your Tech Stack")
                vuln_strs = [f"{v['vuln_type']} (weight:{v['weight']:.1f}, seen:{v['observations']}x)" for v in vulns[:8]]
                lines.append(f"Historically vulnerable to: {', '.join(vuln_strs)}")

            if techniques:
                lines.append("\n### Effective Techniques")
                for t in techniques[:8]:
                    payload_preview = t.get("payload", "")[:80]
                    lines.append(f"  - {t['technique'][:60]} → for {t['for_vuln']} (w:{t['weight']:.1f})")
                    if payload_preview:
                        lines.append(f"    payload: {payload_preview}")

            if waf_bypasses:
                lines.append("\n### WAF Bypass Intelligence")
                for wb in waf_bypasses[:5]:
                    lines.append(f"  - {wb['technique'][:60]} bypasses {wb['waf']} (w:{wb['weight']:.1f})")

        # Similar targets intelligence
        if graph_similar_targets:
            lines.append("\n### What Worked on Similar Targets")
            for st in graph_similar_targets[:5]:
                shared = ", ".join(st.get("shared_technologies", [])[:5])
                found_vulns = ", ".join(st.get("vulnerabilities_found", [])[:5])
                if found_vulns:
                    lines.append(f"  - {st['domain']} shares [{shared}] → found: {found_vulns}")

        # Suggest exploit chains based on current findings + graph knowledge
        existing_vulns = context.get("vulnerabilities", [])
        if existing_vulns and graph_attack_surface:
            found_types = set(v.get("vuln_type", "") for v in existing_vulns)
            graph_vulns = set(v["vuln_type"] for v in graph_attack_surface.get("vulnerabilities", []))
            unexplored = graph_vulns - found_types
            if unexplored:
                lines.append("\n### Suggested Exploit Chains")
                lines.append("Based on findings so far, try these escalation paths:")
                chain_suggestions = {
                    "info_disclosure": "try SSRF to internal URLs → check for Redis/Docker → RCE",
                    "ssrf": "read cloud metadata → pivot to internal services → RCE",
                    "sqli": "extract credentials → auth bypass → admin access",
                    "xss": "steal admin session → CSRF to change settings → account takeover",
                    "auth_bypass": "access admin panel → find file upload → RCE",
                    "misconfiguration": "enumerate exposed services → find debug endpoints → info leak → deeper exploit",
                    "idor": "enumerate user data → find admin IDs → privilege escalation",
                    "lfi": "read config files → extract secrets → auth bypass → RCE",
                    "ssti": "confirm template engine → code execution → RCE",
                }
                for vtype in list(unexplored)[:5]:
                    chain = chain_suggestions.get(vtype, f"investigate {vtype} attack vectors")
                    lines.append(f"  - Graph suggests {vtype} is likely → {chain}")

        result = "\n".join(lines)
        # Keep concise — cap at 2000 chars
        if len(result) > 2000:
            result = result[:1997] + "..."
        return result

    async def _gather_exploit_intelligence(self, context: dict) -> str:
        """Query Sploitus for real exploits matching the tech stack."""
        try:
            from app.core.sploitus import get_exploits_for_tech
        except ImportError:
            return ""

        technologies = context.get("technologies", {})
        if not technologies:
            return ""

        all_exploits = []
        # Extract tech+version pairs
        queries = []
        if isinstance(technologies, dict):
            for category, items in technologies.items():
                if isinstance(items, list):
                    for item in items[:3]:
                        if isinstance(item, str):
                            queries.append(item)
                        elif isinstance(item, dict):
                            name = item.get("name", item.get("product", ""))
                            version = item.get("version", "")
                            if name:
                                queries.append(f"{name} {version}".strip())
                elif isinstance(items, str):
                    queries.append(items)

        # Deduplicate and limit
        seen = set()
        unique_queries = []
        for q in queries:
            q_lower = q.lower().strip()
            if q_lower and q_lower not in seen and len(q_lower) > 2:
                seen.add(q_lower)
                unique_queries.append(q)

        # Query Sploitus (max 5 tech queries to avoid rate limits)
        for query in unique_queries[:5]:
            try:
                results = await get_exploits_for_tech(query)
                for r in results[:3]:
                    all_exploits.append(r)
            except Exception as e:
                logger.debug(f"Sploitus query failed for '{query}': {e}")

        if not all_exploits:
            return ""

        lines = ["## KNOWN EXPLOITS (from Sploitus)"]
        for ex in all_exploits[:15]:
            cve = ex.get("cve", "")
            title = ex.get("title", "")[:100]
            url = ex.get("source_url", "")
            ex_type = ex.get("type", "exploit")
            line = f"  - [{ex_type}] {title}"
            if cve:
                line += f" ({cve})"
            if url:
                line += f" → {url}"
            lines.append(line)
        lines.append("")
        lines.append("Use these as inspiration for your attack vectors. Try to exploit known CVEs!")
        return "\n".join(lines)

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
6. Use search_exploits to find real CVE exploits for identified technologies

Think step by step. Start with the most promising attack vector.
What do you want to test first?"""

    # ──────────────────────────────────────────
    # Loop detection and execution monitor
    # ──────────────────────────────────────────

    def _track_actions(self, actions: list[dict]):
        """Track action URLs and tools for loop detection."""
        for action in actions:
            tool = action.get("tool", "?")
            self._tool_counter[tool] += 1
            url = action.get("url", "")
            if url:
                # Normalize URL (strip params for comparison)
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                self._url_counter[base] += 1

    def _check_for_loops(self) -> str | None:
        """Check if the planner is stuck in a loop."""
        total_actions = sum(self._tool_counter.values())
        if total_actions < 15:
            return None

        # Check for repeated URLs (same URL hit 8+ times)
        most_common_url = self._url_counter.most_common(1)
        if most_common_url and most_common_url[0][1] >= 8:
            repeated_url = most_common_url[0][0]
            unique_urls = len(self._url_counter)
            return MONITOR_PROMPT.format(
                action_count=total_actions,
                repeated=f"{repeated_url} ({most_common_url[0][1]}x)",
                unique_urls=unique_urls,
            )

        # Check for repeated tool pattern (same tool 10+ times in a row)
        recent_tools = [a.get("tool", "?") for a in self._action_log[-10:]]
        if len(recent_tools) >= 10 and len(set(recent_tools)) == 1:
            return MONITOR_PROMPT.format(
                action_count=total_actions,
                repeated=f"tool '{recent_tools[0]}' used {len(recent_tools)}x in a row",
                unique_urls=len(self._url_counter),
            )

        return None

    # ──────────────────────────────────────────
    # Context compression
    # ──────────────────────────────────────────

    def _maybe_compress_context(self):
        """Compress conversation if it's getting too large."""
        from app.core.context_manager import compress_conversation
        total = sum(len(m.get("content", "")) for m in self.conversation)
        if total > 60000:
            self.conversation = compress_conversation(self.conversation, max_total_chars=50000)

    # ──────────────────────────────────────────
    # UA rotation
    # ──────────────────────────────────────────

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

    # ──────────────────────────────────────────
    # Claude communication
    # ──────────────────────────────────────────

    async def _ask_claude(self):
        """Send conversation to Claude with native tool_use.

        Returns the full Message object (not just text) so the caller can
        inspect tool_use blocks.
        """
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
                    tools=PLANNER_TOOLS,
                )
                # Store the full response in conversation (content blocks)
                self.conversation.append({
                    "role": "assistant",
                    "content": message.content,
                })
                return message
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

    # ──────────────────────────────────────────
    # Action parsing
    # ──────────────────────────────────────────

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

    # ──────────────────────────────────────────
    # Action execution
    # ──────────────────────────────────────────

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
                elif tool == "search_exploits":
                    coro = self._exec_search_exploits(action)
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

    # ──────────────────────────────────────────
    # Tool implementations
    # ──────────────────────────────────────────

    async def _exec_http(self, action: dict, client: httpx.AsyncClient, domain: str) -> dict:
        """Execute arbitrary HTTP request."""
        method = action.get("method", "GET").upper()
        url = action.get("url", "")
        if not url or not self._is_in_scope(url, domain):
            return {"tool": "http", "error": f"URL not in scope: {url}"}

        headers = dict(action.get("headers", {}))
        headers = self._add_auth_headers(headers)
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
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
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

            for cookie_name, cookie_value in resp.cookies.items():
                self._session_cookies[cookie_name] = cookie_value

            token = None
            if action.get("extract_token"):
                try:
                    data = resp.json()
                    for key in ("token", "access_token", "jwt", "accessToken", "auth_token", "id_token"):
                        if key in data:
                            token = data[key]
                            break
                        if isinstance(data.get("data"), dict) and key in data["data"]:
                            token = data["data"][key]
                            break
                except Exception:
                    pass

            if token:
                self._session_token = token

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
        for val in values[:30]:
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
                await asyncio.sleep(0.1)
            except Exception as e:
                results.append({"value": str(val)[:100], "error": str(e)})

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

            hidden = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
                text, re.IGNORECASE
            )

            scripts = re.findall(r'<script[^>]*src=["\']([^"\']*)["\']', text, re.IGNORECASE)
            links = re.findall(r'<a[^>]*href=["\']([^"\']*)["\']', text, re.IGNORECASE)
            in_scope_links = [l for l in links if domain in l or l.startswith("/")]
            comments = re.findall(r'<!--(.*?)-->', text, re.DOTALL)
            comments = [c.strip()[:200] for c in comments if c.strip() and len(c.strip()) > 5]
            metas = re.findall(r'<meta[^>]*>', text, re.IGNORECASE)
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

    async def _exec_search_exploits(self, action: dict) -> dict:
        """Search Sploitus for real CVE exploits."""
        query = action.get("query", "")
        if not query:
            return {"tool": "search_exploits", "error": "No query provided"}

        try:
            from app.core.sploitus import search_exploits
            results = await search_exploits(query, max_results=10)
            return {
                "tool": "search_exploits",
                "query": query,
                "count": len(results),
                "exploits": results,
            }
        except Exception as e:
            return {"tool": "search_exploits", "error": str(e)}

    # ──────────────────────────────────────────
    # Smart result formatting with auto-summarization
    # ──────────────────────────────────────────

    async def _format_results_smart(self, results: list[dict]) -> str:
        """Format results with auto-summarization for large responses."""
        from app.core.context_manager import summarize_large_response

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

                headers = result.get("headers", {})
                sec_headers = {k: v for k, v in headers.items() if k.lower() in (
                    "server", "x-powered-by", "content-type", "set-cookie",
                    "access-control-allow-origin", "content-security-policy",
                    "x-frame-options", "authorization", "www-authenticate",
                )}
                if sec_headers:
                    parts.append(f"Security headers: {json.dumps(sec_headers, default=str)}")

                body = result.get("body", "")
                # Auto-summarize large bodies
                if len(body) > 6000:
                    body = await summarize_large_response(body, max_chars=3000, llm=self._llm)
                    parts.append(f"Body (summarized):\n```\n{body}\n```")
                elif len(body) > 3000:
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

            elif tool == "search_exploits":
                parts.append(f"Query: {result.get('query')}")
                parts.append(f"Found: {result.get('count', 0)} exploits")
                for ex in result.get("exploits", [])[:10]:
                    cve = ex.get("cve", "")
                    title = ex.get("title", "")[:100]
                    url = ex.get("source_url", "")
                    line = f"  - {title}"
                    if cve:
                        line += f" ({cve})"
                    if url:
                        line += f" → {url}"
                    parts.append(line)

            parts.append("")

        return "\n".join(parts)
