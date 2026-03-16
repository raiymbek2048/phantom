"""
PHANTOM Phase Optimizer — AI-driven phase ordering.

After recon phases complete (recon → subdomain → portscan → fingerprint),
this module asks Claude AI to decide the optimal order for attack phases
based on recon results, knowledge base insights, and target characteristics.
"""
import json
import logging

logger = logging.getLogger(__name__)

# Recon phases that must run first in fixed order — never reordered
FIXED_RECON_PHASES = {"recon", "subdomain", "portscan", "fingerprint"}

# Phases that must always run — cannot be skipped
CRITICAL_PHASES = {"vuln_scan", "exploit", "evidence", "report"}


class PhaseOptimizer:
    """AI-driven phase ordering — decides which phases to run and in what order
    based on recon results, knowledge base, and target characteristics."""

    async def optimize_phases(
        self,
        db,
        scan_context: dict,
        available_phases: list[str],
        llm,
    ) -> list[str]:
        """After recon+fingerprint, decide optimal phase order for attack phases.

        Args:
            db: database session
            scan_context: dict with recon results (technologies, ports, etc.)
            available_phases: list of attack phase names (post-fingerprint) that can be reordered
            llm: LLMEngine instance for Claude calls

        Returns:
            Reordered list of phase names with optional skips applied
        """
        # 1. Build scan context summary for optimization
        ctx = self._build_context_summary(scan_context)

        # 2. Get KB insights for detected technologies
        technologies = list(ctx.get("technologies", []))
        tech_insights = {}
        best_strategy = None
        try:
            from app.core.knowledge import KnowledgeBase
            kb = KnowledgeBase()
            tech_insights = await kb.get_tech_vuln_insights(db, technologies) or {}
            best_strategy = await kb.get_best_strategy(db, technologies)
        except Exception as e:
            logger.warning("PhaseOptimizer: KB query failed: %s", e)

        # 3. Build rule-based priority hints
        hints = self._rule_based_hints(ctx)

        # 4. Ask Claude to optimize (with KB context + rules)
        try:
            optimized = await self._ask_claude_to_optimize(
                llm, ctx, tech_insights, best_strategy, hints, available_phases
            )
        except Exception as e:
            logger.warning("PhaseOptimizer: Claude optimization failed: %s — using default order", e)
            return available_phases

        # 5. Validate (ensure all critical phases present, no unknown phases)
        validated = self._validate_phase_order(optimized, available_phases)

        return validated

    def _build_context_summary(self, scan_context: dict) -> dict:
        """Extract relevant fields from scan context for the optimizer."""
        techs_raw = scan_context.get("technologies") or {}
        if isinstance(techs_raw, dict):
            tech_list = list((techs_raw.get("summary") or techs_raw).keys())
        elif isinstance(techs_raw, list):
            tech_list = techs_raw
        else:
            tech_list = []

        endpoints = scan_context.get("endpoints") or []
        endpoint_urls = []
        for ep in endpoints:
            if isinstance(ep, dict):
                endpoint_urls.append(ep.get("url", ""))
            elif isinstance(ep, str):
                endpoint_urls.append(ep)

        has_login = any(
            kw in url.lower()
            for url in endpoint_urls
            for kw in ("login", "signin", "auth", "session", "oauth")
        )
        has_api = any(
            kw in url.lower()
            for url in endpoint_urls
            for kw in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")
        )
        has_upload = any(
            kw in url.lower()
            for url in endpoint_urls
            for kw in ("upload", "file", "attach", "media")
        )
        has_graphql = any(
            "graphql" in url.lower()
            for url in endpoint_urls
        )

        waf_info = scan_context.get("waf_info") or {}
        waf_detected = bool(waf_info.get("detected") or waf_info.get("waf_name"))
        waf_name = waf_info.get("waf_name") or waf_info.get("name") or "unknown"

        ports = scan_context.get("ports") or scan_context.get("open_ports") or {}
        if isinstance(ports, dict):
            port_list = list(ports.keys())
        elif isinstance(ports, list):
            port_list = ports
        else:
            port_list = []

        return {
            "technologies": tech_list,
            "subdomains": scan_context.get("subdomains") or [],
            "ports": port_list,
            "endpoints_count": len(endpoints),
            "waf_detected": waf_detected,
            "waf_name": waf_name if waf_detected else "none",
            "has_login": has_login,
            "has_api": has_api,
            "has_upload": has_upload,
            "has_graphql": has_graphql,
        }

    def _rule_based_hints(self, ctx: dict) -> list[str]:
        """Generate optimization hints based on recon data."""
        hints = []

        techs = set(t.lower() for t in (ctx.get("technologies") or []))

        # No login form → skip auth_attack
        if not ctx.get("has_login"):
            hints.append("SKIP auth_attack — no login form detected")

        # No file uploads → deprioritize file upload testing
        if not ctx.get("has_upload"):
            hints.append("DEPRIORITIZE file upload testing")

        # WAF detected → run waf phase BEFORE exploit
        if ctx.get("waf_detected"):
            hints.append(
                "PRIORITIZE waf phase before exploit — WAF detected: "
                + str(ctx.get("waf_name", "unknown"))
            )

        # API-heavy → prioritize IDOR, auth_bypass, business_logic
        if ctx.get("has_api"):
            hints.append("PRIORITIZE business_logic, auth tests — API-heavy target")

        # GraphQL → prioritize introspection + injection
        if ctx.get("has_graphql"):
            hints.append("PRIORITIZE graphql-specific attacks early")

        # WordPress/Drupal → known attack patterns
        if any(t in techs for t in ("wordpress", "wp", "drupal", "joomla")):
            hints.append("PRIORITIZE CMS-specific attacks (known plugin vulns, admin brute-force)")

        # Java/Spring → prioritize deserialization, SSTI
        if any(t in techs for t in ("java", "spring", "tomcat", "struts")):
            hints.append("PRIORITIZE deserialization and SSTI for Java stack")

        # PHP → prioritize LFI, file upload, type juggling
        if "php" in techs:
            hints.append("PRIORITIZE LFI, file upload, type juggling for PHP")

        # Node.js → prioritize SSRF, prototype pollution
        if any(t in techs for t in ("node", "nodejs", "express", "next.js", "nuxt")):
            hints.append("PRIORITIZE SSRF, prototype pollution for Node.js")

        # Many open ports → run service_attack early
        if len(ctx.get("ports", [])) > 5:
            hints.append("PRIORITIZE service_attack — many open ports detected")

        # Few endpoints → deprioritize stress_test
        if ctx.get("endpoints_count", 0) < 5:
            hints.append("DEPRIORITIZE stress_test — few endpoints found")

        # Many subdomains → prioritize sensitive_files (more surface area)
        if len(ctx.get("subdomains", [])) > 10:
            hints.append("PRIORITIZE sensitive_files — large subdomain surface area")

        return hints

    async def _ask_claude_to_optimize(
        self, llm, scan_context, tech_insights, best_strategy, hints, available_phases
    ) -> list[str]:
        """Ask Claude to return optimal phase order as JSON list."""
        tech_insights_str = json.dumps(tech_insights, indent=2, default=str)[:2000]
        strategy_str = (
            json.dumps(best_strategy, indent=2, default=str)[:1000]
            if best_strategy
            else "None — first time seeing this tech stack"
        )
        hints_str = "\n".join("- " + h for h in hints) if hints else "No specific hints"

        prompt = f"""You are PHANTOM's phase optimizer. Based on recon results, decide the optimal order to run attack phases.

## Recon Results
Technologies: {scan_context.get('technologies', [])}
Ports: {scan_context.get('ports', [])}
Subdomains: {len(scan_context.get('subdomains', []))}
WAF: {scan_context.get('waf_detected', False)} ({scan_context.get('waf_name', 'none')})
Login forms: {scan_context.get('has_login', False)}
API endpoints: {scan_context.get('has_api', False)}
File upload: {scan_context.get('has_upload', False)}
GraphQL: {scan_context.get('has_graphql', False)}
Endpoints discovered: {scan_context.get('endpoints_count', 0)}

## Knowledge Base Insights
{tech_insights_str}

## Best Known Strategy
{strategy_str}

## Rule-Based Hints
{hints_str}

## Available Phases (default order)
{json.dumps(available_phases)}

## Rules
- CRITICAL phases that MUST be included: vuln_scan, exploit, evidence, report
- evidence and report MUST be the last two phases (in that order)
- You may reorder all other phases to attack most promising vectors first
- Add "SKIP:" prefix to phases that are clearly unnecessary (e.g., "SKIP:auth_attack")
- Do NOT skip critical phases (vuln_scan, exploit, evidence, report)

Return a JSON array of phase names in optimal order. You may add "SKIP:" prefix to skip phases.
Respond with ONLY a JSON array, nothing else.
Example: ["attack_routing", "endpoint", "vuln_scan", "SKIP:auth_attack", "exploit", "evidence", "report"]"""

        result = await llm.analyze(prompt, temperature=0.2, max_tokens=1024)

        # Parse JSON from response
        parsed = llm._extract_json(result)
        if isinstance(parsed, list) and len(parsed) > 0:
            return [str(p) for p in parsed]

        # If _extract_json failed, try manual extraction
        logger.warning("PhaseOptimizer: could not parse Claude response, falling back to default")
        return available_phases

    def _validate_phase_order(self, phases: list[str], available: list[str]) -> list[str]:
        """Ensure result is valid — all critical phases present, no hallucinated phases."""
        available_set = set(available)

        # Filter out SKIP: prefixed and unknown phases
        result = []
        skipped = set()
        seen = set()

        for p in phases:
            if isinstance(p, str) and p.startswith("SKIP:"):
                name = p[5:].strip()
                if name not in CRITICAL_PHASES:
                    skipped.add(name)
                continue
            if p in available_set and p not in seen:
                result.append(p)
                seen.add(p)

        # Add back any missing phases at the end (before evidence/report)
        # Ensure evidence and report are always last in that order
        has_evidence = "evidence" in seen
        has_report = "report" in seen

        # Remove evidence/report from result — we'll re-add them at the end
        result = [p for p in result if p not in ("evidence", "report")]

        # Add missing phases (except skipped, evidence, report)
        for p in available:
            if p not in seen and p not in skipped and p not in ("evidence", "report"):
                result.append(p)

        # Always append evidence → report at the end
        if "evidence" in available_set:
            result.append("evidence")
        if "report" in available_set:
            result.append("report")

        return result
