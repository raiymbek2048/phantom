"""
AI Orchestrator — the brain of PHANTOM.

Uses local LLM for routine tasks and Claude as mentor for complex decisions.
"""
import json
import logging

from app.ai.llm_engine import LLMEngine, LLMError
from app.ai.claude_mentor import ClaudeMentor

logger = logging.getLogger(__name__)


class AIOrchestrator:
    def __init__(self):
        self.llm = LLMEngine()
        self.mentor = ClaudeMentor()

    async def analyze_and_plan(self, context: dict) -> dict:
        """Analyze scan results and create attack strategy."""
        # Inject knowledge base context
        knowledge = await self._get_knowledge_context(context)
        context["_knowledge_context"] = knowledge

        prompt = self._build_analysis_prompt(context)

        # Try local LLM first
        try:
            strategy = await self.llm.analyze_json(prompt)
            if not isinstance(strategy, dict):
                strategy = {"confidence": 0.3, "attack_plan": []}

            # If local LLM confidence is low, escalate to Claude
            if strategy.get("confidence", 0) < 0.6:
                try:
                    result = await self.mentor.analyze(prompt)
                    mentor_strategy = self.llm._extract_json(result)
                    if isinstance(mentor_strategy, dict):
                        mentor_strategy["source"] = "claude_mentor"
                        return mentor_strategy
                except Exception as e:
                    logger.debug(f"Claude mentor escalation failed: {e}")
                strategy["source"] = "local_llm_low_confidence"
            else:
                strategy["source"] = "local_llm"

            return strategy
        except LLMError as e:
            logger.debug(f"Local LLM strategy failed: {e}")

        # Fallback to Claude mentor
        try:
            result = await self.mentor.analyze(prompt)
            strategy = self.llm._extract_json(result)
            if isinstance(strategy, dict):
                strategy["source"] = "claude_mentor_fallback"
                return strategy
        except Exception as e:
            logger.debug(f"Claude mentor fallback failed: {e}")

        # Ultimate fallback — build smart strategy from collected data
        return self._build_smart_fallback(context)

    def _build_smart_fallback(self, context: dict) -> dict:
        """Build an intelligent fallback strategy from scan data + knowledge base."""
        technologies = (context.get("technologies") or {}).get("summary", {})
        endpoints = context.get("endpoints", [])
        scan_results = context.get("scan_results", [])
        knowledge = context.get("_knowledge_context", "")

        # Determine priority vulns based on detected tech
        priority_vulns = []
        tech_names = [t.lower() for t in technologies.keys()]
        tech_str = " ".join(tech_names)

        # PHP/WordPress/Drupal => SQLi, LFI, RCE priority
        if any(t in tech_str for t in ["php", "wordpress", "drupal", "laravel", "joomla"]):
            priority_vulns.extend(["sqli", "lfi", "cmd_injection", "ssti"])

        # Python/Django/Flask => SSTI, SSRF priority
        if any(t in tech_str for t in ["python", "django", "flask"]):
            priority_vulns.extend(["ssti", "ssrf", "idor"])

        # Node/React/Angular => XSS, SSRF priority
        if any(t in tech_str for t in ["node", "react", "angular", "express", "next"]):
            priority_vulns.extend(["xss", "ssrf", "idor"])

        # Java/Spring => SSTI, deserialization, SSRF
        if any(t in tech_str for t in ["java", "spring", "tomcat"]):
            priority_vulns.extend(["ssti", "ssrf", "sqli"])

        # API endpoints => IDOR, SSRF
        api_endpoints = [e for e in endpoints if e.get("type") == "api"]
        if api_endpoints:
            priority_vulns.extend(["idor", "ssrf"])

        # Always test XSS and open redirect
        priority_vulns.extend(["xss", "open_redirect"])

        # Deduplicate while preserving order
        seen = set()
        unique_vulns = []
        for v in priority_vulns:
            if v not in seen:
                seen.add(v)
                unique_vulns.append(v)

        # Build attack plan from scanner results
        attack_plan = []
        for i, vuln in enumerate(scan_results[:10]):
            attack_plan.append({
                "priority": i + 1,
                "vuln_type": vuln.get("type", "unknown"),
                "target_url": vuln.get("url", context.get("domain")),
                "technique": vuln.get("name", "automated scan finding"),
                "payload_approach": "targeted testing based on scanner detection",
                "waf_considerations": "apply WAF bypass encodings",
            })

        # Add high-interest endpoints to plan
        high_interest = [e for e in endpoints if e.get("interest") in ("high", "critical")]
        for e in high_interest[:5]:
            attack_plan.append({
                "priority": len(attack_plan) + 1,
                "vuln_type": unique_vulns[0] if unique_vulns else "xss",
                "target_url": e.get("url", ""),
                "technique": f"test {e.get('type', 'unknown')} endpoint",
                "payload_approach": "parameter fuzzing",
                "waf_considerations": "standard bypass",
            })

        return {
            "confidence": 0.5,
            "attack_plan": attack_plan,
            "priority_vulns": unique_vulns[:6],
            "high_value_targets": [e.get("url") for e in high_interest[:10]],
            "technology_specific_attacks": [f"test {t} specific vulns" for t in list(technologies.keys())[:5]],
            "recommended_tools": ["nuclei", "ffuf", "katana"],
            "estimated_difficulty": "medium",
            "source": "smart_fallback",
        }

    async def decide_next_action(self, context: dict, current_phase: str) -> dict:
        """AI decides what to do next based on current results."""
        prompt = f"""You are PHANTOM, an autonomous penetration testing AI.

Current target: {context.get('domain')}
Current phase: {current_phase}
Technologies detected: {json.dumps(context.get('technologies', {}), indent=2)[:2000]}
Endpoints found: {len(context.get('endpoints', []))}
Scan results so far: {json.dumps(context.get('scan_results', []), indent=2)[:3000]}

Based on the data collected so far, decide:
1. What vulnerability types are most likely?
2. Which endpoints should be tested first?
3. What specific payloads should be generated?
4. Should we adjust scanning intensity?

Respond ONLY in JSON:
{{
    "priority_vulns": ["vuln_type1", "vuln_type2"],
    "priority_endpoints": ["endpoint1", "endpoint2"],
    "payload_suggestions": ["description of payload approach"],
    "intensity": "low|medium|high",
    "reasoning": "brief explanation"
}}"""

        try:
            return await self.llm.analyze_json(prompt)
        except (LLMError, Exception):
            return {
                "priority_vulns": ["xss", "sqli", "ssrf", "idor"],
                "priority_endpoints": [e.get("url", "") for e in context.get("endpoints", [])[:20]],
                "payload_suggestions": ["standard payload set"],
                "intensity": "medium",
                "reasoning": "default strategy (LLM unavailable)",
            }

    async def evaluate_response(self, request_data: dict, response_data: dict, vuln_type: str) -> dict:
        """AI evaluates if a server response indicates a vulnerability."""
        prompt = f"""Analyze this HTTP response for {vuln_type} vulnerability.

Request:
URL: {request_data.get('url')}
Method: {request_data.get('method')}
Payload: {request_data.get('payload')}

Response:
Status: {response_data.get('status_code')}
Headers: {json.dumps(response_data.get('headers', {}), indent=2)[:1000]}
Body (first 2000 chars): {str(response_data.get('body', ''))[:2000]}

Is this a confirmed vulnerability? Respond ONLY in JSON:
{{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "evidence": "what indicates the vulnerability",
    "severity": "critical/high/medium/low/info",
    "false_positive_indicators": "why this might be a false positive"
}}"""

        try:
            return await self.llm.analyze_json(prompt)
        except (LLMError, Exception):
            return {"is_vulnerable": False, "confidence": 0.0, "evidence": "analysis failed"}

    async def _get_knowledge_context(self, context: dict) -> str:
        """Pull relevant knowledge from the database to enhance AI decisions."""
        try:
            from sqlalchemy import select, and_
            import app.models.database as _db
            from app.models.knowledge import KnowledgePattern

            async with _db.async_session() as db:
                # Get tech correlations for detected technologies
                techs = list((context.get("technologies") or {}).get("summary", {}).keys())
                tech_lower = [t.lower() for t in techs[:5]]

                knowledge_lines = []

                # Fetch relevant patterns for detected technologies
                if tech_lower:
                    result = await db.execute(
                        select(KnowledgePattern).where(
                            and_(
                                KnowledgePattern.technology.in_(tech_lower),
                                KnowledgePattern.confidence > 0.5,
                            )
                        ).order_by(KnowledgePattern.confidence.desc()).limit(20)
                    )
                    patterns = result.scalars().all()

                    for p in patterns:
                        data = p.pattern_data or {}
                        if p.pattern_type == "tech_vuln_correlation":
                            knowledge_lines.append(
                                f"- {p.technology} commonly has {p.vuln_type} "
                                f"(confidence: {p.confidence:.0%}, source: {data.get('source', '?')})"
                            )
                        elif p.pattern_type == "effective_payload":
                            payload = data.get("payload", "")
                            if payload:
                                knowledge_lines.append(
                                    f"- Effective {p.vuln_type} payload for {p.technology}: {payload[:100]}"
                                )
                        elif p.pattern_type == "hacktivity_technique":
                            techniques = data.get("techniques", [])
                            if techniques:
                                knowledge_lines.append(
                                    f"- Real-world {p.vuln_type} technique: {', '.join(techniques[:3])} "
                                    f"(from bug bounty reports)"
                                )

                # Get scan strategy patterns
                result = await db.execute(
                    select(KnowledgePattern).where(
                        KnowledgePattern.pattern_type == "scan_strategy"
                    ).order_by(KnowledgePattern.confidence.desc()).limit(5)
                )
                for p in result.scalars().all():
                    data = p.pattern_data or {}
                    rate = data.get("productive_rate", 0)
                    if rate > 0.5:
                        knowledge_lines.append(
                            f"- Strategy '{p.vuln_type}' has {rate:.0%} success rate "
                            f"({data.get('total_uses', 0)} uses)"
                        )

                if knowledge_lines:
                    return "\n\nKNOWLEDGE BASE (learned from past scans and training):\n" + "\n".join(knowledge_lines[:15])

        except Exception as e:
            logger.debug(f"Knowledge context fetch failed: {e}")
        return ""

    def _build_analysis_prompt(self, context: dict) -> str:
        # Try to get knowledge context (sync wrapper since this may be called sync)
        import asyncio
        knowledge = ""
        try:
            loop = asyncio.get_running_loop()
            knowledge_task = asyncio.ensure_future(self._get_knowledge_context(context))
        except RuntimeError:
            logger.debug("No running event loop for knowledge context")

        return f"""You are PHANTOM, an expert penetration testing AI. Analyze the following reconnaissance data and create a detailed attack strategy.

TARGET: {context.get('domain')}

SUBDOMAINS ({len(context.get('subdomains', []))} found):
{json.dumps(context.get('subdomains', [])[:30], indent=2)}

OPEN PORTS:
{json.dumps(context.get('ports', {}), indent=2)[:2000]}

TECHNOLOGIES:
{json.dumps(context.get('technologies', {}), indent=2)[:2000]}

ENDPOINTS ({len(context.get('endpoints', []))} found):
{json.dumps(context.get('endpoints', [])[:50], indent=2)}

SCANNER RESULTS:
{json.dumps(context.get('scan_results', []), indent=2)[:3000]}
{context.get('_knowledge_context', '')}

Create a comprehensive attack strategy. Use knowledge from past scans and training if available. Respond ONLY in JSON:
{{
    "confidence": 0.0-1.0,
    "attack_plan": [
        {{
            "priority": 1,
            "vuln_type": "type",
            "target_url": "url",
            "technique": "description",
            "payload_approach": "how to craft payload",
            "waf_considerations": "notes on WAF bypass if needed"
        }}
    ],
    "priority_vulns": ["vuln1", "vuln2"],
    "high_value_targets": ["url1", "url2"],
    "technology_specific_attacks": ["attack1", "attack2"],
    "recommended_tools": ["tool1", "tool2"],
    "estimated_difficulty": "easy/medium/hard"
}}"""
