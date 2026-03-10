"""
PHANTOM AI Agent — Autonomous Penetration Testing Brain

Instead of running a fixed pipeline, the agent:
1. Collects initial recon data (fixed step)
2. Enters a decision loop where AI chooses what to do next
3. After each action, AI evaluates results and adapts strategy
4. Learns from outcomes to improve future scans

The AI has access to 25+ security modules and chooses which to run,
in what order, and how deep to go — like a real pentester.
"""
import asyncio
import json
import logging
import time
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_engine import LLMEngine, LLMError
from app.core.knowledge import KnowledgeBase
from app.models.knowledge import AgentDecision
from app.models.scan import Scan, ScanLog, ScanStatus
from app.models.target import Target

logger = logging.getLogger(__name__)

# Maximum steps to prevent infinite loops
MAX_AGENT_STEPS = 30

# Available modules the agent can choose from
AVAILABLE_MODULES = {
    "recon": {
        "description": "DNS records, WHOIS, technology fingerprinting",
        "phase": "reconnaissance",
        "cost": "low",
        "prerequisites": [],
    },
    "subdomain": {
        "description": "Subdomain enumeration and takeover detection",
        "phase": "reconnaissance",
        "cost": "medium",
        "prerequisites": [],
    },
    "portscan": {
        "description": "TCP port scanning to find open services",
        "phase": "reconnaissance",
        "cost": "medium",
        "prerequisites": [],
    },
    "fingerprint": {
        "description": "Technology fingerprinting (frameworks, CMS, servers)",
        "phase": "reconnaissance",
        "cost": "low",
        "prerequisites": [],
    },
    "endpoint": {
        "description": "Endpoint discovery (crawling, JS analysis, API routes)",
        "phase": "reconnaissance",
        "cost": "medium",
        "prerequisites": [],
    },
    "vuln_scan": {
        "description": "Automated vulnerability scanning (basic checks)",
        "phase": "scanning",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "nuclei": {
        "description": "Nuclei deep scan with CVE templates",
        "phase": "scanning",
        "cost": "high",
        "prerequisites": ["endpoint"],
    },
    "sqli": {
        "description": "SQL injection testing (error-based, blind, UNION)",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "xss": {
        "description": "Cross-site scripting (reflected, stored, DOM-based)",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "ssrf": {
        "description": "Server-side request forgery (cloud metadata, internal scan)",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "xxe": {
        "description": "XML external entity injection",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["endpoint"],
    },
    "idor": {
        "description": "Insecure direct object reference / authorization bypass",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "auth_bypass": {
        "description": "JWT attacks, default credentials, verb tampering",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "csrf": {
        "description": "Cross-site request forgery detection",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["endpoint"],
    },
    "cmd_injection": {
        "description": "OS command injection testing",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "ssti": {
        "description": "Server-side template injection",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["endpoint", "fingerprint"],
    },
    "path_traversal": {
        "description": "Path traversal / local file inclusion",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["endpoint"],
    },
    "file_upload": {
        "description": "Malicious file upload testing",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "deserialization": {
        "description": "Insecure deserialization (Java, PHP, Python)",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["fingerprint"],
    },
    "prototype_pollution": {
        "description": "JavaScript prototype pollution",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["fingerprint"],
    },
    "api_security": {
        "description": "GraphQL introspection, mass assignment, data exposure",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "session_management": {
        "description": "Session fixation, weak tokens, cookie flags",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["endpoint"],
    },
    "race_condition": {
        "description": "TOCTOU / double-spend / race condition testing",
        "phase": "exploitation",
        "cost": "medium",
        "prerequisites": ["endpoint"],
    },
    "websocket": {
        "description": "WebSocket hijacking, injection, auth bypass",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["endpoint"],
    },
    "cache_poisoning": {
        "description": "Web cache deception, host header poisoning",
        "phase": "exploitation",
        "cost": "low",
        "prerequisites": ["endpoint"],
    },
    "deep_sqli": {
        "description": "Post-exploitation SQLi: UNION extraction, file read, credential dump",
        "phase": "post-exploitation",
        "cost": "high",
        "prerequisites": ["sqli"],
    },
    "waf_detect": {
        "description": "WAF detection and bypass strategy",
        "phase": "scanning",
        "cost": "low",
        "prerequisites": [],
    },
}


class AIAgent:
    """Autonomous AI Agent that drives the penetration test."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.llm = LLMEngine()
        self.knowledge = KnowledgeBase()
        self.context = {}
        self.step = 0
        self.modules_run = []
        self.vulns_found = []
        self.history = []  # (action, result_summary) pairs

    async def run(self, db: AsyncSession, scan: Scan, target: Target):
        """Main agent loop."""
        # Initialize context
        domain = target.domain
        if ":" in domain or domain.replace(".", "").isdigit() or "." not in domain:
            base_url = f"http://{domain}"
            is_internal = True
        else:
            base_url = f"https://{domain}"
            is_internal = False

        self.context = {
            "target_id": target.id,
            "domain": domain,
            "base_url": base_url,
            "is_internal": is_internal,
            "scope": target.scope,
            "scan_id": scan.id,
            "subdomains": [],
            "ports": {},
            "technologies": {},
            "endpoints": [],
            "vulnerabilities": [],
            "scan_results": [],
            "waf_info": None,
            "payloads": [],
            "evidence": [],
            "rate_limit": target.rate_limit,
        }

        scan_type = scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type)
        self.context["scan_type"] = scan_type

        # Get knowledge context for AI
        knowledge_summary = await self.knowledge.get_summary_for_agent(db, self.context)

        # Load best strategy from KB for fallback decisions
        try:
            techs = list((self.context.get("technologies") or {}).get("summary", {}).keys())
            strategy = await self.knowledge.get_best_strategy(db, techs)
            if strategy:
                self.context["_kb_strategy"] = strategy
        except Exception:
            pass

        await self._log(db, "agent", f"AI Agent starting scan on {domain}")
        await self._log(db, "agent",
            f"Experience: {knowledge_summary['experience']['total_scans_completed']} past scans, "
            f"{knowledge_summary['experience']['knowledge_patterns']} learned patterns")

        # Phase 1: Always do basic recon first
        await self._log(db, "agent", "Phase 1: Gathering reconnaissance data...")
        await self._update_progress(db, scan, "recon", 5)
        await self._run_module("recon", db)
        await self._run_module("endpoint", db)

        if not is_internal:
            await self._run_module("subdomain", db)

        await self._run_module("fingerprint", db)
        await db.commit()

        # Phase 2: AI Decision Loop
        await self._log(db, "agent", "Phase 2: AI Agent entering autonomous decision loop...")

        for step in range(MAX_AGENT_STEPS):
            self.step = step + 1

            # Check if scan was stopped
            await db.refresh(scan)
            if scan.status in (ScanStatus.STOPPED, ScanStatus.PAUSED):
                await self._log(db, "agent", "Scan stopped/paused by user")
                break

            # Ask AI what to do next
            decision = await self._get_next_action(db, knowledge_summary)

            action = decision.get("action", "stop")
            reasoning = decision.get("reasoning", "")

            await self._log(db, "agent",
                f"Step {self.step}: {action} — {reasoning}")

            # Record decision
            decision_record = AgentDecision(
                scan_id=self.scan_id,
                step=self.step,
                action=action,
                reasoning=reasoning,
                context_summary={
                    "technologies": list((self.context.get("technologies") or {}).get("summary", {}).keys()),
                    "endpoints_count": len(self.context.get("endpoints", [])),
                    "vulns_found": len(self.vulns_found),
                    "modules_run": self.modules_run.copy(),
                },
            )
            db.add(decision_record)

            if action == "stop":
                await self._log(db, "agent", f"AI decided to stop: {reasoning}", "success")
                break

            # Execute the action
            if action.startswith("run_module:"):
                module_name = action.split(":", 1)[1]
                if module_name in self.modules_run:
                    # Already done — skip and let AI pick next
                    decision_record.result_summary = {"skipped": True, "reason": "already completed"}
                    self.history.append((action, {"skipped": "already completed"}))
                    continue

                before_vulns = len(self.vulns_found)
                await self._run_module(module_name, db)
                after_vulns = len(self.vulns_found)
                new_vulns = after_vulns - before_vulns

                decision_record.result_summary = {
                    "vulns_found": new_vulns,
                    "total_vulns": after_vulns,
                }
                decision_record.was_productive = new_vulns > 0
                self.history.append((action, {"vulns_found": new_vulns}))

            elif action.startswith("deep_dive:"):
                vuln_type = action.split(":", 1)[1]
                dive_key = f"deep_dive_{vuln_type}"
                if dive_key in self.modules_run:
                    decision_record.result_summary = {"skipped": True, "reason": "already deep-dived"}
                    self.history.append((action, {"skipped": "already done"}))
                    continue

                await self._deep_dive(vuln_type, db)
                self.modules_run.append(dive_key)
                self.history.append((action, {"deep_dive": vuln_type}))

            elif action.startswith("parallel:"):
                modules = [m.strip() for m in action.split(":", 1)[1].split(",")]
                modules = [m for m in modules if m in AVAILABLE_MODULES and m not in self.modules_run]
                if not modules:
                    decision_record.result_summary = {"skipped": True, "reason": "all modules already completed"}
                    self.history.append((action, {"skipped": "all already done"}))
                    continue

                before_vulns = len(self.vulns_found)
                tasks = [self._run_module(m, db) for m in modules]
                await asyncio.gather(*tasks, return_exceptions=True)
                new_vulns = len(self.vulns_found) - before_vulns

                decision_record.result_summary = {"vulns_found": new_vulns, "modules": modules}
                decision_record.was_productive = new_vulns > 0
                self.history.append((action, {"vulns_found": new_vulns, "modules": modules}))

            # Update progress
            progress = min(90, 10 + (self.step / MAX_AGENT_STEPS) * 80)
            await self._update_progress(db, scan, "agent", progress)
            await db.commit()

        # Phase 3: Generate report
        await self._log(db, "agent", "Phase 3: Generating report...")
        await self._update_progress(db, scan, "report", 95)
        await self._run_module("report", db)

        # Phase 4: Learn from this scan
        # Mark scan completed so learn_from_scan can find it
        scan.status = ScanStatus.COMPLETED
        scan.vulns_found = len(self.vulns_found)
        try:
            await db.commit()
            await self.knowledge.learn_from_scan(db, self.scan_id)
            await self._log(db, "agent", "Learning complete — patterns saved for future scans", "success")
            await db.commit()
        except Exception as e:
            logger.error(f"Learning phase error: {e}")
            await self._log(db, "agent", f"Learning error (non-fatal): {str(e)[:100]}", "warning")
            await db.commit()
        # Reset status — pipeline.py will set it again
        scan.status = ScanStatus.RUNNING

        return self.vulns_found

    async def _get_next_action(self, db: AsyncSession, knowledge: dict) -> dict:
        """Ask AI to decide the next action."""
        # Build available and completed module lists
        completed = []
        available = []
        for name, info in AVAILABLE_MODULES.items():
            if name in self.modules_run:
                completed.append(name)
                continue
            prereqs = info.get("prerequisites", [])
            if all(p in self.modules_run for p in prereqs):
                available.append(f"  - run_module:{name} — {info['description']} (cost: {info['cost']})")

        if not available:
            return {"action": "stop", "reasoning": "All available modules have been run"}

        techs = list((self.context.get('technologies') or {}).get('summary', {}).keys())

        # Build vulns summary outside f-string to avoid brace issues
        if self.vulns_found:
            vulns_list = [
                {"title": v.get("title"), "severity": v.get("severity"), "type": v.get("vuln_type")}
                for v in self.vulns_found[:10]
            ]
            vulns_str = json.dumps(vulns_list, indent=2)
        else:
            vulns_str = "None yet"

        history_str = json.dumps(self.history[-3:], indent=2) if self.history else "None yet"
        available_str = "\n".join(available)
        stop_step = MAX_AGENT_STEPS - 3

        # Build RAG context from knowledge base
        knowledge_context = ""
        if knowledge:
            # Tech-vuln insights: what vuln types work on this tech stack
            insights = knowledge.get("tech_vuln_insights", {}).get("recommendations", [])
            if insights:
                top_insights = insights[:5]
                insight_lines = [
                    f"  - {i['vuln_type']}: {i['success_rate']:.1%} success rate ({i['sample_count']} scans)"
                    for i in top_insights
                ]
                knowledge_context += f"\nKNOWLEDGE BASE — Vuln types that work on this tech stack:\n" + "\n".join(insight_lines)

            # Past successful decisions on similar tech
            past = knowledge.get("past_successful_decisions", [])
            if past:
                past_lines = [
                    f"  - {d['action']} → found vulns (tech: {', '.join(d.get('tech_overlap', []))})"
                    for d in past[:3]
                ]
                knowledge_context += f"\n\nPAST SUCCESSFUL ACTIONS on similar targets:\n" + "\n".join(past_lines)

            # False positive patterns to avoid
            fps = knowledge.get("false_positive_patterns", [])
            if fps:
                fp_types = set(f['vuln_type'] for f in fps if f.get('vuln_type'))
                if fp_types:
                    knowledge_context += f"\n\nKNOWN FALSE POSITIVES to be cautious about: {', '.join(fp_types)}"

            # H1 insights — what bounty platforms reward
            h1_insights = knowledge.get("h1_insights", [])
            if h1_insights:
                h1_lines = []
                for h in h1_insights[:5]:
                    line = f"  - {h['vuln_type']}: {h.get('insight', h.get('recommendation', ''))}"
                    if h.get("bounty_range"):
                        line += f" (bounty: {h['bounty_range']})"
                    h1_lines.append(line)
                knowledge_context += f"\n\nH1 INSIGHTS — What bounty platforms accept/reward:\n" + "\n".join(h1_lines)

            # Experience stats
            exp = knowledge.get("experience", {})
            if exp.get("total_scans_completed", 0) > 0:
                knowledge_context += f"\n\nPHANTOM EXPERIENCE: {exp['total_scans_completed']} scans, {exp['total_vulns_found']} vulns, {exp['knowledge_patterns']} learned patterns"

        # Build prompt
        prompt = f"""You are PHANTOM, an autonomous AI penetration tester.
Target: {self.context['domain']}
Technologies: {json.dumps(techs)}
Endpoints: {len(self.context.get('endpoints', []))}
Vulns found: {len(self.vulns_found)}
Step: {self.step}/{MAX_AGENT_STEPS}
WAF: {bool((self.context.get('waf_info') or {}).get('detected'))}
{knowledge_context}

COMPLETED modules (DO NOT repeat these): {completed}

VULNS FOUND:
{vulns_str}

LAST 3 ACTIONS AND RESULTS:
{history_str}

AVAILABLE ACTIONS (only pick from these):
{available_str}
  - deep_dive:<vuln_type> — Go deeper on a CONFIRMED vuln type
  - parallel:<mod1>,<mod2> — Run 2-4 DIFFERENT uncompleted modules at once
  - stop — All important tests done

RULES:
- NEVER pick a module from COMPLETED list
- Each module in parallel: must be different and NOT in completed
- Pick the SINGLE best next action
- PHP detected → sqli, cmd_injection, ssti, path_traversal, file_upload
- Node.js → xss, prototype_pollution, ssrf, idor
- If vulns found → deep_dive to escalate
- Low cost modules first, then high cost
- Stop if step > {stop_step} or all high-priority modules done

Respond ONLY in valid JSON:
""" + '{"action": "run_module:xxx or parallel:x,y or deep_dive:xxx or stop", "reasoning": "1-2 sentences"}'

        try:
            result = await self.llm.analyze_json(prompt)
            if isinstance(result, dict) and "action" in result:
                return result
        except (LLMError, Exception) as e:
            logger.warning(f"Agent LLM decision failed: {e}")

        # Fallback: intelligent rule-based decision
        return self._fallback_decision()

    def _fallback_decision(self) -> dict:
        """Rule-based fallback when LLM is unavailable.
        Uses KB scan_strategy patterns if available, else tech-based rules."""
        techs = set(str(t).lower() for t in
                    (self.context.get("technologies") or {}).get("summary", {}).keys())
        tech_str = " ".join(techs)

        # Try KB-learned productive actions first
        kb_strategy = self.context.get("_kb_strategy")
        if kb_strategy:
            productive_actions = kb_strategy.get("productive_actions", [])
            # Extract module names from "run_module:xxx" format
            kb_modules = []
            for a in productive_actions:
                if a.startswith("run_module:"):
                    kb_modules.append(a.split(":", 1)[1])
            if kb_modules:
                for module in kb_modules:
                    if module not in self.modules_run and module in AVAILABLE_MODULES:
                        prereqs = AVAILABLE_MODULES[module].get("prerequisites", [])
                        if all(p in self.modules_run for p in prereqs):
                            return {
                                "action": f"run_module:{module}",
                                "reasoning": f"KB strategy: {module} was productive on similar tech in past scans",
                            }

        # Build priority order based on technology
        priority_modules = []

        if any(t in tech_str for t in ("php", "wordpress", "drupal", "laravel")):
            priority_modules = ["sqli", "cmd_injection", "file_upload", "ssti", "path_traversal", "xxe"]
        elif any(t in tech_str for t in ("node", "express", "react", "next", "angular")):
            priority_modules = ["xss", "prototype_pollution", "ssrf", "idor", "api_security"]
        elif any(t in tech_str for t in ("java", "spring", "tomcat")):
            priority_modules = ["deserialization", "ssti", "sqli", "ssrf", "path_traversal"]
        elif any(t in tech_str for t in ("python", "django", "flask")):
            priority_modules = ["ssti", "ssrf", "sqli", "idor", "deserialization"]
        else:
            priority_modules = ["sqli", "xss", "ssrf", "idor", "cmd_injection", "ssti"]

        # Add universal modules
        priority_modules.extend([
            "auth_bypass", "csrf", "session_management", "cache_poisoning",
            "websocket", "race_condition", "api_security", "xss",
        ])

        # Deduplicate preserving order
        seen = set()
        unique = []
        for m in priority_modules:
            if m not in seen:
                seen.add(m)
                unique.append(m)
        priority_modules = unique

        # Find next module NOT yet run
        for module in priority_modules:
            if module not in self.modules_run and module in AVAILABLE_MODULES:
                prereqs = AVAILABLE_MODULES[module].get("prerequisites", [])
                if all(p in self.modules_run for p in prereqs):
                    return {
                        "action": f"run_module:{module}",
                        "reasoning": f"Fallback: {module} is next priority for {tech_str or 'unknown'} stack",
                    }

        # Deep dive if we found vulns
        if self.vulns_found:
            vuln_types = set(v.get("vuln_type", "") for v in self.vulns_found)
            if any("sqli" in vt for vt in vuln_types if vt) and "deep_sqli" not in self.modules_run:
                return {"action": "deep_dive:sqli", "reasoning": "SQLi found, escalating to deep extraction"}

        return {"action": "stop", "reasoning": "All priority modules completed"}

    async def _run_module(self, module_name: str, db: AsyncSession):
        """Execute a specific security module."""
        try:
            if module_name == "recon":
                from app.modules.recon import ReconModule
                from app.modules.external_apis import ExternalAPIs
                recon = ReconModule()
                result = await recon.run(self.context["domain"], self.context.get("base_url"))
                external = ExternalAPIs()
                if external.shodan.available or external.securitytrails.available:
                    ip = None
                    for rec in result.get("dns_records", []):
                        if rec.get("type") == "A":
                            ip = rec.get("value")
                            break
                    enrichment = await external.enrich_recon(self.context["domain"], ip)
                    result["external_enrichment"] = enrichment
                self.context["recon_data"] = result

            elif module_name == "subdomain":
                if self.context.get("is_internal"):
                    return
                from app.modules.subdomain import SubdomainModule
                subdomain_mod = SubdomainModule()
                subdomains = await subdomain_mod.run(self.context["domain"])
                self.context["subdomains"] = subdomains
                # Subdomain takeover check
                from app.modules.subdomain_takeover import SubdomainTakeoverModule
                takeover_mod = SubdomainTakeoverModule()
                takeover_results = await takeover_mod.check(self.context)
                if takeover_results:
                    self.context.setdefault("scan_results", []).extend(takeover_results)

            elif module_name == "portscan":
                if self.context.get("is_internal"):
                    domain = self.context["domain"]
                    host = domain.split(":")[0] if ":" in domain else domain
                    port = domain.split(":")[1] if ":" in domain else "80"
                    self.context["ports"] = {host: [{"port": int(port), "state": "open", "service": "http"}]}
                    return
                from app.modules.portscan import PortScanModule
                portscan = PortScanModule()
                targets = [self.context["domain"]] + self.context["subdomains"][:10]
                self.context["ports"] = await portscan.run(targets)

            elif module_name == "fingerprint":
                from app.modules.fingerprint import FingerprintModule
                fp = FingerprintModule()
                self.context["technologies"] = await fp.run(
                    self.context["domain"], self.context["subdomains"][:10],
                    base_url=self.context.get("base_url"))

            elif module_name == "endpoint":
                from app.modules.endpoint import EndpointModule
                ep = EndpointModule()
                self.context["endpoints"] = await ep.run(
                    self.context["domain"], self.context["subdomains"][:10],
                    base_url=self.context.get("base_url"))
                if ep._auth_cookie:
                    self.context["auth_cookie"] = ep._auth_cookie

            elif module_name == "vuln_scan":
                from app.modules.scanner import VulnerabilityScanner
                scanner = VulnerabilityScanner()
                vulns = await scanner.run(self.context)
                self.context["scan_results"] = vulns

            elif module_name == "nuclei":
                from app.modules.nuclei import NucleiModule
                nuclei = NucleiModule()
                findings = await nuclei.run(self.context)
                self.context.setdefault("scan_results", []).extend(findings)

            elif module_name == "waf_detect":
                from app.modules.waf import WAFModule
                waf = WAFModule()
                self.context["waf_info"] = await waf.detect(self.context["domain"])

            elif module_name == "report":
                from app.modules.reporter import ReportGenerator
                reporter = ReportGenerator()
                for vuln in self.context.get("vulnerabilities", []):
                    vuln["target_id"] = self.context["target_id"]
                    vuln["scan_id"] = self.context["scan_id"]
                    await reporter.generate_for_vuln(vuln, db)

            else:
                # Exploitation modules — run via exploiter
                vulns = await self._run_exploit_module(module_name, db)
                self.vulns_found.extend(vulns)

            self.modules_run.append(module_name)

        except Exception as e:
            logger.error(f"Agent module {module_name} error: {e}")
            await self._log(db, "agent", f"Module {module_name} error: {str(e)[:200]}", "error")

    async def _run_exploit_module(self, module_name: str, db: AsyncSession) -> list[dict]:
        """Run a specific exploitation module and return findings."""
        from app.modules.exploiter import Exploiter
        exploiter = Exploiter()
        exploiter.rate_limit = asyncio.Semaphore(self.context.get("rate_limit") or 10)
        exploiter._base_url = self.context.get("base_url", "")
        exploiter._found_keys = set()
        if self.context.get("auth_cookie"):
            exploiter._auth_cookie = self.context["auth_cookie"]

        # Map module name to exploiter check method
        module_map = {
            "sqli": "_check_rest_api_sqli",
            "xss": "_check_reflected_xss",
            "ssrf": "_check_ssrf",
            "xxe": "_check_xxe",
            "idor": "_check_advanced_idor",
            "auth_bypass": "_check_auth_bypass",
            "csrf": "_check_csrf",
            "cmd_injection": "_check_blind_sqli",  # reuses blind injection logic
            "ssti": None,  # handled via payload testing
            "path_traversal": "_check_path_traversal",
            "file_upload": "_check_file_upload",
            "deserialization": "_check_deserialization",
            "prototype_pollution": "_check_prototype_pollution",
            "api_security": "_check_api_security",
            "session_management": "_check_session_management",
            "race_condition": "_check_race_condition",
            "websocket": "_check_websocket",
            "cache_poisoning": "_check_cache_poisoning",
        }

        method_name = module_map.get(module_name)
        if not method_name:
            # For modules without direct mapping, run payload-based testing
            return await self._run_payload_testing(module_name, exploiter, db)

        method = getattr(exploiter, method_name, None)
        if not method:
            return []

        try:
            results = await method(self.context, db)
            if isinstance(results, list):
                return results
        except Exception as e:
            logger.error(f"Exploit module {module_name} error: {e}")

        return []

    async def _run_payload_testing(self, vuln_type: str, exploiter, db) -> list[dict]:
        """Run payload-based testing for a specific vuln type."""
        from app.modules.payload_gen import PayloadGenerator
        gen = PayloadGenerator()
        self.context["ai_strategy"] = {
            "priority_vulns": [vuln_type],
            "attack_plan": [],
        }
        payloads = await gen.generate(self.context)
        # Filter to only this vuln type
        filtered = [p for p in payloads if p.get("vuln_type") == vuln_type]
        if not filtered:
            return []

        self.context["payloads"] = filtered
        results = await exploiter.run(self.context, db)
        return results

    async def _deep_dive(self, vuln_type: str, db: AsyncSession):
        """Go deeper on a confirmed vulnerability type."""
        if vuln_type in ("sqli", "sqli_blind"):
            from app.modules.deep_sqli import DeepSQLi
            deep = DeepSQLi()
            for vuln in self.vulns_found:
                if vuln.get("vuln_type") in ("sqli", "sqli_blind"):
                    url = vuln.get("url", "")
                    # Attempt deep extraction
                    try:
                        await deep.analyze(
                            url=url, param="", method="GET", db=db,
                            extra_fields=None, context=self.context,
                        )
                    except Exception:
                        pass
            self.modules_run.append("deep_sqli")

    async def _log(self, db: AsyncSession, phase: str, message: str, level: str = "info"):
        log_entry = ScanLog(
            scan_id=self.scan_id,
            phase=phase,
            level=level,
            message=message,
        )
        db.add(log_entry)
        await db.flush()

        try:
            from app.api.websocket import publish_scan_event
            await publish_scan_event(self.scan_id, {
                "type": "log",
                "phase": phase,
                "level": level,
                "message": message,
            })
        except Exception:
            pass

    async def _update_progress(self, db: AsyncSession, scan: Scan, phase: str, progress: float):
        scan.current_phase = phase
        scan.progress_percent = progress
        scan.vulns_found = len(self.vulns_found)
        scan.endpoints_found = len(self.context.get("endpoints", []))
        scan.subdomains_found = len(self.context.get("subdomains", []))
        await db.flush()

        try:
            from app.api.websocket import publish_scan_event
            await publish_scan_event(self.scan_id, {
                "type": "progress",
                "phase": phase,
                "progress": progress,
                "vulns_found": len(self.vulns_found),
                "endpoints_found": len(self.context.get("endpoints", [])),
                "subdomains_found": len(self.context.get("subdomains", [])),
            })
        except Exception:
            pass
