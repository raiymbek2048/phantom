"""
PHANTOM Scan Pipeline

The core engine that orchestrates the full penetration testing pipeline.
Each phase runs sequentially, with AI making decisions between phases.
"""
import asyncio
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.models.database as _db
from app.models.scan import Scan, ScanLog, ScanStatus
from app.models.target import Target
from app.modules.recon import ReconModule
from app.modules.subdomain import SubdomainModule
from app.modules.portscan import PortScanModule
from app.modules.fingerprint import FingerprintModule
from app.modules.endpoint import EndpointModule
from app.modules.scanner import VulnerabilityScanner
from app.modules.payload_gen import PayloadGenerator
from app.modules.waf import WAFModule
from app.modules.exploiter import Exploiter
from app.modules.evidence import EvidenceCollector
from app.modules.reporter import ReportGenerator
from app.core.orchestrator import AIOrchestrator
from app.modules.external_apis import ExternalAPIs
from app.modules.nuclei import NucleiModule
from app.modules.service_attack import ServiceAttackModule
from app.modules.sensitive_files import SensitiveFilesModule
from app.modules.auth_attack import AuthAttackModule
from app.modules.stress_test import StressTestModule
from app.core.attack_router import AttackRouter
from app.core.realtime_learner import RealtimeLearner
from app.core.cross_scan_intel import CrossScanIntel
from app.modules.api_discovery import run_api_discovery
from app.modules.security_analyzer import run_security_analysis
from app.modules.vuln_confirmer import VulnConfirmer

# Phase definitions with progress percentages
PHASES = [
    ("recon", "Reconnaissance", 5),
    ("subdomain", "Subdomain Discovery", 12),
    ("portscan", "Port Scanning", 20),
    ("fingerprint", "Technology Fingerprinting", 25),
    ("attack_routing", "Adaptive Attack Routing", 28),
    ("endpoint", "Endpoint Discovery", 35),
    ("sensitive_files", "Sensitive File Discovery", 40),
    ("vuln_scan", "Vulnerability Scanning", 48),
    ("nuclei", "Nuclei Deep Scan", 55),
    ("ai_analysis", "AI Analysis & Strategy", 60),
    ("payload_gen", "Payload Generation", 63),
    ("waf", "WAF Detection & Bypass", 67),
    ("exploit", "Exploitation", 72),
    ("service_attack", "Service & Port Attack", 78),
    ("auth_attack", "Auth Brute Force", 83),
    ("stress_test", "Resilience Testing", 86),
    ("vuln_confirm", "Vulnerability Confirmation", 90),
    ("claude_collab", "Claude Deep Analysis", 93),
    ("evidence", "Evidence Collection", 97),
    ("report", "Report Generation", 100),
]


class ScanPipeline:
    def __init__(self, scan_id: str, celery_task=None):
        self.scan_id = scan_id
        self.celery_task = celery_task
        self.context = {}  # Shared data between phases
        self._idor_seen: set = set()  # Dedup proven IDOR findings
        self.realtime_learner = RealtimeLearner()
        self.cross_scan_intel = CrossScanIntel()

    async def log(self, db: AsyncSession, phase: str, message: str, level: str = "info", data: dict = None):
        log_entry = ScanLog(
            scan_id=self.scan_id,
            phase=phase,
            level=level,
            message=message,
            data=data,
        )
        db.add(log_entry)
        await db.flush()

        # Broadcast log via Redis pub/sub
        await self._publish({
            "type": "log",
            "phase": phase,
            "level": level,
            "message": message,
        })

    async def update_progress(self, db: AsyncSession, scan: Scan, phase: str, progress: float):
        scan.current_phase = phase
        scan.progress_percent = progress
        await db.flush()

        await self._publish({
            "type": "progress",
            "phase": phase,
            "progress": progress,
            "vulns_found": scan.vulns_found,
            "endpoints_found": scan.endpoints_found,
            "subdomains_found": scan.subdomains_found,
        })

    async def _publish(self, event: dict):
        """Publish event to Redis for WebSocket forwarding."""
        try:
            from app.api.websocket import publish_scan_event
            await publish_scan_event(self.scan_id, event)
        except Exception:
            pass

    async def _filter_false_positives(self, findings: list[dict], db: AsyncSession, phase: str) -> list[dict]:
        """Filter out findings that match known false-positive patterns from the KnowledgeBase.

        Compares each finding against stored FP indicators by vuln_type, URL path,
        title, and payload similarity. Returns only findings that don't match FP patterns.
        """
        if not findings:
            return findings

        try:
            from app.core.knowledge import KnowledgeBase
            kb = KnowledgeBase()
            fp_patterns = await kb.get_false_positive_patterns(db)
        except Exception as e:
            # If knowledge base is unavailable, pass all findings through
            await self.log(db, phase, f"FP filter: could not load patterns: {e}", "warning")
            return findings

        if not fp_patterns:
            return findings

        # Build lookup: vuln_type → list of indicator strings
        from collections import defaultdict
        fp_by_type: dict[str | None, list[str]] = defaultdict(list)
        for pat in fp_patterns:
            vt = pat.get("vuln_type")
            indicator = pat.get("indicator", "")
            if indicator:
                fp_by_type[vt].append(indicator)

        kept = []
        filtered_count = 0

        for finding in findings:
            f_vtype = finding.get("vuln_type", "")
            f_url = finding.get("url", "")
            f_title = finding.get("title", "")
            f_payload = finding.get("payload") or finding.get("payload_used", "")

            # Extract URL path for comparison
            f_path = ""
            if f_url:
                from urllib.parse import urlparse
                try:
                    f_path = urlparse(f_url).path or "/"
                except Exception:
                    pass

            is_fp = False
            # Check indicators for this vuln_type + global (None type) patterns
            candidate_indicators = fp_by_type.get(f_vtype, []) + fp_by_type.get(None, [])

            for indicator in candidate_indicators:
                # Match by indicator type prefix
                if indicator.startswith("url_path:") and f_path:
                    if indicator[9:] == f_path:
                        is_fp = True
                        break
                elif indicator.startswith("title:") and f_title:
                    if indicator[6:] == f_title:
                        is_fp = True
                        break
                elif indicator.startswith("payload:") and f_payload:
                    if indicator[8:] == f_payload:
                        is_fp = True
                        break
                elif indicator.startswith("reason:"):
                    # Reason-based indicators: check if any part matches title or URL
                    reason_text = indicator[7:].lower()
                    if reason_text in f_title.lower() or reason_text in f_url.lower():
                        is_fp = True
                        break
                elif not indicator.startswith(("url_path:", "title:", "payload:", "reason:")):
                    # Legacy/plain indicators — substring match against title and URL
                    if indicator.lower() in f_title.lower() or indicator.lower() in f_url.lower():
                        is_fp = True
                        break

            if is_fp:
                filtered_count += 1
            else:
                kept.append(finding)

        if filtered_count:
            await self.log(db, phase,
                f"FP intelligence: filtered {filtered_count} likely false positives, kept {len(kept)} findings")

        return kept

    async def run(self):
        async with _db.async_session() as db:
            # Load scan and target
            result = await db.execute(select(Scan).where(Scan.id == self.scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            result = await db.execute(select(Target).where(Target.id == scan.target_id))
            target = result.scalar_one_or_none()
            if not target:
                return

            # Start scan
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()

            # Determine base URL for the target
            domain = target.domain
            # Internal if: IP address, host:port, or bare hostname (no dots = Docker/local)
            if ":" in domain or domain.replace(".", "").isdigit() or "." not in domain:
                base_url = f"http://{domain}"
                is_internal = True
            else:
                # Auto-detect HTTP vs HTTPS
                is_internal = False
                try:
                    import httpx
                    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as _probe:
                        try:
                            r = await _probe.head(f"https://{domain}")
                            base_url = f"https://{domain}"
                        except Exception:
                            base_url = f"http://{domain}"
                except Exception:
                    base_url = f"https://{domain}"

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
                "waf_info": None,
                "payloads": [],
                "evidence": [],
                "rate_limit": target.rate_limit,
            }

            # Apply scan config overrides
            config = scan.config or {}
            self.context["custom_headers"] = config.get("custom_headers", {})
            self.context["bounty_rules"] = config.get("bounty_rules", {})
            self.context["proxy_url"] = config.get("proxy_url", "")
            if config.get("rate_limit"):
                self.context["rate_limit"] = config["rate_limit"]

            # Configure shared HTTP client for this scan
            from app.utils.http_client import configure as configure_http
            configure_http(
                custom_headers=self.context.get("custom_headers", {}),
                proxy_url=self.context.get("proxy_url", ""),
                timeout=config.get("timeout", 10.0),
            )

            # Determine phases based on scan type
            scan_type = scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type)
            self.context["scan_type"] = scan_type

            try:
                # AI Agent mode — autonomous decision-making
                if scan_type.lower() == "ai":
                    from app.core.agent import AIAgent
                    await self.log(db, "start", f"Starting AI Agent scan on {target.domain}")
                    await db.commit()

                    agent = AIAgent(self.scan_id)
                    vulns = await agent.run(db, scan, target)

                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.subdomains_found = len(agent.context.get("subdomains", []))
                    scan.endpoints_found = len(agent.context.get("endpoints", []))
                    scan.vulns_found = len(vulns)
                    await self.log(db, "complete",
                        f"AI Agent scan completed. Found {scan.vulns_found} vulnerabilities "
                        f"in {agent.step} steps.", "success")
                    await self._publish({
                        "type": "complete",
                        "vulns_found": scan.vulns_found,
                        "endpoints_found": scan.endpoints_found,
                        "subdomains_found": scan.subdomains_found,
                    })
                    await db.commit()

                else:
                    # Classic pipeline mode
                    phases = self._get_phases_for_type(scan_type)
                    await self.log(db, "start", f"Starting {scan_type} scan on {target.domain} ({len(phases)} phases)")
                    await db.commit()

                    # --- Cross-Scan Intelligence: enrich context before phases ---
                    try:
                        await self.cross_scan_intel.enrich_context(self.context, db)
                        intel = self.context.get("cross_scan_intel", {})
                        preds = intel.get("predictions", [])
                        xpayloads = intel.get("cross_scan_payloads_added", 0)
                        if preds:
                            top = preds[0]
                            await self.log(db, "intel",
                                f"Cross-scan intel: {'+'.join(top.get('technologies', [])[:3])} targets have "
                                f"{top['probability']*100:.0f}% {top['vuln_type']} rate, "
                                f"added {xpayloads} cross-scan payloads")
                        elif xpayloads:
                            await self.log(db, "intel",
                                f"Cross-scan intel: added {xpayloads} payloads from similar targets")
                        await db.commit()
                    except Exception as e:
                        await self.log(db, "intel", f"Cross-scan intel skipped: {e}", "warning")
                        await db.commit()

                    for phase_name, progress, phase_func in phases:
                        await self._run_phase(db, scan, phase_name, progress, phase_func)

                    # --- Multi-Round Scanning ---
                    total_rounds = config.get("rounds", 1)
                    is_continuous = config.get("continuous", False)

                    if total_rounds > 1 or is_continuous:
                        await self._run_additional_rounds(
                            db, scan, target, total_rounds, is_continuous
                        )

                    # Complete
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.subdomains_found = len(self.context.get("subdomains", []))
                    scan.endpoints_found = len(self.context.get("endpoints", []))
                    scan.vulns_found = len(self.context.get("vulnerabilities", []))
                    await self.log(db, "complete", f"Scan completed. Found {scan.vulns_found} vulnerabilities.", "success")
                    await self._publish({
                        "type": "complete",
                        "vulns_found": scan.vulns_found,
                        "endpoints_found": scan.endpoints_found,
                        "subdomains_found": scan.subdomains_found,
                    })
                    await db.commit()

                    # Send scan completion notification
                    try:
                        from app.core.notifications import notify_scan_complete
                        notify_scan_complete(scan, target, scan.vulns_found or 0)
                    except Exception:
                        pass

                    # Notify for critical/high vulns found
                    await self._notify_critical_vulns(db, target)

                    # Learn from classic scans too
                    try:
                        from app.core.knowledge import KnowledgeBase
                        kb = KnowledgeBase()
                        await kb.learn_from_scan(db, self.scan_id)
                    except Exception:
                        pass

            except Exception as e:
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.utcnow()
                await self.log(db, "error", f"Scan failed: {str(e)}", "error")
                await db.commit()
                raise

    # --- Multi-Round Attack Strategies ---
    ROUND_STRATEGIES = [
        {
            "name": "Deep IDOR & Access Control",
            "context_flags": {"round_focus": "idor", "try_idor_patterns": True, "test_auth_bypass": True},
            "phases": ["endpoint", "vuln_scan", "exploit", "vuln_confirm", "auth_attack", "ai_analysis"],
        },
        {
            "name": "Injection & RCE Hunting",
            "context_flags": {"round_focus": "injection", "aggressive_payloads": True, "test_ssti": True, "test_nosql": True},
            "phases": ["vuln_scan", "nuclei", "payload_gen", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "Infrastructure & Exposure",
            "context_flags": {"round_focus": "infrastructure", "scan_actuator": True, "scan_swagger": True, "scan_debug": True},
            "phases": ["endpoint", "sensitive_files", "vuln_scan", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "Business Logic & API Abuse",
            "context_flags": {"round_focus": "business_logic", "test_race_conditions": True, "test_mass_assignment": True},
            "phases": ["endpoint", "vuln_scan", "exploit", "vuln_confirm", "service_attack", "ai_analysis"],
        },
        {
            "name": "Auth & JWT Deep Dive",
            "context_flags": {"round_focus": "auth_jwt", "brute_jwt": True, "test_alg_none": True, "test_password_reset": True},
            "phases": ["auth_attack", "vuln_scan", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "WAF Bypass & Evasion",
            "context_flags": {"round_focus": "waf_bypass", "aggressive_waf_bypass": True, "encoding_tricks": True},
            "phases": ["waf", "payload_gen", "exploit", "vuln_confirm", "vuln_scan", "ai_analysis"],
        },
        {
            "name": "Full Re-Scan with New Intel",
            "context_flags": {"round_focus": "rescan", "use_previous_findings": True},
            "phases": ["endpoint", "sensitive_files", "vuln_scan", "nuclei", "payload_gen", "exploit", "vuln_confirm", "service_attack", "auth_attack"],
        },
        {
            "name": "Stress & Edge Cases",
            "context_flags": {"round_focus": "edge_cases", "test_unicode": True, "test_large_payloads": True},
            "phases": ["stress_test", "vuln_scan", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "AI Creative Attack",
            "context_flags": {"round_focus": "creative", "ai_creative_mode": True},
            "phases": ["ai_analysis", "payload_gen", "exploit", "vuln_confirm", "claude_collab"],
        },
    ]

    async def _run_additional_rounds(self, db, scan, target, total_rounds: int, is_continuous: bool):
        """Run additional attack rounds. In continuous mode — truly infinite until user stops.

        Each round:
        1. Ask Claude AI: "what should we try next?" based on all previous attempts
        2. Claude picks strategy, mutates approach, suggests new paths
        3. Run the attack phases Claude recommends
        4. Learn from results, feed back into next round
        5. Sleep briefly between rounds to not hammer target
        Only stops when: user clicks Stop, or (non-continuous) max rounds reached.
        """
        import random

        phase_map = {
            "endpoint": self._phase_endpoint,
            "sensitive_files": self._phase_sensitive_files,
            "vuln_scan": self._phase_vuln_scan,
            "nuclei": self._phase_nuclei,
            "ai_analysis": self._phase_ai_analysis,
            "payload_gen": self._phase_payload_gen,
            "waf": self._phase_waf,
            "exploit": self._phase_exploit,
            "service_attack": self._phase_service_attack,
            "auth_attack": self._phase_auth_attack,
            "stress_test": self._phase_stress_test,
            "claude_collab": self._phase_claude_collab,
            "vuln_confirm": self._phase_vuln_confirm,
        }

        # For continuous mode: no cap. For multi-round: respect the limit.
        if is_continuous:
            max_rounds = 999999  # effectively infinite
        else:
            max_rounds = total_rounds

        vulns_after_round1 = len(self.context.get("vulnerabilities", []))
        round_history = []  # Track what we tried and what happened
        round_num = 1  # Will start from 2

        for round_num in range(2, max_rounds + 1):
            # === CHECK IF USER STOPPED ===
            await db.refresh(scan)
            if scan.status in (ScanStatus.STOPPED, ScanStatus.PAUSED):
                await self.log(db, "multi_round",
                    f"Scan stopped by user at round {round_num}.", "warning")
                await db.commit()
                break

            # === ASK AI: WHAT SHOULD WE TRY NEXT? ===
            ai_strategy = await self._ai_plan_next_round(
                db, scan, target, round_num, round_history
            )

            strategy_name = ai_strategy.get("strategy_name", f"Round {round_num}")
            strategy_phases = ai_strategy.get("phases", ["vuln_scan", "exploit", "ai_analysis"])
            strategy_flags = ai_strategy.get("context_flags", {})
            ai_reasoning = ai_strategy.get("reasoning", "")

            await self.log(db, "multi_round",
                f"=== Round {round_num}: {strategy_name} ===",
                "info")
            if ai_reasoning:
                await self.log(db, "multi_round",
                    f"AI reasoning: {ai_reasoning[:500]}", "info")
            await self._publish({
                "type": "round",
                "round": round_num,
                "total_rounds": "∞" if is_continuous else max_rounds,
                "strategy": strategy_name,
            })
            await db.commit()

            # === APPLY STRATEGY ===
            self.context["current_round"] = round_num
            self.context["round_strategy"] = strategy_name
            for key, val in strategy_flags.items():
                self.context[key] = val

            # Inject AI-suggested custom payloads/paths (normalize to dicts)
            base_url = self.context.get("base_url", "")
            if ai_strategy.get("custom_payloads"):
                normalized_payloads = []
                for p in ai_strategy["custom_payloads"]:
                    if isinstance(p, str):
                        normalized_payloads.append({
                            "payload": p,
                            "target_url": base_url,
                            "vuln_type": "generic",
                            "method": "GET",
                            "source": "ai_round",
                        })
                    elif isinstance(p, dict):
                        p.setdefault("payload", "")
                        p.setdefault("target_url", base_url)
                        p.setdefault("vuln_type", "generic")
                        p.setdefault("method", "GET")
                        p.setdefault("source", "ai_round")
                        normalized_payloads.append(p)
                existing = self.context.get("payloads", [])
                self.context["payloads"] = existing + normalized_payloads
            if ai_strategy.get("custom_endpoints"):
                normalized_eps = []
                for ep in ai_strategy["custom_endpoints"]:
                    if isinstance(ep, str):
                        url = ep if ep.startswith("http") else base_url.rstrip("/") + "/" + ep.lstrip("/")
                        normalized_eps.append({
                            "url": url,
                            "type": "general",
                            "method": "GET",
                        })
                    elif isinstance(ep, dict):
                        ep.setdefault("url", base_url)
                        ep.setdefault("type", "general")
                        ep.setdefault("method", "GET")
                        normalized_eps.append(ep)
                existing = self.context.get("endpoints", [])
                existing_urls = {e["url"] if isinstance(e, dict) else e for e in existing}
                new_eps = [ep for ep in normalized_eps if ep["url"] not in existing_urls]
                self.context["endpoints"] = existing + new_eps
                if new_eps:
                    await self.log(db, "multi_round",
                        f"AI suggested {len(new_eps)} new endpoints to test", "info")

            vulns_before_round = len(self.context.get("vulnerabilities", []))

            # === RUN PHASES ===
            for i, phase_name in enumerate(strategy_phases):
                # Check stop again mid-round
                if i % 3 == 0 and i > 0:
                    await db.refresh(scan)
                    if scan.status in (ScanStatus.STOPPED, ScanStatus.PAUSED):
                        break

                phase_func = phase_map.get(phase_name)
                if not phase_func:
                    continue
                await self._run_phase(db, scan, f"R{round_num}:{phase_name}", 100, phase_func)

            # === RESULTS ===
            vulns_after_round = len(self.context.get("vulnerabilities", []))
            new_this_round = vulns_after_round - vulns_before_round

            round_record = {
                "round": round_num,
                "strategy": strategy_name,
                "new_findings": new_this_round,
                "total_findings": vulns_after_round,
                "phases_run": strategy_phases,
            }
            round_history.append(round_record)

            await self.log(db, "multi_round",
                f"Round {round_num} done: +{new_this_round} new findings "
                f"(total: {vulns_after_round})",
                "success" if new_this_round > 0 else "info")

            # Update scan stats live
            scan.vulns_found = vulns_after_round
            await db.commit()

            # === CLEAN UP ROUND FLAGS ===
            for key in strategy_flags:
                self.context.pop(key, None)

            # === BREATHE — don't hammer the target ===
            # Longer pause if no findings (back off), shorter if productive
            if is_continuous:
                pause = 5 if new_this_round > 0 else 15
                await self.log(db, "multi_round",
                    f"Pausing {pause}s before next round...", "info")
                await db.commit()
                await asyncio.sleep(pause)

        # === FINAL WRAP-UP ===
        total_new = len(self.context.get("vulnerabilities", [])) - vulns_after_round1
        await self.log(db, "multi_round",
            f"Multi-round complete after {round_num} rounds. "
            f"+{total_new} new findings beyond round 1. "
            f"Total: {len(self.context.get('vulnerabilities', []))}",
            "success")
        await db.commit()

        # Re-run evidence and report to capture everything
        await self._run_phase(db, scan, "evidence_final", 98, self._phase_evidence)
        await self._run_phase(db, scan, "report_final", 99, self._phase_report)

    async def _ai_plan_next_round(self, db, scan, target, round_num: int, round_history: list) -> dict:
        """Ask Claude AI to plan the next attack round based on everything tried so far.

        Returns dict with: strategy_name, phases, context_flags, reasoning,
        custom_payloads, custom_endpoints
        """
        from app.ai.llm_engine import LLMEngine
        import random

        # Build history summary for AI
        history_text = ""
        if round_history:
            history_text = "PREVIOUS ROUNDS:\n"
            for rh in round_history[-10:]:  # Last 10 rounds
                history_text += (
                    f"  Round {rh['round']}: {rh['strategy']} → "
                    f"+{rh['new_findings']} findings, phases: {', '.join(rh['phases_run'])}\n"
                )

        # Gather what we know about the target
        endpoints = self.context.get("endpoints", [])
        techs = self.context.get("technologies", {})
        vulns = self.context.get("vulnerabilities", [])
        waf = self.context.get("waf_info")
        ports = self.context.get("ports", {})

        prompt = f"""You are an elite penetration tester doing round {round_num} of a continuous deep scan.
Target: {target.domain}
Technologies: {json.dumps(techs, default=str)[:500]}
Open ports: {json.dumps(ports, default=str)[:300]}
WAF: {waf or 'Unknown'}
Endpoints found: {len(endpoints)} (sample: {json.dumps(endpoints[:15], default=str)[:500]})
Vulnerabilities found so far: {len(vulns)}
{history_text}

Your job: plan the NEXT attack round. You must try something DIFFERENT from previous rounds.
Think like a creative pentester who refuses to give up. Consider:
- Unusual parameter names, hidden API versions (/v1/, /v2/, /internal/)
- Trying different HTTP methods (PUT, PATCH, DELETE, OPTIONS) on known endpoints
- Path traversal with encoding: ..%2f, ..%252f, %00
- Adding auth headers: X-Forwarded-For: 127.0.0.1, X-Original-URL
- Testing backup/dev endpoints: /api-dev/, /api-test/, /old/, /backup/
- GraphQL introspection if /graphql exists
- WebSocket endpoints
- CORS origin reflection with credentials
- Cache poisoning via Host header
- HTTP request smuggling
- Parameter pollution (duplicate params)
- JSON content type confusion (send XML to JSON endpoints)

{'IMPORTANT: Previous rounds found NOTHING new. You MUST change approach drastically. Try completely different techniques, paths, encodings, methods.' if round_history and all(r['new_findings'] == 0 for r in round_history[-3:]) else ''}

Respond in JSON:
{{
  "strategy_name": "<creative name for this round>",
  "reasoning": "<why this approach, what you expect to find>",
  "phases": ["<list of phases to run from: endpoint, sensitive_files, vuln_scan, nuclei, ai_analysis, payload_gen, waf, exploit, vuln_confirm, service_attack, auth_attack, stress_test, claude_collab>"],
  "context_flags": {{"<key>": <value>, ...}},
  "custom_endpoints": ["<new paths to test that scanner might have missed>"],
  "custom_payloads": ["<specific payloads to try>"]
}}"""

        llm = LLMEngine()
        try:
            result = await llm.analyze_json(prompt, temperature=0.7 + min(round_num * 0.02, 0.25))
            # Validate phases
            valid_phases = set(["endpoint", "sensitive_files", "vuln_scan", "nuclei",
                               "ai_analysis", "payload_gen", "waf", "exploit", "vuln_confirm",
                               "service_attack", "auth_attack", "stress_test", "claude_collab"])
            result["phases"] = [p for p in result.get("phases", []) if p in valid_phases]
            if not result["phases"]:
                result["phases"] = ["vuln_scan", "exploit", "ai_analysis"]
            return result
        except Exception as e:
            await self.log(db, "multi_round",
                f"AI planning failed ({e}), using fallback strategy", "warning")
            await db.commit()
            # Fallback: cycle through predefined strategies with mutations
            strategy = self.ROUND_STRATEGIES[(round_num - 2) % len(self.ROUND_STRATEGIES)]
            # Mutate: randomly shuffle phases, add claude_collab
            phases = list(strategy["phases"])
            random.shuffle(phases)
            if "claude_collab" not in phases:
                phases.append("claude_collab")
            return {
                "strategy_name": f"{strategy['name']} (mutated)",
                "reasoning": "AI unavailable, using mutated predefined strategy",
                "phases": phases,
                "context_flags": strategy["context_flags"],
                "custom_endpoints": [],
                "custom_payloads": [],
            }
        finally:
            await llm.close()

    def _get_phases_for_type(self, scan_type: str) -> list[tuple]:
        """Return list of (phase_name, progress%, phase_func) for the scan type."""
        all_phases = [
            ("recon", 5, self._phase_recon),
            ("subdomain", 12, self._phase_subdomain),
            ("portscan", 20, self._phase_portscan),
            ("fingerprint", 25, self._phase_fingerprint),
            ("attack_routing", 28, self._phase_attack_routing),
            ("endpoint", 35, self._phase_endpoint),
            ("sensitive_files", 40, self._phase_sensitive_files),
            ("vuln_scan", 48, self._phase_vuln_scan),
            ("nuclei", 55, self._phase_nuclei),
            ("ai_analysis", 60, self._phase_ai_analysis),
            ("payload_gen", 63, self._phase_payload_gen),
            ("waf", 67, self._phase_waf),
            ("exploit", 72, self._phase_exploit),
            ("service_attack", 78, self._phase_service_attack),
            ("auth_attack", 83, self._phase_auth_attack),
            ("stress_test", 86, self._phase_stress_test),
            ("vuln_confirm", 90, self._phase_vuln_confirm),
            ("claude_collab", 93, self._phase_claude_collab),
            ("evidence", 97, self._phase_evidence),
            ("report", 100, self._phase_report),
        ]

        if scan_type == "quick":
            # Skip heavy phases for quick scan
            skip = {"subdomain", "portscan", "fingerprint", "nuclei", "waf",
                    "evidence", "service_attack", "auth_attack", "stress_test"}
            phases = [(n, p, f) for n, p, f in all_phases if n not in skip]
            # Recalculate progress evenly
            for i, (n, _, f) in enumerate(phases):
                phases[i] = (n, int((i + 1) / len(phases) * 100), f)
            return phases
        elif scan_type == "stealth":
            # All phases but with stealth context flag
            self.context["stealth"] = True
            return all_phases
        elif scan_type == "recon":
            return [
                ("recon", 25, self._phase_recon),
                ("subdomain", 50, self._phase_subdomain),
                ("portscan", 75, self._phase_portscan),
                ("fingerprint", 100, self._phase_fingerprint),
            ]
        elif scan_type == "bounty":
            # Bug bounty: all phases, with bounty-specific filtering
            self.context["bounty_mode"] = True
            return all_phases
        else:
            return all_phases

    async def _run_phase(self, db, scan, phase_name, progress, phase_func):
        # Check if scan was stopped/paused
        await db.refresh(scan)
        if scan.status in (ScanStatus.STOPPED, ScanStatus.PAUSED):
            return

        await self.update_progress(db, scan, phase_name, progress)
        await self.log(db, phase_name, f"Starting phase: {phase_name}")
        await db.commit()

        try:
            await phase_func(db)
            await self.log(db, phase_name, f"Phase {phase_name} completed", "success")
            await db.commit()
        except Exception as e:
            await self.log(db, phase_name, f"Phase {phase_name} error: {str(e)}", "error")
            await db.commit()
            # Don't fail entire scan on single phase failure
            # AI will adapt strategy

    async def _phase_recon(self, db: AsyncSession):
        recon = ReconModule()
        result = await recon.run(self.context["domain"], self.context.get("base_url"), context=self.context)

        # Enrich with external APIs (Shodan, SecurityTrails)
        external = ExternalAPIs()
        if external.shodan.available or external.securitytrails.available:
            ip = None
            for rec in result.get("dns_records", []):
                if rec.get("type") == "A":
                    ip = rec.get("value")
                    break
            enrichment = await external.enrich_recon(self.context["domain"], ip)
            result["external_enrichment"] = enrichment
            if enrichment.get("sources"):
                await self.log(db, "recon", f"External APIs enriched: {', '.join(enrichment['sources'])}")

        self.context["recon_data"] = result

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.recon_data = result

        dns_count = len(result.get("dns_records", []))
        await self.log(db, "recon", f"Recon complete: {dns_count} DNS records found")

    async def _phase_subdomain(self, db: AsyncSession):
        if self.context.get("is_internal"):
            await self.log(db, "subdomain", "Skipped — internal target")
            return

        subdomain_mod = SubdomainModule()
        subdomains = await subdomain_mod.run(self.context["domain"])

        # Merge SecurityTrails subdomains if available
        enrichment = self.context.get("recon_data", {}).get("external_enrichment", {})
        st_subs = enrichment.get("securitytrails_subdomains", [])
        if st_subs:
            existing = set(subdomains)
            added = 0
            for s in st_subs:
                if s not in existing:
                    subdomains.append(s)
                    existing.add(s)
                    added += 1
            if added:
                await self.log(db, "subdomain", f"SecurityTrails added {added} new subdomains")

        self.context["subdomains"] = subdomains

        # Check for subdomain takeover
        from app.modules.subdomain_takeover import SubdomainTakeoverModule
        takeover_mod = SubdomainTakeoverModule()
        takeover_results = await takeover_mod.check(self.context)
        if takeover_results:
            self.context.setdefault("scan_results", []).extend(takeover_results)
            await self.log(db, "subdomain", f"Found {len(takeover_results)} potential subdomain takeovers", "warning")

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.subdomains = subdomains

        await self.log(db, "subdomain", f"Found {len(subdomains)} subdomains")

    async def _phase_portscan(self, db: AsyncSession):
        if self.context.get("is_internal"):
            # For internal targets, just note the known port
            domain = self.context["domain"]
            host = domain.split(":")[0] if ":" in domain else domain
            port = domain.split(":")[1] if ":" in domain else "80"
            self.context["ports"] = {host: [{"port": int(port), "state": "open", "service": "http"}]}
            await self.log(db, "portscan", f"Internal target — port {port} assumed open")
            return

        portscan = PortScanModule()
        targets = [self.context["domain"]] + self.context["subdomains"][:10]

        # Use scan_type from config if available
        config = self.context.get("config") or {}
        port_scan_type = config.get("port_scan_type", "quick")
        scan_results = await portscan.run(targets, scan_type=port_scan_type)

        # Extract ports list from new format (backward compatible)
        ports = {}
        risky_services = []
        for host, data in scan_results.items():
            if isinstance(data, dict):
                ports[host] = data.get("ports", [])
                risky_services.extend(data.get("risky_services", []))
            else:
                ports[host] = data  # old format: list of port dicts

        self.context["ports"] = ports
        self.context["risky_services"] = risky_services

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.ports = ports

        total_open = sum(len(v) if isinstance(v, list) else 0 for v in ports.values())
        await self.log(db, "portscan", f"Found {total_open} open ports across {len(ports)} hosts")
        if risky_services:
            risky_names = [f"{r['service']}:{r['port']}" for r in risky_services[:5]]
            await self.log(db, "portscan", f"Risky services: {', '.join(risky_names)}", level="warning")

    async def _phase_fingerprint(self, db: AsyncSession):
        fingerprint = FingerprintModule()
        base_url = self.context.get("base_url")
        technologies = await fingerprint.run(
            self.context["domain"], self.context["subdomains"][:10], base_url=base_url
        )
        self.context["technologies"] = technologies

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.technologies = technologies

        tech_summary = technologies.get("summary", {})
        await self.log(db, "fingerprint", f"Detected technologies: {list(tech_summary.keys())[:10]}")

    async def _phase_attack_routing(self, db: AsyncSession):
        """Analyze discoveries so far and build an adaptive attack plan."""
        router = AttackRouter()
        plan = router.analyze(self.context)
        if plan:
            # Log top-priority actions
            top_actions = [f"{a['action']} (P{a['priority']})" for a in plan[:5]]
            await self.log(db, "attack_routing",
                f"Attack plan: {len(plan)} actions — top: {', '.join(top_actions)}")

            # If rate limiting was detected, reduce concurrency for remaining phases
            from app.core.attack_router import get_throttle_params
            throttle = get_throttle_params(self.context)
            if throttle:
                new_limit = throttle.get("max_rps", 2)
                self.context["rate_limit"] = min(self.context.get("rate_limit") or 10, new_limit)
                await self.log(db, "attack_routing",
                    f"Rate limiting detected — throttling to {new_limit} req/s", "warning")

            # Publish plan summary via WebSocket
            await self._publish({
                "type": "attack_plan",
                "actions_count": len(plan),
                "top_actions": plan[:5],
            })
        else:
            await self.log(db, "attack_routing", "No specific attack vectors identified — using default strategy")

    async def _phase_endpoint(self, db: AsyncSession):
        endpoint_mod = EndpointModule()
        base_url = self.context.get("base_url")
        endpoints = await endpoint_mod.run(
            self.context["domain"], self.context["subdomains"][:10], base_url=base_url, context=self.context
        )
        self.context["endpoints"] = endpoints
        if endpoint_mod._auth_cookie:
            self.context["auth_cookie"] = endpoint_mod._auth_cookie
            await self.log(db, "endpoint", f"Auto-login successful, got session cookie")
        await self.log(db, "endpoint", f"Discovered {len(endpoints)} endpoints")

        # --- JavaScript endpoint extraction ---
        try:
            from app.modules.js_analyzer import JSAnalyzer
            js_analyzer = JSAnalyzer()
            js_result = await js_analyzer.extract_from_js_files(
                base_url or f"https://{self.context['domain']}",
                endpoints,
                context=self.context,
            )

            # Merge JS endpoints into context
            seen_urls = {ep.get("url", "") for ep in endpoints}
            js_added = 0
            for js_ep in js_result.get("js_endpoints", []):
                # Build full URL if relative
                if js_ep.startswith("/"):
                    full_url = (base_url or f"https://{self.context['domain']}") + js_ep
                else:
                    full_url = js_ep
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    endpoints.append(endpoint_mod._classify_endpoint(full_url))
                    js_added += 1

            # Merge SPA routes
            for route in js_result.get("spa_routes", []):
                full_url = (base_url or f"https://{self.context['domain']}") + route
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    ep = endpoint_mod._classify_endpoint(full_url)
                    ep["discovery"] = "js_spa"
                    endpoints.append(ep)
                    js_added += 1

            self.context["endpoints"] = endpoints

            # Store WebSocket endpoints in context
            ws_endpoints = js_result.get("websocket_endpoints", [])
            if ws_endpoints:
                self.context["websocket_endpoints"] = ws_endpoints

            # Report API keys as findings (save as Vulnerability DB records)
            api_keys = js_result.get("api_keys_found", [])
            if api_keys:
                from app.models.vulnerability import Vulnerability, Severity, VulnType
                for key_info in api_keys:
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f"Exposed {key_info['type']} in JavaScript ({key_info['file']})"[:500],
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        severity=Severity.MEDIUM if key_info["type"] in ("aws_key", "private_key") else Severity.LOW,
                        url=(base_url or f"https://{self.context['domain']}")[:2000],
                        description=(
                            f"A potential {key_info['type']} was found in client-side JavaScript file "
                            f"'{key_info['file']}'. Prefix: {key_info['key_prefix']}. "
                            f"Client-side secrets can be extracted by anyone viewing the page source."
                        ),
                        impact="Leaked credentials or API keys in client-side code can lead to unauthorized access.",
                        remediation="Move secrets to server-side configuration. Use environment variables or a secrets manager.",
                    )
                    db.add(vuln)
                await db.flush()

            # Report source maps as findings
            source_maps = js_result.get("source_maps", [])
            accessible_maps = [sm for sm in source_maps if sm.get("accessible")]
            if accessible_maps:
                from app.models.vulnerability import Vulnerability, Severity, VulnType
                for smap in accessible_maps:
                    orig_count = len(smap.get("original_files", []))
                    orig_files_str = ', '.join(smap.get('original_files', [])[:10])
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f"Source map exposed: {smap['js_file']}"[:500],
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        severity=Severity.LOW,
                        url=smap["url"][:2000],
                        description=(
                            f"JavaScript source map '{smap['url']}' is publicly accessible, "
                            f"exposing {orig_count} original source files. "
                            f"This reveals internal code structure and may contain sensitive logic. "
                            f"Original files: {orig_files_str}"
                        ),
                        impact="Source maps expose original unminified source code, revealing internal application logic, comments, and potentially sensitive information.",
                        remediation="Remove source map files from production or restrict access via server configuration.",
                    )
                    db.add(vuln)
                await db.flush()

            await self.log(
                db, "endpoint",
                f"JS analysis: found {js_added} additional endpoints, "
                f"{len(api_keys)} API keys, {len(source_maps)} source maps"
            )
        except Exception as e:
            await self.log(db, "endpoint", f"JS analysis error (non-fatal): {e}")

        # --- API Discovery (GraphQL introspection, OpenAPI/Swagger, WADL/WSDL) ---
        try:
            api_base = base_url or f"https://{self.context['domain']}"
            api_disc = await run_api_discovery(api_base, self.context["endpoints"], self.context)

            # Merge discovered endpoints
            seen_urls = {ep.get("url", "") for ep in self.context["endpoints"]}
            api_added = 0
            for new_ep in api_disc.get("new_endpoints", []):
                ep_url = new_ep.get("url", "")
                ep_key = ep_url + ":" + new_ep.get("graphql_operation", "")
                if ep_key not in seen_urls:
                    seen_urls.add(ep_key)
                    self.context["endpoints"].append(new_ep)
                    api_added += 1

            # Save findings as Vulnerability DB records
            from app.models.vulnerability import Vulnerability, Severity as SevEnum, VulnType
            severity_map = {"critical": SevEnum.CRITICAL, "high": SevEnum.HIGH, "medium": SevEnum.MEDIUM, "low": SevEnum.LOW, "info": SevEnum.INFO}
            vuln_type_map = {"misconfiguration": VulnType.MISCONFIGURATION, "info_disclosure": VulnType.INFO_DISCLOSURE}
            for finding in api_disc.get("findings", []):
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=finding["title"][:500],
                    vuln_type=vuln_type_map.get(finding.get("vuln_type"), VulnType.MISCONFIGURATION),
                    severity=severity_map.get(finding.get("severity", "low"), SevEnum.LOW),
                    url=(finding.get("endpoint") or api_base)[:2000],
                    description=finding.get("description", ""),
                    evidence=finding.get("evidence", ""),
                    remediation=finding.get("remediation", ""),
                )
                db.add(vuln)
            if api_disc.get("findings"):
                await db.flush()

            # Store GraphQL schema in context for AI analysis
            if api_disc.get("graphql_schema"):
                self.context["graphql_schema"] = api_disc["graphql_schema"]

            # Store OpenAPI info in context
            if api_disc.get("openapi", {}).get("spec_url"):
                self.context["openapi_spec"] = api_disc["openapi"]

            # Log results
            gql = api_disc.get("graphql", {})
            oapi = api_disc.get("openapi", {})
            wadl = api_disc.get("wadl_wsdl", {})
            parts = []
            if gql.get("introspection_enabled"):
                parts.append(
                    f"GraphQL at {gql['endpoint']} ({len(gql.get('queries', []))} queries, "
                    f"{len(gql.get('mutations', []))} mutations)"
                )
            if oapi.get("spec_url"):
                parts.append(f"OpenAPI {oapi.get('version', '?')} at {oapi['spec_url']} ({oapi.get('endpoints_count', 0)} endpoints)")
            if wadl.get("found"):
                parts.append(f"{wadl.get('type', 'service').upper()} at {wadl['url']}")

            if parts:
                await self.log(db, "endpoint", f"API discovery: {'; '.join(parts)}")
            else:
                await self.log(db, "endpoint", "API discovery: no GraphQL/OpenAPI/WADL specs found")

            if api_added > 0:
                await self.log(db, "endpoint", f"API discovery added {api_added} new endpoints")
            await self.log(db, "endpoint",
                f"API discovery: {len(api_disc.get('findings', []))} security findings")

        except Exception as e:
            await self.log(db, "endpoint", f"API discovery error (non-fatal): {e}")

        # Re-run attack router with endpoint data to refine the plan
        router = AttackRouter()
        plan = router.analyze(self.context)
        new_actions = [a for a in plan if a.get("category") in ("auth", "api")]
        if new_actions:
            names = [f"{a['action']}" for a in new_actions[:3]]
            await self.log(db, "endpoint",
                f"Attack plan updated: +{len(new_actions)} actions from endpoints ({', '.join(names)})")

        # --- ID Harvesting ---
        try:
            from app.modules.id_harvester import IDHarvester
            from app.utils.http_client import make_client
            harvester = IDHarvester()
            harvester.harvest_from_endpoints(endpoints)

            # Also harvest from initial endpoint responses
            base_url = self.context.get("base_url")
            async with make_client() as client:
                for ep in endpoints[:50]:  # Sample up to 50 endpoints
                    try:
                        url = ep.get("url", "") if isinstance(ep, dict) else ep
                        if not url:
                            continue
                        resp = await client.get(url)
                        harvester.harvest_from_response(url, resp.text, resp.status_code)
                    except Exception:
                        continue

            self.context["id_harvester"] = harvester
            self.context["harvested_ids"] = harvester.to_dict()
            await self.log(db, "endpoint", f"ID harvesting: {harvester.summary()}")
        except Exception as e:
            await self.log(db, "endpoint", f"ID harvesting error (non-fatal): {e}")

    async def _phase_vuln_scan(self, db: AsyncSession):
        scanner = VulnerabilityScanner()
        vulns = await scanner.run(self.context)
        self.context["scan_results"] = vulns
        await self.log(db, "vuln_scan", f"Scanner found {len(vulns)} potential vulnerabilities")

        # --- Deep Security Header Analysis (CSP, CORS, Cookies, Headers) ---
        try:
            base_url = self.context.get("base_url", f"https://{self.context['domain']}")
            endpoints = self.context.get("endpoints", [])
            sec_findings = await run_security_analysis(base_url, endpoints, self.context)

            if sec_findings:
                from app.models.vulnerability import Vulnerability, Severity as SevEnum, VulnType
                severity_map = {
                    "critical": SevEnum.CRITICAL, "high": SevEnum.HIGH,
                    "medium": SevEnum.MEDIUM, "low": SevEnum.LOW, "info": SevEnum.INFO,
                }
                vt_map = {v.value: v for v in VulnType}
                saved = 0
                for f in sec_findings:
                    sev = severity_map.get(f.get("severity", "info"), SevEnum.INFO)
                    vt = vt_map.get(f.get("vuln_type", "misconfiguration"), VulnType.MISCONFIGURATION)
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f["title"][:500],
                        vuln_type=vt,
                        severity=sev,
                        url=(f.get("url") or base_url)[:2000],
                        description=f.get("impact", ""),
                        payload_used=f.get("payload", ""),
                        remediation=f.get("remediation", ""),
                        ai_analysis=f.get("csp_grade", ""),
                    )
                    db.add(vuln)
                    saved += 1
                await db.flush()

                csp_grade = self.context.get("csp_analysis", {}).get("grade", "N/A")
                cors_count = self.context.get("cors_analysis", {}).get("findings_count", 0)
                await self.log(
                    db, "vuln_scan",
                    f"Security analysis: {saved} findings (CSP grade: {csp_grade}, CORS issues: {cors_count})",
                )
        except Exception as e:
            await self.log(db, "vuln_scan", f"Security header analysis error (non-fatal): {e}", "warning")

    async def _phase_ai_analysis(self, db: AsyncSession):
        orchestrator = AIOrchestrator()
        strategy = await orchestrator.analyze_and_plan(self.context)
        self.context["ai_strategy"] = strategy
        await self.log(db, "ai_analysis", f"AI planned {len(strategy.get('attack_plan', []))} attack vectors")

    async def _phase_payload_gen(self, db: AsyncSession):
        generator = PayloadGenerator()
        payloads = await generator.generate(self.context, db=db)

        # Inject knowledge-driven payloads from the knowledge base
        kb_payloads = await self._get_knowledge_payloads(db)
        if kb_payloads:
            payloads.extend(kb_payloads)
            await self.log(db, "payload_gen", f"Injected {len(kb_payloads)} knowledge-driven payloads")

        self.context["payloads"] = payloads
        await self.log(db, "payload_gen", f"Generated {len(payloads)} total payloads")

        # --- OOB Detection: inject blind-vuln callback payloads ---
        try:
            from app.modules.oob_server import inject_oob_payloads
            oob_count = await inject_oob_payloads(self.context, db)
            if oob_count:
                await self.log(db, "payload_gen",
                    f"OOB: injected {oob_count} out-of-band callback payloads for blind vuln detection")
        except Exception as e:
            await self.log(db, "payload_gen", f"OOB injection skipped: {e}", "warning")

    async def _phase_waf(self, db: AsyncSession):
        waf_mod = WAFModule()
        waf_mod._base_url = self.context.get("base_url", f"https://{self.context['domain']}")
        waf_info = await waf_mod.detect(self.context["domain"])
        self.context["waf_info"] = waf_info

        if waf_info.get("detected"):
            waf_name = waf_info.get("waf_name", "unknown")
            await self.log(db, "waf", f"WAF detected: {waf_name}", "warning")
            # Adapt payloads for WAF bypass
            adapted = await waf_mod.adapt_payloads(self.context["payloads"], waf_info)

            # --- WAF Intelligence: query known effective bypasses ---
            from app.core.waf_intelligence import WAFIntelligence
            waf_intel = WAFIntelligence()
            intel_count = 0
            try:
                # Get WAF profile for logging
                waf_profile = await waf_intel.get_waf_profile(waf_name, db)
                if waf_profile.get("total_attempts", 0) > 0:
                    bypass_rate = waf_profile.get("overall_bypass_rate", 0)
                    await self.log(db, "waf",
                        f"WAF Intelligence: {waf_profile['total_attempts']} past attempts, "
                        f"{bypass_rate:.0%} bypass rate, "
                        f"{len(waf_profile.get('bypass_techniques', []))} known techniques")

                # Collect vuln types from current payloads
                vuln_types = set()
                for p in self.context["payloads"]:
                    vt = p.get("vuln_type", p.get("type", ""))
                    if vt:
                        vuln_types.add(vt)
                if not vuln_types:
                    vuln_types = {"xss", "sqli", "generic"}

                # Query known bypasses per vuln type
                for vt in vuln_types:
                    effective = await waf_intel.get_effective_bypasses(waf_name, vt, db)
                    for payload_str in effective:
                        adapted.append({
                            "payload": payload_str,
                            "vuln_type": vt,
                            "type": vt,
                            "source": "waf_intelligence",
                            "waf_bypass": True,
                        })
                        intel_count += 1

                # Generate mutations for blocked payloads from past experience
                blocked = [
                    bp for bp in waf_profile.get("blocked_patterns", [])
                    if bp.get("success_rate", 0) < 0.1
                ]
                for bp in blocked[:10]:
                    mutations = waf_intel.generate_mutations(
                        waf_name, bp.get("payload", ""), bp.get("vuln_type", "")
                    )
                    for m in mutations[:3]:
                        adapted.append({
                            "payload": m,
                            "vuln_type": bp.get("vuln_type", "generic"),
                            "type": bp.get("vuln_type", "generic"),
                            "source": "waf_intelligence_mutation",
                            "waf_bypass": True,
                        })
                        intel_count += 1
            except Exception as e:
                await self.log(db, "waf", f"WAF Intelligence query error: {e}", "warning")

            # Also inject legacy knowledge-driven WAF bypass patterns
            from app.models.knowledge import KnowledgePattern
            kb_result = await db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "waf_bypass",
                    KnowledgePattern.confidence >= 0.4,
                ).order_by(KnowledgePattern.confidence.desc()).limit(50)
            )
            kb_bypasses = kb_result.scalars().all()
            kb_count = 0
            for bp in kb_bypasses:
                data = bp.pattern_data or {}
                # Match WAF name if specified
                bp_waf = data.get("waf", "").lower()
                if bp_waf and bp_waf not in waf_name.lower():
                    continue
                bypass_payloads = data.get("payloads", [])
                if isinstance(bypass_payloads, list):
                    for pl in bypass_payloads[:5]:
                        adapted.append({
                            "payload": pl if isinstance(pl, str) else str(pl),
                            "type": bp.vuln_type or "generic",
                            "source": "knowledge_waf_bypass",
                        })
                        kb_count += 1

            self.context["payloads"] = adapted
            await self.log(db, "waf",
                f"Adapted {len(adapted)} payloads for WAF bypass "
                f"(+{intel_count} from WAF Intelligence, +{kb_count} from knowledge)")
        else:
            await self.log(db, "waf", "No WAF detected")

    async def _phase_nuclei(self, db: AsyncSession):
        nuclei_mod = NucleiModule()
        findings = await nuclei_mod.run(self.context)
        # Merge nuclei findings into scan_results so AI/exploit phases can use them
        existing = self.context.get("scan_results", [])
        existing.extend(findings)
        self.context["scan_results"] = existing
        await self.log(db, "nuclei", f"Nuclei found {len(findings)} additional findings")

    async def _phase_exploit(self, db: AsyncSession):
        exploiter = Exploiter()
        results = await exploiter.run(self.context, db)

        # --- File Upload Exploitation ---
        try:
            from app.modules.upload_exploit import UploadExploit
            upload_exploiter = UploadExploit()
            endpoints = self.context.get("endpoints", [])
            upload_findings = await upload_exploiter.test_all(endpoints, self.context)
            if upload_findings:
                upload_vulns = await exploiter._save_module_findings(
                    upload_findings, self.context, db,
                )
                results.extend(upload_vulns)
                await self.log(
                    db, "exploit",
                    f"File upload exploit: {len(upload_vulns)} findings "
                    f"({sum(1 for f in upload_findings if f.get('execution_confirmed'))} RCE confirmed)",
                )
                await db.flush()
        except Exception as e:
            await self.log(db, "exploit", f"File upload exploit error: {e}", "warning")

        # --- Smart IDOR Testing ---
        try:
            from app.modules.idor_engine import IDOREngine
            idor_engine = IDOREngine(rate_limit=exploiter.rate_limit)
            endpoints = self.context.get("endpoints", [])
            # Pass harvested IDs from endpoint phase if available
            if self.context.get("harvested_ids"):
                idor_engine.harvested_ids = self.context["harvested_ids"]
            idor_findings = await idor_engine.test_all(endpoints, self.context)
            if idor_findings:
                # Save proven IDOR findings directly as Vulnerability records
                # (bypass LLM evaluation which incorrectly rejects brute-force-proven findings)
                from app.models.vulnerability import Vulnerability, Severity as SevEnum, VulnType
                severity_map = {"critical": SevEnum.CRITICAL, "high": SevEnum.HIGH, "medium": SevEnum.MEDIUM, "low": SevEnum.LOW, "info": SevEnum.INFO}
                idor_saved = 0
                idor_types = {}
                for f in idor_findings:
                    proof = f.get("proof", {})
                    if not proof.get("proven") and not f.get("proven"):
                        continue  # Skip unproven findings
                    # Deduplicate
                    dedup_key = f"{f.get('url', '')}|{f.get('param', '')}|{f.get('idor_type', '')}"
                    if dedup_key in self._idor_seen:
                        continue
                    self._idor_seen.add(dedup_key)

                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f.get("title", "IDOR vulnerability")[:500],
                        vuln_type=VulnType.AUTH_BYPASS,
                        severity=severity_map.get(f.get("severity", "high"), SevEnum.HIGH),
                        url=f.get("url", "")[:2000],
                        parameter=f.get("param"),
                        method=f.get("method", "GET"),
                        description=f.get("description", f.get("evidence", "")),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", "Implement proper authorization checks."),
                        payload_used=f.get("payload", f.get("tampered_value")),
                        request_data=proof.get("request"),
                        response_data=proof.get("response"),
                        ai_confidence=0.9,  # Proven by brute-force
                    )
                    db.add(vuln)
                    idor_saved += 1
                    t = f.get("idor_type", "unknown")
                    idor_types[t] = idor_types.get(t, 0) + 1

                if idor_saved > 0:
                    await db.flush()
                await self.log(
                    db, "exploit",
                    f"Smart IDOR: {idor_saved} proven findings ({idor_types})",
                )
        except Exception as e:
            await self.log(db, "exploit", f"Smart IDOR error: {e}", "warning")

        # Filter out known false positives before saving
        results = await self._filter_false_positives(results, db, "exploit")

        # --- WAF Intelligence: learn from exploit results ---
        waf_info = self.context.get("waf_info") or {}
        if waf_info.get("detected"):
            waf_name = waf_info.get("waf_name", "unknown")
            try:
                from app.core.waf_intelligence import WAFIntelligence
                waf_intel = WAFIntelligence()
                recorded = 0

                # Record successful bypasses from confirmed vulnerabilities
                for vuln in results:
                    payload = vuln.get("payload_used") or vuln.get("payload", "")
                    vt = vuln.get("vuln_type", "unknown")
                    if payload:
                        await waf_intel.record_bypass(
                            waf_name=waf_name,
                            payload=payload,
                            vuln_type=vt,
                            success=True,
                            response_code=200,
                            db=db,
                        )
                        recorded += 1

                # Record failed attempts (payloads that were tried but didn't find vulns)
                # We track waf_bypass payloads that were NOT in results
                successful_payloads = set()
                for vuln in results:
                    p = vuln.get("payload_used") or vuln.get("payload", "")
                    if p:
                        successful_payloads.add(p)

                for p_data in self.context.get("payloads", []):
                    if not p_data.get("waf_bypass"):
                        continue
                    payload = p_data.get("payload", "")
                    if payload and payload not in successful_payloads:
                        vt = p_data.get("vuln_type", p_data.get("type", "generic"))
                        await waf_intel.record_bypass(
                            waf_name=waf_name,
                            payload=payload,
                            vuln_type=vt,
                            success=False,
                            response_code=403,
                            db=db,
                        )
                        recorded += 1

                if recorded:
                    await self.log(db, "exploit",
                        f"WAF Intelligence: recorded {recorded} bypass attempts for {waf_name}")
                    await db.flush()
            except Exception as e:
                await self.log(db, "exploit", f"WAF Intelligence recording error: {e}", "warning")

        # Apply bounty filter if in bounty mode
        if self.context.get("bounty_mode") and self.context.get("bounty_rules"):
            from app.core.bounty_filter import get_bounty_filter
            bf = get_bounty_filter(self.context["bounty_rules"])
            in_scope, out_of_scope = bf.filter_findings(results)
            if out_of_scope:
                await self.log(db, "exploit",
                    f"Bounty filter: removed {len(out_of_scope)} OOS findings, kept {len(in_scope)}")
            results = in_scope

        self.context["vulnerabilities"] = results
        await self.log(db, "exploit", f"Confirmed {len(results)} vulnerabilities", "success")

        # --- Real-time Learning: learn from each confirmed vuln ---
        if results:
            total_mutations = 0
            try:
                for vuln_data in results:
                    mutations = await self.realtime_learner.on_vuln_confirmed(
                        vuln_data, self.context, db,
                    )
                    total_mutations += len(mutations)
                if total_mutations:
                    await self.log(db, "exploit",
                        f"Real-time learner: generated {total_mutations} mutations from "
                        f"{len(results)} confirmed vulns")
                await db.flush()
            except Exception as e:
                await self.log(db, "exploit",
                    f"Real-time learning error: {e}", "warning")

        # --- Real-time Strategy Adaptation ---
        try:
            adjustments = await self.realtime_learner.adapt_strategy(self.context, db)
            notes = adjustments.get("notes", [])
            if notes:
                for note in notes:
                    await self.log(db, "exploit", f"Strategy: {note}")
            await db.flush()
        except Exception as e:
            await self.log(db, "exploit",
                f"Strategy adaptation error: {e}", "warning")

        # --- Multi-Step Attack Chain Engine ---
        if self.context.get("vulnerabilities"):
            try:
                from app.modules.attack_chain import AttackChainModule, select_chains
                from app.models.vulnerability import Vulnerability, Severity, VulnType

                chain_mod = AttackChainModule()
                chain_results = await chain_mod.run_chains(self.context)

                if chain_results:
                    self.context["attack_chains"] = chain_results

                    # Save verified chain results as additional Vulnerability records
                    scan_result = await db.execute(
                        select(Scan).where(Scan.id == self.context["scan_id"])
                    )
                    scan_obj = scan_result.scalar_one_or_none()
                    sev_map = {
                        "critical": Severity.CRITICAL, "high": Severity.HIGH,
                        "medium": Severity.MEDIUM, "low": Severity.LOW,
                    }

                    chains_saved = 0
                    saved_chain_names = set()  # Deduplicate by chain name
                    for chain in chain_results:
                        # Only save VERIFIED chains — unverified are noise
                        if not chain.get("verified"):
                            continue

                        # Deduplicate: one finding per chain type
                        chain_name = chain.get("chain_name") or chain.get("template_id", "")
                        if chain_name in saved_chain_names:
                            continue
                        saved_chain_names.add(chain_name)

                        chain_severity = sev_map.get(
                            chain.get("severity", "high"), Severity.HIGH
                        )
                        trigger_type = chain.get("trigger_vuln", {}).get("type", "")
                        trigger_url = chain.get("trigger_vuln", {}).get("url", "")

                        # Build description from evidence
                        evidence_lines = []
                        for ev in chain.get("evidence", []):
                            if isinstance(ev, dict):
                                evidence_lines.append(
                                    f"Step {ev.get('step', '?')}: {ev.get('action', '')} "
                                    f"-> {ev.get('result', '')}"
                                )

                        description = (
                            f"Multi-step attack chain: {chain.get('chain_name', 'Unknown')}\n\n"
                            + "\n".join(evidence_lines)
                            + f"\n\nSteps completed: {chain.get('steps_completed', 0)}"
                            f"/{chain.get('steps_total', 0)}"
                        )

                        recommendations = chain.get("recommendations", [])
                        remediation = "\n".join(
                            f"- {r}" for r in recommendations
                        ) if recommendations else None

                        vuln = Vulnerability(
                            target_id=self.context["target_id"],
                            scan_id=self.context["scan_id"],
                            title=f"Attack Chain: {chain.get('chain_name', 'Unknown')}"[:500],
                            vuln_type=VulnType.OTHER,
                            severity=chain_severity,
                            url=trigger_url[:2000] if trigger_url else "",
                            method="GET",
                            description=description,
                            impact=chain.get("impact", ""),
                            remediation=remediation,
                            ai_confidence=0.85 if chain.get("verified") else 0.6,
                            request_data={
                                "chain_template": chain.get("template_id", ""),
                                "trigger_type": trigger_type,
                                "steps_completed": chain.get("steps_completed", 0),
                                "steps_total": chain.get("steps_total", 0),
                                "evidence": chain.get("evidence", []),
                            },
                        )
                        db.add(vuln)
                        chains_saved += 1
                        if scan_obj:
                            scan_obj.vulns_found = (scan_obj.vulns_found or 0) + 1

                    if chains_saved:
                        await db.flush()

                    succeeded = sum(
                        1 for c in chain_results if c.get("verified")
                    )
                    await self.log(
                        db, "exploit",
                        f"Attack chains: executed {len(chain_results)} chains, "
                        f"{succeeded} verified, {chains_saved} saved as vulns",
                        "warning" if succeeded > 0 else "info",
                    )
                else:
                    await self.log(
                        db, "exploit",
                        "Attack chains: no applicable chains for current vulns",
                    )
            except Exception as e:
                await self.log(
                    db, "exploit",
                    f"Attack chain engine error: {e}", "warning",
                )

        # --- Access Control Verification ---
        try:
            from app.modules.access_control_prover import AccessControlProver
            prover = AccessControlProver(self.context)
            ac_findings = await prover.prove_all(self.context.get("endpoints", []), db)

            from app.models.vulnerability import Vulnerability, Severity as SevEnum, VulnType
            severity_map = {"critical": SevEnum.CRITICAL, "high": SevEnum.HIGH, "medium": SevEnum.MEDIUM, "low": SevEnum.LOW}

            for finding in ac_findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=finding["title"][:500],
                    vuln_type=VulnType.AUTH_BYPASS,
                    severity=severity_map.get(finding.get("severity", "high"), SevEnum.HIGH),
                    url=finding.get("url", "")[:2000],
                    parameter=finding.get("param"),
                    method=finding.get("method", "GET"),
                    description=finding.get("description", ""),
                    impact=finding.get("impact", ""),
                    remediation=finding.get("remediation", ""),
                    payload_used=finding.get("payload_used"),
                    request_data=finding.get("proof", {}).get("request"),
                    response_data=finding.get("proof", {}).get("response"),
                    evidence=json.dumps(finding.get("proof", {}))[:10000] if finding.get("proof") else None,
                )
                db.add(vuln)
            if ac_findings:
                await db.flush()

            await self.log(db, "exploit", f"Access control prover: {len(ac_findings)} proven vulnerabilities")
        except Exception as e:
            await self.log(db, "exploit", f"Access control prover error (non-fatal): {e}")

        # --- OOB Detection: wait for callbacks and check results ---
        try:
            from app.modules.oob_server import check_oob_results, OOB_HOST
            if OOB_HOST:
                await self.log(db, "exploit", "OOB: waiting 10s for out-of-band callbacks...")
                await asyncio.sleep(10)

                oob_results = await check_oob_results(self.scan_id, db)
                if oob_results:
                    from app.models.vulnerability import Vulnerability, Severity, VulnType
                    scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                    scan_obj = scan_result.scalar_one_or_none()
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                               "medium": Severity.MEDIUM, "low": Severity.LOW}
                    vtype_map = {
                        "ssrf": VulnType.SSRF, "xxe": VulnType.XXE,
                        "cmd_injection": VulnType.CMD_INJECTION, "ssti": VulnType.SSTI,
                    }

                    for oob_vuln in oob_results:
                        vt = vtype_map.get(oob_vuln.get("vuln_type", ""), VulnType.SSRF)
                        vuln = Vulnerability(
                            target_id=self.context["target_id"],
                            scan_id=self.context["scan_id"],
                            title=oob_vuln.get("title", "Blind vuln via OOB")[:500],
                            vuln_type=vt,
                            severity=sev_map.get(oob_vuln.get("severity", "high"), Severity.HIGH),
                            url=oob_vuln.get("url", "")[:2000],
                            method="GET",
                            description=oob_vuln.get("description", ""),
                            ai_confidence=oob_vuln.get("ai_confidence", 0.95),
                        )
                        db.add(vuln)
                        self.context.setdefault("vulnerabilities", []).append(oob_vuln)
                        if scan_obj:
                            scan_obj.vulns_found = (scan_obj.vulns_found or 0) + 1

                    await db.flush()
                    await self.log(db, "exploit",
                        f"OOB: confirmed {len(oob_results)} blind vulnerabilities via callbacks!", "success")
                else:
                    await self.log(db, "exploit", "OOB: no out-of-band callbacks received")

                # Stop the OOB server after checking
                try:
                    from app.modules.oob_server import stop_oob_server
                    await stop_oob_server()
                except Exception:
                    pass
        except Exception as e:
            await self.log(db, "exploit", f"OOB check error: {e}", "warning")

    async def _phase_sensitive_files(self, db: AsyncSession):
        """Discover exposed sensitive files, configs, backups."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 10)
        mod = SensitiveFilesModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "sensitive_files")
        if findings:
            from app.models.vulnerability import Vulnerability, Severity, VulnType
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}

            for f in findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Sensitive file exposed")[:500],
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                    url=f.get("url", "")[:2000],
                    method=f.get("method", "GET"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.9,
                )
                db.add(vuln)
                self.context.setdefault("vulnerabilities", []).append(f)
                if scan:
                    scan.vulns_found = (scan.vulns_found or 0) + 1

            await db.flush()
            await self.log(db, "sensitive_files",
                f"Found {len(findings)} exposed sensitive files/configs", "warning")
        else:
            await self.log(db, "sensitive_files", "No exposed sensitive files found")

    async def _phase_service_attack(self, db: AsyncSession):
        """Attack discovered services — SSH, FTP, Redis, databases, etc."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
        mod = ServiceAttackModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "service_attack")
        if findings:
            # Service attack findings are confirmed vulns — add directly
            from app.models.vulnerability import Vulnerability, Severity, VulnType
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()

            for f in findings:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                vt_map = {v.value: v for v in VulnType}

                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Service vulnerability")[:500],
                    vuln_type=vt_map.get(f.get("vuln_type", ""), VulnType.MISCONFIGURATION),
                    severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.95,
                )
                db.add(vuln)
                self.context.setdefault("vulnerabilities", []).append(f)
                if scan:
                    scan.vulns_found = (scan.vulns_found or 0) + 1

            await db.flush()
            await self.log(db, "service_attack",
                f"Service attacks found {len(findings)} vulnerabilities", "warning")
        else:
            await self.log(db, "service_attack", "No service vulnerabilities found")

    async def _phase_auth_attack(self, db: AsyncSession):
        """Brute force login forms and test default credentials."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
        mod = AuthAttackModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "auth_attack")
        if findings:
            from app.models.vulnerability import Vulnerability, Severity, VulnType
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()

            vt_map = {v.value: v for v in VulnType}
            for f in findings:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Auth vulnerability")[:500],
                    vuln_type=vt_map.get(f.get("vuln_type", "auth_bypass"), VulnType.AUTH_BYPASS),
                    severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.9,
                )
                db.add(vuln)
                self.context.setdefault("vulnerabilities", []).append(f)
                if scan:
                    scan.vulns_found = (scan.vulns_found or 0) + 1

            await db.flush()
            await self.log(db, "auth_attack",
                f"Auth attacks found {len(findings)} vulnerabilities", "warning")
        else:
            await self.log(db, "auth_attack", "No auth vulnerabilities found")

    async def _phase_stress_test(self, db: AsyncSession):
        """Test resilience — rate limiting, slow connections, large payloads."""
        if self.context.get("stealth"):
            await self.log(db, "stress_test", "Skipped in stealth mode")
            return

        sem = asyncio.Semaphore(self.context.get("rate_limit") or 20)
        mod = StressTestModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "stress_test")
        if findings:
            from app.models.vulnerability import Vulnerability, Severity, VulnType
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            vt_map = {v.value: v for v in VulnType}
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}

            for f in findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Resilience issue")[:500],
                    vuln_type=vt_map.get(f.get("vuln_type", "misconfiguration"), VulnType.MISCONFIGURATION),
                    severity=sev_map.get(f.get("severity", "low"), Severity.LOW),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.85,
                )
                db.add(vuln)
                self.context.setdefault("vulnerabilities", []).append(f)
                if scan:
                    scan.vulns_found = (scan.vulns_found or 0) + 1

            await db.flush()
            await self.log(db, "stress_test",
                f"Resilience testing found {len(findings)} issues", "warning")
        else:
            await self.log(db, "stress_test", "Server passed resilience tests")

    async def _phase_claude_collab(self, db: AsyncSession):
        """Claude collaboration: iterative deep analysis with Claude API."""
        from app.ai.get_claude_key import get_claude_api_key
        if not get_claude_api_key():
            await self.log(db, "claude_collab", "Skipped: no Anthropic API key configured")
            return

        from app.ai.claude_collab import ClaudeCollaboration
        from app.models.vulnerability import Vulnerability, Severity, VulnType

        collab = ClaudeCollaboration()
        await self.log(db, "claude_collab",
            f"Starting Claude collaboration on {self.context['domain']}...")

        # RAG: Inject knowledge base context for Claude collaboration
        try:
            from app.core.knowledge import KnowledgeBase
            from app.models.knowledge import KnowledgePattern
            from sqlalchemy import select, and_

            kb = KnowledgeBase()
            techs = list((self.context.get("technologies") or {}).get("summary", {}).keys())
            rag_parts = []

            # WAF bypass patterns from KB
            waf_info = self.context.get("waf_info") or {}
            if waf_info.get("detected"):
                waf_name = waf_info.get("waf_name", "unknown")
                waf_patterns = await db.execute(
                    select(KnowledgePattern).where(
                        and_(
                            KnowledgePattern.pattern_type == "waf_bypass",
                            KnowledgePattern.confidence > 0.3,
                        )
                    ).order_by(KnowledgePattern.confidence.desc()).limit(5)
                )
                waf_results = waf_patterns.scalars().all()
                if waf_results:
                    rag_parts.append(f"WAF BYPASS PATTERNS FROM KNOWLEDGE BASE (WAF: {waf_name}):")
                    for wp in waf_results:
                        d = wp.pattern_data or {}
                        rag_parts.append(f"  - {d.get('technique', wp.vuln_type or '?')}: {d.get('payload', d.get('description', ''))[:100]}")

            # Effective payloads for detected vuln types
            vuln_types = set()
            for v in self.context.get("vulnerabilities", []):
                vt = v.get("vuln_type", "")
                if vt:
                    vuln_types.add(vt)
            for vt in list(vuln_types)[:3]:
                payloads = await kb.get_effective_payloads(db, vt)
                if payloads:
                    rag_parts.append(f"EFFECTIVE PAYLOADS for {vt} from past scans:")
                    for p in payloads[:3]:
                        rag_parts.append(f"  - {p['payload'][:80]} (confidence: {p['confidence']:.0%})")

            # Tech-vuln correlations
            if techs:
                insights = await kb.get_tech_vuln_insights(db, techs)
                recs = insights.get("recommendations", [])[:5]
                if recs:
                    rag_parts.append("HISTORICAL VULN PATTERNS for this tech stack:")
                    for r in recs:
                        rag_parts.append(f"  - {r['vuln_type']}: {r['success_rate']:.0%} success rate on {r['technology']}")

            # H1 insights — what bounty platforms reward
            h1_insights = await kb.get_h1_insights(db)
            if h1_insights:
                rag_parts.append("H1 INSIGHTS — What bounty platforms accept/reward:")
                for h in h1_insights[:5]:
                    line = f"  - {h['vuln_type']}: {h.get('insight', h.get('recommendation', ''))}"
                    if h.get("bounty_range"):
                        line += f" (bounty: {h['bounty_range']})"
                    rag_parts.append(line)

            if rag_parts:
                self.context["_rag_context"] = "\nKNOWLEDGE BASE INTELLIGENCE:\n" + "\n".join(rag_parts) + "\n"
        except Exception as e:
            logger.debug(f"RAG injection for claude_collab failed (non-fatal): {e}")

        # WebSocket callback for live Claude events
        async def on_claude_event(event: dict):
            await self._publish({
                "type": "claude_collab_event",
                **event,
            })

        result = await collab.start_analysis(self.context, on_event=on_claude_event)

        rounds = result.get("rounds", 0)
        findings = result.get("findings", [])
        actions = result.get("actions_taken", 0)
        action_evidence = result.get("action_evidence", {})

        await self.log(db, "claude_collab",
            f"Claude collab: {rounds} rounds, {actions} actions, "
            f"{len(findings)} additional findings",
            "success" if findings else "info")

        # Mapping helpers for Claude finding fields → our enums
        _VULN_TYPE_MAP = {v.value: v for v in VulnType}
        _SEVERITY_MAP = {v.value: v for v in Severity}

        # Add any new findings from Claude collaboration
        if findings:
            # Load the scan object for counter updates
            scan_result = await db.execute(
                select(Scan).where(Scan.id == self.context["scan_id"])
            )
            scan = scan_result.scalar_one_or_none()

            for f in findings:
                # Keep existing logging
                await self.log(db, "claude_collab",
                    f"Claude found: {json.dumps(f, default=str)[:500]}",
                    "warning")

                # --- Map vuln_type ---
                raw_type = str(f.get("type", f.get("vuln_type", ""))).lower().strip()
                vuln_type = _VULN_TYPE_MAP.get(raw_type, VulnType.INFO_DISCLOSURE)

                # --- Map severity ---
                raw_sev = str(f.get("severity", "medium")).lower().strip()
                severity = _SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)

                # --- Build the URL ---
                url = f.get("url", self.context.get("base_url", ""))

                # --- Title & description ---
                title = f.get("title", f.get("name", f"Claude finding: {vuln_type.value}"))
                description = f.get("description", f.get("details", json.dumps(f, default=str)[:2000]))

                # Attach action evidence (request/response proof) if available
                request_data, response_data = collab._get_evidence_for_finding(f)

                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=title[:500],
                    vuln_type=vuln_type,
                    severity=severity,
                    url=url[:2000],
                    parameter=f.get("parameter", f.get("param")),
                    method=f.get("method"),
                    description=description,
                    impact=f.get("impact"),
                    remediation=f.get("remediation", f.get("fix")),
                    payload_used=f.get("payload"),
                    request_data=request_data,
                    response_data=response_data,
                    ai_confidence=0.7,
                    ai_analysis=json.dumps(f, default=str),
                )
                db.add(vuln)
                await db.flush()

                # Track in context so final count is correct
                self.context.setdefault("vulnerabilities", []).append({
                    "id": vuln.id,
                    "vuln_type": vuln_type.value,
                    "severity": severity.value,
                    "url": url,
                    "title": title,
                    "source": "claude_collab",
                })

                # Increment live counter
                if scan:
                    scan.vulns_found = (scan.vulns_found or 0) + 1

                # Publish WebSocket event per finding
                await self._publish({
                    "type": "new_vuln",
                    "source": "claude_collab",
                    "vuln_id": vuln.id,
                    "vuln_type": vuln_type.value,
                    "severity": severity.value,
                    "title": title,
                    "url": url,
                })

    async def _phase_vuln_confirm(self, db: AsyncSession):
        """Confirm all detected vulnerabilities by attempting actual exploitation.

        For each vuln found so far, tries to PROVE it works:
        - SQLi: extract data (already handled by DeepSQLi in exploiter)
        - XSS: verify reflection in executable context
        - SSRF: read cloud metadata / internal files
        - SSTI: execute template expressions
        - CMD Injection: execute unique commands
        - LFI: read sensitive files
        - IDOR: access multiple users' data
        """
        from sqlalchemy import select
        from app.models.vulnerability import Vulnerability

        # Get all vulns for this scan that haven't been confirmed yet
        result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == self.scan_id)
        )
        vulns = result.scalars().all()

        if not vulns:
            await self.log(db, "vuln_confirm", "No vulnerabilities to confirm")
            return

        # Filter out already-confirmed ones
        unconfirmed = [
            v for v in vulns
            if not (v.response_data or {}).get("confirmation", {}).get("confirmed")
            and not (v.response_data or {}).get("deep_sqli")  # SQLi already confirmed by DeepSQLi
        ]

        if not unconfirmed:
            await self.log(db, "vuln_confirm",
                f"All {len(vulns)} vulnerabilities already confirmed or have exploitation data")
            return

        await self.log(db, "vuln_confirm",
            f"Confirming {len(unconfirmed)}/{len(vulns)} vulnerabilities by exploitation...")

        confirmer = VulnConfirmer()
        stats = await confirmer.confirm_all(unconfirmed, self.context, db)

        await self.log(db, "vuln_confirm",
            f"Confirmation results: {stats['confirmed']} confirmed, "
            f"{stats['failed']} unconfirmed, {stats['escalated']} severity escalated "
            f"(of {stats['total']} tested)",
            "success" if stats["confirmed"] > 0 else "info")

        await db.commit()

    async def _phase_evidence(self, db: AsyncSession):
        # Run legacy attack chain analysis (supplements chains from exploit phase)
        try:
            from app.modules.attack_chain import AttackChainModule
            chain_mod = AttackChainModule()
            chains = await chain_mod.analyze(self.context)
            if chains:
                # Merge with chains from exploit phase (don't overwrite)
                existing = self.context.get("attack_chains", [])
                existing_names = {c.get("chain_name") or c.get("template_id") for c in existing}
                new_chains = [c for c in chains if c.get("chain_name") not in existing_names]
                if new_chains:
                    existing.extend(new_chains)
                    self.context["attack_chains"] = existing
                    await self.log(db, "evidence",
                        f"Additional chain analysis: {len(new_chains)} new chains: "
                        + ", ".join(c["chain_name"] for c in new_chains[:5]),
                        "warning")
        except Exception as e:
            await self.log(db, "evidence", f"Chain analysis error: {e}", "error")

        collector = EvidenceCollector()
        evidence = await collector.collect(self.context)
        self.context["evidence"] = evidence
        await self.log(db, "evidence", f"Collected evidence for {len(evidence)} findings")

    async def _phase_report(self, db: AsyncSession):
        reporter = ReportGenerator()
        for vuln in self.context.get("vulnerabilities", []):
            vuln["target_id"] = self.context["target_id"]
            vuln["scan_id"] = self.context["scan_id"]
            await reporter.generate_for_vuln(vuln, db)
        await self.log(db, "report", "Reports generated for all findings")

    async def _notify_critical_vulns(self, db: AsyncSession, target):
        """Send notifications for critical/high severity vulnerabilities found in this scan."""
        try:
            from app.core.notifications import notify_critical_vuln, get_notification_settings
            from app.models.vulnerability import Vulnerability, Severity

            settings = get_notification_settings()
            if not settings.get("enabled_channels"):
                return

            result = await db.execute(
                select(Vulnerability).where(
                    Vulnerability.scan_id == self.scan_id,
                    Vulnerability.severity.in_([Severity.CRITICAL, Severity.HIGH]),
                )
            )
            critical_vulns = result.scalars().all()
            for vuln in critical_vulns:
                if vuln.severity == Severity.CRITICAL and settings.get("notify_critical", True):
                    notify_critical_vuln(vuln, target)
                elif vuln.severity == Severity.HIGH and settings.get("notify_high", True):
                    notify_critical_vuln(vuln, target)
        except Exception:
            pass

    async def _get_knowledge_payloads(self, db: AsyncSession) -> list:
        """Query the knowledge base for effective payloads matching the target's technologies."""
        from app.models.knowledge import KnowledgePattern

        techs = list(self.context.get("technologies", {}).keys())
        payloads = []

        # Get effective payloads (high confidence, proven)
        query = select(KnowledgePattern).where(
            KnowledgePattern.pattern_type.in_(["effective_payload", "waf_bypass", "payload_mutation"]),
            KnowledgePattern.confidence >= 0.5,
        ).order_by(KnowledgePattern.confidence.desc()).limit(200)

        result = await db.execute(query)
        patterns = result.scalars().all()

        for p in patterns:
            data = p.pattern_data or {}
            payload = data.get("payload") or data.get("payloads")
            if not payload:
                continue

            # Filter by technology if we have tech info
            if techs and p.technology and p.technology.lower() not in [t.lower() for t in techs]:
                continue

            if isinstance(payload, list):
                for pl in payload[:3]:
                    payloads.append({
                        "payload": pl if isinstance(pl, str) else pl.get("payload", str(pl)),
                        "type": p.vuln_type or "generic",
                        "source": "knowledge_base",
                        "confidence": p.confidence,
                    })
            elif isinstance(payload, str):
                payloads.append({
                    "payload": payload,
                    "type": p.vuln_type or "generic",
                    "source": "knowledge_base",
                    "confidence": p.confidence,
                })

        return payloads
