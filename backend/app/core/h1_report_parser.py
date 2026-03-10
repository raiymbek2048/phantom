"""
HackerOne Report Parser & Knowledge Extractor.

Fetches disclosed reports from HackerOne, analyzes them with Claude,
and saves extracted patterns into the Knowledge Base.
"""
import json
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_engine import LLMEngine, LLMError
from app.core.h1_client import H1Client
from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)

# Map H1 CWE names to our vuln_types
CWE_TO_VULN_TYPE = {
    "cross-site scripting": "xss",
    "xss": "xss",
    "sql injection": "sqli",
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    "information disclosure": "info_disclosure",
    "information exposure": "info_disclosure",
    "open redirect": "open_redirect",
    "improper authentication": "auth_bypass",
    "authentication bypass": "auth_bypass",
    "broken authentication": "auth_bypass",
    "insecure direct object reference": "idor",
    "idor": "idor",
    "cross-site request forgery": "csrf",
    "csrf": "csrf",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "remote code execution": "rce",
    "rce": "rce",
    "command injection": "cmd_injection",
    "os command injection": "cmd_injection",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "server-side template injection": "ssti",
    "ssti": "ssti",
    "deserialization": "deserialization",
    "race condition": "race_condition",
    "privilege escalation": "privilege_escalation",
    "improper access control": "auth_bypass",
    "business logic": "business_logic",
    "file upload": "file_upload",
    "cors misconfiguration": "cors_misconfiguration",
    "subdomain takeover": "subdomain_takeover",
    "jwt": "jwt_vuln",
}


def normalize_vuln_type(cwe: str | None, title: str | None) -> str | None:
    """Map CWE or title text to internal vuln_type."""
    for source in [cwe, title]:
        if not source:
            continue
        lower = source.lower()
        for key, vuln_type in CWE_TO_VULN_TYPE.items():
            if key in lower:
                return vuln_type
    return None


class H1ReportParser:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.h1 = H1Client()
        self.llm = LLMEngine()

    async def fetch_and_store_hacktivity(self, pages: int = 10) -> dict:
        """Fetch hacktivity and store metadata as knowledge patterns."""
        items = await self.h1.get_hacktivity_pages(pages=pages)
        stats = {"total": len(items), "disclosed": 0, "stored": 0, "skipped": 0}

        for item in items:
            meta = self.h1.extract_hacktivity_metadata(item)

            # Only process items with useful data
            if not meta["program"]:
                stats["skipped"] += 1
                continue

            if meta["disclosed"]:
                stats["disclosed"] += 1

            # Check if already stored
            existing = await self.db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "h1_report",
                    KnowledgePattern.pattern_data["h1_id"].as_string()
                    == str(meta["h1_id"]),
                )
            )
            if existing.scalar_one_or_none():
                stats["skipped"] += 1
                continue

            vuln_type = normalize_vuln_type(meta["cwe"], meta["title"])

            pattern = KnowledgePattern(
                pattern_type="h1_report",
                technology=meta["program"],
                vuln_type=vuln_type,
                pattern_data={
                    "h1_id": meta["h1_id"],
                    "title": meta["title"],
                    "severity": meta["severity"],
                    "cwe": meta["cwe"],
                    "cve_ids": meta["cve_ids"],
                    "bounty": meta["bounty"],
                    "votes": meta["votes"],
                    "url": meta["url"],
                    "substate": meta["substate"],
                    "program": meta["program"],
                    "program_name": meta["program_name"],
                    "reporter": meta["reporter"],
                    "disclosed": meta["disclosed"],
                    "disclosed_at": meta["disclosed_at"],
                    "submitted_at": meta["submitted_at"],
                },
                confidence=0.5 if meta["disclosed"] else 0.3,
                sample_count=1,
            )
            self.db.add(pattern)
            stats["stored"] += 1

        await self.db.commit()
        logger.info(f"H1 hacktivity: {stats}")
        return stats

    async def analyze_disclosed_reports(self, limit: int = 20) -> dict:
        """Find disclosed reports in DB and analyze them with Claude."""
        from sqlalchemy import or_
        result = await self.db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "h1_report",
                KnowledgePattern.pattern_data["disclosed"].as_boolean() == True,
                or_(
                    KnowledgePattern.pattern_data["analyzed"].as_boolean() != True,
                    KnowledgePattern.pattern_data["analyzed"] == None,
                ),
            ).limit(limit)
        )
        reports = result.scalars().all()
        stats = {"total": len(reports), "analyzed": 0, "patterns_created": 0, "failed": 0}

        for report in reports:
            h1_id = report.pattern_data.get("h1_id")
            url = report.pattern_data.get("url")
            title = report.pattern_data.get("title")

            if not url or not title:
                continue

            try:
                # Fetch full report content
                full_report = await self.h1.get_disclosed_report(h1_id)
                report_text = ""
                if full_report:
                    if full_report.get("source") == "scrape":
                        report_text = full_report.get("text", "")
                    elif full_report.get("source") == "nextjs":
                        report_text = json.dumps(
                            full_report.get("data", {}), indent=2
                        )[:10000]

                # Analyze with Claude
                patterns = await self._analyze_report_with_claude(
                    title=title,
                    cwe=report.pattern_data.get("cwe"),
                    severity=report.pattern_data.get("severity"),
                    program=report.pattern_data.get("program_name"),
                    bounty=report.pattern_data.get("bounty"),
                    report_text=report_text[:8000] if report_text else "",
                )

                if patterns:
                    for p in patterns:
                        knowledge = KnowledgePattern(
                            pattern_type=p.get("pattern_type", "h1_insight"),
                            technology=p.get("technology"),
                            vuln_type=p.get("vuln_type"),
                            pattern_data=p.get("pattern_data", {}),
                            confidence=p.get("confidence", 0.4),
                            sample_count=1,
                        )
                        self.db.add(knowledge)
                        stats["patterns_created"] += 1

                # Mark as analyzed
                updated_data = dict(report.pattern_data)
                updated_data["analyzed"] = True
                updated_data["analyzed_at"] = datetime.utcnow().isoformat()
                report.pattern_data = updated_data
                stats["analyzed"] += 1

            except Exception as e:
                logger.error(f"Failed to analyze H1 report {h1_id}: {e}")
                stats["failed"] += 1

        await self.db.commit()
        logger.info(f"H1 report analysis: {stats}")
        return stats

    async def _analyze_report_with_claude(
        self,
        title: str,
        cwe: str | None,
        severity: str | None,
        program: str | None,
        bounty: float | None,
        report_text: str,
    ) -> list[dict]:
        """Use Claude to extract attack patterns from a disclosed report."""
        prompt = f"""Analyze this HackerOne disclosed bug bounty report and extract actionable attack patterns.

Report:
- Title: {title}
- CWE: {cwe or 'unknown'}
- Severity: {severity or 'unknown'}
- Program: {program or 'unknown'}
- Bounty: ${bounty or 0}

{f"Report content:{chr(10)}{report_text}" if report_text else "No full report text available — analyze based on title and metadata."}

Extract patterns as JSON array. Each pattern should have:
- "pattern_type": one of "effective_payload", "tech_vuln_correlation", "endpoint_pattern", "waf_bypass", "h1_insight"
- "technology": detected technology if any (e.g. "php", "nodejs", "wordpress")
- "vuln_type": vulnerability type (xss, sqli, ssrf, idor, auth_bypass, etc.)
- "pattern_data": object with actionable details:
  - For effective_payload: {{"payloads": [...], "context": "..."}}
  - For tech_vuln_correlation: {{"success_indicators": [...], "common_endpoints": [...]}}
  - For endpoint_pattern: {{"paths": [...], "parameters": [...]}}
  - For h1_insight: {{"attack_methodology": "...", "key_finding": "...", "why_paid": "..."}}
- "confidence": 0.3-0.7 based on how actionable the pattern is

Return 1-5 patterns. Focus on what's ACTIONABLE for finding similar bugs.
Respond with ONLY the JSON array."""

        try:
            result = await self.llm.analyze_json(prompt)
            if isinstance(result, list):
                return result[:5]
            return []
        except LLMError as e:
            logger.warning(f"Claude analysis failed: {e}")
            return []

    async def get_stats(self) -> dict:
        """Get statistics about collected H1 data."""
        from sqlalchemy import func

        total = await self.db.execute(
            select(func.count()).where(
                KnowledgePattern.pattern_type == "h1_report"
            )
        )
        disclosed = await self.db.execute(
            select(func.count()).where(
                KnowledgePattern.pattern_type == "h1_report",
                KnowledgePattern.pattern_data["disclosed"].as_boolean() == True,
            )
        )
        analyzed = await self.db.execute(
            select(func.count()).where(
                KnowledgePattern.pattern_type == "h1_report",
                KnowledgePattern.pattern_data["analyzed"].as_boolean() == True,
            )
        )
        insights = await self.db.execute(
            select(func.count()).where(
                KnowledgePattern.pattern_type == "h1_insight"
            )
        )

        # Top programs by bounty
        programs_result = await self.db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "h1_report",
                KnowledgePattern.pattern_data["bounty"].isnot(None),
            )
        )
        programs = programs_result.scalars().all()
        program_bounties: dict[str, list] = {}
        for p in programs:
            prog = p.pattern_data.get("program", "unknown")
            bounty = p.pattern_data.get("bounty")
            if bounty:
                program_bounties.setdefault(prog, []).append(bounty)

        top_programs = sorted(
            [
                {
                    "program": prog,
                    "total_bounty": sum(bounties),
                    "avg_bounty": sum(bounties) / len(bounties),
                    "report_count": len(bounties),
                }
                for prog, bounties in program_bounties.items()
            ],
            key=lambda x: x["total_bounty"],
            reverse=True,
        )[:10]

        # Vuln type distribution
        vuln_result = await self.db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "h1_report",
                KnowledgePattern.vuln_type.isnot(None),
            )
        )
        vuln_patterns = vuln_result.scalars().all()
        vuln_dist: dict[str, int] = {}
        for v in vuln_patterns:
            vuln_dist[v.vuln_type] = vuln_dist.get(v.vuln_type, 0) + 1

        return {
            "total_reports": total.scalar(),
            "disclosed_reports": disclosed.scalar(),
            "analyzed_reports": analyzed.scalar(),
            "h1_insights": insights.scalar(),
            "top_programs": top_programs,
            "vuln_type_distribution": vuln_dist,
        }

    async def close(self):
        await self.h1.close()
        await self.llm.close()
