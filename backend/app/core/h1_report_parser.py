"""
HackerOne Report Parser & Knowledge Extractor.

Fetches disclosed reports from HackerOne, analyzes them with Claude,
and saves extracted patterns into the Knowledge Base.

Two-layer extraction:
1. Regex-based: extract payloads, URLs, code blocks, HTTP requests from report text
2. Claude-based: deep semantic analysis of attack methodology
"""
import json
import logging
import re
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_engine import LLMEngine, LLMError
from app.core.h1_client import H1Client
from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)


# ---- Regex patterns for payload extraction from report text ----

# Code blocks (markdown triple backticks or indented)
_RE_CODE_BLOCK = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL)
_RE_INLINE_CODE = re.compile(r"`([^`]{5,200})`")

# HTTP requests
_RE_HTTP_REQUEST = re.compile(
    r"(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+(https?://\S+|/\S+)",
    re.IGNORECASE,
)

# URLs with injection markers
_RE_PAYLOAD_URL = re.compile(
    r"https?://[^\s\"'<>]+[?&][^\s\"'<>]*"
    r"(?:['\"><;|`\{\}]|%[0-9a-fA-F]{2}|script|alert|union|select|sleep|concat"
    r"|onerror|onload|img\s+src|iframe|eval\(|document\.|\.\.\/|etc\/passwd)",
    re.IGNORECASE,
)

# Common payload patterns in text
_RE_XSS_PAYLOAD = re.compile(
    r"(<script[^>]*>.*?</script>|<img[^>]*onerror[^>]*>|<svg[^>]*onload[^>]*>"
    r"|javascript:[^\s\"']+|<iframe[^>]*>|<details[^>]*open[^>]*ontoggle[^>]*>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_SQLI_PAYLOAD = re.compile(
    r"(['\"]?\s*(?:OR|AND|UNION)\s+(?:SELECT|ALL|1\s*=\s*1|TRUE|SLEEP)|"
    r"(?:WAITFOR\s+DELAY|BENCHMARK\s*\(|pg_sleep|EXTRACTVALUE|UPDATEXML)\s*\()",
    re.IGNORECASE,
)
_RE_SSTI_PAYLOAD = re.compile(
    r"(\{\{.*?\}\}|\$\{.*?\}|<%.*?%>|#\{.*?\}|\[\[.*?\]\])",
)
_RE_CMD_PAYLOAD = re.compile(
    r"[;|`]\s*(cat|ls|id|whoami|ping|curl|wget|nc|nslookup)\s",
    re.IGNORECASE,
)
_RE_SSRF_URL = re.compile(
    r"(https?://(?:169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|"
    r"internal|metadata|2130706433|0x7f000001|[:0]+1)[\S]*)",
    re.IGNORECASE,
)
_RE_PATH_TRAVERSAL = re.compile(
    r"((?:\.\./){2,}[\w/]+|(?:%2e%2e[/%]){2,}|(?:\.\.\\/){2,})",
    re.IGNORECASE,
)

# Endpoint patterns
_RE_API_ENDPOINT = re.compile(
    r"(?:GET|POST|PUT|DELETE|PATCH)\s+(/api/\S+|/v[0-9]/\S+|/graphql\S*)",
    re.IGNORECASE,
)

# Tool names
_TOOLS_RE = re.compile(
    r"\b(burp|sqlmap|ffuf|dirsearch|nuclei|nmap|nikto|wfuzz|gobuster|"
    r"amass|subfinder|httpx|katana|dalfox|xsstrike|ssrfmap|tplmap|"
    r"commix|ghauri|arjun|paramspider|waybackurls|gau)\b",
    re.IGNORECASE,
)


def extract_payloads_from_text(text: str, vuln_type: str | None = None) -> dict:
    """Extract payloads, techniques, and patterns from report text using regex.

    Returns: {payloads: [...], endpoints: [...], tools: [...], techniques: [...]}
    """
    payloads = []
    endpoints = []
    tools = set()
    techniques = []

    if not text:
        return {"payloads": [], "endpoints": [], "tools": [], "techniques": []}

    # Extract from code blocks first (highest quality)
    for block in _RE_CODE_BLOCK.findall(text):
        block = block.strip()
        if len(block) < 5 or len(block) > 2000:
            continue
        # HTTP request in code block
        if re.match(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+", block, re.IGNORECASE):
            payloads.append(block)
        # Curl command
        elif block.startswith("curl "):
            payloads.append(block)
        # Contains injection markers
        elif any(marker in block.lower() for marker in [
            "script", "alert(", "onerror", "union select", "sleep(",
            "{{", "${", "../", "127.0.0.1", "169.254", ";cat ", ";id",
        ]):
            payloads.append(block)

    # Inline code
    for code in _RE_INLINE_CODE.findall(text):
        code = code.strip()
        if any(marker in code.lower() for marker in [
            "<script", "alert(", "onerror", "union", "select", "sleep(",
            "{{", "${", "../", "127.0.0.1", ";cat", ";id", "eval(",
        ]):
            payloads.append(code)

    # XSS payloads
    for m in _RE_XSS_PAYLOAD.finditer(text):
        payloads.append(m.group(0))

    # SQLi payloads
    for m in _RE_SQLI_PAYLOAD.finditer(text):
        # Get surrounding context (50 chars each side)
        start = max(0, m.start() - 50)
        end = min(len(text), m.end() + 50)
        context = text[start:end].strip()
        # Clean to just the payload part
        payloads.append(context)

    # SSTI payloads
    for m in _RE_SSTI_PAYLOAD.finditer(text):
        payload = m.group(0)
        if len(payload) > 4 and payload not in ("{{", "}}", "${}", "#{}", "[[]]"):
            payloads.append(payload)

    # CMD injection
    for m in _RE_CMD_PAYLOAD.finditer(text):
        start = max(0, m.start() - 30)
        end = min(len(text), m.end() + 30)
        payloads.append(text[start:end].strip())

    # SSRF URLs
    for m in _RE_SSRF_URL.finditer(text):
        payloads.append(m.group(0))

    # Path traversal
    for m in _RE_PATH_TRAVERSAL.finditer(text):
        payloads.append(m.group(0))

    # URLs with injection
    for m in _RE_PAYLOAD_URL.finditer(text):
        payloads.append(m.group(0))

    # API endpoints
    for m in _RE_API_ENDPOINT.finditer(text):
        endpoints.append(m.group(1))

    # HTTP request lines
    for m in _RE_HTTP_REQUEST.finditer(text):
        path = m.group(2)
        if path.startswith("/"):
            endpoints.append(path)

    # Tools mentioned
    for m in _TOOLS_RE.finditer(text):
        tools.add(m.group(1).lower())

    # Deduplicate
    seen = set()
    unique_payloads = []
    for p in payloads:
        p_clean = p.strip()[:500]
        if p_clean and p_clean not in seen:
            seen.add(p_clean)
            unique_payloads.append(p_clean)

    seen_ep = set()
    unique_endpoints = []
    for e in endpoints:
        e_clean = e.strip()[:200]
        if e_clean and e_clean not in seen_ep:
            seen_ep.add(e_clean)
            unique_endpoints.append(e_clean)

    return {
        "payloads": unique_payloads[:50],
        "endpoints": unique_endpoints[:20],
        "tools": sorted(tools)[:10],
        "techniques": techniques[:10],
    }

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

                vuln_type = normalize_vuln_type(
                    report.pattern_data.get("cwe"), title
                )

                # Layer 1: Regex-based extraction (fast, no LLM needed)
                if report_text:
                    extracted = extract_payloads_from_text(report_text, vuln_type)
                    if extracted["payloads"]:
                        # Save directly as effective_payload
                        pattern = KnowledgePattern(
                            pattern_type="effective_payload",
                            technology=report.pattern_data.get("program", "generic"),
                            vuln_type=vuln_type or "other",
                            pattern_data={
                                "payload": extracted["payloads"][0],
                                "payloads": extracted["payloads"][:30],
                                "source": "h1_report_regex",
                                "h1_id": h1_id,
                                "title": title,
                                "bounty": report.pattern_data.get("bounty"),
                                "endpoints": extracted["endpoints"][:10],
                                "tools": extracted["tools"],
                            },
                            confidence=0.6 if report.pattern_data.get("bounty") else 0.45,
                            sample_count=1,
                        )
                        self.db.add(pattern)
                        stats["patterns_created"] += 1

                    if extracted["endpoints"]:
                        pattern = KnowledgePattern(
                            pattern_type="endpoint_pattern",
                            technology=report.pattern_data.get("program", "generic"),
                            vuln_type=vuln_type or "other",
                            pattern_data={
                                "paths": extracted["endpoints"],
                                "source": "h1_report_regex",
                                "h1_id": h1_id,
                            },
                            confidence=0.5,
                            sample_count=1,
                        )
                        self.db.add(pattern)
                        stats["patterns_created"] += 1

                # Layer 2: Claude-based analysis (deep, semantic)
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
