"""
HackerOne Report Generator — Claude-powered.

Takes a Vulnerability from DB, generates a professional H1 report using Claude,
checks for duplicates against known disclosed reports, and scores quality.
"""
import json
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_engine import LLMEngine, LLMError
from app.models.vulnerability import Vulnerability
from app.models.knowledge import KnowledgePattern
from app.models.target import Target
from app.modules.hackerone_report import VULN_TYPE_TO_CWE

logger = logging.getLogger(__name__)


class H1ReportGenerator:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.llm = LLMEngine()

    async def generate_report(self, vuln_id: str) -> dict:
        """Generate a full H1 report for a vulnerability."""
        # Load vulnerability with target
        result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.id == vuln_id)
        )
        vuln = result.scalar_one_or_none()
        if not vuln:
            return {"error": "Vulnerability not found"}

        target_result = await self.db.execute(
            select(Target).where(Target.id == vuln.target_id)
        )
        target = target_result.scalar_one_or_none()

        # Step 1: Check for duplicates
        duplicate_check = await self._check_duplicates(vuln, target)

        # Step 2: Generate report with Claude
        report = await self._generate_with_claude(vuln, target)

        # Step 3: Quality scoring
        quality = await self._score_quality(vuln, report)

        return {
            "vuln_id": vuln.id,
            "report": report,
            "duplicate_check": duplicate_check,
            "quality": quality,
            "generated_at": datetime.utcnow().isoformat(),
        }

    async def _generate_with_claude(self, vuln: Vulnerability, target: Target | None) -> dict:
        """Use Claude to generate a professional H1 report."""
        vuln_type = vuln.vuln_type.value
        cwe_info = VULN_TYPE_TO_CWE.get(vuln_type, {"cwe": "CWE-0", "name": vuln_type})

        # RAG: Query knowledge base for similar high-bounty reports
        rag_context = ""
        try:
            similar_reports = await self.db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "h1_report",
                    KnowledgePattern.vuln_type == vuln_type,
                    KnowledgePattern.pattern_data["bounty"].isnot(None),
                ).order_by(KnowledgePattern.confidence.desc()).limit(5)
            )
            reports = similar_reports.scalars().all()
            if reports:
                examples = []
                for r in reports:
                    d = r.pattern_data
                    examples.append(
                        f"- \"{d.get('title', '?')}\" (${d.get('bounty', 0)}, {d.get('severity', '?')})"
                    )
                rag_context = f"\n\nSIMILAR ACCEPTED H1 REPORTS (use as style reference):\n" + "\n".join(examples)

            # Also get effective payloads for this vuln type
            payload_patterns = await self.db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "effective_payload",
                    KnowledgePattern.vuln_type == vuln_type,
                    KnowledgePattern.confidence > 0.4,
                ).limit(3)
            )
            payloads = payload_patterns.scalars().all()
            if payloads:
                payload_strs = []
                for p in payloads:
                    pd = p.pattern_data or {}
                    payload_strs.append(f"- {pd.get('payload', '?')} (confidence: {p.confidence:.0%})")
                rag_context += f"\n\nKNOWN EFFECTIVE PAYLOADS for {vuln_type}:\n" + "\n".join(payload_strs)
        except Exception:
            pass  # RAG is enhancement, don't fail report generation

        # Prepare context
        request_str = json.dumps(vuln.request_data, default=str)[:2000] if vuln.request_data else "N/A"
        response_str = ""
        if vuln.response_data:
            if isinstance(vuln.response_data, dict):
                response_str = vuln.response_data.get("body", "")[:1500]
            else:
                response_str = str(vuln.response_data)[:1500]

        prompt = f"""You are an expert bug bounty hunter writing a HackerOne report. Generate a professional, detailed vulnerability report that maximizes the chance of acceptance and a good bounty.

VULNERABILITY DATA:
- Type: {cwe_info['name']} ({cwe_info['cwe']})
- Severity: {vuln.severity.value}
- CVSS: {vuln.cvss_score or 'not calculated'}
- URL: {vuln.url}
- Method: {vuln.method or 'GET'}
- Parameter: {vuln.parameter or 'N/A'}
- Payload: {vuln.payload_used or 'N/A'}
- Description: {vuln.description[:1500] if vuln.description else 'N/A'}
- AI Analysis: {vuln.ai_analysis[:1000] if vuln.ai_analysis else 'N/A'}
- Target Domain: {target.domain if target else 'unknown'}
- Technologies: {json.dumps(target.technologies) if target and target.technologies else 'unknown'}

REQUEST:
{request_str}

RESPONSE SNIPPET:
{response_str or 'N/A'}

Generate a JSON with these fields:
{{
    "title": "Clear, specific title (e.g., 'Stored XSS in comment field on /blog/post allows session hijacking')",
    "summary": "2-3 sentence summary explaining the vulnerability and its business impact",
    "severity_justification": "Why this severity rating is appropriate",
    "steps_to_reproduce": ["Step 1...", "Step 2...", "Step 3...", "Step 4..."],
    "impact": "Detailed impact statement — what can an attacker actually achieve? Be specific.",
    "poc_description": "Narrative description of the proof of concept",
    "curl_command": "curl command to reproduce (if applicable)",
    "remediation": "Specific technical remediation advice",
    "references": ["relevant URLs, CVEs, or OWASP references"],
    "additional_notes": "Any extra context that strengthens the report"
}}

IMPORTANT:
- Be specific, not generic. Reference the actual URL, parameter, and payload.
- The impact must describe real-world consequences, not just theoretical risk.
- Steps to reproduce must be clear enough for a triager to follow.
- Don't be verbose — quality over quantity.
{rag_context}
Respond with ONLY the JSON."""

        try:
            report_data = await self.llm.analyze_json(prompt)
        except LLMError:
            # Fallback to template-based report
            from app.modules.hackerone_report import generate_hackerone_report
            fallback = generate_hackerone_report({
                "vuln_type": vuln.vuln_type,
                "title": vuln.title,
                "url": vuln.url,
                "method": vuln.method,
                "parameter": vuln.parameter,
                "payload_used": vuln.payload_used,
                "request_data": vuln.request_data,
                "response_data": vuln.response_data,
                "severity": vuln.severity,
                "remediation": vuln.remediation,
                "description": vuln.description,
            })
            return {
                "source": "template",
                **fallback,
            }

        # Build final markdown
        title = report_data.get("title", vuln.title)
        steps = report_data.get("steps_to_reproduce", [])
        steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        refs = report_data.get("references", [])
        refs_md = "\n".join(f"- {r}" for r in refs) if refs else ""
        curl = report_data.get("curl_command", "")
        additional = report_data.get("additional_notes", "")

        markdown = f"""## Summary

{report_data.get('summary', vuln.description or '')}

## Vulnerability Type

- **Type**: {cwe_info['name']}
- **CWE**: {cwe_info['cwe']}
- **Severity**: {vuln.severity.value.capitalize()}{f' (CVSS {vuln.cvss_score})' if vuln.cvss_score else ''}

### Severity Justification

{report_data.get('severity_justification', '')}

## Steps to Reproduce

{steps_md}

{f"**cURL command:**{chr(10)}```bash{chr(10)}{curl}{chr(10)}```" if curl else ""}

## Impact

{report_data.get('impact', '')}

## Proof of Concept

{report_data.get('poc_description', '')}

{self._format_poc_data(vuln)}

## Suggested Remediation

{report_data.get('remediation', vuln.remediation or '')}

{f"## References{chr(10)}{chr(10)}{refs_md}" if refs_md else ""}

{f"## Additional Notes{chr(10)}{chr(10)}{additional}" if additional else ""}

---
*Report generated by PHANTOM — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*"""

        return {
            "source": "claude",
            "title": title,
            "severity": vuln.severity.value,
            "cwe": cwe_info["cwe"],
            "markdown": markdown.strip(),
            "sections": report_data,
        }

    def _format_poc_data(self, vuln: Vulnerability) -> str:
        """Format request/response data for the PoC section."""
        parts = []

        if vuln.request_data and isinstance(vuln.request_data, dict):
            method = vuln.request_data.get("method", "GET")
            url = vuln.request_data.get("url", vuln.url)
            headers = vuln.request_data.get("headers", {})
            body = vuln.request_data.get("body", "")

            req = f"{method} {url} HTTP/1.1\n"
            for k, v in headers.items():
                req += f"{k}: {v}\n"
            if body:
                req += f"\n{body}"
            parts.append(f"**Request:**\n```http\n{req.strip()}\n```")

        if vuln.response_data and isinstance(vuln.response_data, dict):
            status = vuln.response_data.get("status_code", "")
            body = vuln.response_data.get("body", "")
            if body and len(body) > 500:
                body = body[:500] + "\n... (truncated)"
            if status or body:
                parts.append(
                    f"**Response:**\n```http\nHTTP/1.1 {status}\n\n{body}\n```"
                )

        if not parts and vuln.payload_used:
            parts.append(f"**Payload:**\n```\n{vuln.payload_used}\n```")

        return "\n\n".join(parts)

    async def _check_duplicates(self, vuln: Vulnerability, target: Target | None) -> dict:
        """Check if similar vulnerabilities have been reported on H1."""
        vuln_type = vuln.vuln_type.value
        domain = target.domain if target else ""

        # Search in our H1 reports knowledge base
        result = await self.db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "h1_report",
                KnowledgePattern.pattern_data["disclosed"].as_boolean() == True,
            ).limit(500)
        )
        known_reports = result.scalars().all()

        matches = []
        for r in known_reports:
            score = 0
            r_data = r.pattern_data

            # Same program
            if r_data.get("program") and domain and r_data["program"] in domain:
                score += 40

            # Same vuln type
            r_vuln = r.vuln_type or ""
            if r_vuln and (r_vuln in vuln_type or vuln_type in r_vuln):
                score += 30

            # Similar title keywords
            r_title = (r_data.get("title") or "").lower()
            vuln_title = vuln.title.lower()
            common_words = set(r_title.split()) & set(vuln_title.split())
            # Ignore common filler words
            common_words -= {"a", "an", "the", "in", "on", "at", "to", "via", "by", "of", "and", "or", "is"}
            if len(common_words) >= 3:
                score += 20

            # Same CWE
            r_cwe = (r_data.get("cwe") or "").lower()
            vuln_cwe = VULN_TYPE_TO_CWE.get(vuln_type, {}).get("cwe", "").lower()
            if r_cwe and vuln_cwe and r_cwe == vuln_cwe:
                score += 10

            if score >= 40:
                matches.append({
                    "h1_id": r_data.get("h1_id"),
                    "title": r_data.get("title"),
                    "program": r_data.get("program"),
                    "similarity_score": score,
                    "bounty": r_data.get("bounty"),
                    "url": r_data.get("url"),
                })

        matches.sort(key=lambda x: x["similarity_score"], reverse=True)

        is_likely_duplicate = any(m["similarity_score"] >= 70 for m in matches)

        return {
            "is_likely_duplicate": is_likely_duplicate,
            "similar_reports": matches[:5],
            "checked_against": len(known_reports),
            "recommendation": (
                "HIGH RISK of duplicate — similar report already disclosed"
                if is_likely_duplicate
                else "No obvious duplicates found — proceed with caution"
            ),
        }

    async def _score_quality(self, vuln: Vulnerability, report: dict) -> dict:
        """Score the quality of evidence and report completeness."""
        score = 0
        issues = []

        # Has payload
        if vuln.payload_used:
            score += 15
        else:
            issues.append("No payload — report lacks concrete PoC")

        # Has request/response data
        if vuln.request_data:
            score += 15
        else:
            issues.append("No HTTP request data — harder to reproduce")

        if vuln.response_data:
            score += 15
            # Check if response actually shows the vuln
            body = ""
            if isinstance(vuln.response_data, dict):
                body = vuln.response_data.get("body", "")
            if vuln.payload_used and vuln.payload_used in body:
                score += 10  # Payload reflected in response
        else:
            issues.append("No HTTP response data — no proof of exploitation")

        # Has AI validation
        if vuln.ai_confidence and vuln.ai_confidence > 0.7:
            score += 10
        elif vuln.ai_confidence and vuln.ai_confidence > 0.5:
            score += 5
        else:
            issues.append("Low AI confidence — consider manual verification")

        # CVSS calculated
        if vuln.cvss_score:
            score += 10
        else:
            issues.append("No CVSS score — add for credibility")

        # Severity justification
        if vuln.severity.value in ("critical", "high"):
            score += 5  # Higher bounty potential
        elif vuln.severity.value == "info":
            issues.append("Info severity — unlikely to get bounty")

        # Has description
        if vuln.description and len(vuln.description) > 50:
            score += 10
        else:
            issues.append("Weak description — add more detail")

        # Impact statement
        if vuln.impact and len(vuln.impact) > 30:
            score += 10
        else:
            issues.append("No impact statement — critical for bounty")

        # Determine grade
        if score >= 80:
            grade = "A"
            verdict = "Ready to submit"
        elif score >= 60:
            grade = "B"
            verdict = "Good — fix minor issues before submitting"
        elif score >= 40:
            grade = "C"
            verdict = "Needs improvement — strengthen evidence"
        else:
            grade = "D"
            verdict = "Not ready — needs significant work"

        return {
            "score": score,
            "max_score": 100,
            "grade": grade,
            "verdict": verdict,
            "issues": issues,
        }

    async def generate_batch(self, vuln_ids: list[str]) -> list[dict]:
        """Generate reports for multiple vulnerabilities."""
        results = []
        for vid in vuln_ids:
            result = await self.generate_report(vid)
            results.append(result)
        return results

    async def close(self):
        await self.llm.close()
