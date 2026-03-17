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
from app.modules.hackerone_report import VULN_TYPE_TO_CWE, VULN_TYPE_CVSS, _cvss_rating, _get_owasp_reference

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
        cvss_type = VULN_TYPE_CVSS.get(vuln_type)
        cvss_score = vuln.cvss_score or (cvss_type["score"] if cvss_type else None)
        cvss_vector = cvss_type["vector"] if cvss_type else "N/A"
        cvss_rating_str = _cvss_rating(cvss_score) if cvss_score else "Unknown"
        cwe_num = cwe_info["cwe"].split("-")[1] if "-" in cwe_info["cwe"] else "0"
        owasp_ref = _get_owasp_reference(vuln_type)

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
- Severity: {vuln.severity.value} (CVSS: {cvss_score or 'N/A'}, {cvss_rating_str})
- CVSS Vector: {cvss_vector}
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
    "title": "Clear, specific title (e.g., 'Stored XSS in comment field on /blog/post via `message` parameter allows session hijacking')",
    "summary": "2-3 sentence summary: what the vuln is, where it is (exact URL + param), and what an attacker achieves",
    "severity_justification": "Why this severity ({vuln.severity.value}) and CVSS ({cvss_score}) is appropriate — reference confidentiality/integrity/availability impact",
    "steps_to_reproduce": [
        "Step 1: exact URL to visit or request to send (include full URL with parameters)",
        "Step 2: exact payload to inject, which parameter, which field",
        "Step 3: what to observe in response (status code, specific string in body, behavior change)",
        "Step 4: how to verify exploitation succeeded (check DOM, check DB, check logs)"
    ],
    "impact": "Detailed impact: what EXACTLY can an attacker do? (e.g., 'steal admin session cookie and access /admin/users to exfiltrate all user records including emails and password hashes'). Be concrete, not theoretical.",
    "poc_description": "Narrative of the PoC: what was sent, what was received, what it proves. Reference specific HTTP status codes, response strings, or behavioral changes.",
    "curl_command": "Complete, working curl command with all headers and payload. Example: curl -s -X POST 'https://target/endpoint' -H 'Content-Type: application/json' -d '{{\"param\":\"payload\"}}'",
    "remediation": "Specific technical fix with code example where applicable (e.g., 'Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))')",
    "references": ["https://cwe.mitre.org/data/definitions/{cwe_num}.html", "relevant OWASP link", "relevant CVEs if any"],
    "additional_notes": "Any extra context: WAF bypass technique used, chain potential, similar vulns on other endpoints"
}}

CRITICAL REQUIREMENTS:
- Be SPECIFIC: reference the actual URL, parameter, and payload — never use generic placeholders.
- Steps to reproduce must be copy-pasteable by a triager who knows nothing about the target.
- The curl_command must be complete and working (include auth headers if the vuln requires auth).
- Impact must describe real-world consequences with concrete examples (data types exposed, actions possible).
- Remediation must include at least one code example or specific configuration change.
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
        # Always include CWE and OWASP references
        default_refs = [f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"]
        if owasp_ref:
            default_refs.append(owasp_ref)
        all_refs = list(dict.fromkeys(refs + default_refs))  # dedupe preserving order
        refs_md = "\n".join(f"- {r}" for r in all_refs) if all_refs else ""
        curl = report_data.get("curl_command", "")
        additional = report_data.get("additional_notes", "")

        markdown = f"""## Summary

{report_data.get('summary', vuln.description or '')}

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Type** | {cwe_info['name']} |
| **CWE** | [{cwe_info['cwe']}](https://cwe.mitre.org/data/definitions/{cwe_num}.html) |
| **Severity** | {vuln.severity.value.capitalize()} |
| **CVSS Score** | {cvss_score or 'N/A'} ({cvss_rating_str}) |
| **CVSS Vector** | `{cvss_vector}` |
| **URL** | `{vuln.url}` |
| **Parameter** | `{vuln.parameter or 'N/A'}` |
| **Method** | {vuln.method or 'GET'} |

### Severity Justification

{report_data.get('severity_justification', '')}

## Steps to Reproduce

{steps_md}

{f"### cURL Command{chr(10)}{chr(10)}```bash{chr(10)}{curl}{chr(10)}```" if curl else ""}

## Impact

{report_data.get('impact', '')}

## Proof of Concept

{report_data.get('poc_description', '')}

{self._format_poc_data(vuln)}

## Remediation

{report_data.get('remediation', vuln.remediation or '')}

## References

{refs_md}
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1#{cvss_vector.replace('CVSS:3.1/', '')})

{f"## Additional Notes{chr(10)}{chr(10)}{additional}" if additional else ""}

---
*Report generated by PHANTOM — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*"""

        return {
            "source": "claude",
            "title": title,
            "severity": vuln.severity.value,
            "cwe": cwe_info["cwe"],
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_rating": cvss_rating_str,
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
        max_score = 120
        issues = []
        strengths = []

        # Has payload (15 pts)
        if vuln.payload_used:
            score += 15
            strengths.append("Working payload included")
        else:
            issues.append("No payload — report lacks concrete PoC")

        # Has request/response data (15+15+10 pts)
        if vuln.request_data:
            score += 15
            strengths.append("HTTP request data captured")
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
                strengths.append("Payload reflected in response — strong evidence")
        else:
            issues.append("No HTTP response data — no proof of exploitation")

        # Has AI validation (10 pts)
        if vuln.ai_confidence and vuln.ai_confidence > 0.7:
            score += 10
            strengths.append(f"High AI confidence ({vuln.ai_confidence:.0%})")
        elif vuln.ai_confidence and vuln.ai_confidence > 0.5:
            score += 5
        else:
            issues.append("Low AI confidence — consider manual verification")

        # CVSS calculated (10 pts)
        if vuln.cvss_score:
            score += 10
        else:
            # Auto-estimate from type
            cvss_type = VULN_TYPE_CVSS.get(vuln.vuln_type.value)
            if cvss_type:
                score += 5  # We can auto-fill it
            else:
                issues.append("No CVSS score — add for credibility")

        # Severity (5 pts)
        if vuln.severity.value in ("critical", "high"):
            score += 5
            strengths.append(f"{vuln.severity.value.capitalize()} severity — high bounty potential")
        elif vuln.severity.value == "info":
            issues.append("Info severity — unlikely to get bounty")

        # Has description (10 pts)
        if vuln.description and len(vuln.description) > 50:
            score += 10
        else:
            issues.append("Weak description — add more detail")

        # Impact statement (10 pts)
        if vuln.impact and len(vuln.impact) > 30:
            score += 10
        else:
            issues.append("No impact statement — critical for bounty")

        # Confirmed status (5 pts)
        if vuln.title and "[CONFIRMED]" in vuln.title:
            score += 5
            strengths.append("Vulnerability confirmed with exploitation proof")

        # Has CWE mapping (5 pts)
        vuln_type = vuln.vuln_type.value
        if VULN_TYPE_TO_CWE.get(vuln_type):
            score += 5
        else:
            issues.append(f"No CWE mapping for {vuln_type} — add for classification")

        # Normalize to 100
        normalized = min(int(score * 100 / max_score), 100)

        # Determine grade
        if normalized >= 80:
            grade = "A"
            verdict = "Ready to submit — strong report with solid evidence"
        elif normalized >= 60:
            grade = "B"
            verdict = "Good — fix minor issues before submitting"
        elif normalized >= 40:
            grade = "C"
            verdict = "Needs improvement — strengthen evidence and add PoC steps"
        else:
            grade = "D"
            verdict = "Not ready — needs significant work before submission"

        return {
            "score": normalized,
            "max_score": 100,
            "grade": grade,
            "verdict": verdict,
            "issues": issues,
            "strengths": strengths,
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
