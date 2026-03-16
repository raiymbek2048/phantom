"""
Claude Mentor — uses Anthropic Claude API for complex security analysis.

Used when:
- Local LLM confidence is low
- Complex vulnerability analysis needed
- 0-day pattern detection
- Training data generation for local model
"""
import anthropic
from app.config import get_settings

settings = get_settings()

SYSTEM_PROMPT = """You are an elite penetration testing AI mentor. You assist an autonomous security testing system called PHANTOM.

Your role:
1. Analyze complex security scenarios that the local AI cannot handle
2. Provide expert-level vulnerability analysis
3. Generate advanced attack strategies
4. Help identify 0-day vulnerability patterns
5. Generate training data for the local model

Rules:
- Always respond in structured JSON when requested
- Be precise and actionable
- Consider WAF bypass techniques
- Think about chained attacks
- Assess real-world impact accurately
- This is authorized security testing only (bug bounty programs)"""


class ClaudeMentor:
    def __init__(self):
        self.client = None
        from app.ai.get_claude_key import make_anthropic_client
        self.client = make_anthropic_client(sync=False)
        self.model = settings.claude_model

    async def analyze(self, prompt: str) -> str:
        """Send complex analysis to Claude."""
        if not self.client:
            raise MentorError("Anthropic API key not configured")

        message = await self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    async def evaluate_finding(self, vulnerability_data: dict, db=None) -> dict:
        """Have Claude evaluate a potential vulnerability finding."""
        import json

        # RAG: Query knowledge base for context
        rag_context = ""
        if db:
            try:
                from app.models.knowledge import KnowledgePattern
                from sqlalchemy import select, and_
                vuln_type = vulnerability_data.get("vuln_type", "")

                # Get false positive patterns for this vuln type
                fp_result = await db.execute(
                    select(KnowledgePattern).where(
                        and_(
                            KnowledgePattern.pattern_type == "false_positive",
                            KnowledgePattern.vuln_type == vuln_type,
                        )
                    ).limit(5)
                )
                fps = fp_result.scalars().all()
                if fps:
                    fp_indicators = []
                    for fp in fps:
                        indicators = (fp.pattern_data or {}).get("indicators", [])
                        fp_indicators.extend(indicators[:3])
                    if fp_indicators:
                        rag_context += f"\n\nKNOWN FALSE POSITIVE PATTERNS for {vuln_type}:\n"
                        rag_context += "\n".join(f"- {i}" for i in fp_indicators[:5])

                # Get similar past findings
                similar = await db.execute(
                    select(KnowledgePattern).where(
                        and_(
                            KnowledgePattern.pattern_type == "tech_vuln_correlation",
                            KnowledgePattern.vuln_type == vuln_type,
                            KnowledgePattern.confidence > 0.3,
                        )
                    ).order_by(KnowledgePattern.confidence.desc()).limit(3)
                )
                correlations = similar.scalars().all()
                if correlations:
                    rag_context += f"\n\nHISTORICAL DATA for {vuln_type}:\n"
                    for c in correlations:
                        d = c.pattern_data or {}
                        rag_context += f"- On {c.technology}: {d.get('success_rate', 0):.0%} success rate ({d.get('scans_tested', 0)} scans)\n"
            except Exception:
                pass

        prompt = f"""Evaluate this potential security vulnerability finding:

{json.dumps(vulnerability_data, indent=2, default=str)}
{rag_context}

Provide your assessment in JSON:
{{
    "is_valid": true/false,
    "confidence": 0.0-1.0,
    "severity_assessment": "critical/high/medium/low/info",
    "cvss_score": 0.0-10.0,
    "impact_analysis": "description of real-world impact",
    "exploitation_difficulty": "easy/medium/hard",
    "false_positive_risk": "low/medium/high",
    "recommended_payload_improvements": ["suggestion1", "suggestion2"],
    "report_title_suggestion": "concise vulnerability title",
    "remediation": "how to fix"
}}"""

        result = await self.analyze(prompt)
        try:
            if "```json" in result:
                result = result.split("```json")[1].split("```")[0]
            return json.loads(result.strip())
        except (json.JSONDecodeError, IndexError):
            return {"is_valid": False, "confidence": 0.0, "raw": result}

    async def generate_training_data(self, scenario: dict) -> list[dict]:
        """Generate Q&A training pairs for fine-tuning the local model."""
        import json
        prompt = f"""Based on this penetration testing scenario, generate 5 training Q&A pairs
for fine-tuning a local security AI model.

Scenario:
{json.dumps(scenario, indent=2, default=str)}

Generate pairs in this format:
[
    {{
        "instruction": "the question or task",
        "input": "context data",
        "output": "expected expert response"
    }}
]

Focus on:
- Vulnerability identification from HTTP responses
- Payload generation for specific contexts
- WAF bypass techniques
- Impact assessment
- Attack chain planning"""

        result = await self.analyze(prompt)
        try:
            if "```json" in result:
                result = result.split("```json")[1].split("```")[0]
            return json.loads(result.strip())
        except (json.JSONDecodeError, IndexError):
            return []

    async def analyze_zero_day_pattern(self, code_snippet: str, technology: str) -> dict:
        """Analyze code or behavior for potential 0-day vulnerability patterns."""
        import json
        prompt = f"""Analyze this code/behavior for potential unknown (0-day) vulnerability patterns.

Technology: {technology}
Code/Behavior:
{code_snippet[:5000]}

Look for:
1. Unusual input handling
2. Race conditions
3. Logic flaws
4. Memory safety issues
5. Deserialization issues
6. Authentication/authorization bypasses
7. Cryptographic weaknesses

Respond in JSON:
{{
    "potential_vulnerabilities": [
        {{
            "type": "vulnerability type",
            "description": "what was found",
            "confidence": 0.0-1.0,
            "exploitation_approach": "how to exploit",
            "test_payload": "payload to test with"
        }}
    ],
    "overall_risk": "low/medium/high/critical"
}}"""

        result = await self.analyze(prompt)
        try:
            if "```json" in result:
                result = result.split("```json")[1].split("```")[0]
            return json.loads(result.strip())
        except (json.JSONDecodeError, IndexError):
            return {"potential_vulnerabilities": [], "overall_risk": "unknown"}


class MentorError(Exception):
    pass
