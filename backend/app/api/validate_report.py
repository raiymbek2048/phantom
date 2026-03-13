"""
Report Validator Agent API — Multi-Round Deep Validation

AI-powered critical review of scan findings with multi-round analysis.
Each round uses a different expert angle, like a real pentesting team:
- Round 1: General triage — noise vs real vulns
- Round 2: IDOR & Access Control focus
- Round 3: Injection & RCE focus
- Round 4: Business logic & API abuse
- Round 5: Infrastructure & exposure (Swagger, Actuator, JWT)

Supports: ?rounds=N (1-10) or ?continuous=true (keeps going until no new insights)
"""
import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.models.user import User
from app.api.auth import get_current_user
from app.ai.llm_engine import LLMEngine

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Multi-Round Validation Angles ---

ROUND_ANGLES = [
    {
        "name": "General Triage",
        "focus": """You are doing a FIRST PASS triage of all findings.
Separate real vulnerabilities from noise. Flag obvious false positives.
Focus on: severity accuracy, false positive detection, noise removal.
Common noise: missing headers, CSP unsafe-inline (standard for React/Vue),
Slowloris (mitigated by proxies), server errors under load, version disclosure.""",
    },
    {
        "name": "IDOR & Access Control",
        "focus": """You are an IDOR and access control specialist. This is the #1 vulnerability class in real-world pentesting.
Look for:
- API endpoints with sequential/predictable IDs: /api/users/{id}, /api/orders/{id}, /api/documents/{id}
- Missing authorization checks on resource access
- Horizontal privilege escalation (user A accessing user B's data)
- Vertical privilege escalation (regular user → admin endpoints)
- Broken function-level authorization on /admin/*, /api/admin/*
- Mass Assignment: Can users set is_admin, role, price, balance fields?
- Object-level access control bypass via parameter tampering
If the scan found API endpoints but did NOT test for IDOR — that's a critical gap.""",
    },
    {
        "name": "Injection & RCE",
        "focus": """You are an injection specialist focusing on exploitation.
Look for:
- SQL injection — especially JPQL injection in Spring/Java apps (different syntax than MySQL)
- Second-order SQL injection in profile fields, search history
- NoSQL injection in MongoDB queries ($gt, $ne, $regex operators)
- Template injection (SSTI) — {{7*7}} in Jinja2, Thymeleaf, Freemarker
- OS command injection via filename, URL parameters, image processing
- XML External Entity (XXE) in file upload, SOAP endpoints
- LDAP injection in login/search functions
- Expression Language injection in Java EE apps
Verify: does the finding show ACTUAL data extraction or just error-based detection?""",
    },
    {
        "name": "Business Logic & API Abuse",
        "focus": """You are a business logic and API security expert.
Look for:
- Race conditions on payment/transfer/voting endpoints
- Price manipulation by modifying request parameters
- Coupon/discount code abuse and replay
- API rate limiting bypass (header manipulation, IP rotation, endpoint variation)
- GraphQL introspection enabled, batching attacks, nested query DoS
- Broken authentication flows: password reset token prediction, email verification bypass
- Session fixation, token leakage in URL/Referer
- Insecure Direct Object References in business operations (cancel order, modify profile)
- WebSocket security: authentication, message injection, CSWSH
- File upload bypass: polyglot files, double extensions, null bytes""",
    },
    {
        "name": "Infrastructure & Exposure",
        "focus": """You are an infrastructure and misconfiguration specialist.
Look for:
- Swagger UI / OpenAPI exposure: /swagger-ui.html, /swagger-ui/, /v2/api-docs, /v3/api-docs
- Spring Boot Actuator: /actuator, /actuator/env, /actuator/health, /actuator/configprops, /actuator/heapdump
- Debug endpoints: /debug, /trace, /metrics, /info, /jolokia
- JWT weak secrets: alg:none, weak HMAC keys (brutable), RS256→HS256 key confusion
- .env, .git, .DS_Store, backup files (.bak, .old, .swp) exposure
- Admin panels without proper auth: /admin, /panel, /dashboard, /phpmyadmin
- CORS misconfiguration: credentials with wildcard origin, origin reflection
- Subdomain takeover potential on dangling CNAMEs
- Cloud metadata exposure: 169.254.169.254, IMDS v1
- S3 bucket misconfiguration, Azure blob storage public access
Check: did the scanner actually TEST these paths or just report theoretical risks?""",
    },
    {
        "name": "Authentication & JWT Deep Dive",
        "focus": """You are an authentication and token security expert.
Focus exclusively on:
- JWT analysis: decode the token, check alg field, test alg:none, test HS256 with common secrets
- Session management: expiry, rotation after privilege change, secure/httponly/samesite flags
- Password policy: brute-force possible? Account lockout? Credential stuffing protection?
- OAuth/OIDC: redirect_uri validation, state parameter, token leakage
- MFA bypass techniques: backup code brute-force, MFA fatigue, TOTP window
- Password reset: token entropy, token reuse, rate limiting, user enumeration via timing
- Remember-me tokens: predictable? Long-lived? Revocable?
- API key exposure in client-side code, mobile apps, git history""",
    },
    {
        "name": "Spring/Java Specific",
        "focus": """You are a Spring/Java application security specialist.
This round ONLY applies if the target uses Java/Spring. If not, focus on the equivalent for the detected tech stack.
Look for:
- Spring Boot Actuator endpoints (especially /actuator/env, /actuator/heapdump)
- JPQL/HQL injection (different from standard SQL: 'OR 1=1' won't work, use 'OR ''=''')
- SpEL injection in Spring expressions
- Mass Assignment via @ModelAttribute, Jackson deserialization
- Spring Security misconfiguration: permitAll on sensitive endpoints
- Deserialization vulnerabilities (Java serialized objects, SnakeYAML, Jackson polymorphic)
- Log4Shell (Log4j) remnants
- Thymeleaf SSTI: __${T(java.lang.Runtime).getRuntime().exec('id')}__
For non-Java targets: focus on equivalent framework-specific attacks (Django, Rails, Express, Laravel).""",
    },
    {
        "name": "Synthesis & Final Assessment",
        "focus": """You are the LEAD PENTESTER writing the final assessment.
You have access to all previous rounds. Your job:
1. Merge and deduplicate findings from all angles
2. Assign FINAL severity based on exploitability + business impact
3. Create an attack chain: which findings combine for maximum impact?
4. Rate the OVERALL security posture honestly
5. List the TOP 3 things the target should fix IMMEDIATELY
6. Note if the automated scanner missed critical attack surfaces
Be brutally honest. If the target is reasonably secure, say so. If it's a disaster, say that too.""",
    },
]

VALIDATOR_BASE_PROMPT = """You are an experienced penetration tester and security consultant with 15+ years of experience.
You are reviewing an automated scan report. Your job is to be BRUTALLY HONEST.

CRITICAL KNOWLEDGE — What real pentesters find vs what scanners report:
- 90% of automated scanners inflate severity with headers, CSP, SSL, version disclosure
- Real #1 bug class: IDOR (Insecure Direct Object Reference) — accessing /api/users/2 as user 1
- Real #2: Broken Access Control — admin endpoints accessible by regular users
- Real #3: Injection with proof of data extraction, not just error messages
- Mass Assignment: sending extra fields (is_admin=true) in PUT/PATCH requests
- Swagger/Actuator exposure = instant critical if it leaks internal APIs or env vars
- JWT alg:none and weak HMAC secrets = authentication bypass
- JPQL injection syntax differs from MySQL — most scanners miss it entirely

NOISE you should ALWAYS flag:
- Missing security headers → hardening, NOT vulnerability
- CSP unsafe-inline/unsafe-eval → standard for React/Vue/Tailwind
- Slowloris → mitigated by nginx/Cloudflare
- Server errors under load → performance, not security
- COOP/COEP missing → only matters for SharedArrayBuffer
- Version disclosure → informational only
- Rate limiting on non-auth endpoints → low priority

{round_focus}

Respond in JSON:
{{
  "real_risk_score": <0-100>,
  "automated_risk_score": <0-100>,
  "overall_verdict": "<honest 2-3 sentence assessment>",
  "round_name": "<name of this validation round>",
  "findings_review": [
    {{
      "original_title": "<from scan>",
      "original_severity": "<from scan>",
      "real_severity": "<critical/high/medium/low/info/false_positive>",
      "is_real_vulnerability": <bool>,
      "is_false_positive": <bool>,
      "explanation": "<practical explanation>",
      "real_world_impact": "<what attacker could actually do>",
      "remediation_priority": "<immediate/short_term/nice_to_have/ignore>"
    }}
  ],
  "missing_checks": ["<what the scanner missed that a real pentester would test>"],
  "practical_recommendations": ["<ordered by actual impact>"],
  "red_flags": ["<findings that need immediate attention>"],
  "green_flags": ["<positive security aspects>"],
  "new_insights": ["<anything new this round discovered that previous rounds missed>"]
}}"""


@router.post("/scan/{scan_id}")
async def validate_scan_report(
    scan_id: str,
    rounds: int = Query(default=1, ge=1, le=10, description="Number of validation rounds (1-10)"),
    continuous: bool = Query(default=False, description="Keep validating until no new insights"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """AI agent critically reviews findings with multi-round deep analysis."""
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target = (await db.execute(select(Target).where(Target.id == scan.target_id))).scalar()

    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity)
    )
    vulns = result.scalars().all()

    if not vulns:
        return {
            "real_risk_score": 0,
            "automated_risk_score": 0,
            "overall_verdict": "No vulnerabilities found in this scan. Nothing to validate.",
            "findings_review": [],
            "missing_checks": [],
            "practical_recommendations": [],
            "red_flags": [],
            "green_flags": ["No vulnerabilities detected by automated scanning."],
            "rounds_completed": 0,
            "round_results": [],
        }

    # Limit findings to top 50 by severity to avoid token overflow
    MAX_FINDINGS = 50
    if len(vulns) > MAX_FINDINGS:
        logger.info(f"Limiting validation to top {MAX_FINDINGS} findings out of {len(vulns)}")
        vulns_for_review = sorted(vulns, key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(_sev(v), 5))[:MAX_FINDINGS]
    else:
        vulns_for_review = vulns

    findings_text = _build_findings_text(vulns_for_review, target)
    auto_score = _calculate_auto_risk_score(vulns)

    # Determine how many rounds to run
    if continuous:
        max_rounds = 8  # safety cap
    else:
        max_rounds = min(rounds, len(ROUND_ANGLES))

    # Run multi-round validation
    llm = LLMEngine()
    round_results = []
    accumulated_insights = []
    final_result = None

    try:
        for round_idx in range(max_rounds):
            angle = ROUND_ANGLES[round_idx % len(ROUND_ANGLES)]

            # Build context from previous rounds
            prev_context = ""
            if accumulated_insights:
                prev_context = f"\n\nINSIGHTS FROM PREVIOUS ROUNDS:\n" + "\n".join(
                    f"- Round {i+1} ({r['round_name']}): {'; '.join(r.get('new_insights', []))}"
                    for i, r in enumerate(round_results)
                    if r.get("new_insights")
                )

            prompt = VALIDATOR_BASE_PROMPT.format(round_focus=angle["focus"]) + f"""

Target: {target.domain if target else 'Unknown'}
Scan ID: {scan_id}
Scan Date: {scan.created_at.isoformat() if scan.created_at else 'Unknown'}
Total Findings: {len(vulns)}
Automated Risk Score: {auto_score}/100
Round: {round_idx + 1} of {max_rounds} — Focus: {angle['name']}

Severity Breakdown:
- Critical: {sum(1 for v in vulns if _sev(v) == 'critical')}
- High: {sum(1 for v in vulns if _sev(v) == 'high')}
- Medium: {sum(1 for v in vulns if _sev(v) == 'medium')}
- Low: {sum(1 for v in vulns if _sev(v) == 'low')}
- Info: {sum(1 for v in vulns if _sev(v) == 'info')}

Findings:
{findings_text}
{prev_context}

Review each finding through the lens of {angle['name']}. Be honest. Return ONLY valid JSON."""

            try:
                review = await llm.analyze_json(prompt, temperature=0.3 + (round_idx * 0.05), max_tokens=8192)
                review["round_name"] = angle["name"]
                review["round_number"] = round_idx + 1
                round_results.append(review)

                new_insights = review.get("new_insights", [])
                accumulated_insights.extend(new_insights)

                # In continuous mode, stop if no new insights
                if continuous and round_idx > 0 and not new_insights:
                    logger.info(f"Continuous validation: no new insights in round {round_idx + 1}, stopping")
                    break

            except Exception as e:
                logger.warning(f"Round {round_idx + 1} ({angle['name']}) failed: {e}")
                # Use fallback for this round
                fb = _fallback_validation_round(vulns, target, scan_id, auto_score, angle["name"])
                fb["round_number"] = round_idx + 1
                round_results.append(fb)

                if continuous and round_idx > 0:
                    break

        # Merge all rounds into final result
        final_result = _merge_round_results(round_results, vulns, target, scan_id, auto_score)

    except Exception as e:
        logger.error(f"Multi-round validation failed: {e}")
        final_result = _fallback_validation(vulns, target, scan_id, auto_score)
    finally:
        await llm.close()

    return final_result


@router.post("/target/{target_id}")
async def validate_target_report(
    target_id: str,
    rounds: int = Query(default=1, ge=1, le=10),
    continuous: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """AI agent reviews all findings for a target across all scans."""
    target = (await db.execute(select(Target).where(Target.id == target_id))).scalar()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    latest_scan = (await db.execute(
        select(Scan)
        .where(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )).scalar()

    if not latest_scan:
        raise HTTPException(status_code=404, detail="No scans found for target")

    return await validate_scan_report(str(latest_scan.id), rounds, continuous, db, user)


def _sev(v: Vulnerability) -> str:
    s = v.severity
    return s.value.lower() if hasattr(s, "value") else str(s).lower()


def _vtype(v: Vulnerability) -> str:
    vt = v.vuln_type
    return vt.value if hasattr(vt, "value") else str(vt)


def _build_findings_text(vulns: list[Vulnerability], target) -> str:
    lines = []
    for i, v in enumerate(vulns, 1):
        severity = _sev(v)
        vuln_type = _vtype(v)
        lines.append(f"""
--- Finding #{i} ---
Title: {v.title}
Severity: {severity.upper()}
Type: {vuln_type}
URL: {v.url}
Method: {v.method or 'GET'}
Parameter: {v.parameter or 'N/A'}
Payload: {v.payload_used or 'N/A'}
Impact: {v.impact or 'N/A'}
Remediation: {v.remediation or 'N/A'}
AI Confidence: {v.ai_confidence or 'N/A'}
CVSS: {v.cvss_score or 'N/A'}
Response Preview: {json.dumps(v.response_data, default=str)[:300] if v.response_data else 'N/A'}
""")
    return "\n".join(lines)


def _calculate_auto_risk_score(vulns: list[Vulnerability]) -> int:
    score = 0
    for v in vulns:
        sev = _sev(v)
        if sev == "critical":
            score += 25
        elif sev == "high":
            score += 15
        elif sev == "medium":
            score += 8
        elif sev == "low":
            score += 3
        elif sev == "info":
            score += 1
    return min(score, 100)


def _merge_round_results(round_results: list, vulns, target, scan_id, auto_score) -> dict:
    """Merge findings from multiple validation rounds into a final assessment."""
    if not round_results:
        return _fallback_validation(vulns, target, scan_id, auto_score)

    # Use the last round's risk score as the most refined
    final_risk = round_results[-1].get("real_risk_score", auto_score)

    # Average risk scores across rounds for stability
    avg_risk = sum(r.get("real_risk_score", auto_score) for r in round_results) // len(round_results)
    # Weight: 60% last round, 40% average
    real_risk = int(final_risk * 0.6 + avg_risk * 0.4)

    # Merge findings — use the most specific/detailed assessment per finding
    findings_by_title = {}
    for r in round_results:
        for f in r.get("findings_review", []):
            title = f.get("original_title", "")
            existing = findings_by_title.get(title)
            if not existing:
                findings_by_title[title] = f
            else:
                # Prefer the finding with more specific analysis
                if len(f.get("explanation", "")) > len(existing.get("explanation", "")):
                    # Keep the best severity assessment (most conservative)
                    f["_round_severities"] = existing.get("_round_severities", []) + [f.get("real_severity")]
                    findings_by_title[title] = f
                else:
                    existing["_round_severities"] = existing.get("_round_severities", []) + [f.get("real_severity")]

    merged_findings = list(findings_by_title.values())
    # Clean up internal fields
    for f in merged_findings:
        f.pop("_round_severities", None)

    # Collect all unique missing checks, recommendations, flags, insights
    all_missing = []
    all_recommendations = []
    all_red_flags = []
    all_green_flags = []
    all_insights = []
    seen_missing = set()
    seen_recs = set()

    for r in round_results:
        for item in r.get("missing_checks", []):
            if item and item.lower() not in seen_missing:
                seen_missing.add(item.lower())
                all_missing.append(item)
        for item in r.get("practical_recommendations", []):
            if item and item.lower() not in seen_recs:
                seen_recs.add(item.lower())
                all_recommendations.append(item)
        all_red_flags.extend(r.get("red_flags", []))
        all_green_flags.extend(r.get("green_flags", []))
        all_insights.extend(r.get("new_insights", []))

    # Deduplicate flags
    all_red_flags = list(dict.fromkeys(f for f in all_red_flags if f))
    all_green_flags = list(dict.fromkeys(f for f in all_green_flags if f))
    all_insights = list(dict.fromkeys(i for i in all_insights if i))

    # Build combined verdict
    verdicts = [r.get("overall_verdict", "") for r in round_results if r.get("overall_verdict")]
    combined_verdict = verdicts[-1] if verdicts else "Multi-round validation complete."
    if len(round_results) > 1:
        combined_verdict += f" (Validated across {len(round_results)} expert angles)"

    return {
        "real_risk_score": real_risk,
        "automated_risk_score": auto_score,
        "scan_id": scan_id,
        "target_domain": target.domain if target else "Unknown",
        "total_findings": len(vulns),
        "validated_at": datetime.utcnow().isoformat(),
        "overall_verdict": combined_verdict,
        "findings_review": merged_findings,
        "missing_checks": all_missing,
        "practical_recommendations": all_recommendations,
        "red_flags": all_red_flags,
        "green_flags": all_green_flags,
        "rounds_completed": len(round_results),
        "round_results": [
            {
                "round_number": r.get("round_number", i + 1),
                "round_name": r.get("round_name", f"Round {i + 1}"),
                "real_risk_score": r.get("real_risk_score", 0),
                "verdict": r.get("overall_verdict", ""),
                "new_insights": r.get("new_insights", []),
                "findings_count": len(r.get("findings_review", [])),
            }
            for i, r in enumerate(round_results)
        ],
        "accumulated_insights": all_insights,
    }


# --- Noise/Real patterns for fallback ---

NOISE_PATTERNS = {
    "missing security header": {"real_severity": "info", "is_real": False, "priority": "nice_to_have",
        "explanation": "Missing headers are hardening recommendations, not vulnerabilities."},
    "missing cross-origin": {"real_severity": "info", "is_real": False, "priority": "ignore",
        "explanation": "COOP/COEP headers only needed for SharedArrayBuffer."},
    "unsafe-inline": {"real_severity": "low", "is_real": False, "priority": "nice_to_have",
        "explanation": "CSP unsafe-inline is standard for React/Vue/Tailwind. Not exploitable without XSS."},
    "unsafe-eval": {"real_severity": "low", "is_real": False, "priority": "nice_to_have",
        "explanation": "CSP unsafe-eval weakens CSP but needed by many JS libs. Only a risk if XSS exists."},
    "slowloris": {"real_severity": "low", "is_real": False, "priority": "nice_to_have",
        "explanation": "Slowloris mitigated by nginx, Cloudflare, HAProxy."},
    "server errors under": {"real_severity": "info", "is_real": False, "priority": "ignore",
        "explanation": "Performance/availability issue, not a security vulnerability."},
    "rate limit": {"real_severity": "low", "is_real": False, "priority": "nice_to_have",
        "explanation": "Missing rate limiting only critical on auth endpoints."},
    "large request": {"real_severity": "info", "is_real": False, "priority": "ignore",
        "explanation": "Accepting large payloads is default behavior."},
    "long query": {"real_severity": "info", "is_real": False, "priority": "ignore",
        "explanation": "Long query strings are normal."},
    "nested json": {"real_severity": "info", "is_real": False, "priority": "ignore",
        "explanation": "Processing nested JSON is standard behavior."},
    "version disclosure": {"real_severity": "info", "is_real": False, "priority": "nice_to_have",
        "explanation": "Server version in headers is informational."},
    "x-powered-by": {"real_severity": "info", "is_real": False, "priority": "nice_to_have",
        "explanation": "Technology disclosure. Remove for hardening but not a vulnerability."},
    "false positive": {"real_severity": "info", "is_real": False, "priority": "ignore",
        "explanation": "The scanner itself marked this as a false positive."},
}

REAL_VULN_PATTERNS = {
    "sqli": {"bump": True, "explanation": "SQL injection is critical if confirmed with actual data extraction."},
    "xss": {"bump": True, "explanation": "XSS can steal sessions and user data if exploitable."},
    "rce": {"bump": True, "explanation": "Remote code execution = full server compromise."},
    "auth_bypass": {"bump": True, "explanation": "Authentication bypass grants unauthorized access."},
    "idor": {"bump": True, "explanation": "IDOR allows accessing other users' data — #1 real-world vuln class."},
    "ssrf": {"bump": True, "explanation": "SSRF can access internal services and cloud metadata."},
    "privilege escalation": {"bump": True, "explanation": "Privilege escalation grants admin access to regular users."},
    "mass assignment": {"bump": True, "explanation": "Mass assignment lets attackers set unauthorized fields (role, balance, admin)."},
    "jwt": {"bump": True, "explanation": "JWT weak secrets or alg:none = full authentication bypass."},
    "actuator": {"bump": True, "explanation": "Spring Actuator exposure leaks env vars, config, heap dumps."},
    "swagger": {"bump": True, "explanation": "Swagger/OpenAPI exposure reveals all internal API endpoints."},
    "deserialization": {"bump": True, "explanation": "Insecure deserialization can lead to RCE."},
}


def _fallback_validation_round(vulns, target, scan_id, auto_score, round_name) -> dict:
    """Lightweight fallback for a single round when AI fails."""
    return {
        "round_name": round_name,
        "real_risk_score": auto_score // 2,
        "automated_risk_score": auto_score,
        "overall_verdict": f"Round '{round_name}' used rule-based fallback (AI unavailable).",
        "findings_review": [],
        "missing_checks": [],
        "practical_recommendations": [],
        "red_flags": [],
        "green_flags": [],
        "new_insights": [f"AI unavailable for {round_name} — rule-based assessment used"],
    }


def _fallback_validation(vulns, target, scan_id, auto_score) -> dict:
    """Full rule-based validation when AI is completely unavailable."""
    findings_review = []
    real_vulns = 0
    false_positives = 0

    for v in vulns:
        title_lower = v.title.lower() if v.title else ""
        severity = _sev(v)
        vuln_type = _vtype(v)

        is_noise = False
        noise_info = None
        for pattern, info in NOISE_PATTERNS.items():
            if pattern in title_lower:
                is_noise = True
                noise_info = info
                break

        is_real_type = False
        real_info = None
        for pattern, info in REAL_VULN_PATTERNS.items():
            if pattern in vuln_type.lower() or pattern in title_lower:
                is_real_type = True
                real_info = info
                break

        if is_noise:
            false_positives += 1
            findings_review.append({
                "original_title": v.title,
                "original_severity": severity,
                "real_severity": noise_info["real_severity"],
                "is_real_vulnerability": False,
                "is_false_positive": noise_info["real_severity"] == "info",
                "explanation": noise_info["explanation"],
                "real_world_impact": "Minimal to none in practice.",
                "remediation_priority": noise_info["priority"],
            })
        elif is_real_type and "false positive" not in title_lower:
            real_vulns += 1
            findings_review.append({
                "original_title": v.title,
                "original_severity": severity,
                "real_severity": severity,
                "is_real_vulnerability": True,
                "is_false_positive": False,
                "explanation": real_info["explanation"],
                "real_world_impact": f"Potential {vuln_type} exploitation on {v.url}",
                "remediation_priority": "immediate" if severity in ("critical", "high") else "short_term",
            })
        else:
            findings_review.append({
                "original_title": v.title,
                "original_severity": severity,
                "real_severity": severity,
                "is_real_vulnerability": severity in ("critical", "high", "medium"),
                "is_false_positive": False,
                "explanation": f"Finding requires manual verification. Automated severity: {severity}.",
                "real_world_impact": "Needs manual verification to determine actual impact.",
                "remediation_priority": "short_term" if severity in ("critical", "high") else "nice_to_have",
            })

    if real_vulns == 0:
        real_score = max(5, len(vulns))
    else:
        real_score = min(real_vulns * 15 + len(vulns), 100)

    total = len(vulns)
    noise_pct = (false_positives / total * 100) if total > 0 else 0

    return {
        "real_risk_score": real_score,
        "automated_risk_score": auto_score,
        "scan_id": scan_id,
        "target_domain": target.domain if target else "Unknown",
        "total_findings": total,
        "validated_at": datetime.utcnow().isoformat(),
        "overall_verdict": (
            f"Out of {total} findings, {real_vulns} appear to be real vulnerabilities "
            f"and {false_positives} are noise/false positives ({noise_pct:.0f}% noise). "
            f"Real risk score: {real_score}/100 vs automated score: {auto_score}/100. "
            f"AI validation unavailable — this is a rule-based assessment."
        ),
        "findings_review": findings_review,
        "missing_checks": [
            "IDOR testing on /api/{resource}/{id} endpoints with different user contexts",
            "Mass Assignment testing on PUT/PATCH endpoints (is_admin, role, balance fields)",
            "Swagger/OpenAPI exposure check: /swagger-ui, /v2/api-docs, /v3/api-docs",
            "Spring Actuator endpoints: /actuator/env, /actuator/heapdump, /actuator/configprops",
            "JWT analysis: alg:none, weak HMAC secret brute-force, RS256→HS256 confusion",
            "Broken function-level authorization on /admin/* endpoints",
            "Business logic flaws: race conditions, price manipulation, workflow bypass",
            "Authentication flow: password reset token entropy, account lockout, credential stuffing",
            "File upload testing with polyglot payloads and double extensions",
            "WebSocket security testing: auth, injection, CSWSH",
        ],
        "practical_recommendations": [
            "Test ALL /api/{resource}/{id} endpoints for IDOR — this is the #1 real bug class",
            "Check for Swagger UI and Actuator exposure on standard paths",
            "Verify JWT implementation: decode tokens, test alg manipulation",
            "Test Mass Assignment on every update endpoint",
            "Add rate limiting specifically on authentication endpoints",
            "Review CORS: ensure credentials aren't reflected with arbitrary origins",
        ],
        "red_flags": [f.get("original_title") for f in findings_review if f.get("is_real_vulnerability")],
        "green_flags": (
            [f"Scanner found only noise — no real vulnerabilities detected ({noise_pct:.0f}% false positive rate)"]
            if real_vulns == 0 else []
        ),
        "rounds_completed": 1,
        "round_results": [{
            "round_number": 1,
            "round_name": "Rule-Based Fallback",
            "real_risk_score": real_score,
            "verdict": "AI unavailable, used rule-based assessment",
            "new_insights": [],
            "findings_count": len(findings_review),
        }],
        "accumulated_insights": [],
    }
