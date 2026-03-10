import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.vulnerability import Vulnerability, Severity, VulnStatus, VulnType
from app.models.user import User
from app.api.auth import get_current_user
from app.ai.llm_engine import LLMEngine

router = APIRouter()
logger = logging.getLogger(__name__)


class VulnStatusUpdate(BaseModel):
    status: VulnStatus
    bounty_amount: float | None = None


class BulkValidateRequest(BaseModel):
    target_id: str


class BulkCVSSRequest(BaseModel):
    target_id: str


@router.get("/compliance/summary")
async def compliance_summary(
    target_id: str | None = None,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate compliance summary across all vulns (or filtered by target/scan)."""
    query = select(Vulnerability)
    if target_id:
        query = query.where(Vulnerability.target_id == target_id)
    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)

    result = await db.execute(query)
    vulns = result.scalars().all()

    from app.core.compliance import get_compliance_summary
    vuln_dicts = [
        {"vuln_type": v.vuln_type.value, "title": v.title, "severity": v.severity.value}
        for v in vulns
    ]
    return get_compliance_summary(vuln_dicts)


@router.get("/export/{fmt}")
async def export_vulnerabilities(
    fmt: str,
    target_id: str | None = None,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export vulnerabilities as JSON or CSV."""
    if fmt not in ("json", "csv"):
        raise HTTPException(status_code=400, detail="Format must be 'json' or 'csv'")

    query = select(Vulnerability).order_by(Vulnerability.created_at.desc())
    if target_id:
        query = query.where(Vulnerability.target_id == target_id)
    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)

    result = await db.execute(query)
    vulns = result.scalars().all()

    if fmt == "json":
        from fastapi.responses import JSONResponse
        export = []
        for v in vulns:
            export.append({
                "id": v.id, "title": v.title, "url": v.url,
                "vuln_type": v.vuln_type.value, "severity": v.severity.value,
                "status": v.status.value, "method": v.method,
                "parameter": v.parameter, "payload_used": v.payload_used,
                "remediation": v.remediation, "created_at": str(v.created_at),
            })
        return JSONResponse(content=export, headers={
            "Content-Disposition": "attachment; filename=vulnerabilities.json",
        })

    # CSV
    import csv, io
    from fastapi.responses import StreamingResponse
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Title", "URL", "Type", "Severity", "Status", "Method", "Parameter", "Payload", "Remediation", "Created"])
    for v in vulns:
        writer.writerow([
            v.id, v.title, v.url, v.vuln_type.value, v.severity.value,
            v.status.value, v.method, v.parameter, v.payload_used,
            v.remediation, str(v.created_at),
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )


@router.get("")
async def list_vulnerabilities(
    severity: Severity | None = None,
    vuln_type: VulnType | None = None,
    status: VulnStatus | None = None,
    target_id: str | None = None,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(Vulnerability).order_by(Vulnerability.created_at.desc())

    if severity:
        query = query.where(Vulnerability.severity == severity)
    if vuln_type:
        query = query.where(Vulnerability.vuln_type == vuln_type)
    if status:
        query = query.where(Vulnerability.status == status)
    if target_id:
        query = query.where(Vulnerability.target_id == target_id)
    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)

    result = await db.execute(query)
    return result.scalars().all()


@router.post("/validate-all")
async def validate_all_vulnerabilities(
    body: BulkValidateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Validate all unvalidated (status=new) vulnerabilities for a target using AI."""
    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.target_id == body.target_id)
        .where(Vulnerability.status == VulnStatus.NEW)
    )
    vulns = result.scalars().all()

    if not vulns:
        return {"validated": 0, "confirmed": 0, "false_positives": 0, "message": "No unvalidated vulnerabilities found"}

    engine = LLMEngine()
    confirmed = 0
    false_positives = 0
    errors = 0

    try:
        for vuln in vulns:
            try:
                validation = await _validate_single_vuln(vuln, engine)
                # Save to DB
                existing_analysis = {}
                if vuln.ai_analysis:
                    try:
                        existing_analysis = json.loads(vuln.ai_analysis)
                    except (json.JSONDecodeError, TypeError):
                        existing_analysis = {"original": vuln.ai_analysis}

                existing_analysis["validation"] = validation
                vuln.ai_analysis = json.dumps(existing_analysis)

                if validation.get("is_valid", True):
                    vuln.status = VulnStatus.CONFIRMED
                    confirmed += 1
                else:
                    vuln.status = VulnStatus.FALSE_POSITIVE
                    false_positives += 1

                if validation.get("confidence"):
                    vuln.ai_confidence = validation["confidence"]

                await db.flush()
            except Exception as e:
                logger.error(f"Error validating vuln {vuln.id}: {e}")
                errors += 1
    finally:
        await engine.close()

    await db.commit()

    return {
        "validated": confirmed + false_positives,
        "confirmed": confirmed,
        "false_positives": false_positives,
        "errors": errors,
        "total_checked": len(vulns),
    }


@router.post("/calculate-cvss")
async def bulk_calculate_cvss(
    body: BulkCVSSRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Calculate CVSS 3.1 scores for all vulns of a target that don't have them yet."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.target_id == body.target_id)
    )
    vulns = result.scalars().all()

    if not vulns:
        return {"calculated": 0, "skipped": 0, "errors": 0, "message": "No vulnerabilities found for this target"}

    engine = LLMEngine()
    calculated = 0
    skipped = 0
    errors = 0

    try:
        for vuln in vulns:
            # Skip if already has CVSS data
            if vuln.ai_analysis:
                try:
                    existing = json.loads(vuln.ai_analysis)
                    if isinstance(existing, dict) and "cvss" in existing:
                        skipped += 1
                        continue
                except (json.JSONDecodeError, TypeError):
                    pass

            try:
                cvss_data = await _calculate_cvss_for_vuln(vuln, engine)

                # Save to ai_analysis
                existing_analysis = {}
                if vuln.ai_analysis:
                    try:
                        existing_analysis = json.loads(vuln.ai_analysis)
                    except (json.JSONDecodeError, TypeError):
                        existing_analysis = {"original": vuln.ai_analysis}

                existing_analysis["cvss"] = cvss_data
                vuln.ai_analysis = json.dumps(existing_analysis)

                # Update severity and cvss_score
                score = cvss_data.get("cvss_score", 0)
                vuln.cvss_score = score
                vuln.severity = _severity_from_cvss(score)

                await db.flush()
                calculated += 1
            except Exception as e:
                logger.error(f"Error calculating CVSS for vuln {vuln.id}: {e}")
                errors += 1
    finally:
        await engine.close()

    await db.commit()

    return {
        "calculated": calculated,
        "skipped": skipped,
        "errors": errors,
        "total": len(vulns),
    }


VULN_TRANSITIONS = {
    VulnStatus.NEW: [VulnStatus.TRIAGED, VulnStatus.FALSE_POSITIVE, VulnStatus.CONFIRMED],
    VulnStatus.TRIAGED: [VulnStatus.CONFIRMED, VulnStatus.FALSE_POSITIVE],
    VulnStatus.CONFIRMED: [VulnStatus.REPORTED, VulnStatus.FIXED, VulnStatus.FALSE_POSITIVE],
    VulnStatus.REPORTED: [VulnStatus.FIXED, VulnStatus.BOUNTY_RECEIVED],
    VulnStatus.FIXED: [VulnStatus.VERIFIED, VulnStatus.CONFIRMED],
    VulnStatus.VERIFIED: [],
    VulnStatus.BOUNTY_RECEIVED: [VulnStatus.VERIFIED],
    VulnStatus.FALSE_POSITIVE: [VulnStatus.NEW],
}


@router.get("/lifecycle")
async def get_lifecycle_info(
    user: User = Depends(get_current_user),
):
    """Return the vulnerability lifecycle states and allowed transitions."""
    return {
        "states": [s.value for s in VulnStatus],
        "transitions": {k.value: [v.value for v in vs] for k, vs in VULN_TRANSITIONS.items()},
    }


@router.post("/{vuln_id}/transition")
async def transition_vulnerability(
    vuln_id: str,
    new_status: VulnStatus,
    reason: str | None = Query(None, description="Reason for the transition (stored for FP learning)"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Move a vulnerability to the next lifecycle state (validates transitions)."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    allowed = VULN_TRANSITIONS.get(vuln.status, [])
    if new_status not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot transition from {vuln.status.value} to {new_status.value}. Allowed: {[a.value for a in allowed]}"
        )

    old_status = vuln.status.value
    vuln.status = new_status
    await db.flush()

    # Record false positive pattern in KnowledgeBase for future scan filtering
    fp_recorded = False
    if new_status == VulnStatus.FALSE_POSITIVE:
        try:
            from app.core.knowledge import KnowledgeBase
            kb = KnowledgeBase()

            # Extract meaningful indicators from the vulnerability
            indicators = _extract_fp_indicators(vuln, reason)
            for indicator in indicators:
                await kb.record_false_positive(
                    db=db,
                    vuln_type=vuln.vuln_type.value,
                    indicator=indicator,
                )
            fp_recorded = bool(indicators)
            logger.info(f"FP feedback: recorded {len(indicators)} patterns for vuln {vuln.id} ({vuln.vuln_type.value})")
        except Exception as e:
            logger.error(f"Failed to record FP pattern for vuln {vuln.id}: {e}")

    await db.commit()

    resp = {
        "id": vuln.id,
        "old_status": old_status,
        "new_status": new_status.value,
        "allowed_next": [t.value for t in VULN_TRANSITIONS.get(new_status, [])],
    }
    if fp_recorded:
        resp["fp_patterns_recorded"] = True
    return resp


def _extract_fp_indicators(vuln: Vulnerability, reason: str | None = None) -> list[str]:
    """Extract meaningful false-positive indicators from a vulnerability.

    Returns a list of indicator strings that will be stored in the KnowledgeBase
    and matched against future findings to filter likely false positives.
    """
    indicators = []

    # 1. User-provided reason (highest value)
    if reason:
        indicators.append(f"reason:{reason}")

    # 2. URL path pattern — extract the path and generalize it
    url = vuln.url or ""
    if url:
        from urllib.parse import urlparse
        try:
            path = urlparse(url).path or "/"
            # Store the exact path as an indicator
            indicators.append(f"url_path:{path}")
        except Exception:
            pass

    # 3. Title pattern — the scan-generated title often encodes the detection logic
    title = vuln.title or ""
    if title:
        indicators.append(f"title:{title}")

    # 4. Payload pattern — what payload triggered the false alert
    payload = vuln.payload_used or ""
    if payload:
        indicators.append(f"payload:{payload}")

    return indicators


@router.get("/{vuln_id}")
async def get_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.put("/{vuln_id}")
async def update_vulnerability(
    vuln_id: str,
    update: VulnStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.status = update.status
    if update.bounty_amount is not None:
        vuln.bounty_amount = update.bounty_amount
    await db.flush()
    return vuln


@router.post("/{vuln_id}/validate")
async def validate_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Use AI (Claude/Ollama) to analyze if a vulnerability is real or a false positive."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    engine = LLMEngine()
    try:
        validation = await _validate_single_vuln(vuln, engine)
    except Exception as e:
        logger.error(f"Validation failed for {vuln_id}: {e}")
        raise HTTPException(status_code=500, detail=f"AI validation failed: {str(e)}")
    finally:
        await engine.close()

    # Merge validation into existing ai_analysis
    existing_analysis = {}
    if vuln.ai_analysis:
        try:
            existing_analysis = json.loads(vuln.ai_analysis)
        except (json.JSONDecodeError, TypeError):
            existing_analysis = {"original": vuln.ai_analysis}

    existing_analysis["validation"] = validation
    vuln.ai_analysis = json.dumps(existing_analysis)

    # Update status based on validation result
    if validation.get("is_valid", True):
        vuln.status = VulnStatus.CONFIRMED
    else:
        vuln.status = VulnStatus.FALSE_POSITIVE

    if validation.get("confidence"):
        vuln.ai_confidence = validation["confidence"]

    await db.flush()
    await db.commit()

    return {
        "vuln_id": vuln.id,
        "status": vuln.status.value,
        "validation": validation,
    }


@router.post("/{vuln_id}/cvss")
async def calculate_cvss(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Calculate CVSS 3.1 vector and score for a vulnerability using AI (Claude/Ollama)."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    engine = LLMEngine()
    try:
        cvss_data = await _calculate_cvss_for_vuln(vuln, engine)
    except Exception as e:
        logger.error(f"CVSS calculation failed for {vuln_id}: {e}")
        raise HTTPException(status_code=500, detail=f"CVSS calculation failed: {str(e)}")
    finally:
        await engine.close()

    # Save CVSS data into ai_analysis JSON under key "cvss"
    existing_analysis = {}
    if vuln.ai_analysis:
        try:
            existing_analysis = json.loads(vuln.ai_analysis)
        except (json.JSONDecodeError, TypeError):
            existing_analysis = {"original": vuln.ai_analysis}

    existing_analysis["cvss"] = cvss_data
    vuln.ai_analysis = json.dumps(existing_analysis)

    # Update severity based on CVSS score
    score = cvss_data.get("cvss_score", 0)
    vuln.cvss_score = score
    vuln.severity = _severity_from_cvss(score)

    await db.flush()
    await db.commit()

    return {
        "vuln_id": vuln.id,
        "severity": vuln.severity.value,
        "cvss": cvss_data,
    }


@router.get("/{vuln_id}/poc")
async def get_poc(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return {
        "payload_used": vuln.payload_used,
        "request_data": vuln.request_data,
        "response_data": vuln.response_data,
        "screenshots": vuln.screenshots,
    }


@router.get("/{vuln_id}/hackerone")
async def get_hackerone_report(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate Claude-powered HackerOne report with duplicate check and quality scoring."""
    from app.core.h1_report_generator import H1ReportGenerator
    generator = H1ReportGenerator(db)
    try:
        result = await generator.generate_report(vuln_id)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    finally:
        await generator.close()


@router.get("/{vuln_id}/hackerone/quick")
async def get_hackerone_report_quick(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate template-based HackerOne report (fast, no AI)."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from app.modules.hackerone_report import generate_hackerone_report
    return generate_hackerone_report({
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
        "description": getattr(vuln, "description", ""),
    })


@router.post("/{vuln_id}/reverify")
async def reverify_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Re-test a vulnerability to check if it's still exploitable."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    import httpx
    try:
        url = vuln.url
        method = vuln.method or "GET"
        payload = vuln.payload_used or ""

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            if method.upper() == "POST":
                param = vuln.parameter or ""
                resp = await client.post(url, data={param: payload} if param else {})
            else:
                resp = await client.get(url)

            # Check if vuln indicators are still present
            body = resp.text
            still_vulnerable = False
            vuln_type = vuln.vuln_type.value

            if vuln_type in ("xss_reflected", "xss_stored", "xss_dom"):
                still_vulnerable = payload in body if payload else False
            elif vuln_type == "sqli":
                still_vulnerable = any(ind in body for ind in ("error in your SQL", "mysql_", "syntax error", "ORA-", "UNION"))
            elif vuln_type == "cmd_injection":
                still_vulnerable = any(ind in body for ind in ("uid=", "root:", "www-data", "Windows"))
            elif vuln_type == "info_disclosure":
                still_vulnerable = resp.status_code == 200
            elif vuln_type == "csrf":
                still_vulnerable = resp.status_code == 200
            else:
                still_vulnerable = resp.status_code == 200 and len(body) > 100

            new_status = "confirmed" if still_vulnerable else "fixed"
            vuln.status = VulnStatus(new_status)
            await db.flush()

            return {
                "id": vuln.id,
                "still_vulnerable": still_vulnerable,
                "status": new_status,
                "response_code": resp.status_code,
                "response_length": len(body),
            }
    except Exception as e:
        return {
            "id": vuln.id,
            "still_vulnerable": None,
            "status": "error",
            "error": str(e),
        }


@router.get("/{vuln_id}/compliance")
async def get_vuln_compliance(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get compliance mapping for a vulnerability (OWASP, CWE, PCI DSS, NIST)."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from app.core.compliance import get_compliance_for_vuln
    return {
        "vuln_id": vuln.id,
        "vuln_type": vuln.vuln_type.value,
        "compliance": get_compliance_for_vuln(vuln.vuln_type.value),
    }


async def _validate_single_vuln(vuln: Vulnerability, engine: LLMEngine) -> dict:
    """Build a prompt and ask the AI to validate a single vulnerability."""
    # Truncate response data for the prompt
    response_snippet = ""
    if vuln.response_data:
        resp_body = vuln.response_data.get("body", "") if isinstance(vuln.response_data, dict) else str(vuln.response_data)
        response_snippet = resp_body[:1500]

    prompt = f"""Analyze this vulnerability finding and determine if it is a TRUE positive (real vulnerability) or FALSE positive (not exploitable / not a real issue).

VULNERABILITY DETAILS:
- Type: {vuln.vuln_type.value}
- Title: {vuln.title}
- URL: {vuln.url}
- HTTP Method: {vuln.method or "unknown"}
- Parameter: {vuln.parameter or "none"}
- Payload Used: {vuln.payload_used or "none"}
- Current Severity: {vuln.severity.value}
- Description: {vuln.description[:1000] if vuln.description else "none"}

RESPONSE SNIPPET:
{response_snippet or "No response data available"}

REQUEST DATA:
{json.dumps(vuln.request_data, default=str)[:1000] if vuln.request_data else "No request data available"}

Evaluate this finding carefully. Consider:
1. Does the payload actually execute/trigger in the response?
2. Is the vulnerability type correctly identified?
3. Could this be a scanner false positive (e.g., reflected text that isn't actually executable)?
4. What is the real-world exploitability?
5. Is the severity rating appropriate?

Respond with ONLY this JSON structure:
{{
    "is_valid": true or false,
    "confidence": 0.0 to 1.0,
    "adjusted_severity": "critical" or "high" or "medium" or "low" or "info",
    "reasoning": "2-3 sentence explanation of your assessment"
}}"""

    result = await engine.analyze_json(prompt, temperature=0.2)

    # Normalize and validate the result
    validation = {
        "is_valid": bool(result.get("is_valid", True)),
        "confidence": min(1.0, max(0.0, float(result.get("confidence", 0.5)))),
        "adjusted_severity": result.get("adjusted_severity", vuln.severity.value),
        "reasoning": str(result.get("reasoning", "No reasoning provided")),
        "validated_at": datetime.utcnow().isoformat(),
    }

    return validation


def _severity_from_cvss(score: float) -> Severity:
    """Map a CVSS 3.1 numeric score to a Severity enum value."""
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score >= 0.1:
        return Severity.LOW
    return Severity.INFO


async def _calculate_cvss_for_vuln(vuln: Vulnerability, engine: LLMEngine) -> dict:
    """Build a prompt and ask the AI to calculate CVSS 3.1 for a vulnerability."""
    response_snippet = ""
    if vuln.response_data:
        resp_body = vuln.response_data.get("body", "") if isinstance(vuln.response_data, dict) else str(vuln.response_data)
        response_snippet = resp_body[:1000]

    prompt = f"""You are a CVSS 3.1 scoring expert. Calculate the precise CVSS 3.1 Base Score for this vulnerability.

VULNERABILITY DETAILS:
- Type: {vuln.vuln_type.value}
- Title: {vuln.title}
- URL: {vuln.url}
- HTTP Method: {vuln.method or "unknown"}
- Parameter: {vuln.parameter or "none"}
- Payload Used: {vuln.payload_used or "none"}
- Current Severity: {vuln.severity.value}
- Description: {vuln.description[:1000] if vuln.description else "none"}
- Impact: {(vuln.impact or "")[:500]}

RESPONSE SNIPPET:
{response_snippet or "No response data available"}

Calculate the CVSS 3.1 Base Score by evaluating each metric:

- Attack Vector (AV): Network (N), Adjacent (A), Local (L), Physical (P)
- Attack Complexity (AC): Low (L), High (H)
- Privileges Required (PR): None (N), Low (L), High (H)
- User Interaction (UI): None (N), Required (R)
- Scope (S): Unchanged (U), Changed (C)
- Confidentiality Impact (C): None (N), Low (L), High (H)
- Integrity Impact (I): None (N), Low (L), High (H)
- Availability Impact (A): None (N), Low (L), High (H)

The CVSS vector string must follow the format: CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X
The score must be calculated according to the official CVSS 3.1 specification.

Respond with ONLY this JSON structure:
{{
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "cvss_score": 6.1,
    "severity": "medium",
    "attack_vector": "Network",
    "attack_complexity": "Low",
    "privileges_required": "None",
    "user_interaction": "Required",
    "scope": "Changed",
    "confidentiality": "Low",
    "integrity": "Low",
    "availability": "None",
    "reasoning": "Brief explanation of the scoring rationale"
}}"""

    result = await engine.analyze_json(prompt, temperature=0.2)

    # Validate and normalize the CVSS vector
    cvss_vector = result.get("cvss_vector", "")
    if not cvss_vector.startswith("CVSS:3.1/"):
        # Try to fix common issues
        if cvss_vector.startswith("CVSS:3.0/"):
            cvss_vector = "CVSS:3.1/" + cvss_vector[9:]
        elif "/" in cvss_vector and "AV:" in cvss_vector:
            cvss_vector = "CVSS:3.1/" + cvss_vector.split("/", 1)[-1] if "CVSS" in cvss_vector else "CVSS:3.1/" + cvss_vector

    # Ensure score is a valid float
    try:
        cvss_score = round(float(result.get("cvss_score", 0)), 1)
        cvss_score = max(0.0, min(10.0, cvss_score))
    except (ValueError, TypeError):
        cvss_score = 0.0

    # Map score to severity string
    if cvss_score >= 9.0:
        severity_str = "critical"
    elif cvss_score >= 7.0:
        severity_str = "high"
    elif cvss_score >= 4.0:
        severity_str = "medium"
    elif cvss_score >= 0.1:
        severity_str = "low"
    else:
        severity_str = "info"

    cvss_data = {
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "severity": severity_str,
        "attack_vector": str(result.get("attack_vector", "Unknown")),
        "attack_complexity": str(result.get("attack_complexity", "Unknown")),
        "privileges_required": str(result.get("privileges_required", "Unknown")),
        "user_interaction": str(result.get("user_interaction", "Unknown")),
        "scope": str(result.get("scope", "Unknown")),
        "confidentiality": str(result.get("confidentiality", "Unknown")),
        "integrity": str(result.get("integrity", "Unknown")),
        "availability": str(result.get("availability", "Unknown")),
        "reasoning": str(result.get("reasoning", "No reasoning provided")),
        "calculated_at": datetime.utcnow().isoformat(),
    }

    return cvss_data
