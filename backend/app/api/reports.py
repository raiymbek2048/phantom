import json
from datetime import datetime

import markdown
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.report import Report, ReportFormat
from app.models.vulnerability import Vulnerability, Severity
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.api.auth import get_current_user
from app.modules.reporter import VULN_TYPE_CWE, SEVERITY_CVSS, VULN_TYPE_CVSS

router = APIRouter()


class ReportGenerate(BaseModel):
    vulnerability_id: str
    format: ReportFormat = ReportFormat.GENERIC


@router.get("")
async def list_reports(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Report).order_by(Report.created_at.desc()))
    return result.scalars().all()


@router.post("/generate")
async def generate_report(
    data: ReportGenerate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == data.vulnerability_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from app.modules.reporter import ReportGenerator
    generator = ReportGenerator()
    content = await generator.generate(vuln, data.format)

    report = Report(
        target_id=vuln.target_id,
        scan_id=vuln.scan_id,
        vulnerability_id=vuln.id,
        title=vuln.title,
        format=data.format,
        content=content,
    )
    db.add(report)
    await db.flush()
    return report


@router.get("/scan/{scan_id}/html")
async def get_scan_report_html(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate a full HTML report for a scan with all vulnerabilities."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()

    vulns_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity)
    )
    vulns = vulns_result.scalars().all()

    html = _render_scan_report_html(scan, target, vulns)
    return HTMLResponse(content=html)


@router.get("/target/{target_id}/html")
async def get_target_report_html(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate a full HTML report for a target with all vulnerabilities across scans."""
    target_result = await db.execute(select(Target).where(Target.id == target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    vulns_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.target_id == target_id)
        .order_by(Vulnerability.severity)
    )
    vulns = vulns_result.scalars().all()

    scans_result = await db.execute(
        select(Scan)
        .where(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
    )
    latest_scan = scans_result.scalars().first()

    html = _render_scan_report_html(latest_scan, target, vulns)
    return HTMLResponse(content=html)


@router.get("/scan/{scan_id}/pdf")
async def get_scan_report_pdf(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate a PDF report for a scan."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()

    vulns_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity)
    )
    vulns = vulns_result.scalars().all()

    html = _render_scan_report_html(scan, target, vulns)
    pdf_bytes = _html_to_pdf(html)

    domain = target.domain if target else "unknown"
    filename = f"phantom-report-{domain}-{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/target/{target_id}/pdf")
async def get_target_report_pdf(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate a PDF report for a target."""
    target_result = await db.execute(select(Target).where(Target.id == target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    vulns_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.target_id == target_id)
        .order_by(Vulnerability.severity)
    )
    vulns = vulns_result.scalars().all()

    scans_result = await db.execute(
        select(Scan).where(Scan.target_id == target_id).order_by(Scan.created_at.desc())
    )
    latest_scan = scans_result.scalars().first()

    html = _render_scan_report_html(latest_scan, target, vulns)
    pdf_bytes = _html_to_pdf(html)

    filename = f"phantom-report-{target.domain}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _build_json_report(scan, target, vulns: list) -> dict:
    """Build structured JSON report for Tumar One bug bounty platform."""
    domain = target.domain if target else "unknown"

    # Scan metadata
    scan_duration = None
    if scan and scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        scan_duration = int(delta.total_seconds() / 60)

    scan_results = (scan.data if scan and hasattr(scan, 'data') and scan.data else {}) or {}
    recon_data = scan_results.get("recon_data") or scan_results.get("recon") or {}
    fingerprint_data = scan_results.get("fingerprint_data") or scan_results.get("fingerprint") or {}
    technologies = scan_results.get("technologies") or fingerprint_data.get("technologies") or []
    if isinstance(technologies, dict):
        technologies = list(technologies.keys())
    phases_completed = scan_results.get("phases_completed") or scan_results.get("completed_phases") or []
    target_ip = recon_data.get("ip") or recon_data.get("ip_address") or None
    if not target_ip:
        for rec in recon_data.get("dns_records", []):
            if rec.get("type") == "A":
                target_ip = rec.get("value")
                break

    # Severity / type counts
    severity_counts = {}
    type_counts = {}
    for v in vulns:
        sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        severity_counts[sev.lower()] = severity_counts.get(sev.lower(), 0) + 1
        vtype = v.vuln_type.value if hasattr(v.vuln_type, 'value') else str(v.vuln_type)
        type_counts[vtype] = type_counts.get(vtype, 0) + 1

    # Risk score
    risk_weights = {"critical": 40, "high": 25, "medium": 8, "low": 2, "info": 0}
    risk_score = sum(risk_weights.get(s, 0) * c for s, c in severity_counts.items())
    risk_score = min(risk_score, 100)

    # Build vulnerability list
    vuln_list = []
    for v in vulns:
        sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        vtype = v.vuln_type.value if hasattr(v.vuln_type, 'value') else str(v.vuln_type)
        cvss_info = _lookup_cvss(sev, vtype)
        cwe_id, cwe_name = _lookup_cwe(vtype)

        confirmed = False
        if v.title and "[CONFIRMED]" in v.title:
            confirmed = True

        resp_data = v.response_data if isinstance(v.response_data, dict) else {}
        confirmation = resp_data.get("confirmation", {}) if resp_data else {}

        poc = {
            "payload": v.payload_used or None,
            "request": v.request_data if isinstance(v.request_data, dict) else None,
            "response": resp_data or None,
            "confirmation": confirmation if confirmation else None,
        }

        repro_steps = _generate_repro_steps(v, vtype, v.payload_used or "")

        vuln_list.append({
            "id": str(v.id),
            "title": v.title or vtype,
            "type": vtype,
            "severity": sev.lower(),
            "cvss": {"score": cvss_info["score"], "vector": cvss_info["vector"]},
            "cwe": {"id": cwe_id, "name": cwe_name},
            "url": v.url or None,
            "parameter": v.parameter or None,
            "method": v.method or "GET",
            "description": v.description or None,
            "impact": v.impact if hasattr(v, 'impact') and v.impact else None,
            "remediation": v.remediation or _get_default_remediation(vtype),
            "steps_to_reproduce": repro_steps,
            "proof_of_concept": poc,
            "confidence": v.ai_confidence,
            "confirmed": confirmed,
            "found_at": v.created_at.isoformat() if v.created_at else None,
        })

    return {
        "report_format": "phantom_v1",
        "generated_at": datetime.utcnow().isoformat(),
        "target": {
            "domain": domain,
            "ip": target_ip,
            "technologies": technologies if isinstance(technologies, list) else [],
        },
        "scan": {
            "id": str(scan.id) if scan else None,
            "type": scan.scan_type if scan and hasattr(scan, 'scan_type') else "full",
            "started_at": scan.started_at.isoformat() if scan and scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan and scan.completed_at else None,
            "duration_minutes": scan_duration,
            "phases_completed": min(len(phases_completed), len(PIPELINE_PHASES)) if isinstance(phases_completed, list) else phases_completed,
            "total_phases": len(PIPELINE_PHASES),
            "risk_score": risk_score,
        },
        "summary": {
            "total_vulns": len(vulns),
            "by_severity": severity_counts,
            "by_type": type_counts,
        },
        "vulnerabilities": vuln_list,
    }


@router.get("/scan/{scan_id}/json")
async def get_scan_report_json(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export scan report as structured JSON for Tumar One bug bounty platform."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()

    vulns_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity)
    )
    vulns = vulns_result.scalars().all()

    report_data = _build_json_report(scan, target, vulns)
    domain = target.domain if target else "unknown"
    filename = f"phantom-report-{domain}-{scan_id[:8]}.json"

    return JSONResponse(
        content=report_data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/target/{target_id}/json")
async def get_target_report_json(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export target report as structured JSON for Tumar One bug bounty platform."""
    target_result = await db.execute(select(Target).where(Target.id == target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    vulns_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.target_id == target_id)
        .order_by(Vulnerability.severity)
    )
    vulns = vulns_result.scalars().all()

    scans_result = await db.execute(
        select(Scan).where(Scan.target_id == target_id).order_by(Scan.created_at.desc())
    )
    latest_scan = scans_result.scalars().first()

    report_data = _build_json_report(latest_scan, target, vulns)
    filename = f"phantom-report-{target.domain}.json"

    return JSONResponse(
        content=report_data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{report_id}")
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/html")
async def get_report_html(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get a single vulnerability report as HTML."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    md_html = markdown.markdown(report.content, extensions=["tables", "fenced_code"])
    html = _wrap_html(report.title, md_html)
    return HTMLResponse(content=html)


def _severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#2563eb",
        "INFO": "#6b7280",
    }
    return colors.get(severity.upper(), "#6b7280")


def _severity_order(sev: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(sev.upper() if isinstance(sev, str) else sev.value.upper(), 5)


PIPELINE_PHASES = [
    "Recon", "Subdomain Discovery", "Port Scan", "Fingerprint",
    "Attack Routing", "Auth Check", "Endpoint Discovery", "Browser Scan", "GraphQL Attacks", "Application Graph",
    "Stateful Crawling", "Auto Account Registration", "Sensitive Files",
    "Vulnerability Scan", "Nuclei Scan", "AI Analysis",
    "Payload Generation", "WAF Detection", "Exploit",
    "Service Attack", "Auth Attack", "Account Enumeration", "MFA Bypass", "Business Logic",
    "Financial Logic", "JWT Attacks", "Request Smuggling", "Mass Assignment", "Cache Poisoning",
    "Stress Test", "Vulnerability Confirmation",
    "Claude Collaboration", "AI Attack Planner", "Evidence Collection", "Report Generation",
]


def _lookup_cwe(vuln_type_str: str) -> tuple:
    """Look up CWE for a vuln type, trying full string first, then first part before underscore."""
    vt = vuln_type_str.lower()
    if vt in VULN_TYPE_CWE:
        return VULN_TYPE_CWE[vt]
    # Try prefix match: xss_stored -> xss, sqli_blind -> sqli
    short = vt.split("_")[0]
    if short in VULN_TYPE_CWE:
        return VULN_TYPE_CWE[short]
    # Try joining first two parts: cors_misconfiguration
    if "_" in vt:
        parts = vt.split("_")
        for i in range(len(parts), 0, -1):
            candidate = "_".join(parts[:i])
            if candidate in VULN_TYPE_CWE:
                return VULN_TYPE_CWE[candidate]
    return ("N/A", "N/A")


def _lookup_cvss(severity_str: str, vuln_type_str: str = "") -> dict:
    """Look up CVSS score/vector — type-specific first, then severity fallback."""
    vt = vuln_type_str.lower()
    if vt in VULN_TYPE_CVSS:
        return VULN_TYPE_CVSS[vt]
    return SEVERITY_CVSS.get(severity_str.lower(), SEVERITY_CVSS.get("medium", {"score": 5.3, "vector": "N/A"}))


def _generate_repro_steps(vuln, vuln_type: str, payload: str) -> list[str]:
    """Generate step-by-step reproduction instructions with exact details."""
    url = vuln.url or "TARGET_URL"
    method = vuln.method or "GET"
    param = vuln.parameter or ""
    steps = []

    if vuln_type in ("xss", "xss_reflected", "xss_stored", "xss_dom"):
        steps.append(f"Open a browser or HTTP client and send a {method} request to: {url}")
        if param and payload:
            steps.append(f"Set the '{param}' parameter to the XSS payload: {payload}")
        elif param:
            steps.append(f"Inject a script payload (e.g., <script>alert(document.domain)</script>) into the '{param}' parameter")
        elif payload:
            steps.append(f"Inject the payload: {payload}")
        steps.append("Submit the request and observe that the payload is reflected in the response HTML without encoding")
        steps.append("Open browser DevTools (F12) > Console tab and verify JavaScript execution")
    elif vuln_type in ("sqli", "sqli_blind"):
        steps.append(f"Send a {method} request to: {url}")
        if param and payload:
            steps.append(f"Set the '{param}' parameter to the SQL payload: {payload}")
        elif param:
            steps.append(f"Inject a single quote (') into the '{param}' parameter")
        steps.append("Observe SQL error messages, time-based delays, or different response behavior compared to a normal request")
        steps.append("Compare the response with param=1 (normal) vs param=1' (injected) to confirm behavioral difference")
    elif vuln_type == "idor":
        steps.append(f"Authenticate as User A and send a {method} request to: {url}")
        steps.append("Note the object ID/reference in the URL or request body")
        steps.append("Change the ID to another user's resource (e.g., increment by 1, or use a known different user's ID)")
        steps.append("Observe that User B's data is returned — the server performs no authorization check on the resource owner")
    elif vuln_type == "ssrf":
        steps.append(f"Send a {method} request to: {url}")
        if param and payload:
            steps.append(f"Set the '{param}' parameter to: {payload}")
        else:
            steps.append("Supply an internal URL (e.g., http://169.254.169.254/latest/meta-data/) as the URL parameter value")
        steps.append("Observe that the server fetches the internal resource and returns its contents in the response")
        steps.append("Verify internal/cloud metadata data in the response body")
    elif vuln_type == "auth_bypass":
        steps.append(f"Send a {method} request to: {url} WITHOUT authentication credentials (no Cookie, no Authorization header)")
        if payload:
            steps.append(f"Apply the bypass technique: {payload}")
        steps.append("Observe that the protected resource is accessible without valid authentication")
        steps.append("Compare response with and without authentication — both return the same sensitive data")
    elif vuln_type in ("lfi", "path_traversal"):
        steps.append(f"Send a {method} request to: {url}")
        if param and payload:
            steps.append(f"Set the '{param}' parameter to: {payload}")
        else:
            steps.append("Inject a path traversal payload (e.g., ../../../../etc/passwd) into the file/path parameter")
        steps.append("Observe the contents of the local file (e.g., /etc/passwd) in the response")
        steps.append("Verify that the response contains system file contents (root:x:0:0:...)")
    elif vuln_type == "ssti":
        steps.append(f"Send a {method} request to: {url}")
        if param and payload:
            steps.append(f"Set the '{param}' parameter to the template expression: {payload}")
        else:
            steps.append("Inject a template expression (e.g., {{7*7}}) into the vulnerable parameter")
        steps.append("Observe that the expression is evaluated server-side (e.g., '49' appears in the response)")
        steps.append("Escalate to code execution payload to confirm full SSTI (e.g., __import__('os').popen('id').read())")
    elif vuln_type in ("cmd_injection", "rce"):
        steps.append(f"Send a {method} request to: {url}")
        if param and payload:
            steps.append(f"Set the '{param}' parameter to: {payload}")
        else:
            steps.append("Inject an OS command (e.g., ;id or |whoami) into the vulnerable parameter")
        steps.append("Observe command output (e.g., uid=, username) in the response body")
        steps.append("Inject a unique marker command (e.g., echo UNIQUE_STRING) and verify it appears in the response")
    elif vuln_type == "csrf":
        steps.append(f"As an authenticated user, note your session cookie")
        steps.append(f"Create an HTML page with a form that auto-submits a {method} request to: {url}")
        steps.append("Host the malicious page on attacker.com and visit it while logged into the target")
        steps.append("Observe that the state-changing action is performed without any CSRF token validation")
    elif vuln_type in ("misconfiguration", "info_disclosure"):
        steps.append(f"Send a {method} request to: {url}")
        steps.append("Examine the response headers and body")
        steps.append("Note the exposed sensitive information (internal paths, API keys, stack traces, server versions, etc.)")
        steps.append("Verify the information can be leveraged for further attacks")
    elif vuln_type == "cors":
        steps.append(f"Send a {method} request to: {url} with header: Origin: https://attacker.com")
        steps.append("Observe the response contains: Access-Control-Allow-Origin: https://attacker.com")
        steps.append("Verify Access-Control-Allow-Credentials: true is also present")
        steps.append("This allows attacker.com to read authenticated responses cross-origin")
    elif vuln_type == "open_redirect":
        steps.append(f"Send a {method} request to: {url}")
        if param and payload:
            steps.append(f"Set the '{param}' parameter to: {payload}")
        else:
            steps.append("Set the redirect/url/next parameter to an attacker-controlled domain (e.g., https://evil.com)")
        steps.append("Observe a 3xx redirect to the attacker-controlled URL")
        steps.append("This can be used for phishing or OAuth token theft")
    elif vuln_type == "file_upload":
        steps.append(f"Navigate to the file upload form at: {url}")
        steps.append("Upload a file with a dangerous extension (e.g., shell.php, shell.jsp) containing a webshell or reverse shell")
        steps.append("Note the uploaded file location from the response")
        steps.append("Access the uploaded file URL and verify code execution")
    else:
        steps.append(f"Send a {method} request to: {url}")
        if payload:
            steps.append(f"Use the following payload: {payload}")
        if param:
            steps.append(f"Target the '{param}' parameter")
        steps.append("Observe the vulnerability in the server response")

    steps.append("Use the cURL command in the Proof of Concept section to reproduce programmatically")
    return steps


def _get_default_remediation(vuln_type: str) -> str:
    """Get default remediation advice with specific technical fixes."""
    remediations = {
        "xss": "Implement output encoding (HTML entity, JS, URL encoding as appropriate). Deploy a strict Content Security Policy (CSP) header. Use framework auto-escaping (React JSX, Django templates, Go html/template). Validate and sanitize all user input server-side.",
        "sqli": "Use parameterized queries (prepared statements) for all database operations. Example: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`. Never concatenate user input into SQL. Apply least privilege to database accounts.",
        "ssrf": "Implement URL allowlists for outbound requests. Validate and sanitize all URL inputs. Block requests to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254). Disable file://, gopher://, dict:// schemes.",
        "idor": "Implement authorization checks on every object access. Verify the authenticated user has permission to access the requested resource. Use indirect references (UUIDs) instead of sequential IDs. Example: `if resource.owner_id != current_user.id: return 403`.",
        "auth_bypass": "Implement proper authentication verification on every protected endpoint. Use established authentication frameworks. Enforce MFA. Validate tokens server-side on every request. Add authentication middleware to all protected routes.",
        "info_disclosure": "Remove sensitive data from responses. Use DTOs to control output fields. Disable debug mode and verbose errors in production. Remove server version headers (Server, X-Powered-By). Sanitize error responses.",
        "misconfiguration": "Review and harden server configuration per CIS benchmarks. Implement security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options: DENY, X-Content-Type-Options: nosniff. Remove default credentials.",
        "cmd_injection": "Never pass user input to system commands. Use language-native APIs instead of shell commands. If unavoidable, use strict allowlist validation. Example: `subprocess.run(['command', arg], shell=False)` instead of `os.system(f'command {user_input}')`.",
        "rce": "Eliminate code execution paths from user input. Use sandboxed execution environments. Apply the principle of least privilege to application processes. Disable dangerous functions (eval, exec, system).",
        "path_traversal": "Validate file paths against an allowlist. Use chroot or sandboxed file access. Resolve canonical paths and verify they stay within the intended directory. Example: `realpath = os.path.realpath(path); assert realpath.startswith(ALLOWED_DIR)`.",
        "cors": "Configure Access-Control-Allow-Origin to specific trusted domains only. Never reflect arbitrary origins. Do not combine wildcard origins with Access-Control-Allow-Credentials: true.",
        "lfi": "Validate file paths against a strict allowlist. Never pass user input directly to file system operations. Disable PHP wrappers (allow_url_include=Off). Use a file ID mapping instead of direct paths.",
        "ssti": "Never pass user input directly into template strings. Use sandboxed template rendering. Prefer logic-less templates (Mustache, Handlebars). Apply strict input validation. Example: use `render_template('page.html', name=user_input)` instead of `render_template_string(user_input)`.",
        "csrf": "Implement anti-CSRF tokens for all state-changing operations. Set `SameSite=Strict` or `SameSite=Lax` on session cookies. Verify Origin/Referer headers. Use framework-provided CSRF middleware.",
        "xxe": "Disable external entity processing in XML parsers. Example (Python): `parser = etree.XMLParser(resolve_entities=False, no_network=True)`. Use JSON instead of XML where possible.",
        "deserialization": "Avoid deserializing untrusted data. Use safe serialization formats (JSON). Implement integrity checks (HMAC) on serialized objects. Use allowlist-based deserialization filters.",
        "open_redirect": "Validate redirect URLs against an allowlist of trusted domains. Use relative paths instead of full URLs. Never use user input directly in Location headers. Example: `if not is_safe_url(redirect_url): redirect_url = '/'`.",
        "file_upload": "Validate file type using magic bytes (not just extension). Store uploads outside the webroot. Use a CDN or separate domain for serving uploads. Scan for malware. Randomize filenames.",
        "subdomain_takeover": "Remove dangling DNS records pointing to deprovisioned services. Monitor DNS records regularly. Implement subdomain inventory management.",
        "race_condition": "Use database-level locking (SELECT FOR UPDATE) or atomic operations. Implement idempotency keys. Use Redis distributed locks for critical sections.",
        "mass_assignment": "Use allowlists to define which fields can be set by user input. Never pass raw request data to model updates. Example: `user.update(name=data['name'])` instead of `user.update(**data)`.",
        "request_smuggling": "Normalize HTTP parsing between frontend and backend. Reject ambiguous requests with both Content-Length and Transfer-Encoding. Use HTTP/2 end-to-end.",
        "cache_poisoning": "Include all inputs that affect response content in the cache key. Validate Host and X-Forwarded-Host headers. Use Vary headers appropriately.",
        "account_enumeration": "Return identical responses for valid and invalid usernames. Use generic error messages ('Invalid credentials'). Implement rate limiting and CAPTCHA.",
        "mfa_bypass": "Implement MFA checks server-side before granting session access. Rate-limit MFA attempts. Invalidate MFA sessions on suspicious activity. Do not expose MFA state in client-side code.",
        "business_logic": "Implement server-side validation for all business rules. Do not rely on client-side controls. Add monitoring for anomalous transactions. Enforce rate limits on sensitive operations.",
    }
    return remediations.get(vuln_type, "Review and fix the identified vulnerability following OWASP guidelines for this vulnerability type. Implement input validation, output encoding, and proper access controls.")


def _render_scan_report_html(scan, target, vulns: list) -> str:
    domain = target.domain if target else "Unknown"
    scan_date = scan.created_at.strftime("%Y-%m-%d %H:%M") if scan else "N/A"
    scan_duration = ""
    if scan and scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        minutes = int(delta.total_seconds() / 60)
        scan_duration = f"{minutes} min"

    # Count by severity
    severity_counts = {}
    for v in vulns:
        sev = v.severity.value.upper() if hasattr(v.severity, 'value') else str(v.severity).upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Sort vulns by severity
    sorted_vulns = sorted(vulns, key=lambda v: _severity_order(
        v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
    ))

    # Build severity summary badges
    severity_badges = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = _severity_color(sev)
            severity_badges += f'<span class="badge" style="background:{color}">{sev}: {count}</span> '

    # Pluralize
    vuln_count_text = f"1 vulnerability" if len(vulns) == 1 else f"{len(vulns)} vulnerabilities"

    # Extract scan_results data safely
    scan_results = (scan.data if scan and hasattr(scan, 'data') and scan.data else {}) or {}
    recon_data = scan_results.get("recon_data") or scan_results.get("recon") or {}
    fingerprint_data = scan_results.get("fingerprint") or scan_results.get("fingerprint_data") or {}
    technologies = scan_results.get("technologies") or fingerprint_data.get("technologies") or []
    subdomains = scan_results.get("subdomains") or []
    open_ports = scan_results.get("open_ports") or []
    endpoints_data = scan_results.get("endpoints") or scan_results.get("endpoint") or {}
    endpoints_count = len(endpoints_data) if isinstance(endpoints_data, list) else endpoints_data.get("count", 0) if isinstance(endpoints_data, dict) else 0
    phases_completed = scan_results.get("phases_completed") or scan_results.get("completed_phases") or []

    # Extract IP from DNS A records in recon_data
    target_ip = recon_data.get("ip") or recon_data.get("ip_address") or ""
    if not target_ip:
        for rec in recon_data.get("dns_records", []):
            if rec.get("type") == "A":
                target_ip = rec.get("value", "")
                break

    # Calculate risk score
    risk_weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 8, "LOW": 2, "INFO": 0}
    risk_score = sum(risk_weights.get(s, 0) * c for s, c in severity_counts.items())
    risk_score = min(risk_score, 100)
    risk_level = "Critical" if risk_score >= 80 else "High" if risk_score >= 50 else "Medium" if risk_score >= 20 else "Low"
    risk_color = _severity_color(risk_level.upper())

    # Build vulnerability details
    vuln_rows = ""
    vuln_details = ""
    for i, v in enumerate(sorted_vulns, 1):
        sev = v.severity.value.upper() if hasattr(v.severity, 'value') else str(v.severity).upper()
        vtype = v.vuln_type.value if hasattr(v.vuln_type, 'value') else str(v.vuln_type)
        color = _severity_color(sev)

        cvss_info = _lookup_cvss(sev, vtype)
        cwe_info = _lookup_cwe(vtype)

        confirmed = "[CONFIRMED]" in (v.title or "")
        confirmed_badge = ' <span class="badge" style="background:#16a34a">CONFIRMED</span>' if confirmed else ""

        vuln_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{sev}</span></td>
            <td>{vtype}</td>
            <td><a href="#vuln-{i}">{v.title or vtype}</a></td>
            <td><code>{v.url or 'N/A'}</code></td>
            <td>{v.method or 'GET'}</td>
            <td>{cvss_info['score']}</td>
        </tr>"""

        # Detail section
        description = v.description or "Vulnerability confirmed by automated testing."
        remediation = v.remediation or _get_default_remediation(vtype)
        payload = v.payload_used or ""
        impact = v.impact if hasattr(v, 'impact') and v.impact else ""

        # --- Build full HTTP Request section ---
        request_info = ""
        if v.request_data:
            req = v.request_data if isinstance(v.request_data, dict) else {}
            req_method = req.get('method', v.method or 'GET')
            req_url = req.get('url', v.url or '')
            req_headers = req.get('headers', {})
            req_body = req.get('body', '')
            req_param = req.get('param', v.parameter or '')

            # Format as raw HTTP request
            raw_request_lines = [f"{req_method} {_escape_html(req_url)} HTTP/1.1"]
            if isinstance(req_headers, dict):
                for hk, hv in list(req_headers.items())[:15]:
                    raw_request_lines.append(f"{_escape_html(str(hk))}: {_escape_html(str(hv))}")
            if req_body:
                raw_request_lines.append("")
                raw_request_lines.append(_escape_html(str(req_body)[:1000]))
            raw_request = "\n".join(raw_request_lines)

            request_info = f"""
            <h4>HTTP Request</h4>
            <div class="code-block"><pre>{raw_request}</pre></div>"""

        # --- Build full HTTP Response section ---
        response_info = ""
        resp_data = v.response_data if isinstance(v.response_data, dict) else {}
        if resp_data:
            # Check for HTTP response at top level or nested under http_response key
            http_resp = resp_data.get("http_response", {}) if isinstance(resp_data.get("http_response"), dict) else {}
            status_code = resp_data.get("status_code", "") or http_resp.get("status_code", "")
            resp_headers = resp_data.get("headers", {}) or http_resp.get("headers", {})
            body_preview = str(resp_data.get("body_preview") or resp_data.get("body", "") or http_resp.get("body_preview", ""))[:1500]
            body_length = resp_data.get("body_length", "") or resp_data.get("content_length", "") or http_resp.get("content_length", "")

            raw_response_lines = []
            if status_code:
                raw_response_lines.append(f"HTTP/1.1 {status_code}")
            if isinstance(resp_headers, dict):
                for hk, hv in list(resp_headers.items())[:15]:
                    raw_response_lines.append(f"{_escape_html(str(hk))}: {_escape_html(str(hv))}")
            if body_preview:
                raw_response_lines.append("")
                raw_response_lines.append(_escape_html(body_preview))
            raw_response = "\n".join(raw_response_lines)

            if raw_response.strip():
                response_info = f"""
            <h4>HTTP Response{f' ({body_length} bytes)' if body_length else ''}</h4>
            <div class="code-block"><pre>{raw_response}</pre></div>"""

        # --- Confirmation proof ---
        confirmation_info = ""
        confirmation = resp_data.get("confirmation", {}) if resp_data else {}
        if confirmation and isinstance(confirmation, dict) and confirmation.get("confirmed"):
            proof = confirmation.get("proof", "")
            method_used = confirmation.get("method", "")
            depth = confirmation.get("exploitation_depth", "")
            extracted = confirmation.get("extracted_data", {})

            conf_lines = [f"<strong>Status:</strong> Confirmed via {_escape_html(method_used)}"]
            if depth:
                conf_lines.append(f"<strong>Exploitation Depth:</strong> {_escape_html(depth)}")
            if proof:
                conf_lines.append(f"<strong>Proof:</strong> {_escape_html(str(proof)[:500])}")
            if extracted and isinstance(extracted, dict):
                for ek, ev in list(extracted.items())[:10]:
                    ev_str = str(ev)[:300] if not isinstance(ev, (list, dict)) else json.dumps(ev, default=str)[:300]
                    conf_lines.append(f"<strong>{_escape_html(str(ek))}:</strong> <code>{_escape_html(ev_str)}</code>")

            confirmation_info = f"""
            <h4>Exploitation Proof</h4>
            <div class="code-block">{'<br>'.join(conf_lines)}</div>"""

        # --- cURL reproduction command ---
        curl_cmd = ""
        if v.url:
            curl_parts = [f"curl -k -v -X {v.method or 'GET'}"]
            if v.request_data and isinstance(v.request_data, dict):
                for hk, hv in list(v.request_data.get("headers", {}).items())[:10]:
                    if hk.lower() not in ("host", "user-agent", "accept-encoding", "connection"):
                        curl_parts.append(f"  -H '{_escape_html(str(hk))}: {_escape_html(str(hv))}'")
            if payload and (v.method or "GET") in ("POST", "PUT", "PATCH"):
                escaped_payload = _escape_html(payload.replace("'", "'\\''"))
                curl_parts.append(f"  -d '{escaped_payload}'")
            curl_parts.append(f"  '{_escape_html(v.url)}'")
            curl_cmd = " \\\n".join(curl_parts)

        poc_section = ""
        if payload or curl_cmd:
            poc_parts = []
            if payload:
                poc_parts.append(f'<div class="code-block"><strong>Payload:</strong> <code>{_escape_html(payload)}</code></div>')
            if curl_cmd:
                poc_parts.append(f'<div class="code-block"><strong>cURL Command:</strong><pre>{curl_cmd}</pre></div>')
            poc_section = "\n".join(poc_parts)

        # --- Reproduction steps ---
        repro_steps = _generate_repro_steps(v, vtype, payload)

        # --- Impact analysis ---
        impact_section = ""
        if impact:
            impact_section = f"<h4>Impact Analysis</h4><p>{_escape_html(str(impact))}</p>"

        vuln_details += f"""
        <div class="vuln-detail" id="vuln-{i}">
            <h3><span class="badge" style="background:{color}">{sev}</span>{confirmed_badge} {_escape_html(v.title or vtype)}</h3>
            <table class="detail-table">
                <tr><td><strong>Type</strong></td><td>{vtype}</td></tr>
                <tr><td><strong>URL</strong></td><td><code>{_escape_html(v.url or 'N/A')}</code></td></tr>
                <tr><td><strong>Parameter</strong></td><td><code>{_escape_html(v.parameter or 'N/A')}</code></td></tr>
                <tr><td><strong>Method</strong></td><td>{v.method or 'GET'}</td></tr>
                <tr><td><strong>CWE</strong></td><td>{cwe_info[0]} &mdash; {cwe_info[1]}</td></tr>
                <tr><td><strong>CVSS</strong></td><td>{cvss_info['score']} ({cvss_info['vector']})</td></tr>
                <tr><td><strong>Confidence</strong></td><td>{v.ai_confidence or 'N/A'}</td></tr>
            </table>
            <h4>Description</h4>
            <p>{_escape_html(description)}</p>
            {impact_section}
            <h4>Steps to Reproduce</h4>
            <ol>{''.join(f'<li>{_escape_html(s)}</li>' for s in repro_steps)}</ol>
            <h4>Proof of Concept</h4>
            {poc_section if poc_section else '<p>No payload data available.</p>'}
            {request_info}
            {response_info}
            {confirmation_info}
            <h4>Remediation</h4>
            <p>{_escape_html(remediation)}</p>
        </div>"""

    # Build methodology phases HTML
    phases_html = ""
    for idx, phase in enumerate(PIPELINE_PHASES, 1):
        phases_html += f'<div class="methodology-item"><span class="phase-num">{idx}</span>{phase}</div>'

    # Build technologies list
    tech_list = ""
    if technologies:
        if isinstance(technologies, list):
            tech_list = ", ".join(str(t) for t in technologies[:30])
        elif isinstance(technologies, dict):
            tech_list = ", ".join(str(k) for k in technologies.keys())
        else:
            tech_list = str(technologies)

    # Build subdomains preview
    subdomains_list = ""
    if subdomains and isinstance(subdomains, list):
        subdomains_list = ", ".join(str(s) for s in subdomains[:20])
        if len(subdomains) > 20:
            subdomains_list += f" ... (+{len(subdomains) - 20} more)"

    # Build open ports preview
    ports_list = ""
    if open_ports and isinstance(open_ports, list):
        ports_list = ", ".join(str(p) for p in open_ports[:30])

    body = f"""
    <div class="header">
        <h1>PHANTOM Security Assessment Report</h1>
        <p class="subtitle">Automated Penetration Test Results</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-label">Target</div>
                <div class="summary-value">{domain}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Scan Date</div>
                <div class="summary-value">{scan_date}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Duration</div>
                <div class="summary-value">{scan_duration or 'N/A'}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Risk Score</div>
                <div class="summary-value" style="color:{risk_color}">{risk_score}/100 ({risk_level})</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Endpoints Tested</div>
                <div class="summary-value">{endpoints_count or 'N/A'}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Phases Completed</div>
                <div class="summary-value">{min(len(phases_completed), len(PIPELINE_PHASES)) if isinstance(phases_completed, list) else phases_completed or 'N/A'} / {len(PIPELINE_PHASES)}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Subdomains Found</div>
                <div class="summary-value">{len(subdomains) if isinstance(subdomains, list) else 'N/A'}</div>
            </div>
        </div>
        <div style="margin-top:16px">
            <strong>Findings:</strong> {vuln_count_text} &mdash; {severity_badges}
        </div>
    </div>

    <div class="section">
        <h2>Methodology</h2>
        <p style="color:var(--muted);margin-bottom:16px">PHANTOM executes a {len(PIPELINE_PHASES)}-phase automated penetration testing pipeline:</p>
        <div class="methodology-list">
            {phases_html}
        </div>
    </div>

    <div class="section">
        <h2>Recon / Scope</h2>
        <table class="detail-table">
            <tr><td><strong>Domain</strong></td><td>{domain}</td></tr>
            <tr><td><strong>IP Address</strong></td><td>{target_ip or 'N/A'}</td></tr>
            <tr><td><strong>Technologies</strong></td><td>{tech_list or 'N/A'}</td></tr>
            <tr><td><strong>Subdomains</strong></td><td>{subdomains_list or 'None discovered'}</td></tr>
            <tr><td><strong>Open Ports</strong></td><td>{ports_list or 'N/A'}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Vulnerability Summary</h2>
        <table class="vuln-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Title</th>
                    <th>URL</th>
                    <th>Method</th>
                    <th>CVSS</th>
                </tr>
            </thead>
            <tbody>{vuln_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <h2>Detailed Findings</h2>
        {vuln_details if vuln_details else '<p>No vulnerabilities found.</p>'}
    </div>

    <div class="footer">
        <p>Generated by <strong>PHANTOM</strong> AI Pentester &mdash; {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p class="disclaimer">This report is confidential. Unauthorized distribution is prohibited.</p>
    </div>
    """

    return _wrap_html(f"PHANTOM Report - {domain}", body)


def _html_to_pdf(html: str) -> bytes:
    """Convert HTML string to PDF bytes using WeasyPrint."""
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except ImportError:
        raise HTTPException(status_code=500, detail="WeasyPrint not installed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _wrap_html(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{_escape_html(title)}</title>
    <style>
        :root {{
            --bg: #0a0a0f;
            --card: #12121a;
            --border: #1e1e2e;
            --text: #e4e4e7;
            --muted: #71717a;
            --accent: #8b5cf6;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 40px;
        }}
        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 40px;
        }}
        .header h1 {{
            font-size: 2.5rem;
            background: linear-gradient(135deg, #8b5cf6, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}
        .subtitle {{ color: var(--muted); font-size: 1.1rem; }}
        .section {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: var(--accent);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }}
        .summary-card {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .summary-label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .summary-value {{ font-size: 1.3rem; font-weight: 600; margin-top: 4px; }}
        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 700;
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        .vuln-table th {{
            background: var(--bg);
            padding: 12px;
            text-align: left;
            font-size: 0.85rem;
            text-transform: uppercase;
            color: var(--muted);
            border-bottom: 1px solid var(--border);
        }}
        .vuln-table td {{
            padding: 12px;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }}
        .vuln-table a {{ color: var(--accent); text-decoration: none; }}
        .vuln-table a:hover {{ text-decoration: underline; }}
        .vuln-detail {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 20px;
        }}
        .vuln-detail h3 {{
            font-size: 1.2rem;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .vuln-detail h4 {{
            font-size: 1rem;
            color: var(--accent);
            margin: 16px 0 8px;
        }}
        .detail-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .detail-table td {{
            padding: 6px 12px;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }}
        .detail-table td:first-child {{ width: 140px; color: var(--muted); }}
        code {{
            background: rgba(139, 92, 246, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            word-break: break-all;
        }}
        .code-block {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin: 8px 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }}
        .code-block pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            margin-top: 8px;
            color: var(--muted);
        }}
        .footer {{
            text-align: center;
            padding: 32px 0;
            color: var(--muted);
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }}
        .methodology-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 10px;
        }}
        .methodology-item {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 0.88rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .phase-num {{
            background: var(--accent);
            color: white;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 700;
            flex-shrink: 0;
        }}
        .disclaimer {{ font-size: 0.8rem; margin-top: 8px; font-style: italic; }}
        @media print {{
            body {{ background: white; color: #1a1a1a; padding: 20px; }}
            .section {{ border-color: #e5e5e5; }}
            .header h1 {{ background: none; -webkit-text-fill-color: #8b5cf6; }}
            .vuln-detail {{ background: #f9f9f9; }}
            code {{ background: #f3f4f6; }}
            .code-block {{ background: #f9f9f9; border-color: #e5e5e5; }}
        }}
    </style>
</head>
<body>
{body}
</body>
</html>"""
