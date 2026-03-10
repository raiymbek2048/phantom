from datetime import datetime

import markdown
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
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

        vuln_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{sev}</span></td>
            <td>{vtype}</td>
            <td><a href="#vuln-{i}">{v.title or vtype}</a></td>
            <td><code>{v.url or 'N/A'}</code></td>
            <td>{v.method or 'GET'}</td>
        </tr>"""

        # Detail section
        description = v.description or "Vulnerability confirmed by automated testing."
        remediation = v.remediation or "Review and fix the identified vulnerability."
        payload = v.payload_used or "N/A"

        request_info = ""
        if v.request_data:
            req = v.request_data if isinstance(v.request_data, dict) else {}
            request_info = f"""
            <div class="code-block">
                <strong>Request:</strong><br>
                {req.get('method', 'GET')} {req.get('url', v.url)}<br>
                {f"Parameter: {req.get('param', '')}" if req.get('param') else ""}
                {f"<br>Body: {req.get('body', '')}" if req.get('body') else ""}
            </div>"""

        response_info = ""
        if v.response_data:
            resp = v.response_data if isinstance(v.response_data, dict) else {}
            body_preview = str(resp.get("body", ""))[:500]
            response_info = f"""
            <div class="code-block">
                <strong>Response:</strong> HTTP {resp.get('status_code', '?')}<br>
                <pre>{_escape_html(body_preview)}</pre>
            </div>"""

        vuln_details += f"""
        <div class="vuln-detail" id="vuln-{i}">
            <h3><span class="badge" style="background:{color}">{sev}</span> {v.title or vtype}</h3>
            <table class="detail-table">
                <tr><td><strong>Type</strong></td><td>{vtype}</td></tr>
                <tr><td><strong>URL</strong></td><td><code>{v.url or 'N/A'}</code></td></tr>
                <tr><td><strong>Parameter</strong></td><td><code>{v.parameter or 'N/A'}</code></td></tr>
                <tr><td><strong>Method</strong></td><td>{v.method or 'GET'}</td></tr>
                <tr><td><strong>Confidence</strong></td><td>{v.ai_confidence or 'N/A'}</td></tr>
            </table>
            <h4>Description</h4>
            <p>{description}</p>
            <h4>Proof of Concept</h4>
            <div class="code-block"><strong>Payload:</strong> <code>{_escape_html(payload)}</code></div>
            {request_info}
            {response_info}
            <h4>Remediation</h4>
            <p>{remediation}</p>
        </div>"""

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
        </div>
        <div style="margin-top:16px">
            <strong>Findings:</strong> {len(vulns)} vulnerabilities &mdash; {severity_badges}
        </div>
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
