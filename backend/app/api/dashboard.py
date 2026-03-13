from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select, func, case, cast, Date, literal
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.vulnerability import Vulnerability, Severity, VulnType
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.models.knowledge import KnowledgePattern
from app.models.user import User
from app.api.auth import get_current_user

router = APIRouter()


@router.get("/stats")
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Overview stats: totals, vulns by severity, scans by status, KB patterns count."""
    # Total counts
    total_targets = (await db.execute(select(func.count(Target.id)))).scalar() or 0
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar() or 0
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0

    # Vulns by severity
    sev_rows = (await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
    )).all()
    vulns_by_severity = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for sev, cnt in sev_rows:
        key = sev.value if hasattr(sev, "value") else str(sev)
        if key in vulns_by_severity:
            vulns_by_severity[key] = cnt

    # Scans by status
    status_rows = (await db.execute(
        select(Scan.status, func.count(Scan.id))
        .group_by(Scan.status)
    )).all()
    scans_by_status = {
        "queued": 0, "running": 0, "completed": 0, "failed": 0, "stopped": 0, "paused": 0,
    }
    for status, cnt in status_rows:
        key = status.value if hasattr(status, "value") else str(status)
        if key in scans_by_status:
            scans_by_status[key] = cnt

    # KB patterns count
    kb_patterns_count = (await db.execute(
        select(func.count(KnowledgePattern.id))
    )).scalar() or 0

    active_scans = scans_by_status.get("running", 0) + scans_by_status.get("queued", 0)

    return {
        "total_targets": total_targets,
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "active_scans": active_scans,
        "vulns_by_severity": vulns_by_severity,
        "scans_by_status": scans_by_status,
        "kb_patterns": kb_patterns_count,
    }


@router.get("/vulns-over-time")
async def vulns_over_time(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Vulns found per day for the last 30 days, with severity breakdown."""
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    rows = (await db.execute(
        select(
            cast(Vulnerability.created_at, Date).label("day"),
            func.count(Vulnerability.id).label("count"),
            func.count(case((Vulnerability.severity == Severity.CRITICAL, 1))).label("critical"),
            func.count(case((Vulnerability.severity == Severity.HIGH, 1))).label("high"),
            func.count(case((Vulnerability.severity == Severity.MEDIUM, 1))).label("medium"),
            func.count(case((Vulnerability.severity == Severity.LOW, 1))).label("low"),
            func.count(case((Vulnerability.severity == Severity.INFO, 1))).label("info"),
        )
        .where(Vulnerability.created_at >= thirty_days_ago)
        .group_by(cast(Vulnerability.created_at, Date))
        .order_by(cast(Vulnerability.created_at, Date))
    )).all()

    # Build a dict for quick lookup
    day_data = {}
    for row in rows:
        day_data[row.day.isoformat()] = {
            "date": row.day.isoformat(),
            "count": row.count,
            "critical": row.critical,
            "high": row.high,
            "medium": row.medium,
            "low": row.low,
            "info": row.info,
        }

    # Fill all 30 days (including days with 0 vulns)
    result = []
    for i in range(30):
        day = (datetime.utcnow() - timedelta(days=29 - i)).date()
        day_str = day.isoformat()
        if day_str in day_data:
            result.append(day_data[day_str])
        else:
            result.append({
                "date": day_str,
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            })

    return result


@router.get("/top-vuln-types")
async def top_vuln_types(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Top 10 vulnerability types by count with average confidence."""
    rows = (await db.execute(
        select(
            Vulnerability.vuln_type,
            func.count(Vulnerability.id).label("count"),
            func.avg(Vulnerability.ai_confidence).label("avg_confidence"),
        )
        .group_by(Vulnerability.vuln_type)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
    )).all()

    return [
        {
            "type": (row.vuln_type.value if hasattr(row.vuln_type, "value") else str(row.vuln_type)),
            "count": row.count,
            "avg_confidence": round(row.avg_confidence, 3) if row.avg_confidence is not None else None,
        }
        for row in rows
    ]


@router.get("/recent-activity")
async def recent_activity(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Last 20 events: mix of recent vulns and scan completions, sorted by time."""
    # Recent vulns (last 20)
    vuln_rows = (await db.execute(
        select(Vulnerability, Target.domain)
        .join(Target, Vulnerability.target_id == Target.id, isouter=True)
        .order_by(Vulnerability.created_at.desc())
        .limit(20)
    )).all()

    # Recent completed/failed scans (last 20)
    scan_rows = (await db.execute(
        select(Scan, Target.domain)
        .join(Target, Scan.target_id == Target.id, isouter=True)
        .where(Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.STOPPED]))
        .order_by(Scan.completed_at.desc().nulls_last())
        .limit(20)
    )).all()

    events = []

    for vuln, domain in vuln_rows:
        events.append({
            "type": "vuln",
            "id": str(vuln.id),
            "title": vuln.title,
            "severity": vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity),
            "vuln_type": vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type),
            "target_domain": domain,
            "url": vuln.url,
            "created_at": vuln.created_at.isoformat() if vuln.created_at else None,
        })

    for scan, domain in scan_rows:
        scan_time = scan.completed_at or scan.created_at
        events.append({
            "type": "scan",
            "id": str(scan.id),
            "title": f"Scan {scan.status.value if hasattr(scan.status, 'value') else scan.status}",
            "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            "scan_type": scan.scan_type.value if hasattr(scan.scan_type, "value") else str(scan.scan_type),
            "target_domain": domain,
            "vulns_found": scan.vulns_found or 0,
            "created_at": scan_time.isoformat() if scan_time else None,
        })

    # Sort by time descending and take top 20
    events.sort(key=lambda e: e["created_at"] or "", reverse=True)
    return events[:20]


@router.get("/target-risk")
async def target_risk(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Risk score per target. Returns top 10 riskiest targets."""
    rows = (await db.execute(
        select(
            Target.id,
            Target.domain,
            func.count(case((Vulnerability.severity == Severity.CRITICAL, 1))).label("critical"),
            func.count(case((Vulnerability.severity == Severity.HIGH, 1))).label("high"),
            func.count(case((Vulnerability.severity == Severity.MEDIUM, 1))).label("medium"),
            func.count(case((Vulnerability.severity == Severity.LOW, 1))).label("low"),
            func.count(Vulnerability.id).label("total_vulns"),
        )
        .join(Vulnerability, Vulnerability.target_id == Target.id, isouter=True)
        .group_by(Target.id, Target.domain)
        .having(func.count(Vulnerability.id) > 0)
    )).all()

    results = []
    for row in rows:
        # Risk score: critical=10, high=5, medium=2, low=0.5
        risk_score = (row.critical * 10) + (row.high * 5) + (row.medium * 2) + (row.low * 0.5)
        results.append({
            "id": str(row.id),
            "domain": row.domain,
            "risk_score": round(risk_score, 1),
            "critical": row.critical,
            "high": row.high,
            "medium": row.medium,
            "low": row.low,
            "total_vulns": row.total_vulns,
        })

    # Sort by risk score descending, take top 10
    results.sort(key=lambda r: r["risk_score"], reverse=True)
    return results[:10]
