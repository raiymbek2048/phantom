from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select, func, case, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.models.vulnerability import Vulnerability, Severity
from app.models.user import User
from app.api.auth import get_current_user

router = APIRouter()


@router.get("/stats")
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Total counts
    total_targets = (await db.execute(select(func.count(Target.id)))).scalar() or 0
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar() or 0
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0

    # Active scans
    active_scans = (await db.execute(
        select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING)
    )).scalar() or 0

    # Monitored targets
    monitored_targets = (await db.execute(
        select(func.count(Target.id)).where(Target.monitoring_enabled == True)
    )).scalar() or 0

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
        vulns_by_severity[key] = cnt

    # Vulns by type (top 10)
    type_rows = (await db.execute(
        select(Vulnerability.vuln_type, func.count(Vulnerability.id).label("cnt"))
        .group_by(Vulnerability.vuln_type)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
    )).all()
    vulns_by_type = {}
    for vt, cnt in type_rows:
        key = vt.value if hasattr(vt, "value") else str(vt)
        vulns_by_type[key] = cnt

    # Recent vulns (last 10) with target domain
    recent_vulns_rows = (await db.execute(
        select(Vulnerability, Target.domain)
        .join(Target, Vulnerability.target_id == Target.id, isouter=True)
        .order_by(Vulnerability.created_at.desc())
        .limit(10)
    )).all()
    recent_vulns = []
    for vuln, domain in recent_vulns_rows:
        recent_vulns.append({
            "id": vuln.id,
            "title": vuln.title,
            "severity": vuln.severity.value if hasattr(vuln.severity, "value") else vuln.severity,
            "vuln_type": vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else vuln.vuln_type,
            "url": vuln.url,
            "created_at": vuln.created_at.isoformat() if vuln.created_at else None,
            "target_domain": domain,
        })

    # Recent scans (last 10) with target domain
    recent_scans_rows = (await db.execute(
        select(Scan, Target.domain)
        .join(Target, Scan.target_id == Target.id, isouter=True)
        .order_by(Scan.created_at.desc())
        .limit(10)
    )).all()
    recent_scans = []
    for scan, domain in recent_scans_rows:
        recent_scans.append({
            "id": scan.id,
            "target_domain": domain,
            "status": scan.status.value if hasattr(scan.status, "value") else scan.status,
            "scan_type": scan.scan_type.value if hasattr(scan.scan_type, "value") else scan.scan_type,
            "vulns_found": scan.vulns_found,
            "endpoints_found": scan.endpoints_found,
            "subdomains_found": scan.subdomains_found,
            "current_phase": scan.current_phase,
            "progress_percent": scan.progress_percent or 0,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        })

    # Scan activity (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    activity_scans = (await db.execute(
        select(Scan).where(Scan.created_at >= thirty_days_ago)
    )).scalars().all()

    # Build day-by-day activity
    scan_activity = []
    for i in range(30):
        day = (datetime.utcnow() - timedelta(days=29 - i)).date()
        day_scans = [s for s in activity_scans if s.created_at and s.created_at.date() == day]
        day_str = day.isoformat()
        scan_activity.append({
            "date": day_str,
            "scans": len(day_scans),
            "vulns": sum(s.vulns_found or 0 for s in day_scans),
        })

    # LLM provider
    try:
        from app.ai.llm_engine import LLMEngine
        llm = LLMEngine()
        llm_provider = llm.provider
        await llm.close()
    except Exception:
        llm_provider = "unknown"

    # Training active
    training_active = False
    try:
        from app.core.celery_app import celery_app
        inspect = celery_app.control.inspect()
        active_tasks = inspect.active() or {}
        for worker_tasks in active_tasks.values():
            for task in worker_tasks:
                if "training" in task.get("name", "").lower():
                    training_active = True
                    break
    except Exception:
        pass

    return {
        "total_targets": total_targets,
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "active_scans": active_scans,
        "monitored_targets": monitored_targets,
        "vulns_by_severity": vulns_by_severity,
        "vulns_by_type": vulns_by_type,
        "recent_vulns": recent_vulns,
        "recent_scans": recent_scans,
        "scan_activity": scan_activity,
        "llm_provider": llm_provider,
        "training_active": training_active,
    }
