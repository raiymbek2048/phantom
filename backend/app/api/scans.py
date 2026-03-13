import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.scan import Scan, ScanLog, ScanStatus, ScanType
from app.models.target import Target
from app.models.user import User
from app.api.auth import get_current_user
from app.api.audit import log_action

router = APIRouter()


class ScanCreate(BaseModel):
    target_id: str
    scan_type: ScanType = ScanType.FULL
    config: dict | None = None
    priority: int = 5  # 1=highest, 10=lowest
    rounds: int = 1  # 1=single pass, 2-10=multi-round
    continuous: bool = False  # keep scanning until no new findings


class CampaignCreate(BaseModel):
    target_ids: List[str]
    scan_type: ScanType = ScanType.FULL
    priority: int = 5


class CampaignByTagCreate(BaseModel):
    tag: str
    scan_type: ScanType = ScanType.QUICK
    priority: int = 5


@router.get("/queue")
async def get_scan_queue(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get the current scan queue ordered by priority."""
    result = await db.execute(
        select(Scan).where(
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])
        ).order_by(Scan.priority, Scan.created_at)
    )
    scans = result.scalars().all()

    # Load target domains
    target_ids = list(set(s.target_id for s in scans))
    if target_ids:
        targets_result = await db.execute(select(Target).where(Target.id.in_(target_ids)))
        targets_map = {t.id: t.domain for t in targets_result.scalars().all()}
    else:
        targets_map = {}

    return {
        "total": len(scans),
        "running": sum(1 for s in scans if s.status == ScanStatus.RUNNING),
        "queued": sum(1 for s in scans if s.status == ScanStatus.QUEUED),
        "scans": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "domain": targets_map.get(s.target_id, "unknown"),
                "status": s.status.value,
                "scan_type": s.scan_type.value,
                "priority": s.priority,
                "progress_percent": s.progress_percent,
                "current_phase": s.current_phase,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "started_at": s.started_at.isoformat() if s.started_at else None,
            }
            for s in scans
        ],
    }


@router.patch("/{scan_id}/priority")
async def update_scan_priority(
    scan_id: str,
    priority: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update scan priority (1=highest, 10=lowest). Only works for queued scans."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.QUEUED:
        raise HTTPException(status_code=400, detail="Can only change priority of queued scans")
    scan.priority = max(1, min(10, priority))
    await db.flush()
    return {"id": scan.id, "priority": scan.priority}


@router.get("")
async def list_scans(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.post("")
async def create_scan(
    scan_data: ScanCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.models.user import UserRole
    if user.role == UserRole.VIEWER and not user.is_admin:
        raise HTTPException(status_code=403, detail="Viewers cannot start scans")
    # Verify target exists
    result = await db.execute(select(Target).where(Target.id == scan_data.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Block if same target already has a running/queued scan
    dup = await db.execute(
        select(Scan).where(
            Scan.target_id == scan_data.target_id,
            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A scan is already running for this target")

    # Check concurrent scan limit
    from app.config import get_settings as get_app_settings
    max_scans = get_app_settings().max_concurrent_scans
    running = await db.execute(
        select(Scan).where(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]))
    )
    running_count = len(running.scalars().all())
    if running_count >= max_scans:
        raise HTTPException(status_code=429, detail=f"Maximum concurrent scans reached ({running_count}/{max_scans})")

    priority = max(1, min(10, scan_data.priority))
    # Merge multi-round config into scan config
    config = scan_data.config or {}
    if scan_data.rounds > 1:
        config["rounds"] = min(scan_data.rounds, 10)
    if scan_data.continuous:
        config["continuous"] = True
        config["rounds"] = config.get("rounds", 10)  # safety cap for continuous
    scan = Scan(
        target_id=scan_data.target_id,
        scan_type=scan_data.scan_type,
        config=config or None,
        priority=priority,
        status=ScanStatus.QUEUED,
        user_id=user.id,
    )
    db.add(scan)
    await db.flush()

    # Dispatch Celery task with priority (Celery uses 0=highest, 9=lowest)
    from app.core.celery_app import run_scan_task
    run_scan_task.apply_async(args=[scan.id], priority=priority - 1)

    await log_action(db, user, "scan_started", "scan", scan.id,
                     {"target_id": scan_data.target_id, "scan_type": scan_data.scan_type.value},
                     ip_address=request.client.host if request.client else None)

    return scan


@router.post("/campaign")
async def create_campaign(
    campaign_data: CampaignCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Launch a campaign — scan multiple targets in parallel."""
    from app.models.user import UserRole
    if user.role == UserRole.VIEWER and not user.is_admin:
        raise HTTPException(status_code=403, detail="Viewers cannot start scans")

    if not campaign_data.target_ids:
        raise HTTPException(status_code=400, detail="No target IDs provided")
    if len(campaign_data.target_ids) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 targets per campaign")

    from app.config import get_settings as get_app_settings
    max_scans = get_app_settings().max_concurrent_scans

    # Verify all targets exist
    targets = []
    for tid in campaign_data.target_ids:
        result = await db.execute(select(Target).where(Target.id == tid))
        target = result.scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail=f"Target {tid} not found")
        targets.append(target)

    # Check concurrent scan limit
    running = await db.execute(
        select(Scan).where(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]))
    )
    running_count = len(running.scalars().all())
    if running_count + len(targets) > max_scans:
        raise HTTPException(
            status_code=429,
            detail=f"Would exceed max concurrent scans (running: {running_count}, requested: {len(targets)}, limit: {max_scans})"
        )

    campaign_id = str(uuid.uuid4())
    priority = max(1, min(10, campaign_data.priority))
    scans = []

    for target in targets:
        # Skip targets that already have a running/queued scan
        dup = await db.execute(
            select(Scan).where(
                Scan.target_id == target.id,
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
            )
        )
        if dup.scalar_one_or_none():
            continue

        scan = Scan(
            target_id=target.id,
            scan_type=campaign_data.scan_type,
            config={"campaign_id": campaign_id},
            priority=priority,
            status=ScanStatus.QUEUED,
            user_id=user.id,
        )
        db.add(scan)
        await db.flush()
        scans.append(scan)

    await db.commit()

    # Dispatch all scans to Celery
    from app.core.celery_app import run_scan_task
    for scan in scans:
        run_scan_task.apply_async(args=[scan.id], priority=priority - 1)

    return {
        "campaign_id": campaign_id,
        "scan_type": campaign_data.scan_type.value,
        "total_targets": len(campaign_data.target_ids),
        "scans_launched": len(scans),
        "skipped": len(campaign_data.target_ids) - len(scans),
        "scans": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "status": s.status.value,
            }
            for s in scans
        ],
    }


@router.get("/campaign/{campaign_id}")
async def get_campaign_status(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get status of all scans in a campaign."""
    result = await db.execute(
        select(Scan).where(
            Scan.config["campaign_id"].as_string() == campaign_id
        )
    )
    scans = result.scalars().all()

    if not scans:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Load target domains for display
    target_ids = list(set(s.target_id for s in scans))
    targets_result = await db.execute(select(Target).where(Target.id.in_(target_ids)))
    targets_map = {t.id: t.domain for t in targets_result.scalars().all()}

    statuses = [s.status.value for s in scans]
    if all(st == "completed" for st in statuses):
        campaign_status = "completed"
    elif any(st == "failed" for st in statuses):
        campaign_status = "partial"
    elif any(st in ("running", "queued") for st in statuses):
        campaign_status = "running"
    else:
        campaign_status = "unknown"

    total_vulns = sum(s.vulns_found for s in scans)
    total_endpoints = sum(s.endpoints_found for s in scans)

    return {
        "campaign_id": campaign_id,
        "status": campaign_status,
        "total_scans": len(scans),
        "completed": sum(1 for s in statuses if s == "completed"),
        "running": sum(1 for s in statuses if s in ("running", "queued")),
        "failed": sum(1 for s in statuses if s == "failed"),
        "total_vulns_found": total_vulns,
        "total_endpoints_found": total_endpoints,
        "scans": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "domain": targets_map.get(s.target_id, "unknown"),
                "status": s.status.value,
                "scan_type": s.scan_type.value,
                "progress_percent": s.progress_percent,
                "vulns_found": s.vulns_found,
                "endpoints_found": s.endpoints_found,
                "started_at": str(s.started_at) if s.started_at else None,
                "completed_at": str(s.completed_at) if s.completed_at else None,
            }
            for s in scans
        ],
    }


@router.post("/campaign/by-tag")
async def create_campaign_by_tag(
    campaign_data: CampaignByTagCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Launch a campaign for all targets matching a tag."""
    from app.models.user import UserRole
    if user.role == UserRole.VIEWER and not user.is_admin:
        raise HTTPException(status_code=403, detail="Viewers cannot start scans")

    tag = campaign_data.tag.strip().lower()
    if not tag:
        raise HTTPException(status_code=400, detail="Tag is required")

    # Find all targets with this tag
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    all_targets = result.scalars().all()
    targets = [t for t in all_targets if t.tags and tag in t.tags]

    if not targets:
        raise HTTPException(status_code=404, detail=f"No targets found with tag '{tag}'")
    if len(targets) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 targets per campaign")

    from app.config import get_settings as get_app_settings
    max_scans = get_app_settings().max_concurrent_scans

    # Check concurrent scan limit
    running = await db.execute(
        select(Scan).where(Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]))
    )
    running_count = len(running.scalars().all())
    if running_count + len(targets) > max_scans:
        raise HTTPException(
            status_code=429,
            detail=f"Would exceed max concurrent scans (running: {running_count}, requested: {len(targets)}, limit: {max_scans})"
        )

    campaign_id = str(uuid.uuid4())
    priority = max(1, min(10, campaign_data.priority))
    scans = []

    for target in targets:
        # Skip targets that already have a running/queued scan
        dup = await db.execute(
            select(Scan).where(
                Scan.target_id == target.id,
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
            )
        )
        if dup.scalar_one_or_none():
            continue

        scan = Scan(
            target_id=target.id,
            scan_type=campaign_data.scan_type,
            config={"campaign_id": campaign_id},
            priority=priority,
            status=ScanStatus.QUEUED,
            user_id=user.id,
        )
        db.add(scan)
        await db.flush()
        scans.append(scan)

    await db.commit()

    # Dispatch all scans to Celery
    from app.core.celery_app import run_scan_task
    for scan in scans:
        run_scan_task.apply_async(args=[scan.id], priority=priority - 1)

    return {
        "campaign_id": campaign_id,
        "tag": tag,
        "scan_type": campaign_data.scan_type.value,
        "total_targets": len(targets),
        "scans_launched": len(scans),
        "skipped": len(targets) - len(scans),
        "targets": [
            {"id": t.id, "domain": t.domain}
            for t in targets
        ],
        "scans": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "status": s.status.value,
            }
            for s in scans
        ],
    }


@router.get("/{scan_id}/graph")
async def get_scan_graph(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get the application graph data from scan results."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    graph = (scan.scan_results or {}).get("application_graph", {})
    return graph


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/pause")
async def pause_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Scan is not running")
    scan.status = ScanStatus.PAUSED
    return scan


@router.post("/{scan_id}/resume")
async def resume_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.PAUSED:
        raise HTTPException(status_code=400, detail="Scan is not paused")
    scan.status = ScanStatus.RUNNING
    from app.core.celery_app import run_scan_task
    run_scan_task.delay(scan.id)
    return scan


@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in (ScanStatus.RUNNING, ScanStatus.QUEUED):
        raise HTTPException(status_code=400, detail=f"Cannot stop scan with status: {scan.status.value}")
    scan.status = ScanStatus.STOPPED
    scan.completed_at = datetime.utcnow()
    await log_action(db, user, "scan_stopped", "scan", scan.id)
    return scan


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Cannot delete a running scan — stop it first")
    # Delete related records first (order matters for FK constraints)
    from app.models.vulnerability import Vulnerability
    from app.models.report import Report
    # Delete reports referencing this scan's vulnerabilities
    vulns_result = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id))
    for vuln in vulns_result.scalars().all():
        reports = await db.execute(select(Report).where(Report.vulnerability_id == vuln.id))
        for r in reports.scalars().all():
            await db.delete(r)
    # Delete reports referencing this scan directly
    scan_reports = await db.execute(select(Report).where(Report.scan_id == scan_id))
    for r in scan_reports.scalars().all():
        await db.delete(r)
    for model in (ScanLog, Vulnerability):
        related = await db.execute(select(model).where(model.scan_id == scan_id))
        for row in related.scalars().all():
            await db.delete(row)
    await db.delete(scan)
    return {"detail": "Scan deleted"}


@router.get("/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanLog).where(ScanLog.scan_id == scan_id).order_by(ScanLog.created_at)
    )
    return result.scalars().all()


@router.get("/compare/{scan_id_a}/{scan_id_b}/report")
async def compare_scans_report(
    scan_id_a: str,
    scan_id_b: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate an HTML comparison report between two scans."""
    from app.models.vulnerability import Vulnerability
    from fastapi.responses import HTMLResponse

    for sid in (scan_id_a, scan_id_b):
        r = await db.execute(select(Scan).where(Scan.id == sid))
        if not r.scalar_one_or_none():
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")

    scan_a = (await db.execute(select(Scan).where(Scan.id == scan_id_a))).scalar_one()
    scan_b = (await db.execute(select(Scan).where(Scan.id == scan_id_b))).scalar_one()

    target_a = (await db.execute(select(Target).where(Target.id == scan_a.target_id))).scalar_one_or_none()
    target_b = (await db.execute(select(Target).where(Target.id == scan_b.target_id))).scalar_one_or_none()

    vulns_a = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id_a)
    )).scalars().all()
    vulns_b = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id_b)
    )).scalars().all()

    def fingerprint(v):
        return f"{v.vuln_type.value}|{v.url}|{v.parameter or ''}"

    fps_a = {fingerprint(v): v for v in vulns_a}
    fps_b = {fingerprint(v): v for v in vulns_b}

    new_vulns = [fps_b[fp] for fp in fps_b if fp not in fps_a]
    fixed_vulns = [fps_a[fp] for fp in fps_a if fp not in fps_b]
    unchanged_vulns = [fps_b[fp] for fp in fps_b if fp in fps_a]

    html = _render_comparison_report_html(
        scan_a, scan_b, target_a, target_b,
        vulns_a, vulns_b,
        new_vulns, fixed_vulns, unchanged_vulns,
    )
    return HTMLResponse(content=html)


@router.get("/compare/{scan_id_a}/{scan_id_b}")
async def compare_scans(
    scan_id_a: str,
    scan_id_b: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Compare vulnerabilities between two scans."""
    from app.models.vulnerability import Vulnerability

    for sid in (scan_id_a, scan_id_b):
        r = await db.execute(select(Scan).where(Scan.id == sid))
        if not r.scalar_one_or_none():
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")

    scan_a = (await db.execute(select(Scan).where(Scan.id == scan_id_a))).scalar_one()
    scan_b = (await db.execute(select(Scan).where(Scan.id == scan_id_b))).scalar_one()

    vulns_a = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id_a)
    )).scalars().all()
    vulns_b = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id_b)
    )).scalars().all()

    def fingerprint(v):
        return f"{v.vuln_type.value}|{v.url}|{v.parameter or ''}"

    fps_a = {fingerprint(v): v for v in vulns_a}
    fps_b = {fingerprint(v): v for v in vulns_b}

    return {
        "scan_a": {"id": scan_id_a, "created_at": str(scan_a.created_at), "vulns_count": len(vulns_a)},
        "scan_b": {"id": scan_id_b, "created_at": str(scan_b.created_at), "vulns_count": len(vulns_b)},
        "new": [fps_b[fp] for fp in fps_b if fp not in fps_a],
        "fixed": [fps_a[fp] for fp in fps_a if fp not in fps_b],
        "unchanged": [fps_b[fp] for fp in fps_b if fp in fps_a],
        "summary": {
            "new_count": len([fp for fp in fps_b if fp not in fps_a]),
            "fixed_count": len([fp for fp in fps_a if fp not in fps_b]),
            "unchanged_count": len([fp for fp in fps_b if fp in fps_a]),
        },
    }


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


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


def _render_comparison_report_html(
    scan_a, scan_b, target_a, target_b,
    vulns_a, vulns_b,
    new_vulns, fixed_vulns, unchanged_vulns,
) -> str:
    """Render a full HTML comparison report between two scans."""
    domain_a = target_a.domain if target_a else "Unknown"
    domain_b = target_b.domain if target_b else "Unknown"
    date_a = scan_a.created_at.strftime("%Y-%m-%d %H:%M") if scan_a.created_at else "N/A"
    date_b = scan_b.created_at.strftime("%Y-%m-%d %H:%M") if scan_b.created_at else "N/A"
    type_a = scan_a.scan_type.value if hasattr(scan_a.scan_type, 'value') else str(scan_a.scan_type)
    type_b = scan_b.scan_type.value if hasattr(scan_b.scan_type, 'value') else str(scan_b.scan_type)

    # Severity distribution for each scan
    def count_by_severity(vulns):
        counts = {}
        for v in vulns:
            sev = v.severity.value.upper() if hasattr(v.severity, 'value') else str(v.severity).upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    sev_a = count_by_severity(vulns_a)
    sev_b = count_by_severity(vulns_b)

    # Severity comparison bars
    severity_rows = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        ca = sev_a.get(sev, 0)
        cb = sev_b.get(sev, 0)
        if ca == 0 and cb == 0:
            continue
        color = _severity_color(sev)
        max_val = max(ca, cb, 1)
        pct_a = int((ca / max_val) * 100)
        pct_b = int((cb / max_val) * 100)
        diff_label = ""
        if cb > ca:
            diff_label = f'<span style="color:#ef4444;font-weight:600">+{cb - ca}</span>'
        elif cb < ca:
            diff_label = f'<span style="color:#22c55e;font-weight:600">-{ca - cb}</span>'
        else:
            diff_label = '<span style="color:var(--muted)">--</span>'
        severity_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{sev}</span></td>
            <td style="text-align:center">{ca}</td>
            <td>
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden">
                        <div style="width:{pct_a}%;height:100%;background:{color};border-radius:4px"></div>
                    </div>
                </div>
            </td>
            <td style="text-align:center">{cb}</td>
            <td>
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden">
                        <div style="width:{pct_b}%;height:100%;background:{color};border-radius:4px"></div>
                    </div>
                </div>
            </td>
            <td style="text-align:center">{diff_label}</td>
        </tr>"""

    # Build vuln list sections
    def render_vuln_list(vulns, color_accent):
        if not vulns:
            return '<p style="color:var(--muted);font-style:italic;padding:8px 0">None</p>'
        rows = ""
        sorted_v = sorted(vulns, key=lambda v: _severity_order(
            v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        ))
        for v in sorted_v:
            sev = v.severity.value.upper() if hasattr(v.severity, 'value') else str(v.severity).upper()
            vtype = v.vuln_type.value if hasattr(v.vuln_type, 'value') else str(v.vuln_type)
            color = _severity_color(sev)
            rows += f"""
            <div style="display:flex;align-items:flex-start;gap:12px;padding:12px;background:var(--bg);
                        border:1px solid var(--border);border-radius:8px;margin-bottom:8px">
                <span class="badge" style="background:{color};flex-shrink:0;margin-top:2px">{sev}</span>
                <div style="flex:1;min-width:0">
                    <div style="font-weight:600;margin-bottom:4px">{_escape_html(v.title or vtype)}</div>
                    <div style="font-size:0.85rem;color:var(--muted)">
                        <code>{_escape_html(v.url or 'N/A')}</code>
                    </div>
                    {f'<div style="font-size:0.8rem;color:var(--muted);margin-top:4px">Parameter: <code>{_escape_html(v.parameter)}</code></div>' if v.parameter else ''}
                </div>
            </div>"""
        return rows

    new_section = render_vuln_list(new_vulns, "#ef4444")
    fixed_section = render_vuln_list(fixed_vulns, "#22c55e")
    unchanged_section = render_vuln_list(unchanged_vulns, "#6b7280")

    # Endpoints comparison
    ep_a = scan_a.endpoints_found or 0
    ep_b = scan_b.endpoints_found or 0
    ep_diff = ep_b - ep_a
    ep_diff_label = f"+{ep_diff}" if ep_diff > 0 else str(ep_diff) if ep_diff < 0 else "0"
    ep_diff_color = "#ef4444" if ep_diff > 0 else "#22c55e" if ep_diff < 0 else "var(--muted)"

    body = f"""
    <div class="header">
        <h1>PHANTOM Scan Comparison Report</h1>
        <p class="subtitle">Side-by-side analysis of security scan results</p>
    </div>

    <div class="section">
        <h2>Scan Overview</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
            <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:20px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px">
                    <div style="width:12px;height:12px;border-radius:50%;background:#8b5cf6"></div>
                    <span style="font-weight:700;font-size:1.1rem">Scan A</span>
                </div>
                <table class="detail-table">
                    <tr><td><strong>Target</strong></td><td>{_escape_html(domain_a)}</td></tr>
                    <tr><td><strong>Date</strong></td><td>{date_a}</td></tr>
                    <tr><td><strong>Type</strong></td><td style="text-transform:uppercase">{type_a}</td></tr>
                    <tr><td><strong>Vulnerabilities</strong></td><td>{len(vulns_a)}</td></tr>
                    <tr><td><strong>Endpoints</strong></td><td>{ep_a}</td></tr>
                </table>
            </div>
            <div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:20px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px">
                    <div style="width:12px;height:12px;border-radius:50%;background:#06b6d4"></div>
                    <span style="font-weight:700;font-size:1.1rem">Scan B</span>
                </div>
                <table class="detail-table">
                    <tr><td><strong>Target</strong></td><td>{_escape_html(domain_b)}</td></tr>
                    <tr><td><strong>Date</strong></td><td>{date_b}</td></tr>
                    <tr><td><strong>Type</strong></td><td style="text-transform:uppercase">{type_b}</td></tr>
                    <tr><td><strong>Vulnerabilities</strong></td><td>{len(vulns_b)}</td></tr>
                    <tr><td><strong>Endpoints</strong></td><td>{ep_b}</td></tr>
                </table>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Change Summary</h2>
        <div class="summary-grid" style="grid-template-columns:repeat(4,1fr)">
            <div class="summary-card">
                <div class="summary-label">New Vulnerabilities</div>
                <div class="summary-value" style="color:#ef4444">+{len(new_vulns)}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Fixed Vulnerabilities</div>
                <div class="summary-value" style="color:#22c55e">-{len(fixed_vulns)}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Unchanged</div>
                <div class="summary-value">{len(unchanged_vulns)}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Endpoint Delta</div>
                <div class="summary-value" style="color:{ep_diff_color}">{ep_diff_label}</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Severity Distribution Comparison</h2>
        <table class="vuln-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th style="text-align:center">Scan A</th>
                    <th style="width:20%">Distribution A</th>
                    <th style="text-align:center">Scan B</th>
                    <th style="width:20%">Distribution B</th>
                    <th style="text-align:center">Delta</th>
                </tr>
            </thead>
            <tbody>{severity_rows if severity_rows else '<tr><td colspan="6" style="text-align:center;color:var(--muted)">No vulnerabilities in either scan</td></tr>'}</tbody>
        </table>
    </div>

    <div class="section">
        <h2 style="color:#ef4444">New Vulnerabilities ({len(new_vulns)})</h2>
        <p style="color:var(--muted);margin-bottom:16px;font-size:0.9rem">Found in Scan B but not in Scan A</p>
        {new_section}
    </div>

    <div class="section">
        <h2 style="color:#22c55e">Fixed Vulnerabilities ({len(fixed_vulns)})</h2>
        <p style="color:var(--muted);margin-bottom:16px;font-size:0.9rem">Present in Scan A but resolved in Scan B</p>
        {fixed_section}
    </div>

    <div class="section">
        <h2 style="color:var(--muted)">Unchanged Vulnerabilities ({len(unchanged_vulns)})</h2>
        <p style="color:var(--muted);margin-bottom:16px;font-size:0.9rem">Still present in both scans</p>
        {unchanged_section}
    </div>

    <div class="footer">
        <p>Generated by <strong>PHANTOM</strong> AI Pentester &mdash; {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p class="disclaimer">This report is confidential. Unauthorized distribution is prohibited.</p>
    </div>
    """

    return _wrap_comparison_html(f"PHANTOM Comparison - {domain_a}", body)


def _wrap_comparison_html(title: str, body: str) -> str:
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
            code {{ background: #f3f4f6; }}
        }}
    </style>
</head>
<body>
{body}
</body>
</html>"""
