from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.target import Target, TargetStatus, TargetSource
from app.models.user import User
from app.api.auth import get_current_user
from app.api.audit import log_action

router = APIRouter()


class TargetCreate(BaseModel):
    domain: str
    scope: str | None = None
    bounty_program_url: str | None = None
    notes: str | None = None
    source: TargetSource = TargetSource.MANUAL
    rate_limit: int | None = None  # requests/sec override


class TargetUpdate(BaseModel):
    domain: str | None = None
    scope: str | None = None
    status: TargetStatus | None = None
    bounty_program_url: str | None = None
    notes: str | None = None
    rate_limit: int | None = None
    tags: list[str] | None = None


class MonitorRequest(BaseModel):
    enabled: bool = True
    interval: str = "daily"  # hourly, daily, weekly


class TargetResponse(BaseModel):
    id: str
    domain: str
    scope: str | None
    status: TargetStatus
    source: TargetSource
    bounty_program_url: str | None
    notes: str | None
    subdomains: list | None
    technologies: dict | None
    monitoring_enabled: bool
    monitoring_interval: str
    created_at: str

    model_config = {"from_attributes": True}


@router.get("")
async def list_targets(
    tag: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = select(Target).order_by(Target.created_at.desc())
    result = await db.execute(query)
    targets = result.scalars().all()
    if tag:
        targets = [t for t in targets if t.tags and tag in t.tags]
    return targets


@router.get("/tags")
async def list_all_tags(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List all unique tags across all targets."""
    result = await db.execute(select(Target.tags))
    all_tags = set()
    for (tags,) in result.all():
        if tags and isinstance(tags, list):
            all_tags.update(tags)
    return sorted(all_tags)


@router.post("/{target_id}/tags")
async def update_target_tags(
    target_id: str,
    tags: list[str],
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Set tags for a target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.tags = [t.strip().lower() for t in tags if t.strip()]
    await db.flush()
    return {"id": target.id, "tags": target.tags}


@router.post("")
async def create_target(
    target_data: TargetCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Normalize domain
    domain = target_data.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    # Check if target already exists — return it instead of creating duplicate
    existing = await db.execute(select(Target).where(Target.domain == domain).limit(1))
    existing_target = existing.scalar_one_or_none()
    if existing_target:
        return existing_target

    target = Target(
        domain=domain,
        scope=target_data.scope,
        bounty_program_url=target_data.bounty_program_url,
        notes=target_data.notes,
        source=target_data.source,
        rate_limit=target_data.rate_limit,
        user_id=user.id,
    )
    db.add(target)
    await db.flush()
    await log_action(db, user, "target_created", "target", target.id,
                     {"domain": domain}, ip_address=request.client.host if request.client else None)
    return target


@router.post("/{target_id}/monitor")
async def toggle_monitoring(
    target_id: str,
    req: MonitorRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Enable or disable continuous monitoring for a target."""
    if req.interval not in ("hourly", "daily", "weekly"):
        raise HTTPException(status_code=400, detail="Interval must be hourly, daily, or weekly")

    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.monitoring_enabled = req.enabled
    target.monitoring_interval = req.interval
    await db.flush()
    return {
        "id": target.id,
        "domain": target.domain,
        "monitoring_enabled": target.monitoring_enabled,
        "monitoring_interval": target.monitoring_interval,
    }


@router.get("/{target_id}/changes")
async def get_target_changes(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Compare the latest 2 completed scans and return diff (new vulns, fixed vulns, new endpoints)."""
    from app.models.scan import Scan, ScanStatus
    from app.models.vulnerability import Vulnerability

    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get the latest 2 completed scans
    scans_result = await db.execute(
        select(Scan)
        .where(
            Scan.target_id == target_id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(Scan.completed_at.desc())
        .limit(2)
    )
    scans = scans_result.scalars().all()

    if len(scans) < 2:
        return {
            "target_id": target_id,
            "domain": target.domain,
            "has_changes": False,
            "message": "Need at least 2 completed scans to compare",
            "scans_available": len(scans),
        }

    latest, previous = scans[0], scans[1]

    # Get vulnerabilities for both scans
    vulns_latest = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == latest.id)
    )).scalars().all()
    vulns_previous = (await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == previous.id)
    )).scalars().all()

    def vuln_fingerprint(v):
        vt = v.vuln_type.value if hasattr(v.vuln_type, "value") else v.vuln_type
        return f"{vt}|{v.url}|{v.parameter or ''}"

    fps_latest = {vuln_fingerprint(v): v for v in vulns_latest}
    fps_previous = {vuln_fingerprint(v): v for v in vulns_previous}

    new_vulns = [fp for fp in fps_latest if fp not in fps_previous]
    fixed_vulns = [fp for fp in fps_previous if fp not in fps_latest]

    # Compare endpoints
    latest_endpoints = set()
    previous_endpoints = set()
    for v in vulns_latest:
        latest_endpoints.add(v.url)
    for v in vulns_previous:
        previous_endpoints.add(v.url)

    # Also consider scan-level endpoint counts
    new_endpoints = list(latest_endpoints - previous_endpoints)
    removed_endpoints = list(previous_endpoints - latest_endpoints)

    return {
        "target_id": target_id,
        "domain": target.domain,
        "has_changes": bool(new_vulns or fixed_vulns or new_endpoints or removed_endpoints),
        "latest_scan": {
            "id": latest.id,
            "completed_at": str(latest.completed_at),
            "vulns_count": len(vulns_latest),
            "endpoints_found": latest.endpoints_found,
        },
        "previous_scan": {
            "id": previous.id,
            "completed_at": str(previous.completed_at),
            "vulns_count": len(vulns_previous),
            "endpoints_found": previous.endpoints_found,
        },
        "new_vulns": [
            {
                "type": fp.split("|")[0],
                "url": fp.split("|")[1],
                "parameter": fp.split("|")[2] or None,
                "title": fps_latest[fp].title,
                "severity": fps_latest[fp].severity.value if hasattr(fps_latest[fp].severity, "value") else fps_latest[fp].severity,
            }
            for fp in new_vulns
        ],
        "fixed_vulns": [
            {
                "type": fp.split("|")[0],
                "url": fp.split("|")[1],
                "parameter": fp.split("|")[2] or None,
                "title": fps_previous[fp].title,
                "severity": fps_previous[fp].severity.value if hasattr(fps_previous[fp].severity, "value") else fps_previous[fp].severity,
            }
            for fp in fixed_vulns
        ],
        "new_endpoints": new_endpoints,
        "removed_endpoints": removed_endpoints,
        "summary": {
            "new_vulns_count": len(new_vulns),
            "fixed_vulns_count": len(fixed_vulns),
            "new_endpoints_count": len(new_endpoints),
            "removed_endpoints_count": len(removed_endpoints),
        },
    }


@router.get("/{target_id}/recon")
async def get_target_recon(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get comprehensive recon data for a target: subdomains, ports, technologies, endpoints."""
    from app.models.scan import Scan, ScanStatus, ScanLog
    from app.models.vulnerability import Vulnerability

    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Get all completed scans for this target
    scans_result = await db.execute(
        select(Scan).where(
            Scan.target_id == target_id,
            Scan.status == ScanStatus.COMPLETED,
        ).order_by(Scan.completed_at.desc())
    )
    scans = scans_result.scalars().all()

    # Get all vulns for target
    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.target_id == target_id)
    )
    vulns = vulns_result.scalars().all()

    # Collect all endpoints from scan logs
    endpoints = set()
    for scan in scans[:3]:  # Last 3 scans
        logs_result = await db.execute(
            select(ScanLog).where(
                ScanLog.scan_id == scan.id,
                ScanLog.phase == "endpoint",
            )
        )
        for log in logs_result.scalars().all():
            if log.data and isinstance(log.data, dict):
                for ep in log.data.get("endpoints", []):
                    if isinstance(ep, str):
                        endpoints.add(ep)
                    elif isinstance(ep, dict):
                        endpoints.add(ep.get("url", ""))

    # Collect all unique vuln URLs as endpoints too
    for v in vulns:
        if v.url:
            endpoints.add(v.url)

    # Build port info from target data
    ports = target.ports or {}

    # Build tech stack from target data
    technologies = target.technologies or {}

    # Subdomains
    subdomains = target.subdomains or []

    # Vulnerability summary by type
    vuln_summary = {}
    for v in vulns:
        vt = v.vuln_type.value if hasattr(v.vuln_type, "value") else v.vuln_type
        if vt not in vuln_summary:
            vuln_summary[vt] = {"count": 0, "severities": {}}
        vuln_summary[vt]["count"] += 1
        sev = v.severity.value if hasattr(v.severity, "value") else v.severity
        vuln_summary[vt]["severities"][sev] = vuln_summary[vt]["severities"].get(sev, 0) + 1

    # Severity distribution
    severity_dist = {}
    for v in vulns:
        sev = v.severity.value if hasattr(v.severity, "value") else v.severity
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    return {
        "target_id": target_id,
        "domain": target.domain,
        "status": target.status.value,
        "created_at": target.created_at.isoformat() if target.created_at else None,
        "total_scans": len(scans),
        "total_vulns": len(vulns),
        "total_endpoints": len(endpoints),
        "subdomains": subdomains,
        "subdomain_count": len(subdomains) if isinstance(subdomains, list) else 0,
        "technologies": technologies,
        "ports": ports,
        "endpoints": sorted(list(endpoints))[:200],  # Cap at 200
        "vuln_summary": vuln_summary,
        "severity_distribution": severity_dist,
        "recon_data": target.recon_data or {},
        "monitoring": {
            "enabled": target.monitoring_enabled,
            "interval": target.monitoring_interval,
        },
        "scan_history": [
            {
                "id": s.id,
                "scan_type": s.scan_type.value,
                "vulns_found": s.vulns_found,
                "endpoints_found": s.endpoints_found,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in scans[:10]
        ],
    }


@router.get("/{target_id}")
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/{target_id}")
async def update_target(
    target_id: str,
    target_data: TargetUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    for field, value in target_data.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    await db.flush()
    return target


@router.delete("/{target_id}")
async def delete_target(
    target_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    domain = target.domain
    await db.delete(target)
    await log_action(db, user, "target_deleted", "target", target_id,
                     {"domain": domain}, ip_address=request.client.host if request.client else None)
    return {"detail": "Target deleted"}
