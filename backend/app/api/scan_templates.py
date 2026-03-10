"""
Scan Templates API — Save and manage reusable scan configurations.

Endpoints:
  GET    /api/scan-templates          — List all templates
  POST   /api/scan-templates          — Create a template
  GET    /api/scan-templates/{id}     — Get template by ID
  PUT    /api/scan-templates/{id}     — Update template
  DELETE /api/scan-templates/{id}     — Delete template
  POST   /api/scan-templates/{id}/run — Run a scan using template config
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.scan_template import ScanTemplate
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.target import Target
from app.models.user import User
from app.api.auth import get_current_user

router = APIRouter()


class TemplateCreate(BaseModel):
    name: str
    description: str | None = None
    scan_type: str = "full"
    config: dict | None = None


class TemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    scan_type: str | None = None
    config: dict | None = None


class TemplateRun(BaseModel):
    target_id: str
    priority: int = 5


# Built-in templates
BUILTIN_TEMPLATES = [
    {
        "id": "builtin-full",
        "name": "Full Scan",
        "description": "All 13 phases: recon, subdomain, portscan, fingerprint, endpoint, vuln_scan, nuclei, ai_analysis, payload_gen, waf, exploit, evidence, report",
        "scan_type": "full",
        "config": {"phases": "all", "concurrency": 5},
        "builtin": True,
    },
    {
        "id": "builtin-quick",
        "name": "Quick Scan",
        "description": "Fast 7-phase scan: recon, endpoint discovery, vuln scanning, nuclei, AI analysis, exploit, report",
        "scan_type": "quick",
        "config": {"phases": "quick", "concurrency": 5},
        "builtin": True,
    },
    {
        "id": "builtin-stealth",
        "name": "Stealth Scan",
        "description": "Low-and-slow: all phases with reduced concurrency to avoid detection",
        "scan_type": "stealth",
        "config": {"phases": "all", "concurrency": 1, "delay_ms": 2000},
        "builtin": True,
    },
    {
        "id": "builtin-recon",
        "name": "Recon Only",
        "description": "Reconnaissance: subdomain enumeration, port scanning, technology fingerprinting",
        "scan_type": "recon",
        "config": {"phases": ["recon", "subdomain", "portscan", "fingerprint"]},
        "builtin": True,
    },
    {
        "id": "builtin-bounty",
        "name": "Bug Bounty",
        "description": "Optimized for bug bounty: respects scope, rate limits, generates HackerOne reports",
        "scan_type": "bounty",
        "config": {"phases": "all", "respect_scope": True, "rate_limit": 10, "generate_reports": True},
        "builtin": True,
    },
    {
        "id": "builtin-api",
        "name": "API Security",
        "description": "Focus on API endpoints: GraphQL, REST, authentication, IDOR, injection",
        "scan_type": "full",
        "config": {
            "focus": "api",
            "phases": "all",
            "extra_checks": ["graphql_introspection", "jwt_analysis", "idor", "api_rate_limit"],
        },
        "builtin": True,
    },
    {
        "id": "builtin-webapp",
        "name": "Web App Deep Scan",
        "description": "Deep web application testing: XSS, SQLi, CSRF, SSRF, file upload, deserialization",
        "scan_type": "full",
        "config": {
            "focus": "webapp",
            "phases": "all",
            "deep_checks": True,
            "browser_enabled": True,
        },
        "builtin": True,
    },
]


@router.get("")
async def list_templates(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List all scan templates (builtin + user-created)."""
    result = await db.execute(
        select(ScanTemplate).order_by(ScanTemplate.created_at.desc())
    )
    user_templates = result.scalars().all()

    templates = list(BUILTIN_TEMPLATES)
    for t in user_templates:
        templates.append({
            "id": t.id,
            "name": t.name,
            "description": t.description,
            "scan_type": t.scan_type,
            "config": t.config,
            "builtin": False,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        })

    return templates


@router.post("")
async def create_template(
    body: TemplateCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a custom scan template."""
    template = ScanTemplate(
        name=body.name,
        description=body.description,
        scan_type=body.scan_type,
        config=body.config or {},
        user_id=user.id,
    )
    db.add(template)
    await db.commit()
    await db.refresh(template)
    return {
        "id": template.id,
        "name": template.name,
        "description": template.description,
        "scan_type": template.scan_type,
        "config": template.config,
        "builtin": False,
        "created_at": template.created_at.isoformat() if template.created_at else None,
    }


@router.get("/{template_id}")
async def get_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Check builtins first
    for bt in BUILTIN_TEMPLATES:
        if bt["id"] == template_id:
            return bt

    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return {
        "id": template.id,
        "name": template.name,
        "description": template.description,
        "scan_type": template.scan_type,
        "config": template.config,
        "builtin": False,
    }


@router.put("/{template_id}")
async def update_template(
    template_id: str,
    body: TemplateUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if template_id.startswith("builtin-"):
        raise HTTPException(status_code=400, detail="Cannot modify builtin templates")

    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    if body.name is not None:
        template.name = body.name
    if body.description is not None:
        template.description = body.description
    if body.scan_type is not None:
        template.scan_type = body.scan_type
    if body.config is not None:
        template.config = body.config

    await db.commit()
    return {"id": template.id, "name": template.name, "status": "updated"}


@router.delete("/{template_id}")
async def delete_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if template_id.startswith("builtin-"):
        raise HTTPException(status_code=400, detail="Cannot delete builtin templates")

    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    await db.delete(template)
    await db.commit()
    return {"detail": "Template deleted"}


@router.post("/{template_id}/run")
async def run_template(
    template_id: str,
    body: TemplateRun,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Run a scan using a template's configuration."""
    from app.models.user import UserRole
    if user.role == UserRole.VIEWER and not user.is_admin:
        raise HTTPException(status_code=403, detail="Viewers cannot start scans")

    # Get template config
    config = None
    scan_type_str = "full"

    for bt in BUILTIN_TEMPLATES:
        if bt["id"] == template_id:
            config = bt.get("config", {})
            scan_type_str = bt["scan_type"]
            break

    if config is None:
        result = await db.execute(
            select(ScanTemplate).where(ScanTemplate.id == template_id)
        )
        template = result.scalar_one_or_none()
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")
        config = template.config or {}
        scan_type_str = template.scan_type

    # Verify target
    target_result = await db.execute(select(Target).where(Target.id == body.target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Check duplicate
    dup = await db.execute(
        select(Scan).where(
            Scan.target_id == body.target_id,
            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A scan is already running for this target")

    # Map scan type
    try:
        scan_type = ScanType(scan_type_str)
    except ValueError:
        scan_type = ScanType.FULL

    priority = max(1, min(10, body.priority))
    scan = Scan(
        target_id=body.target_id,
        scan_type=scan_type,
        config={**config, "template_id": template_id},
        priority=priority,
        status=ScanStatus.QUEUED,
        user_id=user.id,
    )
    db.add(scan)
    await db.flush()
    await db.commit()

    from app.core.celery_app import run_scan_task
    run_scan_task.apply_async(args=[scan.id], priority=priority - 1)

    return {
        "scan_id": scan.id,
        "template_id": template_id,
        "target": target.domain,
        "scan_type": scan_type.value,
        "status": "queued",
    }
