"""
Auto-Pilot Scanner API endpoints.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.core.autopilot import AutoPilot

router = APIRouter()


@router.get("/status")
async def autopilot_status(db: AsyncSession = Depends(get_db)):
    """Get autopilot status and next recommendation."""
    pilot = AutoPilot(db)
    return await pilot.get_status()


@router.post("/scan")
async def run_single_scan(
    program_handle: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Run a single autopilot scan (optionally for a specific program)."""
    pilot = AutoPilot(db)

    program = None
    if program_handle:
        from sqlalchemy import select
        from app.models.bounty_program import BountyProgram
        result = await db.execute(
            select(BountyProgram).where(BountyProgram.handle == program_handle)
        )
        program = result.scalar_one_or_none()
        if not program:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=f"Program '{program_handle}' not found")

    return await pilot.run_scan(program=program)


@router.post("/cycle")
async def run_cycle(
    max_scans: int = Query(3, ge=1, le=10),
    db: AsyncSession = Depends(get_db),
):
    """Run a full autopilot cycle (multiple scans)."""
    pilot = AutoPilot(db)
    return await pilot.run_cycle(max_scans=max_scans)


@router.post("/start")
async def start_autopilot(
    max_scans: int = Query(3, ge=1, le=10),
):
    """Start autopilot as a background Celery task."""
    from app.core.celery_app import autopilot_task
    task = autopilot_task.delay(max_scans)
    return {"task_id": task.id, "status": "started", "max_scans": max_scans}


@router.post("/stop")
async def stop_autopilot(task_id: str):
    """Stop a running autopilot task."""
    import redis as redis_lib
    from app.config import get_settings
    settings = get_settings()
    r = redis_lib.from_url(settings.redis_url)
    r.set(f"phantom:autopilot:stop:{task_id}", "1", ex=3600)
    return {"status": "stop_requested", "task_id": task_id}
