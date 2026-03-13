from datetime import datetime, timedelta

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.schedule import Schedule
from app.models.scan import ScanType
from app.models.target import Target
from app.models.user import User
from app.api.auth import get_current_user

router = APIRouter()

# Legacy interval presets (kept for backward compat)
INTERVAL_MAP = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
    "monthly": 2592000,
}

# Preset cron expressions for convenience
CRON_PRESETS = {
    "hourly": "0 * * * *",
    "daily": "0 2 * * *",       # 2am daily
    "weekly": "0 2 * * 1",      # Monday 2am
    "monthly": "0 2 1 * *",     # 1st of month 2am
}


def _compute_next_run(cron_expr: str, base_time: datetime | None = None) -> datetime:
    """Compute next run time from a cron expression."""
    base = base_time or datetime.utcnow()
    cron = croniter(cron_expr, base)
    return cron.get_next(datetime)


class ScheduleCreate(BaseModel):
    target_id: str
    scan_type: ScanType = ScanType.FULL
    cron_expression: str | None = None  # e.g. "0 2 * * 1"
    interval: str | None = None         # legacy: hourly/daily/weekly/monthly
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    scan_type: ScanType | None = None
    cron_expression: str | None = None
    interval: str | None = None
    enabled: bool | None = None


class ScheduleResponse(BaseModel):
    id: str
    target_id: str
    user_id: str | None = None
    scan_type: str
    cron_expression: str | None = None
    interval: str | None = None
    enabled: bool
    is_active: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


def _schedule_to_response(sched: Schedule) -> dict:
    return {
        "id": sched.id,
        "target_id": sched.target_id,
        "user_id": sched.user_id or sched.created_by,
        "scan_type": sched.scan_type.value if hasattr(sched.scan_type, "value") else str(sched.scan_type),
        "cron_expression": sched.cron_expression,
        "interval": sched.interval,
        "enabled": sched.enabled,
        "is_active": sched.is_active,
        "last_run_at": sched.last_run_at,
        "next_run_at": sched.next_run_at,
        "created_at": sched.created_at,
        "updated_at": sched.updated_at,
    }


@router.get("")
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Schedule).order_by(Schedule.created_at.desc()))
    schedules = result.scalars().all()
    return [_schedule_to_response(s) for s in schedules]


@router.post("")
async def create_schedule(
    data: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Verify target exists
    result = await db.execute(select(Target).where(Target.id == data.target_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Target not found")

    # Resolve cron expression: explicit cron > preset interval > default daily
    cron_expr = data.cron_expression
    interval_str = data.interval
    interval_seconds = 86400  # default

    if cron_expr:
        # Validate cron expression
        if not croniter.is_valid(cron_expr):
            raise HTTPException(status_code=400, detail=f"Invalid cron expression: {cron_expr}")
    elif interval_str:
        # Check if it's a preset name
        if interval_str in CRON_PRESETS:
            cron_expr = CRON_PRESETS[interval_str]
            interval_seconds = INTERVAL_MAP.get(interval_str, 86400)
        elif croniter.is_valid(interval_str):
            # User passed a cron expression in the interval field
            cron_expr = interval_str
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid interval. Use: {', '.join(CRON_PRESETS.keys())} or a cron expression"
            )
    else:
        # Default: daily at 2am
        cron_expr = CRON_PRESETS["daily"]
        interval_str = "daily"
        interval_seconds = 86400

    now = datetime.utcnow()
    next_run = _compute_next_run(cron_expr, now)

    schedule = Schedule(
        target_id=data.target_id,
        user_id=user.id,
        scan_type=data.scan_type,
        cron_expression=cron_expr,
        interval=interval_str,
        interval_seconds=interval_seconds,
        enabled=data.enabled,
        is_active=data.enabled,
        next_run_at=next_run,
        created_by=user.id,
    )
    db.add(schedule)
    await db.flush()
    return _schedule_to_response(schedule)


@router.put("/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    data: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if data.scan_type is not None:
        schedule.scan_type = data.scan_type

    if data.cron_expression is not None:
        if not croniter.is_valid(data.cron_expression):
            raise HTTPException(status_code=400, detail=f"Invalid cron expression: {data.cron_expression}")
        schedule.cron_expression = data.cron_expression
        schedule.next_run_at = _compute_next_run(data.cron_expression)

    if data.interval is not None:
        if data.interval in CRON_PRESETS:
            schedule.interval = data.interval
            schedule.interval_seconds = INTERVAL_MAP.get(data.interval, 86400)
            if not data.cron_expression:
                schedule.cron_expression = CRON_PRESETS[data.interval]
                schedule.next_run_at = _compute_next_run(schedule.cron_expression)
        elif croniter.is_valid(data.interval):
            schedule.cron_expression = data.interval
            schedule.interval = data.interval
            schedule.next_run_at = _compute_next_run(data.interval)
        else:
            raise HTTPException(status_code=400, detail="Invalid interval or cron expression")

    if data.enabled is not None:
        schedule.enabled = data.enabled
        schedule.is_active = data.enabled

    schedule.updated_at = datetime.utcnow()
    return _schedule_to_response(schedule)


# Keep PATCH for backward compatibility
@router.patch("/{schedule_id}")
async def patch_schedule(
    schedule_id: str,
    data: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return await update_schedule(schedule_id, data, db, user)


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(schedule)
    return {"ok": True}
