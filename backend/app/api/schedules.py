from datetime import datetime, timedelta

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

INTERVAL_MAP = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
    "monthly": 2592000,
}


class ScheduleCreate(BaseModel):
    target_id: str
    scan_type: ScanType = ScanType.FULL
    interval: str = "daily"  # hourly, daily, weekly, monthly


class ScheduleUpdate(BaseModel):
    scan_type: ScanType | None = None
    interval: str | None = None
    is_active: bool | None = None


@router.get("")
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Schedule).order_by(Schedule.created_at.desc()))
    return result.scalars().all()


@router.post("")
async def create_schedule(
    data: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Verify target
    result = await db.execute(select(Target).where(Target.id == data.target_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Target not found")

    interval_seconds = INTERVAL_MAP.get(data.interval)
    if not interval_seconds:
        raise HTTPException(status_code=400, detail=f"Invalid interval. Use: {', '.join(INTERVAL_MAP.keys())}")

    schedule = Schedule(
        target_id=data.target_id,
        scan_type=data.scan_type,
        interval=data.interval,
        interval_seconds=interval_seconds,
        next_run_at=datetime.utcnow() + timedelta(seconds=interval_seconds),
        created_by=user.id,
    )
    db.add(schedule)
    await db.flush()
    return schedule


@router.patch("/{schedule_id}")
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
    if data.interval is not None:
        interval_seconds = INTERVAL_MAP.get(data.interval)
        if not interval_seconds:
            raise HTTPException(status_code=400, detail="Invalid interval")
        schedule.interval = data.interval
        schedule.interval_seconds = interval_seconds
    if data.is_active is not None:
        schedule.is_active = data.is_active

    return schedule


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
