"""
Program Intelligence API endpoints.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.core.program_intel import ProgramIntel

router = APIRouter()


@router.post("/collect")
async def collect_programs(
    pages: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """Fetch bounty programs from HackerOne GraphQL."""
    intel = ProgramIntel(db)
    try:
        stats = await intel.collect_programs(pages=pages)
        return {"status": "ok", **stats}
    finally:
        await intel.close()


@router.post("/enrich")
async def enrich_programs(db: AsyncSession = Depends(get_db)):
    """Enrich programs with bounty data from collected hacktivity."""
    intel = ProgramIntel(db)
    try:
        stats = await intel.enrich_from_hacktivity()
        return {"status": "ok", **stats}
    finally:
        await intel.close()


@router.post("/score")
async def score_programs(db: AsyncSession = Depends(get_db)):
    """Compute ROI and difficulty scores for all programs."""
    intel = ProgramIntel(db)
    try:
        stats = await intel.compute_scores()
        return {"status": "ok", **stats}
    finally:
        await intel.close()


@router.post("/refresh")
async def full_refresh(
    pages: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """Full pipeline: collect → enrich → score."""
    intel = ProgramIntel(db)
    try:
        collect = await intel.collect_programs(pages=pages)
        enrich = await intel.enrich_from_hacktivity()
        scores = await intel.compute_scores()
        return {
            "status": "ok",
            "collection": collect,
            "enrichment": enrich,
            "scoring": scores,
        }
    finally:
        await intel.close()


@router.get("/recommendations")
async def get_recommendations(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Get top recommended programs to target."""
    intel = ProgramIntel(db)
    try:
        return await intel.get_recommendations(limit=limit)
    finally:
        await intel.close()


@router.get("/dashboard")
async def program_dashboard(db: AsyncSession = Depends(get_db)):
    """Program intelligence overview dashboard."""
    intel = ProgramIntel(db)
    try:
        return await intel.get_dashboard()
    finally:
        await intel.close()


@router.get("/{handle}")
async def program_detail(
    handle: str,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed intelligence for a specific program."""
    intel = ProgramIntel(db)
    try:
        detail = await intel.get_program_detail(handle)
        if not detail:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Program not found")
        return detail
    finally:
        await intel.close()
