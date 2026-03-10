"""
HackerOne API endpoints.

Provides access to H1 data collection, analysis, and statistics.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.core.h1_report_parser import H1ReportParser

router = APIRouter()


@router.post("/collect")
async def collect_hacktivity(
    pages: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """Fetch hacktivity from HackerOne and store in knowledge base."""
    parser = H1ReportParser(db)
    try:
        stats = await parser.fetch_and_store_hacktivity(pages=pages)
        return {"status": "ok", **stats}
    finally:
        await parser.close()


@router.post("/analyze")
async def analyze_disclosed(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """Analyze disclosed reports with Claude and extract patterns."""
    parser = H1ReportParser(db)
    try:
        stats = await parser.analyze_disclosed_reports(limit=limit)
        return {"status": "ok", **stats}
    finally:
        await parser.close()


@router.get("/stats")
async def h1_stats(db: AsyncSession = Depends(get_db)):
    """Get statistics about collected H1 data."""
    parser = H1ReportParser(db)
    try:
        return await parser.get_stats()
    finally:
        await parser.close()


@router.post("/collect-and-analyze")
async def collect_and_analyze(
    pages: int = 10,
    analyze_limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """Full pipeline: collect hacktivity + analyze disclosed reports."""
    parser = H1ReportParser(db)
    try:
        collect_stats = await parser.fetch_and_store_hacktivity(pages=pages)
        analyze_stats = await parser.analyze_disclosed_reports(limit=analyze_limit)
        return {
            "status": "ok",
            "collection": collect_stats,
            "analysis": analyze_stats,
        }
    finally:
        await parser.close()
