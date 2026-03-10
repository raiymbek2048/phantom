from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.models.database import engine, Base
from app.api import targets, scans, vulnerabilities, reports, auth, websocket, schedules, training, dashboard, scan_templates, audit, notifications, hackerone, programs, submissions, autopilot, validate_report


async def _ensure_pg_enums(conn):
    """Add new enum values and columns to PostgreSQL."""
    from sqlalchemy import text
    new_values = {
        "vulnstatus": ["TRIAGED", "VERIFIED"],
        "h1status": [
            "DRAFT", "SUBMITTED", "NEW", "TRIAGED", "NEEDS_MORE_INFO",
            "ACCEPTED", "DUPLICATE", "INFORMATIVE", "NOT_APPLICABLE",
            "SPAM", "RESOLVED", "BOUNTY_PAID",
        ],
    }
    for enum_name, values in new_values.items():
        for val in values:
            try:
                await conn.execute(text(
                    f"ALTER TYPE {enum_name} ADD VALUE IF NOT EXISTS '{val}'"
                ))
            except Exception:
                pass

    # Add new columns to existing tables
    new_columns = [
        ("targets", "tags", "JSONB"),
    ]
    for table, column, col_type in new_columns:
        try:
            await conn.execute(text(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_type}"
            ))
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Alter enums outside transaction (requires autocommit)
    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="AUTOCOMMIT")
        await _ensure_pg_enums(conn)
    yield
    # Shutdown
    await engine.dispose()


settings = get_settings()

app = FastAPI(
    title="PHANTOM API",
    description="AI-Powered Autonomous Penetration Testing System",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost",
        "http://10.99.7.53",
        "https://10.99.7.53",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])
app.include_router(training.router, prefix="/api/training", tags=["training"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(scan_templates.router, prefix="/api/scan-templates", tags=["scan-templates"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["notifications"])
app.include_router(hackerone.router, prefix="/api/hackerone", tags=["hackerone"])
app.include_router(programs.router, prefix="/api/programs", tags=["programs"])
app.include_router(submissions.router, prefix="/api/submissions", tags=["submissions"])
app.include_router(autopilot.router, prefix="/api/autopilot", tags=["autopilot"])
app.include_router(validate_report.router, prefix="/api/validate", tags=["validate"])
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])


@app.get("/api/health")
async def health_check():
    from app.ai.llm_engine import LLMEngine
    llm = LLMEngine()
    llm_available = await llm.is_available()
    provider = llm.provider
    await llm.close()
    return {
        "status": "ok",
        "service": "PHANTOM",
        "llm_provider": provider,
        "llm_available": llm_available,
    }
