import logging

from celery import Celery
from celery.signals import worker_ready
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

celery_app = Celery(
    "phantom",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.scan_timeout_minutes * 60,
    worker_max_tasks_per_child=50,
    worker_prefetch_multiplier=1,
    # Celery Beat schedule — check for due scheduled scans every 60s
    beat_schedule={
        "check-scheduled-scans": {
            "task": "phantom.check_schedules",
            "schedule": 60.0,
        },
        "check-monitoring": {
            "task": "phantom.check_monitoring",
            "schedule": 1800.0,  # every 30 minutes
        },
        "auto-live-feeds": {
            "task": "phantom.auto_live_feeds",
            "schedule": 21600.0,  # every 6 hours
        },
        "knowledge-aging": {
            "task": "phantom.knowledge_aging",
            "schedule": 86400.0,  # every 24 hours
        },
        "validate-payloads": {
            "task": "phantom.validate_payloads",
            "schedule": 7200.0,  # every 2 hours
        },
        "h1-collect-hacktivity": {
            "task": "phantom.h1_collect",
            "schedule": 43200.0,  # every 12 hours
        },
    },
)


@worker_ready.connect
def recover_stuck_scans(sender=None, **kwargs):
    """On worker startup, recover scans stuck in RUNNING status (from previous crash/restart)."""
    import asyncio

    async def _recover():
        from app.models.database import reset_engine
        reset_engine()
        from datetime import datetime
        from sqlalchemy import select
        from app.models.database import async_session
        from app.models.scan import Scan, ScanStatus

        async with async_session() as db:
            result = await db.execute(
                select(Scan).where(Scan.status == ScanStatus.RUNNING)
            )
            stuck_scans = result.scalars().all()

            if not stuck_scans:
                logger.info("Scan recovery: no stuck scans found")
                return

            for scan in stuck_scans:
                scan.status = ScanStatus.QUEUED
                scan.current_phase = f"recovery (was: {scan.current_phase})"
                logger.info(f"Scan recovery: requeueing scan {scan.id} (was at {scan.current_phase})")

            await db.commit()
            logger.info(f"Scan recovery: requeued {len(stuck_scans)} stuck scans")

            # Re-dispatch each scan as a new celery task
            for scan in stuck_scans:
                run_scan_task.delay(scan.id)
                logger.info(f"Scan recovery: dispatched scan {scan.id}")

        from app.models.database import engine
        await engine.dispose()

    try:
        asyncio.run(_recover())
    except Exception as e:
        logger.error(f"Scan recovery failed: {e}")


@celery_app.task(bind=True, name="phantom.run_scan", soft_time_limit=None, time_limit=None)
def run_scan_task(self, scan_id: str):
    """Main scan task — runs the full pentest pipeline.
    No time limit — continuous scans can run for days.
    User stops via scan STOP button.
    """
    import asyncio

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.core.pipeline import ScanPipeline
        pipeline = ScanPipeline(scan_id=scan_id, celery_task=self)
        try:
            await pipeline.run()
        finally:
            from app.models.database import engine
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="phantom.check_schedules")
def check_schedules_task():
    """Check for due scheduled scans and launch them."""
    import asyncio

    async def _check():
        from app.models.database import reset_engine
        reset_engine()

        from datetime import datetime, timedelta
        from sqlalchemy import select
        from app.models.database import async_session
        from app.models.schedule import Schedule
        from app.models.scan import Scan, ScanStatus

        async with async_session() as db:
            now = datetime.utcnow()
            result = await db.execute(
                select(Schedule).where(
                    Schedule.is_active == True,
                    Schedule.next_run_at <= now,
                )
            )
            schedules = result.scalars().all()

            for sched in schedules:
                scan = Scan(
                    target_id=sched.target_id,
                    scan_type=sched.scan_type,
                    status=ScanStatus.QUEUED,
                )
                db.add(scan)
                await db.flush()

                sched.last_run_at = now
                sched.next_run_at = now + timedelta(seconds=sched.interval_seconds)
                await db.commit()

                run_scan_task.delay(scan.id)

        # --- Detect and restart stuck scans (>2h without progress) ---
        try:
            stuck_cutoff = now - timedelta(hours=2)
            stuck_result = await db.execute(
                select(Scan).where(
                    Scan.status == ScanStatus.RUNNING,
                    Scan.started_at < stuck_cutoff,
                )
            )
            stuck_scans = stuck_result.scalars().all()
            for stuck in stuck_scans:
                stuck.status = ScanStatus.QUEUED
                stuck.current_phase = f"auto-restart (was: {stuck.current_phase})"
            if stuck_scans:
                await db.commit()
                for stuck in stuck_scans:
                    run_scan_task.delay(stuck.id)
                logger.info(f"Auto-restarted {len(stuck_scans)} stuck scans (>2h)")
        except Exception as e:
            logger.debug(f"Stuck scan check failed: {e}")

        from app.models.database import engine
        await engine.dispose()

    asyncio.run(_check())


@celery_app.task(name="phantom.check_monitoring")
def check_monitoring_task():
    """Check targets with monitoring enabled and launch quick scans if overdue."""
    import asyncio

    async def _check():
        from app.models.database import reset_engine
        reset_engine()

        from datetime import datetime, timedelta
        from sqlalchemy import select
        from app.models.database import async_session
        from app.models.target import Target
        from app.models.scan import Scan, ScanStatus, ScanType

        INTERVAL_MAP = {
            "hourly": timedelta(hours=1),
            "daily": timedelta(days=1),
            "weekly": timedelta(weeks=1),
        }

        async with async_session() as db:
            # Get all targets with monitoring enabled
            result = await db.execute(
                select(Target).where(Target.monitoring_enabled == True)
            )
            targets = result.scalars().all()
            now = datetime.utcnow()

            for target in targets:
                interval = INTERVAL_MAP.get(target.monitoring_interval, timedelta(days=1))

                # Find the latest completed scan for this target
                last_scan_result = await db.execute(
                    select(Scan)
                    .where(
                        Scan.target_id == target.id,
                        Scan.status == ScanStatus.COMPLETED,
                    )
                    .order_by(Scan.completed_at.desc())
                    .limit(1)
                )
                last_scan = last_scan_result.scalar_one_or_none()

                # Skip if there's already a running/queued scan for this target
                active_result = await db.execute(
                    select(Scan).where(
                        Scan.target_id == target.id,
                        Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
                    )
                )
                if active_result.scalar_one_or_none():
                    continue

                # Launch scan if no previous scan or last scan is older than interval
                if not last_scan or (last_scan.completed_at and now - last_scan.completed_at >= interval):
                    scan = Scan(
                        target_id=target.id,
                        scan_type=ScanType.QUICK,
                        status=ScanStatus.QUEUED,
                        config={"monitoring": True},
                    )
                    db.add(scan)
                    await db.flush()
                    await db.commit()
                    run_scan_task.delay(scan.id)

        from app.models.database import engine
        await engine.dispose()

    asyncio.run(_check())


@celery_app.task(bind=True, name="phantom.run_training")
def run_training_task(self):
    """
    Autonomous AI training loop. Phantom decides what to do and when.

    Flow:
    1. Study phase (fast): NVD, ExploitDB, HackerOne, scan history, gaps, WAF
    2. Hunt phase (continuous): Scan bug bounty targets one by one, AI decides everything
    3. After each scan: AI analyzes results and decides next action
    4. No fixed waits — Phantom works as fast as it can
    """
    import asyncio
    import time
    import logging
    import redis as redis_lib

    logger = logging.getLogger(__name__)
    r = redis_lib.from_url(settings.redis_url)
    task_id = self.request.id
    cycle = 0

    def _should_stop():
        if r.get(f"phantom:training:stop:{task_id}"):
            r.delete(f"phantom:training:stop:{task_id}")
            return True
        return False

    while True:
        cycle += 1
        logger.info(f"=== Training cycle {cycle} ===")

        # --- Study Phase: learn from data sources (fast, ~2-5s) ---
        if cycle == 1 or cycle % 5 == 0:
            # Study every 5 scans, or on first cycle
            logger.info(f"Study phase (cycle {cycle})...")
            try:
                result = _run_study_phase()
                logger.info(f"Study done: {result.get('stats', {})}")
            except Exception as e:
                logger.error(f"Study phase error: {e}")

        if _should_stop():
            logger.info(f"Training stopped by user after cycle {cycle}")
            return {"stopped_at_cycle": cycle}

        # --- Hunt Phase: scan a real bug bounty target ---
        logger.info(f"Hunt phase (cycle {cycle}): scanning bug bounty target...")
        try:
            scan_result = _run_hunt_phase(cycle)
            domain = scan_result.get("domain", "?")
            vulns = scan_result.get("vulns_found", 0)
            endpoints = scan_result.get("endpoints_found", 0)
            logger.info(
                f"Hunt complete: {domain} — {vulns} vulns, {endpoints} endpoints"
            )

            # AI decides: if found a lot, go deeper on related targets
            if vulns >= 5:
                logger.info(f"High-value target {domain} ({vulns} vulns) — "
                           f"AI will prioritize similar targets next cycle")
        except Exception as e:
            logger.error(f"Hunt phase error: {e}")
            # Brief pause on error before retrying
            time.sleep(10)

        if _should_stop():
            logger.info(f"Training stopped by user after cycle {cycle}")
            return {"stopped_at_cycle": cycle}

        # No fixed wait — immediately start next cycle
        # Just a 2s breath to not hammer the system
        time.sleep(2)


def _run_study_phase() -> dict:
    """Run the study phase: learn from NVD, ExploitDB, HackerOne, etc."""
    import asyncio

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.training import TrainingEngine

        engine_inst = TrainingEngine()
        try:
            async with async_session() as db:
                report = await engine_inst.study(db)
                return report
        finally:
            await engine_inst.close()
            from app.models.database import engine
            await engine.dispose()

    return asyncio.run(_run())


@celery_app.task(name="phantom.auto_live_feeds")
def auto_live_feeds_task():
    """Auto-fetch live security data every 6 hours."""
    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.live_feeds import run_all_live_feeds

        try:
            async with async_session() as db:
                result = await run_all_live_feeds(db)
                logger.info(f"Auto live feeds: created={result.get('total_created', 0)}")
                return result
        finally:
            from app.models.database import engine
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(bind=True, name="phantom.run_adversarial")
def run_adversarial_task(self, vuln_type: str | None = None, rounds: int = 10):
    """
    Adversarial Red vs Blue testing task.
    Triggered manually — runs `rounds` rounds per vuln_type.
    """
    import asyncio
    import logging
    import redis as redis_lib

    logger = logging.getLogger(__name__)
    r = redis_lib.from_url(settings.redis_url)
    task_id = self.request.id

    # Store task_id in Redis for status tracking
    r.set(f"phantom:adversarial:task:{task_id}", "running", ex=7200)

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.adversarial_testing import AdversarialTester

        tester = AdversarialTester()
        try:
            async with async_session() as db:
                result = await tester.run_red_vs_blue(db, vuln_type=vuln_type, rounds=rounds)
                return result
        finally:
            await tester.close()
            from app.models.database import engine
            await engine.dispose()

    try:
        result = asyncio.run(_run())
        r.set(f"phantom:adversarial:task:{task_id}", "completed", ex=7200)
        logger.info(
            f"Adversarial testing complete: {result['rounds_played']} rounds, "
            f"RED {result['red_wins']} / BLUE {result['blue_wins']}"
        )
        return result
    except Exception as e:
        r.set(f"phantom:adversarial:task:{task_id}", f"failed:{str(e)[:200]}", ex=7200)
        logger.error(f"Adversarial testing failed: {e}")
        raise


def _run_hunt_phase(cycle: int) -> dict:
    """Run hunt phase: full scan on a random bug bounty target."""
    import asyncio

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.bounty_scanner import run_bounty_training_scan

        try:
            async with async_session() as db:
                result = await run_bounty_training_scan(db)
                return result
        finally:
            from app.models.database import engine
            await engine.dispose()

    return asyncio.run(_run())


@celery_app.task(name="phantom.knowledge_aging")
def knowledge_aging_task():
    """Periodic knowledge aging: decay stale patterns and deduplicate."""
    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.knowledge_aging import KnowledgeAging

        aging = KnowledgeAging()
        try:
            async with async_session() as db:
                decay_stats = await aging.decay_confidence(db)
                dedup_stats = await aging.cleanup_duplicates(db)
                logger.info(
                    f"Knowledge aging complete: decay={decay_stats}, dedup={dedup_stats}"
                )
                return {"decay": decay_stats, "dedup": dedup_stats}
        finally:
            from app.models.database import engine
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="phantom.validate_payloads")
def validate_payloads_task():
    """Periodic payload validation: test AI-generated payloads against practice targets."""
    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.payload_validator import PayloadValidator

        validator = PayloadValidator()

        # Check if any practice target is running before doing DB work
        any_running = False
        for key in ["dvwa", "juice-shop", "webgoat", "bwapp"]:
            if await validator._check_target_running(key):
                any_running = True
                break

        if not any_running:
            logger.info("Payload validation skipped — no practice targets running")
            return {"skipped": True, "reason": "no_targets_running"}

        try:
            async with async_session() as db:
                result = await validator.validate_payloads(db, limit=30)
                logger.info(
                    f"Payload validation: tested={result['tested']}, "
                    f"confirmed={result['confirmed']}, failed={result['failed']}"
                )
                return result
        finally:
            from app.models.database import engine
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(bind=True, name="phantom.autopilot")
def autopilot_task(self, max_scans: int = 3):
    """Autopilot: intelligently scan bounty programs."""
    import asyncio
    import logging
    import redis as redis_lib

    logger = logging.getLogger(__name__)
    r = redis_lib.from_url(settings.redis_url)
    task_id = self.request.id

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.autopilot import AutoPilot

        results = []
        try:
            for i in range(max_scans):
                if r.get(f"phantom:autopilot:stop:{task_id}"):
                    r.delete(f"phantom:autopilot:stop:{task_id}")
                    logger.info(f"Autopilot stopped by user after {i} scans")
                    break

                async with async_session() as db:
                    pilot = AutoPilot(db)
                    result = await pilot.run_scan()
                    results.append(result)
                    logger.info(
                        f"Autopilot scan {i+1}/{max_scans}: "
                        f"{result.get('domain', '?')} — {result.get('vulns_found', 0)} vulns"
                    )
                    if result["status"] == "no_programs":
                        break
        finally:
            from app.models.database import engine
            await engine.dispose()

        return {
            "scans_run": len(results),
            "total_vulns": sum(r.get("vulns_found", 0) for r in results),
            "results": results,
        }

    return asyncio.run(_run())


@celery_app.task(name="phantom.h1_collect")
def h1_collect_task():
    """Periodic HackerOne hacktivity collection and analysis."""
    import asyncio
    import logging

    logger = logging.getLogger(__name__)

    async def _run():
        from app.models.database import reset_engine
        reset_engine()
        from app.models.database import async_session
        from app.core.h1_report_parser import H1ReportParser

        try:
            async with async_session() as db:
                parser = H1ReportParser(db)
                try:
                    collect = await parser.fetch_and_store_hacktivity(pages=10)
                    analyze = await parser.analyze_disclosed_reports(limit=10)
                    logger.info(
                        f"H1 collect: stored={collect['stored']}, "
                        f"analyzed={analyze['analyzed']}, "
                        f"patterns={analyze['patterns_created']}"
                    )
                    return {"collection": collect, "analysis": analyze}
                finally:
                    await parser.close()
        finally:
            from app.models.database import engine
            await engine.dispose()

    asyncio.run(_run())
