"""
Training API — Manage AI self-learning and view skills report.

Endpoints:
  POST   /api/training/start     — Start a training session (background)
  POST   /api/training/stop      — Stop continuous training
  GET    /api/training/status    — Current training status
  GET    /api/training/skills    — Full skills & capabilities report
  GET    /api/training/history   — Training session history
  DELETE /api/training/reset     — Reset knowledge base (dangerous)
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.models.knowledge import KnowledgePattern, AgentDecision
from app.models.user import User
from app.api.auth import get_current_user

router = APIRouter()

# In-memory training state (per worker)
_training_state = {
    "active": False,
    "started_at": None,
    "last_report": None,
    "celery_task_id": None,
}


@router.post("/start")
async def start_training(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Start AI training. Runs in a loop until stopped."""
    if _training_state["active"]:
        raise HTTPException(status_code=409, detail="Training is already running")

    from app.core.celery_app import run_training_task
    task = run_training_task.apply_async()

    _training_state["active"] = True
    _training_state["started_at"] = datetime.utcnow().isoformat() + "Z"
    _training_state["celery_task_id"] = task.id

    return {
        "status": "started",
        "task_id": task.id,
        "message": "Training started. AI will continuously learn from NVD, ExploitDB, "
                  "HackerOne reports, scan history, and WAF patterns. Press Stop to end.",
    }


@router.post("/stop")
async def stop_training(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Stop current training."""
    if not _training_state["active"]:
        raise HTTPException(status_code=400, detail="No training session is running")

    # Signal Celery task to stop via Redis
    if _training_state["celery_task_id"]:
        import redis as redis_lib
        from app.config import get_settings
        r = redis_lib.from_url(get_settings().redis_url)
        r.set(f"phantom:training:stop:{_training_state['celery_task_id']}", "1", ex=600)

    _training_state["active"] = False
    _training_state["celery_task_id"] = None

    return {"status": "stopped", "message": "Training session stopped."}


@router.get("/status")
async def training_status(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get current training status and quick stats."""
    # Quick knowledge stats
    total_patterns = (await db.execute(
        select(func.count(KnowledgePattern.id))
    )).scalar() or 0

    avg_confidence = (await db.execute(
        select(func.avg(KnowledgePattern.confidence))
    )).scalar() or 0

    pattern_types = {}
    type_result = await db.execute(
        select(
            KnowledgePattern.pattern_type,
            func.count(KnowledgePattern.id),
            func.avg(KnowledgePattern.confidence),
        ).group_by(KnowledgePattern.pattern_type)
    )
    for pt, count, avg_conf in type_result.all():
        pattern_types[pt] = {"count": count, "avg_confidence": round(float(avg_conf or 0), 3)}

    # Last training session
    last_session = (await db.execute(
        select(KnowledgePattern).where(
            KnowledgePattern.pattern_type == "training_session"
        ).order_by(KnowledgePattern.created_at.desc()).limit(1)
    )).scalar_one_or_none()

    last_training = None
    if last_session:
        last_training = {
            "date": last_session.created_at.isoformat() if last_session.created_at else None,
            "stats": last_session.pattern_data.get("stats", {}),
            "duration": last_session.pattern_data.get("duration_seconds", 0),
        }

    return {
        "training_active": _training_state["active"],
        "started_at": _training_state["started_at"],
        "total_patterns": total_patterns,
        "avg_confidence": round(float(avg_confidence), 3),
        "pattern_types": pattern_types,
        "last_training": last_training,
    }


@router.get("/skills")
async def get_skills_report(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate comprehensive AI skills and capabilities report."""
    from app.core.training import SkillsReport
    report_gen = SkillsReport()
    return await report_gen.generate(db)


@router.get("/history")
async def training_history(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get training session history."""
    result = await db.execute(
        select(KnowledgePattern).where(
            KnowledgePattern.pattern_type == "training_session"
        ).order_by(KnowledgePattern.created_at.desc()).limit(limit)
    )
    sessions = result.scalars().all()

    return [
        {
            "id": s.id,
            "date": s.created_at.isoformat() if s.created_at else None,
            "type": s.pattern_data.get("type", "study"),
            "duration_seconds": s.pattern_data.get("duration_seconds", 0),
            "stats": s.pattern_data.get("stats", {}),
            "phases": [
                {
                    "phase": p.get("phase"),
                    "label": p.get("label", p.get("phase")),
                    "url": p.get("url"),
                    "start": p.get("start"),
                    "end": p.get("end"),
                    "duration_seconds": p.get("duration_seconds"),
                    "results": p.get("results"),
                    "error": p.get("error"),
                    "domains": p.get("domains"),
                }
                for p in s.pattern_data.get("phases", [])
                if p.get("phase") != "error"
            ],
        }
        for s in sessions
    ]


# ---- Practice Range ----

@router.get("/range")
async def list_practice_targets(
    user: User = Depends(get_current_user),
):
    """List available practice targets and their status."""
    from app.core.practice_range import PracticeRange
    pr = PracticeRange()
    targets = await pr.list_targets()
    docker_ok = await pr.check_docker()
    return {"docker_available": docker_ok, "targets": targets}


class DeployRequest(BaseModel):
    target_id: str
    network: str = "phantom_default"


@router.post("/range/deploy")
async def deploy_practice_target(
    req: DeployRequest,
    user: User = Depends(get_current_user),
):
    """Deploy a practice target container."""
    from app.core.practice_range import PracticeRange
    pr = PracticeRange()
    return await pr.deploy_target(req.target_id, req.network)


@router.post("/range/deploy-all")
async def deploy_all_targets(
    user: User = Depends(get_current_user),
):
    """Deploy all practice targets."""
    from app.core.practice_range import PracticeRange
    pr = PracticeRange()
    return await pr.deploy_all()


@router.post("/range/stop/{target_id}")
async def stop_practice_target(
    target_id: str,
    user: User = Depends(get_current_user),
):
    """Stop a practice target."""
    from app.core.practice_range import PracticeRange
    pr = PracticeRange()
    return await pr.stop_target(target_id)


@router.get("/range/score/{target_id}")
async def score_practice_scan(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Score the latest scan on a practice target."""
    from app.core.practice_range import PracticeRange, PRACTICE_TARGETS
    from app.models.scan import Scan, ScanStatus
    from app.models.target import Target
    from app.models.vulnerability import Vulnerability

    if target_id not in PRACTICE_TARGETS:
        raise HTTPException(status_code=404, detail=f"Unknown practice target: {target_id}")

    config = PRACTICE_TARGETS[target_id]
    # Find target by domain containing the target_id
    result = await db.execute(
        select(Target).where(Target.domain.contains(target_id))
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"No scan found for {target_id}. Add it as a target and scan first.")

    # Get latest completed scan
    scan_result = await db.execute(
        select(Scan).where(
            Scan.target_id == target.id,
            Scan.status == ScanStatus.COMPLETED,
        ).order_by(Scan.completed_at.desc()).limit(1)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="No completed scan found for this target")

    # Get ALL vulns for this target (not just latest scan)
    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.target_id == target.id)
    )
    vulns = vulns_result.scalars().all()

    pr = PracticeRange()
    score = await pr.score_scan(target_id, [
        {"vuln_type": v.vuln_type, "url": v.url, "severity": v.severity}
        for v in vulns
    ])
    score["scan_id"] = scan.id
    score["scan_date"] = scan.completed_at.isoformat() if scan.completed_at else None
    return score


@router.get("/knowledge-health")
async def knowledge_health(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get knowledge base health report."""
    from app.core.knowledge_aging import KnowledgeAging
    aging = KnowledgeAging()
    return await aging.get_health_report(db)


@router.post("/knowledge-aging")
async def run_knowledge_aging(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Manually trigger knowledge aging (confidence decay + deduplication)."""
    from app.core.knowledge_aging import KnowledgeAging
    aging = KnowledgeAging()
    decay_stats = await aging.decay_confidence(db)
    dedup_stats = await aging.cleanup_duplicates(db)
    return {
        "status": "completed",
        "decay": decay_stats,
        "dedup": dedup_stats,
        "message": (
            f"Aging complete: {decay_stats['decayed']} decayed, "
            f"{decay_stats['deleted']} deleted, "
            f"{dedup_stats['merged']} merged."
        ),
    }


@router.delete("/reset")
async def reset_knowledge(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Reset the entire knowledge base. USE WITH CAUTION."""
    await db.execute(delete(KnowledgePattern))
    await db.execute(delete(AgentDecision))
    await db.commit()

    return {
        "status": "reset",
        "message": "Knowledge base has been completely reset. "
                  "Run a training session to rebuild.",
    }


# ---- Expert Knowledge Injection ----

@router.post("/inject-knowledge")
async def inject_expert_knowledge(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Inject expert-level penetration testing knowledge into the AI's knowledge base."""
    from app.core.knowledge_injection import inject_expert_knowledge as do_inject
    stats = await do_inject(db)
    return {
        "status": "injected",
        "message": f"Injected {stats['created']} expert patterns ({stats['skipped']} already existed).",
        **stats,
    }


# ---- Advanced Training Modules ----

class TrainingModuleRequest(BaseModel):
    module: str  # cve_replay, ctf, reports, waf_evasion, mutation, feedback, community, adversarial, all


class LiveFeedRequest(BaseModel):
    feed: str = "all"  # nvd, exploitdb, nuclei, hacktivity, scan_feedback, all


class AIMutationRequest(BaseModel):
    action: str = "mutate"  # mutate, evolve, targeted
    technology: str | None = None
    vuln_type: str | None = None
    count: int = 10


class ValidatePayloadsRequest(BaseModel):
    vuln_type: str | None = None
    limit: int = 50


class AdversarialTestRequest(BaseModel):
    vuln_type: str | None = None
    rounds: int = 10


@router.post("/adversarial")
async def start_adversarial_test(
    req: AdversarialTestRequest = AdversarialTestRequest(),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Start adversarial Red vs Blue testing (background Celery task)."""
    from app.core.celery_app import run_adversarial_task

    task = run_adversarial_task.apply_async(
        kwargs={"vuln_type": req.vuln_type, "rounds": req.rounds}
    )

    return {
        "status": "started",
        "task_id": task.id,
        "vuln_type": req.vuln_type or "all",
        "rounds": req.rounds,
        "message": (
            f"Adversarial testing started: {req.rounds} rounds"
            + (f" for {req.vuln_type}" if req.vuln_type else " per vuln type (xss, sqli, cmd_injection, ssrf, lfi)")
            + ". RED team generates evasive payloads, BLUE team tries to detect them."
        ),
    }


@router.get("/adversarial/stats")
async def get_adversarial_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get adversarial testing statistics and results."""
    from app.core.adversarial_testing import AdversarialTester

    tester = AdversarialTester()
    try:
        stats = await tester.get_adversarial_stats(db)
        return stats
    finally:
        await tester.close()


@router.post("/inject-module")
async def inject_training_module(
    req: TrainingModuleRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Inject knowledge from a specific training module."""
    module_map = {
        "cve_replay": ("app.core.training_modules", "inject_cve_replay_knowledge"),
        "ctf": ("app.core.training_modules", "inject_ctf_knowledge"),
        "reports": ("app.core.training_modules", "inject_report_analysis_knowledge"),
        "waf_evasion": ("app.core.advanced_training", "inject_waf_evasion_knowledge"),
        "mutation": ("app.core.advanced_training", "inject_mutation_knowledge"),
        "feedback": ("app.core.advanced_training", "inject_feedback_knowledge"),
        "community": ("app.core.community_knowledge", "inject_community_knowledge"),
        "adversarial": ("app.core.community_knowledge", "inject_adversarial_knowledge"),
    }

    if req.module == "all":
        total_stats = {"created": 0, "skipped": 0, "modules_run": 0, "details": {}}
        for mod_name, (mod_path, func_name) in module_map.items():
            try:
                import importlib
                mod = importlib.import_module(mod_path)
                func = getattr(mod, func_name)
                stats = await func(db)
                total_stats["created"] += stats.get("created", 0)
                total_stats["skipped"] += stats.get("skipped", 0)
                total_stats["modules_run"] += 1
                total_stats["details"][mod_name] = stats
            except Exception as e:
                total_stats["details"][mod_name] = {"error": str(e)[:200]}
        return {
            "status": "injected",
            "message": f"Ran {total_stats['modules_run']} modules, injected {total_stats['created']} patterns.",
            **total_stats,
        }

    if req.module not in module_map:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown module: {req.module}. Available: {', '.join(module_map.keys())}, all"
        )

    mod_path, func_name = module_map[req.module]
    try:
        import importlib
        mod = importlib.import_module(mod_path)
        func = getattr(mod, func_name)
        stats = await func(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Module error: {str(e)[:300]}")

    return {
        "status": "injected",
        "module": req.module,
        "message": f"Injected {stats.get('created', 0)} patterns ({stats.get('skipped', 0)} already existed).",
        **stats,
    }


@router.post("/live-feed")
async def run_live_feed(
    req: LiveFeedRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Fetch fresh data from live security feeds (NVD, ExploitDB, Nuclei, HackerOne)."""
    from app.core.live_feeds import (
        fetch_live_cves, fetch_live_exploits, fetch_live_nuclei_templates,
        fetch_live_hacktivity, fetch_payloads_all_the_things,
        analyze_scan_feedback, run_all_live_feeds,
    )

    feed_map = {
        "nvd": ("NVD CVEs", fetch_live_cves),
        "exploitdb": ("ExploitDB", fetch_live_exploits),
        "nuclei": ("Nuclei Templates", fetch_live_nuclei_templates),
        "hacktivity": ("HackerOne Hacktivity", fetch_live_hacktivity),
        "payloads": ("PayloadsAllTheThings", fetch_payloads_all_the_things),
        "scan_feedback": ("Scan Feedback", analyze_scan_feedback),
    }

    if req.feed == "all":
        result = await run_all_live_feeds(db)
        return {"status": "completed", **result}

    if req.feed not in feed_map:
        raise HTTPException(status_code=400, detail=f"Unknown feed: {req.feed}. Available: {', '.join(feed_map.keys())}, all")

    name, func = feed_map[req.feed]
    try:
        stats = await func(db)
        return {"status": "completed", "feed": req.feed, "name": name, **stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feed error: {str(e)[:300]}")


@router.post("/ai-mutate")
async def run_ai_mutation(
    req: AIMutationRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate AI-powered payload mutations using Claude/Ollama."""
    from app.core.ai_mutation_engine import (
        generate_ai_mutations, evolve_successful_payloads,
        generate_targeted_payloads, run_ai_mutation_engine,
    )

    if req.action == "mutate":
        stats = await generate_ai_mutations(db, max_mutations=req.count)
        return {"status": "completed", "action": "mutate", **stats}
    elif req.action == "evolve":
        stats = await evolve_successful_payloads(db)
        return {"status": "completed", "action": "evolve", **stats}
    elif req.action == "targeted":
        if not req.technology or not req.vuln_type:
            raise HTTPException(status_code=400, detail="technology and vuln_type required for targeted mutation")
        stats = await generate_targeted_payloads(db, req.technology, req.vuln_type, req.count)
        return {"status": "completed", "action": "targeted", **stats}
    elif req.action == "all":
        stats = await run_ai_mutation_engine(db)
        return {"status": "completed", "action": "all", **stats}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}. Available: mutate, evolve, targeted, all")


@router.post("/validate-payloads")
async def validate_payloads(
    req: ValidatePayloadsRequest = ValidatePayloadsRequest(),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Validate AI-generated payloads against live practice targets.

    Tests unvalidated/low-confidence payloads (ai_mutation, effective_payload)
    by sending them to running practice targets (DVWA, Juice Shop, WebGoat)
    and adjusting confidence based on results.
    """
    from app.core.payload_validator import PayloadValidator

    validator = PayloadValidator()
    stats = await validator.validate_payloads(
        db, vuln_type=req.vuln_type, limit=req.limit,
    )
    return {"status": "completed", **stats}


@router.post("/h1-deep-analyze")
async def h1_deep_analyze(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    limit: int = 20,
):
    """Deep-analyze disclosed H1 reports: regex payload extraction + Claude semantic analysis."""
    from app.core.h1_report_parser import H1ReportParser

    parser = H1ReportParser(db)
    try:
        # First collect fresh hacktivity
        collect_stats = await parser.fetch_and_store_hacktivity(pages=5)
        # Then deep-analyze disclosed reports
        analyze_stats = await parser.analyze_disclosed_reports(limit=limit)
        h1_stats = await parser.get_stats()
        return {
            "status": "completed",
            "collection": collect_stats,
            "analysis": analyze_stats,
            "kb_stats": {
                "total_reports": h1_stats["total_reports"],
                "disclosed": h1_stats["disclosed_reports"],
                "analyzed": h1_stats["analyzed_reports"],
                "insights": h1_stats["h1_insights"],
            },
        }
    finally:
        await parser.close()


@router.get("/modules")
async def list_training_modules(
    user: User = Depends(get_current_user),
):
    """List available training modules."""
    return {
        "static": [
            {"id": "expert", "name": "Expert Knowledge", "description": "Curated payloads, playbooks, WAF bypasses, false positive rules", "category": "knowledge", "endpoint": "/inject-knowledge"},
            {"id": "cve_replay", "name": "CVE Replay", "description": "50+ real-world CVE exploits with detection & PoC payloads", "category": "knowledge"},
            {"id": "ctf", "name": "CTF Techniques", "description": "40+ HackTheBox/TryHackMe techniques (JWT, SSTI, smuggling, etc.)", "category": "knowledge"},
            {"id": "reports", "name": "Report Analysis", "description": "30+ disclosed HackerOne/Bugcrowd report patterns", "category": "knowledge"},
            {"id": "waf_evasion", "name": "WAF Evasion Lab", "description": "100+ WAF bypass payloads for 10 major WAFs", "category": "evasion"},
            {"id": "mutation", "name": "Payload Mutation", "description": "30+ mutation techniques with chaining strategies", "category": "evasion"},
            {"id": "feedback", "name": "Scan Feedback Loop", "description": "25+ smart scan strategy adjustment rules", "category": "strategy"},
            {"id": "community", "name": "Community Knowledge", "description": "Nuclei templates + SecLists + OWASP test patterns", "category": "community"},
            {"id": "adversarial", "name": "Adversarial Self-Test", "description": "Scanner evasion techniques + blind spot awareness", "category": "strategy"},
        ],
        "live": [
            {"id": "nvd", "name": "Live NVD CVEs", "description": "Fetch fresh CVEs from National Vulnerability Database (new data every run)", "category": "live", "endpoint": "/live-feed"},
            {"id": "exploitdb", "name": "Live ExploitDB", "description": "Pull latest exploits from ExploitDB GitLab mirror", "category": "live", "endpoint": "/live-feed"},
            {"id": "nuclei", "name": "Live Nuclei Templates", "description": "Sync latest nuclei detection templates from GitHub", "category": "live", "endpoint": "/live-feed"},
            {"id": "hacktivity", "name": "Live HackerOne Hacktivity", "description": "Learn from latest disclosed bug bounty reports", "category": "live", "endpoint": "/live-feed"},
            {"id": "payloads", "name": "PayloadsAllTheThings", "description": "5000+ community-vetted payloads from GitHub (XSS, SQLi, SSRF, SSTI, LFI, CMD, XXE)", "category": "live", "endpoint": "/live-feed"},
            {"id": "scan_feedback", "name": "Scan Feedback Analysis", "description": "Analyze completed scans to improve detection strategy", "category": "live", "endpoint": "/live-feed"},
            {"id": "h1_deep", "name": "H1 Deep Report Analysis", "description": "Extract payloads, techniques, and endpoints from disclosed HackerOne reports (regex + Claude)", "category": "live", "endpoint": "/h1-deep-analyze"},
        ],
        "ai": [
            {"id": "mutate", "name": "AI Payload Mutation", "description": "Claude/Ollama generates new WAF-evading payload variants", "category": "ai", "endpoint": "/ai-mutate"},
            {"id": "evolve", "name": "Evolve Successful Payloads", "description": "Create evolved variants of payloads that worked in real scans", "category": "ai", "endpoint": "/ai-mutate"},
            {"id": "targeted", "name": "Targeted Payload Generation", "description": "Generate payloads for specific technology + vuln type combos", "category": "ai", "endpoint": "/ai-mutate"},
            {"id": "validate", "name": "Payload Validation Pipeline", "description": "Test AI-generated payloads against practice targets (DVWA, Juice Shop, WebGoat) and adjust confidence", "category": "ai", "endpoint": "/validate-payloads"},
        ],
    }


# ---- Knowledge Graph ----

@router.get("/graph-summary")
async def knowledge_graph_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get knowledge graph node/edge statistics."""
    from app.core.knowledge_graph import KnowledgeGraph
    return await KnowledgeGraph.get_graph_summary(db)


@router.get("/graph-tech-chain/{technology}")
async def knowledge_graph_tech_chain(
    technology: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get full knowledge chain for a technology (vulns, payloads, co-occurring techs)."""
    from app.core.knowledge_graph import KnowledgeGraph
    return await KnowledgeGraph.get_tech_chain(db, technology)


@router.get("/graph-attack-surface")
async def knowledge_graph_attack_surface(
    technologies: str,  # comma-separated
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Query attack surface for given technologies (comma-separated).
    Returns known vulns, effective techniques, and WAF bypasses."""
    from app.core.knowledge_graph import KnowledgeGraph
    tech_list = [t.strip() for t in technologies.split(",") if t.strip()]
    if not tech_list:
        raise HTTPException(status_code=400, detail="Provide at least one technology")
    return await KnowledgeGraph.query_attack_surface(db, tech_list)


@router.get("/graph-similar-targets")
async def knowledge_graph_similar_targets(
    domain: str,
    technologies: str = "",  # comma-separated
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Find targets with similar tech stacks and what vulns were found on them."""
    from app.core.knowledge_graph import KnowledgeGraph
    tech_list = [t.strip() for t in technologies.split(",") if t.strip()]
    return await KnowledgeGraph.find_similar_targets(db, domain, tech_list)


# ---- Settings (Claude API Key) ----

REDIS_KEY_CLAUDE = "phantom:settings:anthropic_api_key"


class ClaudeKeyRequest(BaseModel):
    api_key: str


@router.post("/settings/claude-key")
async def set_claude_key(
    req: ClaudeKeyRequest,
    user: User = Depends(get_current_user),
):
    """Save Claude API key (stored in Redis, persists across restarts)."""
    import redis as redis_lib
    from app.config import get_settings
    r = redis_lib.from_url(get_settings().redis_url)

    key = req.api_key.strip()
    if not key.startswith("sk-ant-"):
        raise HTTPException(status_code=400, detail="Invalid key format. Should start with sk-ant-")
    if key.startswith("sk-ant-oat"):
        raise HTTPException(status_code=400, detail="This is an OAuth token, not an API key. OAuth tokens from Max subscription are detected automatically — no need to paste them.")

    # Test the key
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=10,
            messages=[{"role": "user", "content": "ping"}],
        )
        # Key works
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Key validation failed: {str(e)[:200]}")

    r.set(REDIS_KEY_CLAUDE, key)
    # Mask key for display
    masked = key[:10] + "..." + key[-4:]

    return {"status": "saved", "key_masked": masked, "message": "Claude API key saved successfully."}


@router.get("/settings/claude-key")
async def get_claude_key_status(
    user: User = Depends(get_current_user),
):
    """Check if Claude API key is configured."""
    import redis as redis_lib
    from app.config import get_settings
    r = redis_lib.from_url(get_settings().redis_url)
    key = r.get(REDIS_KEY_CLAUDE)

    from app.ai.get_claude_key import get_claude_api_key, get_key_source
    api_key = get_claude_api_key()
    if api_key:
        source = get_key_source()
        masked = api_key[:14] + "..." + api_key[-4:] if source == "max_subscription" else api_key[:10] + "..." + api_key[-4:]
        return {
            "configured": True,
            "key_masked": masked,
            "source": source,
        }
    return {"configured": False}


@router.delete("/settings/claude-key")
async def delete_claude_key(
    user: User = Depends(get_current_user),
):
    """Remove saved Claude API key."""
    import redis as redis_lib
    from app.config import get_settings
    r = redis_lib.from_url(get_settings().redis_url)
    r.delete(REDIS_KEY_CLAUDE)
    return {"status": "deleted"}
