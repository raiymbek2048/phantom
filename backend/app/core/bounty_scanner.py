"""
Bug Bounty Training Scanner

Runs REAL scans on bug bounty program targets using the full PHANTOM pipeline.
The AI decides what to do — recon, fingerprint, exploit, everything.

Each training cycle:
1. Pick a random bug bounty target
2. Create/find Target in DB
3. Launch a full scan via ScanPipeline
4. AI orchestrator decides all phases and techniques
5. Results feed back into the knowledge base automatically
"""
import logging
import random
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.target import Target, TargetSource
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

# Bug bounty programs that explicitly allow security testing
BOUNTY_TARGETS = [
    {
        "domain": "www.yahoo.com",
        "program": "Yahoo",
        "platform": "hackerone",
        "url": "https://hackerone.com/yahoo",
    },
    {
        "domain": "www.shopify.com",
        "program": "Shopify",
        "platform": "hackerone",
        "url": "https://hackerone.com/shopify",
    },
    {
        "domain": "gitlab.com",
        "program": "GitLab",
        "platform": "hackerone",
        "url": "https://hackerone.com/gitlab",
    },
    {
        "domain": "www.dropbox.com",
        "program": "Dropbox",
        "platform": "hackerone",
        "url": "https://hackerone.com/dropbox",
    },
    {
        "domain": "www.uber.com",
        "program": "Uber",
        "platform": "hackerone",
        "url": "https://hackerone.com/uber",
    },
    {
        "domain": "www.paypal.com",
        "program": "PayPal",
        "platform": "hackerone",
        "url": "https://hackerone.com/paypal",
    },
    {
        "domain": "www.coinbase.com",
        "program": "Coinbase",
        "platform": "hackerone",
        "url": "https://hackerone.com/coinbase",
    },
    {
        "domain": "slack.com",
        "program": "Slack",
        "platform": "hackerone",
        "url": "https://hackerone.com/slack",
    },
    {
        "domain": "www.tiktok.com",
        "program": "TikTok",
        "platform": "hackerone",
        "url": "https://hackerone.com/tiktok",
    },
    {
        "domain": "www.spotify.com",
        "program": "Spotify",
        "platform": "hackerone",
        "url": "https://hackerone.com/spotify",
    },
    {
        "domain": "www.airbnb.com",
        "program": "Airbnb",
        "platform": "hackerone",
        "url": "https://hackerone.com/airbnb",
    },
    {
        "domain": "www.grab.com",
        "program": "Grab",
        "platform": "hackerone",
        "url": "https://hackerone.com/grab",
    },
    {
        "domain": "www.starbucks.com",
        "program": "Starbucks",
        "platform": "hackerone",
        "url": "https://hackerone.com/starbucks",
    },
    {
        "domain": "www.pinterest.com",
        "program": "Pinterest",
        "platform": "bugcrowd",
        "url": "https://bugcrowd.com/pinterest",
    },
    {
        "domain": "www.indeed.com",
        "program": "Indeed",
        "platform": "hackerone",
        "url": "https://hackerone.com/indeed",
    },
    {
        "domain": "www.grammarly.com",
        "program": "Grammarly",
        "platform": "hackerone",
        "url": "https://hackerone.com/grammarly",
    },
    {
        "domain": "www.wordpress.com",
        "program": "WordPress",
        "platform": "hackerone",
        "url": "https://hackerone.com/automattic",
    },
    {
        "domain": "www.zomato.com",
        "program": "Zomato",
        "platform": "hackerone",
        "url": "https://hackerone.com/zomato",
    },
    {
        "domain": "www.vimeo.com",
        "program": "Vimeo",
        "platform": "hackerone",
        "url": "https://hackerone.com/vimeo",
    },
    {
        "domain": "www.semrush.com",
        "program": "Semrush",
        "platform": "hackerone",
        "url": "https://hackerone.com/semrush",
    },
    {
        "domain": "www.reddit.com",
        "program": "Reddit",
        "platform": "hackerone",
        "url": "https://hackerone.com/reddit",
    },
    {
        "domain": "www.notion.so",
        "program": "Notion",
        "platform": "hackerone",
        "url": "https://hackerone.com/notion",
    },
    {
        "domain": "www.figma.com",
        "program": "Figma",
        "platform": "hackerone",
        "url": "https://hackerone.com/figma",
    },
    {
        "domain": "www.canva.com",
        "program": "Canva",
        "platform": "bugcrowd",
        "url": "https://bugcrowd.com/canva",
    },
    {
        "domain": "www.twitch.tv",
        "program": "Twitch",
        "platform": "hackerone",
        "url": "https://hackerone.com/twitch",
    },
    {
        "domain": "mail.ru",
        "program": "Mail.ru",
        "platform": "hackerone",
        "url": "https://hackerone.com/mailru",
    },
    {
        "domain": "www.booking.com",
        "program": "Booking.com",
        "platform": "hackerone",
        "url": "https://hackerone.com/bookingcom",
    },
    {
        "domain": "www.alibaba.com",
        "program": "Alibaba",
        "platform": "hackerone",
        "url": "https://hackerone.com/alibaba",
    },
    {
        "domain": "www.cloudflare.com",
        "program": "Cloudflare",
        "platform": "hackerone",
        "url": "https://hackerone.com/cloudflare",
    },
    {
        "domain": "www.snapchat.com",
        "program": "Snapchat",
        "platform": "hackerone",
        "url": "https://hackerone.com/snapchat",
    },
]


async def run_bounty_training_scan(db: AsyncSession) -> dict:
    """
    Pick a random bug bounty target and run a FULL scan through the pipeline.
    The AI orchestrator decides what to check and how deep to go.

    Returns dict with domain, program, scan_id, vulns_found.
    """
    # Pick random target
    target_info = random.choice(BOUNTY_TARGETS)
    domain = target_info["domain"]
    program = target_info["program"]

    logger.info(f"Bounty training: selected {domain} ({program})")

    # Find or create target in DB
    result = await db.execute(
        select(Target).where(Target.domain == domain)
    )
    target = result.scalar_one_or_none()

    if not target:
        target = Target(
            domain=domain,
            source=TargetSource.HACKERONE if target_info["platform"] == "hackerone" else TargetSource.BUGCROWD,
            bounty_program_url=target_info.get("url"),
            notes=f"Auto-added by training: {program} bug bounty program",
        )
        db.add(target)
        await db.flush()
        logger.info(f"Created target: {domain} (id={target.id})")
    else:
        logger.info(f"Found existing target: {domain} (id={target.id})")

    # Create scan — use FULL type so AI gets maximum freedom
    scan = Scan(
        target_id=target.id,
        scan_type=ScanType.FULL,
        status=ScanStatus.QUEUED,
        config={
            "training_mode": True,
            "program": program,
            "platform": target_info["platform"],
        },
    )
    db.add(scan)
    await db.commit()

    scan_id = scan.id
    logger.info(f"Created training scan: {scan_id} for {domain}")

    # Run the FULL pipeline — AI decides everything
    from app.core.pipeline import ScanPipeline
    pipeline = ScanPipeline(scan_id=scan_id)

    try:
        await pipeline.run()
    except Exception as e:
        logger.error(f"Training scan failed for {domain}: {e}")

    # Reload scan to get results
    await db.refresh(scan)

    # Count vulns found
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = vuln_result.scalars().all()

    vuln_summary = {}
    for v in vulns:
        vtype = v.vuln_type.value if hasattr(v.vuln_type, "value") else str(v.vuln_type)
        vuln_summary[vtype] = vuln_summary.get(vtype, 0) + 1

    result = {
        "domain": domain,
        "program": program,
        "platform": target_info["platform"],
        "scan_id": scan_id,
        "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        "vulns_found": len(vulns),
        "vuln_types": vuln_summary,
        "endpoints_found": scan.endpoints_found or 0,
        "subdomains_found": scan.subdomains_found or 0,
    }

    logger.info(
        f"Training scan complete: {domain} — "
        f"{len(vulns)} vulns, {scan.endpoints_found or 0} endpoints"
    )

    # Save as training session record for history
    from app.models.knowledge import KnowledgePattern
    duration = (datetime.utcnow() - scan.started_at).total_seconds() if scan.started_at else 0
    session = KnowledgePattern(
        pattern_type="training_session",
        technology="bounty_hunt",
        vuln_type=None,
        confidence=1.0,
        pattern_data={
            "type": "hunt",
            "duration_seconds": round(duration, 1),
            "stats": {
                "vulns_found": len(vulns),
                "endpoints_found": scan.endpoints_found or 0,
                "subdomains_found": scan.subdomains_found or 0,
            },
            "phases": [
                {
                    "phase": "bounty_scan",
                    "label": f"Hunt: {domain} ({program})",
                    "url": f"https://{domain}",
                    "start": scan.started_at.isoformat() if scan.started_at else None,
                    "end": (scan.completed_at or datetime.utcnow()).isoformat(),
                    "duration_seconds": round(duration, 1),
                    "results": len(vulns),
                    "domains": [domain],
                    "vuln_types": vuln_summary,
                },
            ],
        },
    )
    db.add(session)
    await db.commit()

    return result
