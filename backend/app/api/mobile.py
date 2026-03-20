"""Mobile API — APK upload, static analysis, dynamic analysis, and target creation."""
import asyncio
import os
import tempfile
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.mobile_api_extractor import MobileAPIExtractor
from app.models.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

# Dynamic scan state (singleton — one scan at a time)
_dynamic_scan_task: asyncio.Task | None = None
_dynamic_scan_result: dict | None = None
_dynamic_scan_status: str = "idle"  # idle, running, completed, failed


@router.post("/analyze-apk")
async def analyze_apk(file: UploadFile = File(...)):
    """Upload an APK file for analysis. Returns extracted endpoints, secrets, and issues."""
    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(400, "File must be an APK")

    # Save to temp file
    tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    try:
        content = await file.read()
        if len(content) > 200 * 1024 * 1024:  # 200MB limit
            raise HTTPException(400, "APK too large (max 200MB)")
        tmp.write(content)
        tmp.close()

        extractor = MobileAPIExtractor()
        result = await extractor.extract_from_apk(tmp.name)

        if "error" in result:
            raise HTTPException(500, result["error"])

        # Generate findings
        findings = extractor.generate_findings(result)
        result["findings"] = findings
        result["findings_count"] = len(findings)

        return result

    finally:
        os.unlink(tmp.name)


@router.post("/analyze-apk-url")
async def analyze_apk_url(url: str = Form(...)):
    """Download and analyze APK from URL."""
    if not url.startswith("http"):
        raise HTTPException(400, "Invalid URL")

    extractor = MobileAPIExtractor()
    result = await extractor.extract_from_url(url)

    if "error" in result:
        raise HTTPException(500, result["error"])

    findings = extractor.generate_findings(result)
    result["findings"] = findings
    result["findings_count"] = len(findings)

    return result


@router.post("/analyze-package")
async def analyze_package(package_name: str = Form(...)):
    """Analyze APK by Android package name (downloads from public sources)."""
    if not package_name or "." not in package_name:
        raise HTTPException(400, "Invalid package name (e.g. kz.homebank.mobile)")

    extractor = MobileAPIExtractor()
    result = await extractor.extract_from_package(package_name)

    if "error" in result:
        raise HTTPException(500, result["error"])

    findings = extractor.generate_findings(result)
    result["findings"] = findings
    result["findings_count"] = len(findings)

    return result


# ─── Dynamic Analysis Endpoints ─────────────────────────────────


async def _run_dynamic_scan(apk_path: str, package_name: str, duration: int):
    """Background task: run dynamic scan."""
    global _dynamic_scan_result, _dynamic_scan_status
    try:
        from app.modules.mobile_dynamic_scanner import MobileDynamicScanner
        scanner = MobileDynamicScanner()
        _dynamic_scan_status = "running"
        _dynamic_scan_result = await scanner.scan(apk_path, package_name, duration)
        _dynamic_scan_status = "completed"
    except Exception as e:
        logger.error(f"Dynamic scan failed: {e}", exc_info=True)
        _dynamic_scan_result = {"errors": [str(e)]}
        _dynamic_scan_status = "failed"
    finally:
        try:
            os.unlink(apk_path)
        except OSError:
            pass


@router.post("/dynamic-scan")
async def start_dynamic_scan(
    package_name: str = Form(...),
    duration: int = Form(120),
):
    """Start dynamic APK analysis — runs app in emulator, intercepts traffic.

    1. Downloads APK by package name
    2. Installs in Android emulator
    3. Starts mitmproxy + Frida SSL bypass
    4. Launches app, auto-interacts
    5. Captures all HTTP/S traffic
    6. Returns endpoints, tokens, headers
    """
    global _dynamic_scan_task, _dynamic_scan_status, _dynamic_scan_result

    if _dynamic_scan_status == "running":
        raise HTTPException(409, "Dynamic scan already running")

    if not package_name or "." not in package_name:
        raise HTTPException(400, "Invalid package name")

    # Download APK via static extractor
    extractor = MobileAPIExtractor()
    apk_path = await extractor.download_apk(package_name)
    if not apk_path:
        raise HTTPException(404, f"Could not download APK for {package_name}")

    _dynamic_scan_result = None
    _dynamic_scan_status = "running"
    _dynamic_scan_task = asyncio.create_task(
        _run_dynamic_scan(apk_path, package_name, duration)
    )

    return {
        "status": "started",
        "package_name": package_name,
        "duration": duration,
        "message": f"Dynamic scan started. Check /api/mobile/dynamic-status for progress.",
    }


@router.post("/dynamic-scan-apk")
async def start_dynamic_scan_apk(
    file: UploadFile = File(...),
    package_name: str = Form(""),
    duration: int = Form(120),
):
    """Start dynamic scan with uploaded APK file."""
    global _dynamic_scan_task, _dynamic_scan_status, _dynamic_scan_result

    if _dynamic_scan_status == "running":
        raise HTTPException(409, "Dynamic scan already running")

    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(400, "File must be an APK")

    tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    content = await file.read()
    tmp.write(content)
    tmp.close()

    _dynamic_scan_result = None
    _dynamic_scan_status = "running"
    _dynamic_scan_task = asyncio.create_task(
        _run_dynamic_scan(tmp.name, package_name, duration)
    )

    return {
        "status": "started",
        "package_name": package_name or "(auto-detect)",
        "duration": duration,
    }


@router.get("/dynamic-status")
async def dynamic_scan_status():
    """Get dynamic scan status and results."""
    return {
        "status": _dynamic_scan_status,
        "result": _dynamic_scan_result,
    }


@router.get("/emulator-status")
async def emulator_status():
    """Check if Android emulator is running."""
    try:
        from app.modules.mobile_dynamic_scanner import MobileDynamicScanner
        scanner = MobileDynamicScanner()
        running = await scanner.is_emulator_running()
        return {"emulator_running": running}
    except Exception as e:
        return {"emulator_running": False, "error": str(e)}


# ─── Static → Targets Pipeline ──────────────────────────────────


@router.post("/create-targets-from-apk")
async def create_targets_from_apk(
    package_name: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    """Analyze APK and create PHANTOM targets from discovered base URLs.

    Pipeline: APK download → decompile → extract endpoints → create targets.
    Returns list of created/existing targets ready for scanning.
    """
    from app.models.target import Target
    from sqlalchemy import select

    if not package_name or "." not in package_name:
        raise HTTPException(400, "Invalid package name")

    # Step 1: Static analysis
    extractor = MobileAPIExtractor()
    result = await extractor.extract_from_package(package_name)
    if "error" in result:
        raise HTTPException(500, result["error"])

    findings = extractor.generate_findings(result)

    # Step 2: Extract unique domains from base_urls and api_endpoints
    domains = set()
    for url in result.get("base_urls", []):
        try:
            parsed = urlparse(url)
            if parsed.hostname and not _is_internal(parsed.hostname):
                domains.add(parsed.hostname)
        except Exception:
            pass
    for ep in result.get("api_endpoints", []):
        url = ep if isinstance(ep, str) else ep.get("url", "")
        try:
            parsed = urlparse(url)
            if parsed.hostname and not _is_internal(parsed.hostname):
                domains.add(parsed.hostname)
        except Exception:
            pass

    # Step 3: Create targets for each domain
    created = []
    existing = []
    for domain in sorted(domains):
        # Check if target already exists
        stmt = select(Target).where(Target.domain == domain)
        db_result = await db.execute(stmt)
        target = db_result.scalar_one_or_none()

        if target:
            existing.append({
                "id": str(target.id),
                "domain": target.domain,
                "status": "existing",
            })
        else:
            target = Target(
                domain=domain,
                scope=f"*.{domain}",
                tags=["mobile", "apk", package_name],
            )
            db.add(target)
            await db.flush()
            created.append({
                "id": str(target.id),
                "domain": domain,
                "status": "created",
            })

    await db.commit()

    return {
        "package_name": package_name,
        "static_findings": len(findings),
        "domains_found": len(domains),
        "targets_created": len(created),
        "targets_existing": len(existing),
        "targets": created + existing,
        "base_urls": result.get("base_urls", []),
        "secrets_count": len(result.get("secrets", [])),
        "android_issues_count": len(result.get("android_issues", [])),
    }


def _is_internal(hostname: str) -> bool:
    """Check if hostname is internal/localhost."""
    internal = (
        "localhost", "127.0.0.1", "0.0.0.0", "10.0.2.2",
        "example.com", "example.org",
    )
    if hostname in internal:
        return True
    if hostname.startswith("10.") or hostname.startswith("192.168."):
        return True
    if hostname.startswith("172.") and 16 <= int(hostname.split(".")[1]) <= 31:
        return True
    return False
