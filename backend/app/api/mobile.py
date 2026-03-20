"""Mobile API — APK upload and analysis endpoints."""
import os
import tempfile
import logging

from fastapi import APIRouter, UploadFile, File, HTTPException, Form

from app.modules.mobile_api_extractor import MobileAPIExtractor

logger = logging.getLogger(__name__)
router = APIRouter()


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
