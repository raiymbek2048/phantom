"""
Live Data Feeds — Fresh Security Intelligence for PHANTOM

Unlike the static training module, this fetcher pulls NEW data from live APIs
on every run, using Redis to track progress and avoid re-fetching.

Feeds:
1. NVD CVE Feed (cve_live) — Recent CVEs with CVSS, CWE, CPE extraction
2. ExploitDB Feed (exploit_live) — Recent exploit files from GitLab mirror
3. Nuclei Templates (nuclei_live) — Latest detection templates from GitHub
4. HackerOne Hacktivity (hacktivity_live) — Disclosed bug reports
5. Scan Feedback Analysis (scan_insight) — Learn from own completed scans
"""
import asyncio
import json
import logging
import re
import uuid
import yaml
from datetime import datetime, timedelta
from collections import defaultdict

import httpx
import redis as redis_lib
from sqlalchemy import select, func, and_, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.knowledge import KnowledgePattern
from app.models.vulnerability import Vulnerability, VulnType, Severity
from app.models.scan import Scan, ScanStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE / CPE mappings (shared with training.py)
# ---------------------------------------------------------------------------

CWE_TO_VULN_TYPE = {
    "CWE-79": "xss_reflected", "CWE-80": "xss_reflected", "CWE-87": "xss_reflected",
    "CWE-89": "sqli", "CWE-90": "sqli", "CWE-564": "sqli",
    "CWE-918": "ssrf",
    "CWE-22": "lfi", "CWE-23": "lfi", "CWE-36": "lfi",
    "CWE-78": "cmd_injection", "CWE-77": "cmd_injection", "CWE-94": "cmd_injection",
    "CWE-502": "deserialization",
    "CWE-611": "xxe",
    "CWE-601": "open_redirect",
    "CWE-352": "csrf",
    "CWE-284": "idor", "CWE-639": "idor", "CWE-862": "idor",
    "CWE-1321": "prototype_pollution",
    "CWE-384": "session_fixation",
    "CWE-614": "misconfig", "CWE-16": "misconfig",
    "CWE-200": "info_disclosure", "CWE-209": "info_disclosure",
    "CWE-532": "info_disclosure",
    "CWE-1336": "ssti",
}

TECH_FROM_CPE = {
    "php": "php", "wordpress": "wordpress", "drupal": "drupal",
    "joomla": "joomla", "apache": "apache", "nginx": "nginx",
    "node.js": "node", "nodejs": "node", "express": "node",
    "django": "python", "flask": "python", "python": "python",
    "spring": "java", "java": "java", "tomcat": "java",
    "ruby": "ruby", "rails": "ruby",
    "asp.net": "aspnet", ".net": "aspnet", "iis": "aspnet",
    "react": "react", "angular": "angular", "vue": "vue",
    "mysql": "mysql", "postgresql": "postgresql", "mongodb": "mongodb",
    "redis": "redis", "elasticsearch": "elasticsearch",
    "docker": "docker", "kubernetes": "kubernetes",
    "laravel": "laravel", "symfony": "symfony",
    "nextjs": "nextjs", "nuxt": "nuxt",
}

# Severity from CVSS score
def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"

# Description-based vuln classification
_DESC_PATTERNS = {
    "xss_reflected": ["cross-site scripting", "xss", "script injection"],
    "sqli": ["sql injection", "sqli", "sql command"],
    "cmd_injection": ["command injection", "os command", "shell injection",
                      "remote code execution via command"],
    "ssrf": ["server-side request forgery", "ssrf"],
    "lfi": ["local file inclusion", "path traversal", "directory traversal", "file read"],
    "xxe": ["xml external entity", "xxe"],
    "csrf": ["cross-site request forgery", "csrf"],
    "ssti": ["template injection", "ssti", "server-side template"],
    "deserialization": ["deserialization", "unserialize", "pickle", "readobject"],
    "open_redirect": ["open redirect", "url redirect", "unvalidated redirect"],
    "idor": ["insecure direct object", "idor", "broken access control"],
    "misconfig": ["misconfiguration", "default credentials", "insecure default"],
    "info_disclosure": ["information disclosure", "information leak", "sensitive data"],
}


def _classify_from_description(desc: str) -> set:
    desc_lower = desc.lower()
    return {vt for vt, kws in _DESC_PATTERNS.items() if any(kw in desc_lower for kw in kws)}


def _extract_payload_hints(desc: str) -> list:
    """Try to extract payload-like strings from CVE descriptions."""
    hints = []
    # Quoted strings that look like payloads
    quoted = re.findall(r'"([^"]{5,120})"', desc)
    for q in quoted:
        ql = q.lower()
        if any(kw in ql for kw in ["script", "select", "union", "<", ">", "../",
                                     "eval", "exec", "cmd", "passwd", "etc/"]):
            hints.append(q)
    # URL-like payloads
    urls = re.findall(r'(https?://\S{10,80})', desc)
    for u in urls:
        if any(kw in u.lower() for kw in ["169.254", "localhost", "127.0.0.1",
                                            "metadata", "internal"]):
            hints.append(u)
    return hints[:5]


# ---------------------------------------------------------------------------
# Redis helper
# ---------------------------------------------------------------------------

def _get_redis():
    return redis_lib.from_url(get_settings().redis_url, decode_responses=True)


def _redis_get(key: str) -> str | None:
    try:
        r = _get_redis()
        return r.get(key)
    except Exception:
        return None


def _redis_set(key: str, value: str):
    try:
        r = _get_redis()
        r.set(key, value)
    except Exception as e:
        logger.warning(f"Redis SET failed for {key}: {e}")


# ---------------------------------------------------------------------------
# Pattern upsert helper (self-contained, does not depend on TrainingEngine)
# ---------------------------------------------------------------------------

async def _upsert_pattern(
    db: AsyncSession,
    pattern_type: str,
    technology: str,
    vuln_type: str | None,
    pattern_data: dict,
    confidence: float = 0.5,
) -> str:
    """Insert or update a KnowledgePattern. Returns 'created' or 'updated'."""
    conditions = [
        KnowledgePattern.pattern_type == pattern_type,
        KnowledgePattern.technology == technology,
    ]
    if vuln_type is not None:
        conditions.append(KnowledgePattern.vuln_type == vuln_type)
    else:
        conditions.append(KnowledgePattern.vuln_type.is_(None))

    # Deduplicate by checking a unique key inside pattern_data (if present)
    unique_key = pattern_data.get("_unique_key")
    if unique_key:
        # Use JSON containment-style check: look for existing with same unique key
        result = await db.execute(
            select(KnowledgePattern).where(and_(*conditions)).limit(50)
        )
        existing_list = result.scalars().all()
        existing = None
        for p in existing_list:
            if p.pattern_data and p.pattern_data.get("_unique_key") == unique_key:
                existing = p
                break
    else:
        result = await db.execute(
            select(KnowledgePattern).where(and_(*conditions)).limit(1)
        )
        existing = result.scalar_one_or_none()

    if existing:
        data = existing.pattern_data or {}
        # Merge list fields
        for key in ("payloads", "indicators", "tags", "paths", "matchers",
                     "techniques", "programs"):
            if key in pattern_data and key in data:
                merged = list(set(data[key] + pattern_data[key]))
                pattern_data[key] = merged[-200:]
        data.update(pattern_data)
        existing.pattern_data = data
        existing.sample_count += 1
        existing.updated_at = datetime.utcnow()
        existing.confidence = min(0.99, existing.confidence + 0.01)
        return "updated"
    else:
        db.add(KnowledgePattern(
            id=str(uuid.uuid4()),
            pattern_type=pattern_type,
            technology=technology,
            vuln_type=vuln_type,
            pattern_data=pattern_data,
            confidence=confidence,
            sample_count=1,
        ))
        return "created"


# ---------------------------------------------------------------------------
# Feed 1: Live NVD CVE Feed
# ---------------------------------------------------------------------------

async def fetch_live_cves(
    db: AsyncSession, days_back: int = 7, max_results: int = 500
) -> dict:
    """Pull recent CVEs from NVD API 2.0, tracking last-fetched date in Redis.

    Returns: {fetched, created, skipped, updated, errors}
    """
    stats = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0}

    # Determine start date: either from Redis or days_back
    redis_key = "phantom:live_feeds:nvd_last_date"
    last_date_str = _redis_get(redis_key)

    if last_date_str:
        try:
            start_date = datetime.fromisoformat(last_date_str)
        except ValueError:
            start_date = datetime.utcnow() - timedelta(days=days_back)
    else:
        start_date = datetime.utcnow() - timedelta(days=days_back)

    end_date = datetime.utcnow()

    # Don't re-fetch if we just ran (< 1 hour gap)
    if last_date_str and (end_date - start_date).total_seconds() < 3600:
        logger.info("NVD: Last fetch was < 1 hour ago, using full days_back range")
        start_date = datetime.utcnow() - timedelta(days=days_back)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    page_size = min(max_results, 200)  # NVD max is 2000, we use 200 for safety
    start_index = 0
    total_fetched = 0

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        while total_fetched < max_results:
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.999"),
                "resultsPerPage": page_size,
                "startIndex": start_index,
            }

            try:
                resp = await client.get(url, params=params)
                if resp.status_code == 403:
                    logger.warning("NVD API rate limited (403), sleeping 30s...")
                    await asyncio.sleep(30)
                    resp = await client.get(url, params=params)

                if resp.status_code != 200:
                    logger.warning(f"NVD API returned {resp.status_code}")
                    stats["errors"] += 1
                    break

                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                if not vulnerabilities:
                    break

                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    result = await _process_live_cve(db, cve)
                    stats[result] += 1
                    total_fetched += 1
                    stats["fetched"] += 1

                    if total_fetched >= max_results:
                        break

                # Batch commit
                await db.commit()

                # Check if we've exhausted results
                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break

                # Rate limit: NVD allows 5 requests per 30 seconds without API key
                await asyncio.sleep(6.5)

            except httpx.TimeoutException:
                logger.warning("NVD API timeout, retrying after 10s...")
                await asyncio.sleep(10)
                stats["errors"] += 1
            except Exception as e:
                logger.error(f"NVD fetch error: {e}")
                stats["errors"] += 1
                break

    # Update Redis tracking
    _redis_set(redis_key, end_date.isoformat())

    logger.info(f"NVD Live Feed: fetched={stats['fetched']}, "
                f"created={stats['created']}, updated={stats['updated']}")
    return stats


async def _process_live_cve(db: AsyncSession, cve: dict) -> str:
    """Process a single CVE into knowledge patterns. Returns 'created'/'updated'/'skipped'."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return "skipped"

    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # Extract CWEs
    cwes = []
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    # Extract CVSS score
    cvss_score = 0.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = cve.get("metrics", {}).get(key, [])
        if metric_list:
            cvss_score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
            break

    # Skip low-value entries
    if cvss_score < 3.0 and not cwes:
        return "skipped"

    # Extract technologies from CPE
    technologies = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                for keyword, tech in TECH_FROM_CPE.items():
                    if keyword in cpe.lower():
                        technologies.add(tech)

    # Map CWE to vuln_type
    vuln_types = set()
    for cwe in cwes:
        vt = CWE_TO_VULN_TYPE.get(cwe)
        if vt:
            vuln_types.add(vt)
    if not vuln_types:
        vuln_types = _classify_from_description(desc_en)
    if not vuln_types:
        vuln_types = {"other"}

    # Extract payload hints from description
    payload_hints = _extract_payload_hints(desc_en)

    # Store patterns: one per (tech, vuln_type) combo
    result = "skipped"
    techs = technologies or {"generic"}

    for tech in techs:
        for vt in vuln_types:
            pattern_data = {
                "_unique_key": cve_id,
                "cve_id": cve_id,
                "description": desc_en[:500],
                "cvss_score": cvss_score,
                "severity": _cvss_to_severity(cvss_score),
                "cwes": cwes,
                "source": "nvd_live",
            }
            if payload_hints:
                pattern_data["payloads"] = payload_hints

            action = await _upsert_pattern(
                db,
                pattern_type="cve_live",
                technology=tech,
                vuln_type=vt,
                pattern_data=pattern_data,
                confidence=min(0.9, cvss_score / 10.0),
            )
            if action == "created":
                result = "created"
            elif action == "updated" and result != "created":
                result = "updated"

    return result


# ---------------------------------------------------------------------------
# Feed 2: Live ExploitDB Feed
# ---------------------------------------------------------------------------

# ExploitDB categories -> vuln types
_EXPLOITDB_CAT_MAP = {
    "php": "sqli", "multiple": None, "hardware": None,
    "windows": "cmd_injection", "linux": "cmd_injection",
    "webapps": "xss_reflected", "remote": "cmd_injection",
    "local": "lfi", "dos": None, "shellcode": "cmd_injection",
}


async def fetch_live_exploits(
    db: AsyncSession, max_pages: int = 5
) -> dict:
    """Pull recent exploits from ExploitDB's GitLab mirror.

    Returns: {fetched, created, skipped, updated, errors}
    """
    stats = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0}

    redis_key = "phantom:live_feeds:exploitdb_last"
    last_fetch = _redis_get(redis_key)

    base_url = "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/tree"

    # Exploit categories to scan
    categories = ["exploits/php", "exploits/multiple", "exploits/hardware",
                   "exploits/windows", "exploits/linux"]

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for category_path in categories:
            category_name = category_path.split("/")[-1]
            page = 1

            while page <= max_pages:
                params = {
                    "path": category_path,
                    "per_page": 20,
                    "page": page,
                    "order_by": "name",
                    "sort": "desc",
                }

                try:
                    resp = await client.get(base_url, params=params)
                    if resp.status_code != 200:
                        logger.warning(f"ExploitDB API returned {resp.status_code} "
                                       f"for {category_path}")
                        stats["errors"] += 1
                        break

                    items = resp.json()
                    if not items:
                        break

                    for item in items:
                        if item.get("type") != "blob":
                            continue

                        filename = item.get("name", "")
                        file_path = item.get("path", "")

                        # Extract CVE ID from filename (e.g., "12345.txt")
                        exploit_id = filename.replace(".txt", "").replace(".py", "").replace(".rb", "")

                        # Try to fetch raw content for payload extraction
                        raw_url = (
                            f"https://gitlab.com/api/v4/projects/"
                            f"exploit-database%2Fexploitdb/repository/files/"
                            f"{file_path.replace('/', '%2F')}/raw"
                        )
                        content = ""
                        try:
                            raw_resp = await client.get(
                                raw_url, params={"ref": "main"}
                            )
                            if raw_resp.status_code == 200:
                                content = raw_resp.text[:3000]  # First 3KB
                        except Exception:
                            pass  # Content fetch is best-effort

                        # Parse exploit metadata from content
                        title = ""
                        cve_ids = []
                        payloads = []

                        if content:
                            # Extract title
                            title_match = re.search(r'#\s*Title:\s*(.+)', content)
                            if title_match:
                                title = title_match.group(1).strip()

                            # Extract CVE references
                            cve_ids = re.findall(r'CVE-\d{4}-\d{4,}', content)

                            # Extract payload-like lines
                            for line in content.split("\n"):
                                line = line.strip()
                                if len(line) > 10 and any(
                                    kw in line.lower()
                                    for kw in ["payload", "exploit", "shell",
                                               "inject", "curl ", "wget ",
                                               "http://", "<?php"]
                                ):
                                    # Clean comment markers
                                    clean = re.sub(r'^[#/\*\s]+', '', line)
                                    if 10 < len(clean) < 200:
                                        payloads.append(clean)

                        # Determine vuln type from category + content
                        vuln_type = _EXPLOITDB_CAT_MAP.get(category_name)
                        if not vuln_type and content:
                            detected = _classify_from_description(content[:1000])
                            vuln_type = next(iter(detected), None)
                        if not vuln_type:
                            vuln_type = "other"

                        # Determine technology
                        tech = "generic"
                        content_lower = (content + title).lower()
                        for kw, t in TECH_FROM_CPE.items():
                            if kw in content_lower:
                                tech = t
                                break

                        pattern_data = {
                            "_unique_key": f"edb-{exploit_id}",
                            "exploit_id": exploit_id,
                            "title": title or filename,
                            "category": category_name,
                            "source": "exploitdb_live",
                        }
                        if cve_ids:
                            pattern_data["cve_ids"] = cve_ids[:5]
                        if payloads:
                            pattern_data["payloads"] = payloads[:10]

                        action = await _upsert_pattern(
                            db,
                            pattern_type="exploit_live",
                            technology=tech,
                            vuln_type=vuln_type,
                            pattern_data=pattern_data,
                            confidence=0.6,
                        )
                        stats[action] += 1
                        stats["fetched"] += 1

                    await db.commit()
                    page += 1

                    # Rate limit: GitLab allows ~10 req/s for unauthenticated
                    await asyncio.sleep(1.0)

                except httpx.TimeoutException:
                    logger.warning(f"ExploitDB timeout for {category_path} page {page}")
                    stats["errors"] += 1
                    break
                except Exception as e:
                    logger.error(f"ExploitDB fetch error: {e}")
                    stats["errors"] += 1
                    break

    _redis_set(redis_key, datetime.utcnow().isoformat())

    logger.info(f"ExploitDB Live Feed: fetched={stats['fetched']}, "
                f"created={stats['created']}, updated={stats['updated']}")
    return stats


# ---------------------------------------------------------------------------
# Feed 3: Live Nuclei Templates Sync
# ---------------------------------------------------------------------------

# Nuclei template directories to scan
_NUCLEI_PATHS = [
    "http/cves",
    "http/vulnerabilities",
    "http/exposures",
    "http/misconfiguration",
]


async def fetch_live_nuclei_templates(
    db: AsyncSession, max_templates: int = 100
) -> dict:
    """Pull latest nuclei templates from GitHub and extract detection patterns.

    Returns: {fetched, created, skipped, updated, errors}
    """
    stats = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0}

    redis_key = "phantom:live_feeds:nuclei_last_sha"
    last_sha = _redis_get(redis_key)

    base_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents"
    templates_processed = 0
    latest_sha = last_sha

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for dir_path in _NUCLEI_PATHS:
            if templates_processed >= max_templates:
                break

            try:
                resp = await client.get(f"{base_url}/{dir_path}")
                if resp.status_code != 200:
                    logger.warning(f"GitHub API returned {resp.status_code} "
                                   f"for nuclei/{dir_path}")
                    stats["errors"] += 1
                    continue

                items = resp.json()
                if not isinstance(items, list):
                    continue

                # For CVE dirs, we get subdirectories (by year); for others, direct files
                yaml_files = []
                subdirs = []

                for item in items:
                    if item.get("type") == "file" and item["name"].endswith(".yaml"):
                        yaml_files.append(item)
                    elif item.get("type") == "dir":
                        subdirs.append(item)

                # For CVE directories organized by year, get latest year
                if subdirs and not yaml_files:
                    # Sort by name descending to get latest year first
                    subdirs.sort(key=lambda x: x["name"], reverse=True)
                    for subdir in subdirs[:2]:  # Latest 2 years
                        if templates_processed >= max_templates:
                            break
                        try:
                            sub_resp = await client.get(subdir["url"])
                            if sub_resp.status_code == 200:
                                sub_items = sub_resp.json()
                                if isinstance(sub_items, list):
                                    for si in sub_items:
                                        if (si.get("type") == "file"
                                                and si["name"].endswith(".yaml")):
                                            yaml_files.append(si)
                            await asyncio.sleep(1.0)  # Rate limit
                        except Exception:
                            pass

                # Process YAML template files (most recent first by name)
                yaml_files.sort(key=lambda x: x["name"], reverse=True)

                for yf in yaml_files:
                    if templates_processed >= max_templates:
                        break

                    sha = yf.get("sha", "")
                    # Track latest SHA for progress
                    if not latest_sha:
                        latest_sha = sha

                    # Fetch raw YAML content
                    download_url = yf.get("download_url", "")
                    if not download_url:
                        continue

                    try:
                        raw_resp = await client.get(download_url)
                        if raw_resp.status_code != 200:
                            continue

                        content = raw_resp.text
                        result = await _process_nuclei_template(db, content, yf["name"])
                        stats[result] += 1
                        stats["fetched"] += 1
                        templates_processed += 1

                    except Exception as e:
                        logger.debug(f"Error processing nuclei template {yf['name']}: {e}")
                        stats["errors"] += 1

                    # Rate limit for GitHub API (60 req/hr unauthenticated)
                    await asyncio.sleep(1.5)

                await db.commit()

            except httpx.TimeoutException:
                logger.warning(f"GitHub API timeout for nuclei/{dir_path}")
                stats["errors"] += 1
            except Exception as e:
                logger.error(f"Nuclei templates fetch error for {dir_path}: {e}")
                stats["errors"] += 1

    if latest_sha:
        _redis_set(redis_key, latest_sha)

    logger.info(f"Nuclei Live Feed: fetched={stats['fetched']}, "
                f"created={stats['created']}, updated={stats['updated']}")
    return stats


async def _process_nuclei_template(
    db: AsyncSession, content: str, filename: str
) -> str:
    """Parse a nuclei YAML template and store detection patterns."""
    try:
        template = yaml.safe_load(content)
    except Exception:
        return "skipped"

    if not isinstance(template, dict):
        return "skipped"

    info = template.get("info", {})
    template_id = template.get("id", filename.replace(".yaml", ""))
    name = info.get("name", "")
    severity = info.get("severity", "info")
    tags = info.get("tags", "")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    # Extract detection details from requests/matchers
    paths = []
    methods = []
    matchers = []
    headers = {}

    payloads = []

    for req_block in template.get("http", template.get("requests", [])):
        if isinstance(req_block, dict):
            # Paths
            for p in req_block.get("path", []):
                if isinstance(p, str):
                    # Strip template variables like {{BaseURL}}
                    clean_path = re.sub(r'\{\{BaseURL\}\}', '', p)
                    if clean_path:
                        paths.append(clean_path)

            # Method
            method = req_block.get("method", "GET")
            if method:
                methods.append(method)

            # Headers
            hdrs = req_block.get("headers", {})
            if isinstance(hdrs, dict):
                headers.update(hdrs)

            # Body payloads
            body = req_block.get("body", "")
            if body and isinstance(body, str) and len(body) > 5:
                payloads.append(body.strip())

            # Raw requests — extract payload from raw HTTP
            for raw in req_block.get("raw", []):
                if isinstance(raw, str) and len(raw) > 10:
                    # Extract body (after double newline)
                    parts = raw.split("\n\n", 1)
                    if len(parts) == 2 and len(parts[1].strip()) > 3:
                        payloads.append(parts[1].strip())
                    # Also extract path with injected payloads
                    first_line = raw.strip().split("\n")[0]
                    if " " in first_line:
                        raw_path = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else ""
                        raw_path = re.sub(r'\{\{BaseURL\}\}', '', raw_path)
                        if raw_path and any(c in raw_path for c in ["'", '"', "<", "{", "|", ".."]):
                            payloads.append(raw_path)

            # Payloads from fuzzing wordlists
            for p in req_block.get("payloads", {}).values():
                if isinstance(p, list):
                    payloads.extend(str(v) for v in p[:20])

            # Matchers
            for matcher in req_block.get("matchers", []):
                if isinstance(matcher, dict):
                    m_type = matcher.get("type", "")
                    words = matcher.get("words", [])
                    regex_list = matcher.get("regex", [])
                    status = matcher.get("status", [])

                    if words:
                        matchers.extend(words[:5])
                    if regex_list:
                        matchers.extend(regex_list[:3])
                    if status:
                        matchers.extend([str(s) for s in status[:3]])

    # Determine vuln type from tags/name
    vuln_type = None
    combined = " ".join(tags + [name.lower()])
    detected = _classify_from_description(combined)
    vuln_type = next(iter(detected), None)

    # Fallback: map common nuclei tags
    if not vuln_type:
        tag_map = {
            "sqli": "sqli", "xss": "xss_reflected", "ssrf": "ssrf",
            "lfi": "lfi", "rfi": "rfi", "rce": "cmd_injection",
            "xxe": "xxe", "ssti": "ssti", "redirect": "open_redirect",
            "csrf": "csrf", "idor": "idor", "exposure": "info_disclosure",
            "misconfig": "misconfig", "misconfiguration": "misconfig",
            "cve": None, "panel": "info_disclosure", "login": "info_disclosure",
        }
        for tag in tags:
            mapped = tag_map.get(tag.lower())
            if mapped:
                vuln_type = mapped
                break

    if not vuln_type:
        vuln_type = "other"

    # Determine technology from tags
    tech = "generic"
    for tag in tags:
        tag_lower = tag.lower()
        for kw, t in TECH_FROM_CPE.items():
            if kw in tag_lower:
                tech = t
                break
        if tech != "generic":
            break

    pattern_data = {
        "_unique_key": f"nuclei-{template_id}",
        "template_id": template_id,
        "name": name,
        "severity": severity,
        "tags": tags[:20],
        "source": "nuclei_live",
    }
    if paths:
        pattern_data["paths"] = paths[:20]
    if methods:
        pattern_data["methods"] = methods[:5]
    if matchers:
        pattern_data["matchers"] = matchers[:20]
    if headers:
        pattern_data["headers"] = dict(list(headers.items())[:10])
    if payloads:
        # Deduplicate and store payloads for use by payload_gen
        unique_payloads = list(dict.fromkeys(payloads))[:30]
        pattern_data["payloads"] = unique_payloads
        pattern_data["payload"] = unique_payloads[0]  # Primary payload for compat

    action = await _upsert_pattern(
        db,
        pattern_type="nuclei_live",
        technology=tech,
        vuln_type=vuln_type,
        pattern_data=pattern_data,
        confidence={"critical": 0.9, "high": 0.8, "medium": 0.6,
                     "low": 0.4, "info": 0.3}.get(severity, 0.5),
    )
    return action


# ---------------------------------------------------------------------------
# Feed 4: Live HackerOne Hacktivity
# ---------------------------------------------------------------------------

_H1_GRAPHQL_QUERY = """
query HacktivityPageQuery($orderBy: HacktivityItemOrderInput, $first: Int, $after: String) {
  hacktivity_items(
    order_by: $orderBy,
    first: $first,
    after: $after,
    where: {report: {disclosed_at: {_is_null: false}}}
  ) {
    edges {
      node {
        ... on HacktivityItemInterface {
          id
          databaseId: _id
          reporter {
            username
          }
          team {
            handle
            name
          }
          report {
            title
            substate
            severity_rating
            disclosed_at
          }
          severity_rating
          upvoted: voted
          __typename
        }
      }
      cursor
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
"""

# Simplified query as fallback (H1 changes schema frequently)
_H1_SIMPLE_QUERY = """
{
  hacktivity_items(first: 25, order_by: {field: popular, direction: DESC}) {
    edges {
      node {
        ... on Disclosed {
          id
          severity_rating
          report { title substate disclosed_at }
          team { handle name }
        }
      }
    }
  }
}
"""

# H1 severity -> vuln type heuristics from report titles
_H1_TITLE_PATTERNS = {
    "xss": "xss_reflected", "cross-site scripting": "xss_reflected",
    "stored xss": "xss_stored", "dom xss": "xss_dom", "dom-based": "xss_dom",
    "sql injection": "sqli", "sqli": "sqli", "blind sql": "sqli_blind",
    "ssrf": "ssrf", "server-side request": "ssrf",
    "rce": "cmd_injection", "remote code": "cmd_injection",
    "command injection": "cmd_injection",
    "idor": "idor", "insecure direct": "idor",
    "csrf": "csrf", "cross-site request": "csrf",
    "open redirect": "open_redirect", "redirect": "open_redirect",
    "xxe": "xxe", "xml external": "xxe",
    "ssti": "ssti", "template injection": "ssti",
    "lfi": "lfi", "local file": "lfi", "path traversal": "lfi",
    "information disclosure": "info_disclosure", "info leak": "info_disclosure",
    "authentication bypass": "auth_bypass", "auth bypass": "auth_bypass",
    "privilege escalation": "privilege_escalation",
    "race condition": "race_condition",
    "file upload": "file_upload",
    "subdomain takeover": "subdomain_takeover",
    "cors": "cors_misconfiguration",
}


async def fetch_live_hacktivity(
    db: AsyncSession, max_reports: int = 50
) -> dict:
    """Pull recent disclosed reports from HackerOne's public hacktivity.

    Returns: {fetched, created, skipped, updated, errors}
    """
    stats = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0}

    redis_key = "phantom:live_feeds:hacktivity_cursor"
    last_cursor = _redis_get(redis_key)

    url = "https://hackerone.com/graphql"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; PHANTOM/1.0; security research)",
    }

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        # Try the full GraphQL query first, fall back to simple
        for query in [_H1_GRAPHQL_QUERY, _H1_SIMPLE_QUERY]:
            try:
                variables = {
                    "first": min(max_reports, 25),
                    "orderBy": {"field": "popular", "direction": "DESC"},
                }
                if last_cursor and query == _H1_GRAPHQL_QUERY:
                    variables["after"] = last_cursor

                payload = {"query": query, "variables": variables}
                resp = await client.post(url, json=payload, headers=headers)

                if resp.status_code != 200:
                    logger.warning(f"HackerOne API returned {resp.status_code}")
                    continue

                data = resp.json()
                if "errors" in data:
                    logger.debug(f"HackerOne GraphQL errors: {data['errors']}")
                    continue

                edges = (data.get("data", {})
                         .get("hacktivity_items", {})
                         .get("edges", []))

                if not edges:
                    continue

                end_cursor = (data.get("data", {})
                              .get("hacktivity_items", {})
                              .get("pageInfo", {})
                              .get("endCursor"))

                for edge in edges:
                    node = edge.get("node", {})
                    if not node:
                        continue

                    report = node.get("report", {}) or {}
                    team = node.get("team", {}) or {}
                    title = report.get("title", "")
                    severity = (node.get("severity_rating")
                                or report.get("severity_rating", ""))
                    program = team.get("handle", "unknown")
                    disclosed_at = report.get("disclosed_at", "")
                    h1_id = node.get("id") or node.get("databaseId", "")

                    if not title:
                        stats["skipped"] += 1
                        continue

                    # Classify vuln type from title
                    title_lower = title.lower()
                    vuln_type = None
                    for pattern, vt in _H1_TITLE_PATTERNS.items():
                        if pattern in title_lower:
                            vuln_type = vt
                            break
                    if not vuln_type:
                        vuln_type = "other"

                    # Extract techniques from title
                    techniques = []
                    tech_keywords = ["bypass", "chain", "escalat", "blind",
                                     "stored", "reflected", "dom-based",
                                     "time-based", "error-based", "union",
                                     "race", "parameter pollution"]
                    for kw in tech_keywords:
                        if kw in title_lower:
                            techniques.append(kw)

                    pattern_data = {
                        "_unique_key": f"h1-{h1_id}" if h1_id else f"h1-{title[:50]}",
                        "title": title[:300],
                        "program": program,
                        "severity": severity or "unknown",
                        "disclosed_at": disclosed_at,
                        "source": "hacktivity_live",
                        "programs": [program],
                    }
                    if techniques:
                        pattern_data["techniques"] = techniques

                    action = await _upsert_pattern(
                        db,
                        pattern_type="hacktivity_live",
                        technology="generic",
                        vuln_type=vuln_type,
                        pattern_data=pattern_data,
                        confidence={"critical": 0.9, "high": 0.8, "medium": 0.6,
                                     "low": 0.4, "none": 0.3}.get(
                            (severity or "").lower(), 0.5
                        ),
                    )
                    stats[action] += 1
                    stats["fetched"] += 1

                await db.commit()

                if end_cursor:
                    _redis_set(redis_key, end_cursor)

                # If we got results, no need to try the fallback query
                break

            except httpx.TimeoutException:
                logger.warning("HackerOne API timeout")
                stats["errors"] += 1
            except Exception as e:
                logger.error(f"HackerOne fetch error: {e}")
                stats["errors"] += 1

    logger.info(f"HackerOne Live Feed: fetched={stats['fetched']}, "
                f"created={stats['created']}, updated={stats['updated']}")
    return stats


# ---------------------------------------------------------------------------
# Feed 5: Scan Feedback Analysis
# ---------------------------------------------------------------------------

async def analyze_scan_feedback(db: AsyncSession, max_scans: int = 0) -> dict:
    """Analyze completed scans to learn what works and what doesn't.

    Args:
        max_scans: Limit number of scans to analyze (0 = unlimited).

    Returns: {fetched, created, skipped, updated, errors}
    """
    stats = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0}

    redis_key = "phantom:live_feeds:feedback_last_scan_date"
    last_date_str = _redis_get(redis_key)

    if last_date_str:
        try:
            last_date = datetime.fromisoformat(last_date_str)
        except ValueError:
            last_date = datetime.utcnow() - timedelta(days=90)
    else:
        last_date = datetime.utcnow() - timedelta(days=90)

    # Get completed scans since last analysis
    conditions = [
        Scan.status == ScanStatus.COMPLETED,
        Scan.completed_at.isnot(None),
        Scan.completed_at > last_date,
    ]

    query = select(Scan).where(and_(*conditions)).order_by(Scan.completed_at.asc())
    if max_scans > 0:
        query = query.limit(max_scans)
    result = await db.execute(query)
    scans = result.scalars().all()

    if not scans:
        logger.info("Scan Feedback: No new completed scans to analyze")
        return stats

    # Aggregate statistics
    vuln_type_counts = defaultdict(int)          # vuln_type -> total found
    tech_vuln_success = defaultdict(lambda: defaultdict(int))  # tech -> vuln_type -> count
    scan_durations = []
    vulns_per_scan = []
    vuln_type_by_severity = defaultdict(lambda: defaultdict(int))  # vuln_type -> severity -> count

    latest_scan_date = last_date

    for scan in scans:
        stats["fetched"] += 1

        if scan.completed_at and scan.completed_at > latest_scan_date:
            latest_scan_date = scan.completed_at

        # Get vulnerabilities for this scan
        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        vulns = vuln_result.scalars().all()
        vulns_per_scan.append(len(vulns))

        # Calculate scan duration
        if scan.started_at and scan.completed_at:
            duration = (scan.completed_at - scan.started_at).total_seconds()
            scan_durations.append(duration)

        # Analyze each vulnerability
        for vuln in vulns:
            vt = vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type)
            sev = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)

            vuln_type_counts[vt] += 1
            vuln_type_by_severity[vt][sev] += 1

            # Try to determine technology from URL/payload
            url_lower = (vuln.url or "").lower()
            tech = "generic"
            for kw, t in TECH_FROM_CPE.items():
                if kw in url_lower:
                    tech = t
                    break
            tech_vuln_success[tech][vt] += 1

    # Generate insights

    # 1. Overall scan effectiveness
    avg_vulns = sum(vulns_per_scan) / len(vulns_per_scan) if vulns_per_scan else 0
    avg_duration = sum(scan_durations) / len(scan_durations) if scan_durations else 0

    insight_data = {
        "_unique_key": "scan_effectiveness_overall",
        "scans_analyzed": len(scans),
        "avg_vulns_per_scan": round(avg_vulns, 1),
        "avg_scan_duration_seconds": round(avg_duration, 1),
        "total_vulns_found": sum(vuln_type_counts.values()),
        "analysis_date": datetime.utcnow().isoformat(),
        "source": "scan_feedback",
    }
    action = await _upsert_pattern(
        db, pattern_type="scan_insight", technology="generic",
        vuln_type=None, pattern_data=insight_data, confidence=0.8,
    )
    stats[action] += 1

    # 2. Per vuln-type effectiveness insights
    for vt, count in vuln_type_counts.items():
        severity_dist = dict(vuln_type_by_severity.get(vt, {}))
        # Calculate a "value score" (weighted by severity)
        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0.5}
        value_score = sum(
            severity_weights.get(s, 1) * c for s, c in severity_dist.items()
        )

        vt_insight = {
            "_unique_key": f"vuln_effectiveness_{vt}",
            "vuln_type": vt,
            "total_found": count,
            "severity_distribution": severity_dist,
            "value_score": round(value_score, 1),
            "source": "scan_feedback",
            "analysis_date": datetime.utcnow().isoformat(),
        }
        action = await _upsert_pattern(
            db, pattern_type="scan_insight", technology="generic",
            vuln_type=vt, pattern_data=vt_insight,
            confidence=min(0.95, 0.5 + count * 0.05),
        )
        stats[action] += 1

    # 3. Technology-specific success rates
    for tech, vt_counts in tech_vuln_success.items():
        total = sum(vt_counts.values())
        top_vulns = sorted(vt_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        tech_insight = {
            "_unique_key": f"tech_success_{tech}",
            "technology": tech,
            "total_vulns": total,
            "top_vuln_types": {vt: cnt for vt, cnt in top_vulns},
            "source": "scan_feedback",
            "analysis_date": datetime.utcnow().isoformat(),
        }
        action = await _upsert_pattern(
            db, pattern_type="scan_insight", technology=tech,
            vuln_type=None, pattern_data=tech_insight,
            confidence=min(0.9, 0.5 + total * 0.03),
        )
        stats[action] += 1

    # 4. Reinforce confidence on patterns that match found vulns
    for vt, count in vuln_type_counts.items():
        # Find existing patterns for this vuln type and boost confidence
        boost_result = await db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.vuln_type == vt,
                    KnowledgePattern.pattern_type.in_(
                        ["cve_live", "exploit_live", "nuclei_live",
                         "tech_vuln_correlation", "effective_payload"]
                    ),
                )
            ).limit(50)
        )
        patterns_to_boost = boost_result.scalars().all()
        for p in patterns_to_boost:
            # Small confidence boost based on real scan results
            p.confidence = min(0.99, p.confidence + 0.01 * min(count, 5))
            p.updated_at = datetime.utcnow()

    await db.commit()

    _redis_set(redis_key, latest_scan_date.isoformat())

    logger.info(f"Scan Feedback Analysis: analyzed {len(scans)} scans, "
                f"created={stats['created']}, updated={stats['updated']}")
    return stats


# ---------------------------------------------------------------------------
# Feed 6: PayloadsAllTheThings (GitHub raw → effective_payload KB patterns)
# ---------------------------------------------------------------------------

# Mapping of GitHub raw file paths → (vuln_type, technology)
_PATT_SOURCES: list[tuple[str, str, str]] = [
    # XSS (Intruders/ — plural)
    ("XSS Injection/Intruders/IntrudersXSS.txt", "xss_reflected", "generic"),
    ("XSS Injection/Intruders/JHADDIX_XSS.txt", "xss_reflected", "generic"),
    ("XSS Injection/Intruders/BRUTELOGIC-XSS-JS.txt", "xss_reflected", "generic"),
    ("XSS Injection/Intruders/XSS_Polyglots.txt", "xss_reflected", "generic"),
    ("XSS Injection/Intruders/xss_payloads_quick.txt", "xss_reflected", "generic"),
    ("XSS Injection/1 - XSS Filter Bypass.md", "xss_reflected", "generic"),
    ("XSS Injection/3 - XSS Common WAF Bypass.md", "xss_reflected", "generic"),
    # SQLi (Intruder/ — singular!)
    ("SQL Injection/MySQL Injection.md", "sqli", "mysql"),
    ("SQL Injection/PostgreSQL Injection.md", "sqli", "postgresql"),
    ("SQL Injection/MSSQL Injection.md", "sqli", "mssql"),
    ("SQL Injection/SQLite Injection.md", "sqli", "sqlite"),
    ("SQL Injection/Intruder/Auth_Bypass.txt", "sqli", "generic"),
    ("SQL Injection/Intruder/Generic_Fuzz.txt", "sqli", "generic"),
    ("SQL Injection/Intruder/Generic_TimeBased.txt", "sqli", "generic"),
    ("SQL Injection/Intruder/Generic_UnionSelect.txt", "sqli", "generic"),
    ("SQL Injection/Intruder/Generic_ErrorBased.txt", "sqli", "generic"),
    ("SQL Injection/Intruder/SQLi_Polyglots.txt", "sqli", "generic"),
    # SSRF (no Intruders/ folder — use markdown)
    ("Server Side Request Forgery/README.md", "ssrf", "generic"),
    ("Server Side Request Forgery/SSRF-Cloud-Instances.md", "ssrf", "cloud"),
    # SSTI (Intruder/ — singular!)
    ("Server Side Template Injection/Intruder/ssti.fuzz", "ssti", "generic"),
    ("Server Side Template Injection/Python.md", "ssti", "python"),
    ("Server Side Template Injection/Java.md", "ssti", "java"),
    ("Server Side Template Injection/PHP.md", "ssti", "php"),
    ("Server Side Template Injection/JavaScript.md", "ssti", "node"),
    # LFI (Intruders/ — plural)
    ("File Inclusion/Intruders/JHADDIX_LFI.txt", "lfi", "generic"),
    ("File Inclusion/Intruders/Linux-files.txt", "lfi", "linux"),
    ("File Inclusion/Intruders/Windows-files.txt", "lfi", "windows"),
    ("File Inclusion/Intruders/dot-slash-PathTraversal_and_LFI_pairing.txt", "lfi", "generic"),
    ("File Inclusion/Intruders/List_Of_File_To_Include.txt", "lfi", "generic"),
    # Command Injection (Intruder/ — singular!)
    ("Command Injection/Intruder/command-execution-unix.txt", "cmd_injection", "linux"),
    ("Command Injection/Intruder/command_exec.txt", "cmd_injection", "generic"),
    ("Command Injection/README.md", "cmd_injection", "generic"),
    # XXE (Intruders/ — plural)
    ("XXE Injection/Intruders/XXE_Fuzzing.txt", "xxe", "generic"),
    ("XXE Injection/README.md", "xxe", "generic"),
    # Open Redirect (Intruder/ — singular!)
    ("Open Redirect/Intruder/Open-Redirect-payloads.txt", "open_redirect", "generic"),
    ("Open Redirect/Intruder/openredirects.txt", "open_redirect", "generic"),
    # CSRF (no Intruders folder)
    ("Cross-Site Request Forgery/README.md", "csrf", "generic"),
    # Directory Traversal (Intruder/ — singular!)
    ("Directory Traversal/Intruder/deep_traversal.txt", "path_traversal", "generic"),
    ("Directory Traversal/Intruder/directory_traversal.txt", "path_traversal", "generic"),
    # CORS
    ("CORS Misconfiguration/README.md", "cors_misconfiguration", "generic"),
    # JWT
    ("JSON Web Token/README.md", "jwt_vuln", "generic"),
    # Deserialization
    ("Insecure Deserialization/README.md", "deserialization", "generic"),
    # NoSQL Injection
    ("NoSQL Injection/README.md", "sqli", "mongodb"),
    # GraphQL
    ("GraphQL Injection/README.md", "misconfiguration", "graphql"),
    # IDOR
    ("Insecure Direct Object References/README.md", "idor", "generic"),
]

_PATT_BASE_URL = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/"


def _extract_payloads_from_text(content: str, max_payloads: int = 200) -> list[str]:
    """Extract actual payloads from a raw file (txt or markdown)."""
    payloads = []
    in_code_block = False

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Toggle code block state
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue

        # Skip markdown headers, comments, descriptions
        if stripped.startswith(("#", "##", "###", ">")):
            continue
        if stripped.startswith(("*", "-", "//", "/*", "Note:", "Reference")):
            # But allow payload-like lines starting with - or *
            if len(stripped) < 10 or not any(c in stripped for c in "<'\"`;/\\{"):
                continue
            # Strip the leading - or * for payload extraction
            stripped = stripped.lstrip("-* ").strip()

        # Must look like a payload (has special chars or is in code block)
        if in_code_block or any(c in stripped for c in "<'\"`;/\\{}()[]|&$%"):
            # Skip very long lines (likely descriptions) and very short ones
            if 3 <= len(stripped) <= 2000:
                payloads.append(stripped)

        if len(payloads) >= max_payloads:
            break

    return payloads


def _extract_payloads_from_markdown(content: str, max_payloads: int = 150) -> list[str]:
    """Extract payloads from markdown README files (code blocks + inline code)."""
    payloads = []

    # Extract from code blocks
    code_blocks = re.findall(r'```[\w]*\n(.*?)```', content, re.DOTALL)
    for block in code_blocks:
        for line in block.strip().splitlines():
            line = line.strip()
            if 3 <= len(line) <= 2000 and not line.startswith(("#", "//")):
                payloads.append(line)

    # Extract inline code with payload-like content
    inline_codes = re.findall(r'`([^`]{3,500})`', content)
    for code in inline_codes:
        if any(c in code for c in "<'\"`;/\\{}()[]|&$%"):
            payloads.append(code)

    # Deduplicate preserving order
    seen = set()
    unique = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique[:max_payloads]


async def fetch_payloads_all_the_things(
    db: AsyncSession, max_sources: int = 50
) -> dict:
    """Fetch payloads from PayloadsAllTheThings GitHub repo and inject into KB.

    Returns: {fetched, created, skipped, updated, errors, sources_processed}
    """
    stats = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0,
             "sources_processed": 0}

    redis_key = "phantom:live_feeds:patt_last_run"
    last_run = _redis_get(redis_key)

    # Rate limit: don't hammer GitHub more than once per hour
    if last_run:
        try:
            last_dt = datetime.fromisoformat(last_run)
            if (datetime.utcnow() - last_dt).total_seconds() < 3600:
                logger.info("PayloadsAllTheThings: skipping, ran less than 1 hour ago")
                return stats
        except ValueError:
            pass

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for path, vuln_type, technology in _PATT_SOURCES[:max_sources]:
            url = _PATT_BASE_URL + path.replace(" ", "%20")
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    logger.debug(f"PATT: {path} → HTTP {resp.status_code}")
                    stats["errors"] += 1
                    continue

                content = resp.text
                stats["sources_processed"] += 1

                # Extract payloads based on file type
                if path.endswith(".md"):
                    payloads = _extract_payloads_from_markdown(content)
                else:
                    payloads = _extract_payloads_from_text(content)

                if not payloads:
                    stats["skipped"] += 1
                    continue

                stats["fetched"] += len(payloads)

                # Store as effective_payload pattern
                unique_key = f"patt-{vuln_type}-{technology}-{path.split('/')[-1]}"
                action = await _upsert_pattern(
                    db,
                    pattern_type="effective_payload",
                    technology=technology,
                    vuln_type=vuln_type,
                    pattern_data={
                        "_unique_key": unique_key,
                        "payload": payloads[0],
                        "payloads": payloads[:200],
                        "source": "PayloadsAllTheThings",
                        "source_file": path,
                        "payload_count": len(payloads),
                    },
                    confidence=0.65,  # Community-vetted = decent confidence
                )
                stats[action] += 1

                # Small delay to be nice to GitHub
                await asyncio.sleep(0.3)

            except httpx.TimeoutException:
                logger.warning(f"PATT timeout: {path}")
                stats["errors"] += 1
            except Exception as e:
                logger.error(f"PATT error for {path}: {e}")
                stats["errors"] += 1

    await db.commit()
    _redis_set(redis_key, datetime.utcnow().isoformat())

    logger.info(f"PayloadsAllTheThings: sources={stats['sources_processed']}, "
                f"payloads={stats['fetched']}, created={stats['created']}, "
                f"updated={stats['updated']}")
    return stats


# ---------------------------------------------------------------------------
# Master function
# ---------------------------------------------------------------------------

async def run_all_live_feeds(db: AsyncSession) -> dict:
    """Run all 5 live feeds and return combined stats with per-feed breakdown.

    Returns: {
        "total": {fetched, created, updated, skipped, errors},
        "feeds": {
            "nvd_cves": {...},
            "exploitdb": {...},
            "nuclei_templates": {...},
            "hacktivity": {...},
            "scan_feedback": {...},
        },
        "started_at": "...",
        "completed_at": "...",
        "duration_seconds": ...
    }
    """
    started_at = datetime.utcnow()
    results = {}
    total = {"fetched": 0, "created": 0, "updated": 0, "skipped": 0, "errors": 0}

    feeds = [
        ("nvd_cves", lambda: fetch_live_cves(db)),
        ("exploitdb", lambda: fetch_live_exploits(db)),
        ("nuclei_templates", lambda: fetch_live_nuclei_templates(db)),
        ("hacktivity", lambda: fetch_live_hacktivity(db)),
        ("payloads_all_the_things", lambda: fetch_payloads_all_the_things(db)),
        ("scan_feedback", lambda: analyze_scan_feedback(db)),
    ]

    for feed_name, feed_fn in feeds:
        logger.info(f"Running live feed: {feed_name}...")
        try:
            feed_stats = await feed_fn()
            results[feed_name] = feed_stats
            for key in total:
                total[key] += feed_stats.get(key, 0)
        except Exception as e:
            logger.error(f"Live feed {feed_name} failed: {e}")
            results[feed_name] = {"fetched": 0, "created": 0, "updated": 0,
                                   "skipped": 0, "errors": 1, "error": str(e)}
            total["errors"] += 1

    completed_at = datetime.utcnow()

    report = {
        "total": total,
        "feeds": results,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": round((completed_at - started_at).total_seconds(), 2),
    }

    logger.info(f"All live feeds completed in {report['duration_seconds']}s: "
                f"fetched={total['fetched']}, created={total['created']}, "
                f"updated={total['updated']}, errors={total['errors']}")

    return report
