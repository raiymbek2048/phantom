"""
Mobile API Extractor — decompiles APK files and extracts security-relevant data.

Pipeline:
1. Download APK from URL or use uploaded file
2. Decompile with jadx (Java source) + apktool (resources/manifest)
3. Extract API endpoints, secrets, OAuth config, cert pinning
4. Feed discovered endpoints into PHANTOM for scanning
5. Report hardcoded secrets and misconfigurations

Requires: jadx, apktool (installed in Docker image)
"""
import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ─── Patterns ────────────────────────────────────────────────────────────

# API endpoint patterns in decompiled source
API_URL_PATTERN = re.compile(
    r'["\']'
    r'(https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})'
    r'(?:/[a-zA-Z0-9._/\-{}%+]+)*'
    r'(?:\?[a-zA-Z0-9._=&%+-]*)?)'
    r'["\']',
)

# Relative API paths
API_PATH_PATTERN = re.compile(
    r'["\']'
    r'(/(?:api|v\d+|rest|graphql|ws|mobile|app|auth|oauth)'
    r'(?:/[a-zA-Z0-9._/\-{}%+]+)*)'
    r'["\']',
)

# Secret patterns
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    # AWS secret must be near aws/secret/key context, not any random base64
    ("AWS Secret Key", re.compile(
        r'(?:aws|secret|s3)[_\s"\']*(?:key|access|secret)[^=]{0,10}[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
        re.IGNORECASE,
    )),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z_-]{35}')),
    ("Firebase URL", re.compile(r'https://[a-z0-9-]+\.firebaseio\.com')),
    ("Firebase API Key", re.compile(r'["\']AIza[0-9A-Za-z_-]{35}["\']')),
    ("Google OAuth Client ID", re.compile(r'\d+-[a-z0-9]+\.apps\.googleusercontent\.com')),
    ("Private Key", re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----')),
    ("Generic API Key", re.compile(r'(?:api[_-]?key|apikey|api_secret|client_secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-/.+=]{16,})["\']', re.IGNORECASE)),
    ("Bearer Token", re.compile(r'["\']Bearer\s+([a-zA-Z0-9_\-/.+=]{20,})["\']')),
    ("JWT Token", re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    ("OAuth Client Secret", re.compile(r'client[_-]?secret\s*[=:]\s*["\']([a-zA-Z0-9_\-/.+=]{8,})["\']', re.IGNORECASE)),
    # Hardcoded password: must be assignment, not method call like .isPassword()
    ("Hardcoded Password", re.compile(
        r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,64})["\']'
        r'(?!\s*\))',  # exclude .isPassword() pattern
        re.IGNORECASE,
    )),
    ("Encryption Key", re.compile(r'(?:encrypt|aes|des|secret)[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-/.+=]{8,})["\']', re.IGNORECASE)),
    ("Database URL", re.compile(r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+', re.IGNORECASE)),
    ("Stripe Key", re.compile(r'[sp]k_(?:live|test)_[a-zA-Z0-9]{20,}')),
    ("Slack Token", re.compile(r'xox[bpsa]-[a-zA-Z0-9-]+')),
    ("SendGrid Key", re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}')),
    ("Twilio SID", re.compile(r'AC[a-f0-9]{32}')),
    ("GitHub Token", re.compile(r'gh[ps]_[a-zA-Z0-9]{36}')),
]

# False positive values to skip
_FP_VALUES = {
    "true", "false", "null", "undefined", "password", "none", "empty",
    "test", "example", "placeholder", "changeme", "TODO", "FIXME",
    "N/A", "n/a", "default", "string", "object", "boolean",
}

# OAuth / Auth config patterns
OAUTH_PATTERNS = [
    ("OAuth Authorize URL", re.compile(r'["\']'
        r'(https?://[^\s"\']+/(?:oauth|authorize|auth)[^\s"\']*)["\']', re.IGNORECASE)),
    ("OAuth Token URL", re.compile(r'["\']'
        r'(https?://[^\s"\']+/(?:token|oauth/token)[^\s"\']*)["\']', re.IGNORECASE)),
    ("OAuth Client ID", re.compile(r'client[_-]?id\s*[=:]\s*["\']([a-zA-Z0-9_\-/.+=]{8,})["\']', re.IGNORECASE)),
    ("OAuth Redirect URI", re.compile(r'redirect[_-]?uri\s*[=:]\s*["\']([^\s"\']+)["\']', re.IGNORECASE)),
    ("OAuth Scope", re.compile(r'scope\s*[=:]\s*["\']([^\s"\']+)["\']', re.IGNORECASE)),
]

# Certificate pinning patterns
CERT_PIN_PATTERNS = [
    ("OkHttp CertificatePinner", re.compile(r'CertificatePinner')),
    ("TrustManager", re.compile(r'X509TrustManager|TrustManagerFactory')),
    ("SSL Pinning", re.compile(r'ssl[_-]?pin|certificate[_-]?pin', re.IGNORECASE)),
    ("Network Security Config", re.compile(r'network_security_config|cleartextTrafficPermitted')),
    ("SHA256 Pin", re.compile(r'sha256/[a-zA-Z0-9+/=]{43,}')),
]

# Android-specific security issues
ANDROID_ISSUES = [
    ("Debuggable App", re.compile(r'android:debuggable\s*=\s*["\']true["\']')),
    ("Backup Allowed", re.compile(r'android:allowBackup\s*=\s*["\']true["\']')),
    ("Cleartext Traffic", re.compile(r'android:usesCleartextTraffic\s*=\s*["\']true["\']')),
    ("Exported Component", re.compile(r'android:exported\s*=\s*["\']true["\']')),
    ("Custom Permission", re.compile(r'android:protectionLevel\s*=\s*["\'](?:normal|dangerous)["\']')),
    ("WebView JS Enabled", re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)')),
    ("WebView File Access", re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)')),
    ("Insecure Random", re.compile(r'java\.util\.Random\b')),
    ("ECB Mode", re.compile(r'AES/ECB|DES/ECB|Cipher\.getInstance\s*\(\s*["\']AES["\']')),
    ("Hardcoded IV", re.compile(r'IvParameterSpec\s*\(\s*["\']')),
    ("SharedPreferences Sensitive", re.compile(
        r'getSharedPreferences.*(?:password|token|secret|key|pin|auth)',
        re.IGNORECASE,
    )),
    ("Log Sensitive Data", re.compile(
        r'Log\.[dievw]\s*\(.*(?:password|token|secret|key|auth|credential)',
        re.IGNORECASE,
    )),
]

# Domains to skip (noise)
SKIP_DOMAINS = {
    "schemas.android.com", "www.w3.org", "xmlpull.org",
    "schemas.openxmlformats.org", "purl.org", "apache.org",
    "google.com", "googleapis.com", "gstatic.com",
    "android.com", "example.com", "localhost",
    "facebook.com", "fb.com", "graph.facebook.com",
    "crashlytics.com", "firebase.google.com",
}

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


class MobileAPIExtractor:
    """Decompiles APK and extracts API endpoints, secrets, and configs."""

    def __init__(self):
        self.work_dir: Path | None = None
        self.jadx_available = shutil.which("jadx") is not None
        self.apktool_available = shutil.which("apktool") is not None

    async def extract_from_apk(self, apk_path: str) -> dict:
        """Main entry: decompile APK and extract everything.

        Returns: {
            "package_name": str,
            "app_name": str,
            "api_endpoints": [{"url": str, "source_file": str}],
            "api_paths": [str],
            "secrets": [{"type": str, "value": str, "file": str}],
            "oauth_config": [{"type": str, "value": str}],
            "cert_pinning": [{"type": str, "file": str}],
            "android_issues": [{"issue": str, "file": str, "severity": str}],
            "permissions": [str],
            "activities": [str],
            "services": [str],
            "receivers": [str],
            "providers": [str],
            "base_urls": [str],  # unique base URLs for scanning
        }
        """
        if not os.path.isfile(apk_path):
            return {"error": f"APK file not found: {apk_path}"}

        result = {
            "package_name": "",
            "app_name": "",
            "api_endpoints": [],
            "api_paths": [],
            "secrets": [],
            "oauth_config": [],
            "cert_pinning": [],
            "android_issues": [],
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "base_urls": [],
        }

        self.work_dir = Path(tempfile.mkdtemp(prefix="phantom_apk_"))

        try:
            # Step 1: Decompile with jadx (Java source)
            jadx_dir = self.work_dir / "jadx_out"
            if self.jadx_available:
                logger.info(f"Decompiling APK with jadx: {apk_path}")
                await self._run_jadx(apk_path, jadx_dir)
            else:
                logger.warning("jadx not available — skipping Java decompilation")

            # Step 2: Decompile with apktool (resources + manifest)
            apktool_dir = self.work_dir / "apktool_out"
            if self.apktool_available:
                logger.info(f"Decompiling APK with apktool: {apk_path}")
                await self._run_apktool(apk_path, apktool_dir)
            else:
                logger.warning("apktool not available — skipping resource extraction")

            # Step 3: Parse AndroidManifest.xml
            manifest_path = apktool_dir / "AndroidManifest.xml"
            if manifest_path.exists():
                manifest_data = self._parse_manifest(manifest_path)
                result.update(manifest_data)

            # Step 4: Scan all decompiled files
            scan_dirs = []
            if jadx_dir.exists():
                scan_dirs.append(jadx_dir)
            if apktool_dir.exists():
                scan_dirs.append(apktool_dir)

            if not scan_dirs:
                return {"error": "Neither jadx nor apktool available"}

            for scan_dir in scan_dirs:
                self._scan_directory(scan_dir, result)

            # Step 5: Extract unique base URLs for PHANTOM scanning
            seen_bases = set()
            for ep in result["api_endpoints"]:
                parsed = urlparse(ep["url"])
                base = f"{parsed.scheme}://{parsed.netloc}"
                if parsed.netloc and parsed.netloc not in SKIP_DOMAINS:
                    seen_bases.add(base)
            result["base_urls"] = sorted(seen_bases)

            # Dedup
            result["api_endpoints"] = self._dedup_endpoints(result["api_endpoints"])
            result["api_paths"] = sorted(set(result["api_paths"]))
            result["secrets"] = self._dedup_by_value(result["secrets"])

            logger.info(
                f"APK analysis complete: {len(result['api_endpoints'])} endpoints, "
                f"{len(result['secrets'])} secrets, {len(result['android_issues'])} issues, "
                f"{len(result['base_urls'])} unique base URLs"
            )

        finally:
            # Cleanup
            if self.work_dir and self.work_dir.exists():
                shutil.rmtree(self.work_dir, ignore_errors=True)

        return result

    async def extract_from_url(self, url: str) -> dict:
        """Download APK from URL and extract."""
        tmp_apk = Path(tempfile.mktemp(suffix=".apk", prefix="phantom_"))
        try:
            async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return {"error": f"Failed to download APK: HTTP {resp.status_code}"}
                tmp_apk.write_bytes(resp.content)
                logger.info(f"Downloaded APK: {len(resp.content)} bytes")

            return await self.extract_from_apk(str(tmp_apk))
        finally:
            if tmp_apk.exists():
                tmp_apk.unlink()

    async def download_apk(self, package_name: str) -> str | None:
        """Download APK by package name. Returns path to APK file or None."""
        http_downloaders = [
            ("Aptoide", self._download_aptoide),
            ("APK.cafe", self._download_apkcafe),
            ("APKPure", self._download_apkpure),
            ("Uptodown", self._download_uptodown),
        ]
        for name, downloader in http_downloaders:
            try:
                apk_path = await downloader(package_name)
                if apk_path and os.path.isfile(apk_path):
                    logger.info(f"APK downloaded via {name}: {apk_path}")
                    return apk_path
            except Exception as e:
                logger.debug(f"{name} failed for {package_name}: {e}")

        browser_sources = [
            ("APKPure (browser)", self._browser_download_apkpure),
            ("APKMirror (browser)", self._browser_download_apkmirror),
        ]
        for name, downloader in browser_sources:
            try:
                apk_path = await downloader(package_name)
                if apk_path and os.path.isfile(apk_path):
                    logger.info(f"APK downloaded via {name}: {apk_path}")
                    return apk_path
            except Exception as e:
                logger.debug(f"{name} failed for {package_name}: {e}")

        return None

    async def extract_from_package(self, package_name: str) -> dict:
        """Try to download APK by package name from public sources."""
        # Phase 1: Try lightweight HTTP scrapers
        http_downloaders = [
            ("Aptoide", self._download_aptoide),
            ("APK.cafe", self._download_apkcafe),
            ("APKPure", self._download_apkpure),
            ("Uptodown", self._download_uptodown),
        ]
        for name, downloader in http_downloaders:
            try:
                apk_path = await downloader(package_name)
                if apk_path and os.path.isfile(apk_path):
                    try:
                        result = await self.extract_from_apk(apk_path)
                        if "error" not in result:
                            logger.info(f"APK downloaded via {name}")
                            return result
                    finally:
                        if os.path.exists(apk_path):
                            os.unlink(apk_path)
            except Exception as e:
                logger.debug(f"{name} failed for {package_name}: {e}")

        # Phase 2: Use headless browser (handles JS/Cloudflare)
        browser_sources = [
            ("APKPure (browser)", self._browser_download_apkpure),
            ("APKMirror (browser)", self._browser_download_apkmirror),
        ]
        for name, downloader in browser_sources:
            try:
                apk_path = await downloader(package_name)
                if apk_path and os.path.isfile(apk_path):
                    try:
                        result = await self.extract_from_apk(apk_path)
                        if "error" not in result:
                            logger.info(f"APK downloaded via {name}")
                            return result
                    finally:
                        if os.path.exists(apk_path):
                            os.unlink(apk_path)
            except Exception as e:
                logger.debug(f"{name} failed for {package_name}: {e}")

        return {
            "error": (
                f"Could not download APK for package: {package_name}. "
                "All sources blocked. Upload the APK file directly to the bot."
            )
        }

    # ─── HTTP-based downloaders ───────────────────────────────────────

    async def _download_apkcafe(self, package_name: str) -> str | None:
        """Download APK from apk.cafe — simple structure, often works."""
        tmp_apk = tempfile.mktemp(suffix=".apk", prefix="phantom_")
        # apk.cafe slug: kz.kkb.homebank → homebank
        # Try known slug patterns
        parts = package_name.split(".")
        slugs = [parts[-1], "-".join(parts), package_name]

        async with httpx.AsyncClient(
            timeout=120, follow_redirects=True, headers=BROWSER_HEADERS
        ) as client:
            for slug in slugs:
                try:
                    page_url = f"https://{slug}.apk.cafe/"
                    resp = await client.get(page_url)
                    if resp.status_code != 200:
                        continue

                    # Find download link on page
                    for pattern in [
                        r'href="(https://[^"]+\.apk)"',
                        r'href="(/download/[^"]+)"',
                        r'data-href="(https://[^"]+\.apk[^"]*)"',
                    ]:
                        m = re.search(pattern, resp.text)
                        if m:
                            dl_url = m.group(1)
                            if dl_url.startswith("/"):
                                dl_url = f"https://{slug}.apk.cafe{dl_url}"
                            dl_resp = await client.get(dl_url)
                            if (dl_resp.status_code == 200
                                    and len(dl_resp.content) > 100000
                                    and dl_resp.content[:2] == b"PK"):
                                Path(tmp_apk).write_bytes(dl_resp.content)
                                logger.info(f"apk.cafe: {len(dl_resp.content)} bytes")
                                return tmp_apk
                except Exception:
                    continue
        return None

    async def _download_aptoide(self, package_name: str) -> str | None:
        """Download APK from Aptoide webservice API."""
        tmp_apk = tempfile.mktemp(suffix=".apk", prefix="phantom_")
        async with httpx.AsyncClient(
            timeout=120, follow_redirects=True, headers=BROWSER_HEADERS
        ) as client:
            # Aptoide has a public API for app info
            api_url = f"https://ws75.aptoide.com/api/7/app/search?query={package_name}&limit=1"
            resp = await client.get(api_url)
            if resp.status_code != 200:
                return None

            try:
                data = resp.json()
                apps = data.get("datalist", {}).get("list", [])
                if not apps:
                    return None

                # Find matching package
                app_info = None
                for app in apps:
                    if app.get("package") == package_name:
                        app_info = app
                        break
                if not app_info:
                    app_info = apps[0]  # Best match

                apk_url = app_info.get("file", {}).get("path")
                if not apk_url:
                    # Try alternate field
                    apk_url = app_info.get("file", {}).get("path_alt")
                if not apk_url:
                    logger.debug(f"Aptoide: no download URL for {package_name}")
                    return None

                logger.info(f"Aptoide: downloading from {apk_url[:80]}...")
                dl_resp = await client.get(apk_url)
                if (dl_resp.status_code == 200
                        and len(dl_resp.content) > 100000
                        and dl_resp.content[:2] == b"PK"):
                    Path(tmp_apk).write_bytes(dl_resp.content)
                    logger.info(f"Aptoide: {len(dl_resp.content)} bytes")
                    return tmp_apk
            except Exception as e:
                logger.debug(f"Aptoide parse error: {e}")
        return None

    async def _download_apkpure(self, package_name: str) -> str | None:
        """Download APK from APKPure via HTTP."""
        tmp_apk = tempfile.mktemp(suffix=".apk", prefix="phantom_")
        async with httpx.AsyncClient(
            timeout=120, follow_redirects=True, headers=BROWSER_HEADERS
        ) as client:
            # Direct download endpoint
            dl_url = f"https://d.apkpure.com/b/APK/{package_name}?version=latest"
            resp = await client.get(dl_url, headers={
                **BROWSER_HEADERS,
                "Referer": f"https://apkpure.com/app/{package_name}",
            })
            if resp.status_code == 200 and len(resp.content) > 100000:
                if resp.content[:2] == b"PK":
                    Path(tmp_apk).write_bytes(resp.content)
                    logger.info(f"APKPure direct: {len(resp.content)} bytes")
                    return tmp_apk

            # Search + navigate
            resp = await client.get(f"https://apkpure.com/search?q={package_name}")
            if resp.status_code != 200:
                return None

            app_match = re.search(
                rf'href="(/[^"]+/{package_name})"', resp.text,
            )
            if not app_match:
                return None

            dl_page = await client.get(
                f"https://apkpure.com{app_match.group(1)}/download"
            )
            if dl_page.status_code != 200:
                return None

            for pattern in [
                r'href="(https://[^"]+\.apk[^"]*)"',
                r'data-dt-url="(https://[^"]+)"',
                r'"download_link"\s*:\s*"(https://[^"]+)"',
            ]:
                m = re.search(pattern, dl_page.text)
                if m:
                    resp3 = await client.get(m.group(1))
                    if resp3.status_code == 200 and len(resp3.content) > 100000:
                        if resp3.content[:2] == b"PK":
                            Path(tmp_apk).write_bytes(resp3.content)
                            return tmp_apk
        return None

    async def _download_uptodown(self, package_name: str) -> str | None:
        """Download APK from Uptodown."""
        tmp_apk = tempfile.mktemp(suffix=".apk", prefix="phantom_")
        # Uptodown uses app name slug, not package name — try search
        async with httpx.AsyncClient(
            timeout=120, follow_redirects=True, headers=BROWSER_HEADERS
        ) as client:
            # Search
            search_resp = await client.get(
                f"https://en.uptodown.com/android/search",
                params={"q": package_name},
            )
            if search_resp.status_code != 200:
                return None

            # Find app link
            m = re.search(
                r'href="(https://[a-z0-9-]+\.en\.uptodown\.com/android)"',
                search_resp.text,
            )
            if not m:
                return None

            app_url = m.group(1)
            resp = await client.get(f"{app_url}/download")
            if resp.status_code != 200:
                return None

            # Find download data-url
            for pattern in [
                r'data-url="(https://[^"]+\.apk[^"]*)"',
                r'id="detail-download-button"[^>]*data-url="([^"]+)"',
                r'"downloadUrl"\s*:\s*"(https://[^"]+)"',
                r'class="button download"[^>]*href="([^"]+)"',
            ]:
                m = re.search(pattern, resp.text)
                if m:
                    dl_url = m.group(1)
                    if dl_url.startswith("/"):
                        dl_url = f"{app_url}{dl_url}"
                    dl_resp = await client.get(dl_url)
                    if (dl_resp.status_code == 200
                            and len(dl_resp.content) > 100000
                            and dl_resp.content[:2] == b"PK"):
                        Path(tmp_apk).write_bytes(dl_resp.content)
                        logger.info(f"Uptodown: {len(dl_resp.content)} bytes")
                        return tmp_apk
        return None

    # ─── Browser-based downloaders (playwright) ──────────────────────

    async def _browser_download_apkpure(self, package_name: str) -> str | None:
        """Use headless Chromium to download from APKPure."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.debug("playwright not available")
            return None

        tmp_dir = tempfile.mkdtemp(prefix="phantom_apkdl_")
        tmp_apk = os.path.join(tmp_dir, "app.apk")

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    user_agent=BROWSER_HEADERS["User-Agent"],
                    accept_downloads=True,
                )
                page = await context.new_page()

                # Search for the app
                logger.info(f"Browser: searching APKPure for {package_name}")
                await page.goto(
                    f"https://apkpure.com/search?q={package_name}",
                    timeout=30000,
                )
                await page.wait_for_load_state("domcontentloaded")

                # Click on the matching result
                app_link = page.locator(f'a[href*="/{package_name}"]').first
                if not await app_link.is_visible():
                    logger.debug("APKPure browser: app not found in search")
                    await browser.close()
                    return None

                await app_link.click()
                await page.wait_for_load_state("domcontentloaded")

                # Find and click download button
                dl_btn = page.locator(
                    'a.da, a[href*="/download"], .download-start-btn'
                ).first
                if await dl_btn.is_visible():
                    # Start download
                    async with page.expect_download(timeout=120000) as dl_info:
                        await dl_btn.click()
                    download = await dl_info.value
                    await download.save_as(tmp_apk)
                    logger.info(f"APKPure browser: downloaded to {tmp_apk}")

                    if os.path.isfile(tmp_apk) and os.path.getsize(tmp_apk) > 100000:
                        # Verify PK header
                        with open(tmp_apk, "rb") as f:
                            if f.read(2) == b"PK":
                                await browser.close()
                                return tmp_apk

                await browser.close()
        except Exception as e:
            logger.debug(f"APKPure browser error: {e}")
        finally:
            # Clean up tmp_dir only if download failed
            if not os.path.isfile(tmp_apk):
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return None

    async def _browser_download_apkmirror(self, package_name: str) -> str | None:
        """Use headless Chromium to download from APKMirror."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None

        tmp_dir = tempfile.mkdtemp(prefix="phantom_apkdl_")
        tmp_apk = os.path.join(tmp_dir, "app.apk")

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    user_agent=BROWSER_HEADERS["User-Agent"],
                    accept_downloads=True,
                )
                page = await context.new_page()

                logger.info(f"Browser: searching APKMirror for {package_name}")
                await page.goto(
                    f"https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s={package_name}",
                    timeout=30000,
                )
                await page.wait_for_load_state("domcontentloaded")

                # Click first result
                first_result = page.locator(
                    '.appRowTitle a.fontBlack'
                ).first
                if not await first_result.is_visible():
                    await browser.close()
                    return None

                await first_result.click()
                await page.wait_for_load_state("domcontentloaded")

                # Find APK variant (not bundle)
                apk_row = page.locator(
                    '.table-row a[href*="download"]'
                ).first
                # Try to find any download link
                if not await apk_row.is_visible():
                    apk_row = page.locator('a[href*="-release/"]').first

                if await apk_row.is_visible():
                    await apk_row.click()
                    await page.wait_for_load_state("domcontentloaded")

                    # Click "Download APK" button
                    dl_btn = page.locator(
                        'a.downloadButton, a[href*="download.php"], '
                        'a:has-text("Download APK")'
                    ).first
                    if await dl_btn.is_visible():
                        await dl_btn.click()
                        await page.wait_for_load_state("domcontentloaded")

                        # Final download click
                        final_btn = page.locator(
                            'a[data-google-vignette], a[href*="download"]'
                        ).first
                        if await final_btn.is_visible():
                            async with page.expect_download(
                                timeout=120000
                            ) as dl_info:
                                await final_btn.click()
                            download = await dl_info.value
                            await download.save_as(tmp_apk)

                            if (os.path.isfile(tmp_apk)
                                    and os.path.getsize(tmp_apk) > 100000):
                                with open(tmp_apk, "rb") as f:
                                    if f.read(2) == b"PK":
                                        await browser.close()
                                        return tmp_apk

                await browser.close()
        except Exception as e:
            logger.debug(f"APKMirror browser error: {e}")
        finally:
            if not os.path.isfile(tmp_apk):
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return None

    # ─── Decompilation ───────────────────────────────────────────────────

    async def _run_jadx(self, apk_path: str, output_dir: Path):
        """Run jadx decompiler."""
        output_dir.mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            "jadx", "--no-res", "--no-debug-info",
            "-d", str(output_dir), apk_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        if proc.returncode != 0:
            logger.warning(f"jadx exit code {proc.returncode}: {stderr.decode()[:500]}")

    async def _run_apktool(self, apk_path: str, output_dir: Path):
        """Run apktool for resource extraction."""
        output_dir.mkdir(parents=True, exist_ok=True)
        proc = await asyncio.create_subprocess_exec(
            "apktool", "d", "-f", "-o", str(output_dir), apk_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        if proc.returncode != 0:
            logger.warning(f"apktool exit code {proc.returncode}: {stderr.decode()[:500]}")

    # ─── Manifest Parsing ────────────────────────────────────────────────

    def _parse_manifest(self, manifest_path: Path) -> dict:
        """Parse AndroidManifest.xml for security-relevant info."""
        result = {
            "package_name": "",
            "app_name": "",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }

        try:
            content = manifest_path.read_text(errors="replace")

            # Package name
            pkg_match = re.search(r'package="([^"]+)"', content)
            if pkg_match:
                result["package_name"] = pkg_match.group(1)

            # App name
            name_match = re.search(r'android:label="([^"]+)"', content)
            if name_match:
                result["app_name"] = name_match.group(1)

            # Permissions
            result["permissions"] = re.findall(
                r'<uses-permission\s+android:name="([^"]+)"', content,
            )

            # Components
            result["activities"] = re.findall(
                r'<activity[^>]*android:name="([^"]+)"', content,
            )
            result["services"] = re.findall(
                r'<service[^>]*android:name="([^"]+)"', content,
            )
            result["receivers"] = re.findall(
                r'<receiver[^>]*android:name="([^"]+)"', content,
            )
            result["providers"] = re.findall(
                r'<provider[^>]*android:name="([^"]+)"', content,
            )

        except Exception as e:
            logger.error(f"Manifest parsing error: {e}")

        return result

    # ─── File Scanning ───────────────────────────────────────────────────

    def _scan_directory(self, scan_dir: Path, result: dict):
        """Recursively scan decompiled files for security data."""
        extensions = {".java", ".kt", ".xml", ".json", ".properties",
                      ".yml", ".yaml", ".cfg", ".conf", ".txt", ".smali"}

        file_count = 0
        for root, dirs, files in os.walk(scan_dir):
            # Skip build/test directories
            dirs[:] = [d for d in dirs if d not in
                       {"build", "test", "tests", ".git", "gradle"}]

            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext not in extensions:
                    continue

                fpath = Path(root) / fname
                try:
                    content = fpath.read_text(errors="replace")
                    if len(content) > 500_000:  # Skip huge files
                        continue

                    rel_path = str(fpath.relative_to(scan_dir))
                    self._scan_file_content(content, rel_path, result)
                    file_count += 1

                except Exception:
                    continue

        logger.info(f"Scanned {file_count} files in {scan_dir.name}")

    def _scan_file_content(self, content: str, file_path: str, result: dict):
        """Scan a single file's content for patterns."""

        # API URLs
        for match in API_URL_PATTERN.finditer(content):
            url = match.group(1)
            domain = urlparse(url).netloc.lower()
            if domain and domain not in SKIP_DOMAINS:
                result["api_endpoints"].append({
                    "url": url,
                    "source_file": file_path,
                })

        # API paths
        for match in API_PATH_PATTERN.finditer(content):
            path = match.group(1)
            if len(path) > 3 and not path.endswith((".xml", ".png", ".jpg")):
                result["api_paths"].append(path)

        # Secrets
        for secret_type, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                # Skip very short or obvious non-secrets
                if len(value) < 6:
                    continue
                # Skip common false positives
                if value.lower().strip() in _FP_VALUES:
                    continue
                # Skip Java method patterns (isPassword(), getPassword(), etc.)
                ctx_start = max(0, match.start() - 30)
                ctx = content[ctx_start:match.start()]
                if re.search(r'\.\s*(?:is|get|set|has|check)\s*$', ctx, re.IGNORECASE):
                    continue
                # Skip pure base64 that decodes to ASCII text (not a real secret)
                if secret_type == "AWS Secret Key":
                    try:
                        import base64
                        decoded = base64.b64decode(value).decode("utf-8", errors="strict")
                        if decoded.isascii() and " " in decoded:
                            continue  # English text, not a key
                    except Exception:
                        pass
                result["secrets"].append({
                    "type": secret_type,
                    "value": value[:100],  # Truncate long values
                    "file": file_path,
                })

        # OAuth config
        for config_type, pattern in OAUTH_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                result["oauth_config"].append({
                    "type": config_type,
                    "value": value[:200],
                    "file": file_path,
                })

        # Certificate pinning
        for pin_type, pattern in CERT_PIN_PATTERNS:
            if pattern.search(content):
                result["cert_pinning"].append({
                    "type": pin_type,
                    "file": file_path,
                })

        # Android security issues
        for issue_name, pattern in ANDROID_ISSUES:
            if pattern.search(content):
                severity = "high"
                if issue_name in ("Debuggable App", "WebView JS Enabled",
                                  "WebView File Access"):
                    severity = "critical"
                elif issue_name in ("Backup Allowed", "Cleartext Traffic"):
                    severity = "high"
                elif issue_name in ("Insecure Random", "ECB Mode",
                                    "Hardcoded IV", "Log Sensitive Data"):
                    severity = "medium"

                result["android_issues"].append({
                    "issue": issue_name,
                    "file": file_path,
                    "severity": severity,
                })

    # ─── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _dedup_endpoints(endpoints: list[dict]) -> list[dict]:
        seen = set()
        deduped = []
        for ep in endpoints:
            url = ep["url"]
            if url not in seen:
                seen.add(url)
                deduped.append(ep)
        return deduped

    @staticmethod
    def _dedup_by_value(items: list[dict]) -> list[dict]:
        seen = set()
        deduped = []
        for item in items:
            key = (item.get("type", ""), item.get("value", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped

    def generate_findings(self, data: dict) -> list[dict]:
        """Convert extraction results to Vulnerability findings."""
        findings = []

        # Secrets → critical findings
        for secret in data.get("secrets", []):
            stype = secret["type"]
            severity = "critical"
            if stype in ("Generic API Key", "Hardcoded Password",
                         "OAuth Client Secret", "Encryption Key"):
                severity = "critical"
            elif stype in ("Firebase URL", "Database URL"):
                severity = "high"
            else:
                severity = "high"

            findings.append({
                "title": f"[APK] {stype} found in source code",
                "url": f"apk://{data.get('package_name', '?')}/{secret['file']}",
                "severity": severity,
                "vuln_type": "info_disclosure",
                "description": (
                    f"Hardcoded {stype} found in decompiled APK source.\n"
                    f"File: {secret['file']}\n"
                    f"Value: {secret['value'][:40]}..."
                ),
                "impact": (
                    f"Exposed {stype} in mobile app binary can be extracted "
                    f"by anyone. May grant access to backend services."
                ),
                "remediation": (
                    "Never hardcode secrets in mobile apps. Use server-side "
                    "token exchange, secure key storage (Android Keystore), "
                    "or environment-based configuration."
                ),
                "payload": f"{stype}: {secret['value'][:50]}",
            })

        # Android issues → findings
        for issue in data.get("android_issues", []):
            findings.append({
                "title": f"[APK] {issue['issue']}",
                "url": f"apk://{data.get('package_name', '?')}/{issue['file']}",
                "severity": issue.get("severity", "medium"),
                "vuln_type": "misconfiguration",
                "description": (
                    f"Android security issue: {issue['issue']}\n"
                    f"File: {issue['file']}"
                ),
                "impact": self._issue_impact(issue["issue"]),
                "remediation": self._issue_remediation(issue["issue"]),
            })

        # OAuth config without cert pinning → finding
        if data.get("oauth_config") and not data.get("cert_pinning"):
            findings.append({
                "title": "[APK] OAuth config without certificate pinning",
                "url": f"apk://{data.get('package_name', '?')}",
                "severity": "high",
                "vuln_type": "misconfiguration",
                "description": (
                    "OAuth configuration found but no certificate pinning "
                    "detected. Traffic can be intercepted with a proxy."
                ),
                "impact": (
                    "Attacker can intercept OAuth tokens via MITM attack "
                    "using tools like Burp Suite or mitmproxy."
                ),
                "remediation": (
                    "Implement certificate pinning using OkHttp "
                    "CertificatePinner or Android Network Security Config."
                ),
            })

        return findings

    @staticmethod
    def _issue_impact(issue_name: str) -> str:
        impacts = {
            "Debuggable App": "Attacker can attach debugger, inspect memory, bypass security checks",
            "Backup Allowed": "App data can be extracted via ADB backup without root",
            "Cleartext Traffic": "Network traffic sent unencrypted, vulnerable to MITM",
            "Exported Component": "Component accessible to other apps, potential unauthorized access",
            "WebView JS Enabled": "JavaScript in WebView enables XSS and code execution attacks",
            "WebView File Access": "WebView can access local files, enabling data exfiltration",
            "Insecure Random": "java.util.Random is predictable, tokens/keys can be guessed",
            "ECB Mode": "ECB encryption leaks patterns in data, not semantically secure",
            "Hardcoded IV": "Reused initialization vector weakens encryption",
            "SharedPreferences Sensitive": "Sensitive data stored in plaintext SharedPreferences",
            "Log Sensitive Data": "Credentials/tokens logged, accessible via logcat",
        }
        return impacts.get(issue_name, "Security issue found in mobile application")

    @staticmethod
    def _issue_remediation(issue_name: str) -> str:
        remediations = {
            "Debuggable App": "Set android:debuggable='false' in release builds",
            "Backup Allowed": "Set android:allowBackup='false' or implement BackupAgent with encryption",
            "Cleartext Traffic": "Set android:usesCleartextTraffic='false', enforce HTTPS",
            "Exported Component": "Set android:exported='false' unless intentionally public",
            "WebView JS Enabled": "Disable JavaScript in WebView unless absolutely needed. Validate URLs.",
            "WebView File Access": "Disable file access in WebView. Use setAllowFileAccess(false)",
            "Insecure Random": "Use java.security.SecureRandom for cryptographic operations",
            "ECB Mode": "Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with random IV",
            "Hardcoded IV": "Generate random IV for each encryption operation",
            "SharedPreferences Sensitive": "Use EncryptedSharedPreferences or Android Keystore",
            "Log Sensitive Data": "Remove all logging of sensitive data in release builds. Use ProGuard/R8.",
        }
        return remediations.get(issue_name, "Fix the identified security issue")
