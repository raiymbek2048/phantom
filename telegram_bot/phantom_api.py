"""PHANTOM API client for Telegram bot."""
import httpx
import logging
import tempfile
import os

logger = logging.getLogger(__name__)


class PhantomAPI:
    def __init__(self, base_url: str, username: str = "admin", password: str = "changeme"):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token: str | None = None

    async def _ensure_auth(self):
        if self.token:
            return
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(
                f"{self.base_url}/api/auth/login",
                data={"username": self.username, "password": self.password},
            )
            resp.raise_for_status()
            self.token = resp.json()["access_token"]

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        await self._ensure_auth()
        async with httpx.AsyncClient(timeout=60) as c:
            resp = await c.request(
                method,
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self.token}"},
                **kwargs,
            )
            if resp.status_code == 401:
                self.token = None
                await self._ensure_auth()
                resp = await c.request(
                    method,
                    f"{self.base_url}{path}",
                    headers={"Authorization": f"Bearer {self.token}"},
                    **kwargs,
                )
            if resp.status_code >= 400:
                detail = resp.text[:500]
                try:
                    detail = resp.json().get("detail", detail)
                except Exception:
                    pass
                raise httpx.HTTPStatusError(
                    f"{resp.status_code}: {detail}",
                    request=resp.request,
                    response=resp,
                )
            ct = resp.headers.get("content-type", "")
            if ct.startswith("application/json"):
                return resp.json()
            return {"raw": resp.text, "content_type": ct}

    async def _download(self, path: str, suffix: str = ".pdf") -> str | None:
        """Download a file and return temp file path."""
        await self._ensure_auth()
        async with httpx.AsyncClient(timeout=120) as c:
            resp = await c.get(
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            if resp.status_code != 200:
                return None
            fd, fpath = tempfile.mkstemp(suffix=suffix)
            with os.fdopen(fd, "wb") as f:
                f.write(resp.content)
            return fpath

    # --- Targets ---
    async def get_stats(self) -> dict:
        return await self._request("GET", "/api/dashboard/stats")

    async def list_targets(self) -> list:
        return await self._request("GET", "/api/targets")

    async def create_target(self, domain: str, scope: str | None = None) -> dict:
        data = {"domain": domain}
        if scope:
            data["scope"] = scope
        return await self._request("POST", "/api/targets", json=data)

    async def get_target(self, target_id: str) -> dict:
        return await self._request("GET", f"/api/targets/{target_id}")

    async def get_target_recon(self, target_id: str) -> dict:
        return await self._request("GET", f"/api/targets/{target_id}/recon")

    # --- Scans ---
    async def start_scan(self, target_id: str, scan_type: str = "full") -> dict:
        data = {"target_id": target_id, "scan_type": scan_type}
        return await self._request("POST", "/api/scans", json=data)

    async def list_scans(self, limit: int = 10) -> list:
        return await self._request("GET", f"/api/scans?limit={limit}")

    async def get_scan(self, scan_id: str) -> dict:
        return await self._request("GET", f"/api/scans/{scan_id}")

    async def get_scan_logs(self, scan_id: str, limit: int = 30) -> list:
        return await self._request("GET", f"/api/scans/{scan_id}/logs?limit={limit}")

    async def stop_scan(self, scan_id: str) -> dict:
        return await self._request("POST", f"/api/scans/{scan_id}/stop")

    async def get_scan_queue(self) -> dict:
        return await self._request("GET", "/api/scans/queue")

    # --- Vulnerabilities ---
    async def list_vulns(self, target_id: str | None = None, severity: str | None = None, limit: int = 20) -> list:
        params = f"?limit={limit}"
        if target_id:
            params += f"&target_id={target_id}"
        if severity:
            params += f"&severity={severity}"
        return await self._request("GET", f"/api/vulnerabilities{params}")

    async def get_vuln(self, vuln_id: str) -> dict:
        return await self._request("GET", f"/api/vulnerabilities/{vuln_id}")

    async def get_vuln_poc(self, vuln_id: str) -> dict:
        return await self._request("GET", f"/api/vulnerabilities/{vuln_id}/poc")

    # --- Reports ---
    async def generate_h1_report(self, vuln_id: str) -> dict:
        return await self._request("GET", f"/api/vulnerabilities/{vuln_id}/hackerone/quick")

    async def generate_h1_report_ai(self, vuln_id: str) -> dict:
        return await self._request("GET", f"/api/vulnerabilities/{vuln_id}/hackerone")

    async def download_scan_pdf(self, scan_id: str) -> str | None:
        return await self._download(f"/api/reports/scan/{scan_id}/pdf", ".pdf")

    async def download_scan_html(self, scan_id: str) -> str | None:
        return await self._download(f"/api/reports/scan/{scan_id}/html", ".html")

    async def download_target_html(self, target_id: str) -> str | None:
        return await self._download(f"/api/reports/target/{target_id}/html", ".html")

    # --- System ---
    async def get_health(self) -> dict:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.get(f"{self.base_url}/api/health")
            return resp.json()

    async def get_token_status(self) -> dict:
        return await self._request("GET", "/api/training/settings/claude-token-status")

    async def get_kb_status(self) -> dict:
        return await self._request("GET", "/api/training/status")

    async def get_vulns_over_time(self) -> dict:
        return await self._request("GET", "/api/dashboard/vulns-over-time")

    async def get_top_targets(self) -> dict:
        return await self._request("GET", "/api/dashboard/top-targets")

    # --- Autopilot ---
    async def autopilot_status(self) -> dict:
        return await self._request("GET", "/api/autopilot/status")

    async def autopilot_start(self) -> dict:
        return await self._request("POST", "/api/autopilot/start")

    async def autopilot_stop(self) -> dict:
        return await self._request("POST", "/api/autopilot/stop")
