"""
HackerOne API Client.

Fetches hacktivity, disclosed reports, and program info from HackerOne API v1.
Public endpoints (hacktivity) work without auth.
Private endpoints (reports, submissions) require API credentials.
"""
import logging
from typing import Any

import httpx
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

H1_API_BASE = "https://api.hackerone.com/v1"
H1_WEB_BASE = "https://hackerone.com"


class H1Client:
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={"Accept": "application/json"},
        )
        self._auth = None
        if settings.hackerone_username and settings.hackerone_api_token:
            self._auth = (settings.hackerone_username, settings.hackerone_api_token)

    async def get_hacktivity(
        self,
        page_size: int = 25,
        page_number: int = 1,
        sort_type: str = "latest_disclosable_activity_at",
    ) -> list[dict]:
        """Fetch recent hacktivity items (public, no auth needed)."""
        params = {
            "page[size]": page_size,
            "page[number]": page_number,
            "sort_type": sort_type,
        }
        resp = await self.client.get(
            f"{H1_API_BASE}/hackers/hacktivity", params=params
        )
        resp.raise_for_status()
        return resp.json().get("data", [])

    async def get_hacktivity_pages(
        self, pages: int = 10, page_size: int = 25
    ) -> list[dict]:
        """Fetch multiple pages of hacktivity."""
        all_items = []
        for page in range(1, pages + 1):
            try:
                items = await self.get_hacktivity(
                    page_size=page_size, page_number=page
                )
                if not items:
                    break
                all_items.extend(items)
                logger.info(f"H1 hacktivity page {page}: {len(items)} items")
            except Exception as e:
                logger.error(f"H1 hacktivity page {page} failed: {e}")
                break
        return all_items

    async def get_disclosed_report(self, report_id: int) -> dict | None:
        """Fetch a single disclosed report by ID (auth required for full details)."""
        if self._auth:
            try:
                resp = await self.client.get(
                    f"{H1_API_BASE}/hackers/reports/{report_id}",
                    auth=self._auth,
                )
                if resp.status_code == 200:
                    return resp.json().get("data")
            except Exception as e:
                logger.warning(f"H1 report {report_id} auth fetch failed: {e}")

        # Fallback: scrape the public disclosed report page
        return await self._scrape_disclosed_report(report_id)

    async def _scrape_disclosed_report(self, report_id: int) -> dict | None:
        """Scrape disclosed report from HackerOne web page."""
        try:
            resp = await self.client.get(
                f"{H1_WEB_BASE}/reports/{report_id}",
                headers={"Accept": "text/html"},
                follow_redirects=True,
                timeout=15.0,
            )
            if resp.status_code != 200:
                return None
            html = resp.text

            # Extract JSON-LD or structured data from the page
            import json
            import re

            # Try __NEXT_DATA__ (Next.js)
            match = re.search(
                r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL
            )
            if match:
                try:
                    next_data = json.loads(match.group(1))
                    return {"source": "nextjs", "report_id": report_id, "data": next_data}
                except json.JSONDecodeError:
                    pass

            # Try extracting visible text content
            # Remove scripts and styles
            clean = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
            clean = re.sub(r"<style[^>]*>.*?</style>", "", clean, flags=re.DOTALL)
            clean = re.sub(r"<[^>]+>", "\n", clean)
            clean = re.sub(r"\n{3,}", "\n\n", clean).strip()

            # Limit to reasonable size
            if len(clean) > 15000:
                clean = clean[:15000]

            return {"source": "scrape", "report_id": report_id, "text": clean}
        except Exception as e:
            logger.error(f"H1 scrape report {report_id} failed: {e}")
            return None

    async def get_programs(self, page_size: int = 25, page_number: int = 1) -> list[dict]:
        """Fetch bug bounty programs (public directory)."""
        params = {
            "page[size]": page_size,
            "page[number]": page_number,
        }
        try:
            resp = await self.client.get(
                f"{H1_API_BASE}/hackers/programs", params=params
            )
            resp.raise_for_status()
            return resp.json().get("data", [])
        except Exception as e:
            logger.error(f"H1 programs fetch failed: {e}")
            return []

    def extract_hacktivity_metadata(self, item: dict) -> dict:
        """Extract structured metadata from a hacktivity item."""
        attrs = item.get("attributes", {})
        rels = item.get("relationships", {})

        program_data = rels.get("program", {}).get("data", {}).get("attributes", {})
        reporter_data = rels.get("reporter", {}).get("data", {}).get("attributes", {})

        return {
            "h1_id": item.get("id"),
            "title": attrs.get("title"),
            "disclosed": attrs.get("disclosed", False),
            "disclosed_at": attrs.get("disclosed_at"),
            "submitted_at": attrs.get("submitted_at"),
            "severity": attrs.get("severity_rating"),
            "cwe": attrs.get("cwe"),
            "cve_ids": attrs.get("cve_ids") or [],
            "bounty": attrs.get("total_awarded_amount"),
            "votes": attrs.get("votes", 0),
            "url": attrs.get("url"),
            "substate": attrs.get("substate"),
            "program": program_data.get("handle"),
            "program_name": program_data.get("name"),
            "reporter": reporter_data.get("username"),
            "has_vulnerability_info": bool(attrs.get("vulnerability_information")),
        }

    async def close(self):
        await self.client.aclose()
