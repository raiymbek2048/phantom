"""
Evidence Collection Module

Collects comprehensive proof for vulnerability reports:
1. HTTP request/response logs with full headers
2. Screenshots via headless Chrome
3. Replay cURL commands for each finding
4. Response diff evidence (original vs exploit)
5. Timeline of attack chain steps
6. Formatted evidence package for HackerOne reports
"""
import asyncio
import json
import hashlib
import os
import re
from datetime import datetime
from urllib.parse import urlparse

import httpx

from app.utils.http_client import make_client


class EvidenceCollector:
    def __init__(self):
        self.evidence_dir = "/app/results/evidence"
        os.makedirs(self.evidence_dir, exist_ok=True)

    async def collect(self, context: dict) -> list[dict]:
        """Collect evidence for all confirmed vulnerabilities."""
        evidence_list = []
        scan_id = context.get("scan_id", "unknown")
        auth_cookie = context.get("auth_cookie")

        headers = {}
        if auth_cookie:
            if auth_cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = auth_cookie

        vulns = context.get("vulnerabilities", [])
        if not vulns:
            return []

        async with make_client(extra_headers=headers) as client:
            for vuln in vulns:
                vuln_id = vuln.get("id", "unknown")
                evidence = await self._collect_for_vuln(client, vuln, scan_id, str(vuln_id))
                evidence_list.append(evidence)

        return evidence_list

    async def _collect_for_vuln(self, client: httpx.AsyncClient,
                                 vuln: dict, scan_id: str, vuln_id: str) -> dict:
        """Collect comprehensive evidence for a single vulnerability."""
        evidence_path = os.path.join(self.evidence_dir, scan_id, vuln_id)
        os.makedirs(evidence_path, exist_ok=True)

        evidence = {
            "vuln_id": vuln_id,
            "vuln_title": vuln.get("title", ""),
            "severity": vuln.get("severity", ""),
            "timestamp": datetime.utcnow().isoformat(),
            "files": [],
            "curl_command": None,
            "http_log": None,
            "reproduction_steps": [],
        }

        url = vuln.get("url")
        method = vuln.get("method", "GET").upper()
        payload = vuln.get("payload")

        # 1. Save vulnerability details
        details_file = os.path.join(evidence_path, "vulnerability.json")
        with open(details_file, "w") as f:
            json.dump(vuln, f, indent=2, default=str)
        evidence["files"].append(details_file)

        # 2. Generate cURL reproduction command
        curl_cmd = self._generate_curl(url, method, payload, vuln)
        evidence["curl_command"] = curl_cmd
        curl_file = os.path.join(evidence_path, "reproduce.sh")
        with open(curl_file, "w") as f:
            f.write(f"#!/bin/bash\n# Reproduce: {vuln.get('title', '')}\n\n{curl_cmd}\n")
        evidence["files"].append(curl_file)

        # 3. Capture live HTTP request/response if URL available
        if url:
            http_log = await self._capture_http_exchange(client, url, method, payload)
            if http_log:
                evidence["http_log"] = http_log
                log_file = os.path.join(evidence_path, "http_exchange.json")
                with open(log_file, "w") as f:
                    json.dump(http_log, f, indent=2, default=str)
                evidence["files"].append(log_file)

        # 4. Take screenshot
        if url:
            screenshot_path = await self._take_screenshot(url, evidence_path)
            if screenshot_path:
                evidence["files"].append(screenshot_path)

        # 5. Generate reproduction steps
        evidence["reproduction_steps"] = self._generate_steps(vuln)

        # 6. Generate HackerOne-formatted report section
        h1_report = self._format_h1_evidence(vuln, evidence)
        h1_file = os.path.join(evidence_path, "h1_report_section.md")
        with open(h1_file, "w") as f:
            f.write(h1_report)
        evidence["files"].append(h1_file)

        return evidence

    def _generate_curl(self, url: str | None, method: str,
                       payload: str | None, vuln: dict) -> str:
        """Generate a cURL command to reproduce the vulnerability."""
        if not url:
            return "# No URL available"

        parts = [f"curl -k -v -X {method}"]

        # Add headers
        headers = vuln.get("headers", {})
        content_type = vuln.get("content_type_sent")
        if content_type:
            parts.append(f"  -H 'Content-Type: {content_type}'")
        for k, v in headers.items():
            parts.append(f"  -H '{k}: {v}'")

        # Add auth placeholder
        cookie = vuln.get("cookie")
        if cookie:
            parts.append(f"  -H 'Cookie: {cookie}'")
        else:
            parts.append("  -H 'Cookie: YOUR_SESSION_COOKIE'")

        # Add method override header if present
        override_header = vuln.get("header")
        if override_header:
            parts.append(f"  -H '{override_header}'")

        # Add payload
        if payload:
            escaped = payload.replace("'", "'\\''")
            parts.append(f"  -d '{escaped}'")

        parts.append(f"  '{url}'")
        return " \\\n".join(parts)

    async def _capture_http_exchange(self, client: httpx.AsyncClient,
                                      url: str, method: str,
                                      payload: str | None) -> dict | None:
        """Capture full HTTP request/response for evidence."""
        try:
            kwargs = {}
            if payload:
                try:
                    kwargs["json"] = json.loads(payload)
                except (json.JSONDecodeError, TypeError):
                    kwargs["content"] = str(payload)

            resp = await client.request(method, url, **kwargs)

            # Build request log
            request_headers = dict(resp.request.headers)
            # Mask sensitive headers
            for sensitive in ("authorization", "cookie"):
                if sensitive in request_headers:
                    val = request_headers[sensitive]
                    request_headers[sensitive] = val[:20] + "..." if len(val) > 20 else val

            return {
                "request": {
                    "method": method,
                    "url": str(resp.request.url),
                    "headers": request_headers,
                    "body": payload,
                },
                "response": {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_preview": resp.text[:2000],
                    "body_length": len(resp.text),
                    "body_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                },
            }
        except Exception:
            return None

    async def _take_screenshot(self, url: str, output_dir: str) -> str | None:
        """Take a screenshot of a URL using headless Chrome."""
        screenshot_path = os.path.join(output_dir, "screenshot.png")

        try:
            proc = await asyncio.create_subprocess_exec(
                "chromium",
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                f"--screenshot={screenshot_path}",
                "--window-size=1920,1080",
                "--ignore-certificate-errors",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=15)

            if os.path.exists(screenshot_path):
                return screenshot_path
        except Exception:
            pass

        return None

    def _generate_steps(self, vuln: dict) -> list[str]:
        """Generate step-by-step reproduction instructions."""
        steps = []
        vuln_type = vuln.get("vuln_type", "")
        url = vuln.get("url", "")
        payload = vuln.get("payload", "")
        method = vuln.get("method", "GET")

        steps.append(f"1. Navigate to or send a request to: {url}")

        if vuln_type == "xss":
            steps.append(f"2. Inject the following payload: {payload}")
            steps.append("3. Observe that the payload executes in the browser context")
            steps.append("4. Check browser console/DOM for script execution evidence")
        elif vuln_type == "sqli":
            steps.append(f"2. Inject SQL payload: {payload}")
            steps.append("3. Observe modified response indicating SQL execution")
            steps.append("4. Compare response with normal request to confirm injection")
        elif vuln_type == "idor":
            original_id = vuln.get("original_id", "")
            tested_id = vuln.get("tested_id", "")
            steps.append(f"2. Note the original object ID: {original_id}")
            steps.append(f"3. Change the ID to: {tested_id}")
            steps.append("4. Observe that the response returns another user's data")
        elif vuln_type == "ssrf":
            steps.append(f"2. Supply the SSRF payload: {payload}")
            steps.append("3. Observe the server making a request to the internal/external target")
        elif vuln_type == "auth_bypass":
            steps.append(f"2. Apply the bypass technique: {payload or method}")
            steps.append("3. Observe access granted without proper authentication")
        elif vuln_type == "info_disclosure":
            sensitive = vuln.get("sensitive_fields", [])
            steps.append(f"2. Observe the response contains sensitive data: {', '.join(sensitive) if sensitive else 'see response'}")
            steps.append("3. Confirm this data should not be exposed to the current user")
        elif vuln_type == "misconfiguration":
            steps.append(f"2. Send the request with method/headers: {method} {vuln.get('header', '')}")
            steps.append("3. Observe the misconfigured server behavior")
        else:
            if payload:
                steps.append(f"2. Use payload: {payload}")
            steps.append(f"3. Observe the vulnerability in the response")

        steps.append(f"{len(steps) + 1}. Use the provided cURL command to reproduce programmatically")
        return steps

    def _format_h1_evidence(self, vuln: dict, evidence: dict) -> str:
        """Format evidence as a HackerOne report section."""
        title = vuln.get("title", "Vulnerability")
        severity = vuln.get("severity", "medium").upper()
        url = vuln.get("url", "N/A")
        impact = vuln.get("impact", "")
        remediation = vuln.get("remediation", "")
        curl_cmd = evidence.get("curl_command", "")
        steps = evidence.get("reproduction_steps", [])

        sections = [
            f"# {title}",
            "",
            f"**Severity:** {severity}",
            f"**URL:** `{url}`",
            "",
            "## Summary",
            impact or "See details below.",
            "",
            "## Steps to Reproduce",
        ]

        for step in steps:
            sections.append(step)

        sections.extend([
            "",
            "## Proof of Concept",
            "",
            "### cURL Command",
            "```bash",
            curl_cmd,
            "```",
        ])

        http_log = evidence.get("http_log")
        if http_log and http_log.get("response"):
            resp = http_log["response"]
            sections.extend([
                "",
                "### HTTP Response",
                f"**Status:** {resp.get('status_code')}",
                f"**Body Length:** {resp.get('body_length')} bytes",
                "",
                "```",
                resp.get("body_preview", "")[:500],
                "```",
            ])

        if remediation:
            sections.extend([
                "",
                "## Recommended Fix",
                remediation,
            ])

        sections.extend([
            "",
            "## Impact",
            impact or "This vulnerability allows an attacker to compromise the application's security.",
        ])

        return "\n".join(sections)
