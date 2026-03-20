"""AI Agent — Claude as the brain for PHANTOM Telegram bot.

Claude receives user messages, decides which PHANTOM tools to call,
executes them, and responds naturally.
"""
import json
import logging
import time
import traceback

import httpx
import redis as redis_lib

logger = logging.getLogger("phantom_agent")

SYSTEM_PROMPT = """Ты — PHANTOM AI Assistant, помощник для управления платформой пентестинга PHANTOM через Telegram.
Ты общаешься на русском языке (если пользователь пишет на другом — отвечай на его языке).
Ты можешь управлять всей платформой через инструменты (tools).

Правила:
- Будь кратким, но информативным. Telegram — не место для эссе.
- Используй эмодзи умеренно для наглядности.
- Когда пользователь просит просканировать сайт — сначала создай target (если его нет), потом запусти скан.
- Когда просят отчёт — скачай PDF и отправь файлом.
- Когда просят уязвимости — покажи самые важные (critical/high первыми).
- Если нужно несколько действий — делай их последовательно через tool calls.
- ID объектов показывай коротко (первые 8 символов).
- Для URL без протокола — добавляй https://
- Отвечай ТОЛЬКО на основе реальных данных из tools. Не выдумывай.
"""

# Tool definitions for Claude
TOOLS = [
    {
        "name": "get_dashboard",
        "description": "Get PHANTOM dashboard stats: total targets, scans, vulnerabilities, critical/high counts, KB patterns",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "list_targets",
        "description": "List all scan targets. Each target has: id, domain, status, scope. Use target 'id' field for start_scan.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "create_target",
        "description": "Create a new scan target. Pass domain name (e.g. 'example.com' or 'https://example.com'). Returns existing target if domain already exists.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to scan (e.g. example.com or https://example.com)"},
                "scope": {"type": "string", "description": "Optional scope rules (e.g. '*.example.com')"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "start_scan",
        "description": "Start a security scan on a target. scan_type: 'full' (all phases, thorough) or 'quick' (fast recon only)",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_id": {"type": "string", "description": "Target UUID"},
                "scan_type": {"type": "string", "enum": ["full", "quick"], "description": "Scan type"},
            },
            "required": ["target_id"],
        },
    },
    {
        "name": "get_scan_status",
        "description": "Get details of a specific scan including progress, current phase, findings count",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "list_running_scans",
        "description": "Get currently running and queued scans",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "stop_scan",
        "description": "Stop a running scan",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "list_vulnerabilities",
        "description": "List found vulnerabilities. Can filter by severity (critical/high/medium/low) and target_id.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "target_id": {"type": "string"},
                "limit": {"type": "integer", "description": "Max results (default 20)"},
            },
            "required": [],
        },
    },
    {
        "name": "get_vulnerability",
        "description": "Get detailed info about a specific vulnerability including description, payload, remediation",
        "input_schema": {
            "type": "object",
            "properties": {"vuln_id": {"type": "string"}},
            "required": ["vuln_id"],
        },
    },
    {
        "name": "get_recon_data",
        "description": "Get reconnaissance data for a target: subdomains, technologies, open ports, endpoints",
        "input_schema": {
            "type": "object",
            "properties": {"target_id": {"type": "string"}},
            "required": ["target_id"],
        },
    },
    {
        "name": "generate_h1_report",
        "description": "Generate a HackerOne-style vulnerability report for a specific vulnerability",
        "input_schema": {
            "type": "object",
            "properties": {"vuln_id": {"type": "string"}},
            "required": ["vuln_id"],
        },
    },
    {
        "name": "download_report_pdf",
        "description": "Download a PDF report for a completed scan. Returns file path to send to user.",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "download_report_html",
        "description": "Download an HTML report for a completed scan.",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "get_health",
        "description": "Check system health: API status, LLM availability, provider",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_token_status",
        "description": "Check Claude AI token status: access/refresh token presence, expiry time",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_scan_logs",
        "description": "Get recent log entries for a scan to see what happened",
        "input_schema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "autopilot_start",
        "description": "Start PHANTOM autopilot — automatically scans all targets in rotation",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "autopilot_stop",
        "description": "Stop autopilot",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "autopilot_status",
        "description": "Get autopilot status and recommendation",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_top_targets",
        "description": "Get top targets ranked by vulnerability count",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "monitor_scan",
        "description": "Start background monitoring of a scan — sends progress updates to the user every N seconds until scan completes. Then sends final summary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan UUID to monitor"},
                "interval": {"type": "integer", "description": "Update interval in seconds (default 30, min 15)"},
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "send_file",
        "description": "Send a file (PDF/HTML report) to the user in Telegram. Use after download_report_pdf/html.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Local file path from download"},
                "caption": {"type": "string", "description": "File caption"},
            },
            "required": ["file_path"],
        },
    },
]


OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"


class PhantomAgent:
    """AI agent that uses Claude to reason and PHANTOM API to act."""

    def __init__(self, phantom_api, claude_api_url: str, claude_api_key: str, model: str = "claude-haiku-4-5-20251001", redis_url: str = "redis://redis:6379/0"):
        self.api = phantom_api
        self.claude_url = claude_api_url
        self.claude_key = claude_api_key
        self.model = model
        self.redis_url = redis_url
        # Per-user conversation history (chat_id -> messages)
        self._conversations: dict[int, list] = {}
        self._max_history = 20  # messages per user

    def _get_history(self, chat_id: int) -> list:
        if chat_id not in self._conversations:
            self._conversations[chat_id] = []
        return self._conversations[chat_id]

    def _add_message(self, chat_id: int, role: str, content):
        hist = self._get_history(chat_id)
        hist.append({"role": role, "content": content})
        # Trim old messages
        if len(hist) > self._max_history * 2:
            self._conversations[chat_id] = hist[-self._max_history:]

    async def _call_claude(self, chat_id: int) -> dict:
        """Call Claude API with conversation history and tools."""
        messages = self._get_history(chat_id)
        async with httpx.AsyncClient(timeout=120) as c:
            resp = await c.post(
                f"{self.claude_url}/v1/messages",
                headers={
                    "x-api-key": self.claude_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 4096,
                    "system": SYSTEM_PROMPT,
                    "tools": TOOLS,
                    "messages": messages,
                },
            )
            if resp.status_code != 200:
                logger.error(f"Claude API error: {resp.status_code} {resp.text[:500]}")
                raise Exception(f"Claude API error: {resp.status_code}")
            return resp.json()

    def _refresh_oauth_token(self) -> str | None:
        """Refresh OAuth token using refresh_token from Redis. Returns new access token or None."""
        try:
            r = redis_lib.from_url(self.redis_url)
            refresh_token = r.get("phantom:settings:claude_refresh_token")
            if not refresh_token:
                logger.error("No refresh token in Redis")
                return None
            refresh_token = refresh_token.decode() if isinstance(refresh_token, bytes) else refresh_token
            if not refresh_token.startswith("sk-ant-ort"):
                logger.error("Invalid refresh token format")
                return None

            resp = httpx.post(
                OAUTH_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": OAUTH_CLIENT_ID,
                },
                timeout=15.0,
            )
            if resp.status_code != 200:
                logger.error(f"OAuth refresh failed: {resp.status_code} {resp.text[:200]}")
                return None

            data = resp.json()
            new_access = data.get("access_token")
            new_refresh = data.get("refresh_token")
            expires_in = data.get("expires_in", 28800)

            if not new_access:
                return None

            # Store in Redis
            r.set("phantom:settings:claude_oauth_token", new_access)
            if new_refresh:
                r.set("phantom:settings:claude_refresh_token", new_refresh)
            r.set("phantom:settings:claude_token_expires_at", str(int(time.time()) + expires_in))
            r.close()

            logger.info(f"OAuth token refreshed: {new_access[:20]}... expires in {expires_in}s")
            return new_access

        except Exception as e:
            logger.error(f"OAuth refresh error: {e}")
            return None

    async def _call_claude_oauth(self, chat_id: int, oauth_token: str) -> dict:
        """Call Claude API with OAuth Bearer token. Auto-refreshes on 401."""
        messages = self._get_history(chat_id)
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "tools": TOOLS,
            "messages": messages,
        }

        for attempt in range(2):  # try once, refresh, retry
            async with httpx.AsyncClient(timeout=120) as c:
                resp = await c.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "Authorization": f"Bearer {oauth_token}",
                        "anthropic-version": "2023-06-01",
                        "anthropic-beta": "oauth-2025-04-20",
                        "content-type": "application/json",
                    },
                    json=payload,
                )
                if resp.status_code == 200:
                    return resp.json()

                if resp.status_code == 401 and attempt == 0:
                    logger.warning("OAuth 401 — refreshing token...")
                    new_token = self._refresh_oauth_token()
                    if new_token:
                        oauth_token = new_token
                        continue  # retry with new token
                    else:
                        logger.error("Token refresh failed")

                logger.error(f"Claude OAuth API error: {resp.status_code} {resp.text[:500]}")
                raise Exception(f"Claude API error: {resp.status_code}")

        raise Exception("Claude API: max retries exhausted")

    async def _execute_tool(self, name: str, args: dict) -> str:
        """Execute a PHANTOM tool and return result as string."""
        try:
            if name == "get_dashboard":
                result = await self.api.get_stats()
            elif name == "list_targets":
                result = await self.api.list_targets()
            elif name == "create_target":
                domain = args["domain"]
                result = await self.api.create_target(domain, args.get("scope"))
            elif name == "start_scan":
                result = await self.api.start_scan(args["target_id"], args.get("scan_type", "full"))
            elif name == "get_scan_status":
                result = await self.api.get_scan(args["scan_id"])
            elif name == "list_running_scans":
                result = await self.api.get_scan_queue()
            elif name == "stop_scan":
                result = await self.api.stop_scan(args["scan_id"])
            elif name == "list_vulnerabilities":
                result = await self.api.list_vulns(
                    target_id=args.get("target_id"),
                    severity=args.get("severity"),
                    limit=args.get("limit", 20),
                )
            elif name == "get_vulnerability":
                result = await self.api.get_vuln(args["vuln_id"])
            elif name == "get_recon_data":
                result = await self.api.get_target_recon(args["target_id"])
            elif name == "generate_h1_report":
                result = await self.api.generate_h1_report(args["vuln_id"])
            elif name == "download_report_pdf":
                path = await self.api.download_scan_pdf(args["scan_id"])
                result = {"file_path": path, "type": "pdf"} if path else {"error": "Failed to generate PDF"}
            elif name == "download_report_html":
                path = await self.api.download_scan_html(args["scan_id"])
                result = {"file_path": path, "type": "html"} if path else {"error": "Failed to generate HTML"}
            elif name == "get_health":
                result = await self.api.get_health()
            elif name == "get_token_status":
                result = await self.api.get_token_status()
            elif name == "get_scan_logs":
                result = await self.api.get_scan_logs(args["scan_id"])
            elif name == "autopilot_start":
                result = await self.api.autopilot_start()
            elif name == "autopilot_stop":
                result = await self.api.autopilot_stop()
            elif name == "autopilot_status":
                result = await self.api.autopilot_status()
            elif name == "get_top_targets":
                result = await self.api.get_top_targets()
            elif name == "monitor_scan":
                interval = max(15, args.get("interval", 30))
                return json.dumps({"_monitor_scan": args["scan_id"], "interval": interval})
            elif name == "send_file":
                # This is handled specially in the bot — return the path
                return json.dumps({"_send_file": args.get("file_path"), "caption": args.get("caption", "")})
            else:
                result = {"error": f"Unknown tool: {name}"}

            # Truncate large results
            text = json.dumps(result, default=str, ensure_ascii=False)
            if len(text) > 15000:
                text = text[:15000] + "\n... (truncated)"
            return text

        except Exception as e:
            logger.error(f"Tool {name} error: {e}")
            return json.dumps({"error": str(e)})

    async def process_message(self, chat_id: int, user_text: str, get_key_func) -> list[dict]:
        """Process a user message through Claude agent loop.

        Returns list of responses: [{"type": "text", "text": "..."}, {"type": "file", "path": "...", "caption": "..."}]
        """
        self._add_message(chat_id, "user", user_text)
        responses = []
        max_rounds = 8  # prevent infinite tool loops

        for _ in range(max_rounds):
            # Get Claude's response
            key_info = get_key_func()
            if not key_info:
                responses.append({"type": "text", "text": "❌ Claude API key not available. Check /token"})
                return responses

            api_key, is_oauth = key_info
            try:
                if is_oauth:
                    result = await self._call_claude_oauth(chat_id, api_key)
                else:
                    result = await self._call_claude(chat_id)
            except Exception as e:
                responses.append({"type": "text", "text": f"❌ AI Error: {e}"})
                return responses

            stop_reason = result.get("stop_reason")
            content_blocks = result.get("content", [])

            # Collect assistant response
            self._add_message(chat_id, "assistant", content_blocks)

            # Process content blocks
            tool_uses = []
            for block in content_blocks:
                if block.get("type") == "text":
                    text = block["text"].strip()
                    if text:
                        responses.append({"type": "text", "text": text})
                elif block.get("type") == "tool_use":
                    tool_uses.append(block)

            if not tool_uses or stop_reason == "end_turn":
                break

            # Execute tools and feed results back
            tool_results = []
            for tool in tool_uses:
                logger.info(f"Executing tool: {tool['name']}({tool.get('input', {})})")
                result_str = await self._execute_tool(tool["name"], tool.get("input", {}))

                # Check for special actions (file send, scan monitor)
                try:
                    parsed = json.loads(result_str)
                    if isinstance(parsed, dict):
                        if parsed.get("_send_file"):
                            responses.append({
                                "type": "file",
                                "path": parsed["_send_file"],
                                "caption": parsed.get("caption", ""),
                            })
                        if parsed.get("_monitor_scan"):
                            responses.append({
                                "type": "monitor",
                                "scan_id": parsed["_monitor_scan"],
                                "interval": parsed.get("interval", 30),
                            })
                except (json.JSONDecodeError, TypeError):
                    pass

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool["id"],
                    "content": result_str,
                })

            self._add_message(chat_id, "user", tool_results)

        return responses

    def clear_history(self, chat_id: int):
        """Clear conversation history for a user."""
        self._conversations.pop(chat_id, None)
