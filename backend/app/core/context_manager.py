"""
Context Manager for Attack Planner — prevents context window overflow.

Inspired by PentAGI's Chain AST approach: intelligently compresses
conversation history while preserving security-relevant signals.
"""
import json
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns for extracting security signals
RE_STATUS_CODE = re.compile(r'\b([1-5]\d{2})\b')
RE_EMAIL = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_TOKEN = re.compile(
    r'(?:eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'  # JWT
    r'|(?:Bearer\s+[A-Za-z0-9_.~+/=-]{20,})'
    r'|(?:(?:sk|pk)[-_][a-zA-Z0-9]{20,})'  # API keys
    r'|(?:ghp_[A-Za-z0-9]{36})'  # GitHub PAT
    r'|(?:AKIA[0-9A-Z]{16})'  # AWS key
)
RE_ENDPOINT = re.compile(r'(?:https?://[^\s"\'<>]+|/(?:api|v[0-9]|admin|auth|login|graphql|rest)[^\s"\'<>]*)')
RE_VERSION = re.compile(r'\b(?:v?\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?)\b')
RE_ERROR = re.compile(
    r'(?:error|exception|traceback|warning|denied|forbidden|unauthorized|invalid|failed|timeout)'
    r'[:\s][^\n]{5,80}',
    re.IGNORECASE,
)
RE_HEADER = re.compile(
    r'(?:Server|X-Powered-By|X-Frame-Options|X-AspNet-Version|X-Runtime'
    r'|WWW-Authenticate|Set-Cookie|Content-Security-Policy|X-Debug)'
    r':\s*[^\n]+',
    re.IGNORECASE,
)

# Anonymization replacements
ANON_PATTERNS = [
    (RE_TOKEN, '[TOKEN]'),
    (RE_IP, '[IP]'),
    (RE_EMAIL, '[EMAIL]'),
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*\S+', re.IGNORECASE), 'password=[REDACTED]'),
    (re.compile(r'(?:secret|api[_-]?key)\s*[=:]\s*\S+', re.IGNORECASE), 'secret=[REDACTED]'),
]


def extract_security_signals(text: str) -> dict:
    """Extract security-relevant data from any text."""
    if not text:
        return {}

    status_codes = sorted(set(RE_STATUS_CODE.findall(text)))
    # Filter to plausible HTTP codes only
    status_codes = [c for c in status_codes if c[0] in '12345' and int(c) < 600]

    return {
        'status_codes': status_codes[:20],
        'errors': list(set(RE_ERROR.findall(text)))[:15],
        'tokens': [t[:40] + '...' for t in set(RE_TOKEN.findall(text))][:5],
        'endpoints': list(set(RE_ENDPOINT.findall(text)))[:30],
        'emails': list(set(RE_EMAIL.findall(text)))[:10],
        'ips': list(set(RE_IP.findall(text)))[:10],
        'versions': list(set(RE_VERSION.findall(text)))[:10],
        'headers': list(set(RE_HEADER.findall(text)))[:15],
    }


def _smart_truncate(text: str, max_chars: int = 4000) -> str:
    """Truncate text preserving head, tail, and extracted signals."""
    if len(text) <= max_chars:
        return text

    signals = extract_security_signals(text)
    non_empty = {k: v for k, v in signals.items() if v}

    head = text[:1000]
    tail = text[-500:]
    signal_block = ""
    if non_empty:
        signal_block = "\n--- Extracted Signals ---\n" + json.dumps(non_empty, indent=1)

    budget = max_chars - len(signal_block) - 60  # 60 for separator text
    head_budget = min(1000, budget * 2 // 3)
    tail_budget = min(500, budget // 3)

    return (
        head[:head_budget]
        + f"\n\n[... truncated {len(text) - head_budget - tail_budget} chars ...]\n\n"
        + tail[-tail_budget:]
        + signal_block
    )


async def summarize_large_response(
    text: str,
    max_chars: int = 4000,
    llm: Optional[object] = None,
) -> str:
    """Summarize a large text block, preserving security-relevant info.

    Uses LLM if available, otherwise falls back to smart truncation.
    """
    if not text or len(text) <= max_chars:
        return text or ""

    # Try LLM summarization
    if llm is not None:
        try:
            available = await llm.is_available()
            if available:
                prompt = (
                    "Summarize this HTTP response / tool output for a penetration tester. "
                    "PRESERVE ALL: status codes, error messages, tokens, session IDs, "
                    "API endpoints, form fields, headers (Server, X-Powered-By), "
                    "version numbers, technology hints, and anything security-relevant. "
                    "Be concise but lose no security signal.\n\n"
                    f"--- START ---\n{text[:12000]}\n--- END ---"
                )
                summary = await llm.analyze(prompt, temperature=0.1, max_tokens=1500)
                if summary and len(summary) > 20:
                    return summary[:max_chars]
        except Exception as e:
            logger.debug(f"LLM summarization failed, using truncation: {e}")

    return _smart_truncate(text, max_chars)


def compress_conversation(
    messages: list[dict],
    max_total_chars: int = 80000,
) -> list[dict]:
    """Compress conversation history to fit context window.

    Strategy:
    - Keep system prompt (index 0) and last 4 messages untouched
    - Compress older messages into action summaries
    """
    if not messages:
        return messages

    total = sum(len(m.get('content', '')) for m in messages)
    if total <= max_total_chars:
        return messages

    # Identify protected messages
    keep_tail = 4
    if len(messages) <= keep_tail + 1:
        return messages  # too few to compress

    system_msg = messages[0] if messages[0].get('role') == 'system' else None
    start_idx = 1 if system_msg else 0
    tail_msgs = messages[-keep_tail:]
    middle = messages[start_idx:-keep_tail]

    if not middle:
        return messages

    # Build compressed summary of middle messages
    actions_tried = []
    findings = []
    for msg in middle:
        content = msg.get('content', '')
        role = msg.get('role', 'unknown')

        if role == 'assistant':
            # Extract action blocks
            for m in re.finditer(r'```action\s*\n(.*?)```', content, re.DOTALL):
                try:
                    action = json.loads(m.group(1))
                    tool = action.get('tool', '?')
                    method = action.get('method', '')
                    url = action.get('url', '')[:80]
                    actions_tried.append(f"  - {tool} {method} {url}".strip())
                except json.JSONDecodeError:
                    pass
            # Extract reasoning snippets
            for line in content.split('\n'):
                line_s = line.strip()
                if line_s.startswith(('Found:', 'Interesting:', 'Vulnerability:', '[VULN]', 'CONFIRMED')):
                    findings.append(f"  - {line_s[:120]}")

        elif role == 'user':
            # Tool results — extract signals
            signals = extract_security_signals(content)
            codes = signals.get('status_codes', [])
            errors = signals.get('errors', [])
            if codes or errors:
                snippet = f"  - Response codes: {', '.join(codes[:5])}"
                if errors:
                    snippet += f" | errors: {errors[0][:60]}"
                findings.append(snippet)

    summary_parts = [f"[Compressed {len(middle)} earlier messages]"]
    if actions_tried:
        summary_parts.append("Actions tried:\n" + '\n'.join(actions_tried[:30]))
    if findings:
        summary_parts.append("Key findings:\n" + '\n'.join(findings[:20]))
    summary_parts.append("[End compressed history — continue from here]")

    compressed_msg = {
        'role': 'user',
        'content': '\n\n'.join(summary_parts),
    }

    result = []
    if system_msg:
        result.append(system_msg)
    result.append(compressed_msg)
    result.extend(tail_msgs)

    new_total = sum(len(m.get('content', '')) for m in result)
    logger.info(f"Context compressed: {total} -> {new_total} chars ({len(messages)} -> {len(result)} msgs)")
    return result


def anonymize_for_storage(text: str) -> str:
    """Mask sensitive data for KB storage."""
    if not text:
        return text

    result = text
    for pattern, replacement in ANON_PATTERNS:
        result = pattern.sub(replacement, result)

    # Mask cookie values but keep names
    result = re.sub(
        r'((?:session|token|auth|csrf|jwt)[a-z_-]*=)[^\s;]+',
        r'\1[REDACTED]',
        result,
        flags=re.IGNORECASE,
    )

    return result
