"""Dynamic Scan Bridge — relays scanner prompts to Telegram and user answers back.

The mobile dynamic scanner (running on the backend) communicates via Redis:
- Scanner sets `phantom:dynamic_scan:prompt` with {question, screenshot, timestamp, notification?}
- This bridge polls that key, sends screenshot + question to user via Telegram
- When user replies, bridge writes answer to `phantom:dynamic_scan:response`

This enables interactive login flows: scanner takes screenshot of login screen,
user sees it in Telegram, enters phone/OTP, scanner fills the form via UIAutomator.
"""
import asyncio
import base64
import json
import logging
import os
import tempfile
import time

import redis as redis_lib

logger = logging.getLogger("dynamic_bridge")

REDIS_PROMPT_KEY = "phantom:dynamic_scan:prompt"
REDIS_RESPONSE_KEY = "phantom:dynamic_scan:response"


class DynamicScanBridge:
    """Polls Redis for dynamic scan prompts, relays to Telegram user."""

    def __init__(self, bot, chat_ids: set[int], redis_url: str):
        self.bot = bot
        self.chat_ids = chat_ids
        self.redis_url = redis_url
        self._running = False
        self._pending_prompt: bool = False  # True when waiting for user reply
        self._last_prompt_ts: float = 0  # Avoid re-sending same prompt

    async def start(self):
        self._running = True
        logger.info(f"DynamicScanBridge started, chat_ids: {self.chat_ids}")
        while self._running:
            try:
                await self._check_prompt()
            except Exception as e:
                logger.error(f"DynamicScanBridge error: {e}")
            await asyncio.sleep(2)

    def stop(self):
        self._running = False

    @property
    def has_pending(self) -> bool:
        return self._pending_prompt

    async def _check_prompt(self):
        """Check Redis for new scanner prompt."""
        r = redis_lib.from_url(self.redis_url)
        data = r.get(REDIS_PROMPT_KEY)
        if not data:
            r.close()
            return

        prompt = json.loads(data.decode() if isinstance(data, bytes) else data)
        ts = prompt.get("timestamp", 0)

        # Skip if we already sent this prompt
        if ts <= self._last_prompt_ts:
            r.close()
            return

        self._last_prompt_ts = ts
        is_notification = prompt.get("notification", False)
        question = prompt.get("question", "")
        screenshot_b64 = prompt.get("screenshot", "")

        logger.info(f"Scanner prompt: {question[:80]}... (notification={is_notification})")

        for chat_id in self.chat_ids:
            try:
                # Send screenshot if available
                if screenshot_b64:
                    await self._send_screenshot(chat_id, screenshot_b64, question if is_notification else "")

                # Send question text
                if is_notification:
                    if not screenshot_b64:
                        await self.bot.send_message(
                            chat_id,
                            f"📱 <b>Dynamic Scan</b>\n{question}",
                            parse_mode="HTML",
                        )
                else:
                    text = (
                        f"📱 <b>Dynamic Scan — нужен ваш ответ</b>\n\n"
                        f"{question}\n\n"
                        f"<i>Ответьте на это сообщение (текстом).</i>\n"
                        f"⏱ Таймаут: 5 минут"
                    )
                    await self.bot.send_message(chat_id, text, parse_mode="HTML")
                    self._pending_prompt = True

            except Exception as e:
                logger.error(f"Failed to send prompt to {chat_id}: {e}")

        # For notifications, clear the prompt key right away
        if is_notification:
            r.delete(REDIS_PROMPT_KEY)

        r.close()

    async def _send_screenshot(self, chat_id: int, b64_data: str, caption: str = ""):
        """Decode base64 screenshot and send as photo to Telegram."""
        try:
            img_bytes = base64.b64decode(b64_data)
            tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
            tmp.write(img_bytes)
            tmp.close()

            with open(tmp.name, "rb") as f:
                await self.bot.send_photo(
                    chat_id,
                    f,
                    caption=caption[:1024] if caption else "📱 Screenshot from emulator",
                )
            os.unlink(tmp.name)
        except Exception as e:
            logger.error(f"Failed to send screenshot: {e}")
            # Fallback: just mention screenshot was available
            await self.bot.send_message(chat_id, "📷 (скриншот не удалось отправить)")

    def try_handle_response(self, chat_id: int, text: str) -> bool:
        """Try to handle user message as dynamic scan response.

        Returns True if message was consumed.
        """
        if not self._pending_prompt:
            return False

        text = text.strip()
        if not text:
            return False

        # Write answer to Redis
        try:
            r = redis_lib.from_url(self.redis_url)
            r.set(
                REDIS_RESPONSE_KEY,
                json.dumps({"answer": text, "timestamp": time.time()}),
                ex=300,
            )
            r.delete(REDIS_PROMPT_KEY)
            r.close()
        except Exception as e:
            logger.error(f"Failed to submit dynamic scan response: {e}")
            return False

        self._pending_prompt = False
        logger.info(f"Dynamic scan response submitted: {text[:30]}...")
        return True
