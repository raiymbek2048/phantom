"""Auth Bridge — handles PHANTOM auth requests via Telegram.

Polls Redis for auth requests from the pipeline, asks user in Telegram,
sends response back via Redis.
"""
import asyncio
import json
import logging

import redis as redis_lib

logger = logging.getLogger("auth_bridge")

AUTH_REQUEST_QUEUE = "phantom:auth:requests"
AUTH_RESPONSE_QUEUE = "phantom:auth:responses:{}"

AUTH_TYPE_LABELS = {
    "form_login": "🔐 Логин + пароль",
    "api_login": "🔐 API логин",
    "phone_otp": "📱 Телефон + SMS код",
    "oauth": "🔗 OAuth авторизация",
    "basic_auth": "🔐 HTTP Basic Auth",
    "otp": "📱 Введи OTP код",
    "custom": "🔐 Авторизация",
}


class AuthBridge:
    """Polls Redis for auth requests, asks user via Telegram bot."""

    def __init__(self, bot, chat_ids: set[int], redis_url: str):
        self.bot = bot
        self.chat_ids = chat_ids
        self.redis_url = redis_url
        self._running = False
        # Track pending requests: request_id -> {chat_id, message_id}
        self._pending: dict[str, dict] = {}

    async def start(self):
        self._running = True
        logger.info(f"AuthBridge started, chat_ids: {self.chat_ids}")
        while self._running:
            try:
                await self._check_requests()
            except Exception as e:
                logger.error(f"AuthBridge error: {e}")
            await asyncio.sleep(2)

    def stop(self):
        self._running = False

    async def _check_requests(self):
        r = redis_lib.from_url(self.redis_url)
        while True:
            data = r.lpop(AUTH_REQUEST_QUEUE)
            if not data:
                break
            request = json.loads(data.decode() if isinstance(data, bytes) else data)
            await self._handle_request(request)
        r.close()

    async def _handle_request(self, request: dict):
        """Send auth request to user in Telegram."""
        request_id = request.get("request_id", "?")
        domain = request.get("domain", "?")
        auth_type = request.get("auth_type", "custom")
        details = request.get("details", "")
        fields = request.get("login_fields", [])
        login_url = request.get("login_url", "")

        label = AUTH_TYPE_LABELS.get(auth_type, "🔐 Авторизация")

        if auth_type == "otp":
            text = (
                f"📱 <b>PHANTOM нужен OTP код</b>\n\n"
                f"Сайт: <code>{domain}</code>\n"
                f"{details}\n\n"
                f"Отправь код одним сообщением:"
            )
        else:
            text = (
                f"{label}\n\n"
                f"🎯 <b>PHANTOM нужна авторизация</b>\n"
                f"Сайт: <code>{domain}</code>\n"
            )
            if login_url:
                text += f"Login URL: <code>{login_url}</code>\n"
            if details:
                text += f"\n{details}\n"

            text += "\n<b>Отправь данные в формате:</b>\n"
            if "phone" in fields and "otp" in fields:
                text += "<code>phone: +77001234567</code>\n"
                text += "\nПосле отправки номера, я запрошу OTP код."
            elif "phone" in fields:
                text += "<code>phone: +77001234567</code>"
            elif "username" in fields or "password" in fields:
                text += "<code>login: username\npassword: mypassword</code>"
            else:
                text += "<code>login: your_login\npassword: your_password</code>"

            text += (
                f"\n\nИли отправь <code>skip</code> чтобы пропустить авторизацию.\n"
                f"⏱ Таймаут: 5 минут"
            )

        for chat_id in self.chat_ids:
            try:
                msg = await self.bot.send_message(chat_id, text, parse_mode="HTML")
                self._pending[request_id] = {
                    "chat_id": chat_id,
                    "domain": domain,
                    "auth_type": auth_type,
                    "fields": fields,
                }
                logger.info(f"Auth request sent to chat {chat_id}: {request_id}")
            except Exception as e:
                logger.error(f"Failed to send auth request to {chat_id}: {e}")

    def try_handle_auth_response(self, chat_id: int, text: str) -> bool:
        """Try to match user message to a pending auth request.

        Returns True if message was consumed as auth response.
        """
        # Find pending request for this chat
        for request_id, info in list(self._pending.items()):
            if info["chat_id"] != chat_id:
                continue

            response = self._parse_response(text, info)
            if response is None:
                continue

            # Submit to Redis
            try:
                r = redis_lib.from_url(self.redis_url)
                response_key = AUTH_RESPONSE_QUEUE.format(request_id)
                r.rpush(response_key, json.dumps(response))
                r.expire(response_key, 600)
                r.close()
            except Exception as e:
                logger.error(f"Failed to submit auth response: {e}")
                return False

            del self._pending[request_id]
            logger.info(f"Auth response submitted for {request_id}")
            return True

        return False

    def _parse_response(self, text: str, info: dict) -> dict | None:
        """Parse user response into credentials dict."""
        text = text.strip()

        if text.lower() == "skip":
            return {"skip": True}

        auth_type = info.get("auth_type", "custom")

        # OTP — just the code
        if auth_type == "otp":
            code = text.replace(" ", "")
            if code.isdigit() and 3 <= len(code) <= 8:
                return {"otp": code}
            return {"otp": text}  # let it try anyway

        # Parse key: value format
        parsed = {}
        for line in text.split("\n"):
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                # Normalize key names
                if key in ("login", "username", "user", "email", "логин"):
                    parsed["username"] = value
                elif key in ("password", "pass", "pwd", "пароль"):
                    parsed["password"] = value
                elif key in ("phone", "tel", "телефон", "номер"):
                    parsed["phone"] = value
                elif key in ("otp", "code", "код", "sms"):
                    parsed["otp"] = value
                elif key in ("token", "jwt", "cookie"):
                    parsed["token"] = value

        if parsed:
            return parsed

        # Single line — could be just a password or phone number
        if text.startswith("+") or text.replace(" ", "").isdigit():
            return {"phone": text}

        # Single line, no format — treat as password if fields suggest it
        if len(text) < 100 and not " " in text:
            return {"password": text}

        return None

    @property
    def has_pending(self) -> bool:
        return bool(self._pending)
