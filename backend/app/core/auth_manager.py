"""Authentication Manager — smart auth detection & human-in-the-loop via Telegram.

Decides when a target needs authentication, what type, and either:
1. Auto-logs in (if credentials stored)
2. Asks the user via Telegram bot for credentials/OTP
3. Skips auth if not needed

Auth flow:
  Recon detects login → AuthManager checks if we have creds →
  If no: asks user via Redis queue → user responds via Telegram →
  AuthManager logs in → stores session → pipeline continues
"""
import json
import logging
import time
import re
from enum import Enum

logger = logging.getLogger(__name__)

# Redis keys
AUTH_REQUEST_QUEUE = "phantom:auth:requests"       # PHANTOM → Telegram bot
AUTH_RESPONSE_QUEUE = "phantom:auth:responses:{}"  # Telegram bot → PHANTOM (per request_id)
AUTH_SESSIONS_KEY = "phantom:auth:sessions:{}"     # target_domain → session data
AUTH_CREDENTIALS_KEY = "phantom:auth:creds:{}"     # target_domain → encrypted creds


class AuthType(str, Enum):
    NONE = "none"                # No auth needed
    FORM_LOGIN = "form_login"   # Username + password form
    API_LOGIN = "api_login"     # POST /api/auth/login
    PHONE_OTP = "phone_otp"     # Phone number + SMS code
    OAUTH = "oauth"             # OAuth redirect flow
    BASIC_AUTH = "basic_auth"   # HTTP Basic Auth
    CUSTOM = "custom"           # Unknown — ask user


class AuthManager:
    """Manages authentication for scan targets."""

    def __init__(self, redis_url: str = None):
        self._redis = None
        self._redis_url = redis_url

    def _get_redis(self):
        if not self._redis:
            import redis as redis_lib
            if self._redis_url:
                self._redis = redis_lib.from_url(self._redis_url)
            else:
                from app.config import get_settings
                self._redis = redis_lib.from_url(get_settings().redis_url)
        return self._redis

    # --- Auth Detection ---

    def detect_auth_type(self, context: dict) -> dict:
        """Analyze recon/endpoint data to determine auth requirements.

        Returns: {
            "needs_auth": bool,
            "auth_type": AuthType,
            "login_url": str | None,
            "login_fields": list | None,  # ["username", "password"] or ["phone", "otp"]
            "details": str,
        }
        """
        forms = context.get("forms", [])
        endpoints = context.get("endpoints", [])
        technologies = context.get("technologies", [])
        main_page_content = context.get("main_page_content", "")

        # 1. Check if we found login forms
        login_form = self._find_login_form(forms)
        if login_form:
            return login_form

        # 2. Check endpoints for auth-related APIs
        auth_api = self._find_auth_api(endpoints)
        if auth_api:
            return auth_api

        # 3. Check if main page redirects to login
        if self._page_redirects_to_login(main_page_content, context):
            return {
                "needs_auth": True,
                "auth_type": AuthType.CUSTOM,
                "login_url": context.get("login_redirect_url"),
                "login_fields": None,
                "details": "Main page redirects to login. Manual auth likely needed.",
            }

        # 4. Check for HTTP 401/403 responses on key endpoints
        if self._has_auth_barriers(context):
            return {
                "needs_auth": True,
                "auth_type": AuthType.CUSTOM,
                "login_url": None,
                "login_fields": None,
                "details": "Multiple endpoints return 401/403. Auth required for deep scan.",
            }

        return {
            "needs_auth": False,
            "auth_type": AuthType.NONE,
            "login_url": None,
            "login_fields": None,
            "details": "No authentication required detected.",
        }

    def _find_login_form(self, forms: list) -> dict | None:
        """Find a login form among extracted forms."""
        for form in forms:
            fields = form.get("fields", [])
            field_names = [f.get("name", "").lower() for f in fields]
            field_types = [f.get("type", "").lower() for f in fields]

            has_password = "password" in field_types
            has_phone = any("phone" in n or "tel" in n or "mobile" in n for n in field_names)
            has_otp = any("otp" in n or "code" in n or "sms" in n or "verify" in n for n in field_names)
            has_username = any(
                n in ("username", "email", "login", "user", "name", "iin", "account")
                for n in field_names
            )

            if has_phone and (has_otp or not has_password):
                return {
                    "needs_auth": True,
                    "auth_type": AuthType.PHONE_OTP,
                    "login_url": form.get("action"),
                    "login_fields": ["phone", "otp"],
                    "details": f"Phone + OTP login form at {form.get('action', '?')}",
                }

            if has_password and has_username:
                return {
                    "needs_auth": True,
                    "auth_type": AuthType.FORM_LOGIN,
                    "login_url": form.get("action"),
                    "login_fields": ["username", "password"],
                    "details": f"Login form at {form.get('action', '?')}",
                }

            if has_password:
                return {
                    "needs_auth": True,
                    "auth_type": AuthType.FORM_LOGIN,
                    "login_url": form.get("action"),
                    "login_fields": ["password"],
                    "details": f"Password form at {form.get('action', '?')}",
                }

        return None

    def _find_auth_api(self, endpoints: list) -> dict | None:
        """Find auth API endpoints."""
        auth_patterns = [
            r"/api/v?\d*/auth/login",
            r"/api/v?\d*/login",
            r"/api/v?\d*/signin",
            r"/auth/token",
            r"/oauth/token",
            r"/rest/user/login",
            r"/api/v?\d*/auth/otp",
        ]
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            for pattern in auth_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    is_otp = "otp" in url.lower()
                    return {
                        "needs_auth": True,
                        "auth_type": AuthType.PHONE_OTP if is_otp else AuthType.API_LOGIN,
                        "login_url": url,
                        "login_fields": ["phone", "otp"] if is_otp else ["username", "password"],
                        "details": f"Auth API endpoint: {url}",
                    }
        return None

    def _page_redirects_to_login(self, content: str, context: dict) -> bool:
        """Check if main page content suggests login redirect."""
        if not content:
            return False
        indicators = ["login", "signin", "sign-in", "авторизац", "войти", "вход"]
        content_lower = content.lower()
        return any(ind in content_lower for ind in indicators) and len(content) < 5000

    def _has_auth_barriers(self, context: dict) -> bool:
        """Check if many endpoints returned 401/403."""
        status_codes = context.get("endpoint_status_codes", {})
        auth_blocked = sum(1 for code in status_codes.values() if code in (401, 403))
        total = len(status_codes)
        return total > 5 and auth_blocked / total > 0.5

    # --- Credential Management ---

    def get_stored_credentials(self, domain: str) -> dict | None:
        """Get stored credentials for a domain."""
        try:
            r = self._get_redis()
            data = r.get(AUTH_CREDENTIALS_KEY.format(domain))
            if data:
                return json.loads(data.decode() if isinstance(data, bytes) else data)
        except Exception as e:
            logger.error(f"Failed to get creds for {domain}: {e}")
        return None

    def store_credentials(self, domain: str, creds: dict):
        """Store credentials for a domain. creds: {username, password} or {phone}."""
        try:
            r = self._get_redis()
            r.set(AUTH_CREDENTIALS_KEY.format(domain), json.dumps(creds))
            # No expiry — credentials persist until manually removed
        except Exception as e:
            logger.error(f"Failed to store creds for {domain}: {e}")

    # --- Session Management ---

    def get_stored_session(self, domain: str) -> dict | None:
        """Get stored session (cookie/token) for a domain."""
        try:
            r = self._get_redis()
            data = r.get(AUTH_SESSIONS_KEY.format(domain))
            if data:
                session = json.loads(data.decode() if isinstance(data, bytes) else data)
                # Check if expired
                if session.get("expires_at", 0) > time.time():
                    return session
                logger.info(f"Session expired for {domain}")
        except Exception as e:
            logger.error(f"Failed to get session for {domain}: {e}")
        return None

    def store_session(self, domain: str, session: dict, ttl: int = 3600):
        """Store auth session. session: {cookie, token, headers, expires_at}."""
        try:
            r = self._get_redis()
            session["expires_at"] = session.get("expires_at", int(time.time()) + ttl)
            r.set(AUTH_SESSIONS_KEY.format(domain), json.dumps(session))
            r.expire(AUTH_SESSIONS_KEY.format(domain), ttl + 60)
        except Exception as e:
            logger.error(f"Failed to store session for {domain}: {e}")

    # --- Human-in-the-Loop (Telegram) ---

    def request_credentials_from_user(self, domain: str, auth_info: dict, scan_id: str) -> str:
        """Send auth request to Telegram bot. Returns request_id to poll for response."""
        request_id = f"auth_{domain}_{int(time.time())}"
        request_data = {
            "request_id": request_id,
            "scan_id": scan_id,
            "domain": domain,
            "auth_type": auth_info.get("auth_type", "custom"),
            "login_url": auth_info.get("login_url"),
            "login_fields": auth_info.get("login_fields", []),
            "details": auth_info.get("details", ""),
            "timestamp": time.time(),
        }
        try:
            r = self._get_redis()
            r.rpush(AUTH_REQUEST_QUEUE, json.dumps(request_data))
            logger.info(f"Auth request sent to Telegram: {request_id} for {domain}")
            return request_id
        except Exception as e:
            logger.error(f"Failed to send auth request: {e}")
            return ""

    def request_otp_from_user(self, domain: str, scan_id: str, context: str = "") -> str:
        """Request OTP code from user via Telegram."""
        request_id = f"otp_{domain}_{int(time.time())}"
        request_data = {
            "request_id": request_id,
            "scan_id": scan_id,
            "domain": domain,
            "auth_type": "otp",
            "details": context or f"Enter OTP code for {domain}",
            "login_fields": ["otp"],
            "timestamp": time.time(),
        }
        try:
            r = self._get_redis()
            r.rpush(AUTH_REQUEST_QUEUE, json.dumps(request_data))
            return request_id
        except Exception as e:
            logger.error(f"Failed to send OTP request: {e}")
            return ""

    def wait_for_response(self, request_id: str, timeout: int = 300) -> dict | None:
        """Wait for user response from Telegram (blocking, up to timeout seconds).

        Returns: {username, password} or {otp} or {token} or None on timeout.
        """
        if not request_id:
            return None
        try:
            r = self._get_redis()
            response_key = AUTH_RESPONSE_QUEUE.format(request_id)
            # BLPOP with timeout
            result = r.blpop(response_key, timeout=timeout)
            if result:
                _, data = result
                return json.loads(data.decode() if isinstance(data, bytes) else data)
            logger.warning(f"Auth request {request_id} timed out after {timeout}s")
        except Exception as e:
            logger.error(f"Failed to get auth response: {e}")
        return None

    def submit_response(self, request_id: str, response: dict):
        """Submit auth response (called by Telegram bot)."""
        try:
            r = self._get_redis()
            response_key = AUTH_RESPONSE_QUEUE.format(request_id)
            r.rpush(response_key, json.dumps(response))
            r.expire(response_key, 600)  # cleanup after 10 min
        except Exception as e:
            logger.error(f"Failed to submit auth response: {e}")

    # --- High-Level Auth Flow ---

    def ensure_authenticated(self, domain: str, context: dict, scan_id: str) -> dict | None:
        """Main entry point: ensure we have a valid session for this domain.

        Returns session dict or None. May block waiting for user input.

        Flow:
        1. Check stored session → return if valid
        2. Check stored credentials → try auto-login
        3. Detect auth type → ask user via Telegram
        4. User responds → login → store session
        """
        # 1. Existing valid session?
        session = self.get_stored_session(domain)
        if session:
            logger.info(f"Using stored session for {domain}")
            return session

        # 2. Stored credentials? Try auto-login
        creds = self.get_stored_credentials(domain)
        if creds:
            logger.info(f"Have stored creds for {domain}, attempting login...")
            # Auth type determines how we login
            auth_info = self.detect_auth_type(context)
            if auth_info["auth_type"] == AuthType.PHONE_OTP:
                # Need OTP even with stored phone
                request_id = self.request_otp_from_user(
                    domain, scan_id,
                    f"PHANTOM отправил SMS на {creds.get('phone', '?')}. Введи OTP код:"
                )
                response = self.wait_for_response(request_id, timeout=300)
                if response and response.get("otp"):
                    creds["otp"] = response["otp"]
                    return {"credentials": creds, "needs_login": True}
            else:
                return {"credentials": creds, "needs_login": True}

        # 3. Detect auth type
        auth_info = self.detect_auth_type(context)
        if not auth_info["needs_auth"]:
            logger.info(f"No auth needed for {domain}")
            return None  # No auth needed

        # 4. Ask user via Telegram
        logger.info(f"Auth needed for {domain}: {auth_info['auth_type']}")
        request_id = self.request_credentials_from_user(domain, auth_info, scan_id)
        if not request_id:
            logger.error("Failed to create auth request")
            return None

        # 5. Wait for user response (blocks up to 5 min)
        response = self.wait_for_response(request_id, timeout=300)
        if not response:
            logger.warning(f"No auth response for {domain}, continuing without auth")
            return None

        # 6. Store credentials for future use
        if response.get("username") or response.get("phone"):
            self.store_credentials(domain, {
                k: v for k, v in response.items()
                if k in ("username", "password", "phone", "email")
            })

        return {"credentials": response, "needs_login": True}
