"""Notification settings and history API."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.models.user import User
from app.api.auth import get_current_user
from app.core.notifications import (
    get_notification_settings,
    save_notification_settings,
    send_test_notification,
    get_notification_history,
)

router = APIRouter()


class NotificationSettingsUpdate(BaseModel):
    enabled_channels: list[str] | None = None  # ["webhook", "email", "telegram"]
    webhook_url: str | None = None
    email_to: str | None = None
    email_from: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_tls: bool | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    notify_critical: bool | None = None
    notify_high: bool | None = None
    notify_scan_complete: bool | None = None
    notify_new_finding: bool | None = None


@router.get("/settings")
async def get_settings(user: User = Depends(get_current_user)):
    """Get current notification settings."""
    settings = get_notification_settings()
    # Mask sensitive fields
    masked = dict(settings)
    if masked.get("smtp_password"):
        masked["smtp_password"] = "********"
    if masked.get("telegram_bot_token"):
        token = masked["telegram_bot_token"]
        if len(token) > 8:
            masked["telegram_bot_token"] = token[:4] + "..." + token[-4:]
    return masked


@router.put("/settings")
async def update_settings(
    body: NotificationSettingsUpdate,
    user: User = Depends(get_current_user),
):
    """Update notification settings."""
    current = get_notification_settings()
    updates = body.model_dump(exclude_unset=True)

    # Don't overwrite password with mask
    if updates.get("smtp_password") == "********":
        del updates["smtp_password"]
    # Don't overwrite token with mask
    if "telegram_bot_token" in updates:
        token = updates["telegram_bot_token"]
        if token and "..." in token and len(token) < 15:
            del updates["telegram_bot_token"]

    current.update(updates)
    save_notification_settings(current)
    # Return masked version
    masked = dict(current)
    if masked.get("smtp_password"):
        masked["smtp_password"] = "********"
    if masked.get("telegram_bot_token"):
        t = masked["telegram_bot_token"]
        if len(t) > 8:
            masked["telegram_bot_token"] = t[:4] + "..." + t[-4:]
    return masked


@router.post("/test")
async def test_notifications(user: User = Depends(get_current_user)):
    """Send a test notification to all enabled channels."""
    results = send_test_notification()
    return {"results": results}


@router.get("/history")
async def notification_history(
    limit: int = 100,
    user: User = Depends(get_current_user),
):
    """List recent notifications sent (last 100)."""
    history = get_notification_history(min(limit, 100))
    return history
