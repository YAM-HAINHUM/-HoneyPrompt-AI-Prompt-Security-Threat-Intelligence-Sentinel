"""
notifications.py — Admin-to-user notification system for HoneyPrompt.

Admins can send, edit, and delete targeted notifications to specific users
or broadcast to all users. Users can read and dismiss them.
Stored in notifications.json.
"""
import json
import os
import uuid
from datetime import datetime
from storage_paths import data_file, read_json, write_json

NOTIF_FILE = data_file("notifications.json")

PRIORITY_COLORS = {"info": "#3b82f6", "warning": "#f59e0b", "danger": "#ef4444", "success": "#10b981"}


def _read() -> list:
    return read_json(NOTIF_FILE, [])


def _write(data: list):
    write_json(NOTIF_FILE, data, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Admin operations
# ---------------------------------------------------------------------------

def create_notification(
    sent_by: str,
    target_user: str,          # username or "__all__" for broadcast
    title: str,
    message: str,
    priority: str = "info",    # info | warning | danger | success
) -> dict:
    notif = {
        "notification_id": "NTF-" + str(uuid.uuid4())[:8].upper(),
        "sent_by": sent_by,
        "target_user": target_user.casefold() if target_user != "__all__" else "__all__",
        "title": title.strip()[:120],
        "message": message.strip()[:1000],
        "priority": priority if priority in PRIORITY_COLORS else "info",
        "created_at": datetime.now().isoformat(),
        "updated_at": None,
        "dismissed_by": [],   # list of usernames who dismissed
        "read_by": [],        # list of usernames who read
    }
    data = _read()
    data.append(notif)
    _write(data)
    return notif


def update_notification(notification_id: str, updates: dict) -> dict | None:
    data = _read()
    for n in data:
        if n["notification_id"] == notification_id:
            for k in ("title", "message", "priority"):
                if k in updates and updates[k] is not None:
                    n[k] = updates[k]
            n["updated_at"] = datetime.now().isoformat()
            _write(data)
            return n
    return None


def delete_notification(notification_id: str) -> bool:
    data = _read()
    before = len(data)
    data = [n for n in data if n["notification_id"] != notification_id]
    if len(data) < before:
        _write(data)
        return True
    return False


def get_all_notifications(page: int = 1, page_size: int = 50) -> dict:
    data = list(reversed(_read()))
    total = len(data)
    offset = (page - 1) * page_size
    return {"items": data[offset: offset + page_size], "total": total, "page": page, "page_size": page_size}


# ---------------------------------------------------------------------------
# User operations
# ---------------------------------------------------------------------------

def get_user_notifications(username: str) -> list:
    """Return notifications targeted at this user or broadcast, not dismissed by them."""
    uid = username.casefold()
    result = []
    for n in reversed(_read()):
        if n["target_user"] != "__all__" and n["target_user"] != uid:
            continue
        if uid in [x.casefold() for x in n.get("dismissed_by", [])]:
            continue
        result.append({
            **n,
            "is_read": uid in [x.casefold() for x in n.get("read_by", [])],
        })
    return result


def mark_notification_read(notification_id: str, username: str) -> dict | None:
    uid = username.casefold()
    data = _read()
    for n in data:
        if n["notification_id"] != notification_id:
            continue
        if n["target_user"] != "__all__" and n["target_user"] != uid:
            return None
        if uid not in [x.casefold() for x in n.get("read_by", [])]:
            n.setdefault("read_by", []).append(uid)
            _write(data)
        return {**n, "is_read": True}
    return None


def dismiss_notification(notification_id: str, username: str) -> bool:
    uid = username.casefold()
    data = _read()
    for n in data:
        if n["notification_id"] != notification_id:
            continue
        if n["target_user"] != "__all__" and n["target_user"] != uid:
            return False
        if uid not in [x.casefold() for x in n.get("dismissed_by", [])]:
            n.setdefault("dismissed_by", []).append(uid)
            # also mark read
            if uid not in [x.casefold() for x in n.get("read_by", [])]:
                n.setdefault("read_by", []).append(uid)
            _write(data)
        return True
    return False


def unread_count_for_user(username: str) -> int:
    uid = username.casefold()
    count = 0
    for n in _read():
        if n["target_user"] != "__all__" and n["target_user"] != uid:
            continue
        if uid in [x.casefold() for x in n.get("dismissed_by", [])]:
            continue
        if uid not in [x.casefold() for x in n.get("read_by", [])]:
            count += 1
    return count
