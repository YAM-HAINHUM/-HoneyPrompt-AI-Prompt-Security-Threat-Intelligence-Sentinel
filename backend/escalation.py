"""
Escalation engine: tracks consecutive malicious prompts per user,
issues warnings, notifies admin, and temporarily blocks users.
All thresholds are read from security_settings.json at runtime.
"""
import json
import os
from datetime import datetime, timedelta

ACTIVITY_FILE = "security_activity.json"
SETTINGS_FILE = "security_settings.json"

DEFAULT_SETTINGS = {"warning_threshold": 3, "block_threshold": 5, "block_cooldown_minutes": 15}


def _read_settings() -> dict:
    if not os.path.exists(SETTINGS_FILE):
        return DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_FILE, "r") as f:
            data = json.load(f)
        return {**DEFAULT_SETTINGS, **data}
    except Exception:
        return DEFAULT_SETTINGS.copy()


def write_settings(updates: dict):
    current = _read_settings()
    current.update(updates)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(current, f, indent=2)
    return current


def get_settings() -> dict:
    return _read_settings()


def _read_activity() -> dict:
    if not os.path.exists(ACTIVITY_FILE):
        return {}
    try:
        with open(ACTIVITY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_activity(data: dict):
    with open(ACTIVITY_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _default_record() -> dict:
    return {
        "consecutive_malicious_count": 0,
        "total_malicious_count": 0,
        "warning_count": 0,
        "blocked_at": None,
        "blocked_until": None,
        "current_status": "ACTIVE",
        "last_updated": None,
    }


def get_user_activity(username: str) -> dict:
    key = username.casefold()
    data = _read_activity()
    return data.get(key, _default_record())


def get_all_activity() -> dict:
    return _read_activity()


def _save_user_activity(username: str, record: dict):
    key = username.casefold()
    data = _read_activity()
    record["last_updated"] = datetime.now().isoformat()
    data[key] = record
    _write_activity(data)


def check_and_lift_block(username: str) -> dict:
    """Auto-lift block if cooldown has expired. Returns updated record."""
    record = get_user_activity(username)
    if record["current_status"] == "BLOCKED" and record.get("blocked_until"):
        try:
            until = datetime.fromisoformat(record["blocked_until"])
            if datetime.now() >= until:
                record["current_status"] = "ACTIVE"
                record["consecutive_malicious_count"] = 0
                record["blocked_at"] = None
                record["blocked_until"] = None
                _save_user_activity(username, record)
        except (ValueError, TypeError):
            pass
    return record


def process_classification(username: str, classification: str, analysis: dict) -> dict:
    """
    Call after every ML classification. Updates counters and returns an
    action dict with keys: status, warning_message, admin_notification, blocked.
    """
    settings = _read_settings()
    warn_at = int(settings.get("warning_threshold", 3))
    block_at = int(settings.get("block_threshold", 5))
    cooldown = int(settings.get("block_cooldown_minutes", 15))

    record = check_and_lift_block(username)

    result = {
        "status": record["current_status"],
        "warning_message": None,
        "admin_notification": None,
        "blocked": record["current_status"] == "BLOCKED",
        "consecutive_malicious_count": record["consecutive_malicious_count"],
        "blocked_until": record.get("blocked_until"),
    }

    # If already blocked, return immediately
    if record["current_status"] == "BLOCKED":
        return result

    is_malicious = classification == "MALICIOUS"

    if is_malicious:
        record["consecutive_malicious_count"] += 1
        record["total_malicious_count"] += 1
    else:
        # Any non-malicious prompt resets the consecutive counter
        record["consecutive_malicious_count"] = 0

    consecutive = record["consecutive_malicious_count"]

    if is_malicious and consecutive >= block_at:
        # Block the user
        now = datetime.now()
        blocked_until = now + timedelta(minutes=cooldown)
        record["current_status"] = "BLOCKED"
        record["blocked_at"] = now.isoformat()
        record["blocked_until"] = blocked_until.isoformat()
        record["warning_count"] += 1
        result["blocked"] = True
        result["blocked_until"] = blocked_until.isoformat()
        result["status"] = "BLOCKED"
        result["warning_message"] = (
            f"🔴 Account Temporarily Restricted\n\n"
            f"Your account has been temporarily restricted due to {consecutive} consecutive "
            f"malicious prompt attempts. Access will be restored in {cooldown} minutes."
        )
        result["admin_notification"] = {
            "level": "BLOCK",
            "username": username,
            "consecutive": consecutive,
            "threat_type": analysis.get("threat_type", "Unknown"),
            "severity": analysis.get("severity", "HIGH"),
            "confidence": analysis.get("confidence", 0),
            "timestamp": now.isoformat(),
            "action": "USER TEMPORARILY BLOCKED",
            "status": "BLOCKED",
        }
    elif is_malicious and consecutive >= warn_at:
        record["warning_count"] += 1
        result["warning_message"] = (
            f"🔶 Security Warning: Multiple malicious activities detected "
            f"({consecutive} consecutive). Further violations may temporarily restrict your account."
        )
        result["admin_notification"] = {
            "level": "WARNING",
            "username": username,
            "consecutive": consecutive,
            "threat_type": analysis.get("threat_type", "Unknown"),
            "severity": analysis.get("severity", "HIGH"),
            "confidence": analysis.get("confidence", 0),
            "timestamp": datetime.now().isoformat(),
            "action": "WARNING ISSUED",
            "status": "ACTIVE",
        }

    result["consecutive_malicious_count"] = consecutive
    _save_user_activity(username, record)
    return result


def admin_unblock_user(username: str) -> dict:
    record = get_user_activity(username)
    record["current_status"] = "ACTIVE"
    record["consecutive_malicious_count"] = 0
    record["blocked_at"] = None
    record["blocked_until"] = None
    _save_user_activity(username, record)
    return record
