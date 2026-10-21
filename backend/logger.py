import json
import os
import uuid
from datetime import datetime
from storage_paths import data_file, read_json, write_json

LOG_FILE = data_file("attacks.json")


def log_event(
    user_message: str,
    analysis: dict,
    ai_response: str,
    session_id: str = "default-session",
    user: str = "Admin_01",
    extra_fields: dict | None = None,
    request_id: str | None = None,
    timestamp: str | None = None,
):
    """Logs every request (safe, suspicious, or malicious) to attacks.json."""
    classification = analysis.get("classification") or "SAFE"
    threat_type_raw = analysis.get("threat_type")
    threat_type = str(threat_type_raw) if threat_type_raw and str(threat_type_raw) not in ("None", "none", "") else ("Normal Query" if classification == "SAFE" else "Unknown Threat")
    entry = {
        "request_id": request_id or str(uuid.uuid4())[:8].upper(),
        "timestamp": timestamp or datetime.now().isoformat(),
        "user": user,
        "user_id": user,
        "session_id": session_id,
        "prompt_preview": user_message[:120] + ("..." if len(user_message) > 120 else ""),
        "classification": classification,
        "threat_type": threat_type,
        "severity": analysis.get("severity") or "NONE",
        "risk_score": analysis.get("risk_score") or 0,
        "confidence": analysis.get("confidence") or 0.0,
        "action": analysis.get("action") or "ALLOWED",
        "reason": analysis.get("reason") or "",
        "categories": analysis.get("categories") or [],
        "llm_status": "BYPASSED" if analysis.get("action") == "BLOCKED" else "CALLED",
        "response_preview": ai_response[:80] + ("..." if len(ai_response) > 80 else ""),
    }
    if extra_fields:
        entry.update(extra_fields)
    entry.setdefault("conversation_id", session_id)

    logs = _read_logs()
    logs.append(entry)
    _write_logs(logs)
    return entry


# Keep old name for backward compatibility
def log_threat(user_message: str, analysis: dict, ai_response: str):
    log_event(user_message, analysis, ai_response)


def get_logs():
    return _read_logs()


def get_stats():
    all_logs = _read_logs()
    logs = [l for l in all_logs if not l.get("is_test")]
    total = len(logs)
    safe = sum(1 for l in logs if l.get("classification") == "SAFE")
    suspicious = sum(1 for l in logs if l.get("classification") == "SUSPICIOUS")
    malicious = sum(1 for l in logs if l.get("classification") == "MALICIOUS")
    blocked = sum(1 for l in logs if l.get("action") == "BLOCKED")
    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious,
        "blocked": blocked,
        "critical": sum(1 for l in logs if l.get("severity") == "CRITICAL"),
        "high": sum(1 for l in logs if l.get("severity") == "HIGH"),
        "medium": sum(1 for l in logs if l.get("severity") == "MEDIUM"),
    }


def mark_false_positive(request_id: str, username: str, reason: str = ""):
    logs = _read_logs()
    for entry in logs:
        if entry.get("request_id") == request_id and entry.get("user", "").casefold() == username.casefold():
            if entry.get("classification") == "SAFE":
                return None
            entry["false_positive_report"] = {
                "reported_at": datetime.now().isoformat(),
                "reason": reason.strip()[:500],
            }
            _write_logs(logs)
            return entry
    return None


def get_user_alerts(username: str, limit: int = 20):
    owner = username.casefold()
    alerts = [
        entry for entry in reversed(_read_logs())
        if entry.get("user", "").casefold() == owner
        and entry.get("classification") != "SAFE"
        and not entry.get("is_test")
    ][:limit]
    result = []
    for entry in alerts:
        row = {key: value for key, value in entry.items() if key != "read_by"}
        # Normalise legacy "None" string stored by old logger
        if row.get("threat_type") in ("None", "none", None, ""):
            row["threat_type"] = "Unknown Threat"
        row["is_read"] = owner in [name.casefold() for name in entry.get("read_by", [])]
        result.append(row)
    return result


def mark_alert_read(request_id: str, username: str):
    owner = username.casefold()
    logs = _read_logs()
    for entry in logs:
        if (
            entry.get("request_id") == request_id
            and entry.get("user", "").casefold() == owner
            and entry.get("classification") != "SAFE"
        ):
            read_by = entry.setdefault("read_by", [])
            if owner not in [name.casefold() for name in read_by]:
                read_by.append(owner)
                _write_logs(logs)
            return entry
    return None


def _read_logs():
    return read_json(LOG_FILE, [])


def _write_logs(logs):
    write_json(LOG_FILE, logs)
