"""
soc_store.py — HoneyPrompt Security Operations Center data layer.

Manages:
  - Security alerts (with lifecycle: NEW → INVESTIGATING → RESOLVED → DISMISSED)
  - Incidents
  - Admin audit log (immutable append-only)
  - Security policies (extended from escalation settings)
  - User risk scores
  - Test events (flagged separately so they don't pollute analytics)
"""

import json
import os
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta

ALERTS_FILE = "soc_alerts.json"
INCIDENTS_FILE = "soc_incidents.json"
AUDIT_FILE = "soc_audit.json"
POLICIES_FILE = "soc_policies.json"
RISK_FILE = "soc_risk.json"

DEFAULT_POLICIES = {
    "warning_threshold": 3,
    "block_threshold": 5,
    "block_cooldown_minutes": 30,
    "suspicious_ml_threshold": 0.80,
    "malicious_ml_threshold": 0.9625,
    "alert_severity_threshold": "MEDIUM",
    "rate_limit_chat_per_minute": 20,
    "rate_limit_auth_per_minute": 10,
    "session_timeout_minutes": 60,
    "auto_block_on_critical": True,
    "auto_alert_on_repeated": True,
    "repeated_attack_window_minutes": 30,
    "repeated_attack_count": 3,
}

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ---------------------------------------------------------------------------
# Generic file helpers
# ---------------------------------------------------------------------------

def _read(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _read_dict(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Security Policies
# ---------------------------------------------------------------------------

def get_policies() -> dict:
    stored = _read_dict(POLICIES_FILE)
    return {**DEFAULT_POLICIES, **stored}


def update_policies(updates: dict) -> dict:
    current = get_policies()
    current.update(updates)
    _write(POLICIES_FILE, current)
    return current


# ---------------------------------------------------------------------------
# Admin Audit Log (append-only)
# ---------------------------------------------------------------------------

def audit_log(admin: str, action: str, target: str = "", reason: str = "", extra: dict | None = None) -> dict:
    entry = {
        "audit_id": str(uuid.uuid4())[:12].upper(),
        "timestamp": datetime.now().isoformat(),
        "admin": admin,
        "action": action,
        "target": target,
        "reason": reason[:500] if reason else "",
    }
    if extra:
        entry.update(extra)
    logs = _read(AUDIT_FILE)
    logs.append(entry)
    _write(AUDIT_FILE, logs)
    return entry


def get_audit_logs(page: int = 1, page_size: int = 50, action_filter: str = "") -> dict:
    logs = list(reversed(_read(AUDIT_FILE)))
    if action_filter:
        logs = [l for l in logs if action_filter.casefold() in l.get("action", "").casefold()]
    total = len(logs)
    offset = (page - 1) * page_size
    return {"items": logs[offset: offset + page_size], "total": total, "page": page, "page_size": page_size}


# ---------------------------------------------------------------------------
# Security Alerts
# ---------------------------------------------------------------------------

def _read_alerts():
    return _read(ALERTS_FILE)


def _write_alerts(alerts):
    _write(ALERTS_FILE, alerts)


def create_alert(
    user: str,
    threat_type: str,
    severity: str,
    confidence: float,
    risk_score: int,
    action: str,
    prompt_preview: str,
    reason: str,
    request_id: str,
    session_id: str = "",
    categories: list | None = None,
    is_test: bool = False,
) -> dict:
    alert = {
        "alert_id": "ALT-" + str(uuid.uuid4())[:8].upper(),
        "request_id": request_id,
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "threat_type": threat_type,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "action": action,
        "prompt_preview": prompt_preview[:200],
        "reason": reason[:500],
        "session_id": session_id,
        "categories": categories or [],
        "status": "NEW",
        "is_test": is_test,
        "notes": [],
    }
    alerts = _read_alerts()
    alerts.append(alert)
    _write_alerts(alerts)
    return alert


def get_alerts(
    page: int = 1,
    page_size: int = 50,
    severity_filter: str = "",
    status_filter: str = "",
    user_filter: str = "",
    exclude_test: bool = True,
) -> dict:
    alerts = list(reversed(_read_alerts()))
    if exclude_test:
        alerts = [a for a in alerts if not a.get("is_test")]
    if severity_filter:
        alerts = [a for a in alerts if a.get("severity", "").upper() == severity_filter.upper()]
    if status_filter:
        alerts = [a for a in alerts if a.get("status", "").upper() == status_filter.upper()]
    if user_filter:
        alerts = [a for a in alerts if user_filter.casefold() in a.get("user", "").casefold()]
    total = len(alerts)
    offset = (page - 1) * page_size
    return {"items": alerts[offset: offset + page_size], "total": total, "page": page, "page_size": page_size}


def update_alert_status(alert_id: str, status: str, admin: str, note: str = "") -> dict | None:
    valid = {"NEW", "INVESTIGATING", "RESOLVED", "DISMISSED"}
    if status.upper() not in valid:
        return None
    alerts = _read_alerts()
    for a in alerts:
        if a["alert_id"] == alert_id:
            a["status"] = status.upper()
            a["updated_at"] = datetime.now().isoformat()
            a["updated_by"] = admin
            if note:
                a["notes"].append({"ts": datetime.now().isoformat(), "admin": admin, "note": note[:500]})
            _write_alerts(alerts)
            return a
    return None


def get_alert_stats(hours: int = 24) -> dict:
    alerts = [a for a in _read_alerts() if not a.get("is_test")]
    cutoff = datetime.now() - timedelta(hours=hours)
    recent = [a for a in alerts if datetime.fromisoformat(a["timestamp"]) >= cutoff]
    sev_dist = Counter(a.get("severity", "NONE") for a in recent)
    type_dist = Counter(a.get("threat_type", "Unknown") for a in recent)
    return {
        "total": len(recent),
        "by_severity": dict(sev_dist),
        "by_type": dict(type_dist),
        "new": sum(1 for a in recent if a.get("status") == "NEW"),
        "critical": sum(1 for a in recent if a.get("severity") == "CRITICAL"),
    }


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def create_incident(
    admin: str,
    title: str,
    severity: str,
    description: str,
    related_alert_ids: list | None = None,
) -> dict:
    incident = {
        "incident_id": "INC-" + str(uuid.uuid4())[:8].upper(),
        "created_at": datetime.now().isoformat(),
        "created_by": admin,
        "title": title[:200],
        "severity": severity,
        "description": description[:2000],
        "status": "OPEN",
        "related_alerts": related_alert_ids or [],
        "notes": [],
        "updated_at": None,
        "resolved_at": None,
    }
    incidents = _read(INCIDENTS_FILE)
    incidents.append(incident)
    _write(INCIDENTS_FILE, incidents)
    return incident


def get_incidents(page: int = 1, page_size: int = 50, status_filter: str = "") -> dict:
    incidents = list(reversed(_read(INCIDENTS_FILE)))
    if status_filter:
        incidents = [i for i in incidents if i.get("status", "").upper() == status_filter.upper()]
    total = len(incidents)
    offset = (page - 1) * page_size
    return {"items": incidents[offset: offset + page_size], "total": total, "page": page, "page_size": page_size}


def update_incident(incident_id: str, admin: str, updates: dict) -> dict | None:
    incidents = _read(INCIDENTS_FILE)
    for inc in incidents:
        if inc["incident_id"] == incident_id:
            allowed = {"title", "severity", "description", "status"}
            for k, v in updates.items():
                if k in allowed:
                    inc[k] = v
            if updates.get("status") == "RESOLVED" and not inc.get("resolved_at"):
                inc["resolved_at"] = datetime.now().isoformat()
            if "note" in updates and updates["note"]:
                inc["notes"].append({"ts": datetime.now().isoformat(), "admin": admin, "note": updates["note"][:500]})
            inc["updated_at"] = datetime.now().isoformat()
            inc["updated_by"] = admin
            _write(INCIDENTS_FILE, incidents)
            return inc
    return None


# ---------------------------------------------------------------------------
# User Risk Scores
# ---------------------------------------------------------------------------

def _read_risk() -> dict:
    return _read_dict(RISK_FILE)


def _write_risk(data: dict):
    _write(RISK_FILE, data)


def update_user_risk(username: str, analysis: dict, is_malicious: bool) -> dict:
    key = username.casefold()
    data = _read_risk()
    rec = data.get(key, {
        "username": username,
        "risk_score": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "consecutive_attacks": 0,
        "last_threat": None,
        "last_threat_type": None,
        "last_activity": None,
        "total_prompts": 0,
    })
    rec["total_prompts"] = rec.get("total_prompts", 0) + 1
    rec["last_activity"] = datetime.now().isoformat()
    if is_malicious:
        rec["malicious_count"] = rec.get("malicious_count", 0) + 1
        rec["consecutive_attacks"] = rec.get("consecutive_attacks", 0) + 1
        rec["last_threat"] = datetime.now().isoformat()
        rec["last_threat_type"] = analysis.get("threat_type", "Unknown")
    elif analysis.get("classification") == "SUSPICIOUS":
        rec["suspicious_count"] = rec.get("suspicious_count", 0) + 1
        rec["consecutive_attacks"] = max(0, rec.get("consecutive_attacks", 0))
    else:
        rec["consecutive_attacks"] = 0

    # Risk score formula: weighted combination
    mal = rec.get("malicious_count", 0)
    sus = rec.get("suspicious_count", 0)
    consec = rec.get("consecutive_attacks", 0)
    total = max(1, rec.get("total_prompts", 1))
    score = min(100, int(
        (mal / total) * 60 +
        (sus / total) * 15 +
        min(consec, 10) * 2.5
    ))
    rec["risk_score"] = score
    rec["risk_level"] = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    data[key] = rec
    _write_risk(data)
    return rec


def get_user_risk(username: str) -> dict:
    key = username.casefold()
    data = _read_risk()
    return data.get(key, {
        "username": username,
        "risk_score": 0,
        "risk_level": "LOW",
        "malicious_count": 0,
        "suspicious_count": 0,
        "consecutive_attacks": 0,
        "last_threat": None,
        "last_threat_type": None,
        "last_activity": None,
        "total_prompts": 0,
    })


def get_all_user_risks() -> list:
    data = _read_risk()
    return sorted(data.values(), key=lambda r: r.get("risk_score", 0), reverse=True)


def reset_user_risk(username: str) -> dict:
    key = username.casefold()
    data = _read_risk()
    if key in data:
        data[key]["risk_score"] = 0
        data[key]["risk_level"] = "LOW"
        data[key]["malicious_count"] = 0
        data[key]["suspicious_count"] = 0
        data[key]["consecutive_attacks"] = 0
        data[key]["last_threat"] = None
        _write_risk(data)
        return data[key]
    return get_user_risk(username)


# ---------------------------------------------------------------------------
# Threat Intelligence Analytics
# ---------------------------------------------------------------------------

def get_threat_intelligence(hours: int = 24) -> dict:
    from logger import _read_logs
    logs = [l for l in _read_logs() if not l.get("is_test")]
    cutoff = datetime.now() - timedelta(hours=hours)

    def in_window(entry):
        try:
            return datetime.fromisoformat(entry["timestamp"]) >= cutoff
        except Exception:
            return False

    recent = [l for l in logs if in_window(l)]
    total = len(recent)
    malicious = [l for l in recent if l.get("classification") == "MALICIOUS"]
    suspicious = [l for l in recent if l.get("classification") == "SUSPICIOUS"]
    safe = [l for l in recent if l.get("classification") == "SAFE"]

    attack_types = Counter(l.get("threat_type", "Unknown") for l in malicious)
    severity_dist = Counter(l.get("severity", "NONE") for l in recent)
    user_attacks = Counter(l.get("user", "unknown") for l in malicious)
    fp_count = sum(1 for l in recent if l.get("false_positive_report"))

    # Hourly trend (last 24 buckets)
    hourly = defaultdict(lambda: {"safe": 0, "suspicious": 0, "malicious": 0})
    for l in recent:
        try:
            hour_key = datetime.fromisoformat(l["timestamp"]).strftime("%Y-%m-%dT%H:00")
            hourly[hour_key][l.get("classification", "SAFE").lower()] += 1
        except Exception:
            pass

    return {
        "window_hours": hours,
        "total": total,
        "safe": len(safe),
        "suspicious": len(suspicious),
        "malicious": len(malicious),
        "blocked": sum(1 for l in recent if l.get("action") == "BLOCKED"),
        "block_rate": round(len(malicious) / max(1, total), 4),
        "false_positive_rate": round(fp_count / max(1, len(malicious)), 4),
        "top_attack_types": dict(attack_types.most_common(10)),
        "severity_distribution": dict(severity_dist),
        "top_targeted_users": dict(user_attacks.most_common(10)),
        "hourly_trend": dict(sorted(hourly.items())),
    }


# ---------------------------------------------------------------------------
# Attack Pattern Detection
# ---------------------------------------------------------------------------

def detect_repeated_patterns(username: str, window_minutes: int = 30, threshold: int = 3) -> dict | None:
    """Detect if a user has submitted multiple related malicious prompts recently."""
    from logger import _read_logs
    cutoff = datetime.now() - timedelta(minutes=window_minutes)
    user_logs = [
        l for l in _read_logs()
        if l.get("user", "").casefold() == username.casefold()
        and l.get("classification") == "MALICIOUS"
        and not l.get("is_test")
    ]
    recent = []
    for l in user_logs:
        try:
            if datetime.fromisoformat(l["timestamp"]) >= cutoff:
                recent.append(l)
        except Exception:
            pass

    if len(recent) < threshold:
        return None

    type_counts = Counter(l.get("threat_type", "Unknown") for l in recent)
    dominant_type, dominant_count = type_counts.most_common(1)[0]
    return {
        "username": username,
        "attack_count": len(recent),
        "dominant_threat_type": dominant_type,
        "dominant_count": dominant_count,
        "window_minutes": window_minutes,
        "detected_at": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# Model monitoring info (reads training_report.json)
# ---------------------------------------------------------------------------

def get_model_info() -> dict:
    report_path = os.path.join(os.path.dirname(__file__), "models", "training_report.json")
    if not os.path.exists(report_path):
        return {"error": "Training report not found"}
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        tm = report.get("test_metrics", {})
        return {
            "model": report.get("training_configuration", {}).get("model", "Unknown"),
            "model_version": 2,
            "dataset_files": report.get("dataset_files", []),
            "clean_rows": report.get("clean_rows", 0),
            "class_distribution": report.get("clean_class_distribution", {}),
            "split_sizes": report.get("split_sizes", {}),
            "accuracy": tm.get("accuracy"),
            "precision": tm.get("precision"),
            "recall": tm.get("recall"),
            "f1": tm.get("f1"),
            "roc_auc": tm.get("roc_auc"),
            "false_positive_rate": tm.get("false_positive_rate"),
            "false_negative_rate": tm.get("false_negative_rate"),
            "confusion_matrix": tm.get("confusion_matrix"),
            "confusion_matrix_labels": tm.get("confusion_matrix_labels"),
            "per_class": tm.get("per_class"),
            "false_positives_count": len(tm.get("false_positives", [])),
            "false_negatives_count": len(tm.get("false_negatives", [])),
            "operating_thresholds": report.get("operating_thresholds", {}),
            "challenge_set": report.get("unseen_challenge_set", {}),
            "attack_type_classifier": report.get("attack_type_classifier"),
        }
    except Exception as e:
        return {"error": str(e)}
