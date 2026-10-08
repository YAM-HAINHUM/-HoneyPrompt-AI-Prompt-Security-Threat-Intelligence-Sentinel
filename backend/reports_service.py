"""
reports_service.py — Core reporting service for HoneyPrompt Sentinel.
Queries real database data (attacks.json, users.json, conversations.json,
soc_alerts.json, soc_incidents.json, soc_audit.json, security_activity.json),
applies server-side filters, aggregates statistics, and enforces RBAC scoping.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import json
import os
import re

ATTACKS_FILE = "attacks.json"
USERS_FILE = "users.json"
CONVERSATIONS_FILE = "conversations.json"
ALERTS_FILE = "soc_alerts.json"
INCIDENTS_FILE = "soc_incidents.json"
AUDIT_FILE = "soc_audit.json"
ACTIVITY_FILE = "security_activity.json"
RISK_FILE = "soc_risk.json"

ALL_THREAT_CATEGORIES = [
    "Prompt Injection",
    "Jailbreak Attempts",
    "System Prompt Extraction",
    "Credential Extraction",
    "Data Exfiltration",
    "Role Manipulation",
    "Privilege Escalation",
    "Security Policy Bypass",
    "Harmful Requests",
    "Probing & Reconnaissance",
    "Obfuscated Payloads",
    "Other Threats",
]


def _read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _sanitize_text(value: str) -> str:
    if not value:
        return ""
    value = re.sub(r"(?i)(\b(?:api[_-]?key|password|secret|token|auth)\b\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", value)
    value = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,})\b", "[REDACTED]", value)
    return value


def _parse_date(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str[:19], fmt)
        except Exception:
            pass
    return None


def get_date_boundaries(date_range: str = "30d", date_from: str | None = None, date_to: str | None = None):
    now = datetime.now()
    dt_from = None
    dt_to = None

    if date_from:
        dt_from = _parse_date(date_from)
    if date_to:
        dt_to = _parse_date(date_to)
        if dt_to:
            dt_to = dt_to.replace(hour=23, minute=59, second=59, microsecond=999999)

    if not dt_from:
        range_lower = (date_range or "30d").lower()
        if range_lower in ("today", "1d", "24h"):
            dt_from = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif range_lower in ("7d", "7days", "week"):
            dt_from = now - timedelta(days=7)
        elif range_lower in ("30d", "30days", "month"):
            dt_from = now - timedelta(days=30)
        elif range_lower in ("90d", "90days", "quarter"):
            dt_from = now - timedelta(days=90)
        elif range_lower in ("all", "custom") and not date_from:
            dt_from = now - timedelta(days=365)
        else:
            dt_from = now - timedelta(days=30)

    if not dt_to:
        dt_to = now

    return dt_from, dt_to


def filter_logs(logs: list, filters: dict, dt_from: datetime, dt_to: datetime) -> list:
    clf_filter = (filters.get("classification") or "").upper()
    sev_filter = (filters.get("severity") or "").upper()
    threat_filter = (filters.get("threat_type") or "").strip()
    user_filter = (filters.get("user") or "").strip().casefold()
    action_filter = (filters.get("action") or "").upper()

    filtered = []
    for entry in logs:
        if entry.get("is_test"):
            continue

        ts = _parse_date(entry.get("timestamp"))
        if ts:
            if ts < dt_from or ts > dt_to:
                continue

        if clf_filter and clf_filter != "ALL":
            if entry.get("classification", "").upper() != clf_filter:
                continue

        if sev_filter and sev_filter != "ALL":
            if entry.get("severity", "").upper() != sev_filter:
                continue

        if threat_filter and threat_filter.upper() != "ALL":
            if threat_filter.casefold() not in entry.get("threat_type", "").casefold():
                continue

        if user_filter and user_filter != "all":
            if user_filter != entry.get("user", "").casefold():
                continue

        if action_filter and action_filter != "ALL":
            if entry.get("action", "").upper() != action_filter:
                continue

        filtered.append(entry)

    return filtered


# ===========================================================================
# ADMIN REPORTS
# ===========================================================================

def build_security_overview_report(filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    logs_raw = _read_json(ATTACKS_FILE, [])
    users_dict = _read_json(USERS_FILE, {})
    activity_dict = _read_json(ACTIVITY_FILE, {})
    alerts_raw = _read_json(ALERTS_FILE, [])

    logs = filter_logs(logs_raw, filters, dt_from, dt_to)

    total_prompts = len(logs)
    safe_count = sum(1 for l in logs if l.get("classification") == "SAFE")
    suspicious_count = sum(1 for l in logs if l.get("classification") == "SUSPICIOUS")
    malicious_count = sum(1 for l in logs if l.get("classification") == "MALICIOUS")
    blocked_count = sum(1 for l in logs if l.get("action") == "BLOCKED")

    confidences = [float(l.get("confidence", 0)) for l in logs if l.get("confidence") is not None]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
    max_conf = max(confidences) if confidences else 0.0
    min_conf = min(confidences) if confidences else 0.0

    block_rate = (blocked_count / total_prompts * 100) if total_prompts > 0 else 0.0

    # User statuses
    now = datetime.now()
    blocked_users_set = set()
    for username, state in activity_dict.items():
        blocked_until = state.get("blocked_until")
        if blocked_until:
            try:
                if datetime.fromisoformat(blocked_until) > now:
                    blocked_users_set.add(username.casefold())
            except Exception:
                pass

    total_users_count = len(users_dict)
    blocked_users_count = len(blocked_users_set)
    active_users_count = max(0, total_users_count - blocked_users_count)
    inactive_users_count = sum(1 for u in users_dict.values() if not u.get("is_active", True))

    # Threat & Severity breakdowns
    threat_by_type = Counter()
    for l in logs:
        if l.get("classification") != "SAFE":
            tt = l.get("threat_type") or "Unknown Threat"
            threat_by_type[tt] += 1

    severity_dist = Counter(l.get("severity", "NONE").upper() for l in logs)
    warning_events = sum(1 for l in logs if l.get("classification") == "SUSPICIOUS" or l.get("severity") in ("MEDIUM", "HIGH"))

    # Security score (100 is best, deduct for malicious prompts and critical threats)
    if total_prompts > 0:
        mal_ratio = malicious_count / total_prompts
        crit_ratio = severity_dist.get("CRITICAL", 0) / total_prompts
        score = max(10, min(100, round(100 - (mal_ratio * 50 + crit_ratio * 40))))
    else:
        score = 98

    # Daily score trend
    daily_groups = defaultdict(lambda: {"safe": 0, "suspicious": 0, "malicious": 0, "total": 0})
    for l in logs:
        ts = _parse_date(l.get("timestamp"))
        if ts:
            day_str = ts.strftime("%Y-%m-%d")
            daily_groups[day_str]["total"] += 1
            clf = l.get("classification", "SAFE")
            if clf == "SAFE":
                daily_groups[day_str]["safe"] += 1
            elif clf == "SUSPICIOUS":
                daily_groups[day_str]["suspicious"] += 1
            elif clf == "MALICIOUS":
                daily_groups[day_str]["malicious"] += 1

    trend = []
    for day in sorted(daily_groups.keys())[-14:]:
        d = daily_groups[day]
        t = d["total"]
        day_score = max(20, round(100 - (d["malicious"] / t * 60 + d["suspicious"] / t * 20))) if t > 0 else 100
        trend.append({"date": day, "score": day_score, "total": t, "malicious": d["malicious"], "safe": d["safe"]})

    # Users summary list
    user_agg = defaultdict(lambda: {"total": 0, "safe": 0, "suspicious": 0, "malicious": 0, "blocked": 0, "last_active": None})
    for l in logs:
        u = l.get("user", "Unknown")
        user_agg[u]["total"] += 1
        clf = l.get("classification", "SAFE")
        if clf == "SAFE":
            user_agg[u]["safe"] += 1
        elif clf == "SUSPICIOUS":
            user_agg[u]["suspicious"] += 1
        elif clf == "MALICIOUS":
            user_agg[u]["malicious"] += 1
        if l.get("action") == "BLOCKED":
            user_agg[u]["blocked"] += 1
        ts = l.get("timestamp")
        if not user_agg[u]["last_active"] or (ts and ts > user_agg[u]["last_active"]):
            user_agg[u]["last_active"] = ts

    users_list = []
    for username, udata in users_dict.items():
        stats = user_agg.get(username, {})
        is_blocked = username.casefold() in blocked_users_set
        mal = stats.get("malicious", 0)
        risk = min(100, mal * 25 + stats.get("suspicious", 0) * 10)
        users_list.append({
            "username": username,
            "email": udata.get("email", ""),
            "status": "BLOCKED" if is_blocked else ("ACTIVE" if udata.get("is_active", True) else "INACTIVE"),
            "total_prompts": stats.get("total", 0),
            "safe": stats.get("safe", 0),
            "suspicious": stats.get("suspicious", 0),
            "malicious": mal,
            "blocked": stats.get("blocked", 0),
            "risk_score": risk,
            "last_activity": stats.get("last_active") or udata.get("created_at"),
        })

    return {
        "report_type": "security_overview",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": total_prompts,
        "summary": {
            "total_users": total_users_count,
            "active_users": active_users_count,
            "inactive_users": inactive_users_count,
            "blocked_users": blocked_users_count,
            "total_prompts": total_prompts,
            "safe": safe_count,
            "suspicious": suspicious_count,
            "malicious": malicious_count,
            "blocked": blocked_count,
            "warning_events": warning_events,
            "block_rate": round(block_rate, 1),
            "avg_confidence": round(avg_conf, 3),
            "max_confidence": round(max_conf, 3),
            "min_confidence": round(min_conf, 3),
            "security_score": score,
            "critical": severity_dist.get("CRITICAL", 0),
            "high": severity_dist.get("HIGH", 0),
            "medium": severity_dist.get("MEDIUM", 0),
            "low": severity_dist.get("LOW", 0),
            "none": severity_dist.get("NONE", 0),
        },
        "threat_by_type": dict(threat_by_type),
        "severity_dist": dict(severity_dist),
        "score_trend": trend,
        "users": users_list,
        "recent_threats": [
            {
                "request_id": l.get("request_id"),
                "timestamp": l.get("timestamp"),
                "user": l.get("user"),
                "threat_type": l.get("threat_type"),
                "severity": l.get("severity"),
                "classification": l.get("classification"),
                "action": l.get("action"),
                "prompt_preview": _sanitize_text(l.get("prompt_preview", "")),
            }
            for l in reversed(logs) if l.get("classification") != "SAFE"
        ][:20],
    }


def build_threat_intelligence_report(filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    logs_raw = _read_json(ATTACKS_FILE, [])
    logs = filter_logs(logs_raw, filters, dt_from, dt_to)

    threat_logs = [l for l in logs if l.get("classification") != "SAFE"]

    type_stats = defaultdict(lambda: {"count": 0, "severities": Counter(), "confidences": [], "actions": Counter(), "users": set()})
    for l in threat_logs:
        tt = l.get("threat_type") or "Unclassified"
        type_stats[tt]["count"] += 1
        type_stats[tt]["severities"][l.get("severity", "MEDIUM").upper()] += 1
        type_stats[tt]["actions"][l.get("action", "ALLOWED").upper()] += 1
        type_stats[tt]["users"].add(l.get("user", "Unknown"))
        if l.get("confidence") is not None:
            type_stats[tt]["confidences"].append(float(l["confidence"]))

    threat_items = []
    for tt, s in sorted(type_stats.items(), key=lambda x: -x[1]["count"]):
        top_sev = s["severities"].most_common(1)[0][0] if s["severities"] else "MEDIUM"
        avg_c = sum(s["confidences"]) / len(s["confidences"]) if s["confidences"] else 0.85
        threat_items.append({
            "threat_type": tt,
            "count": s["count"],
            "severity": top_sev,
            "avg_confidence": round(avg_c, 3),
            "target_users_count": len(s["users"]),
            "blocked_count": s["actions"].get("BLOCKED", 0),
        })

    # Most targeted users
    user_target_counts = Counter(l.get("user", "Unknown") for l in threat_logs)

    # Hourly / daily trends
    daily_trends = defaultdict(Counter)
    for l in threat_logs:
        ts = _parse_date(l.get("timestamp"))
        if ts:
            daily_trends[ts.strftime("%Y-%m-%d")][l.get("threat_type", "Other")] += 1

    trend_series = []
    for day in sorted(daily_trends.keys())[-14:]:
        trend_series.append({
            "date": day,
            "total_attacks": sum(daily_trends[day].values()),
            "top_type": daily_trends[day].most_common(1)[0][0] if daily_trends[day] else "None",
        })

    # Recent critical threats
    crit_threats = [
        {
            "request_id": l.get("request_id"),
            "timestamp": l.get("timestamp"),
            "user": l.get("user"),
            "threat_type": l.get("threat_type"),
            "severity": l.get("severity"),
            "confidence": l.get("confidence"),
            "action": l.get("action"),
            "reason": l.get("reason"),
            "prompt_preview": _sanitize_text(l.get("prompt_preview", "")),
        }
        for l in reversed(threat_logs)
        if l.get("severity") in ("CRITICAL", "HIGH")
    ][:30]

    return {
        "report_type": "threat_intelligence",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(threat_logs),
        "total_threats": len(threat_logs),
        "threats": threat_items,
        "top_users": dict(user_target_counts.most_common(10)),
        "trends": trend_series,
        "critical_threats": crit_threats,
    }


def build_user_security_report(filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    logs_raw = _read_json(ATTACKS_FILE, [])
    users_dict = _read_json(USERS_FILE, {})
    activity_dict = _read_json(ACTIVITY_FILE, {})

    logs = filter_logs(logs_raw, filters, dt_from, dt_to)

    user_stats = defaultdict(lambda: {
        "total": 0, "safe": 0, "suspicious": 0, "malicious": 0,
        "blocked": 0, "last_activity": None, "last_threat": None,
        "last_threat_type": "None", "confidences": []
    })

    for l in logs:
        u = l.get("user", "Unknown")
        user_stats[u]["total"] += 1
        clf = l.get("classification", "SAFE")
        if clf == "SAFE":
            user_stats[u]["safe"] += 1
        elif clf == "SUSPICIOUS":
            user_stats[u]["suspicious"] += 1
        elif clf == "MALICIOUS":
            user_stats[u]["malicious"] += 1
        if l.get("action") == "BLOCKED":
            user_stats[u]["blocked"] += 1

        ts = l.get("timestamp")
        if not user_stats[u]["last_activity"] or (ts and ts > user_stats[u]["last_activity"]):
            user_stats[u]["last_activity"] = ts

        if clf != "SAFE":
            if not user_stats[u]["last_threat"] or (ts and ts > user_stats[u]["last_threat"]):
                user_stats[u]["last_threat"] = ts
                user_stats[u]["last_threat_type"] = l.get("threat_type", "Threat")

        if l.get("confidence") is not None:
            user_stats[u]["confidences"].append(float(l["confidence"]))

    now = datetime.now()
    user_rows = []
    user_filter = (filters.get("user") or "").strip().casefold()

    for username, udata in users_dict.items():
        if user_filter and user_filter != "all" and user_filter != username.casefold():
            continue

        s = user_stats.get(username, {})
        act_state = activity_dict.get(username, {})
        consec = act_state.get("consecutive_count", 0)
        blocked_until = act_state.get("blocked_until")

        is_blocked = False
        if blocked_until:
            try:
                is_blocked = datetime.fromisoformat(blocked_until) > now
            except Exception:
                pass

        mal = s.get("malicious", 0)
        susp = s.get("suspicious", 0)
        risk_score = min(100, mal * 25 + susp * 10 + consec * 15)

        if is_blocked:
            acc_status = "BLOCKED"
        elif not udata.get("is_active", True):
            acc_status = "INACTIVE"
        elif consec >= 2 or risk_score >= 50:
            acc_status = "RESTRICTED"
        else:
            acc_status = "ACTIVE"

        user_rows.append({
            "user_id": udata.get("id", username),
            "username": username,
            "email": udata.get("email", ""),
            "role": udata.get("role", "user"),
            "status": acc_status,
            "total_prompts": s.get("total", 0),
            "safe": s.get("safe", 0),
            "suspicious": susp,
            "malicious": mal,
            "blocked": s.get("blocked", 0),
            "consecutive_malicious": consec,
            "risk_score": risk_score,
            "current_restrictions": f"Blocked until {blocked_until[:16]}" if is_blocked else ("Elevated Monitored" if consec > 0 else "Normal"),
            "last_activity": s.get("last_activity") or udata.get("created_at"),
            "last_threat": s.get("last_threat") or "None",
            "last_threat_type": s.get("last_threat_type", "None"),
            "created_at": udata.get("created_at", "—"),
        })

    user_rows.sort(key=lambda x: -x["risk_score"])

    return {
        "report_type": "user_security",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(user_rows),
        "users": user_rows,
        "risk_summary": {
            "critical_risk": sum(1 for u in user_rows if u["risk_score"] >= 75),
            "high_risk": sum(1 for u in user_rows if 50 <= u["risk_score"] < 75),
            "medium_risk": sum(1 for u in user_rows if 25 <= u["risk_score"] < 50),
            "low_risk": sum(1 for u in user_rows if u["risk_score"] < 25),
        },
    }


def build_audit_log_report(filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    raw_audit = _read_json(AUDIT_FILE, [])
    action_filter = (filters.get("action") or "").strip().casefold()
    user_filter = (filters.get("user") or "").strip().casefold()

    filtered = []
    for a in raw_audit:
        ts = _parse_date(a.get("timestamp"))
        if ts and (ts < dt_from or ts > dt_to):
            continue

        if action_filter and action_filter != "all":
            if action_filter not in a.get("action", "").casefold():
                continue

        if user_filter and user_filter != "all":
            admin_match = user_filter == a.get("admin", "").casefold()
            target_match = user_filter == a.get("target", "").casefold()
            if not (admin_match or target_match):
                continue

        filtered.append({
            "audit_id": a.get("audit_id", "—"),
            "timestamp": a.get("timestamp"),
            "admin": a.get("admin", "SYSTEM"),
            "action": a.get("action", "—"),
            "target": a.get("target", "—"),
            "threat": a.get("threat", "—"),
            "severity": a.get("severity", "NONE"),
            "result": a.get("result", "SUCCESS"),
            "reason": _sanitize_text(a.get("reason", "")),
            "request_id": a.get("request_id", "—"),
            "session_id": a.get("session_id", "—"),
        })

    filtered.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    action_counts = Counter(l.get("action", "Other") for l in filtered)

    return {
        "report_type": "audit_log",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(filtered),
        "logs": filtered,
        "action_breakdown": dict(action_counts),
    }


def build_incidents_report(filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    raw_incidents = _read_json(INCIDENTS_FILE, [])
    status_filter = (filters.get("status") or "").upper()
    sev_filter = (filters.get("severity") or "").upper()

    filtered = []
    for inc in raw_incidents:
        ts = _parse_date(inc.get("created_at"))
        if ts and (ts < dt_from or ts > dt_to):
            continue

        if status_filter and status_filter != "ALL":
            if inc.get("status", "").upper() != status_filter:
                continue

        if sev_filter and sev_filter != "ALL":
            if inc.get("severity", "").upper() != sev_filter:
                continue

        res_time = None
        if inc.get("resolved_at") and inc.get("created_at"):
            c_ts = _parse_date(inc.get("created_at"))
            r_ts = _parse_date(inc.get("resolved_at"))
            if c_ts and r_ts:
                res_time = round((r_ts - c_ts).total_seconds() / 60, 1)

        filtered.append({
            "incident_id": inc.get("incident_id"),
            "created_at": inc.get("created_at"),
            "title": inc.get("title", "—"),
            "user": inc.get("user", inc.get("target_user", "Multiple")),
            "threat": inc.get("threat_type", inc.get("title", "Threat Incident")),
            "severity": inc.get("severity", "HIGH"),
            "status": inc.get("status", "OPEN"),
            "description": inc.get("description", ""),
            "created_by": inc.get("created_by", "Admin"),
            "assigned_admin": inc.get("assigned_admin", inc.get("created_by", "Security Team")),
            "actions_taken": inc.get("actions_taken", "Incident response executed"),
            "resolution": inc.get("resolution", "Under investigation" if inc.get("status") != "RESOLVED" else "Threat mitigated"),
            "resolved_at": inc.get("resolved_at"),
            "resolution_time_minutes": res_time,
        })

    filtered.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    status_counts = Counter(i.get("status", "OPEN") for i in filtered)
    sev_counts = Counter(i.get("severity", "HIGH") for i in filtered)

    return {
        "report_type": "incidents",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(filtered),
        "incidents": filtered,
        "status_summary": dict(status_counts),
        "severity_summary": dict(sev_counts),
    }


def build_chat_activity_report(filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    conv_store = _read_json(CONVERSATIONS_FILE, {"conversations": [], "messages": []})
    logs_raw = _read_json(ATTACKS_FILE, [])

    user_filter = (filters.get("user") or "").strip().casefold()

    convs = conv_store.get("conversations", [])
    msgs = conv_store.get("messages", [])

    if user_filter and user_filter != "all":
        convs = [c for c in convs if c.get("user_id", "").casefold() == user_filter]
        allowed_cids = {c["conversation_id"] for c in convs}
        msgs = [m for m in msgs if m.get("conversation_id") in allowed_cids]

    logs = filter_logs(logs_raw, filters, dt_from, dt_to)

    threat_count = sum(1 for l in logs if l.get("classification") != "SAFE")
    blocked_count = sum(1 for l in logs if l.get("action") == "BLOCKED")
    suspicious_count = sum(1 for l in logs if l.get("classification") == "SUSPICIOUS")

    # Conversation stats
    total_convs = len(convs)
    total_msgs = len(msgs)

    # Activity by user
    user_msgs = Counter(c.get("user_id", "unknown") for c in convs)

    return {
        "report_type": "chat_activity",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": total_convs + total_msgs,
        "summary": {
            "total_conversations": total_convs,
            "total_messages": total_msgs,
            "threat_detections": threat_count,
            "blocked_messages": blocked_count,
            "suspicious_messages": suspicious_count,
            "active_chat_users": len(user_msgs),
        },
        "conversations": [
            {
                "conversation_id": c.get("conversation_id"),
                "user": c.get("user_id"),
                "title": c.get("title"),
                "created_at": c.get("created_at"),
                "updated_at": c.get("updated_at"),
            }
            for c in convs[:50]
        ],
    }


# ===========================================================================
# USER REPORTS (STRICTLY SCOPED TO AUTHENTICATED USER)
# ===========================================================================

def build_personal_security_report(username: str, filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    user_filters = {**filters, "user": username}
    logs_raw = _read_json(ATTACKS_FILE, [])
    activity_dict = _read_json(ACTIVITY_FILE, {})
    users_dict = _read_json(USERS_FILE, {})

    logs = filter_logs(logs_raw, user_filters, dt_from, dt_to)

    total_prompts = len(logs)
    safe_count = sum(1 for l in logs if l.get("classification") == "SAFE")
    suspicious_count = sum(1 for l in logs if l.get("classification") == "SUSPICIOUS")
    malicious_count = sum(1 for l in logs if l.get("classification") == "MALICIOUS")
    blocked_count = sum(1 for l in logs if l.get("action") == "BLOCKED")

    confidences = [float(l.get("confidence", 0)) for l in logs if l.get("confidence") is not None]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    # User activity & restrictions
    act_state = activity_dict.get(username, {})
    consec = act_state.get("consecutive_count", 0)
    blocked_until = act_state.get("blocked_until")

    now = datetime.now()
    is_blocked = False
    if blocked_until:
        try:
            is_blocked = datetime.fromisoformat(blocked_until) > now
        except Exception:
            pass

    risk_score = min(100, malicious_count * 25 + suspicious_count * 10 + consec * 15)
    sec_score = max(10, 100 - risk_score)

    threat_cats = Counter()
    for l in logs:
        if l.get("classification") != "SAFE":
            threat_cats[l.get("threat_type", "General Threat")] += 1

    # Daily trend
    daily = defaultdict(lambda: {"safe": 0, "suspicious": 0, "malicious": 0, "total": 0})
    for l in logs:
        ts = _parse_date(l.get("timestamp"))
        if ts:
            d_str = ts.strftime("%Y-%m-%d")
            daily[d_str]["total"] += 1
            clf = l.get("classification", "SAFE")
            if clf == "SAFE":
                daily[d_str]["safe"] += 1
            elif clf == "SUSPICIOUS":
                daily[d_str]["suspicious"] += 1
            elif clf == "MALICIOUS":
                daily[d_str]["malicious"] += 1

    trend = [
        {"date": day, **daily[day]}
        for day in sorted(daily.keys())[-14:]
    ]

    return {
        "report_type": "personal_security",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": {"date_range": filters.get("date_range", "30d")},
        "record_count": total_prompts,
        "summary": {
            "username": username,
            "status": "BLOCKED" if is_blocked else ("RESTRICTED" if consec > 0 else "ACTIVE"),
            "total_prompts": total_prompts,
            "safe": safe_count,
            "suspicious": suspicious_count,
            "malicious": malicious_count,
            "blocked": blocked_count,
            "avg_confidence": round(avg_conf, 3),
            "risk_score": risk_score,
            "security_score": sec_score,
            "current_restrictions": f"Chat access blocked until {blocked_until[:16]}" if is_blocked else "Full chat permissions active",
            "consecutive_malicious": consec,
        },
        "threat_categories": dict(threat_cats),
        "activity_trend": trend,
        "recent_events": [
            {
                "request_id": l.get("request_id"),
                "timestamp": l.get("timestamp"),
                "classification": l.get("classification"),
                "threat_type": l.get("threat_type"),
                "severity": l.get("severity"),
                "action": l.get("action"),
                "prompt_preview": _sanitize_text(l.get("prompt_preview", "")),
            }
            for l in reversed(logs)
        ][:15],
    }


def build_user_security_history_report(username: str, filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    user_filters = {**filters, "user": username}
    logs_raw = _read_json(ATTACKS_FILE, [])
    logs = filter_logs(logs_raw, user_filters, dt_from, dt_to)

    history_items = [
        {
            "request_id": l.get("request_id"),
            "timestamp": l.get("timestamp"),
            "prompt_preview": _sanitize_text(l.get("prompt_preview", "")),
            "classification": l.get("classification", "SAFE"),
            "threat_type": l.get("threat_type", "Normal Query"),
            "severity": l.get("severity", "NONE"),
            "confidence": l.get("confidence", 0.0),
            "action": l.get("action", "ALLOWED"),
            "reason": _sanitize_text(l.get("reason", "")),
        }
        for l in reversed(logs)
    ]

    return {
        "report_type": "security_history",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(history_items),
        "history": history_items,
    }


def build_user_chat_activity_report(username: str, filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    conv_store = _read_json(CONVERSATIONS_FILE, {"conversations": [], "messages": []})
    logs_raw = _read_json(ATTACKS_FILE, [])

    uid = username.casefold()
    convs = [c for c in conv_store.get("conversations", []) if c.get("user_id", "").casefold() == uid]
    cids = {c["conversation_id"] for c in convs}
    msgs = [m for m in conv_store.get("messages", []) if m.get("conversation_id") in cids]

    user_logs = filter_logs(logs_raw, {"user": username}, dt_from, dt_to)
    threats = sum(1 for l in user_logs if l.get("classification") != "SAFE")
    blocked = sum(1 for l in user_logs if l.get("action") == "BLOCKED")
    suspicious = sum(1 for l in user_logs if l.get("classification") == "SUSPICIOUS")

    return {
        "report_type": "my_chat_activity",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(convs) + len(msgs),
        "summary": {
            "username": username,
            "total_conversations": len(convs),
            "total_messages": len(msgs),
            "threat_detections": threats,
            "blocked_messages": blocked,
            "suspicious_messages": suspicious,
        },
        "conversations": [
            {
                "conversation_id": c.get("conversation_id"),
                "title": c.get("title"),
                "created_at": c.get("created_at"),
                "updated_at": c.get("updated_at"),
            }
            for c in convs[:30]
        ],
    }


def build_user_alerts_report(username: str, filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    alerts_raw = _read_json(ALERTS_FILE, [])
    sev_filter = (filters.get("severity") or "").upper()
    uid = username.casefold()

    user_alerts = []
    for a in alerts_raw:
        if a.get("user", "").casefold() != uid:
            continue
        if a.get("is_test"):
            continue

        ts = _parse_date(a.get("timestamp"))
        if ts and (ts < dt_from or ts > dt_to):
            continue

        if sev_filter and sev_filter != "ALL":
            if a.get("severity", "").upper() != sev_filter:
                continue

        user_alerts.append({
            "alert_id": a.get("alert_id"),
            "timestamp": a.get("timestamp"),
            "threat_type": a.get("threat_type", "Security Alert"),
            "severity": a.get("severity", "MEDIUM"),
            "classification": a.get("classification", "SUSPICIOUS"),
            "action": a.get("action", "MONITORED"),
            "description": _sanitize_text(a.get("reason", a.get("prompt_preview", ""))),
            "status": a.get("status", "NEW"),
        })

    user_alerts.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    return {
        "report_type": "security_alerts",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(user_alerts),
        "alerts": user_alerts,
    }


def build_user_chats_report(filters: dict) -> dict:
    dt_from, dt_to = get_date_boundaries(
        filters.get("date_range", "30d"),
        filters.get("date_from"),
        filters.get("date_to"),
    )
    logs_raw = _read_json(ATTACKS_FILE, [])
    conv_store = _read_json(CONVERSATIONS_FILE, {})
    users_dict = _read_json(USERS_FILE, {})

    target_user = (filters.get("user") or "").strip().casefold()
    logs = filter_logs(logs_raw, filters, dt_from, dt_to)

    convs = conv_store.get("conversations", [])
    msgs = conv_store.get("messages", [])

    if target_user:
        convs = [c for c in convs if c.get("user_id", "").casefold() == target_user]
        cids = {c["conversation_id"] for c in convs}
        msgs = [m for m in msgs if m.get("conversation_id") in cids]

    formatted_msgs = [
        {
            "request_id": m.get("message_id") or m.get("id"),
            "conversation_id": m.get("conversation_id"),
            "timestamp": m.get("timestamp"),
            "user": m.get("user") or target_user or "User",
            "prompt": _sanitize_text(m.get("prompt") or m.get("message") or ""),
            "response": _sanitize_text(m.get("response") or m.get("ai_response") or ""),
            "classification": m.get("classification", "SAFE"),
            "threat_type": m.get("threat_type", "Normal Query"),
            "severity": m.get("severity", "NONE"),
            "confidence": float(m.get("confidence", 0.0)),
            "risk_score": int(m.get("risk_score", 0)),
            "action": m.get("action", "ALLOWED"),
            "reason": _sanitize_text(m.get("reason", "")),
        }
        for m in msgs
    ]
    formatted_msgs.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    total_prompts = len(logs)
    malicious = sum(1 for l in logs if l.get("classification") == "MALICIOUS")
    suspicious = sum(1 for l in logs if l.get("classification") == "SUSPICIOUS")
    safe = sum(1 for l in logs if l.get("classification") == "SAFE")
    blocked = sum(1 for l in logs if l.get("action") == "BLOCKED")

    return {
        "report_type": "user_chats",
        "generated_at": datetime.now().isoformat(),
        "date_from": dt_from.strftime("%Y-%m-%d"),
        "date_to": dt_to.strftime("%Y-%m-%d"),
        "filters": filters,
        "record_count": len(formatted_msgs),
        "summary": {
            "target_user": target_user or "All Users",
            "total_conversations": len(convs),
            "total_messages": len(formatted_msgs),
            "total_prompts": total_prompts,
            "safe": safe,
            "suspicious": suspicious,
            "malicious": malicious,
            "blocked": blocked,
        },
        "conversations": [
            {
                "conversation_id": c.get("conversation_id"),
                "user": c.get("user_id"),
                "title": c.get("title"),
                "created_at": c.get("created_at"),
                "updated_at": c.get("updated_at"),
            }
            for c in convs[:50]
        ],
        "messages": formatted_msgs[:100],
    }
