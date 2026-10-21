"""
conversation_risk.py — Per-conversation security context for HoneyPrompt.

Tracks risk progression, intent history, and escalation level across the
full conversation so that a single ambiguous message does not trigger a
block, but a conversation that gradually develops malicious intent does.

Escalation levels:
  0 = SAFE        — no threat signals
  1 = SUSPICIOUS  — potential harmful intent developing
  2 = HIGH_RISK   — repeated suspicious / increasingly clear harmful intent
  3 = MALICIOUS   — intent sufficiently confirmed → block
"""

import json
import os
from datetime import datetime
from storage_paths import data_file, read_json, write_json

CONV_RISK_FILE = data_file("conv_risk.json")

# How much a single SAFE message decays the conversation risk score
_SAFE_DECAY = 8
# How much a SUSPICIOUS message raises the conversation risk score
_SUSPICIOUS_DELTA = 20
# How much a MALICIOUS message raises the conversation risk score
# A single MALICIOUS detection raises to HIGH_RISK (40); a second pushes to MALICIOUS (80+)
_MALICIOUS_DELTA = 40
# Thresholds for escalation level
_THRESHOLD_SUSPICIOUS = 20   # 1 SUSPICIOUS message
_THRESHOLD_HIGH_RISK = 40    # 1 MALICIOUS OR 2 SUSPICIOUS messages
_THRESHOLD_MALICIOUS = 80    # 2 MALICIOUS OR sustained escalation


def _read() -> dict:
    return read_json(CONV_RISK_FILE, {})


def _write(data: dict):
    write_json(CONV_RISK_FILE, data, ensure_ascii=False)


def get_conversation_risk(conversation_id: str) -> dict:
    """Return the current risk state for a conversation."""
    data = _read()
    return data.get(conversation_id, _default_state(conversation_id))


def _default_state(conversation_id: str) -> dict:
    return {
        "conversation_id": conversation_id,
        "risk_score": 0,
        "escalation_level": 0,          # 0=SAFE 1=SUSPICIOUS 2=HIGH_RISK 3=MALICIOUS
        "escalation_label": "SAFE",
        "previous_classifications": [], # ordered list of all classifications
        "threat_history": [],           # structured history of security threat events
        "suspicious_count": 0,
        "malicious_count": 0,
        "safe_count": 0,
        "total_messages": 0,
        "threat_categories": [],
        "intent_progression": [],        # last 10 classifications
        "last_threat": None,             # last threat details dictionary
        "last_threat_type": None,
        "last_threat_at": None,
        "response_mode": "NORMAL",
        "honeypot_active": False,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }


def update_conversation_risk(
    conversation_id: str,
    classification: str,
    threat_type: str,
    risk_score: int,
    categories: list,
    prompt_preview: str,
    response_mode: str = "NORMAL",
    allow_deescalation: bool = False,
) -> dict:
    """
    Update the conversation-level risk state after each message.
    Returns the updated state.
    """
    data = _read()
    state = data.get(conversation_id, _default_state(conversation_id))

    state["total_messages"] = state.get("total_messages", 0) + 1
    state["response_mode"] = response_mode

    # Record classification history
    prev_classes = state.setdefault("previous_classifications", [])
    prev_classes.append(classification)

    # Update intent progression (keep last 10)
    progression = state.setdefault("intent_progression", [])
    progression.append({
        "classification": classification,
        "threat_type": threat_type,
        "risk_score": risk_score,
        "response_mode": response_mode,
        "prompt_preview": prompt_preview[:80],
        "timestamp": datetime.now().isoformat(),
    })
    state["intent_progression"] = progression[-10:]

    # Update counts and threat history
    if classification == "MALICIOUS":
        state["malicious_count"] = state.get("malicious_count", 0) + 1
        state["last_threat_type"] = threat_type
        state["last_threat_at"] = datetime.now().isoformat()
        threat_rec = {
            "timestamp": datetime.now().isoformat(),
            "classification": classification,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "categories": categories,
            "prompt_preview": prompt_preview[:80],
            "response_mode": response_mode,
        }
        state.setdefault("threat_history", []).append(threat_rec)
        state["last_threat"] = threat_rec

        # Accumulate threat categories (deduplicated, last 20)
        cats = state.setdefault("threat_categories", [])
        for c in categories:
            if c not in cats:
                cats.append(c)
        state["threat_categories"] = cats[-20:]

    elif classification == "SUSPICIOUS":
        state["suspicious_count"] = state.get("suspicious_count", 0) + 1
        state["last_threat_type"] = threat_type
        state["last_threat_at"] = datetime.now().isoformat()
        threat_rec = {
            "timestamp": datetime.now().isoformat(),
            "classification": classification,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "categories": categories,
            "prompt_preview": prompt_preview[:80],
            "response_mode": response_mode,
        }
        state.setdefault("threat_history", []).append(threat_rec)
        state["last_threat"] = threat_rec

    else:
        state["safe_count"] = state.get("safe_count", 0) + 1

    # Update conversation risk score with decay/boost
    current = state.get("risk_score", 0)
    if classification == "MALICIOUS":
        current = min(100, current + _MALICIOUS_DELTA)
    elif classification == "SUSPICIOUS":
        current = min(100, current + _SUSPICIOUS_DELTA)
    else:
        decay = _SAFE_DECAY if not allow_deescalation else (_SAFE_DECAY * 3)
        current = max(0, current - decay)
    state["risk_score"] = current

    # Determine escalation level
    if current >= _THRESHOLD_MALICIOUS:
        new_level = 3
    elif current >= _THRESHOLD_HIGH_RISK:
        new_level = 2
    elif current >= _THRESHOLD_SUSPICIOUS:
        new_level = 1
    else:
        new_level = 0

    if classification == "SAFE" and (allow_deescalation or current < _THRESHOLD_SUSPICIOUS):
        # A new SAFE message reduces/resets escalation where appropriate
        state["escalation_level"] = new_level
    else:
        state["escalation_level"] = max(state.get("escalation_level", 0), new_level)

    labels = {0: "SAFE", 1: "SUSPICIOUS", 2: "HIGH_RISK", 3: "MALICIOUS"}
    state["escalation_label"] = labels[state["escalation_level"]]

    # Activate honeypot mode once conversation reaches SUSPICIOUS or has honeypot response
    if state["escalation_level"] >= 1 or response_mode in ("HONEYPOT", "HIGH_RISK"):
        state["honeypot_active"] = True

    state["updated_at"] = datetime.now().isoformat()
    data[conversation_id] = state
    _write(data)
    return state


def get_escalation_label(conversation_id: str) -> str:
    """Quick helper — returns the current escalation label string."""
    return get_conversation_risk(conversation_id).get("escalation_label", "SAFE")


def conversation_is_honeypot_active(conversation_id: str) -> bool:
    return get_conversation_risk(conversation_id).get("honeypot_active", False)


def reset_conversation_risk(conversation_id: str):
    """Reset or remove risk state for a conversation (useful for testing or deletion)."""
    data = _read()
    if conversation_id in data:
        del data[conversation_id]
        _write(data)
