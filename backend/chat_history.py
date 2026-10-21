"""
Conversation and message persistence for HoneyPrompt chat history.
Stored in conversations.json alongside the existing attacks.json.
"""
import re
import uuid
from datetime import datetime
from storage_paths import data_file, read_json, write_json

CONV_FILE = data_file("conversations.json")


def _redact_sensitive_text(value: str) -> str:
    value = re.sub(r"(?i)(\b(?:api[_-]?key|password|secret|token)\b\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", value)
    return re.sub(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,})\b", "[REDACTED]", value)


def _read_store() -> dict:
    data = read_json(CONV_FILE, {"conversations": [], "messages": []})
    data.setdefault("conversations", [])
    data.setdefault("messages", [])
    return data


def _write_store(data: dict):
    write_json(CONV_FILE, data)


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

def create_conversation(user_id: str, title: str = "New Chat") -> dict:
    store = _read_store()
    conv = {
        "conversation_id": str(uuid.uuid4()),
        "user_id": user_id.casefold(),
        "title": title,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }
    store["conversations"].append(conv)
    _write_store(store)
    return conv


def get_conversations(user_id: str) -> list:
    store = _read_store()
    uid = user_id.casefold()
    convs = [c for c in store["conversations"] if c["user_id"] == uid]
    return sorted(convs, key=lambda c: c["updated_at"], reverse=True)


def get_conversation_summaries(user_id: str) -> list:
    store = _read_store()
    uid = user_id.casefold()
    messages_by_conversation: dict[str, list[dict]] = {}
    for message in store["messages"]:
        if message.get("user_id") == uid:
            messages_by_conversation.setdefault(message["conversation_id"], []).append(message)

    summaries = []
    for conversation in store["conversations"]:
        if conversation.get("user_id") != uid:
            continue
        messages = messages_by_conversation.get(conversation["conversation_id"], [])
        classifications = [message.get("classification", "SAFE") for message in messages]
        security_status = (
            "MALICIOUS" if "MALICIOUS" in classifications
            else "SUSPICIOUS" if "SUSPICIOUS" in classifications
            else "SAFE"
        )
        summaries.append({
            **conversation,
            "first_prompt_preview": (messages[0].get("prompt", "")[:120] if messages else ""),
            "message_count": len(messages),
            "security_status": security_status,
        })
    return sorted(summaries, key=lambda item: item.get("updated_at", ""), reverse=True)


def get_conversation(conversation_id: str, user_id: str) -> dict | None:
    store = _read_store()
    uid = user_id.casefold()
    return next(
        (c for c in store["conversations"]
         if c["conversation_id"] == conversation_id and c["user_id"] == uid),
        None,
    )


def rename_conversation(conversation_id: str, user_id: str, title: str) -> dict | None:
    store = _read_store()
    uid = user_id.casefold()
    for c in store["conversations"]:
        if c["conversation_id"] == conversation_id and c["user_id"] == uid:
            c["title"] = title[:120]
            c["updated_at"] = datetime.now().isoformat()
            _write_store(store)
            return c
    return None


def delete_conversation(conversation_id: str, user_id: str) -> bool:
    store = _read_store()
    uid = user_id.casefold()
    before = len(store["conversations"])
    store["conversations"] = [
        c for c in store["conversations"]
        if not (c["conversation_id"] == conversation_id and c["user_id"] == uid)
    ]
    store["messages"] = [
        m for m in store["messages"] if m["conversation_id"] != conversation_id
    ]
    if len(store["conversations"]) < before:
        _write_store(store)
        return True
    return False


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def add_message(
    conversation_id: str,
    user_id: str,
    prompt: str,
    response: str,
    classification: str,
    threat_type: str,
    severity: str,
    confidence: float,
    risk_score: int,
    action: str,
    reason: str = "",
    request_id: str | None = None,
    timestamp: str | None = None,
) -> dict:
    store = _read_store()
    uid = user_id.casefold()
    safe_prompt = _redact_sensitive_text(prompt)
    safe_response = _redact_sensitive_text(response)
    msg = {
        "message_id": str(uuid.uuid4()),
        "conversation_id": conversation_id,
        "user_id": uid,
        "prompt": safe_prompt,
        "response": safe_response,
        "classification": classification,
        "threat_type": threat_type,
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "action": action,
        "reason": reason,
        "request_id": request_id,
        "timestamp": timestamp or datetime.now().isoformat(),
    }
    store["messages"].append(msg)
    # Update conversation updated_at and auto-title from first prompt
    for c in store["conversations"]:
        if c["conversation_id"] == conversation_id and c["user_id"] == uid:
            c["updated_at"] = msg["timestamp"]
            if c["title"] == "New Chat" and safe_prompt.strip():
                c["title"] = safe_prompt.strip()[:60]
            break
    _write_store(store)
    return msg


def get_messages(conversation_id: str, user_id: str) -> list:
    store = _read_store()
    uid = user_id.casefold()
    return [
        m for m in store["messages"]
        if m["conversation_id"] == conversation_id and m["user_id"] == uid
    ]
