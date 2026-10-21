import uvicorn
import os
import uuid
import hashlib
import json
from datetime import date, datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware
import io
import asyncio
from fastapi.responses import Response, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
from dotenv import load_dotenv
from groq import AuthenticationError, Groq

from detection import analyze_prompt, analyze_with_context, confidence_for_prompt, load_threat_model, model_probability
from response_service import generate_chat_response, BLOCKED_RESPONSE
from notifications import (
    create_notification, update_notification, delete_notification,
    get_all_notifications, get_user_notifications,
    mark_notification_read, dismiss_notification, unread_count_for_user,
)
from conversation_risk import get_conversation_risk, update_conversation_risk
from honeypot_responses import get_deception_response
from logger import log_event, get_logs, get_stats, _read_logs, mark_false_positive, get_user_alerts, mark_alert_read
from chat_history import (
    create_conversation, get_conversations, get_conversation,
    get_conversation_summaries, rename_conversation, delete_conversation,
    add_message, get_messages,
)
from soc_store import (
    get_policies, update_policies,
    audit_log, get_audit_logs,
    create_alert, get_alerts, update_alert_status, get_alert_stats,
    create_incident, get_incidents, update_incident,
    update_user_risk, get_user_risk, get_all_user_risks, reset_user_risk,
    get_threat_intelligence, detect_repeated_patterns, get_model_info,
)
from rate_limiter import is_rate_limited
from reports_store import save_report_record, get_report_history
from storage_paths import data_file, read_json, write_json
from reports_service import (
    build_security_overview_report,
    build_threat_intelligence_report,
    build_user_security_report,
    build_audit_log_report,
    build_incidents_report,
    build_chat_activity_report,
    build_user_chats_report,
    build_personal_security_report,
    build_user_security_history_report,
    build_user_chat_activity_report,
    build_user_alerts_report,
)
from report_generators import generate_pdf, generate_excel
from email_service import send_report_email

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "honeyprompt-sentinel-secret-2024")

app = FastAPI(title="HoneyPrompt Sentinel", version="2.5")

class AlertEventBroker:
    """Manages real-time SSE event subscriptions for SOC administrators."""
    def __init__(self):
        self.listeners: set[asyncio.Queue] = set()

    def add_listener(self, queue: asyncio.Queue):
        self.listeners.add(queue)

    def remove_listener(self, queue: asyncio.Queue):
        self.listeners.discard(queue)

    async def broadcast(self, data: dict):
        for q in list(self.listeners):
            try:
                await q.put(data)
            except Exception:
                pass

alert_broker = AlertEventBroker()


@app.on_event("startup")
async def load_prompt_classifier():
    loaded = load_threat_model()
    print(f"[Detection] Trained prompt classifier {'loaded' if loaded else 'unavailable; using security rules'}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def disable_api_cache(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response


# HONEYPOT decoy strings are embedded in the security analysis layer (detection.py).
# The system prompt for the LLM is managed in response_service.py.

# ---------------------------------------------------------------------------
# SIMPLE TOKEN AUTH (file-based users, no DB dependency)
# ---------------------------------------------------------------------------
USERS_FILE = data_file("users.json")
BLOCKED_PATTERNS_FILE = data_file("blocked_patterns.json")
SECURITY_SETTINGS_FILE = data_file("security_settings.json")
ACTIVITY_FILE = data_file("security_activity.json")
DEFAULT_SECURITY_SETTINGS = {"warning_threshold": 3, "block_threshold": 5, "block_cooldown_minutes": 15}
security = HTTPBearer(auto_error=False)


def _hash_password(password: str) -> str:
    return hashlib.sha256((password + SECRET_KEY).encode()).hexdigest()


def _read_users() -> dict:
    if not os.path.exists(USERS_FILE):
        # Seed default admin
        users = {
            "admin_01": {
                "username": "admin_01",
                "full_name": "Admin User",
                "email": "admin@honeyprompt.ai",
                "password_hash": _hash_password("Admin@1234"),
                "role": "Admin",
                "is_active": True,
                "is_blocked": False,
                "created_at": datetime.now().isoformat(),
                "last_login": None,
            }
        }
        write_json(USERS_FILE, users)
        return users
    return read_json(USERS_FILE, {})


def _write_users(users: dict):
    write_json(USERS_FILE, users)


def _read_blocked_patterns() -> list:
    if not os.path.exists(BLOCKED_PATTERNS_FILE):
        return []
    return read_json(BLOCKED_PATTERNS_FILE, [])


def _write_blocked_patterns(patterns: list):
    write_json(BLOCKED_PATTERNS_FILE, patterns)


def _analyze_prompt(text: str) -> dict:
    analysis = analyze_prompt(text)
    lowered = text.casefold()
    if any(p.get("is_active", True) and p.get("phrase", "").casefold() in lowered for p in _read_blocked_patterns()):
        probability = model_probability(text)
        return {
            **analysis,
            "classification": "MALICIOUS",
            "threat_type": "Administrator Blocklist",
            "severity": "HIGH",
            "risk_score": 100,
            "confidence": probability if probability is not None else confidence_for_prompt(text, "MALICIOUS", evidence_count=2, rule_count=1),
            "action": "BLOCKED",
            "reason": "This prompt matched an administrator-managed security pattern.",
            "is_threat": True,
            "categories": list(analysis.get("categories", [])) + ["admin_blocklist"],
        }
    return analysis


# Token store — persisted to disk so backend restarts don't invalidate sessions
_TOKENS_FILE = data_file("sessions.json")


def _load_tokens() -> dict:
    return read_json(_TOKENS_FILE, {})


def _save_tokens(tokens: dict):
    write_json(_TOKENS_FILE, tokens)


_tokens: dict = _load_tokens()


def _token_owner(token: str) -> str | None:
    _tokens.clear()
    _tokens.update(_load_tokens())
    return _tokens.get(token)


def _create_token(username: str) -> str:
    token = str(uuid.uuid4())
    _tokens[token] = username
    _save_tokens(_tokens)
    return token

def get_current_user_obj(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = _token_owner(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    users = _read_users()
    user = users.get(username.lower())
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.get("is_active", True) or user.get("is_blocked", False):
        raise HTTPException(status_code=403, detail="This account is inactive or blocked")
    return user

def admin_required(current_user: dict = Depends(get_current_user_obj)):
    if current_user.get("role", "").casefold() != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


def _read_security_settings() -> dict:
    try:
        return {**DEFAULT_SECURITY_SETTINGS, **read_json(SECURITY_SETTINGS_FILE, {})}
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_SECURITY_SETTINGS)


def _write_security_settings(settings: dict):
    write_json(SECURITY_SETTINGS_FILE, settings)


def _read_activity() -> dict:
    try:
        return read_json(ACTIVITY_FILE, {})
    except (OSError, json.JSONDecodeError):
        return {}


def _write_activity(activity: dict):
    write_json(ACTIVITY_FILE, activity)


def _chat_activity(username: str) -> dict:
    activity = _read_activity()
    state = activity.get(username.casefold(), {
        "consecutive_count": 0,
        "blocked_until": None,
        "block_reason": None,
        "blocked_by": None,
        "blocked_at": None,
        "block_source": None,
    })
    blocked_until = state.get("blocked_until")
    if blocked_until:
        try:
            if datetime.fromisoformat(blocked_until) <= datetime.now():
                state["blocked_until"] = None
                state["consecutive_count"] = 0
                state["block_reason"] = None
                state["blocked_by"] = None
                state["blocked_at"] = None
                state["block_source"] = None
                activity[username.casefold()] = state
                _write_activity(activity)
            else:
                metadata_updated = False
                if not state.get("block_reason"):
                    count = state.get("consecutive_count", 0)
                    state["block_reason"] = f"{count} consecutive malicious prompts detected." if count else "Temporary chat restriction applied by Sentinel."
                    metadata_updated = True
                if not state.get("blocked_by"):
                    state["blocked_by"] = "SENTINEL"
                    metadata_updated = True
                if not state.get("block_source"):
                    state["block_source"] = "automatic"
                    metadata_updated = True
                state.setdefault("blocked_at", None)
                if metadata_updated:
                    activity[username.casefold()] = state
                    _write_activity(activity)
        except ValueError:
            state["blocked_until"] = None
            state["consecutive_count"] = 0
            state["block_reason"] = None
            state["blocked_by"] = None
            state["blocked_at"] = None
            state["block_source"] = None
            activity[username.casefold()] = state
            _write_activity(activity)
    return state


def _save_chat_activity(username: str, state: dict):
    activity = _read_activity()
    activity[username.casefold()] = state
    _write_activity(activity)


# ---------------------------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = "default-session"
    conversation_id: Optional[str] = None


class ConversationCreate(BaseModel):
    title: str = "New Chat"


class ConversationRename(BaseModel):
    title: str


class SecuritySettingsUpdate(BaseModel):
    warning_threshold: int
    block_threshold: int
    block_cooldown_minutes: int


class TemporaryBlockUpdate(BaseModel):
    duration_minutes: int
    reason: str = ""


class LoginRequest(BaseModel):
    username: str
    password: str


class SignupRequest(BaseModel):
    full_name: str
    username: str
    email: str
    password: str


class UserAccessUpdate(BaseModel):
    is_active: Optional[bool] = None
    is_blocked: Optional[bool] = None


class ThreatPatternCreate(BaseModel):
    phrase: str


class ThreatPatternUpdate(BaseModel):
    is_active: bool


class FalsePositiveReport(BaseModel):
    reason: str = ""


class NotificationCreate(BaseModel):
    target_user: str          # username or "__all__"
    title: str
    message: str
    priority: str = "info"   # info | warning | danger | success


class NotificationUpdate(BaseModel):
    title: Optional[str] = None
    message: Optional[str] = None
    priority: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class ReportExportRequest(BaseModel):
    report_type: str = "security_overview"
    date_range: str = "30d"
    date_from: str | None = None
    date_to: str | None = None
    classification: str | None = None
    severity: str | None = None
    threat_type: str | None = None
    user: str | None = None
    action: str | None = None
    status: str | None = None


class EmailReportRequest(BaseModel):
    recipient_email: str
    cc_email: str | None = None
    subject: str | None = None
    message: str | None = None
    report_type: str = "security_overview"
    format: str = "PDF"
    date_range: str = "30d"
    date_from: str | None = None
    date_to: str | None = None
    classification: str | None = None
    severity: str | None = None
    threat_type: str | None = None
    user: str | None = None
    action: str | None = None
    status: str | None = None


# ---------------------------------------------------------------------------
# AUTH ENDPOINTS
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(req: LoginRequest):
    users = _read_users()
    key = req.username.lower()
    user = users.get(key)
    if not user or user["password_hash"] != _hash_password(req.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if not user.get("is_active", True) or user.get("is_blocked", False):
        raise HTTPException(status_code=403, detail="This account is inactive or blocked.")
    token = _create_token(key)
    # Update last login
    users[key]["last_login"] = datetime.now().isoformat()
    _write_users(users)
    return {
        "token": token,
        "user": {
            "username": user["username"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user["role"],
            "is_active": user.get("is_active", True),
            "is_blocked": user.get("is_blocked", False),
            "created_at": user.get("created_at"),
            "last_login": user["last_login"],
        },
    }


@app.post("/api/auth/signup")
async def signup(req: SignupRequest):
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    users = _read_users()
    key = req.username.lower()
    if key in users:
        raise HTTPException(status_code=409, detail="Username already exists.")
    users[key] = {
        "username": req.username,
        "full_name": req.full_name,
        "email": req.email,
        "password_hash": _hash_password(req.password),
        "role": "User",
        "is_active": True,
        "is_blocked": False,
        "created_at": datetime.now().isoformat(),
        "last_login": None,
    }
    _write_users(users)
    token = _create_token(key)
    return {"token": token, "user": {"username": req.username, "full_name": req.full_name, "email": req.email, "role": "User", "is_active": True, "is_blocked": False, "created_at": users[key]["created_at"], "last_login": None}}


@app.post("/api/auth/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials and credentials.credentials in _tokens:
        del _tokens[credentials.credentials]
        _save_tokens(_tokens)
    return {"status": "logged out"}


@app.get("/api/auth/me")
async def auth_me(current_user: dict = Depends(get_current_user_obj)):
    return {k: v for k, v in current_user.items() if k != "password_hash"}


@app.post("/api/user/password")
async def user_change_password(request: PasswordChangeRequest, current_user: dict = Depends(get_current_user_obj)):
    if current_user["password_hash"] != _hash_password(request.current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(request.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    if request.current_password == request.new_password:
        raise HTTPException(status_code=400, detail="Choose a password different from the current one")
    username = current_user["username"].lower()
    users = _read_users()
    users[username]["password_hash"] = _hash_password(request.new_password)
    users[username]["password_changed_at"] = datetime.now().isoformat()
    _write_users(users)
    for token, token_owner in list(_tokens.items()):
        if token_owner.lower() == username:
            del _tokens[token]
    _save_tokens(_tokens)
    return {"status": "password_updated", "reauthentication_required": True}


@app.get("/api/admin/users")
async def admin_get_all_users(_admin: dict = Depends(admin_required)):
    users = _read_users()
    # Exclude password hashes from response
    return [ {k: v for k, v in user.items() if k != "password_hash"} for user in users.values() ]


@app.patch("/api/admin/users/{username}/access")
async def admin_update_user_access(username: str, update: UserAccessUpdate, admin: dict = Depends(admin_required)):
    key = username.lower()
    users = _read_users()
    target = users.get(key)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if key == admin["username"].lower() or target.get("role") == "Admin":
        raise HTTPException(status_code=400, detail="Administrator accounts cannot be changed here")
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No access changes provided")
    target.update(changes)
    _write_users(users)
    return {k: v for k, v in target.items() if k != "password_hash"}


@app.get("/api/admin/users/{username}/logs")
async def admin_get_user_logs(username: str, _admin: dict = Depends(admin_required)):
    key = username.lower()
    if key not in _read_users():
        raise HTTPException(status_code=404, detail="User not found")
    return [entry for entry in reversed(_read_logs()) if entry.get("user", "").lower() == key]


@app.get("/api/admin/security-settings")
async def admin_get_security_settings(_admin: dict = Depends(admin_required)):
    return _read_security_settings()


@app.patch("/api/admin/security-settings")
async def admin_update_security_settings(update: SecuritySettingsUpdate, _admin: dict = Depends(admin_required)):
    if update.warning_threshold < 1 or update.block_threshold <= update.warning_threshold:
        raise HTTPException(status_code=400, detail="Block threshold must be greater than the warning threshold.")
    if update.block_cooldown_minutes < 1 or update.block_cooldown_minutes > 1440:
        raise HTTPException(status_code=400, detail="Block duration must be between 1 and 1440 minutes.")
    settings = update.model_dump()
    _write_security_settings(settings)
    return settings


@app.get("/api/admin/chat-activity")
async def admin_get_chat_activity(_admin: dict = Depends(admin_required)):
    users = _read_users()
    logs = _read_logs()
    results = []
    for key, user in users.items():
        if user.get("role", "").casefold() == "admin":
            continue
        state = _chat_activity(key)
        recent = [entry for entry in reversed(logs) if entry.get("user", "").casefold() == key.casefold() and entry.get("classification") == "MALICIOUS"][:20]
        results.append({
            "username": user.get("username", key),
            "user_id": key,
            "email": user.get("email"),
            "consecutive_count": state.get("consecutive_count", 0),
            "blocked_until": state.get("blocked_until"),
            "is_chat_blocked": bool(state.get("blocked_until")),
            "block_reason": state.get("block_reason"),
            "blocked_by": state.get("blocked_by"),
            "blocked_at": state.get("blocked_at"),
            "block_source": state.get("block_source"),
            "threat_history": recent,
        })
    return results


@app.get("/api/admin/users/{username}/conversations")
async def admin_get_user_conversations(username: str, _admin: dict = Depends(admin_required)):
    key = username.casefold()
    user = _read_users().get(key)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return [
        {
            **conversation,
            "messages": get_messages(conversation["conversation_id"], key),
        }
        for conversation in get_conversations(key)
    ]


@app.patch("/api/admin/users/{username}/chat-block")
async def admin_update_chat_block(username: str, update: TemporaryBlockUpdate, admin: dict = Depends(admin_required)):
    key = username.casefold()
    users = _read_users()
    if key not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if users[key].get("role", "").casefold() == "admin" or key == admin["username"].casefold():
        raise HTTPException(status_code=400, detail="Administrator chat access cannot be changed here")
    if update.duration_minutes < -1 or update.duration_minutes > 52560000:
        raise HTTPException(status_code=400, detail="Duration must be -1 (permanent) or between 0 and 52560000 minutes.")
    state = _chat_activity(key)
    reason = update.reason.strip()[:500] or ("Restriction lifted by an administrator." if update.duration_minutes == 0 else "Manually restricted by an administrator.")

    if update.duration_minutes == 0:
        state["blocked_until"] = None
        state["consecutive_count"] = 0
        state["block_reason"] = None
        state["blocked_by"] = None
        state["blocked_at"] = None
        state["block_source"] = None
        users[key]["is_blocked"] = False
        _write_users(users)
        audit_log(admin["username"], "USER_UNBLOCKED", key, reason)
        log_event(
            "[SYSTEM NOTICE] Access Restriction Lifted",
            {
                "classification": "SAFE",
                "threat_type": "Administrative Unblock",
                "severity": "NONE",
                "risk_score": 0,
                "confidence": 1.0,
                "action": "ALLOWED",
                "reason": reason,
            },
            f"Your account access has been fully restored by an administrator ({admin['username']}).",
            session_id="admin-notice",
            user=key,
            extra_fields={"blocked_by": admin["username"], "action_type": "UNBLOCK"}
        )
    else:
        state["blocked_at"] = datetime.now().isoformat()
        if update.duration_minutes == -1:
            state["blocked_until"] = "2099-12-31T23:59:59"
            users[key]["is_blocked"] = True
        else:
            state["blocked_until"] = (datetime.now() + timedelta(minutes=update.duration_minutes)).isoformat()
            users[key]["is_blocked"] = False
        state["block_reason"] = reason
        state["blocked_by"] = admin["username"]
        state["block_source"] = "manual"
        _write_users(users)
        audit_log(admin["username"], "USER_BLOCKED", key, reason, {
            "duration_minutes": update.duration_minutes,
            "blocked_until": state["blocked_until"],
        })
        log_event(
            "[SYSTEM NOTICE] Administrative Restriction Applied",
            {
                "classification": "MALICIOUS",
                "threat_type": "Administrative Block",
                "severity": "CRITICAL",
                "risk_score": 100,
                "confidence": 1.0,
                "action": "BLOCKED",
                "reason": reason,
            },
            f"Your access has been restricted by an administrator ({admin['username']}). Reason: {reason}",
            session_id="admin-notice",
            user=key,
            extra_fields={
                "blocked_until": state["blocked_until"],
                "blocked_by": admin["username"],
                "duration_minutes": update.duration_minutes,
                "action_type": "BLOCK"
            }
        )
    _save_chat_activity(key, state)
    return {
        "username": key,
        "consecutive_count": state.get("consecutive_count", 0),
        "blocked_until": state.get("blocked_until"),
        "is_chat_blocked": bool(state.get("blocked_until")),
        "block_reason": state.get("block_reason"),
        "blocked_by": state.get("blocked_by"),
        "blocked_at": state.get("blocked_at"),
        "block_source": state.get("block_source"),
    }


@app.get("/api/admin/patterns")
async def admin_get_patterns(_admin: dict = Depends(admin_required)):
    return _read_blocked_patterns()


@app.post("/api/admin/patterns", status_code=201)
async def admin_add_pattern(request: ThreatPatternCreate, admin: dict = Depends(admin_required)):
    phrase = request.phrase.strip()
    if len(phrase) < 3:
        raise HTTPException(status_code=400, detail="Pattern must contain at least 3 characters")
    patterns = _read_blocked_patterns()
    if any(p["phrase"].casefold() == phrase.casefold() for p in patterns):
        raise HTTPException(status_code=409, detail="Pattern already exists")
    pattern = {"id": str(uuid.uuid4()), "phrase": phrase, "is_active": True, "created_by": admin["username"], "created_at": datetime.now().isoformat()}
    patterns.append(pattern)
    _write_blocked_patterns(patterns)
    return pattern


@app.patch("/api/admin/patterns/{pattern_id}")
async def admin_update_pattern(pattern_id: str, update: ThreatPatternUpdate, _admin: dict = Depends(admin_required)):
    patterns = _read_blocked_patterns()
    pattern = next((p for p in patterns if p["id"] == pattern_id), None)
    if pattern is None:
        raise HTTPException(status_code=404, detail="Pattern not found")
    pattern["is_active"] = update.is_active
    pattern["updated_at"] = datetime.now().isoformat()
    _write_blocked_patterns(patterns)
    return pattern


@app.get("/api/admin/alerts")
async def admin_get_alerts(_admin: dict = Depends(admin_required)):
    alerts_data = get_alerts(page=1, page_size=50, exclude_test=True)
    return alerts_data.get("items", [])


@app.get("/api/soc/alerts/stream")
async def soc_alerts_stream(request: Request, token: Optional[str] = Query(None)):
    """Server-Sent Events (SSE) stream pushing real-time SOC security alerts to admin interfaces."""
    user = None
    token_user = _token_owner(token) if token else None
    if token_user:
        uname = token_user
        u = _read_users().get(uname.lower())
        if u and u.get("role", "").casefold() == "admin":
            user = u
    if not user:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            t = auth_header.split(" ", 1)[1]
            token_user = _token_owner(t)
            if token_user:
                uname = token_user
                u = _read_users().get(uname.lower())
                if u and u.get("role", "").casefold() == "admin":
                    user = u

    if not user:
        raise HTTPException(status_code=403, detail="Admin authorization required for alert stream")

    queue = asyncio.Queue()
    alert_broker.add_listener(queue)

    async def event_generator():
        try:
            # Initial handshake
            yield f"data: {json.dumps({'type': 'CONNECTED', 'message': 'Sentinel SOC alert stream connected'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        except Exception:
            pass
        finally:
            alert_broker.remove_listener(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/user/alerts")
async def user_get_alerts(current_user: dict = Depends(get_current_user_obj)):
    return get_user_alerts(current_user["username"])


@app.post("/api/user/alerts/{request_id}/read")
async def user_mark_alert_read(request_id: str, current_user: dict = Depends(get_current_user_obj)):
    entry = mark_alert_read(request_id, current_user["username"])
    if entry is None:
        raise HTTPException(status_code=404, detail="Alert not found for this account")
    return {"status": "read", "request_id": request_id}


# ---------------------------------------------------------------------------
# EXISTING ENDPOINTS (preserved + enhanced)
# ---------------------------------------------------------------------------
@app.get("/status")
async def health_check():
    return {
        "status": "nominal",
        "system": "HoneyPrompt Proxy Active",
        "provider": "Groq",
        "llm_key_configured": bool(GROQ_API_KEY),
    }


@app.get("/api/logs")
async def fetch_logs(_admin: dict = Depends(admin_required)):
    return get_logs()


@app.get("/api/stats")
async def fetch_stats(_admin: dict = Depends(admin_required)):
    return get_stats()

# Admin-only aggregated stats (including user counts)
@app.get("/api/admin/stats")
async def admin_fetch_stats(_admin: dict = Depends(admin_required)):
    # Base stats from logs
    base = get_stats()
    # User stats
    users = _read_users()
    total_users = len(users)
    active_users = sum(1 for u in users.values() if u.get("is_active", True) and not u.get("is_blocked", False))
    base.update({"total_users": total_users, "active_users": active_users})
    return base

# User-specific stats (filtered by their logs)
@app.get("/api/user/stats")
async def user_fetch_stats(current_user: dict = Depends(get_current_user_obj)):
    username = current_user["username"]
    logs = [l for l in _read_logs() if l.get("user") == username]
    total = len(logs)
    safe = sum(1 for l in logs if l.get("classification") == "SAFE")
    suspicious = sum(1 for l in logs if l.get("classification") == "SUSPICIOUS")
    malicious = sum(1 for l in logs if l.get("classification") == "MALICIOUS")
    blocked = sum(1 for l in logs if l.get("action") == "BLOCKED")
    return {"total": total, "safe": safe, "suspicious": suspicious, "malicious": malicious, "blocked": blocked}

# User-specific recent logs
@app.get("/api/user/logs")
async def user_fetch_logs(current_user: dict = Depends(get_current_user_obj)):
    username = current_user["username"]
    logs = [l for l in _read_logs() if l.get("user") == username]
    # Return most recent 20
    return logs[::-1][:20]


@app.get("/api/user/history")
async def user_get_history(
    current_user: dict = Depends(get_current_user_obj),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: str = "",
    classification: Optional[str] = None,
    threat_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    owner = current_user["username"].casefold()
    entries = [entry for entry in reversed(_read_logs()) if entry.get("user", "").casefold() == owner]
    if classification and classification.upper() != "ALL":
        entries = [entry for entry in entries if entry.get("classification", "").upper() == classification.upper()]
    if threat_type and threat_type.casefold() != "all":
        entries = [entry for entry in entries if entry.get("threat_type", "").casefold() == threat_type.casefold()]
    if search.strip():
        query = search.casefold()
        entries = [entry for entry in entries if query in f"{entry.get('prompt_preview', '')} {entry.get('threat_type', '')}".casefold()]
    try:
        start_date = date.fromisoformat(date_from) if date_from else None
        end_date = date.fromisoformat(date_to) if date_to else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Dates must use YYYY-MM-DD format") from exc
    if start_date or end_date:
        def matches_date(entry):
            try:
                event_date = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00")).date()
            except (KeyError, ValueError):
                return False
            return (start_date is None or event_date >= start_date) and (end_date is None or event_date <= end_date)
        entries = [entry for entry in entries if matches_date(entry)]
    total = len(entries)
    offset = (page - 1) * page_size
    return {"items": entries[offset:offset + page_size], "total": total, "page": page, "page_size": page_size}


@app.get("/api/user/chat-status")
async def user_chat_status(current_user: dict = Depends(get_current_user_obj)):
    settings = _read_security_settings()
    state = _chat_activity(current_user["username"])
    return {
        "consecutive_count": state.get("consecutive_count", 0),
        "blocked_until": state.get("blocked_until"),
        "is_chat_blocked": bool(state.get("blocked_until")),
        "warning_threshold": settings["warning_threshold"],
        "block_threshold": settings["block_threshold"],
    }


@app.get("/api/user/conversations")
async def user_list_conversations(current_user: dict = Depends(get_current_user_obj)):
    return get_conversation_summaries(current_user["username"])


@app.post("/api/user/conversations", status_code=201)
async def user_create_conversation(request: ConversationCreate, current_user: dict = Depends(get_current_user_obj)):
    title = request.title.strip()[:120] or "New Chat"
    return create_conversation(current_user["username"], title)


@app.get("/api/user/conversations/{conversation_id}")
async def user_get_conversation(conversation_id: str, current_user: dict = Depends(get_current_user_obj)):
    conversation = get_conversation(conversation_id, current_user["username"])
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"conversation": conversation, "messages": get_messages(conversation_id, current_user["username"])}


@app.patch("/api/user/conversations/{conversation_id}")
async def user_rename_conversation(conversation_id: str, request: ConversationRename, current_user: dict = Depends(get_current_user_obj)):
    title = request.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Conversation title cannot be empty")
    conversation = rename_conversation(conversation_id, current_user["username"], title)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation


@app.delete("/api/user/conversations/{conversation_id}")
async def user_delete_conversation(conversation_id: str, current_user: dict = Depends(get_current_user_obj)):
    if not delete_conversation(conversation_id, current_user["username"]):
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"status": "deleted", "conversation_id": conversation_id}


# ---------------------------------------------------------------------------
# NOTIFICATION ENDPOINTS — ADMIN
# ---------------------------------------------------------------------------

@app.get("/api/admin/notifications")
async def admin_list_notifications(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _admin: dict = Depends(admin_required),
):
    return get_all_notifications(page=page, page_size=page_size)


@app.post("/api/admin/notifications", status_code=201)
async def admin_send_notification(body: NotificationCreate, admin: dict = Depends(admin_required)):
    if not body.title.strip():
        raise HTTPException(status_code=400, detail="Title cannot be empty")
    if not body.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    # Validate target user exists (unless broadcast)
    if body.target_user != "__all__":
        if body.target_user.casefold() not in _read_users():
            raise HTTPException(status_code=404, detail="Target user not found")
    notif = create_notification(
        sent_by=admin["username"],
        target_user=body.target_user,
        title=body.title,
        message=body.message,
        priority=body.priority,
    )
    audit_log(admin["username"], "NOTIFICATION_SENT", body.target_user, body.title[:80])
    return notif


@app.patch("/api/admin/notifications/{notification_id}")
async def admin_update_notification(
    notification_id: str,
    body: NotificationUpdate,
    admin: dict = Depends(admin_required),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")
    result = update_notification(notification_id, updates)
    if result is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    audit_log(admin["username"], "NOTIFICATION_UPDATED", notification_id, str(updates)[:120])
    return result


@app.delete("/api/admin/notifications/{notification_id}", status_code=204)
async def admin_delete_notification(notification_id: str, admin: dict = Depends(admin_required)):
    if not delete_notification(notification_id):
        raise HTTPException(status_code=404, detail="Notification not found")
    audit_log(admin["username"], "NOTIFICATION_DELETED", notification_id)
    return


# ---------------------------------------------------------------------------
# NOTIFICATION ENDPOINTS — USER
# ---------------------------------------------------------------------------

@app.get("/api/user/notifications")
async def user_get_notifications(current_user: dict = Depends(get_current_user_obj)):
    return get_user_notifications(current_user["username"])


@app.get("/api/user/notifications/unread-count")
async def user_notification_unread_count(current_user: dict = Depends(get_current_user_obj)):
    return {"count": unread_count_for_user(current_user["username"])}


@app.post("/api/user/notifications/{notification_id}/read")
async def user_read_notification(notification_id: str, current_user: dict = Depends(get_current_user_obj)):
    result = mark_notification_read(notification_id, current_user["username"])
    if result is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "read", "notification_id": notification_id}


@app.post("/api/user/notifications/{notification_id}/dismiss")
async def user_dismiss_notification(notification_id: str, current_user: dict = Depends(get_current_user_obj)):
    if not dismiss_notification(notification_id, current_user["username"]):
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "dismissed", "notification_id": notification_id}


@app.post("/api/user/logs/{request_id}/false-positive")
async def user_report_false_positive(request_id: str, report: FalsePositiveReport, current_user: dict = Depends(get_current_user_obj)):
    entry = mark_false_positive(request_id, current_user["username"], report.reason)
    if entry is None:
        raise HTTPException(status_code=404, detail="Threat event not found for this account")
    return {"status": "reported", "request_id": request_id}


@app.post("/api/chat")
async def chat_proxy(request: ChatRequest, http_request: Request, current_user: dict = Depends(get_current_user_obj)):
    user_message = request.message.strip()
    if not user_message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    username = current_user["username"]
    state = _chat_activity(username)
    if state.get("blocked_until"):
        raise HTTPException(status_code=429, detail={
            "code": "CHAT_TEMPORARILY_BLOCKED",
            "message": "Your chat access is temporarily restricted due to repeated malicious prompts.",
            "blocked_until": state["blocked_until"],
            "consecutive_count": state.get("consecutive_count", 0),
        })

    if request.conversation_id:
        conversation = get_conversation(request.conversation_id, username)
        if conversation is None:
            raise HTTPException(status_code=404, detail="Conversation not found")
        conversation_id = request.conversation_id
    else:
        conversation_id = create_conversation(username)["conversation_id"]
    session_id = conversation_id if request.session_id == "default-session" else request.session_id

    print(f"\n[Incoming] {user_message[:80]}")

    # STEP 1: Load conversation history + risk state for context-aware detection
    prior_messages = get_messages(conversation_id, username)
    conv_risk_state = get_conversation_risk(conversation_id)

    # STEP 2: Context-aware intent detection
    analysis = _analyze_prompt(user_message)  # base single-message analysis
    analysis = analyze_with_context(
        current_prompt=user_message,
        conversation_history=prior_messages,
        conversation_risk_state=conv_risk_state,
        base_analysis=analysis,
    )
    classification = analysis["classification"]
    action = analysis["action"]

    print(f"[Detection] {classification} | {analysis['threat_type']} | risk={analysis['risk_score']} | conv_risk={conv_risk_state.get('risk_score', 0)} | escalation={analysis.get('escalation_label', 'SAFE')}")

    # STEP 3: Update conversation-level risk state with memory & response mode
    response_mode = analysis.get("response_mode", "NORMAL")
    allow_deescalation = (response_mode == "EDUCATIONAL")
    updated_conv_risk = update_conversation_risk(
        conversation_id=conversation_id,
        classification=classification,
        threat_type=analysis["threat_type"],
        risk_score=analysis["risk_score"],
        categories=analysis.get("categories", []),
        prompt_preview=user_message[:80],
        response_mode=response_mode,
        allow_deescalation=allow_deescalation,
    )

    settings = _read_security_settings()
    warning_threshold = settings["warning_threshold"]
    block_threshold = settings["block_threshold"]

    # STEP 4: Update per-user consecutive count
    if classification == "MALICIOUS":
        state["consecutive_count"] = state.get("consecutive_count", 0) + 1
        count = state["consecutive_count"]
    else:
        count = state.get("consecutive_count", 0)
        if classification == "SAFE":
            state["consecutive_count"] = 0
            state["blocked_until"] = None
            count = 0

    # Determine action thresholds
    # Default action depends on classification — SAFE prompts are simply ALLOWED
    if classification == "SAFE":
        current_action = "ALLOWED"
    elif classification == "SUSPICIOUS":
        current_action = "MONITORED"
    else:
        current_action = "THREAT_RECORDED"
    blocked_until = None

    policies = get_policies()
    auto_block_enabled = policies.get("auto_block_on_critical", True)

    if classification == "MALICIOUS" and count >= warning_threshold:
        current_action = "ADMIN_ALERTED"
    if classification == "MALICIOUS" and count > warning_threshold:
        current_action = "THREAT_ESCALATED"
    if classification == "MALICIOUS" and count >= block_threshold and auto_block_enabled:
        blocked_until = (datetime.now() + timedelta(minutes=settings["block_cooldown_minutes"])).isoformat()
        state["blocked_until"] = blocked_until
        state["blocked_at"] = datetime.now().isoformat()
        state["block_reason"] = f"{count} consecutive malicious prompts detected."
        state["blocked_by"] = "SENTINEL"
        state["block_source"] = "automatic"
        current_action = "CHAT_TEMPORARILY_BLOCKED"
    elif classification == "MALICIOUS" and count >= block_threshold and not auto_block_enabled:
        current_action = "ADMIN_APPROVAL_REQUIRED"
    if classification == "MALICIOUS" and count >= max(warning_threshold, block_threshold - 1):
        analysis["severity"] = "CRITICAL"
    _save_chat_activity(username, state)

    # -----------------------------------------------------------------------
    # STEP 6: CONTEXT-AWARE RESPONSE GENERATION (Requirements 1, 2, 3, 5, 10)
    # The classifier does not produce a generic refusal.
    # The response layer generates the response based on:
    #   Current Prompt + Previous Conversation + Security Analysis + Intent Progression
    # Internal response modes: NORMAL, EDUCATIONAL, CLARIFICATION,
    # SAFE_REDIRECT, HONEYPOT, HIGH_RISK, BLOCKED.
    # The user NEVER sees classification labels, risk scores, or detection reasons.
    # -----------------------------------------------------------------------
    if current_action == "CHAT_TEMPORARILY_BLOCKED":
        effective_mode = "BLOCKED"
    else:
        effective_mode = analysis.get("response_mode", "NORMAL")
    analysis["response_mode"] = effective_mode

    reply = generate_chat_response(
        current_prompt=user_message,
        conversation_history=prior_messages,
        analysis=analysis,
        conv_risk_state=updated_conv_risk,
        groq_api_key=GROQ_API_KEY,
    )

    request_id = str(uuid.uuid4())[:8].upper()
    event_timestamp = datetime.now().isoformat()
    analysis["action"] = current_action
    update_user_risk(
        username,
        analysis,
        is_malicious=(classification == "MALICIOUS"),
        conversation_id=conversation_id,
        request_id=request_id,
        timestamp=event_timestamp,
    )

    alert_record = None
    if analysis.get("admin_alert"):
        alert_record = create_alert(
            user=username,
            threat_type=analysis["threat_type"],
            severity=analysis["severity"],
            confidence=analysis["confidence"],
            risk_score=analysis["risk_score"],
            action=current_action,
            prompt_preview=user_message[:200],
            reason=analysis.get("reason", ""),
            request_id=request_id,
            session_id=session_id,
            categories=analysis.get("categories", []),
            conversation_id=conversation_id,
            timestamp=event_timestamp,
            recommended_action=analysis.get("recommended_action", "Review Required"),
        )
        audit_log(
            admin="SENTINEL",
            action="HIGH_RISK_ALERT_TRIGGERED",
            target=username,
            reason=f"Alert {alert_record['alert_id']}: {analysis['threat_type']} (Risk: {analysis['risk_score']})",
            extra={
                "alert_id": alert_record["alert_id"],
                "request_id": request_id,
                "conversation_id": conversation_id,
                "risk_score": analysis["risk_score"],
                "severity": analysis["severity"],
                "threat_type": analysis["threat_type"],
                "action": current_action,
            }
        )

    # Build enriched admin intelligence fields (stored in log/DB, never sent to user)
    admin_intel = {
        "user_id": username,
        "conversation_id": conversation_id,
        "request_id": request_id,
        "timestamp": event_timestamp,
        "classification": classification,
        "severity": analysis["severity"],
        "risk_score": analysis["risk_score"],
        "confidence": analysis["confidence"],
        "consecutive_count": count,
        "repeated_malicious_activity": count >= warning_threshold,
        "latest_prompt_preview": user_message[:120],
        "current_action": current_action,
        "client_ip": http_request.client.host if http_request.client else None,
        "conversation_risk_score": updated_conv_risk.get("risk_score", 0),
        "escalation_level": updated_conv_risk.get("escalation_level", 0),
        "escalation_label": updated_conv_risk.get("escalation_label", "SAFE"),
        "conversation_suspicious_count": updated_conv_risk.get("suspicious_count", 0),
        "conversation_malicious_count": updated_conv_risk.get("malicious_count", 0),
        "honeypot_active": updated_conv_risk.get("honeypot_active", False),
        "intent_indicators": analysis.get("intent_indicators", []),
        "context_escalated": analysis.get("context_escalated", False),
        "threat_categories": updated_conv_risk.get("threat_categories", []),
        "intent_progression": updated_conv_risk.get("intent_progression", [])[-3:],
        "response_mode": effective_mode,
        "admin_alert_fired": bool(alert_record),
    }

    log_event(
        user_message, analysis, reply, session_id, username, admin_intel,
        request_id=request_id, timestamp=event_timestamp,
    )
    add_message(
        conversation_id, username, user_message, reply,
        classification, analysis["threat_type"], analysis["severity"],
        analysis["confidence"], analysis["risk_score"], current_action,
        analysis.get("reason", ""), request_id=request_id, timestamp=event_timestamp,
    )

    activity_event = {
        "request_id": request_id,
        "conversation_id": conversation_id,
        "user": username,
        "classification": classification,
        "threat_type": analysis["threat_type"],
        "severity": analysis["severity"],
        "risk_score": analysis["risk_score"],
        "confidence": analysis["confidence"],
        "action": current_action,
        "timestamp": event_timestamp,
    }
    if alert_record:
        activity_event["alert_id"] = alert_record["alert_id"]
        activity_event["status"] = alert_record["status"]
        await alert_broker.broadcast({
            "type": "SECURITY_ALERT",
            "activity": activity_event,
            "alert": {
                **alert_record,
                "severity_icon": "🔴" if alert_record["severity"] in ("CRITICAL", "HIGH") else "🟠",
                "prompt_preview": user_message[:150],
            },
        })
    else:
        await alert_broker.broadcast({"type": "CHAT_ACTIVITY", "activity": activity_event})

    return {
        "response": reply,
        "conversation_id": conversation_id,
        "consecutive_count": count,
        "warning_threshold": warning_threshold,
        "block_threshold": block_threshold,
        "warning": count >= warning_threshold,
        "blocked_until": blocked_until,
        "current_action": current_action,
    }


# ===========================================================================
# SOC API ROUTES
# ===========================================================================

# --- Pydantic models for SOC ---
class AlertStatusUpdate(BaseModel):
    status: str
    note: str = ""

class IncidentCreate(BaseModel):
    title: str
    severity: str
    description: str
    related_alert_ids: Optional[List[str]] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    note: Optional[str] = None

class PoliciesUpdate(BaseModel):
    warning_threshold: Optional[int] = None
    block_threshold: Optional[int] = None
    block_cooldown_minutes: Optional[int] = None
    suspicious_ml_threshold: Optional[float] = None
    malicious_ml_threshold: Optional[float] = None
    alert_severity_threshold: Optional[str] = None
    rate_limit_chat_per_minute: Optional[int] = None
    rate_limit_auth_per_minute: Optional[int] = None
    session_timeout_minutes: Optional[int] = None
    auto_block_on_critical: Optional[bool] = None
    auto_alert_on_repeated: Optional[bool] = None
    repeated_attack_window_minutes: Optional[int] = None
    repeated_attack_count: Optional[int] = None

class TestPromptRequest(BaseModel):
    prompt: str

# --- Security Command Center ---
@app.get("/api/soc/command-center")
async def soc_command_center(current_user: dict = Depends(get_current_user_obj)):
    from collections import Counter
    logs = _read_logs()
    users = _read_users()
    activity = _read_activity()
    now = datetime.now()
    def in_window(entry, hours):
        try:
            return (now - datetime.fromisoformat(entry["timestamp"])).total_seconds() < hours * 3600
        except Exception:
            return False
    total_users = len(users)
    active_users = sum(1 for u in users.values() if u.get("is_active", True) and not u.get("is_blocked", False))
    suspended = sum(1 for u in users.values() if u.get("is_blocked", False) or u.get("is_active") is False)
    chat_blocked = sum(1 for s in activity.values() if s.get("blocked_until") and datetime.fromisoformat(s["blocked_until"]) > now)
    real_logs = [l for l in logs if not l.get("is_test")]
    total_prompts = len(real_logs)
    safe = sum(1 for l in real_logs if l.get("classification") == "SAFE")
    suspicious = sum(1 for l in real_logs if l.get("classification") == "SUSPICIOUS")
    malicious = sum(1 for l in real_logs if l.get("classification") == "MALICIOUS")
    critical = sum(1 for l in real_logs if l.get("severity") == "CRITICAL")
    threat_classes = {"MALICIOUS", "SUSPICIOUS"}
    last24 = sum(1 for l in real_logs if in_window(l, 24) and l.get("classification") in threat_classes)
    last7d = sum(1 for l in real_logs if in_window(l, 168) and l.get("classification") in threat_classes)
    last30d = sum(1 for l in real_logs if in_window(l, 720) and l.get("classification") in threat_classes)
    alerts_data = get_alerts(page=1, page_size=1000, exclude_test=True)
    active_alerts = sum(1 for a in alerts_data["items"] if a.get("status") in ("NEW", "INVESTIGATING"))
    system_status = "CRITICAL" if critical > 0 else "WARNING" if malicious > 0 else "NOMINAL"
    return {
        "total_users": total_users, "active_users": active_users, "suspended_users": suspended,
        "chat_blocked_users": chat_blocked, "total_prompts": total_prompts,
        "safe": safe, "suspicious": suspicious, "malicious": malicious, "critical": critical,
        "threats_24h": last24, "threats_7d": last7d, "threats_30d": last30d,
        "active_alerts": active_alerts, "system_status": system_status,
    }

# --- SOC Alerts ---
@app.get("/api/soc/alerts")
async def soc_get_alerts(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    severity: str = "", status: str = "", user: str = "",
    exclude_test: bool = True,
    _admin: dict = Depends(admin_required)
):
    return get_alerts(page=page, page_size=page_size, severity_filter=severity,
                      status_filter=status, user_filter=user, exclude_test=exclude_test)

@app.patch("/api/soc/alerts/{alert_id}")
async def soc_update_alert(alert_id: str, body: AlertStatusUpdate, admin: dict = Depends(admin_required)):
    result = update_alert_status(alert_id, body.status, admin["username"], body.note)
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found or invalid status")
    audit_log(admin["username"], f"ALERT_STATUS_CHANGED_{body.status}", alert_id, body.note)
    return result

@app.get("/api/soc/alerts/stats")
async def soc_alert_stats(hours: int = Query(24, ge=1, le=720), _admin: dict = Depends(admin_required)):
    return get_alert_stats(hours=hours)

# --- Threat Intelligence ---
@app.get("/api/soc/threat-intelligence")
async def soc_threat_intelligence(hours: int = Query(24, ge=1, le=720), _admin: dict = Depends(admin_required)):
    return get_threat_intelligence(hours=hours)

# --- User Risk ---
@app.get("/api/soc/user-risk")
async def soc_all_user_risk(_admin: dict = Depends(admin_required)):
    users = _read_users()
    now = datetime.now()
    results = []
    for uname, udata in users.items():
        key = uname.casefold()
        risk = get_user_risk(key)
        state = _chat_activity(key)
        blocked_until = state.get("blocked_until")
        is_blocked_chat = False
        if blocked_until:
            try:
                is_blocked_chat = datetime.fromisoformat(blocked_until) > now
            except ValueError:
                is_blocked_chat = False
        is_account_blocked = bool(udata.get("is_blocked", False))

        results.append({
            "username": udata.get("username", uname),
            "full_name": udata.get("full_name", uname),
            "email": udata.get("email", ""),
            "role": udata.get("role", "User"),
            "is_active": udata.get("is_active", True),
            "is_blocked": is_account_blocked or is_blocked_chat,
            "created_at": udata.get("created_at"),
            "risk_score": risk.get("risk_score", 0),
            "risk_level": risk.get("risk_level", "LOW"),
            "malicious_count": risk.get("malicious_count", 0),
            "suspicious_count": risk.get("suspicious_count", 0),
            "consecutive_attacks": risk.get("consecutive_attacks", 0),
            "last_threat": risk.get("last_threat"),
            "last_threat_type": risk.get("last_threat_type"),
            "last_activity": risk.get("last_activity"),
            "last_classification": risk.get("last_classification"),
            "last_severity": risk.get("last_severity"),
            "last_risk_score": risk.get("last_risk_score"),
            "last_action": risk.get("last_action"),
            "last_conversation_id": risk.get("last_conversation_id"),
            "last_request_id": risk.get("last_request_id"),
            "total_prompts": risk.get("total_prompts", 0),
            "blocked_until": state.get("blocked_until") if is_blocked_chat or is_account_blocked else None,
            "block_reason": state.get("block_reason"),
            "blocked_by": state.get("blocked_by"),
            "blocked_at": state.get("blocked_at"),
            "block_source": state.get("block_source"),
        })
    results.sort(key=lambda r: (r.get("risk_score", 0), 1 if r.get("is_blocked") else 0), reverse=True)
    return results

@app.get("/api/soc/user-risk/{username}")
async def soc_user_risk(username: str, admin: dict = Depends(admin_required)):
    key = username.casefold()
    if key not in _read_users():
        raise HTTPException(status_code=404, detail="User not found")
    risk = get_user_risk(username)
    logs = [l for l in reversed(_read_logs()) if l.get("user", "").casefold() == key][:50]
    activity = _read_activity().get(key, {})
    conversations = get_conversation_summaries(key)
    return {
        "risk": risk,
        "recent_logs": logs,
        "chat_activity": activity,
        "conversations": conversations,
    }


@app.get("/api/soc/user-risk/{username}/conversations/{conversation_id}")
async def soc_user_conversation(
    username: str,
    conversation_id: str,
    _admin: dict = Depends(admin_required),
):
    key = username.casefold()
    if key not in _read_users():
        raise HTTPException(status_code=404, detail="User not found")
    conversation = get_conversation(conversation_id, key)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {
        "conversation": conversation,
        "messages": get_messages(conversation_id, key),
    }

@app.post("/api/soc/user-risk/{username}/reset")
async def soc_reset_user_risk(username: str, admin: dict = Depends(admin_required)):
    key = username.casefold()
    if key not in _read_users():
        raise HTTPException(status_code=404, detail="User not found")
    result = reset_user_risk(username)
    audit_log(admin["username"], "USER_RISK_RESET", username)
    return result

# --- Incidents ---
@app.get("/api/soc/incidents")
async def soc_get_incidents(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    status: str = "",
    _admin: dict = Depends(admin_required)
):
    return get_incidents(page=page, page_size=page_size, status_filter=status)

@app.post("/api/soc/incidents", status_code=201)
async def soc_create_incident(body: IncidentCreate, admin: dict = Depends(admin_required)):
    inc = create_incident(admin["username"], body.title, body.severity, body.description, body.related_alert_ids)
    audit_log(admin["username"], "INCIDENT_CREATED", inc["incident_id"], body.description[:100])
    return inc

@app.patch("/api/soc/incidents/{incident_id}")
async def soc_update_incident(incident_id: str, body: IncidentUpdate, admin: dict = Depends(admin_required)):
    updates = body.model_dump(exclude_none=True)
    result = update_incident(incident_id, admin["username"], updates)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    audit_log(admin["username"], f"INCIDENT_UPDATED", incident_id, updates.get("note", ""))
    return result

# --- Admin Audit Log ---
@app.get("/api/soc/audit")
async def soc_get_audit(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    action: str = "",
    _admin: dict = Depends(admin_required)
):
    return get_audit_logs(page=page, page_size=page_size, action_filter=action)

# --- Security Policies ---
@app.get("/api/soc/policies")
async def soc_get_policies(_admin: dict = Depends(admin_required)):
    return get_policies()

@app.patch("/api/soc/policies")
async def soc_update_policies(body: PoliciesUpdate, admin: dict = Depends(admin_required)):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No policy changes provided")
    if "warning_threshold" in updates and "block_threshold" in updates:
        if updates["block_threshold"] <= updates["warning_threshold"]:
            raise HTTPException(status_code=400, detail="Block threshold must exceed warning threshold")
    result = update_policies(updates)
    # Also sync to legacy security_settings.json
    legacy = {}
    for k in ("warning_threshold", "block_threshold", "block_cooldown_minutes"):
        if k in result:
            legacy[k] = result[k]
    if legacy:
        _write_security_settings({**_read_security_settings(), **legacy})
    audit_log(admin["username"], "POLICIES_UPDATED", "", str(updates)[:300])
    return result

# --- Model Monitoring ---
@app.get("/api/soc/model")
async def soc_model_info(_admin: dict = Depends(admin_required)):
    return get_model_info()

# --- Security Testing Center ---
@app.post("/api/soc/test-prompt")
async def soc_test_prompt(body: TestPromptRequest, admin: dict = Depends(admin_required)):
    prompt = body.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    if len(prompt) > 2000:
        raise HTTPException(status_code=400, detail="Test prompt too long (max 2000 chars)")
    analysis = _analyze_prompt(prompt)
    # Log as test event — does NOT affect user analytics
    entry = log_event(prompt, analysis, "[TEST EVENT]", "test-session", admin["username"], {"is_test": True})
    audit_log(admin["username"], "SECURITY_TEST_PROMPT", "", prompt[:120])
    return {
        "classification": analysis["classification"],
        "threat_type": analysis["threat_type"],
        "severity": analysis["severity"],
        "confidence": analysis["confidence"],
        "risk_score": analysis["risk_score"],
        "action": analysis["action"],
        "reason": analysis["reason"],
        "categories": analysis["categories"],
        "escalation_label": analysis.get("escalation_label", "SAFE"),
        "context_escalated": analysis.get("context_escalated", False),
        "intent_indicators": analysis.get("intent_indicators", []),
        "is_test": True,
        "request_id": entry["request_id"],
    }

# --- Reports ---
@app.get("/api/soc/reports/summary")
async def soc_report_summary(hours: int = Query(24, ge=1, le=720), _admin: dict = Depends(admin_required)):
    intel = get_threat_intelligence(hours=hours)
    users = _read_users()
    risks = get_all_user_risks()
    high_risk = [r for r in risks if r.get("risk_score", 0) >= 50]
    alerts_data = get_alerts(page=1, page_size=1000, exclude_test=True)
    incidents_data = get_incidents(page=1, page_size=1000)
    return {
        "generated_at": datetime.now().isoformat(),
        "window_hours": hours,
        "threat_summary": intel,
        "total_users": len(users),
        "high_risk_users": len(high_risk),
        "open_alerts": sum(1 for a in alerts_data["items"] if a.get("status") in ("NEW", "INVESTIGATING")),
        "open_incidents": sum(1 for i in incidents_data["items"] if i.get("status") not in ("RESOLVED", "CLOSED")),
        "model_info": get_model_info(),
        "top_risk_users": high_risk[:10],
    }

@app.get("/api/soc/reports/csv")
async def soc_report_csv(hours: int = Query(24, ge=1, le=720), _admin: dict = Depends(admin_required)):
    import csv, io
    from fastapi.responses import StreamingResponse
    logs = [l for l in _read_logs() if not l.get("is_test")]
    cutoff = datetime.now() - timedelta(hours=hours)
    recent = [l for l in logs if datetime.fromisoformat(l["timestamp"]) >= cutoff]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "request_id", "timestamp", "user", "classification", "threat_type",
        "severity", "confidence", "risk_score", "action", "reason", "prompt_preview"
    ])
    writer.writeheader()
    for row in recent:
        writer.writerow({k: row.get(k, "") for k in writer.fieldnames})
    output.seek(0)
    filename = f"honeyprompt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})


# ===========================================================================
# REPORT & EXPORT CENTER ENDPOINTS (ADMIN)
# ===========================================================================

@app.get("/api/admin/reports/security")
async def admin_report_security_overview(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    classification: str | None = Query(None),
    severity: str | None = Query(None),
    threat_type: str | None = Query(None),
    user: str | None = Query(None),
    action: str | None = Query(None),
    _admin: dict = Depends(admin_required),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to,
        "classification": classification, "severity": severity,
        "threat_type": threat_type, "user": user, "action": action,
    }
    return build_security_overview_report(filters)


@app.get("/api/admin/reports/threats")
async def admin_report_threat_intelligence(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    severity: str | None = Query(None),
    threat_type: str | None = Query(None),
    user: str | None = Query(None),
    _admin: dict = Depends(admin_required),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to,
        "severity": severity, "threat_type": threat_type, "user": user,
    }
    return build_threat_intelligence_report(filters)


@app.get("/api/admin/reports/users")
async def admin_report_user_security(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    user: str | None = Query(None),
    _admin: dict = Depends(admin_required),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to, "user": user,
    }
    return build_user_security_report(filters)


@app.get("/api/admin/reports/audit")
async def admin_report_audit_log(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    action: str | None = Query(None),
    user: str | None = Query(None),
    _admin: dict = Depends(admin_required),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to,
        "action": action, "user": user,
    }
    return build_audit_log_report(filters)


@app.get("/api/admin/reports/incidents")
async def admin_report_incidents(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    _admin: dict = Depends(admin_required),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to,
        "status": status, "severity": severity,
    }
    return build_incidents_report(filters)


@app.get("/api/admin/reports/activity")
async def admin_report_chat_activity(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    user: str | None = Query(None),
    _admin: dict = Depends(admin_required),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to, "user": user,
    }
    return build_chat_activity_report(filters)


@app.get("/api/admin/reports/user-chats")
async def admin_report_user_chats(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    user: str | None = Query(None),
    classification: str | None = Query(None),
    severity: str | None = Query(None),
    threat_type: str | None = Query(None),
    action: str | None = Query(None),
    _admin: dict = Depends(admin_required),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to,
        "user": user, "classification": classification, "severity": severity,
        "threat_type": threat_type, "action": action,
    }
    return build_user_chats_report(filters)


@app.post("/api/admin/reports/pdf")
async def admin_export_pdf(req: ReportExportRequest, admin: dict = Depends(admin_required)):
    filters = req.model_dump()
    rtype = req.report_type

    if rtype == "security_overview":
        data = build_security_overview_report(filters)
    elif rtype == "threat_intelligence":
        data = build_threat_intelligence_report(filters)
    elif rtype == "user_security":
        data = build_user_security_report(filters)
    elif rtype == "audit_log":
        data = build_audit_log_report(filters)
    elif rtype == "incidents":
        data = build_incidents_report(filters)
    elif rtype == "chat_activity":
        data = build_chat_activity_report(filters)
    elif rtype == "user_chats":
        data = build_user_chats_report(filters)
    else:
        raise HTTPException(status_code=400, detail=f"Invalid report type: {rtype}")

    try:
        pdf_bytes = generate_pdf(rtype, data, generated_by=admin["username"], filters=filters)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to generate PDF report.")

    save_report_record(
        generated_by=admin["username"],
        role="admin",
        report_type=rtype,
        fmt="PDF",
        date_from=data.get("date_from", ""),
        date_to=data.get("date_to", ""),
        filters=filters,
        record_count=data.get("record_count", 0),
        status="SUCCESS",
    )
    audit_log(admin["username"], "GENERATE_REPORT_PDF", rtype, f"Generated {rtype} PDF report ({data.get('record_count', 0)} records)")

    filename = f"HoneyPrompt_{rtype.title().replace('_', '')}_Report_{datetime.now().strftime('%Y-%m-%d')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/api/admin/reports/excel")
async def admin_export_excel(req: ReportExportRequest, admin: dict = Depends(admin_required)):
    filters = req.model_dump()
    rtype = req.report_type

    if rtype == "security_overview":
        data = build_security_overview_report(filters)
    elif rtype == "threat_intelligence":
        data = build_threat_intelligence_report(filters)
    elif rtype == "user_security":
        data = build_user_security_report(filters)
    elif rtype == "audit_log":
        data = build_audit_log_report(filters)
    elif rtype == "incidents":
        data = build_incidents_report(filters)
    elif rtype == "chat_activity":
        data = build_chat_activity_report(filters)
    elif rtype == "user_chats":
        data = build_user_chats_report(filters)
    else:
        raise HTTPException(status_code=400, detail=f"Invalid report type: {rtype}")

    try:
        xlsx_bytes = generate_excel(rtype, data, generated_by=admin["username"], filters=filters)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to generate Excel report.")

    save_report_record(
        generated_by=admin["username"],
        role="admin",
        report_type=rtype,
        fmt="EXCEL",
        date_from=data.get("date_from", ""),
        date_to=data.get("date_to", ""),
        filters=filters,
        record_count=data.get("record_count", 0),
        status="SUCCESS",
    )
    audit_log(admin["username"], "GENERATE_REPORT_EXCEL", rtype, f"Generated {rtype} Excel report ({data.get('record_count', 0)} records)")

    filename = f"HoneyPrompt_{rtype.title().replace('_', '')}_Report_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/api/admin/reports/email")
async def admin_email_report(req: EmailReportRequest, admin: dict = Depends(admin_required)):
    if not req.recipient_email or "@" not in req.recipient_email:
        raise HTTPException(status_code=400, detail="Invalid recipient email address.")

    filters = req.model_dump()
    rtype = req.report_type

    try:
        if rtype == "security_overview":
            data = build_security_overview_report(filters)
        elif rtype == "threat_intelligence":
            data = build_threat_intelligence_report(filters)
        elif rtype == "user_security":
            data = build_user_security_report(filters)
        elif rtype == "audit_log":
            data = build_audit_log_report(filters)
        elif rtype == "incidents":
            data = build_incidents_report(filters)
        elif rtype == "chat_activity":
            data = build_chat_activity_report(filters)
        elif rtype == "user_chats":
            data = build_user_chats_report(filters)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid report type: {rtype}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unable to generate report data: {e}")

    fmt = (req.format or "PDF").upper()
    try:
        if fmt == "EXCEL":
            attachment_bytes = generate_excel(rtype, data, generated_by=admin["username"], filters=filters)
            filename = f"HoneyPrompt_{rtype.title().replace('_', '')}_Report_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        else:
            attachment_bytes = generate_pdf(rtype, data, generated_by=admin["username"], filters=filters)
            filename = f"HoneyPrompt_{rtype.title().replace('_', '')}_Report_{datetime.now().strftime('%Y-%m-%d')}.pdf"
            content_type = "application/pdf"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unable to generate report file: {e}")

    try:
        send_report_email(
            to_email=req.recipient_email,
            subject=req.subject or f"HoneyPrompt Sentinel Security Report — {rtype.replace('_', ' ').title()}",
            message=req.message or f"Attached is your generated {fmt} security report for window: {data.get('date_from')} to {data.get('date_to')}.",
            attachment_bytes=attachment_bytes,
            filename=filename,
            content_type=content_type,
            cc_email=req.cc_email,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unable to send email: {e}")

    save_report_record(
        generated_by=admin["username"],
        role="admin",
        report_type=rtype,
        fmt=f"EMAIL_{fmt}",
        date_from=data.get("date_from", ""),
        date_to=data.get("date_to", ""),
        filters=filters,
        record_count=data.get("record_count", 0),
        status="SUCCESS",
    )
    audit_log(admin["username"], f"EMAIL_REPORT_{fmt}", rtype, f"Sent {rtype} report to {req.recipient_email}")

    return {
        "status": "success",
        "message": f"Report generated and emailed successfully to {req.recipient_email}.",
        "recipient": req.recipient_email,
        "format": fmt,
        "record_count": data.get("record_count", 0)
    }


@app.get("/api/admin/reports/history")
async def admin_reports_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    admin: dict = Depends(admin_required),
):
    return get_report_history(admin["username"], role="admin", page=page, page_size=page_size)


# ===========================================================================
# REPORT & EXPORT CENTER ENDPOINTS (USER)
# ===========================================================================

@app.get("/api/user/reports/security")
async def user_report_personal_security(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    current_user: dict = Depends(get_current_user_obj),
):
    filters = {"date_range": date_range, "date_from": date_from, "date_to": date_to}
    return build_personal_security_report(current_user["username"], filters)


@app.get("/api/user/reports/history")
async def user_report_security_history(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    classification: str | None = Query(None),
    severity: str | None = Query(None),
    threat_type: str | None = Query(None),
    current_user: dict = Depends(get_current_user_obj),
):
    filters = {
        "date_range": date_range, "date_from": date_from, "date_to": date_to,
        "classification": classification, "severity": severity, "threat_type": threat_type,
    }
    return build_user_security_history_report(current_user["username"], filters)


@app.get("/api/user/reports/activity")
async def user_report_chat_activity(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    current_user: dict = Depends(get_current_user_obj),
):
    filters = {"date_range": date_range, "date_from": date_from, "date_to": date_to}
    return build_user_chat_activity_report(current_user["username"], filters)


@app.get("/api/user/reports/alerts")
async def user_report_alerts(
    date_range: str = Query("30d"),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    severity: str | None = Query(None),
    current_user: dict = Depends(get_current_user_obj),
):
    filters = {"date_range": date_range, "date_from": date_from, "date_to": date_to, "severity": severity}
    return build_user_alerts_report(current_user["username"], filters)


@app.post("/api/user/reports/pdf")
async def user_export_pdf(req: ReportExportRequest, current_user: dict = Depends(get_current_user_obj)):
    filters = req.model_dump()
    rtype = req.report_type
    username = current_user["username"]

    if rtype == "personal_security":
        data = build_personal_security_report(username, filters)
    elif rtype == "security_history":
        data = build_user_security_history_report(username, filters)
    elif rtype == "my_chat_activity":
        data = build_user_chat_activity_report(username, filters)
    elif rtype == "security_alerts":
        data = build_user_alerts_report(username, filters)
    else:
        raise HTTPException(status_code=400, detail=f"Invalid user report type: {rtype}")

    try:
        pdf_bytes = generate_pdf(rtype, data, generated_by=username, filters=filters)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to generate PDF report.")

    save_report_record(
        generated_by=username,
        role="user",
        report_type=rtype,
        fmt="PDF",
        date_from=data.get("date_from", ""),
        date_to=data.get("date_to", ""),
        filters=filters,
        record_count=data.get("record_count", 0),
        status="SUCCESS",
    )

    filename = f"HoneyPrompt_User_{rtype.title().replace('_', '')}_{datetime.now().strftime('%Y-%m-%d')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/api/user/reports/excel")
async def user_export_excel(req: ReportExportRequest, current_user: dict = Depends(get_current_user_obj)):
    filters = req.model_dump()
    rtype = req.report_type
    username = current_user["username"]

    if rtype == "personal_security":
        data = build_personal_security_report(username, filters)
    elif rtype == "security_history":
        data = build_user_security_history_report(username, filters)
    elif rtype == "my_chat_activity":
        data = build_user_chat_activity_report(username, filters)
    elif rtype == "security_alerts":
        data = build_user_alerts_report(username, filters)
    else:
        raise HTTPException(status_code=400, detail=f"Invalid user report type: {rtype}")

    try:
        xlsx_bytes = generate_excel(rtype, data, generated_by=username, filters=filters)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to generate Excel report.")

    save_report_record(
        generated_by=username,
        role="user",
        report_type=rtype,
        fmt="EXCEL",
        date_from=data.get("date_from", ""),
        date_to=data.get("date_to", ""),
        filters=filters,
        record_count=data.get("record_count", 0),
        status="SUCCESS",
    )

    filename = f"HoneyPrompt_User_{rtype.title().replace('_', '')}_{datetime.now().strftime('%Y-%m-%d')}.xlsx"
    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/user/reports/generation-history")
async def user_reports_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user_obj),
):
    return get_report_history(current_user["username"], role="user", page=page, page_size=page_size)

@app.get("/api/soc/restrictions")
async def soc_active_restrictions(_admin: dict = Depends(admin_required)):
    activity = _read_activity()
    users = _read_users()
    now = datetime.now()
    result = []
    for key, user in users.items():
        state = activity.get(key, {})
        blocked_until = state.get("blocked_until")
        is_chat_blocked = False
        if blocked_until:
            try:
                is_chat_blocked = datetime.fromisoformat(blocked_until) > now
            except Exception:
                is_chat_blocked = False
        is_acc_blocked = bool(user.get("is_blocked", False))
        if is_chat_blocked or is_acc_blocked:
            result.append({
                "username": user.get("username", key),
                "email": user.get("email", ""),
                "blocked_until": blocked_until if is_chat_blocked else ("2099-12-31T23:59:59" if is_acc_blocked else None),
                "blocked_at": state.get("blocked_at"),
                "block_reason": state.get("block_reason", "Administrative restriction"),
                "blocked_by": state.get("blocked_by", "SENTINEL"),
                "block_source": state.get("block_source", "manual" if is_acc_blocked else "automatic"),
                "consecutive_count": state.get("consecutive_count", 0),
            })
    return result


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
