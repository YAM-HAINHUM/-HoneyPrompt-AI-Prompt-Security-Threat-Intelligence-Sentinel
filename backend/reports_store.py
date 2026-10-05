"""
reports_store.py — Report generation history for HoneyPrompt Sentinel.
Stores metadata about every generated report (no file content, just metadata).
"""
import json
import os
import uuid
from datetime import datetime

REPORTS_FILE = "report_history.json"


def _read():
    if not os.path.exists(REPORTS_FILE):
        return []
    try:
        with open(REPORTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _write(data):
    with open(REPORTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_report_record(
    generated_by: str,
    role: str,
    report_type: str,
    fmt: str,
    date_from: str,
    date_to: str,
    filters: dict,
    record_count: int,
    status: str = "SUCCESS",
) -> dict:
    record = {
        "report_id": "RPT-" + str(uuid.uuid4())[:8].upper(),
        "generated_by": generated_by,
        "role": role,
        "report_type": report_type,
        "format": fmt,
        "date_from": date_from,
        "date_to": date_to,
        "filters": filters,
        "record_count": record_count,
        "status": status,
        "generated_at": datetime.now().isoformat(),
    }
    records = _read()
    records.append(record)
    _write(records)
    return record


def get_report_history(username: str, role: str, page: int = 1, page_size: int = 20) -> dict:
    records = list(reversed(_read()))
    if role.casefold() != "admin":
        records = [r for r in records if r.get("generated_by", "").casefold() == username.casefold()]
    total = len(records)
    offset = (page - 1) * page_size
    return {"items": records[offset: offset + page_size], "total": total, "page": page, "page_size": page_size}
