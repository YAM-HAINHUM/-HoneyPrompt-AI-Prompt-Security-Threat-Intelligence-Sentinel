"""Canonical paths for backend JSON stores."""

import json
import os
import uuid
from pathlib import Path
from typing import Any


DATA_DIR = Path(__file__).resolve().parent


def data_file(name: str) -> str:
    return str(DATA_DIR / name)


def read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as store:
            return json.load(store)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"JSON data store is invalid: {path}") from exc


def write_json(path: str, data: Any, *, ensure_ascii: bool = True) -> None:
    destination = Path(path)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(temporary, "w", encoding="utf-8") as store:
            json.dump(data, store, indent=2, ensure_ascii=ensure_ascii)
            store.flush()
            os.fsync(store.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
