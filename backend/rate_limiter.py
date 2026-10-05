"""rate_limiter.py — Simple in-memory sliding-window rate limiter."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock

_buckets: dict[str, deque] = defaultdict(deque)
_lock = Lock()


def is_rate_limited(key: str, max_requests: int, window_seconds: int = 60) -> bool:
    """Return True if key has exceeded max_requests in the last window_seconds."""
    now = datetime.now()
    cutoff = now - timedelta(seconds=window_seconds)
    with _lock:
        dq = _buckets[key]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= max_requests:
            return True
        dq.append(now)
        return False


def get_request_count(key: str, window_seconds: int = 60) -> int:
    now = datetime.now()
    cutoff = now - timedelta(seconds=window_seconds)
    with _lock:
        dq = _buckets[key]
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)
