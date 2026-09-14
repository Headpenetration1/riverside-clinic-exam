"""A small fixed-window rate limiter.

In-memory, per process, which is fine for a single instance and for tests.
A real deployment would swap the storage for Redis (e.g. Flask-Limiter) so
the limits hold across workers.
"""
import threading
import time
from functools import wraps

from flask import current_app, jsonify, request
from werkzeug.exceptions import TooManyRequests


class RateLimiter:
    def __init__(self):
        self._buckets: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int) -> bool:
        """Record one hit; return True if still within the limit."""
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= window:
                start, count = now, 0
            count += 1
            self._buckets[key] = (start, count)
        return count <= limit

    def hits(self, key: str, window: int) -> int:
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
        return 0 if now - start >= window else count

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


def get_limiter() -> RateLimiter:
    return current_app.extensions["limiter"]


def rate_limited(limit: int, window: int, key_func=None, *, scope: str | None = None,
                 methods: tuple[str, ...] | None = None):
    """Limit matching requests by IP or a caller-provided identity.

    Views with the same explicit ``scope`` share a bucket, which lets JSON and
    HTML versions of one operation enforce a single quota. ``methods`` can
    exclude read-only requests on a combined GET/POST route.
    """
    limited_methods = frozenset(method.upper() for method in methods) if methods else None

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if limited_methods is not None and request.method not in limited_methods:
                return view(*args, **kwargs)
            ident = key_func() if key_func else request.remote_addr
            bucket = scope or f"{view.__module__}.{view.__name__}"
            key = f"{bucket}:{ident}"
            if not get_limiter().hit(key, limit, window):
                if not request.path.startswith("/api/"):    # HTML form: render the error page
                    raise TooManyRequests(description="Too many requests, slow down", retry_after=window)
                resp = jsonify({"error": "Too many requests, slow down"})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(window)
                return resp
            return view(*args, **kwargs)
        return wrapper
    return decorator
