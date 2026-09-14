"""Small helpers shared by controllers and services."""
import re
from datetime import datetime, timezone

from flask import abort, jsonify, request

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


def utcnow() -> datetime:
    """Naive UTC timestamp. SQLite drops tzinfo, so we keep everything naive-UTC on purpose."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def json_error(message: str, status: int):
    return jsonify({"error": message}), status


def require_json() -> dict:
    """Return the JSON body as a dict or abort. Requiring JSON also blocks
    classic cross-site form posts from ever reaching the API handlers."""
    if not request.is_json:
        abort(415, description="Request body must be JSON")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description="Request body must be a JSON object")
    return data


def normalise_email(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL_RE.match(value):
        return None
    return value


def clean_text(value, max_len: int) -> str | None:
    """Strip, enforce a length limit and drop control characters (except newline/tab)."""
    if not isinstance(value, str):
        return None
    value = "".join(ch for ch in value if ch in "\n\t" or (ord(ch) >= 32 and ord(ch) != 127)).strip()
    if not value or len(value) > max_len:
        return None
    return value


def client_ip() -> str:
    # Behind a reverse proxy this should come from ProxyFix / X-Forwarded-For.
    return request.remote_addr or "unknown"
