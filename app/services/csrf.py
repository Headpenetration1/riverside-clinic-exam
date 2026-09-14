"""CSRF protection for the HTML forms (double-check against the signed session).

The JSON API does not need this: it only accepts Bearer tokens from a header
and requires a JSON content type, which browsers will not send cross-site
from a plain form.
"""
import hmac
import secrets

from flask import abort, request, session


def csrf_token() -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def validate_csrf() -> None:
    expected = session.get("csrf")
    supplied = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(400, description="Invalid or missing CSRF token")
