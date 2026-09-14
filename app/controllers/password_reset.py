"""Account recovery (Task A.3.3) - the JSON API.

The rules live in services/password_reset.py and are shared with the HTML
pages in controllers/pages.py. The forgot-password response is identical
whether or not the email exists.
"""
from flask import Blueprint, jsonify

from ..services import password_reset as recovery
from ..services.ratelimit import rate_limited
from ..services.security import PasswordPolicyError
from ..utils import json_error, normalise_email, require_json

bp = Blueprint("password_reset", __name__, url_prefix="/api/auth")

FORGOT_RESPONSE = {"message": recovery.GENERIC_MESSAGE}


@bp.post("/forgot-password")
@rate_limited(5, 300)
def forgot_password():
    data = require_json()
    email = normalise_email(data.get("email"))
    if email is not None:
        recovery.request_reset(email)
    return jsonify(FORGOT_RESPONSE), 200         # same answer, no enumeration


@bp.post("/reset-password")
@rate_limited(10, 300)
def reset_password():
    data = require_json()
    try:
        recovery.reset_password(data.get("token"), data.get("new_password"))
    except (recovery.ResetTokenError, PasswordPolicyError) as exc:
        return json_error(str(exc), 400)
    return jsonify({"message": "Password updated. Please log in again."}), 200
