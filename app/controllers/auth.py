from flask import Blueprint, current_app, g, jsonify, request

from ..extensions import db
from ..models import User
from ..services.audit import record
from ..services.auth import AuthError, api_auth_required, authenticate, register_user
from ..services.ratelimit import rate_limited
from ..services.security import (
    PasswordPolicyError,
    consume_refresh_token,
    create_access_token,
    issue_refresh_token,
    revoke_all_refresh_tokens,
    revoke_refresh_token,
)
from ..utils import clean_text, json_error, normalise_email, require_json

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

def _token_response(user: User) -> dict:
    access = create_access_token(user)
    refresh = issue_refresh_token(user)
    db.session.commit()
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": current_app.config["ACCESS_TOKEN_TTL"],
        "user": user.to_dict(),
    }


@bp.post("/register")
@rate_limited(10, 60)
def register():
    data = require_json()
    email = normalise_email(data.get("email"))
    full_name = clean_text(data.get("full_name"), 120)
    if email is None:
        return json_error("A valid email address is required", 400)
    if full_name is None:
        return json_error("full_name is required (max 120 characters)", 400)
    try:
        user = register_user(email, full_name, data.get("password"))   # self-service accounts are patients
    except PasswordPolicyError as exc:
        return json_error(str(exc), 400)
    except AuthError as exc:
        return json_error(exc.message, exc.status)
    db.session.commit()
    return jsonify(user.to_dict()), 201


@bp.post("/login")
@rate_limited(20, 60)
def login():
    data = require_json()
    email = normalise_email(data.get("email"))
    password = data.get("password")
    if email is None or not isinstance(password, str):
        return json_error("Invalid email or password", 401)
    try:
        user = authenticate(email, password)
    except AuthError as exc:
        db.session.commit()      # persist the failed-login audit row
        return json_error(exc.message, exc.status)
    return jsonify(_token_response(user)), 200


@bp.post("/refresh")
@rate_limited(30, 60)
def refresh():
    data = require_json()
    user = consume_refresh_token(data.get("refresh_token"))
    if user is None:
        db.session.rollback()
        return json_error("Invalid or expired refresh token", 401)
    return jsonify(_token_response(user)), 200


@bp.post("/logout")
@api_auth_required()
def logout():
    data = request.get_json(silent=True) or {}
    if data.get("everywhere"):
        revoke_all_refresh_tokens(g.current_user)
    else:
        revoke_refresh_token(data.get("refresh_token"))
    record("auth.logout")
    db.session.commit()
    return "", 204


@bp.get("/me")
@api_auth_required()
def me():
    return jsonify(g.current_user.to_dict())
