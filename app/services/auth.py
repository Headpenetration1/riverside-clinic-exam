"""Registration, login and the two auth decorators.

Two decorators because the JSON API and the HTML pages authenticate
differently on purpose:
- API: `Authorization: Bearer <jwt>` only. Cookies are ignored, so a
  cross-site request can never be authenticated by accident.
- Pages: HttpOnly cookie only, with CSRF tokens on every form.
"""
from functools import wraps

from flask import current_app, g, jsonify, redirect, request, url_for
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import User
from .audit import record
from .ratelimit import get_limiter
from .security import (
    check_password_policy,
    decode_access_token,
    hash_password,
    needs_rehash,
    verify_password,
)

FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW = 300   # seconds
GENERIC_LOGIN_ERROR = "Invalid email or password"


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def register_user(email: str, full_name: str, password: str, role: str = "patient") -> User:
    check_password_policy(password, email)          # raises PasswordPolicyError
    user = User(email=email, full_name=full_name, role=role, password_hash=hash_password(password))
    db.session.add(user)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        raise AuthError("An account with that email already exists", 409) from None
    record("auth.register", target=email, user=user)
    return user


def _dummy_hash() -> str:
    # one hash per app so that "unknown user" takes as long as "wrong password"
    ext = current_app.extensions
    if "dummy_hash" not in ext:
        ext["dummy_hash"] = hash_password("not-a-real-password-just-for-timing")
    return ext["dummy_hash"]


def authenticate(email: str, password: str) -> User:
    """Return the user or raise AuthError. Same message for every failure."""
    limiter = get_limiter()
    fail_key = f"login-fail:{email}"
    if limiter.hits(fail_key, FAILED_LOGIN_WINDOW) >= FAILED_LOGIN_LIMIT:
        raise AuthError("Too many failed attempts for this account, try again later", 429)

    user = db.session.scalar(db.select(User).where(User.email == email))
    if user is None:
        verify_password(_dummy_hash(), password)
        limiter.hit(fail_key, FAILED_LOGIN_LIMIT, FAILED_LOGIN_WINDOW)
        record("auth.login_failed", target=email, user=None)
        raise AuthError(GENERIC_LOGIN_ERROR, 401)

    if not verify_password(user.password_hash, password) or not user.is_active:
        limiter.hit(fail_key, FAILED_LOGIN_LIMIT, FAILED_LOGIN_WINDOW)
        record("auth.login_failed", target=email, user=None)
        raise AuthError(GENERIC_LOGIN_ERROR, 401)

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)   # transparent parameter upgrade
    record("auth.login", user=user)
    return user


def user_from_token(token: str | None) -> User | None:
    if not token:
        return None
    claims = decode_access_token(token)
    if claims is None:
        return None
    user = db.session.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        return None
    return user


def _bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def api_auth_required(roles: tuple[str, ...] | None = None):
    """JSON API: Bearer header only."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = user_from_token(_bearer_token())
            if user is None:
                resp = jsonify({"error": "Authentication required"})
                resp.status_code = 401
                resp.headers["WWW-Authenticate"] = 'Bearer realm="api"'
                return resp
            if roles and user.role not in roles:
                return jsonify({"error": "You do not have permission to do that"}), 403
            g.current_user = user
            return view(*args, **kwargs)
        return wrapper
    return decorator


def page_auth_required(roles: tuple[str, ...] | None = None):
    """HTML pages: HttpOnly cookie only."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = user_from_token(request.cookies.get(current_app.config["AUTH_COOKIE_NAME"]))
            if user is None:
                return redirect(url_for("pages.login"))
            if roles and user.role not in roles:
                return "Forbidden", 403
            g.current_user = user
            return view(*args, **kwargs)
        return wrapper
    return decorator
