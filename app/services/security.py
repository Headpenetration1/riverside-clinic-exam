"""Passwords and tokens.

- Passwords: Argon2id via argon2-cffi. The stored string carries the salt and
  the parameters, so parameters can be raised later and old hashes upgraded on
  next login (see needs_rehash).
- Access tokens: short-lived JWT (HS256). Stateless, 15 minutes.
- Refresh / reset tokens: random opaque strings. Only SHA-256(token) is stored.
"""
import hashlib
import secrets
import uuid
from datetime import timedelta

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import current_app

from ..extensions import db
from ..models import RefreshToken, User
from ..utils import utcnow

# A tiny excerpt of a breached-password list. In production this check is
# replaced by the Have I Been Pwned k-anonymity range API.
COMMON_PASSWORDS = frozenset({
    "password1234", "123456789012", "qwertyuiop12", "iloveyou1234", "welcome12345",
    "letmein12345", "adminadmin12", "passw0rd1234", "changeme1234", "clinic123456",
    "riversideclinic", "password12345", "1234567890ab",
})
MIN_PASSWORD_LENGTH = 15


class PasswordPolicyError(ValueError):
    pass


# ---------- passwords ----------

def _hasher() -> PasswordHasher:
    cfg = current_app.config
    return PasswordHasher(
        time_cost=cfg["ARGON2_TIME_COST"],
        memory_cost=cfg["ARGON2_MEMORY_COST"],
        parallelism=cfg["ARGON2_PARALLELISM"],
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


def hash_password(password: str) -> str:
    return _hasher().hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher().verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher().check_needs_rehash(password_hash)


def check_password_policy(password, email: str | None = None) -> None:
    """NIST 800-63B style: length and a breached-list check, no composition rules."""
    if not isinstance(password, str):
        raise PasswordPolicyError("Password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 128:
        raise PasswordPolicyError("Password must be at most 128 characters")
    if password.lower() in COMMON_PASSWORDS:
        raise PasswordPolicyError("That password appears in breach lists; choose another")
    if email and email.split("@")[0].lower() in password.lower():
        raise PasswordPolicyError("Password must not contain your email address")


# ---------- opaque tokens ----------

def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)   # 384 bits of randomness


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------- access tokens (JWT) ----------

def create_access_token(user: User) -> str:
    now = utcnow()
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(seconds=current_app.config["ACCESS_TOKEN_TTL"]),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")


def decode_access_token(token: str) -> dict | None:
    """Return the claims or None. Never raises on bad input."""
    try:
        claims = jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=["HS256"],                 # pin the algorithm - never trust the header
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError:
        return None
    if claims.get("type") != "access":
        return None
    return claims


# ---------- refresh tokens ----------

def issue_refresh_token(user: User) -> str:
    raw = new_opaque_token()
    db.session.add(RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw),
        expires_at=utcnow() + timedelta(seconds=current_app.config["REFRESH_TOKEN_TTL"]),
    ))
    return raw


def consume_refresh_token(raw) -> User | None:
    """Validate and revoke a refresh token in one step (rotation). Returns the user."""
    if not isinstance(raw, str) or not raw:
        return None
    rt = db.session.scalar(db.select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw)))
    if rt is None or not rt.is_valid or not rt.user.is_active:
        return None
    rt.revoked_at = utcnow()
    return rt.user


def revoke_refresh_token(raw) -> None:
    if not isinstance(raw, str):
        return
    rt = db.session.scalar(db.select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw)))
    if rt is not None and rt.revoked_at is None:
        rt.revoked_at = utcnow()


def revoke_all_refresh_tokens(user: User) -> None:
    now = utcnow()
    for rt in user.refresh_tokens:
        if rt.revoked_at is None:
            rt.revoked_at = now
