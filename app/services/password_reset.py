"""Account recovery rules (Task A.3.3), shared by the JSON API and the HTML pages.

request_reset(email): a random token is generated, only its SHA-256 is
stored, and the raw token is mailed as a link. Nothing is revealed about
whether the address is registered: unknown or inactive accounts are ignored
silently and the caller answers the same way in every case.

reset_password(token, new_password): the token must exist, be unused and
unexpired and belong to an active account; the password policy is enforced;
the password is re-hashed, the token is burned and every refresh token of
the account is revoked, so old sessions die with the old password.

Both functions commit, because mailing a link for a token that was never
stored (or not burning a token that was used) would be a security bug.
"""
from datetime import timedelta

from flask import current_app, url_for

from ..extensions import db
from ..models import PasswordResetToken, User
from ..utils import utcnow
from .audit import record
from .security import (
    check_password_policy,
    hash_password,
    hash_token,
    new_opaque_token,
    revoke_all_refresh_tokens,
)

GENERIC_MESSAGE = "If that address is registered, a reset link has been sent."
INVALID_TOKEN = "Invalid or expired reset token"


class ResetTokenError(ValueError):
    pass


def reset_link(raw_token: str) -> str:
    """Build an absolute link from the validated configured public origin.

    The request Host header is deliberately never used: production requires an
    explicit HTTPS origin, while development and testing have fixed local
    defaults.
    """
    base = current_app.config["PUBLIC_BASE_URL"]
    return base.rstrip("/") + url_for("pages.reset_password", token=raw_token)


def _invalidate_active_tokens(user_id: int, now) -> None:
    """Burn every unused, unexpired reset token for one account."""
    db.session.execute(
        db.update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
    )


def _claim_token(token_id: int, now) -> bool:
    """Atomically claim one still-active token.

    Validation and password-policy work happen before this write. The
    conditional UPDATE closes the gap between the earlier read and token
    consumption: a concurrent request can change the row first, but only one
    transaction can observe a row count of one.
    """
    result = db.session.execute(
        db.update(PasswordResetToken)
        .where(
            PasswordResetToken.id == token_id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def request_reset(email: str) -> None:
    user = db.session.scalar(db.select(User).where(User.email == email).with_for_update())
    if user is None or not user.is_active:
        return
    raw = new_opaque_token()
    ttl = current_app.config["RESET_TOKEN_TTL"]
    now = utcnow()
    _invalidate_active_tokens(user.id, now)
    db.session.add(PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw),
        expires_at=now + timedelta(seconds=ttl),
    ))
    record("auth.reset_requested", user=user)
    db.session.commit()
    current_app.extensions["mailer"].send(
        to=user.email,
        subject="Riverside Clinic - reset your password",
        body=f"Use this link within {ttl // 60} minutes to choose a new password:\n{reset_link(raw)}\n"
             "If you did not ask for this, you can ignore this email.",
    )


def find_valid_token(raw) -> PasswordResetToken | None:
    if not isinstance(raw, str) or not raw:
        return None
    prt = db.session.scalar(
        db.select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(raw))
    )
    if prt is None or not prt.is_valid or not prt.user.is_active:
        return None
    return prt


def reset_password(raw, new_password) -> User:
    """Raises ResetTokenError for a bad token, PasswordPolicyError for a weak password."""
    prt = find_valid_token(raw)
    if prt is None:
        raise ResetTokenError(INVALID_TOKEN)
    check_password_policy(new_password, prt.user.email)
    now = utcnow()
    if not _claim_token(prt.id, now):
        db.session.rollback()
        raise ResetTokenError(INVALID_TOKEN)
    _invalidate_active_tokens(prt.user_id, now)
    prt.user.password_hash = hash_password(new_password)
    revoke_all_refresh_tokens(prt.user)
    record("auth.password_reset", user=prt.user)
    db.session.commit()
    return prt.user
