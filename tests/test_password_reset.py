"""Task A.3.3 - account recovery."""
import re
from datetime import timedelta

from app.extensions import db
from app.models import PasswordResetToken
from app.services import password_reset as recovery
from app.services.security import hash_token
from app.utils import utcnow
from tests.conftest import GOOD_PASSWORD

NEW_PASSWORD = "a-brand-new-secret-phrase"


def _request_reset(client, app, email="alice@example.com") -> str:
    before = len(app.extensions["mailer"].outbox)
    resp = client.post("/api/auth/forgot-password", json={"email": email})
    assert resp.status_code == 200
    mail = app.extensions["mailer"].outbox[before]
    token = re.search(r"token=([A-Za-z0-9_\-]+)", mail["body"]).group(1)
    return token


def test_forgot_password_does_not_reveal_whether_email_exists(client, app, make_user):
    make_user("alice@example.com")
    known = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    unknown = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.get_json() == unknown.get_json()
    assert len(app.extensions["mailer"].outbox) == 1        # only the real user got a mail


def test_reset_token_is_stored_hashed(client, app, make_user):
    make_user("alice@example.com")
    token = _request_reset(client, app)
    with app.app_context():
        row = db.session.scalar(db.select(PasswordResetToken))
        assert row.token_hash != token and len(row.token_hash) == 64


def test_valid_token_sets_new_password(client, app, make_user):
    make_user("alice@example.com")
    token = _request_reset(client, app)
    resp = client.post("/api/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD})
    assert resp.status_code == 200
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": GOOD_PASSWORD}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": NEW_PASSWORD}).status_code == 200


def test_token_cannot_be_reused(client, app, make_user):
    make_user("alice@example.com")
    token = _request_reset(client, app)
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 200
    replay = client.post("/api/auth/reset-password", json={"token": token, "new_password": "yet-another-secret-phrase"})
    assert replay.status_code == 400
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": NEW_PASSWORD}).status_code == 200


def test_new_reset_request_invalidates_previous_active_token(client, app, make_user):
    make_user("alice@example.com")
    first = _request_reset(client, app)
    second = _request_reset(client, app)

    stale = client.post("/api/auth/reset-password", json={"token": first, "new_password": NEW_PASSWORD})
    assert stale.status_code == 400
    assert client.post("/api/auth/reset-password", json={
        "token": second, "new_password": NEW_PASSWORD,
    }).status_code == 200


def test_successful_reset_invalidates_every_other_active_token(client, app, make_user):
    user_id = make_user("alice@example.com")
    first = _request_reset(client, app)
    second = "second-independently-issued-reset-token"
    with app.app_context():
        db.session.add(PasswordResetToken(
            user_id=user_id,
            token_hash=hash_token(second),
            expires_at=utcnow() + timedelta(minutes=30),
        ))
        db.session.commit()

    assert client.post("/api/auth/reset-password", json={
        "token": first, "new_password": NEW_PASSWORD,
    }).status_code == 200
    assert client.post("/api/auth/reset-password", json={
        "token": second, "new_password": "another-valid-secret-phrase",
    }).status_code == 400

    with app.app_context():
        rows = db.session.scalars(db.select(PasswordResetToken)).all()
        assert rows and all(row.used_at is not None for row in rows)


def test_atomic_claim_rejects_token_used_after_initial_validation(client, app, make_user, monkeypatch):
    make_user("alice@example.com")
    token = _request_reset(client, app)
    original_find = recovery.find_valid_token

    def find_then_simulate_competing_claim(raw):
        stale = original_find(raw)
        assert stale is not None
        db.session.execute(
            db.update(PasswordResetToken)
            .where(PasswordResetToken.id == stale.id)
            .values(used_at=utcnow())
        )
        db.session.commit()
        return stale

    monkeypatch.setattr(recovery, "find_valid_token", find_then_simulate_competing_claim)
    rejected = client.post("/api/auth/reset-password", json={
        "token": token, "new_password": NEW_PASSWORD,
    })
    assert rejected.status_code == 400

    with app.app_context():
        row = db.session.scalar(db.select(PasswordResetToken))
        assert row.used_at is not None
    assert client.post("/api/auth/login", json={
        "email": "alice@example.com", "password": GOOD_PASSWORD,
    }).status_code == 200
    assert client.post("/api/auth/login", json={
        "email": "alice@example.com", "password": NEW_PASSWORD,
    }).status_code == 401


def test_expired_token_is_rejected(client, app, make_user):
    make_user("alice@example.com")
    token = _request_reset(client, app)
    with app.app_context():
        row = db.session.scalar(db.select(PasswordResetToken))
        row.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 400


def test_garbage_and_missing_tokens_are_rejected(client):
    assert client.post("/api/auth/reset-password", json={"token": "nope", "new_password": NEW_PASSWORD}).status_code == 400
    assert client.post("/api/auth/reset-password", json={"new_password": NEW_PASSWORD}).status_code == 400
    assert client.post("/api/auth/reset-password", json={"token": 12345, "new_password": NEW_PASSWORD}).status_code == 400


def test_reset_enforces_password_policy_and_keeps_token_usable(client, app, make_user):
    make_user("alice@example.com")
    token = _request_reset(client, app)
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": "short"}).status_code == 400
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 200


def test_reset_invalidates_existing_sessions(client, app, make_user, login):
    make_user("alice@example.com")
    session = login("alice@example.com")
    token = _request_reset(client, app)
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 200
    assert client.post("/api/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401


def test_forgot_password_is_rate_limited(client):
    for _ in range(5):
        assert client.post("/api/auth/forgot-password", json={"email": "x@example.com"}).status_code == 200
    assert client.post("/api/auth/forgot-password", json={"email": "x@example.com"}).status_code == 429
