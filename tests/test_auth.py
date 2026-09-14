"""Task A.3.1 / A.3.2 / A.4.3 - registration, login and token handling.

These were written before the auth code existed (see git history: "red" commit
first, then the implementation).
"""
from datetime import datetime, timedelta, timezone

import jwt

from app.extensions import db
from app.models import RefreshToken, User
from tests.conftest import GOOD_PASSWORD


# ---------- registration ----------

def test_register_stores_argon2id_hash_not_the_password(client, app):
    resp = client.post("/api/auth/register", json={
        "email": "New.User@Example.com", "full_name": "New User", "password": GOOD_PASSWORD,
    })
    assert resp.status_code == 201
    assert "password" not in resp.get_json() and "password_hash" not in resp.get_json()
    with app.app_context():
        user = db.session.scalar(db.select(User).where(User.email == "new.user@example.com"))
        assert user.password_hash.startswith("$argon2id$")
        assert GOOD_PASSWORD not in user.password_hash
        assert user.role == "patient"           # nobody self-registers as clinician/admin


def test_register_rejects_short_and_breached_passwords(client):
    for bad in ("short", "x" * 14, "password1234"):
        resp = client.post("/api/auth/register", json={"email": "a@b.co", "full_name": "A", "password": bad})
        assert resp.status_code == 400, bad
        assert "error" in resp.get_json()


def test_register_accepts_password_at_15_character_boundary(client):
    resp = client.post("/api/auth/register", json={
        "email": "boundary@example.com", "full_name": "Boundary", "password": "x" * 15,
    })
    assert resp.status_code == 201


def test_register_rejects_invalid_email_and_duplicate(client, make_user):
    make_user("taken@example.com")
    assert client.post("/api/auth/register", json={"email": "nope", "full_name": "X", "password": GOOD_PASSWORD}).status_code == 400
    resp = client.post("/api/auth/register", json={"email": "TAKEN@example.com", "full_name": "X", "password": GOOD_PASSWORD})
    assert resp.status_code == 409


def test_register_requires_json_body(client):
    resp = client.post("/api/auth/register", data={"email": "a@b.co", "password": GOOD_PASSWORD})
    assert resp.status_code == 415


# ---------- login ----------

def test_login_returns_access_and_refresh_tokens(client, make_user):
    make_user("alice@example.com")
    resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": GOOD_PASSWORD})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 900
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["role"] == "patient" and claims["type"] == "access"
    assert len(body["refresh_token"]) >= 48


def test_login_failures_use_one_generic_message(client, make_user):
    make_user("alice@example.com")
    wrong_pw = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "not-it-not-it"})
    no_user = client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "not-it-not-it"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.get_json() == no_user.get_json() == {"error": "Invalid email or password"}


def test_refresh_token_is_stored_hashed(client, make_user, login, app):
    make_user("alice@example.com")
    session = login("alice@example.com")
    with app.app_context():
        stored = db.session.scalar(db.select(RefreshToken))
        assert stored.token_hash != session["refresh_token"]
        assert len(stored.token_hash) == 64


def test_account_locks_after_five_failed_attempts(client, make_user):
    make_user("alice@example.com")
    for _ in range(5):
        assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong-wrong-wrong"}).status_code == 401
    # even the correct password is refused now
    resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": GOOD_PASSWORD})
    assert resp.status_code == 429


def test_deactivated_user_cannot_log_in(client, make_user):
    make_user("gone@example.com", is_active=False)
    resp = client.post("/api/auth/login", json={"email": "gone@example.com", "password": GOOD_PASSWORD})
    assert resp.status_code == 401


# ---------- protected endpoints ----------

def test_protected_endpoint_requires_bearer_token(client, patient):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": "Basic abc"}).status_code == 401
    resp = client.get("/api/auth/me", headers=patient["headers"])
    assert resp.status_code == 200 and resp.get_json()["email"] == "alice@example.com"


def test_api_ignores_cookies_only_accepts_header(client, patient):
    client.set_cookie("access_token", patient["access_token"])
    assert client.get("/api/auth/me").status_code == 401


def test_tampered_token_is_rejected(client, patient):
    header, payload, sig = patient["access_token"].split(".")
    forged = f"{header}.{payload}.{sig[:-3]}abc"
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_token_with_wrong_algorithm_none_is_rejected(client, patient, app):
    forged = jwt.encode({"sub": str(patient["id"]), "role": "admin", "type": "access",
                         "iat": datetime.now(timezone.utc), "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                        key="", algorithm="none")
    assert client.get("/api/admin/users", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_expired_token_is_rejected(client, patient, app):
    expired = jwt.encode({"sub": str(patient["id"]), "role": "patient", "type": "access",
                          "iat": datetime.now(timezone.utc) - timedelta(hours=2),
                          "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
                         app.config["JWT_SECRET"], algorithm="HS256")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_refresh_rotates_and_old_token_dies(client, patient):
    first = client.post("/api/auth/refresh", json={"refresh_token": patient["refresh_token"]})
    assert first.status_code == 200
    assert first.get_json()["refresh_token"] != patient["refresh_token"]
    replay = client.post("/api/auth/refresh", json={"refresh_token": patient["refresh_token"]})
    assert replay.status_code == 401


def test_logout_revokes_refresh_token(client, patient):
    assert client.post("/api/auth/logout", headers=patient["headers"],
                       json={"refresh_token": patient["refresh_token"]}).status_code == 204
    assert client.post("/api/auth/refresh", json={"refresh_token": patient["refresh_token"]}).status_code == 401


def test_role_checks(client, patient, clinician, admin):
    assert client.get("/api/admin/users", headers=patient["headers"]).status_code == 403
    assert client.get("/api/admin/users", headers=clinician["headers"]).status_code == 403
    assert client.get("/api/admin/users", headers=admin["headers"]).status_code == 200
    assert client.get("/api/patients", headers=patient["headers"]).status_code == 403
    assert client.get("/api/patients", headers=clinician["headers"]).status_code == 200


def test_deactivated_user_token_stops_working(client, patient, admin):
    resp = client.post(f"/api/admin/users/{patient['id']}/deactivate", headers=admin["headers"])
    assert resp.status_code == 200
    assert client.get("/api/auth/me", headers=patient["headers"]).status_code == 401
    assert client.post("/api/auth/refresh", json={"refresh_token": patient["refresh_token"]}).status_code == 401
