"""Task A.3.3 - the HTML side of account recovery.

A patient must be able to complete a reset from the emailed link alone:
ask for a link on a page, click the link, choose a new password, log in.
The JSON API tests live in test_password_reset.py; these cover the pages.
"""
import base64
import re

import pytest

from app import create_app
from tests.conftest import GOOD_PASSWORD, csrf_from

NEW_PASSWORD = "a-brand-new-secret-phrase"
GENERIC_ANSWER = b"If that address is registered, a reset link has been sent."


def _ask_for_reset(client, app, email="alice@example.com"):
    """Submit the forgot-password form; return (final page, new outbox mails)."""
    token = csrf_from(client.get("/forgot-password").data)
    before = len(app.extensions["mailer"].outbox)
    resp = client.post("/forgot-password", data={"csrf_token": token, "email": email}, follow_redirects=True)
    return resp, app.extensions["mailer"].outbox[before:]


def _token_from(mail: dict) -> str:
    return re.search(r"token=([A-Za-z0-9_\-]+)", mail["body"]).group(1)


def _reset_via_form(client, token: str, password: str, confirm: str | None = None):
    csrf = csrf_from(client.get(f"/reset-password?token={token}").data)
    return client.post("/reset-password", data={
        "csrf_token": csrf,
        "token": token,
        "new_password": password,
        "confirm_password": password if confirm is None else confirm,
    })


def test_login_page_links_to_a_forgot_password_page(client):
    assert b'href="/forgot-password"' in client.get("/login").data
    page = client.get("/forgot-password")
    assert page.status_code == 200
    assert b'name="email"' in page.data and b'name="csrf_token"' in page.data


def test_forgot_password_form_gives_same_answer_for_known_and_unknown_email(client, app, make_user):
    make_user("alice@example.com")
    known, known_mail = _ask_for_reset(client, app, "alice@example.com")
    unknown, unknown_mail = _ask_for_reset(client, app, "nobody@example.com")
    assert known.status_code == unknown.status_code == 200
    assert GENERIC_ANSWER in known.data and GENERIC_ANSWER in unknown.data
    assert unknown_mail == []
    assert len(known_mail) == 1 and known_mail[0]["to"] == "alice@example.com"
    assert "/reset-password?token=" in known_mail[0]["body"]


def test_forgot_password_form_requires_csrf(client, app, make_user):
    make_user("alice@example.com")
    assert client.post("/forgot-password", data={"email": "alice@example.com"}).status_code == 400
    assert app.extensions["mailer"].outbox == []


def test_forgot_password_form_is_rate_limited(client):
    csrf = csrf_from(client.get("/forgot-password").data)
    for _ in range(5):
        assert client.post("/forgot-password", data={"csrf_token": csrf, "email": "x@example.com"}).status_code == 302
    blocked = client.post("/forgot-password", data={"csrf_token": csrf, "email": "x@example.com"})
    assert blocked.status_code == 429 and blocked.mimetype == "text/html"
    assert "Retry-After" in blocked.headers


def test_reset_page_shows_the_form_for_a_valid_token(client, app, make_user):
    make_user("alice@example.com")
    _, mails = _ask_for_reset(client, app)
    token = _token_from(mails[0])
    page = client.get(f"/reset-password?token={token}")
    assert page.status_code == 200
    assert f'name="token" value="{token}"'.encode() in page.data
    assert b'name="new_password"' in page.data and b'name="csrf_token"' in page.data
    assert page.headers["Cache-Control"] == "no-store"      # the token is in the URL


def test_reset_page_rejects_missing_or_garbage_token(client):
    for path in ("/reset-password", "/reset-password?token=nope"):
        page = client.get(path)
        assert page.status_code == 400
        assert b"invalid or has expired" in page.data
        assert b'href="/forgot-password"' in page.data       # a way to ask for a new one
        assert b'name="new_password"' not in page.data


def test_reset_form_sets_new_password_and_burns_the_token(client, app, make_user, page_login):
    make_user("alice@example.com")
    _, mails = _ask_for_reset(client, app)
    token = _token_from(mails[0])

    resp = _reset_via_form(client, token, NEW_PASSWORD)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")
    landing = client.get("/login")
    assert b"Password updated" in landing.data

    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": GOOD_PASSWORD}).status_code == 401
    page_login("alice@example.com", NEW_PASSWORD)
    assert client.get(f"/reset-password?token={token}").status_code == 400      # burnt


def test_reset_form_rejects_weak_password_and_keeps_token_usable(client, app, make_user):
    make_user("alice@example.com")
    _, mails = _ask_for_reset(client, app)
    token = _token_from(mails[0])
    weak = _reset_via_form(client, token, "short")
    assert weak.status_code == 400 and b"at least 15 characters" in weak.data
    assert f'name="token" value="{token}"'.encode() in weak.data   # form re-rendered, can try again
    assert _reset_via_form(client, token, NEW_PASSWORD).status_code == 302


def test_reset_form_rejects_mismatched_confirmation(client, app, make_user):
    make_user("alice@example.com")
    _, mails = _ask_for_reset(client, app)
    token = _token_from(mails[0])
    resp = _reset_via_form(client, token, NEW_PASSWORD, confirm="something-else-entirely")
    assert resp.status_code == 400 and b"do not match" in resp.data
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": GOOD_PASSWORD}).status_code == 200


def test_reset_form_requires_csrf(client, app, make_user):
    make_user("alice@example.com")
    _, mails = _ask_for_reset(client, app)
    token = _token_from(mails[0])
    resp = client.post("/reset-password", data={"token": token, "new_password": NEW_PASSWORD,
                                                "confirm_password": NEW_PASSWORD})
    assert resp.status_code == 400
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": NEW_PASSWORD}).status_code == 401


def test_reset_logs_the_current_browser_out(client, app, make_user, page_login):
    make_user("alice@example.com")
    page_login("alice@example.com")
    assert client.get("/dashboard").status_code == 200
    _, mails = _ask_for_reset(client, app)
    assert _reset_via_form(client, _token_from(mails[0]), NEW_PASSWORD).status_code == 302
    assert client.get("/dashboard").status_code == 302             # cookie cleared, must log in again


def test_reset_link_uses_public_base_url_not_the_host_header(tmp_path):
    """Host-header poisoning: an attacker who triggers a reset with a forged
    Host must not get a link that points at their own server."""
    app = create_app(
        "testing",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        UPLOAD_DIR=str(tmp_path / "uploads"),
        PUBLIC_BASE_URL="https://portal.example.org",
    )
    client = app.test_client()
    assert client.post("/api/auth/register", json={"email": "alice@example.com", "full_name": "Alice",
                                                   "password": GOOD_PASSWORD}).status_code == 201
    resp = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"},
                       headers={"Host": "evil.example"})
    assert resp.status_code == 200
    body = app.extensions["mailer"].outbox[0]["body"]
    assert "https://portal.example.org/reset-password?token=" in body
    assert "evil.example" not in body


def test_default_test_reset_link_never_uses_the_host_header(client, app, make_user):
    make_user("alice@example.com")
    resp = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"},
                       headers={"Host": "evil.example"})
    assert resp.status_code == 200
    body = app.extensions["mailer"].outbox[0]["body"]
    assert "http://localhost/reset-password?token=" in body
    assert "evil.example" not in body


def _production_overrides(tmp_path, public_base_url):
    return {
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'production.db'}",
        "UPLOAD_DIR": str(tmp_path / "uploads"),
        "SECRET_KEY": "production-secret-key-for-test",
        "JWT_SECRET": "production-jwt-secret-for-test",
        "FILE_ENCRYPTION_KEY": base64.b64encode(b"\x02" * 32).decode(),
        "PUBLIC_BASE_URL": public_base_url,
    }


def test_production_requires_explicit_public_base_url(tmp_path):
    with pytest.raises(RuntimeError, match="PUBLIC_BASE_URL"):
        create_app("production", **_production_overrides(tmp_path, None))


@pytest.mark.parametrize("bad_url", [
    "http://portal.example.org",
    "javascript:alert(1)",
    "https://user:password@portal.example.org",
    "https://portal.example.org/reset?next=evil.example",
    "https://portal.example.org/#fragment",
    "https://portal.example.org?",
    "https://portal.example.org/#",
])
def test_production_rejects_unsafe_public_base_url(tmp_path, bad_url):
    with pytest.raises(RuntimeError, match="PUBLIC_BASE_URL"):
        create_app("production", **_production_overrides(tmp_path, bad_url))
