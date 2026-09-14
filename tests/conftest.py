"""Fixtures. Every test gets its own app, its own SQLite file and its own upload
directory, so tests cannot leak state into each other."""
import re

import pytest

from app import create_app
from app.extensions import db
from app.models import User
from app.services.security import hash_password

GOOD_PASSWORD = "correct-horse-battery-staple"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')

# smallest valid files of each allowed type
TINY_PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
TINY_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
TINY_JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 32


@pytest.fixture
def app(tmp_path):
    application = create_app(
        "testing",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        UPLOAD_DIR=str(tmp_path / "uploads"),
    )
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(app):
    def _make(email, password=GOOD_PASSWORD, role="patient", full_name=None, is_active=True) -> int:
        with app.app_context():
            user = User(
                email=email,
                full_name=full_name or email.split("@")[0].title(),
                role=role,
                password_hash=hash_password(password),
                is_active=is_active,
            )
            db.session.add(user)
            db.session.commit()
            return user.id
    return _make


@pytest.fixture
def login(client):
    def _login(email, password=GOOD_PASSWORD) -> dict:
        resp = client.post("/api/auth/login", json={"email": email, "password": password})
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()
        return {
            "headers": {"Authorization": f"Bearer {body['access_token']}"},
            "access_token": body["access_token"],
            "refresh_token": body["refresh_token"],
            "user": body["user"],
        }
    return _login


@pytest.fixture
def patient(make_user, login):
    uid = make_user("alice@example.com")
    session = login("alice@example.com")
    session["id"] = uid
    session["email"] = "alice@example.com"
    return session


@pytest.fixture
def other_patient(make_user, login):
    uid = make_user("mallory@example.com")
    session = login("mallory@example.com")
    session["id"] = uid
    return session


@pytest.fixture
def clinician(make_user, login):
    uid = make_user("dr.bob@example.com", role="clinician", full_name="Dr Bob")
    session = login("dr.bob@example.com")
    session["id"] = uid
    return session


@pytest.fixture
def admin(make_user, login):
    uid = make_user("admin@example.com", role="admin")
    session = login("admin@example.com")
    session["id"] = uid
    return session


def csrf_from(html: bytes) -> str:
    match = CSRF_RE.search(html.decode())
    assert match, "no csrf token in page"
    return match.group(1)


@pytest.fixture
def page_login(client):
    """Log in through the HTML form so the client holds the auth cookie."""
    def _login(email, password=GOOD_PASSWORD):
        token = csrf_from(client.get("/login").data)
        resp = client.post("/login", data={"csrf_token": token, "email": email, "password": password})
        assert resp.status_code == 302, resp.data
        return token
    return _login
