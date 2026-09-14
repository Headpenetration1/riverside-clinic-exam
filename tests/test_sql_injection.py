"""Task A.4.1 - SQL injection.

Two halves:
1. Classic payloads fired at the real endpoints (login, patient search).
2. A side-by-side of the mistake (string formatting) and the fix (bound
   parameters) on a throwaway sqlite table, so the difference is visible.
   The vulnerable function lives only in this test file. It is never imported
   by the application.
"""
import sqlite3

from sqlalchemy.dialects import sqlite

from app.controllers.patients import search_patients
from app.extensions import db
from app.models import User
from tests.conftest import GOOD_PASSWORD

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "alice@example.com' --",
    "alice@example.com'; DROP TABLE users; --",
    "\" OR \"\"=\"",
    "' UNION SELECT id, email, password_hash FROM users --",
]


def test_login_cannot_be_bypassed_with_injection(client, make_user):
    make_user("alice@example.com")
    for payload in PAYLOADS:
        resp = client.post("/api/auth/login", json={"email": payload, "password": payload})
        assert resp.status_code in (400, 401), payload
        assert "access_token" not in (resp.get_json() or {})
    # the password field too - it is never near SQL, but check anyway
    resp = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "' OR '1'='1"})
    assert resp.status_code == 401
    # and the table is still there
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": GOOD_PASSWORD}).status_code == 200


def test_patient_search_treats_payloads_as_plain_text(client, clinician, make_user):
    make_user("alice@example.com", full_name="Alice Andersen")
    make_user("carl@example.com", full_name="Carl Carlsen")
    for payload in PAYLOADS:
        resp = client.get("/api/patients", headers=clinician["headers"], query_string={"q": payload})
        assert resp.status_code == 200, payload
        assert resp.get_json() == [], payload           # no rows match the literal text
    # ordinary search still works, and wildcards are literal too
    assert [u["full_name"] for u in client.get("/api/patients", headers=clinician["headers"],
                                                 query_string={"q": "carl"}).get_json()] == ["Carl Carlsen"]
    assert client.get("/api/patients", headers=clinician["headers"], query_string={"q": "%"}).get_json() == []


def test_orm_query_binds_user_input_as_a_parameter(app):
    payload = "' OR 1=1 --"
    stmt = db.select(User).where(User.email == payload)
    compiled = stmt.compile(dialect=sqlite.dialect())
    sql = str(compiled)
    assert "OR 1=1" not in sql                        # the payload never touches the SQL text
    assert "users.email = ?" in sql
    assert list(compiled.params.values()) == [payload]
    with app.app_context():
        assert db.session.scalar(stmt) is None
        assert search_patients(payload) == []


# ---------- the demonstration ----------

def _demo_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE demo_users (id INTEGER PRIMARY KEY, email TEXT, secret TEXT)")
    conn.executemany("INSERT INTO demo_users (email, secret) VALUES (?, ?)",
                     [("alice@example.com", "s3cret-alice"), ("bob@example.com", "s3cret-bob")])
    return conn


def _vulnerable_lookup(conn, email, secret):
    # THE MISTAKE: user input concatenated into SQL. Do not copy this.
    sql = f"SELECT id, email FROM demo_users WHERE email = '{email}' AND secret = '{secret}'"  # nosec - deliberate
    return conn.execute(sql).fetchall()


def _parameterised_lookup(conn, email, secret):
    # THE FIX: placeholders; the driver sends values separately from the SQL text
    return conn.execute("SELECT id, email FROM demo_users WHERE email = ? AND secret = ?", (email, secret)).fetchall()


def test_string_formatting_is_bypassed_but_parameters_are_not():
    conn = _demo_db()
    comment_out = ("alice@example.com' --", "wrong")
    always_true = ("x", "x' OR '1'='1")

    assert _vulnerable_lookup(conn, *comment_out) == [(1, "alice@example.com")]   # logged in as Alice
    assert len(_vulnerable_lookup(conn, *always_true)) == 2                       # every account matches

    assert _parameterised_lookup(conn, *comment_out) == []
    assert _parameterised_lookup(conn, *always_true) == []

    # the genuine credentials still work with parameters
    assert _parameterised_lookup(conn, "alice@example.com", "s3cret-alice") == [(1, "alice@example.com")]
