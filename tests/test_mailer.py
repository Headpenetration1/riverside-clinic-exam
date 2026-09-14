"""Outgoing mail: SMTP delivery, failure handling and backend selection.

The reset flow is only complete if the link can actually reach the patient.
"""
import base64
import smtplib

import pytest

from app import create_app
from app.services.mailer import ConsoleMailer, Mailer, SmtpMailer

SECRETS = {
    "SECRET_KEY": "x" * 48,
    "JWT_SECRET": "y" * 48,
    "FILE_ENCRYPTION_KEY": base64.b64encode(b"\x02" * 32).decode(),
}


class FakeSMTP:
    """Stands in for smtplib.SMTP and records what the mailer does."""
    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls: list = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append("quit")

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg):
        self.calls.append(("send", msg))


class BrokenSMTP:
    def __init__(self, *args, **kwargs):
        raise smtplib.SMTPConnectError(421, "no route to mail server")


@pytest.fixture(autouse=True)
def _clean_fake():
    FakeSMTP.instances.clear()


def _app(tmp_path, config="testing", **overrides):
    return create_app(
        config,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        UPLOAD_DIR=str(tmp_path / "uploads"),
        **overrides,
    )


def test_smtp_mailer_delivers_over_starttls_with_login(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    mailer = SmtpMailer(host="smtp.example.org", port=587, username="portal", password="hunter2-not-real",
                        use_tls=True, sender="noreply@example.org")
    mailer.send(to="alice@example.com", subject="Reset", body="hello")

    (conn,) = FakeSMTP.instances
    assert (conn.host, conn.port) == ("smtp.example.org", 587) and conn.timeout is not None
    assert [c if isinstance(c, str) else c[0] for c in conn.calls] == ["starttls", "login", "send", "quit"]
    msg = conn.calls[2][1]
    assert msg["From"] == "noreply@example.org" and msg["To"] == "alice@example.com"
    assert msg["Subject"] == "Reset" and msg.get_content().strip() == "hello"
    assert mailer.outbox[-1]["to"] == "alice@example.com"


def test_delivery_failure_keeps_the_forgot_password_answer_generic(client, app, make_user, monkeypatch, caplog):
    """An SMTP outage must not turn forgot-password into an oracle
    (500 for a real account, 200 for an unknown one)."""
    monkeypatch.setattr(smtplib, "SMTP", BrokenSMTP)
    app.extensions["mailer"] = SmtpMailer(host="smtp.example.org", port=587, username=None, password=None,
                                          use_tls=True, sender="noreply@example.org", logger=app.logger)
    make_user("alice@example.com")
    with caplog.at_level("WARNING"):
        known = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
        unknown = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.get_json() == unknown.get_json()
    assert "mail delivery failed" in caplog.text
    token = app.extensions["mailer"].outbox[0]["body"].split("token=")[1].split()[0]
    assert token not in caplog.text                      # the failure is logged, the token is not


def test_console_mailer_logs_the_whole_message_for_developers(caplog):
    import logging
    mailer = ConsoleMailer(logging.getLogger("test.console"))
    with caplog.at_level("INFO"):
        mailer.send(to="alice@example.com", subject="Reset", body="http://localhost:5000/reset-password?token=abc")
    assert "http://localhost:5000/reset-password?token=abc" in caplog.text


def test_mailer_backend_follows_configuration(tmp_path):
    assert type(_app(tmp_path / "t").extensions["mailer"]) is Mailer                      # tests: outbox only
    assert isinstance(_app(tmp_path / "s", SMTP_HOST="smtp.example.org").extensions["mailer"], SmtpMailer)
    assert isinstance(_app(tmp_path / "d", "development", **SECRETS).extensions["mailer"], ConsoleMailer)
    with pytest.warns(UserWarning, match="SMTP_HOST"):
        prod = _app(tmp_path / "p", "production", PUBLIC_BASE_URL="https://portal.example.org", **SECRETS)
    assert type(prod.extensions["mailer"]) is Mailer


def test_console_mailer_output_is_visible_without_debug_mode(tmp_path, caplog):
    """`flask run` without --debug leaves the app logger at WARNING, which would
    silently swallow the only copy of the reset link a developer has."""
    import logging
    app = _app(tmp_path, "development", **SECRETS)
    assert app.logger.isEnabledFor(logging.INFO)
    with caplog.at_level(logging.INFO, logger=app.logger.name):
        app.extensions["mailer"].send(to="a@example.com", subject="Reset", body="http://localhost/reset-password?token=abc")
    assert "token=abc" in caplog.text
