"""Outgoing mail.

Every backend keeps an outbox (the test-suite reads it) and hands the message
to `_deliver()`. Delivery errors are logged and swallowed on purpose: the
forgot-password endpoint must answer the same way whether or not the mail
went out, otherwise an SMTP outage turns it into an account-enumeration
oracle (500 for a real account, 200 for an unknown one). Log lines carry
recipient and subject, never the body, because the body holds the reset token.

Backends, chosen by `build_mailer()`:
- SmtpMailer     when SMTP_HOST is configured (production).
- ConsoleMailer  development without SMTP: the whole message, link included,
                 goes to the log so the flow can be tried locally.
- Mailer         outbox only (tests, and the fallback).
"""
import logging
import smtplib
import ssl
import warnings
from email.message import EmailMessage


class Mailer:
    def __init__(self, logger: logging.Logger | None = None):
        self.outbox: list[dict] = []
        self.log = logger or logging.getLogger(__name__)

    def send(self, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})
        try:
            self._deliver(to, subject, body)
        except (OSError, smtplib.SMTPException) as exc:
            self.log.warning("mail delivery failed to=%s subject=%r: %s: %s",
                             to, subject, type(exc).__name__, exc)
        else:
            self.log.info("mail to=%s subject=%r handled by %s", to, subject, type(self).__name__)

    def _deliver(self, to: str, subject: str, body: str) -> None:
        """Outbox only: nothing leaves the process."""


class ConsoleMailer(Mailer):
    def _deliver(self, to: str, subject: str, body: str) -> None:
        self.log.info("mail to=%s subject=%r\n%s", to, subject, body)


class SmtpMailer(Mailer):
    def __init__(self, host: str, port: int, username: str | None, password: str | None,
                 use_tls: bool, sender: str, logger: logging.Logger | None = None, timeout: int = 10):
        super().__init__(logger)
        self.host, self.port, self.timeout = host, port, timeout
        self.username, self.password = username, password
        self.use_tls, self.sender = use_tls, sender

    def _deliver(self, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
        msg.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
            if self.use_tls:
                smtp.starttls(context=ssl.create_default_context())
            if self.username:
                smtp.login(self.username, self.password or "")
            smtp.send_message(msg)


def build_mailer(app) -> Mailer:
    cfg = app.config
    if cfg.get("SMTP_HOST"):
        return SmtpMailer(
            host=cfg["SMTP_HOST"], port=cfg["SMTP_PORT"],
            username=cfg.get("SMTP_USERNAME"), password=cfg.get("SMTP_PASSWORD"),
            use_tls=cfg["SMTP_USE_TLS"], sender=cfg["MAIL_FROM"], logger=app.logger,
        )
    if cfg.get("ENV_NAME") == "development":
        if not app.logger.isEnabledFor(logging.INFO):
            app.logger.setLevel(logging.INFO)     # `flask run` without --debug would hide the link
        return ConsoleMailer(app.logger)
    if cfg.get("ENV_NAME") == "production":
        warnings.warn("SMTP_HOST not set; password-reset emails will not be delivered.", stacklevel=2)
    return Mailer(app.logger)
