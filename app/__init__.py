"""Application factory."""
import logging
import re

from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from .config import get_config, validate_secrets
from .extensions import db
from .services.cerebras import CerebrasClient
from .services.csrf import csrf_token
from .services.mailer import build_mailer
from .services.ratelimit import RateLimiter


class RedactingFilter(logging.Filter):
    """Last line of defence: scrub bearer tokens and API keys from log lines."""
    PATTERNS = (re.compile(r"Bearer\s+[A-Za-z0-9._\-]+"), re.compile(r"csk-[A-Za-z0-9]+"))

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pat in self.PATTERNS:
            msg = pat.sub("[redacted]", msg)
        record.msg, record.args = msg, ()
        return True


def create_app(config_name: str | None = None, **overrides) -> Flask:
    load_dotenv()
    app = Flask(__name__, template_folder="views/templates", static_folder="views/static")
    app.config.from_object(get_config(config_name))
    app.config.update(overrides)
    validate_secrets(app)

    import os
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    db.init_app(app)
    app.extensions["limiter"] = RateLimiter()
    app.extensions["mailer"] = build_mailer(app)
    app.extensions["cerebras"] = CerebrasClient(
        api_key_getter=lambda: app.config.get("CEREBRAS_API_KEY"),
        model=app.config["CEREBRAS_MODEL"],
        url=app.config["CEREBRAS_API_URL"],
        timeout=app.config["CEREBRAS_TIMEOUT"],
    )
    app.logger.addFilter(RedactingFilter())
    app.jinja_env.globals["csrf_token"] = csrf_token

    from . import models  # noqa: F401  (register tables)
    from .controllers import register_blueprints
    register_blueprints(app)
    _register_handlers(app)

    with app.app_context():
        db.create_all()   # a real deployment would use Alembic migrations instead
    return app


def _register_handlers(app: Flask) -> None:
    @app.context_processor
    def inject_user():
        return {"current_user": g.get("current_user")}

    @app.after_request
    def security_headers(resp):
        h = resp.headers
        h.setdefault("Content-Security-Policy",
                     "default-src 'self'; object-src 'none'; base-uri 'self'; "
                     "form-action 'self'; frame-ancestors 'none'")
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.path.startswith("/api/"):
            h.setdefault("Cache-Control", "no-store")
        if app.config.get("HSTS_ENABLED"):
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    @app.errorhandler(HTTPException)
    def handle_http_error(exc: HTTPException):
        if request.path.startswith("/api/"):
            return jsonify({"error": exc.description if exc.code < 500 else exc.name}), exc.code
        page = render_template("error.html", code=exc.code, name=exc.name, description=exc.description)
        headers = {"Retry-After": str(exc.retry_after)} if getattr(exc, "retry_after", None) else {}
        return page, exc.code, headers

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception):
        app.logger.exception("unhandled error")           # full detail in the log...
        db.session.rollback()
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500   # ...nothing to the client
        return render_template("error.html", code=500, name="Internal Server Error", description=""), 500
