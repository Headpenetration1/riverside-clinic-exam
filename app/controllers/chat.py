from flask import Blueprint, current_app, g, jsonify

from ..extensions import db
from ..services.audit import record
from ..services.auth import api_auth_required
from ..services.cerebras import ChatUpstreamError
from ..services.chat import (
    CHAT_RATE_LIMIT,
    CHAT_RATE_SCOPE,
    CHAT_RATE_WINDOW,
    ChatValidationError,
    build_messages,
    sanitise_reply,
    validate_chat_input,
)
from ..services.ratelimit import rate_limited
from ..utils import json_error, require_json

bp = Blueprint("chat", __name__, url_prefix="/api/chat")
UNAVAILABLE = "The assistant is unavailable right now. Please try again later."


def ask_assistant(user, message: str, history: list[dict]) -> str:
    """Shared by the API and the HTML page. Raises ChatUpstreamError."""
    client = current_app.extensions["cerebras"]
    reply = client.chat(build_messages(message, history))
    record("chat.message", target=f"chars:{len(message)}", user=user)   # no content is logged
    db.session.commit()
    return sanitise_reply(reply)


@bp.post("")
@api_auth_required(roles=("patient", "clinician"))
@rate_limited(
    CHAT_RATE_LIMIT,
    CHAT_RATE_WINDOW,
    key_func=lambda: f"user:{g.current_user.id}",
    scope=CHAT_RATE_SCOPE,
)
def chat():
    try:
        message, history = validate_chat_input(require_json())
    except ChatValidationError as exc:
        return json_error(str(exc), 400)
    try:
        reply = ask_assistant(g.current_user, message, history)
    except ChatUpstreamError as exc:
        current_app.logger.warning("assistant unavailable: %s", exc)   # detail stays server-side
        return json_error(UNAVAILABLE, 502)
    return jsonify({"reply": reply})
