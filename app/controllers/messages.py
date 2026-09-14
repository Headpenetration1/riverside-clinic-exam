from flask import Blueprint, g, jsonify

from ..extensions import db
from ..models import Message
from ..services.auth import api_auth_required
from ..utils import clean_text, json_error, require_json

bp = Blueprint("messages", __name__, url_prefix="/api/messages")
MAX_BODY = 2000


def recent_messages(limit: int = 50) -> list[Message]:
    return list(db.session.scalars(db.select(Message).order_by(Message.created_at.desc(), Message.id.desc()).limit(limit)))


def create_message(user, body) -> Message:
    text = clean_text(body, MAX_BODY)
    if text is None:
        return None
    msg = Message(author_id=user.id, body=text)   # stored as typed; escaping happens on output
    db.session.add(msg)
    db.session.flush()
    return msg


@bp.get("")
@api_auth_required()
def list_messages():
    return jsonify([m.to_dict() for m in recent_messages()])


@bp.post("")
@api_auth_required()
def post_message():
    data = require_json()
    msg = create_message(g.current_user, data.get("body"))
    if msg is None:
        return json_error(f"body must be a non-empty string of at most {MAX_BODY} characters", 400)
    db.session.commit()
    return jsonify(msg.to_dict()), 201
