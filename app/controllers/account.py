"""Data-subject rights (GDPR art. 15/20 access and portability, art. 17 erasure)."""
from flask import Blueprint, g, jsonify

from ..extensions import db
from ..models import AuditEvent
from ..services.audit import record
from ..services.auth import api_auth_required
from ..services.documents import list_documents
from ..services.files import remove_stored

me_bp = Blueprint("me", __name__, url_prefix="/api/me")


@me_bp.get("/export")
@api_auth_required()
def export_my_data():
    user = g.current_user
    docs = [] if user.role == "admin" else [d.to_dict() for d in list_documents(user) if d.owner_id == user.id]
    events = db.session.scalars(
        db.select(AuditEvent).where(AuditEvent.user_id == user.id).order_by(AuditEvent.created_at.desc()).limit(200)
    )
    record("account.export")
    db.session.commit()
    return jsonify({
        "user": user.to_dict(),
        "documents": docs,
        "messages": [m.to_dict() for m in user.messages],
        "audit_events": [e.to_dict() for e in events],
    })


@me_bp.delete("")
@api_auth_required()
def delete_my_account():
    user = g.current_user
    for doc in user.documents:
        remove_stored(doc.stored_name)
    record("account.delete", target=f"user:{user.id}", user=None)   # keep an anonymous trace
    db.session.delete(user)                                          # cascades to docs/tokens/messages
    db.session.commit()
    return "", 204
