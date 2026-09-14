from flask import Blueprint, jsonify

from ..extensions import db
from ..models import User
from ..services.audit import record
from ..services.auth import api_auth_required
from ..services.security import revoke_all_refresh_tokens
from ..utils import json_error

bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@bp.get("/users")
@api_auth_required(roles=("admin",))
def list_users():
    return jsonify([u.to_dict() for u in db.session.scalars(db.select(User).order_by(User.id))])


@bp.post("/users/<int:user_id>/deactivate")
@api_auth_required(roles=("admin",))
def deactivate(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        return json_error("User not found", 404)
    user.is_active = False
    revoke_all_refresh_tokens(user)
    record("admin.deactivate_user", target=f"user:{user_id}")
    db.session.commit()
    return jsonify(user.to_dict())
