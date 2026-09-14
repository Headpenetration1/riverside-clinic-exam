"""Clinician-only patient search. The `q` parameter is user input that ends up
in a SQL WHERE clause - the classic SQL injection spot - so it goes through
the ORM as a bound parameter, with LIKE wildcards escaped as well."""
from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import User
from ..services.auth import api_auth_required

bp = Blueprint("patients", __name__, url_prefix="/api/patients")


def search_patients(q: str, limit: int = 20) -> list[User]:
    q = (q or "").strip()[:100]
    stmt = db.select(User).where(User.role == "patient").order_by(User.full_name).limit(limit)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        stmt = stmt.where(
            db.or_(User.full_name.ilike(pattern, escape="\\"), User.email.ilike(pattern, escape="\\"))
        )
    return list(db.session.scalars(stmt))


@bp.get("")
@api_auth_required(roles=("clinician",))
def search():
    users = search_patients(request.args.get("q", ""))
    return jsonify([{"id": u.id, "full_name": u.full_name, "email": u.email} for u in users])


__all__ = ["bp", "search_patients"]
