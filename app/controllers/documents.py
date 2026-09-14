import io

from flask import Blueprint, g, jsonify, request, send_file

from ..extensions import db
from ..services import documents as docs
from ..services.auth import api_auth_required
from ..utils import json_error

bp = Blueprint("documents", __name__, url_prefix="/api/documents")


def attachment_response(doc, data: bytes):
    resp = send_file(
        io.BytesIO(data),
        mimetype=doc.mime_type,
        as_attachment=True,             # never render inline
        download_name=doc.original_name,
        max_age=0,
    )
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return resp


@bp.post("")
@api_auth_required(roles=("patient", "clinician"))
def upload():
    upload_file = request.files.get("file")
    if upload_file is None:
        return json_error("Attach the file in a multipart field named 'file'", 400)
    data = upload_file.read()
    try:
        doc = docs.create_document(g.current_user, upload_file.filename, data)
    except docs.FileValidationError as exc:
        db.session.rollback()
        return json_error(str(exc), 400)
    db.session.commit()
    return jsonify(doc.to_dict()), 201


@bp.get("")
@api_auth_required(roles=("patient", "clinician"))
def list_all():
    patient_id = request.args.get("patient_id", type=int)
    return jsonify([d.to_dict() for d in docs.list_documents(g.current_user, patient_id)])


@bp.get("/<int:doc_id>")
@api_auth_required(roles=("patient", "clinician"))
def metadata(doc_id: int):
    return jsonify(docs.get_document(g.current_user, doc_id).to_dict())


@bp.get("/<int:doc_id>/download")
@api_auth_required(roles=("patient", "clinician"))
def download(doc_id: int):
    doc, data = docs.read_document(g.current_user, doc_id)
    db.session.commit()
    return attachment_response(doc, data)


@bp.delete("/<int:doc_id>")
@api_auth_required(roles=("patient", "clinician"))
def delete(doc_id: int):
    docs.delete_document(g.current_user, doc_id)
    db.session.commit()
    return "", 204
