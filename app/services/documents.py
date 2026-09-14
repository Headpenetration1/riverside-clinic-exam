"""Document rules shared by the JSON API and the HTML pages.

Authorization matrix:
- patient   : own documents only (read, upload, delete)
- clinician : read any patient's documents, upload their own; cannot delete others'
- admin     : manages accounts, has NO access to clinical documents (least privilege)

Unauthorised access to a specific document returns 404, not 403, so an
attacker iterating over IDs cannot even learn which IDs exist.
"""
import hmac
import json

from flask import abort

from ..extensions import db
from ..models import Document, User
from .audit import record
from .files import (
    FileIntegrityError,
    FileValidationError,
    load_decrypted,
    new_stored_name,
    remove_stored,
    sha256_hex,
    store_encrypted,
    validate_upload,
)


def _document_aad(doc: Document) -> bytes:
    """Return canonical, immutable context authenticated with the file blob."""
    context = {
        "document_id": doc.id,
        "mime_type": doc.mime_type,
        "original_name": doc.original_name,
        "owner_id": doc.owner_id,
        "sha256": doc.sha256,
        "size_bytes": doc.size_bytes,
        "stored_name": doc.stored_name,
    }
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def create_document(user: User, filename: str | None, data: bytes) -> Document:
    if user.role == "admin":
        abort(403, description="Administrators cannot upload clinical documents")
    safe_name, mime = validate_upload(filename, data)   # raises FileValidationError
    stored_name = new_stored_name()
    doc = Document(
        owner_id=user.id,
        original_name=safe_name,
        stored_name=stored_name,
        mime_type=mime,
        size_bytes=len(data),
        sha256=sha256_hex(data),
    )
    try:
        # Flush inside a savepoint so the primary key can be part of the AAD.
        # If encryption or audit creation fails, both the row and external blob
        # are cleaned up while any earlier request work remains intact.
        with db.session.begin_nested():
            db.session.add(doc)
            db.session.flush()
            store_encrypted(data, stored_name=stored_name, associated_data=_document_aad(doc))
            record("document.upload", target=f"document:{doc.id}", user=user)
    except Exception:
        remove_stored(stored_name)
        raise
    return doc


def list_documents(user: User, patient_id: int | None = None) -> list[Document]:
    if user.role == "admin":
        abort(403, description="Administrators cannot view clinical documents")
    stmt = db.select(Document).order_by(Document.uploaded_at.desc())
    if user.role == "patient":
        stmt = stmt.where(Document.owner_id == user.id)
    elif patient_id is not None:
        stmt = stmt.where(Document.owner_id == patient_id)
    return list(db.session.scalars(stmt))


def get_document(user: User, doc_id: int, *, write: bool = False) -> Document:
    if user.role == "admin":
        abort(403, description="Administrators cannot access clinical documents")
    doc = db.session.get(Document, doc_id)
    if doc is None:
        abort(404, description="Document not found")
    if user.role == "patient" and doc.owner_id != user.id:
        abort(404, description="Document not found")       # deliberately not 403
    if write and doc.owner_id != user.id:
        abort(403, description="Only the owner can modify this document")
    return doc


def read_document(user: User, doc_id: int) -> tuple[Document, bytes]:
    doc = get_document(user, doc_id)
    data = load_decrypted(doc.stored_name, associated_data=_document_aad(doc))
    digest_matches = hmac.compare_digest(doc.sha256, sha256_hex(data))
    if len(data) != doc.size_bytes or not digest_matches:
        raise FileIntegrityError("stored file failed integrity check")
    record("document.download", target=f"document:{doc.id}", user=user)
    return doc, data


def delete_document(user: User, doc_id: int) -> None:
    doc = get_document(user, doc_id, write=True)
    remove_stored(doc.stored_name)
    db.session.delete(doc)
    record("document.delete", target=f"document:{doc_id}", user=user)


__all__ = [
    "FileIntegrityError", "FileValidationError", "create_document", "list_documents", "get_document",
    "read_document", "delete_document",
]
