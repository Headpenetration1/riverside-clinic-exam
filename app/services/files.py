"""Upload validation and encrypted storage.

Validation is allowlist-only: the extension must be one we serve, and the
first bytes must match that type. A .pdf that starts with <html> is rejected,
so nothing we later serve can be sniffed into something executable.

Storage: each file is encrypted with AES-256-GCM under a key from the
environment, written under a random hex name outside the web root. New blobs
use a versioned envelope and authenticate caller-supplied document metadata as
AES-GCM associated data. GCM therefore protects both the bytes and the database
context they belong to. The reader still accepts the original nonce-first
format so existing installations can migrate without losing documents; callers
must verify the database's plaintext digest after decrypting those legacy blobs.
"""
import base64
import hashlib
import os
import re
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app
from werkzeug.utils import secure_filename

MAGIC = {
    "pdf": (b"%PDF-",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
}
MIME = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}
STORED_NAME_RE = re.compile(r"^[0-9a-f]{32}$")
NONCE_LEN = 12
GCM_TAG_LEN = 16
FILE_FORMAT_V1 = b"RIVERSIDE-FILE\x00\x01"


class FileValidationError(ValueError):
    pass


class FileIntegrityError(RuntimeError):
    """The encrypted bytes do not belong to the expected document context."""


def validate_upload(filename: str | None, data: bytes) -> tuple[str, str]:
    """Return (safe_display_name, mime_type) or raise FileValidationError."""
    safe = secure_filename(filename or "")
    if not safe or "." not in safe:
        raise FileValidationError("Filename must have an allowed extension")
    ext = safe.rsplit(".", 1)[1].lower()
    if ext not in current_app.config["ALLOWED_EXTENSIONS"]:
        raise FileValidationError(f"File type .{ext} is not allowed")
    if not data:
        raise FileValidationError("File is empty")
    if not any(data.startswith(magic) for magic in MAGIC[ext]):
        raise FileValidationError("File content does not match its extension")
    return safe[:255], MIME[ext]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key() -> bytes:
    key = base64.b64decode(current_app.config["FILE_ENCRYPTION_KEY"])
    if len(key) != 32:
        raise RuntimeError("FILE_ENCRYPTION_KEY must be 32 bytes")
    return key


def _path(stored_name: str) -> str:
    # belt and braces: the name comes from our own DB, but check it anyway
    if not STORED_NAME_RE.match(stored_name):
        raise ValueError("invalid stored name")
    return os.path.join(current_app.config["UPLOAD_DIR"], stored_name)


def new_stored_name() -> str:
    return uuid.uuid4().hex


def store_encrypted(data: bytes, *, stored_name: str, associated_data: bytes) -> str:
    """Write a v1 encrypted blob bound to immutable document metadata.

    ``stored_name`` is allocated before this call so the database row can be
    flushed and its primary key included in ``associated_data``. The exclusive
    create prevents an unexpected existing file from being overwritten.
    """
    if not associated_data:
        raise ValueError("associated data is required for encrypted file storage")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_key()).encrypt(nonce, data, FILE_FORMAT_V1 + associated_data)
    path = _path(stored_name)
    try:
        with open(path, "xb") as fh:
            fh.write(FILE_FORMAT_V1 + nonce + ciphertext)
        os.chmod(path, 0o600)
    except Exception:
        # A short/partially written blob must never survive a failed upload.
        remove_stored(stored_name)
        raise
    return stored_name


def load_decrypted(stored_name: str, *, associated_data: bytes) -> bytes:
    """Decrypt a v1 blob, or a digest-verified legacy blob via the caller.

    Legacy blobs have no format marker and used ``nonce || ciphertext`` with no
    associated data. Supporting that shape keeps existing uploads readable;
    the document service's mandatory SHA-256 check supplies swap detection for
    those rows until they are re-encrypted.
    """
    with open(_path(stored_name), "rb") as fh:
        blob = fh.read()

    if blob.startswith(FILE_FORMAT_V1):
        payload = blob[len(FILE_FORMAT_V1):]
        aad = FILE_FORMAT_V1 + associated_data
    else:
        payload = blob
        aad = None

    if len(payload) < NONCE_LEN + GCM_TAG_LEN:
        raise FileIntegrityError("stored file failed integrity check")
    nonce, ciphertext = payload[:NONCE_LEN], payload[NONCE_LEN:]
    try:
        return AESGCM(_key()).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise FileIntegrityError("stored file failed integrity check") from None


def remove_stored(stored_name: str) -> None:
    try:
        os.remove(_path(stored_name))
    except FileNotFoundError:
        pass
