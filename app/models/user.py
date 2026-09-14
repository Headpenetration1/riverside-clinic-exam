from ..extensions import db
from ..utils import utcnow

ROLES = ("patient", "clinician", "admin")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="patient")
    password_hash = db.Column(db.String(255), nullable=False)   # Argon2id string, never the password
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    documents = db.relationship("Document", back_populates="owner", cascade="all, delete-orphan")
    messages = db.relationship("Message", back_populates="author", cascade="all, delete-orphan")
    refresh_tokens = db.relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    reset_tokens = db.relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        # deliberately no password_hash here, ever
        return {
            "id": self.id,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() + "Z",
        }
