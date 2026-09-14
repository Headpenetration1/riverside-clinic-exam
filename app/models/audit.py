from ..extensions import db
from ..utils import utcnow


class AuditEvent(db.Model):
    """Who did what, when, from where. Never stores document contents,
    passwords, tokens or chat text - only the fact that something happened."""
    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "ip": self.ip,
            "at": self.created_at.isoformat() + "Z",
        }
