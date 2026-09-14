from ..extensions import db
from ..utils import utcnow


class Message(db.Model):
    """Noticeboard posts. User-controlled text that gets rendered back to other
    users, i.e. exactly where stored XSS would live if we got escaping wrong."""
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    author = db.relationship("User", back_populates="messages")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "author": self.author.full_name,
            "body": self.body,
            "created_at": self.created_at.isoformat() + "Z",
        }
