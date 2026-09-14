from flask import g

from ..extensions import db
from ..models import AuditEvent
from ..utils import client_ip

_CURRENT_USER = object()


def record(action: str, target: str | None = None, user=_CURRENT_USER) -> None:
    """Add an audit row to the current session (the caller commits).

    Omitting ``user`` attributes the event to ``g.current_user``. Passing
    ``None`` explicitly records an anonymous actor, which is important when
    retaining the account-deletion event after its user row is removed.
    """
    if user is _CURRENT_USER:
        user = g.get("current_user")
    db.session.add(AuditEvent(
        user_id=user.id if user is not None else None,
        action=action,
        target=(target or "")[:255] or None,
        ip=client_ip(),
    ))
