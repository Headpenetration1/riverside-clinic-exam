"""Create demo accounts. Passwords come from the environment, never from source.

    SEED_PASSWORD='some-long-passphrase' python scripts/seed.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app                      # noqa: E402
from app.extensions import db                   # noqa: E402
from app.models import User                     # noqa: E402
from app.services.security import check_password_policy, hash_password  # noqa: E402

ACCOUNTS = [
    ("admin@riverside.example", "Portal Admin", "admin"),
    ("dr.hansen@riverside.example", "Dr Ingrid Hansen", "clinician"),
    ("patient@riverside.example", "Test Patient", "patient"),
]

if __name__ == "__main__":
    password = os.environ.get("SEED_PASSWORD")
    if not password:
        sys.exit("Set SEED_PASSWORD to a passphrase of at least 15 characters")
    check_password_policy(password)
    app = create_app()
    with app.app_context():
        for email, name, role in ACCOUNTS:
            if db.session.scalar(db.select(User).where(User.email == email)) is None:
                db.session.add(User(email=email, full_name=name, role=role, password_hash=hash_password(password)))
                print(f"created {role:<9} {email}")
        db.session.commit()
