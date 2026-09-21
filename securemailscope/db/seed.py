"""
SecureMailScope - Database Seeding Utility
Creates default SOC analyst user account if not already present.
"""
import uuid
import logging
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import UserModel
from securemailscope.core.security import hash_password

logger = logging.getLogger("securemailscope.db.seed")


def seed_default_user():
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter_by(email="alex.morgan@soc.internal").first()
        if not user:
            user = UserModel(
                user_id="USR-SOC-ALEX",
                email="alex.morgan@soc.internal",
                password_hash=hash_password("password123"),
                full_name="Alex Morgan",
                role="analyst",
                is_active=True
            )
            db.add(user)
            db.commit()
            logger.info("Default analyst user alex.morgan@soc.internal seeded.")
    except Exception as e:
        logger.warning(f"Could not seed default user: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_default_user()
    print("[+] Seeding completed.")
