"""
SecureMailScope - Database Engine and Session Factory
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from securemailscope.core.config import config

db_url = config.database_url
connect_args = {}
if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    db_url,
    connect_args=connect_args,
    echo=config.debug
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def setup_evidence_triggers(eng=engine):
    """Installs SQLite immutability triggers on the evidence table."""
    from sqlalchemy import text
    try:
        with eng.connect() as conn:
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS prevent_evidence_update
                BEFORE UPDATE ON evidence
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(FAIL, 'IMMUTABLE_VIOLATION: Evidence records cannot be updated. Evidence ledger is append-only.');
                END;
            """))
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS prevent_evidence_delete
                BEFORE DELETE ON evidence
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(FAIL, 'IMMUTABLE_VIOLATION: Evidence records cannot be deleted. Evidence ledger is append-only.');
                END;
            """))
            conn.commit()
    except Exception:
        pass


def migrate_evidence_integrity(eng=engine):
    """
    Safely adds user_id, previous_entry_hash, and entry_hash columns if missing,
    and backfills sequential hash chain for legacy evidence records.
    """
    import json
    from sqlalchemy import text
    from securemailscope.evidence.hasher import compute_hash_for_evidence, GENESIS_HASH

    with eng.connect() as conn:
        try:
            res = conn.execute(text("PRAGMA table_info(evidence)")).fetchall()
            existing_cols = {row[1] for row in res}
        except Exception:
            return

        if not existing_cols:
            return

        # Add missing columns
        if "user_id" not in existing_cols:
            try:
                conn.execute(text("ALTER TABLE evidence ADD COLUMN user_id VARCHAR(64) REFERENCES users(user_id) ON DELETE SET NULL"))
                conn.commit()
            except Exception:
                pass

        if "previous_entry_hash" not in existing_cols:
            try:
                conn.execute(text("ALTER TABLE evidence ADD COLUMN previous_entry_hash VARCHAR(64)"))
                conn.commit()
            except Exception:
                pass

        if "entry_hash" not in existing_cols:
            try:
                conn.execute(text("ALTER TABLE evidence ADD COLUMN entry_hash VARCHAR(64)"))
                conn.commit()
            except Exception:
                pass

        # Temporarily drop triggers if they exist to allow legacy backfill
        try:
            conn.execute(text("DROP TRIGGER IF EXISTS prevent_evidence_update"))
            conn.commit()
        except Exception:
            pass

        # Backfill user_id from investigations
        try:
            conn.execute(text("""
                UPDATE evidence
                SET user_id = (
                    SELECT user_id FROM investigations
                    WHERE investigations.investigation_id = evidence.investigation_id
                )
                WHERE user_id IS NULL AND EXISTS (
                    SELECT 1 FROM investigations
                    WHERE investigations.investigation_id = evidence.investigation_id AND investigations.user_id IS NOT NULL
                )
            """))
            conn.commit()
        except Exception:
            pass

        # Backfill sequential hashes for rows
        rows = conn.execute(text("""
            SELECT evidence_id, investigation_id, user_id, type, claim, source_tool, 
                   tool_version, tool_args, raw_artifact_ref, timestamp, confidence, 
                   severity, hypothesis_id, provenance_chain, details, previous_entry_hash, entry_hash
            FROM evidence
            ORDER BY timestamp ASC, evidence_id ASC
        """)).fetchall()

        if rows:
            prev_hash = GENESIS_HASH
            for r in rows:
                row_dict = {
                    "evidence_id": r[0],
                    "investigation_id": r[1],
                    "user_id": r[2],
                    "type": r[3],
                    "claim": r[4],
                    "source_tool": r[5],
                    "tool_version": r[6] or "1.0",
                    "tool_args": json.loads(r[7]) if isinstance(r[7], str) else (r[7] or {}),
                    "raw_artifact_ref": r[8] or "",
                    "timestamp": r[9],
                    "confidence": r[10] or 1.0,
                    "severity": r[11] or "informational",
                    "hypothesis_id": r[12],
                    "provenance_chain": json.loads(r[13]) if isinstance(r[13], str) else (r[13] or []),
                    "details": json.loads(r[14]) if isinstance(r[14], str) else (r[14] or {}),
                    "previous_entry_hash": r[15],
                    "entry_hash": r[16]
                }

                expected_hash = compute_hash_for_evidence(row_dict, prev_hash)
                if not row_dict["entry_hash"] or row_dict["entry_hash"] != expected_hash or row_dict["previous_entry_hash"] != prev_hash:
                    conn.execute(
                        text("UPDATE evidence SET previous_entry_hash = :p_hash, entry_hash = :e_hash WHERE evidence_id = :eid"),
                        {"p_hash": prev_hash, "e_hash": expected_hash, "eid": r[0]}
                    )
                prev_hash = expected_hash
            conn.commit()


def init_db():
    from securemailscope.db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    migrate_evidence_integrity(engine)
    setup_evidence_triggers(engine)

