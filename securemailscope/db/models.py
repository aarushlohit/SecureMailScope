"""
SecureMailScope - SQLAlchemy ORM Database Models
Designed for SQLite with full PostgreSQL portability.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    Text,
    DateTime,
    JSON,
    ForeignKey,
    Index
)
from sqlalchemy.orm import relationship
from securemailscope.db.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserModel(Base):
    __tablename__ = "users"

    user_id = Column(String(64), primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(32), default="analyst")  # analyst, admin, auditor
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)

    investigations = relationship("InvestigationModel", back_populates="user")
    auth_sessions = relationship("AuthSessionModel", back_populates="user", cascade="all, delete-orphan")


class AuthSessionModel(Base):
    __tablename__ = "auth_sessions"

    session_id = Column(String(64), primary_key=True, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True, index=True)
    user_agent = Column(String(255), nullable=True)

    user = relationship("UserModel", back_populates="auth_sessions")


class InvestigationModel(Base):
    __tablename__ = "investigations"

    investigation_id = Column(String(64), primary_key=True, index=True)
    user_id = Column(String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True)
    artifact_name = Column(String(255), nullable=False)
    artifact_path = Column(String(512), nullable=False)
    artifact_sha256 = Column(String(64), default="")
    artifact_md5 = Column(String(32), default="")
    artifact_size = Column(Integer, default=0)
    file_type = Column(String(32), default="pcap")
    status = Column(String(32), default="INGESTED", index=True)
    created_at = Column(DateTime, default=utc_now)
    completed_at = Column(DateTime, nullable=True)

    packet_count = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    completeness_percentage = Column(Float, default=100.0)
    protocols_detected = Column(JSON, default=list)
    streams_analyzed = Column(Integer, default=0)

    # Posture scorecard summary
    posture_score = Column(Float, default=100.0)
    risk_level = Column(String(32), default="SECURE")
    confidence_score = Column(Float, default=100.0)
    posture_details = Column(JSON, default=dict)

    limitations = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)

    # Relationships
    user = relationship("UserModel", back_populates="investigations")
    artifacts = relationship("ArtifactModel", back_populates="investigation", cascade="all, delete-orphan")
    sessions = relationship("ForensicSessionModel", back_populates="investigation", cascade="all, delete-orphan")
    evidence = relationship("EvidenceModel", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="investigation", cascade="all, delete-orphan")
    hypotheses = relationship("HypothesisModel", back_populates="investigation", cascade="all, delete-orphan")
    tool_executions = relationship("ToolExecutionModel", back_populates="investigation", cascade="all, delete-orphan")
    agent_runs = relationship("AgentRunModel", back_populates="investigation", cascade="all, delete-orphan")
    audit_events = relationship("AuditEventModel", back_populates="investigation", cascade="all, delete-orphan")


class EvidenceModel(Base):
    __tablename__ = "evidence"

    evidence_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True, index=True)
    type = Column(String(64), nullable=False, index=True)  # OBSERVED, DERIVED, ML_CLASSIFICATION, etc.
    claim = Column(Text, nullable=False)
    source_tool = Column(String(64), nullable=False)
    tool_version = Column(String(32), default="1.0")
    tool_args = Column(JSON, default=dict)
    raw_artifact_ref = Column(String(255), default="")
    timestamp = Column(DateTime, default=utc_now)
    confidence = Column(Float, default=1.0)
    severity = Column(String(32), default="informational")
    hypothesis_id = Column(String(64), nullable=True, index=True)
    provenance_chain = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    previous_entry_hash = Column(String(64), nullable=True, index=True)
    entry_hash = Column(String(64), nullable=True, index=True)

    investigation = relationship("InvestigationModel", back_populates="evidence")
    user = relationship("UserModel")



class FindingModel(Base):
    __tablename__ = "findings"

    finding_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), default="CANDIDATE", index=True)  # CANDIDATE, SUPPORTED, VERIFIED, REFUTED, INCONCLUSIVE
    confidence = Column(Float, default=1.0)
    evidence_ids = Column(JSON, default=list)  # Must strictly link to valid evidence
    rule_id = Column(String(64), nullable=True)
    hypothesis_id = Column(String(64), nullable=True)
    remediation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    investigation = relationship("InvestigationModel", back_populates="findings")


class HypothesisModel(Base):
    __tablename__ = "hypotheses"

    hypothesis_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(32), default="PROPOSED", index=True)
    confidence = Column(Float, default=0.5)
    supporting_evidence_ids = Column(JSON, default=list)
    refuting_evidence_ids = Column(JSON, default=list)
    notes = Column(JSON, default=list)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    investigation = relationship("InvestigationModel", back_populates="hypotheses")


class ToolExecutionModel(Base):
    __tablename__ = "tool_executions"

    execution_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    tool = Column(String(64), nullable=False, index=True)
    tool_version = Column(String(32), default="1.0")
    args = Column(JSON, default=dict)
    status = Column(String(32), default="SUCCESS")
    start_time = Column(DateTime, default=utc_now)
    end_time = Column(DateTime, default=utc_now)
    stdout_summary = Column(Text, default="")
    stderr = Column(Text, default="")
    evidence_ids = Column(JSON, default=list)

    investigation = relationship("InvestigationModel", back_populates="tool_executions")


class AgentRunModel(Base):
    __tablename__ = "agent_runs"

    run_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default="RUNNING")
    start_time = Column(DateTime, default=utc_now)
    end_time = Column(DateTime, nullable=True)
    steps_count = Column(Integer, default=0)
    llm_provider = Column(String(32), default="deterministic")
    llm_model = Column(String(64), default="")
    deterministic_fallback = Column(Boolean, default=True)

    investigation = relationship("InvestigationModel", back_populates="agent_runs")
    steps = relationship("AgentStepModel", back_populates="run", cascade="all, delete-orphan")


class AgentStepModel(Base):
    __tablename__ = "agent_steps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    step_number = Column(Integer, nullable=False)
    run_id = Column(String(64), ForeignKey("agent_runs.run_id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id = Column(String(64), nullable=False, index=True)
    state = Column(String(32), nullable=False)  # OBSERVE, HYPOTHESIZE, PLAN, SELECT_TOOL, EXECUTE, etc.
    hypothesis = Column(String(255), nullable=True)
    selected_tool = Column(String(64), nullable=True)
    tool_arguments = Column(JSON, default=dict)
    reason = Column(Text, default="")
    result = Column(JSON, default=dict)
    evidence_ids = Column(JSON, default=list)
    next_action = Column(String(255), default="")
    provider = Column(String(32), default="deterministic")
    model = Column(String(64), default="")
    timestamp = Column(DateTime, default=utc_now)
    duration = Column(Float, default=0.0)

    run = relationship("AgentRunModel", back_populates="steps")


class MLPredictionModel(Base):
    __tablename__ = "ml_predictions"

    prediction_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    model_name = Column(String(64), default="XGBoostCryptoRisk")
    model_version = Column(String(32), default="1.0")
    predicted_class = Column(String(64), nullable=False)
    risk_probability = Column(Float, default=0.0)
    class_confidence = Column(Float, default=0.0)
    is_anomalous = Column(Boolean, default=False)
    shap_attributions = Column(JSON, default=dict)
    feature_vector = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=utc_now)


class ExternalEvidenceModel(Base):
    __tablename__ = "external_evidence"

    external_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    hypothesis_id = Column(String(64), nullable=True, index=True)
    query = Column(String(512), nullable=False)
    provider = Column(String(32), default="tavily")
    timestamp = Column(DateTime, default=utc_now)
    urls = Column(JSON, default=list)
    titles = Column(JSON, default=list)
    snippets = Column(JSON, default=list)
    retrieval_metadata = Column(JSON, default=dict)


class RecommendationModel(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(64), nullable=True)
    title = Column(String(255), nullable=False)
    action_text = Column(Text, nullable=False)
    priority = Column(String(32), default="medium")
    created_at = Column(DateTime, default=utc_now)


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    event_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=True, index=True)
    timestamp = Column(DateTime, default=utc_now)
    actor = Column(String(64), nullable=False)  # "INVESTIGATION_AGENT", "LLM_ROUTER", "GATEKEEPER", etc.
    action = Column(String(64), nullable=False)
    provider = Column(String(32), nullable=True)
    model = Column(String(64), nullable=True)
    latency_ms = Column(Float, nullable=True)
    tokens_used = Column(Integer, nullable=True)
    success = Column(Boolean, default=True)
    failure_reason = Column(Text, nullable=True)
    details = Column(JSON, default=dict)

    investigation = relationship("InvestigationModel", back_populates="audit_events")


class ArtifactModel(Base):
    __tablename__ = "artifacts"

    artifact_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_name = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, default=0)
    sha256 = Column(String(64), default="")
    md5 = Column(String(32), default="")
    file_type = Column(String(32), default="pcap")
    created_at = Column(DateTime, default=utc_now)
    meta_info = Column(JSON, default=dict)

    investigation = relationship("InvestigationModel", back_populates="artifacts")


class ForensicSessionModel(Base):
    __tablename__ = "forensic_sessions"

    session_id = Column(String(64), primary_key=True, index=True)
    investigation_id = Column(String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), nullable=False, index=True)
    stream_id = Column(Integer, nullable=False)
    client_ip = Column(String(64), default="")
    server_ip = Column(String(64), default="")
    client_port = Column(Integer, default=0)
    server_port = Column(Integer, default=0)
    protocol = Column(String(32), default="UNKNOWN")
    tls_version = Column(String(32), nullable=True)
    cipher_suite = Column(String(128), nullable=True)
    sni = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now)
    details = Column(JSON, default=dict)

    investigation = relationship("InvestigationModel", back_populates="sessions")
