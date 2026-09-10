"""
SecureMailScope - Data Models & Schemas
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InvestigationStatus(str, Enum):
    INGESTED = "INGESTED"
    ANALYZING = "ANALYZING"
    INVESTIGATING = "INVESTIGATING"
    WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FindingStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    SUPPORTED = "SUPPORTED"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class HypothesisStatus(str, Enum):
    PROPOSED = "PROPOSED"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    LEAVE_UNCHANGED = "LEAVE_UNCHANGED"
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EvidenceType(str, Enum):
    CAPTURE_METADATA = "capture_metadata"
    CAPTURE_COMPLETENESS = "capture_completeness"
    PROTOCOL_IDENTIFIED = "protocol_identified"
    TCP_STREAM_RECONSTRUCTED = "tcp_stream_reconstructed"
    STARTTLS_ADVERTISED = "starttls_advertised"
    STARTTLS_REQUESTED = "starttls_requested"
    STARTTLS_ACCEPTED = "starttls_accepted"
    STARTTLS_STRIPPED = "starttls_stripped"
    PLAINTEXT_CONTINUATION = "plaintext_continuation"
    TLS_CLIENT_HELLO = "tls_client_hello"
    TLS_SERVER_HELLO = "tls_server_hello"
    TLS_VERSION_DETECTED = "tls_version_detected"
    CIPHER_SUITE_DETECTED = "cipher_suite_detected"
    KEY_EXCHANGE_DETECTED = "key_exchange_detected"
    CERTIFICATE_EXTRACTED = "certificate_extracted"
    CERTIFICATE_VALIDATION = "certificate_validation"
    CRYPTO_RULE_TRIGGERED = "crypto_rule_triggered"
    ML_PREDICTION = "ml_prediction"
    EXTERNAL_INTEL = "external_intel"


class Evidence(BaseModel):
    evidence_id: str
    investigation_id: str
    type: EvidenceType
    claim: str
    source_tool: str
    tool_version: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    raw_artifact_ref: str
    timestamp: str = Field(default_factory=utc_now_iso)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    hypothesis_id: Optional[str] = None
    provenance_chain: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class ToolExecution(BaseModel):
    execution_id: str
    investigation_id: str
    tool: str
    tool_version: str
    args: Dict[str, Any]
    status: str
    start_time: str
    end_time: str
    stdout_summary: str = ""
    stderr: str = ""
    evidence_ids: List[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    hypothesis_id: str
    investigation_id: str
    title: str
    description: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = 0.5
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    refuting_evidence_ids: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)


class Finding(BaseModel):
    finding_id: str
    investigation_id: str
    title: str
    description: str
    severity: SeverityLevel
    status: FindingStatus = FindingStatus.CANDIDATE
    confidence: float = 1.0
    evidence_ids: List[str]
    rule_id: Optional[str] = None
    hypothesis_id: Optional[str] = None
    remediation: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)


class TimelineEvent(BaseModel):
    event_id: str
    timestamp: str = Field(default_factory=utc_now_iso)
    phase: str
    actor: str  # "SYSTEM", "TOOL", "AGENT", "VERIFIER"
    action: str
    detail: str
    evidence_id: Optional[str] = None
    hypothesis_id: Optional[str] = None


class PostureScorecard(BaseModel):
    overall_posture_score: float  # 0 to 100
    risk_level: str  # SECURE, LOW RISK, MEDIUM RISK, HIGH RISK, CRITICAL RISK
    confidence_score: float  # 0 to 100
    score_deductions: List[Dict[str, Any]] = Field(default_factory=list)
    bonus_points: List[Dict[str, Any]] = Field(default_factory=list)
    ml_risk_probability: float = 0.0
    ml_anomaly_contribution: float = 0.0


class Investigation(BaseModel):
    investigation_id: str
    artifact_name: str
    artifact_path: str
    artifact_sha256: str
    artifact_md5: str
    artifact_size: int
    file_type: str = "pcap"
    status: InvestigationStatus = InvestigationStatus.INGESTED
    created_at: str = Field(default_factory=utc_now_iso)
    completed_at: Optional[str] = None
    packet_count: int = 0
    duration_seconds: float = 0.0
    completeness_percentage: float = 100.0
    protocols_detected: List[str] = Field(default_factory=list)
    streams_analyzed: int = 0
    posture: Optional[PostureScorecard] = None
    evidence_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    hypothesis_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
