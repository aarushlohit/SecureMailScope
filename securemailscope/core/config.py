"""
SecureMailScope - Core Configuration and Exceptions
"""
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"

for directory in (SAMPLES_DIR, REPORTS_DIR, DATA_DIR):
    directory.mkdir(parents=True, exist_ok=True)


class AppConfig(BaseModel):
    app_name: str = "SecureMailScope"
    version: str = "1.0.0"
    sih_problem_id: str = "SIH26159"
    organization: str = "National Technical Research Organisation (NTRO)"
    environment: str = "production"
    debug: bool = False
    evidence_db_path: Path = DATA_DIR / "evidence_ledger.json"
    ml_model_path: Path = DATA_DIR / "xgboost_crypto_model.json"
    
    # Forensic thresholds
    capture_completeness_threshold_high: float = 95.0
    capture_completeness_threshold_low: float = 60.0
    posture_score_critical_max: float = 24.0
    posture_score_high_max: float = 49.0
    posture_score_medium_max: float = 74.0
    posture_score_low_max: float = 89.0


config = AppConfig()


class SecureMailScopeException(Exception):
    """Base exception for SecureMailScope."""
    pass


class InvalidArtifactError(SecureMailScopeException):
    """Raised when an uploaded PCAP or file is invalid or corrupted."""
    pass


class EvidenceValidationError(SecureMailScopeException):
    """Raised when finding validation fails due to invalid or unpersisted evidence."""
    pass


class ToolExecutionError(SecureMailScopeException):
    """Raised when a forensic tool execution fails in the gateway."""
    pass


class HypothesisStateError(SecureMailScopeException):
    """Raised on invalid hypothesis state transitions."""
    pass
