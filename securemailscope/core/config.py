"""
SecureMailScope - Core Configuration and Exceptions
"""
import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"

# Auto-load .env if present
env_file = BASE_DIR / ".env"
if env_file.exists():
    with open(env_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'\"")
                os.environ[key] = val

def _env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes", "on")

def _env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


class AppConfig(BaseModel):
    app_name: str = "SecureMailScope"
    version: str = "2.6.0"
    sih_problem_id: str = "SIH26159"
    organization: str = "National Technical Research Organisation (NTRO)"
    environment: str = Field(default_factory=lambda: os.environ.get("APP_ENV", "development"))
    host: str = Field(default_factory=lambda: os.environ.get("APP_HOST", "127.0.0.1"))
    port: int = Field(default_factory=lambda: _env_int("APP_PORT", 8000))
    debug: bool = Field(default_factory=lambda: _env_bool("DEBUG", False))

    # Database & Security
    database_url: str = Field(default_factory=lambda: os.environ.get("DATABASE_URL", f"sqlite:///{DATA_DIR}/securemailscope.db"))
    # Production deployments must set this explicitly. Development may use a
    # process-local random key so an accidental public default can never sign
    # sessions.
    secret_key: Optional[str] = Field(default_factory=lambda: os.environ.get("SECRET_KEY") or None)

    # Evidence & ML Paths
    evidence_db_path: Path = Field(default_factory=lambda: Path(os.environ.get("EVIDENCE_LEDGER_PATH", DATA_DIR / "evidence_ledger.json")))
    ml_model_path: Path = DATA_DIR / "xgboost_crypto_model.json"
    artifact_dir: Path = Field(default_factory=lambda: Path(os.environ.get("ARTIFACT_DIR", DATA_DIR / "artifacts")))
    tool_output_dir: Path = Field(default_factory=lambda: Path(os.environ.get("TOOL_OUTPUT_DIR", DATA_DIR / "tool-output")))
    report_dir: Path = Field(default_factory=lambda: Path(os.environ.get("REPORT_DIR", DATA_DIR / "reports")))

    # NVIDIA NIM Primary LLM
    nvidia_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("NVIDIA_NIM_API_KEY") or os.environ.get("NVIDIA_API_KEY") or None)
    nvidia_model: str = Field(default_factory=lambda: os.environ.get("NVIDIA_NIM_MODEL") or os.environ.get("NVIDIA_MODEL", "moonshotai/kimi-k3"))
    nvidia_base_url: str = Field(default_factory=lambda: os.environ.get("NVIDIA_NIM_BASE_URL") or os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"))
    nvidia_timeout_seconds: int = Field(default_factory=lambda: _env_int("NVIDIA_TIMEOUT_SECONDS", 60))

    # Google Gemini Fallback LLM
    gemini_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("GEMINI_API_KEY") or None)
    gemini_model: str = Field(default_factory=lambda: os.environ.get("GEMINI_MODEL", "gemini-3.6-flash"))
    gemini_timeout_seconds: int = Field(default_factory=lambda: _env_int("GEMINI_TIMEOUT_SECONDS", 30))

    # Tavily Search Tool
    tavily_api_key: Optional[str] = Field(default_factory=lambda: os.environ.get("TAVILY_API_KEY") or None)
    tavily_enabled: bool = Field(default_factory=lambda: _env_bool("TAVILY_ENABLED", True))
    allow_external_intel: bool = Field(default_factory=lambda: _env_bool("ALLOW_EXTERNAL_INTEL", True if os.environ.get("TAVILY_API_KEY") else False))

    # Agent Configuration
    agent_enabled: bool = Field(default_factory=lambda: _env_bool("AGENT_ENABLED", True))
    agent_max_steps: int = Field(default_factory=lambda: _env_int("AGENT_MAX_STEPS", 20))
    agent_max_tool_calls: int = Field(default_factory=lambda: _env_int("AGENT_MAX_TOOL_CALLS", 30))
    agent_timeout_seconds: int = Field(default_factory=lambda: _env_int("AGENT_TIMEOUT_SECONDS", 120))

    # Forensic Binary Paths
    tshark_path: Optional[str] = Field(default_factory=lambda: os.environ.get("TSHARK_PATH") or None)
    capinfos_path: Optional[str] = Field(default_factory=lambda: os.environ.get("CAPINFOS_PATH") or None)
    zeek_path: Optional[str] = Field(default_factory=lambda: os.environ.get("ZEEK_PATH") or None)
    openssl_path: Optional[str] = Field(default_factory=lambda: os.environ.get("OPENSSL_PATH") or None)

    # Forensic thresholds
    capture_completeness_threshold_high: float = 95.0
    capture_completeness_threshold_low: float = 60.0
    posture_score_critical_max: float = 24.0
    posture_score_high_max: float = 49.0
    posture_score_medium_max: float = 74.0
    posture_score_low_max: float = 89.0


config = AppConfig()

if config.environment.lower() in {"production", "prod"} and not config.secret_key:
    raise RuntimeError("SECRET_KEY must be configured when APP_ENV is production")

for directory in (SAMPLES_DIR, REPORTS_DIR, DATA_DIR, config.artifact_dir, config.tool_output_dir, config.report_dir):
    directory.mkdir(parents=True, exist_ok=True)


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
