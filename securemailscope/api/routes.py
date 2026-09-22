"""
SecureMailScope - Production REST & SSE API Routes
"""
import uuid
import shutil
import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request, Response, BackgroundTasks, Depends
from fastapi.responses import FileResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse
from sqlalchemy.orm import Session

from securemailscope.core.config import config, SAMPLES_DIR, REPORTS_DIR, DATA_DIR
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.ml.benchmark import BenchmarkEngine
from securemailscope.forensics.tcp_stream import TCPReconstructionEngine
from securemailscope.forensics.system_tools import SystemToolDiscovery
from securemailscope.forensics.knowledge_graph import KnowledgeGraphEngine
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter
from backend.llm.router import LLMRouter
from backend.llm.schemas import ChatRequest as LLMChatRequest, ChatMessage
from securemailscope.api.sse import SSEEventBus
from securemailscope.db.session import SessionLocal, get_db
from securemailscope.db.models import InvestigationModel, AgentStepModel, ArtifactModel, ForensicSessionModel

from securemailscope.api.auth import auth_router, get_current_user, get_current_user_optional
from securemailscope.db.models import UserModel

router = APIRouter(prefix="/api")
router.include_router(auth_router)
logger = logging.getLogger("securemailscope.api.routes")
ledger = EvidenceLedger.get_instance()
llm_router = LLMRouter()
agent = InvestigationAgent(ledger, router=llm_router)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB limit
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".eml"}
VALID_MAGIC_PREFIXES = (
    b"\xd4\xc3\xb2\xa1",  # PCAP LE
    b"\xa1\xb2\xc3\xd4",  # PCAP BE
    b"\x4d\x3c\xb2\xa1",  # PCAP-NS LE
    b"\xa1\xb2\x3c\x4d",  # PCAP-NS BE
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG Section Header Block
    b"\x1f\x8b"           # GZIP compressed PCAP
)


def validate_and_save_pcap(upload_file: UploadFile, dest_path: Path) -> int:
    filename = upload_file.filename or ""
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal attempted.")

    clean_name = Path(filename).name

    ext = Path(clean_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension '{ext}'. Only .pcap, .pcapng, .cap, and .eml are permitted."
        )

    bytes_read = 0
    with open(dest_path, "wb") as out_f:
        first_chunk = upload_file.file.read(4096)
        if not first_chunk:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        if ext in (".pcap", ".pcapng", ".cap"):
            if not any(first_chunk.startswith(magic) for magic in VALID_MAGIC_PREFIXES):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid file format: file signature does not match PCAP or PCAP-NG."
                )
        elif ext == ".eml":
            # EML validation: must be text-based RFC-822 header
            try:
                first_text = first_chunk.decode("utf-8", errors="ignore")
                valid_eml_headers = ("from:", "received:", "return-path:", "date:", "subject:", "message-id:", "mime-version:", "delivered-to:", "content-type:")
                if not any(h in first_text.lower() for h in valid_eml_headers):
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid file format: file content does not conform to RFC-2822 / EML format."
                    )
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid EML file encoding.")

        bytes_read += len(first_chunk)
        out_f.write(first_chunk)

        while True:
            chunk = upload_file.file.read(65536)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > MAX_UPLOAD_SIZE:
                dest_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowed size of {MAX_UPLOAD_SIZE // (1024 * 1024)}MB."
                )
            out_f.write(chunk)

    return bytes_read


class ChatRequest(BaseModel):
    message: str
    deep_research: bool = False


class AgentStepRequest(BaseModel):
    tool_name: Optional[str] = None
    tool_arguments: Optional[Dict[str, Any]] = None
    hypothesis_id: Optional[str] = None


def require_owned_investigation_model(
    investigation_id: str,
    current_user: UserModel,
    db: Session,
) -> InvestigationModel:
    inv = db.query(InvestigationModel).filter(
        InvestigationModel.investigation_id == investigation_id,
        InvestigationModel.user_id == current_user.user_id,
    ).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return inv


def _serialize_investigation(investigation_id: str) -> Dict[str, Any]:
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    d = inv.model_dump()
    d["security_score"] = inv.posture.overall_posture_score if inv.posture else 100.0
    d["risk_level"] = inv.posture.risk_level.replace(" RISK", "") if inv.posture else "SECURE"
    d["confidence_score"] = (inv.posture.confidence_score / 100.0) if inv.posture else 1.0
    d["completeness_ratio"] = (inv.completeness_percentage / 100.0) if inv.completeness_percentage else 1.0
    d["stream_count"] = inv.streams_analyzed

    d["findings"] = [f.model_dump() for f in ledger.get_findings_for_investigation(investigation_id)]
    d["evidence_ledger"] = [e.model_dump() for e in ledger.get_evidence_for_investigation(investigation_id)]
    d["investigation_timeline"] = [t.model_dump() for t in ledger.get_timeline(investigation_id)]
    d["hypotheses"] = [h.model_dump() for h in ledger.get_hypotheses_for_investigation(investigation_id)]

    try:
        with SessionLocal() as db_session:
            steps = db_session.query(AgentStepModel).filter_by(investigation_id=investigation_id).order_by(AgentStepModel.step_number.asc()).all()
            d["agent_steps"] = [
                {
                    "step_number": s.step_number,
                    "state": s.state,
                    "hypothesis": s.hypothesis,
                    "tool": s.selected_tool,
                    "tool_arguments": s.tool_arguments,
                    "reason": s.reason,
                    "result": s.result,
                    "evidence_ids": s.evidence_ids,
                    "next_action": s.next_action,
                    "provider": s.provider,
                    "model": s.model,
                    "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                    "duration": s.duration
                }
                for s in steps
            ]
    except Exception:
        d["agent_steps"] = []

    if inv.artifact_path and Path(inv.artifact_path).exists():
        try:
            streams = TCPReconstructionEngine.reconstruct_streams(inv.artifact_path)
            d["tcp_streams"] = [s.to_dict() for s in streams]
        except Exception:
            d["tcp_streams"] = []
    else:
        d["tcp_streams"] = []

    return d


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "platform": config.app_name,
        "version": config.version,
        "environment": config.environment,
        "database": config.database_url.split("://")[0]
    }


@router.get("/system/tools")
def get_system_tools():
    """
    Returns installed, path, version, and health status for system binaries:
    tshark, capinfos, zeek, and openssl.
    """
    return SystemToolDiscovery.discover_all()


@router.get("/system/llm/status")
async def get_system_llm_status():
    """
    Returns real status of NVIDIA, Gemini, and Tavily without exposing secrets.
    """
    return await llm_router.get_system_llm_status()


@router.get("/ml/metrics")
@router.get("/ml/benchmark")
def get_ml_metrics():
    """
    Calculates and returns empirical benchmark and performance metrics:
    Precision, Recall, F1, Accuracy, Feature Attribution, and Confusion Matrix.
    """
    return BenchmarkEngine.evaluate_benchmark(num_samples=600)


@router.post("/ml/retrain")
def retrain_ml_model(num_synthetic: int = 1600):
    """
    Triggers end-to-end retraining of the XGBoost CryptoRiskClassifier
    using the multi-source RealDatasetPipeline (Authentic PCAPs + EFF Transparency data).
    """
    from securemailscope.ml.model import CryptoRiskClassifier
    classifier = CryptoRiskClassifier.get_instance()
    report = classifier.train_and_save(num_synthetic=num_synthetic)
    return {
        "status": "SUCCESS",
        "message": "Model retrained successfully on multi-source authentic datasets.",
        "report": report
    }


@router.get("/ml/dataset/stats")
def get_ml_dataset_stats():
    """
    Returns real dataset statistics, including authentic PCAP captures,
    EFF domain coverage, and latest training evaluation metrics.
    """
    from securemailscope.ml.model import CryptoRiskClassifier
    from securemailscope.ml.real_dataset_pipeline import RealDatasetPipeline
    classifier = CryptoRiskClassifier.get_instance()
    report = classifier.get_training_report()
    _, _, live_stats = RealDatasetPipeline.build_comprehensive_training_set(num_synthetic=100)
    return {
        "dataset_summary": live_stats,
        "latest_training_report": report
    }




@router.get("/all-findings")
def get_all_findings(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns all verified findings recorded in the Evidence Ledger across all investigations.
    """
    rule_score_deductions = {
        "RULE-STARTTLS-PLAINTEXT-VIOLATION": 80.0,
        "RULE-CIPHER-BROKEN": 40.0,
        "RULE-TLS-DEPRECATED": 35.0,
        "RULE-CLEARTEXT-AUTH": 30.0,
        "RULE-CIPHER-LEGACY": 25.0,
        "RULE-NO-PFS": 20.0,
        "RULE-CERT-EXPIRED": 25.0,
        "RULE-KEY-WEAK": 25.0,
        "RULE-SIG-WEAK": 15.0,
    }
    allowed_investigation_ids = {
        row.investigation_id
        for row in db.query(InvestigationModel.investigation_id).filter_by(user_id=current_user.user_id).all()
    }
    fnds = [f for f in ledger.get_all_findings() if f.investigation_id in allowed_investigation_ids]
    result = []
    for f in fnds:
        d = f.model_dump()
        d["severity"] = f.severity.value
        d["score_deduction"] = rule_score_deductions.get(f.rule_id, 20.0) if f.rule_id else 0.0
        result.append(d)
    return result


@router.get("/intel/query")
def query_intel(intel_type: str, target: str):
    """
    Controlled external threat intelligence / DNS policy query endpoint.
    Performs real passive DNS lookups (MX, SPF, DMARC, MTA-STS, TLSA) or Tavily OSINT search
    strictly guarded by SSRF validation and sandboxing.
    """
    from securemailscope.tools.dns_tools import DNSSecurityTools
    from securemailscope.tools.tavily import TavilySearchTool

    itype = intel_type.lower().strip()
    target_clean = target.strip()

    if itype in ("ip", "domain", "mx"):
        # For domain / IP / MX lookups, run real DNS policy queries
        mx_res = DNSSecurityTools.query_mx(target_clean)
        spf_res = DNSSecurityTools.query_spf(target_clean)
        dmarc_res = DNSSecurityTools.query_dmarc(target_clean)
        sts_res = DNSSecurityTools.query_mta_sts(target_clean)
        tlsa_res = DNSSecurityTools.query_tlsa(target_clean)

        return {
            "query_type": itype,
            "target": target_clean,
            "dns_security": {
                "mx": mx_res,
                "spf": spf_res,
                "dmarc": dmarc_res,
                "mta_sts": sts_res,
                "dane_tlsa": tlsa_res
            }
        }
    elif itype in ("spf",):
        return DNSSecurityTools.query_spf(target_clean)
    elif itype in ("dmarc",):
        return DNSSecurityTools.query_dmarc(target_clean)
    elif itype in ("mta-sts", "sts"):
        return DNSSecurityTools.query_mta_sts(target_clean)
    elif itype in ("tlsa", "dane"):
        return DNSSecurityTools.query_tlsa(target_clean)
    elif itype in ("tavily", "osint", "search"):
        res = TavilySearchTool.execute(
            investigation_id="GLOBAL_INTEL",
            query=f"email security threat {target_clean}",
            max_results=5
        )
        return {
            "query_type": "tavily_osint",
            "target": target_clean,
            "tavily_result": res
        }
    elif itype in ("certificate", "cert"):
        # Cert lookup by domain or SHA256
        tlsa_res = DNSSecurityTools.query_tlsa(target_clean)
        return {
            "query_type": "certificate",
            "target": target_clean,
            "dane_tlsa_records": tlsa_res,
            "note": "Certificate transparency & TLSA DANE DNS records resolved."
        }
    else:
        # Default fallback: full DNS security bundle
        return {
            "query_type": itype,
            "target": target_clean,
            "mx": DNSSecurityTools.query_mx(target_clean),
            "spf": DNSSecurityTools.query_spf(target_clean),
            "dmarc": DNSSecurityTools.query_dmarc(target_clean)
        }


@router.get("/samples")
def list_samples():
    samples = []
    for p in SAMPLES_DIR.glob("*.pcap"):
        samples.append({
            "name": p.name,
            "size_bytes": p.stat().st_size,
            "path": str(p.resolve())
        })
    return {"samples": samples}


@router.post("/investigations")
async def create_investigation(
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    sample_name: Optional[str] = Form(None),
    background: bool = Form(False),
    current_user: UserModel = Depends(get_current_user)
):
    inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    pcap_dest: Path

    if file and file.filename:
        safe_name = Path(file.filename).name
        pcap_dest = DATA_DIR / f"{inv_id}_{safe_name}"
        validate_and_save_pcap(file, pcap_dest)
    elif sample_name:
        clean_sample = Path(sample_name).name
        if ".." in sample_name or clean_sample != sample_name:
            raise HTTPException(status_code=400, detail="Invalid sample name: path traversal attempted.")
        sample_path = SAMPLES_DIR / clean_sample
        if not sample_path.exists():
            raise HTTPException(status_code=404, detail=f"Sample '{clean_sample}' not found.")
        pcap_dest = DATA_DIR / f"{inv_id}_{clean_sample}"
        shutil.copyfile(sample_path, pcap_dest)
    else:
        raise HTTPException(status_code=400, detail="Must provide either an uploaded PCAP or a sample_name.")

    user_id = current_user.user_id

    # Pre-record investigation ownership in database
    try:
        db = SessionLocal()
        try:
            inv_db = InvestigationModel(
                investigation_id=inv_id,
                user_id=user_id,
                artifact_name=pcap_dest.name,
                artifact_path=str(pcap_dest.resolve()),
                status="ANALYZING"
            )
            db.add(inv_db)
            db.commit()
        finally:
            db.close()
    except Exception:
        pass

    if background:
        background_tasks.add_task(agent.run_investigation, inv_id, pcap_dest)
        return JSONResponse(
            status_code=202,
            content={
                "investigation_id": inv_id,
                "status": "ANALYZING",
                "message": "Investigation started in background. Subscribe to SSE stream for live updates."
            }
        )

    # Run agent investigation synchronously
    try:
        inv = agent.run_investigation(inv_id, pcap_dest)
        return _serialize_investigation(inv.investigation_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.post("/investigations/{investigation_id}/artifacts")
async def upload_artifact(
    investigation_id: str,
    file: UploadFile = File(...),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)

    safe_name = Path(file.filename).name
    pcap_dest = config.artifact_dir / f"{investigation_id}_{safe_name}"
    size = validate_and_save_pcap(file, pcap_dest)

    return {
        "investigation_id": investigation_id,
        "artifact_name": safe_name,
        "artifact_path": str(pcap_dest),
        "size_bytes": size
    }


@router.post("/investigations/{investigation_id}/analyze")
async def analyze_investigation(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    inv = ledger.get_investigation(investigation_id)
    if not inv or not Path(inv.artifact_path).exists():
        raise HTTPException(status_code=404, detail="Investigation or artifact file not found.")

    try:
        updated_inv = agent.run_investigation(investigation_id, Path(inv.artifact_path))
        return _serialize_investigation(updated_inv.investigation_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/investigations/{investigation_id}/replay")
def replay_investigation(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deterministic Replay of investigation steps without re-executing tools.
    """
    require_owned_investigation_model(investigation_id, current_user, db)
    try:
        db_inv = db.query(InvestigationModel).filter_by(investigation_id=investigation_id).first()
        inv = ledger.get_investigation(investigation_id)
        if not inv and not db_inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")

        steps = db.query(AgentStepModel).filter_by(investigation_id=investigation_id).order_by(AgentStepModel.step_number.asc()).all()
        if not steps:
            tl = ledger.get_timeline(investigation_id)
            return {
                "investigation_id": investigation_id,
                "step_count": len(tl),
                "steps": [t.model_dump() for t in tl]
            }

        return {
            "investigation_id": investigation_id,
            "step_count": len(steps),
            "steps": [
                {
                    "step_number": s.step_number,
                    "state": s.state,
                    "hypothesis": s.hypothesis,
                    "tool": s.selected_tool,
                    "tool_arguments": s.tool_arguments,
                    "reason": s.reason,
                    "result": s.result,
                    "evidence_ids": s.evidence_ids,
                    "next_action": s.next_action,
                    "provider": s.provider,
                    "model": s.model,
                    "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                    "duration": s.duration
                }
                for s in steps
            ]
        }
    finally:
        pass


@router.get("/investigations")
def list_investigations(
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_investigation_ids = {
        row.investigation_id
        for row in db.query(InvestigationModel.investigation_id).filter_by(user_id=current_user.user_id).all()
    }
    invs = [inv for inv in ledger.list_investigations() if inv.investigation_id in allowed_investigation_ids]
    result = []
    for inv in invs:
        d = inv.model_dump()
        d["security_score"] = inv.posture.overall_posture_score if inv.posture else 100.0
        d["risk_level"] = inv.posture.risk_level.replace(" RISK", "") if inv.posture else "SECURE"
        d["confidence_score"] = (inv.posture.confidence_score / 100.0) if inv.posture else 1.0
        d["completeness_ratio"] = (inv.completeness_percentage / 100.0) if inv.completeness_percentage else 1.0
        d["stream_count"] = inv.streams_analyzed
        result.append(d)
    return result


@router.get("/investigations/{investigation_id}")
def get_investigation(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    return _serialize_investigation(investigation_id)


@router.get("/investigations/{investigation_id}/evidence")
def get_evidence(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    evs = ledger.get_evidence_for_investigation(investigation_id)
    return [e.model_dump() for e in evs]


@router.get("/investigations/{investigation_id}/graph")
def get_investigation_knowledge_graph(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns the complete forensic knowledge graph linking Artifacts, Streams,
    Tools, Evidence Claims, Findings, and ML feature attribution.
    """
    require_owned_investigation_model(investigation_id, current_user, db)
    graph = KnowledgeGraphEngine.build_graph(investigation_id, ledger)
    return graph


@router.get("/all-evidence")
def get_all_evidence(
    investigation_id: Optional[str] = None,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    source_tool: Optional[str] = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    allowed_investigation_ids = {
        row.investigation_id
        for row in db.query(InvestigationModel.investigation_id).filter_by(user_id=current_user.user_id).all()
    }
    evs = [e for e in ledger.get_all_evidence() if e.investigation_id in allowed_investigation_ids]
    if investigation_id:
        if investigation_id not in allowed_investigation_ids:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        evs = [e for e in evs if e.investigation_id == investigation_id]
    if severity:
        sev_clean = severity.lower()
        evs = [e for e in evs if (e.severity.value.lower() if hasattr(e.severity, "value") else str(e.severity).lower()) == sev_clean]
    if type:
        type_clean = type.lower()
        evs = [e for e in evs if (e.type.value.lower() if hasattr(e.type, "value") else str(e.type).lower()) == type_clean]
    if source_tool:
        evs = [e for e in evs if e.source_tool.lower() == source_tool.lower()]

    result = []
    for e in evs:
        d = e.model_dump()
        d["evidence_type"] = e.type.value if hasattr(e.type, "value") else str(e.type)
        d["observed_claim"] = e.claim
        result.append(d)
    return result


@router.get("/investigations/{investigation_id}/findings")
def get_findings(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    fnds = ledger.get_findings_for_investigation(investigation_id)
    return [f.model_dump() for f in fnds]


@router.get("/investigations/{investigation_id}/sessions")
def get_sessions(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    inv = ledger.get_investigation(investigation_id)
    if not inv or not Path(inv.artifact_path).exists():
        raise HTTPException(status_code=404, detail="Artifact file not found.")
    streams = TCPReconstructionEngine.reconstruct_streams(inv.artifact_path)
    return {"sessions": [s.to_dict() for s in streams]}


@router.get("/investigations/{investigation_id}/timeline")
def get_timeline(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    tl = ledger.get_timeline(investigation_id)
    return [t.model_dump() for t in tl]


@router.get("/investigations/{investigation_id}/ai-summary")
@router.post("/investigations/{investigation_id}/ai-summary")
@router.get("/investigations/{investigation_id}/summary")
async def get_investigation_ai_summary(
    investigation_id: str,
    refresh: bool = False,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Generates or retrieves cached AI investigation summary.
    Enforces authentication and strict investigation ownership.
    Grounds all explanations in verifiable ledger records.
    """
    require_owned_investigation_model(investigation_id, current_user, db)
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    from securemailscope.ai.summary import generate_investigation_summary
    evs = ledger.get_evidence_for_investigation(investigation_id)
    fnds = ledger.get_findings_for_investigation(investigation_id)

    sessions = []
    if inv.artifact_path and Path(inv.artifact_path).exists():
        try:
            sessions = TCPReconstructionEngine.reconstruct_streams(inv.artifact_path)
        except Exception:
            sessions = []

    summary = await generate_investigation_summary(
        investigation=inv,
        evidence=evs,
        findings=fnds,
        sessions=sessions,
        force_refresh=refresh
    )
    return summary


@router.post("/agent/chat")
async def general_agent_chat(
    req: ChatRequest,
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """
    General Forensic AI Agent Chat loop for user questions (e.g. 'hi', general queries,
    system capabilities, protocol questions) without requiring an active PCAP investigation.
    """
    from backend.llm.exceptions import ProviderUnavailableError
    
    user_name = current_user.full_name if (current_user and isinstance(current_user, UserModel)) else "Analyst"
    system_prompt = (
        "You are SecureMailScope's Forensic AI Agent.\n"
        f"You are speaking with {user_name}.\n"
        "SPECIALIZATION: Email protocol security (SMTP, IMAP, POP3), PCAP packet capture analysis, "
        "STARTTLS stripping detection, DKIM/SPF/DMARC validation, and cryptographic forensic verification.\n"
        "RULES:\n"
        "1. Respond directly, concisely, and helpfully to any analyst query (such as greetings, questions about email security, or system features).\n"
        "2. If the user wants to analyze a capture file, prompt them to attach or upload a PCAP or EML artifact.\n"
        "3. Maintain a professional, forensic tone."
    )
    
    messages = [
        ChatMessage(role="system", content=system_prompt),
        ChatMessage(role="user", content=req.message)
    ]
    
    try:
        llm_req = LLMChatRequest(
            messages=messages,
            temperature=0.3,
            max_tokens=1000
        )
        res = await llm_router.chat(llm_req)
        answer = res.content
        provider_used = res.provider
        model_used = res.model
    except Exception as e:
        logger.warning(f"General agent chat error: {e}")
        answer = (
            f"Hello {user_name}! I am SecureMailScope's Forensic AI Agent. "
            "I specialize in passive network packet forensic analysis for SMTP, IMAP, and POP3 captures. "
            "How can I assist your investigation today? Attach a .pcap or .eml artifact to begin deep packet inspection."
        )
        provider_used = "deterministic_fallback"
        model_used = "rule_engine_v2"
        
    return {
        "reply": answer,
        "answer": answer,
        "provider": provider_used,
        "model": model_used,
        "tool_calls_made": [],
        "agent_steps": [],
        "evidence_citations": [],
        "investigation_id": "general",
        "agentic_tool_calling": False,
        "deep_research": req.deep_research
    }


@router.post("/investigations/{investigation_id}/agent/chat")
async def chat_with_agent(
    investigation_id: str,
    req: ChatRequest,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Full multi-round agentic investigation loop.
    LLM receives tool schemas, selects tools, backend executes them,
    results return to LLM for re-evaluation. Evidence-grounded throughout.
    """
    if investigation_id == "general":
        return await general_agent_chat(req, current_user)

    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    import json as _json
    from securemailscope.agent.investigator import LLM_TOOL_SCHEMAS
    from backend.llm.exceptions import ProviderUnavailableError

    require_owned_investigation_model(investigation_id, current_user, db)
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    findings = ledger.get_findings_for_investigation(investigation_id)
    evidence = ledger.get_evidence_for_investigation(investigation_id)

    evidence_facts = [
        f"[{e.evidence_id}] ({e.type.value}): {e.claim}"
        for e in evidence[:20]
    ]
    findings_facts = [
        f"[{f.finding_id}] ({f.severity.value}): {f.title} (Evidence: {', '.join(f.evidence_ids)})"
        for f in findings
    ]

    protocols = ", ".join(inv.protocols_detected) if inv.protocols_detected else "Unknown"
    posture_score = inv.posture.overall_posture_score if inv.posture else "N/A"

    system_prompt = (
        "You are SecureMailScope's Forensic AI Agent.\n"
        "RULES:\n"
        "1. Only cite real Evidence IDs listed below — never invent packets, versions, or certificate details.\n"
        "2. If you need more data, call a tool. Do NOT fabricate findings.\n"
        "3. Available forensic tools: inspect_pcap, list_sessions, extract_smtp, extract_imap, "
        "extract_pop3, analyze_tls, extract_certificate, check_completeness, evaluate_rules, "
        "run_ml_classifier, search_threat_intel, finalize_finding.\n"
        "4. When asked about external threat intelligence, reputations, or domain/MTA history, invoke search_threat_intel to perform Tavily OSINT threat search.\n"
        "5. Stop calling tools once evidence is sufficient. Provide a final grounded answer.\n\n"
        f"INVESTIGATION: {inv.investigation_id} — {inv.artifact_name}\n"
        f"COMPLETENESS: {inv.completeness_percentage}%\n"
        f"POSTURE SCORE: {posture_score}/100\n"
        f"PROTOCOLS: {protocols}\n\n"
        f"EVIDENCE ({len(evidence_facts)} items):\n" + "\n".join(evidence_facts) + "\n\n"
        f"VERIFIED FINDINGS ({len(findings_facts)} items):\n" + ("\n".join(findings_facts) or "(none yet)")
    )

    messages = [
        ChatMessage(role="system", content=system_prompt),
        ChatMessage(role="user", content=req.message)
    ]

    run_id = f"CHAT-{uuid.uuid4().hex[:8].upper()}"
    tool_calls_made: list = []
    agent_steps: list = []
    max_rounds = 4
    final_answer = ""
    provider_used = "unknown"
    model_used = "unknown"
    pcap_path = Path(inv.artifact_path) if inv.artifact_path else None

    # Tool name mapping: LLM schema names → Gateway tool names
    TOOL_MAP = {
        "inspect_pcap": "pcap.inspect",
        "list_sessions": "pcap.sessions",
        "check_completeness": "pcap.completeness",
        "extract_smtp": "smtp.analyze",
        "extract_imap": "imap.analyze",
        "extract_pop3": "pop3.analyze",
        "analyze_tls": "tls.handshake",
        "extract_certificate": "tls.certificate",
        "evaluate_rules": "rules.evaluate",
        "run_ml_classifier": "ml.predict",
        "search_threat_intel": "intel.tavily_search",
        "intel_tavily_search": "intel.tavily_search",
        "intel.tavily_search": "intel.tavily_search",
        "finalize_finding": "findings.verify",
    }

    for round_num in range(max_rounds):
        # Send to LLM WITH tool schemas
        try:
            llm_req = LLMChatRequest(
                messages=messages,
                tools=LLM_TOOL_SCHEMAS,
                max_tokens=2048,
                temperature=0.2
            )
            resp = await llm_router.chat(llm_req, investigation_id=investigation_id)
            provider_used = resp.provider
            model_used = resp.model
        except ProviderUnavailableError:
            return {
                "ai_unavailable": True,
                "forensic_results_available": True,
                "message": (
                    "LLM provider unavailable — deterministic forensic analysis is still available. "
                    "View the Evidence, Findings, and Timeline tabs for full results."
                ),
                "evidence_ids": [e.evidence_id for e in evidence[:8]],
                "evidence_citations": [e.evidence_id for e in evidence[:8]],
                "investigation_id": investigation_id,
                "provider": "none",
                "model": "none"
            }
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"LLM error: {exc}")

        tool_calls = resp.tool_calls or []

        if not tool_calls:
            # LLM provided a final text answer — stop the loop
            final_answer = resp.content or ""
            agent_steps.append({
                "round": round_num + 1,
                "state": "VERDICT",
                "provider": resp.provider,
                "model": resp.model,
                "answer_length": len(final_answer)
            })
            break

        # There are tool calls — execute each via the Gateway
        messages.append(ChatMessage(
            role="assistant",
            content=resp.content or "",
            tool_calls=tool_calls
        ))

        for tc in tool_calls:
            fn = tc.get("function", {})
            t_name = fn.get("name", "")
            raw_args = fn.get("arguments", "{}")
            try:
                t_args = _json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
            except Exception:
                t_args = {}

            tool_calls_made.append({
                "tool": t_name,
                "name": t_name,
                "arguments": t_args,
                "round": round_num + 1,
                "provider": resp.provider
            })
            agent_steps.append({
                "round": round_num + 1,
                "state": "SELECT_TOOL",
                "tool": t_name,
                "provider": resp.provider,
                "model": resp.model
            })

            # Execute via Tool Gateway
            gateway_name = TOOL_MAP.get(t_name, t_name)
            try:
                if gateway_name in ("pcap.inspect", "pcap.sessions", "pcap.completeness") and pcap_path:
                    tool_result = agent.gateway.execute_tool(
                        investigation_id, gateway_name, {"file_path": str(pcap_path)}
                    )
                elif gateway_name in ("smtp.analyze", "imap.analyze", "pop3.analyze", "tls.handshake",
                                      "tls.certificate", "starttls.analyze") and pcap_path:
                    tool_result = agent.gateway.execute_tool(
                        investigation_id, gateway_name,
                        {"file_path": str(pcap_path), **t_args}
                    )
                elif gateway_name == "rules.evaluate":
                    tool_result = agent.gateway.execute_tool(
                        investigation_id, "rules.evaluate",
                        {"investigation_id": investigation_id}
                    )
                elif gateway_name == "ml.predict":
                    forensic_ctx = {
                        "protocols": inv.protocols_detected or [],
                        "packet_count": inv.total_packets or 0
                    }
                    tool_result = agent.gateway.execute_tool(
                        investigation_id, "ml.predict",
                        {"forensic_context": forensic_ctx}
                    )
                elif gateway_name == "intel.tavily_search":
                    tool_result = agent.gateway.execute_tool(
                        investigation_id, "intel.tavily_search",
                        {"query": t_args.get("query", "")}
                    )
                else:
                    tool_result = {
                        "status": "tool_not_applicable",
                        "tool": t_name,
                        "note": "Tool requires specific artifact context not available in chat mode."
                    }
                eids = tool_result.get("evidence_ids", []) if isinstance(tool_result, dict) else []
            except Exception as ex:
                tool_result = {"error": str(ex), "tool": t_name}
                eids = []

            agent_steps.append({
                "round": round_num + 1,
                "state": "EXECUTE",
                "tool": t_name,
                "gateway_tool": gateway_name,
                "evidence_ids": eids,
                "success": "error" not in tool_result
            })

            # Feed tool result back to LLM
            messages.append(ChatMessage(
                role="tool",
                name=t_name,
                tool_call_id=tc.get("id"),
                content=_json.dumps(tool_result if isinstance(tool_result, dict) else {"result": str(tool_result)})
            ))
    else:
        # Exhausted max_rounds without a final answer
        final_answer = (
            f"Investigation analysis complete ({max_rounds} rounds). "
            "Review the Evidence and Findings tabs for detailed results."
        )

    # Collect cited evidence IDs
    cited_eids = [e.evidence_id for e in evidence if e.evidence_id in final_answer]
    if not cited_eids and evidence:
        cited_eids = [e.evidence_id for e in evidence[:6]]

    # Persist AgentRun summary
    try:
        db = SessionLocal()
        try:
            from securemailscope.db.models import AgentRunModel
            arm = AgentRunModel(
                run_id=run_id,
                investigation_id=investigation_id,
                provider=provider_used,
                model=model_used,
                status="COMPLETED",
                total_steps=len(agent_steps),
                total_tool_calls=len(tool_calls_made),
                final_answer=final_answer[:1000] if final_answer else ""
            )
            db.add(arm)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
    except Exception:
        pass  # Persistence failure must not break the response

    return {
        "reply": final_answer,
        "answer": final_answer,
        "provider": provider_used,
        "model": model_used,
        "tool_calls_made": tool_calls_made,
        "agent_steps": agent_steps,
        "rounds_executed": len([s for s in agent_steps if s["state"] == "VERDICT" or s["state"] == "EXECUTE"]),
        "evidence_ids": cited_eids,
        "evidence_citations": cited_eids,
        "investigation_id": investigation_id,
        "run_id": run_id,
        "agentic_tool_calling": len(tool_calls_made) > 0,
        "deep_research": req.deep_research
    }


@router.post("/investigations/{investigation_id}/agent/step")
def execute_agent_step(
    investigation_id: str,
    req: AgentStepRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    tool_name = req.tool_name or "pcap.completeness"
    tool_args = req.tool_arguments or {"file_path": inv.artifact_path}

    res = agent.gateway.execute_tool(investigation_id, tool_name, tool_args, hypothesis_id=req.hypothesis_id)
    return res


@router.get("/investigations/{investigation_id}/events")
async def stream_investigation_events(
    investigation_id: str,
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    SSE stream yielding real events:
    investigation.started, protocol.detected, session.reconstructed, starttls.detected,
    tls.handshake.detected, certificate.extracted, rule.triggered, ml.prediction.completed,
    hypothesis.created, agent.tool_selected, tool.started, tool.completed, evidence.created,
    hypothesis.updated, finding.verified, report.generated.
    """
    require_owned_investigation_model(investigation_id, current_user, db)
    queue = SSEEventBus.subscribe(investigation_id)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20.0)
                    yield event
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "heartbeat"}
        finally:
            SSEEventBus.unsubscribe(investigation_id, queue)

    return EventSourceResponse(event_generator())


@router.get("/investigations/{investigation_id}/reports/json")
@router.get("/investigations/{investigation_id}/report/json")
def get_json_report(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    from securemailscope.ai.summary import get_cached_summary
    ai_sum = get_cached_summary(investigation_id)
    out_path = REPORTS_DIR / f"{investigation_id}_report.json"
    JSONReporter.generate_report(investigation_id, ledger, out_path, ai_summary=ai_sum)
    return FileResponse(out_path, media_type="application/json", filename=f"{investigation_id}_report.json")


@router.get("/investigations/{investigation_id}/reports/html")
@router.get("/investigations/{investigation_id}/report/html")
def get_html_report(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    from securemailscope.ai.summary import get_cached_summary
    ai_sum = get_cached_summary(investigation_id)
    out_path = REPORTS_DIR / f"{investigation_id}_report.html"
    HTMLReporter.generate_report(investigation_id, ledger, out_path, ai_summary=ai_sum)
    return FileResponse(out_path, media_type="text/html", filename=f"{investigation_id}_report.html")


@router.get("/investigations/{investigation_id}/reports/pdf")
@router.get("/investigations/{investigation_id}/report/pdf")
def get_pdf_report(
    investigation_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_owned_investigation_model(investigation_id, current_user, db)
    from securemailscope.ai.summary import get_cached_summary
    ai_sum = get_cached_summary(investigation_id)
    out_path = REPORTS_DIR / f"{investigation_id}_report.pdf"
    PDFReporter.generate_report(investigation_id, ledger, out_path, ai_summary=ai_sum)
    return FileResponse(out_path, media_type="application/pdf", filename=f"{investigation_id}_report.pdf")
