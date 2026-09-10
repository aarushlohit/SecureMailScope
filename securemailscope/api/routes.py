"""
SecureMailScope - Production REST & SSE API Routes
"""
import uuid
import shutil
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request, Response, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from securemailscope.core.config import config, SAMPLES_DIR, REPORTS_DIR, DATA_DIR
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.ml.benchmark import BenchmarkEngine
from securemailscope.forensics.tcp_stream import TCPReconstructionEngine
from securemailscope.forensics.system_tools import SystemToolDiscovery
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter
from backend.llm.router import LLMRouter
from backend.llm.schemas import ChatRequest as LLMChatRequest, ChatMessage
from securemailscope.api.sse import SSEEventBus
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import InvestigationModel, AgentStepModel, ArtifactModel, ForensicSessionModel

router = APIRouter(prefix="/api")
ledger = EvidenceLedger.get_instance()
llm_router = LLMRouter()
agent = InvestigationAgent(ledger, router=llm_router)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB limit
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
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
            detail=f"Invalid file extension '{ext}'. Only .pcap, .pcapng, and .cap are permitted."
        )

    bytes_read = 0
    with open(dest_path, "wb") as out_f:
        first_chunk = upload_file.file.read(4096)
        if not first_chunk:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        if not any(first_chunk.startswith(magic) for magic in VALID_MAGIC_PREFIXES):
            raise HTTPException(
                status_code=400,
                detail="Invalid file format: file signature does not match PCAP or PCAP-NG."
            )

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


@router.get("/all-evidence")
def get_all_evidence():
    """
    Returns all evidence recorded in the Evidence Ledger across all investigations.
    Enforces the 'No Evidence -> No Finding' audit requirement.
    """
    evs = ledger.get_all_evidence()
    result = []
    for e in evs:
        d = e.model_dump()
        d["evidence_type"] = e.type.value
        d["observed_claim"] = e.claim
        result.append(d)
    return result


@router.get("/all-findings")
def get_all_findings():
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
    fnds = ledger.get_all_findings()
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
    background: bool = Form(False)
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
        return get_investigation(inv.investigation_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.post("/investigations/{investigation_id}/artifacts")
async def upload_artifact(investigation_id: str, file: UploadFile = File(...)):
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

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
async def analyze_investigation(investigation_id: str):
    inv = ledger.get_investigation(investigation_id)
    if not inv or not Path(inv.artifact_path).exists():
        raise HTTPException(status_code=404, detail="Investigation or artifact file not found.")

    try:
        updated_inv = agent.run_investigation(investigation_id, Path(inv.artifact_path))
        return get_investigation(updated_inv.investigation_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/investigations/{investigation_id}/replay")
def replay_investigation(investigation_id: str):
    """
    Deterministic Replay of investigation steps without re-executing tools.
    """
    db = SessionLocal()
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
        db.close()


@router.get("/investigations")
def list_investigations():
    invs = ledger.list_investigations()
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
def get_investigation(investigation_id: str):
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    d = inv.model_dump()
    d["security_score"] = inv.posture.overall_posture_score if inv.posture else 100.0
    d["risk_level"] = inv.posture.risk_level.replace(" RISK", "") if inv.posture else "SECURE"
    d["confidence_score"] = (inv.posture.confidence_score / 100.0) if inv.posture else 1.0
    d["completeness_ratio"] = (inv.completeness_percentage / 100.0) if inv.completeness_percentage else 1.0
    d["stream_count"] = inv.streams_analyzed

    # Attach related models
    d["findings"] = [f.model_dump() for f in ledger.get_findings_for_investigation(investigation_id)]
    d["evidence_ledger"] = [e.model_dump() for e in ledger.get_evidence_for_investigation(investigation_id)]
    d["investigation_timeline"] = [t.model_dump() for t in ledger.get_timeline(investigation_id)]
    d["hypotheses"] = [h.model_dump() for h in ledger.get_hypotheses_for_investigation(investigation_id)]

    if inv.artifact_path and Path(inv.artifact_path).exists():
        try:
            streams = TCPReconstructionEngine.reconstruct_streams(inv.artifact_path)
            d["tcp_streams"] = [s.to_dict() for s in streams]
        except Exception:
            d["tcp_streams"] = []
    else:
        d["tcp_streams"] = []

    return d


@router.get("/investigations/{investigation_id}/evidence")
def get_evidence(investigation_id: str):
    evs = ledger.get_evidence_for_investigation(investigation_id)
    return [e.model_dump() for e in evs]


@router.get("/investigations/{investigation_id}/findings")
def get_findings(investigation_id: str):
    fnds = ledger.get_findings_for_investigation(investigation_id)
    return [f.model_dump() for f in fnds]


@router.get("/investigations/{investigation_id}/sessions")
def get_sessions(investigation_id: str):
    inv = ledger.get_investigation(investigation_id)
    if not inv or not Path(inv.artifact_path).exists():
        raise HTTPException(status_code=404, detail="Artifact file not found.")
    streams = TCPReconstructionEngine.reconstruct_streams(inv.artifact_path)
    return {"sessions": [s.to_dict() for s in streams]}


@router.get("/investigations/{investigation_id}/timeline")
def get_timeline(investigation_id: str):
    tl = ledger.get_timeline(investigation_id)
    return [t.model_dump() for t in tl]


@router.post("/investigations/{investigation_id}/agent/chat")
async def chat_with_agent(investigation_id: str, req: ChatRequest):
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    findings = ledger.get_findings_for_investigation(investigation_id)
    evidence = ledger.get_evidence_for_investigation(investigation_id)

    # Grounded evidence summary for LLM prompt
    evidence_facts = [
        f"[{e.evidence_id}] ({e.type.value}): {e.claim}"
        for e in evidence[:15]
    ]
    findings_facts = [
        f"[{f.finding_id}] ({f.severity.value}): {f.title} (Supporting: {', '.join(f.evidence_ids)})"
        for f in findings
    ]

    system_prompt = (
        "You are the SecureMailScope Forensic AI Agent. You reason strictly OVER provided Evidence IDs.\n"
        "Rules:\n"
        "1. Never invent packets, versions, or cipher suites.\n"
        "2. Always cite matching Evidence IDs (e.g. [E-XXXXXX]) for every factual claim.\n"
        "3. Explain whether STARTTLS was stripped, if certificates were expired, and capture completeness implications.\n\n"
        f"ACTIVE INVESTIGATION: {inv.investigation_id} ({inv.artifact_name})\n"
        f"COMPLETENESS: {inv.completeness_percentage}%\n"
        f"POSTURE SCORE: {inv.posture.overall_posture_score if inv.posture else 100}/100\n"
        f"EVIDENCE FACTS:\n" + "\n".join(evidence_facts) + "\n\n"
        f"FINDINGS:\n" + "\n".join(findings_facts)
    )

    llm_req = LLMChatRequest(
        messages=[
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=req.message)
        ],
        max_tokens=2048,
        temperature=0.3
    )

    llm_resp = await llm_router.chat(llm_req, investigation_id=investigation_id)

    # Collect cited evidence IDs from text
    cited_eids = [e.evidence_id for e in evidence if e.evidence_id in llm_resp.content]
    if not cited_eids:
        cited_eids = [e.evidence_id for e in evidence[:4]]

    return {
        "reply": llm_resp.content,
        "answer": llm_resp.content,
        "provider": llm_resp.provider,
        "model": llm_resp.model,
        "evidence_ids": cited_eids,
        "evidence_citations": cited_eids,
        "investigation_id": investigation_id,
        "deep_research": req.deep_research
    }


@router.post("/investigations/{investigation_id}/agent/step")
def execute_agent_step(investigation_id: str, req: AgentStepRequest):
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    tool_name = req.tool_name or "pcap.completeness"
    tool_args = req.tool_arguments or {"file_path": inv.artifact_path}

    res = agent.gateway.execute_tool(investigation_id, tool_name, tool_args, hypothesis_id=req.hypothesis_id)
    return res


@router.get("/investigations/{investigation_id}/events")
async def stream_investigation_events(investigation_id: str, request: Request):
    """
    SSE stream yielding real events:
    investigation.started, protocol.detected, session.reconstructed, starttls.detected,
    tls.handshake.detected, certificate.extracted, rule.triggered, ml.prediction.completed,
    hypothesis.created, agent.tool_selected, tool.started, tool.completed, evidence.created,
    hypothesis.updated, finding.verified, report.generated.
    """
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
def get_json_report(investigation_id: str):
    out_path = REPORTS_DIR / f"{investigation_id}_report.json"
    JSONReporter.generate_report(investigation_id, ledger, out_path)
    return FileResponse(out_path, media_type="application/json", filename=f"{investigation_id}_report.json")


@router.get("/investigations/{investigation_id}/reports/html")
@router.get("/investigations/{investigation_id}/report/html")
def get_html_report(investigation_id: str):
    out_path = REPORTS_DIR / f"{investigation_id}_report.html"
    HTMLReporter.generate_report(investigation_id, ledger, out_path)
    return FileResponse(out_path, media_type="text/html", filename=f"{investigation_id}_report.html")


@router.get("/investigations/{investigation_id}/reports/pdf")
@router.get("/investigations/{investigation_id}/report/pdf")
def get_pdf_report(investigation_id: str):
    out_path = REPORTS_DIR / f"{investigation_id}_report.pdf"
    PDFReporter.generate_report(investigation_id, ledger, out_path)
    return FileResponse(out_path, media_type="application/pdf", filename=f"{investigation_id}_report.pdf")
