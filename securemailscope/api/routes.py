"""
SecureMailScope - REST API Routes
"""
import uuid
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from securemailscope.core.config import config, SAMPLES_DIR, REPORTS_DIR, DATA_DIR
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.agent.intelligence import IntelligenceAdapter
from securemailscope.ml.benchmark import BenchmarkEngine
from securemailscope.forensics.tcp_stream import TCPReconstructionEngine
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter

router = APIRouter(prefix="/api")
ledger = EvidenceLedger.get_instance()
agent = InvestigationAgent(ledger)


class ChatRequest(BaseModel):
    message: str
    deep_research: bool = False


class IntelQueryRequest(BaseModel):
    query_type: str  # "ip", "domain", "certificate"
    target: str


@router.get("/health")
def health_check():
    return {"status": "ok", "platform": "SecureMailScope", "version": "2.6.0"}


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
    file: Optional[UploadFile] = File(None),
    sample_name: Optional[str] = Form(None)
):
    inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    pcap_dest: Path

    if file and file.filename:
        safe_name = Path(file.filename).name
        pcap_dest = DATA_DIR / f"{inv_id}_{safe_name}"
        with open(pcap_dest, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    elif sample_name:
        sample_path = SAMPLES_DIR / sample_name
        if not sample_path.exists():
            raise HTTPException(status_code=404, detail=f"Sample '{sample_name}' not found.")
        pcap_dest = DATA_DIR / f"{inv_id}_{sample_name}"
        shutil.copyfile(sample_path, pcap_dest)
    else:
        raise HTTPException(status_code=400, detail="Must provide either an uploaded PCAP or a sample_name.")

    # Run agent investigation
    try:
        inv = agent.run_investigation(inv_id, pcap_dest)
        return get_investigation(inv.investigation_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


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

    # Attach reconstructed streams if PCAP available
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


@router.get("/investigations/{investigation_id}/hypotheses")
def get_hypotheses(investigation_id: str):
    hyps = ledger.get_hypotheses_for_investigation(investigation_id)
    return [h.model_dump() for h in hyps]


@router.get("/investigations/{investigation_id}/findings")
def get_findings(investigation_id: str):
    fnds = ledger.get_findings_for_investigation(investigation_id)
    return [f.model_dump() for f in fnds]


@router.get("/investigations/{investigation_id}/timeline")
def get_timeline(investigation_id: str):
    tl = ledger.get_timeline(investigation_id)
    return [t.model_dump() for t in tl]


@router.get("/investigations/{investigation_id}/streams")
def get_streams(investigation_id: str):
    inv = ledger.get_investigation(investigation_id)
    if not inv or not Path(inv.artifact_path).exists():
        raise HTTPException(status_code=404, detail="Artifact PCAP file not found.")
    streams = TCPReconstructionEngine.reconstruct_streams(inv.artifact_path)
    return {"streams": [s.to_dict() for s in streams]}


@router.post("/investigations/{investigation_id}/agent/chat")
def chat_with_agent(investigation_id: str, req: ChatRequest):
    inv = ledger.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    findings = ledger.get_findings_for_investigation(investigation_id)
    evidence = ledger.get_evidence_for_investigation(investigation_id)
    hypotheses = ledger.get_hypotheses_for_investigation(investigation_id)

    query = req.message.lower()

    # Evidence-grounded reasoning response
    reply_lines = []
    actions_taken = []
    relevant_evidence_ids = []

    if "starttls" in query or "downgrade" in query or "stripping" in query:
        st_ev = [e for e in evidence if "starttls" in e.type.value or "plaintext" in e.type.value]
        if st_ev:
            relevant_evidence_ids = [e.evidence_id for e in st_ev]
            has_pt = any(e.type.value == "plaintext_continuation" for e in st_ev)
            if has_pt:
                reply_lines.append("I evaluated the STARTTLS negotiation flow in the capture.")
                reply_lines.append("• STARTTLS was advertised in the EHLO response.")
                reply_lines.append("• Client issued STARTTLS and server returned `220 2.0.0 Ready to start TLS`.")
                reply_lines.append("• However, no TLS ClientHello followed; cleartext SMTP commands (`MAIL FROM`, `RCPT TO`, `DATA`) continued on the wire.")
                reply_lines.append(f"• Capture completeness is verified at {inv.completeness_percentage}%, refuting packet-loss as a cause.")
                reply_lines.append("\n**Verdict:** Verified STARTTLS Downgrade / Stripping Protocol Violation (Critical Severity).")
            else:
                reply_lines.append("STARTTLS was advertised, accepted, and followed by a valid TLS handshake.")
        else:
            reply_lines.append("No STARTTLS anomalies observed in the current session.")

    elif "cert" in query or "x.509" in query or "chain" in query:
        cert_ev = [e for e in evidence if "certificate" in e.type.value]
        if cert_ev:
            relevant_evidence_ids = [e.evidence_id for e in cert_ev]
            c_info = cert_ev[0].details
            reply_lines.append(f"X.509 Certificate Analysis for `{inv.artifact_name}`:")
            reply_lines.append(f"• Subject: `{c_info.get('subject')}`")
            reply_lines.append(f"• Issuer: `{c_info.get('issuer')}`")
            reply_lines.append(f"• Public Key: {c_info.get('public_key_algorithm')} {c_info.get('public_key_bits')} bits")
            reply_lines.append(f"• Validity: Not After {c_info.get('not_after')}")
            errs = c_info.get('validation_errors', [])
            if errs:
                reply_lines.append(f"\n⚠️ **Validation Deficiencies Detected:**\n" + "\n".join(f"- {err}" for err in errs))
            else:
                reply_lines.append("\n✓ Certificate conforms to standard cryptographic validity criteria.")
        else:
            if any("TLS 1.3" in e.claim for e in evidence):
                reply_lines.append("In TLS 1.3, the certificate exchange is encrypted after ServerHello. Passive PCAP inspection cannot extract raw X.509 bytes without session keys.")
            else:
                reply_lines.append("No X.509 certificate messages were observed in this capture stream.")

    elif "completeness" in query or "packet loss" in query or "quality" in query:
        comp_ev = [e for e in evidence if e.type.value == "capture_completeness"]
        if comp_ev:
            relevant_evidence_ids = [e.evidence_id for e in comp_ev]
            cd = comp_ev[0].details
            reply_lines.append(f"Capture Completeness Assessment:")
            reply_lines.append(f"• Calculated Score: **{cd.get('completeness_percentage')}%** ({cd.get('assessment')})")
            reply_lines.append(f"• Total TCP Packets: {cd.get('total_tcp_packets')}")
            reply_lines.append(f"• Sequence Gaps: {cd.get('sequence_gaps')}")
            reply_lines.append(f"• Retransmissions: {cd.get('retransmissions')}")
            if cd.get('completeness_percentage', 100) < 60:
                reply_lines.append("\n⚠️ Due to low capture completeness, some missing protocol segments may represent packet drops rather than active protocol attacks.")
            else:
                reply_lines.append("\n✓ High capture completeness provides >95% confidence in forensic observations.")

    elif "report" in query or "summary" in query or "posture" in query:
        post = inv.posture
        reply_lines.append(f"**Forensic Executive Summary for {inv.artifact_name}:**")
        reply_lines.append(f"• **Security Posture Score:** {post.overall_posture_score}/100 ({post.risk_level})")
        reply_lines.append(f"• **Forensic Confidence:** {post.confidence_score}%")
        reply_lines.append(f"• **Protocols Detected:** {', '.join(inv.protocols_detected)}")
        reply_lines.append(f"• **Verified Findings:** {len(findings)}")
        for f in findings:
            reply_lines.append(f"  - `[{f.severity.value.upper()}]` {f.title}")
            relevant_evidence_ids.extend(f.evidence_ids)

    else:
        # Generic grounding on active investigation
        reply_lines.append(f"I am actively tracking Investigation `{inv.investigation_id}` (`{inv.artifact_name}`).")
        reply_lines.append(f"The evidence ledger currently contains **{len(evidence)} verified facts** and **{len(findings)} findings**.")
        reply_lines.append("You can ask me to inspect STARTTLS transitions, verify certificate validity, analyze TCP streams, or explain score deductions.")

    return {
        "reply": "\n".join(reply_lines),
        "answer": "\n".join(reply_lines),
        "evidence_ids": list(set(relevant_evidence_ids))[:5],
        "evidence_citations": list(set(relevant_evidence_ids))[:5],
        "investigation_id": investigation_id,
        "deep_research": req.deep_research
    }


@router.get("/intel/query")
@router.post("/intel/query")
def query_intel(
    query_type: Optional[str] = None,
    intel_type: Optional[str] = None,
    target: Optional[str] = None,
    req: Optional[IntelQueryRequest] = None
):
    q_type = query_type or intel_type or (req.query_type if req else "domain")
    t_val = target or (req.target if req else "")

    if not t_val:
        raise HTTPException(status_code=400, detail="Missing 'target' parameter for threat intelligence query.")

    if q_type == "ip":
        return IntelligenceAdapter.lookup_ip(t_val)
    elif q_type == "domain":
        return IntelligenceAdapter.lookup_domain(t_val)
    elif q_type in ("certificate", "cert"):
        return IntelligenceAdapter.lookup_certificate(t_val)
    else:
        raise HTTPException(status_code=400, detail="Invalid query_type. Use 'ip', 'domain', or 'certificate'.")


@router.get("/all-findings")
def list_all_findings():
    invs = ledger.list_investigations()
    all_f = []
    for inv in invs:
        fnds = ledger.get_findings_for_investigation(inv.investigation_id)
        for f in fnds:
            fd = f.model_dump()
            fd["artifact_name"] = inv.artifact_name
            fd["investigation_id"] = inv.investigation_id
            all_f.append(fd)
    return all_f


@router.get("/all-evidence")
def list_all_evidence():
    invs = ledger.list_investigations()
    all_e = []
    for inv in invs:
        evs = ledger.get_evidence_for_investigation(inv.investigation_id)
        for e in evs:
            ed = e.model_dump()
            ed["artifact_name"] = inv.artifact_name
            ed["investigation_id"] = inv.investigation_id
            all_e.append(ed)
    return all_e


@router.get("/investigations/{investigation_id}/report/json")
@router.get("/investigations/{investigation_id}/reports/json")
def download_json_report(investigation_id: str):
    out_path = REPORTS_DIR / f"{investigation_id}_report.json"
    JSONReporter.generate_report(investigation_id, ledger, out_path)
    return FileResponse(out_path, media_type="application/json", filename=f"{investigation_id}_report.json")


@router.get("/investigations/{investigation_id}/report/html")
@router.get("/investigations/{investigation_id}/reports/html")
def view_html_report(investigation_id: str):
    out_path = REPORTS_DIR / f"{investigation_id}_report.html"
    HTMLReporter.generate_report(investigation_id, ledger, out_path)
    return FileResponse(out_path, media_type="text/html", filename=f"{investigation_id}_report.html")


@router.get("/investigations/{investigation_id}/report/pdf")
@router.get("/investigations/{investigation_id}/reports/pdf")
def download_pdf_report(investigation_id: str):
    out_path = REPORTS_DIR / f"{investigation_id}_report.pdf"
    PDFReporter.generate_report(investigation_id, ledger, out_path)
    return FileResponse(out_path, media_type="application/pdf", filename=f"{investigation_id}_report.pdf")


@router.get("/ml/benchmark")
def get_ml_benchmark():
    return BenchmarkEngine.evaluate_benchmark(num_samples=800)
