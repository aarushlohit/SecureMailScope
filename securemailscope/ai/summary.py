"""
SecureMailScope - AI Investigation Summary & Reasoning Engine
Generates structured, evidence-grounded investigation summaries using
the configured LLM provider (NVIDIA NIM -> Gemini -> Deterministic Fallback).
Strictly prevents hallucinations: validates evidence and finding citations against
the immutable Evidence Ledger.
"""
import json
import re
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from backend.llm.router import LLMRouter
from backend.llm.schemas import ChatRequest, ChatMessage
from backend.llm.exceptions import ProviderUnavailableError, LLMException

logger = logging.getLogger("securemailscope.ai.summary")

PROMPT_VERSION = "2.1.0"

# In-memory summary cache: key -> summary dict
_SUMMARY_CACHE: Dict[str, Dict[str, Any]] = {}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_forensic_data_hash(
    artifact_sha256: str,
    evidence_ids: List[str],
    finding_ids: List[str],
    stream_count: int
) -> str:
    """Computes a deterministic hash of the underlying forensic data for cache invalidation."""
    raw = f"{artifact_sha256}|{','.join(sorted(evidence_ids))}|{','.join(sorted(finding_ids))}|{stream_count}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _extract_json_block(text: str) -> Optional[Dict[str, Any]]:
    """Extracts and parses JSON from model output, handling markdown blocks."""
    text = text.strip()
    # Try parsing direct JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from ```json ... ``` code fence
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try searching for outermost { ... }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except json.JSONDecodeError:
            pass

    return None


def _validate_and_sanitize_summary(
    raw_summary: Dict[str, Any],
    valid_evidence_ids: set,
    valid_finding_ids: set
) -> Dict[str, Any]:
    """
    Validates that all evidence and finding citations in the AI output
    strictly exist in the underlying forensic data. Strips any hallucinated IDs.
    """
    sanitized = {
        "investigation_summary": str(raw_summary.get("investigation_summary", "")).strip(),
        "executive_summary": str(raw_summary.get("executive_summary", "")).strip(),
        "key_observations": [str(x).strip() for x in raw_summary.get("key_observations", []) if str(x).strip()],
        "finding_reasoning": [],
        "risk_explanation": str(raw_summary.get("risk_explanation", "")).strip(),
        "limitations": [str(x).strip() for x in raw_summary.get("limitations", []) if str(x).strip()],
        "recommended_actions": [str(x).strip() for x in raw_summary.get("recommended_actions", []) if str(x).strip()],
    }

    # Validate each finding reasoning item
    for fr in raw_summary.get("finding_reasoning", []):
        if not isinstance(fr, dict):
            continue
        fid = fr.get("finding_id")
        # Validate finding_id
        if fid not in valid_finding_ids and len(valid_finding_ids) > 0:
            # Skip hallucinated finding reasoning
            continue

        # Filter supporting evidence IDs to strictly existing ones
        raw_eids = fr.get("supporting_evidence_ids", [])
        clean_eids = [eid for eid in raw_eids if eid in valid_evidence_ids]

        sanitized["finding_reasoning"].append({
            "finding_id": fid or "N/A",
            "title": str(fr.get("title", "Finding Reasoning")).strip(),
            "severity": str(fr.get("severity", "informational")).lower(),
            "reasoning": str(fr.get("reasoning", "")).strip(),
            "supporting_evidence_ids": clean_eids,
            "confidence": float(fr.get("confidence", 1.0)) if isinstance(fr.get("confidence"), (int, float)) else 1.0
        })

    return sanitized


def generate_deterministic_fallback_summary(
    investigation: Any,
    evidence: List[Any],
    findings: List[Any],
    sessions: List[Any],
    reason: str = "AI provider unavailable"
) -> Dict[str, Any]:
    """
    Generates a truthful, deterministic forensic summary without calling external LLMs.
    Clearly labeled as generated_by: deterministic-system (is_ai_generated: False).
    """
    inv_id = getattr(investigation, "investigation_id", "N/A")
    artifact_name = getattr(investigation, "artifact_name", "capture.pcap")
    artifact_sha256 = getattr(investigation, "artifact_sha256", "N/A")
    packet_count = getattr(investigation, "packet_count", 0)
    completeness = getattr(investigation, "completeness_percentage", 100.0)

    posture = getattr(investigation, "posture", None)
    score = posture.overall_posture_score if posture else getattr(investigation, "security_score", 100.0)
    risk_lvl = posture.risk_level if posture else getattr(investigation, "risk_level", "UNKNOWN")

    key_obs = [
        f"Analyzed {packet_count} packets from artifact '{artifact_name}'.",
        f"Capture completeness calculated at {completeness}% based on TCP sequence integrity.",
        f"Reconstructed {len(sessions)} communication streams.",
        f"Recorded {len(evidence)} immutable evidence entries in cryptographic ledger.",
        f"Identified {len(findings)} validated security findings."
    ]

    finding_reasonings = []
    for f in findings:
        fid = getattr(f, "finding_id", str(f.get("finding_id", "") if isinstance(f, dict) else ""))
        title = getattr(f, "title", str(f.get("title", "") if isinstance(f, dict) else ""))
        sev = getattr(f, "severity", "medium")
        sev_str = sev.value if hasattr(sev, "value") else str(sev).lower()
        desc = getattr(f, "description", str(f.get("description", "") if isinstance(f, dict) else ""))
        eids = getattr(f, "evidence_ids", f.get("evidence_ids", []) if isinstance(f, dict) else [])
        conf = getattr(f, "confidence", 1.0)
        finding_reasonings.append({
            "finding_id": fid,
            "title": title,
            "severity": sev_str,
            "reasoning": desc or "Identified by deterministic rule engine.",
            "supporting_evidence_ids": eids,
            "confidence": float(conf)
        })

    return {
        "status": "fallback",
        "reason": reason,
        "investigation_summary": (
            f"Forensic evaluation of capture '{artifact_name}' (SHA-256: {artifact_sha256[:16]}...) "
            f"encompassing {packet_count} packets across {len(sessions)} stream(s). "
            f"The capture exhibits {completeness}% completeness. Deterministic rule evaluation "
            f"yielded {len(findings)} finding(s) with an overall security posture score of {score}/100 ({risk_lvl})."
        ),
        "executive_summary": (
            f"Artifact '{artifact_name}' evaluated with security posture score {score}/100 ({risk_lvl}). "
            f"A total of {len(findings)} security findings were confirmed against {len(evidence)} ledger evidence items."
        ),
        "key_observations": key_obs,
        "finding_reasoning": finding_reasonings,
        "risk_explanation": f"Security posture score {score}/100 indicates {risk_lvl} threat profile based on observed cleartext transmissions and cipher negotiation.",
        "limitations": [
            "Forensic conclusions are strictly bounded by packets present in the capture.",
            f"Capture completeness is {completeness}%; gaps or missing packets may limit protocol analysis.",
            "AI reasoning service was unavailable; this summary was compiled deterministically from validated ledger facts."
        ],
        "recommended_actions": [
            "Review flagged findings and examine cited evidence records in the evidence ledger.",
            "Enforce transport-layer encryption (STARTTLS / TLS 1.3) across all email protocol endpoints.",
            "Disable deprecated SSL/TLS cipher suites and require Perfect Forward Secrecy (PFS)."
        ],
        "generated_by": "deterministic-system",
        "provider": "deterministic-system",
        "model": "rule-engine",
        "prompt_version": PROMPT_VERSION,
        "generated_at": utc_now_iso(),
        "is_ai_generated": False,
    }


async def generate_investigation_summary(
    investigation: Any,
    evidence: List[Any],
    findings: List[Any],
    sessions: List[Any],
    forensic_metadata: Optional[Dict[str, Any]] = None,
    router: Optional[LLMRouter] = None,
    force_refresh: bool = False
) -> Dict[str, Any]:
    """
    Generates an AI-assisted investigation summary grounded in actual forensic evidence.
    Employs priority LLM routing (NVIDIA NIM -> Gemini -> Deterministic Fallback).
    Caches results by investigation_id + forensic_data_hash + prompt_version.
    """
    inv_id = getattr(investigation, "investigation_id", "INV-UNKNOWN")
    artifact_name = getattr(investigation, "artifact_name", "capture.pcap")
    artifact_sha256 = getattr(investigation, "artifact_sha256", "")
    packet_count = getattr(investigation, "packet_count", 0)
    completeness = getattr(investigation, "completeness_percentage", 100.0)

    # Collect valid IDs for citation verification
    valid_evidence_ids = {
        getattr(e, "evidence_id", e.get("evidence_id") if isinstance(e, dict) else str(e))
        for e in evidence
    }
    valid_finding_ids = {
        getattr(f, "finding_id", f.get("finding_id") if isinstance(f, dict) else str(f))
        for f in findings
    }

    # Check cache
    forensic_hash = compute_forensic_data_hash(
        artifact_sha256=artifact_sha256,
        evidence_ids=list(valid_evidence_ids),
        finding_ids=list(valid_finding_ids),
        stream_count=len(sessions)
    )
    cache_key = f"{inv_id}:{forensic_hash}:{PROMPT_VERSION}"

    if not force_refresh and cache_key in _SUMMARY_CACHE:
        logger.info(f"Returning cached AI summary for {inv_id}")
        return _SUMMARY_CACHE[cache_key]

    # Prepare structured forensic context for the LLM
    evidence_snippets = []
    for e in evidence[:25]:
        eid = getattr(e, "evidence_id", e.get("evidence_id") if isinstance(e, dict) else "")
        etype = getattr(e, "type", e.get("type", "") if isinstance(e, dict) else "")
        etype_str = etype.value if hasattr(etype, "value") else str(etype)
        claim = getattr(e, "claim", e.get("claim", "") if isinstance(e, dict) else "")
        source_tool = getattr(e, "source_tool", e.get("source_tool", "") if isinstance(e, dict) else "")
        evidence_snippets.append({"evidence_id": eid, "type": etype_str, "claim": claim, "source_tool": source_tool})

    finding_snippets = []
    for f in findings:
        fid = getattr(f, "finding_id", f.get("finding_id") if isinstance(f, dict) else "")
        title = getattr(f, "title", f.get("title", "") if isinstance(f, dict) else "")
        sev = getattr(f, "severity", "medium")
        sev_str = sev.value if hasattr(sev, "value") else str(sev).lower()
        desc = getattr(f, "description", f.get("description", "") if isinstance(f, dict) else "")
        eids = getattr(f, "evidence_ids", f.get("evidence_ids", []) if isinstance(f, dict) else [])
        finding_snippets.append({
            "finding_id": fid,
            "title": title,
            "severity": sev_str,
            "description": desc,
            "cited_evidence_ids": eids
        })

    session_snippets = []
    for s in sessions[:10]:
        sid = getattr(s, "stream_id", s.get("stream_id") if isinstance(s, dict) else "")
        proto = getattr(s, "protocol_hint", s.get("protocol_hint", "") if isinstance(s, dict) else "")
        client = getattr(s, "client_endpoint", s.get("client_endpoint", "") if isinstance(s, dict) else "")
        server = getattr(s, "server_endpoint", s.get("server_endpoint", "") if isinstance(s, dict) else "")
        session_snippets.append({"stream_id": sid, "protocol": proto, "client": client, "server": server})

    posture = getattr(investigation, "posture", None)
    posture_score = posture.overall_posture_score if posture else getattr(investigation, "security_score", 100.0)
    risk_level = posture.risk_level if posture else getattr(investigation, "risk_level", "UNKNOWN")

    forensic_payload = {
        "investigation_id": inv_id,
        "artifact_name": artifact_name,
        "artifact_sha256": artifact_sha256,
        "packet_count": packet_count,
        "completeness_percentage": completeness,
        "security_score": posture_score,
        "risk_level": risk_level,
        "reconstructed_sessions": session_snippets,
        "evidence_records": evidence_snippets,
        "validated_findings": finding_snippets,
    }

    system_prompt = (
        "You are SecureMailScope's Chief Forensic AI Analyst. "
        "You synthesize structured forensic evidence into an explainable, professional investigation summary.\n"
        "STRICT FORENSIC CONSTRAINTS:\n"
        "1. Reason ONLY over the provided forensic facts. Do NOT hallucinate or invent packet counts, IP addresses, credentials, or findings.\n"
        "2. When explaining findings, you MUST ONLY cite evidence IDs that are listed in the input.\n"
        "3. If details are not present in the capture, state 'Not available in the captured evidence'.\n"
        "4. Your output MUST be a valid JSON object matching this exact schema:\n"
        "{\n"
        '  "investigation_summary": "detailed summary of the capture and analysis...",\n'
        '  "executive_summary": "high-level executive briefing for leadership...",\n'
        '  "key_observations": ["observation 1", "observation 2", ...],\n'
        '  "finding_reasoning": [\n'
        '    {\n'
        '      "finding_id": "matching existing finding_id",\n'
        '      "title": "matching title",\n'
        '      "severity": "critical|high|medium|low|informational",\n'
        '      "reasoning": "technical explanation of why this finding was raised...",\n'
        '      "supporting_evidence_ids": ["EVD-...", ...],\n'
        '      "confidence": 0.95\n'
        '    }\n'
        '  ],\n'
        '  "risk_explanation": "explanation of security risk posture...",\n'
        '  "limitations": ["limitation 1", ...],\n'
        '  "recommended_actions": ["action 1", ...]\n'
        "}"
    )

    user_prompt = (
        f"Generate the forensic investigation summary for investigation {inv_id}.\n\n"
        f"ACTUAL FORENSIC DATA:\n{json.dumps(forensic_payload, indent=2)}"
    )

    llm_router = router or LLMRouter()
    chat_req = ChatRequest(
        messages=[
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=user_prompt),
        ],
        temperature=0.1,
        max_tokens=1500
    )

    try:
        resp = await llm_router.chat(chat_req, investigation_id=inv_id)
        raw_text = resp.content or ""
        parsed = _extract_json_block(raw_text)

        if not parsed:
            logger.warning("LLM response did not contain valid JSON. Falling back to deterministic summary.")
            return generate_deterministic_fallback_summary(
                investigation, evidence, findings, sessions,
                reason="LLM response did not contain valid structured JSON"
            )

        sanitized = _validate_and_sanitize_summary(parsed, valid_evidence_ids, valid_finding_ids)
        sanitized["status"] = "success"
        sanitized["generated_by"] = resp.provider
        sanitized["provider"] = resp.provider
        sanitized["model"] = resp.model
        sanitized["prompt_version"] = PROMPT_VERSION
        sanitized["generated_at"] = utc_now_iso()
        sanitized["is_ai_generated"] = True
        sanitized["forensic_data_hash"] = forensic_hash

        # Cache the valid result
        _SUMMARY_CACHE[cache_key] = sanitized
        return sanitized

    except ProviderUnavailableError as e:
        logger.info(f"AI providers unavailable ({e}). Generating truthful deterministic fallback.")
        fallback = generate_deterministic_fallback_summary(
            investigation, evidence, findings, sessions,
            reason="AI providers unavailable. Generated from deterministic ledger records."
        )
        _SUMMARY_CACHE[cache_key] = fallback
        return fallback

    except Exception as e:
        logger.error(f"Unexpected error during AI summary generation: {e}")
        fallback = generate_deterministic_fallback_summary(
            investigation, evidence, findings, sessions,
            reason=f"AI provider request encountered error: {str(e)}"
        )
        return fallback


def get_cached_summary(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve the cached AI summary for an investigation if present."""
    if investigation_id in _SUMMARY_CACHE:
        return _SUMMARY_CACHE[investigation_id]
    for key, val in _SUMMARY_CACHE.items():
        if key.startswith(f"{investigation_id}:"):
            return val
    return None

