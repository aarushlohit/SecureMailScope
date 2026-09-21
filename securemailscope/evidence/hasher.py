"""
SecureMailScope - Deterministic Evidence Hasher & Hash-Chain Utility
Provides cryptographic canonicalization and SHA-256 block hashing for the immutable ledger.
"""
import json
import hashlib
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64


def _normalize_for_canonical_json(obj: Any) -> Any:
    """Recursively normalizes Python structures into JSON-canonical primitives."""
    if obj is None:
        return None
    if isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _normalize_for_canonical_json(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple, set)):
        return [_normalize_for_canonical_json(item) for item in obj]
    if hasattr(obj, "value"):  # Enums
        return str(obj.value)
    return str(obj)


def canonicalize_evidence_payload(
    claim: str,
    source_tool: str,
    tool_version: str = "1.0",
    tool_args: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
    provenance_chain: Optional[List[Any]] = None
) -> str:
    """
    Serializes evidence content into a strict, deterministic, canonical JSON string.
    Ensures identical SHA-256 hashes across different platforms, processes, and runs.
    """
    normalized_dict = {
        "claim": str(claim).strip(),
        "details": _normalize_for_canonical_json(details or {}),
        "provenance_chain": _normalize_for_canonical_json(provenance_chain or []),
        "source_tool": str(source_tool).strip(),
        "tool_args": _normalize_for_canonical_json(tool_args or {}),
        "tool_version": str(tool_version).strip() if tool_version else "1.0"
    }
    return json.dumps(normalized_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_evidence_entry_hash(
    evidence_id: str,
    investigation_id: str,
    user_id: Optional[str],
    evidence_type: str,
    source_ref: str,
    timestamp_iso: str,
    canonical_payload: str,
    previous_entry_hash: str
) -> str:
    """
    Computes a deterministic SHA-256 block hash for an evidence ledger entry.
    """
    block_data = {
        "canonical_payload": canonical_payload,
        "evidence_id": str(evidence_id).strip(),
        "evidence_type": str(evidence_type).strip(),
        "investigation_id": str(investigation_id).strip(),
        "previous_entry_hash": str(previous_entry_hash or GENESIS_HASH).strip(),
        "source_ref": str(source_ref or "").strip(),
        "timestamp": str(timestamp_iso).strip(),
        "user_id": str(user_id or "").strip()
    }
    canonical_block = json.dumps(block_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical_block.encode("utf-8")).hexdigest()


def _normalize_timestamp(ts: Any) -> str:
    if isinstance(ts, datetime):
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts.isoformat()
    if isinstance(ts, str):
        cleaned = ts.strip()
        # Replace space separator between date and time with T
        if " " in cleaned and len(cleaned) >= 19 and cleaned[10] == " ":
            cleaned = cleaned[:10] + "T" + cleaned[11:]
        if cleaned.endswith("+00:00"):
            cleaned = cleaned[:-6]
        elif cleaned.endswith("Z"):
            cleaned = cleaned[:-1]
        return cleaned
    return str(ts or "")


def compute_hash_for_evidence(
    ev: Any,
    previous_hash: str = GENESIS_HASH
) -> str:
    """
    Helper function to compute hash directly from an Evidence model or dict.
    """
    if isinstance(ev, dict):
        eid = ev.get("evidence_id", "")
        iid = ev.get("investigation_id", "")
        uid = ev.get("user_id")
        etype = ev.get("type", "")
        claim = ev.get("claim", "")
        tool = ev.get("source_tool", "")
        tver = ev.get("tool_version", "1.0")
        targs = ev.get("tool_args", {})
        ref = ev.get("raw_artifact_ref", "")
        ts = ev.get("timestamp", "")
        prov = ev.get("provenance_chain", [])
        dets = ev.get("details", {})
    else:
        eid = getattr(ev, "evidence_id", "")
        iid = getattr(ev, "investigation_id", "")
        uid = getattr(ev, "user_id", None)
        etype = getattr(ev, "type", "")
        if hasattr(etype, "value"):
            etype = etype.value
        claim = getattr(ev, "claim", "")
        tool = getattr(ev, "source_tool", "")
        tver = getattr(ev, "tool_version", "1.0")
        targs = getattr(ev, "tool_args", {})
        ref = getattr(ev, "raw_artifact_ref", "")
        ts = getattr(ev, "timestamp", "")
        prov = getattr(ev, "provenance_chain", [])
        dets = getattr(ev, "details", {})

    canonical_payload = canonicalize_evidence_payload(
        claim=claim,
        source_tool=tool,
        tool_version=tver,
        tool_args=targs,
        details=dets,
        provenance_chain=prov
    )

    normalized_ts = _normalize_timestamp(ts)

    return compute_evidence_entry_hash(
        evidence_id=eid,
        investigation_id=iid,
        user_id=uid,
        evidence_type=str(etype),
        source_ref=ref,
        timestamp_iso=normalized_ts,
        canonical_payload=canonical_payload,
        previous_entry_hash=previous_hash
    )

