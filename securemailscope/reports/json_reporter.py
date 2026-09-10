"""
SecureMailScope - Deterministic JSON Report Generator
"""
import json
from pathlib import Path
from typing import Dict, Any
from securemailscope.evidence.ledger import EvidenceLedger


class JSONReporter:
    """
    Generates structured, machine-readable JSON forensic dossiers
    directly from the persisted Evidence Ledger.
    """

    @staticmethod
    def generate_report(investigation_id: str, ledger: EvidenceLedger, output_path: Path) -> Path:
        inv = ledger.get_investigation(investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        evidence_list = ledger.get_evidence_for_investigation(investigation_id)
        hypotheses = ledger.get_hypotheses_for_investigation(investigation_id)
        findings = ledger.get_findings_for_investigation(investigation_id)
        timeline = ledger.get_timeline(investigation_id)
        tool_execs = ledger.get_tool_executions(investigation_id)

        report_data = {
            "meta": {
                "report_format": "SecureMailScope-Forensic-Dossier-v1.0",
                "problem_statement": "SIH26159",
                "organization": "National Technical Research Organisation (NTRO)",
                "generated_at": inv.created_at,
                "investigation_id": inv.investigation_id
            },
            "investigation": inv.model_dump(),
            "scorecard": inv.posture.model_dump() if inv.posture else None,
            "findings": [f.model_dump() for f in findings],
            "hypotheses": [h.model_dump() for h in hypotheses],
            "evidence_ledger": [e.model_dump() for e in evidence_list],
            "timeline": [t.model_dump() for t in timeline],
            "tool_executions": [tx.model_dump() for tx in tool_execs],
            "limitations": inv.limitations,
            "recommendations": inv.recommendations
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        return output_path
