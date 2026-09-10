"""
SecureMailScope - Threat Prioritization Engine
"""
from typing import List, Dict, Any
from securemailscope.evidence.models import Finding, SeverityLevel


class ThreatPrioritizer:
    """
    Ranks findings based on: Severity × Evidence Confidence × Exposure
    """
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 100,
        SeverityLevel.HIGH: 75,
        SeverityLevel.MEDIUM: 50,
        SeverityLevel.LOW: 25,
        SeverityLevel.INFORMATIONAL: 10
    }

    @staticmethod
    def prioritize_findings(findings: List[Finding]) -> List[Dict[str, Any]]:
        ranked = []
        for f in findings:
            weight = ThreatPrioritizer.SEVERITY_WEIGHTS.get(f.severity, 20)
            score = round(weight * f.confidence, 1)
            priority_label = "P1 - Critical" if score >= 90 else (
                "P2 - High" if score >= 65 else (
                    "P3 - Medium" if score >= 40 else "P4 - Low"
                )
            )
            ranked.append({
                "finding": f,
                "priority_label": priority_label,
                "priority_score": score,
                "evidence_count": len(f.evidence_ids)
            })

        ranked.sort(key=lambda x: x["priority_score"], reverse=True)
        return ranked
