"""
SecureMailScope - Explainable Posture Scorer
"""
from typing import Dict, Any, List
from securemailscope.evidence.models import PostureScorecard


class PostureScorer:
    """
    Calculates an explainable 0 to 100 Security Posture Score.
    Every single point deduction is tied to specific deterministic rule triggers
    and ML risk probabilities.
    """

    @staticmethod
    def calculate_posture(forensic_context: Dict[str, Any], triggered_rules: List[Dict[str, Any]], ml_result: Dict[str, Any]) -> PostureScorecard:
        base_score = 100.0
        deductions: List[Dict[str, Any]] = []
        bonus_points: List[Dict[str, Any]] = []

        # Deductions from Rule Triggers
        rule_weights = {
            "RULE-STARTTLS-PLAINTEXT-VIOLATION": {"points": 80.0, "reason": "STARTTLS plaintext fallback exposed email payloads."},
            "RULE-CIPHER-BROKEN": {"points": 40.0, "reason": "Use of cryptographically broken cipher (RC4)."},
            "RULE-TLS-DEPRECATED": {"points": 35.0, "reason": "Use of deprecated TLS protocol (TLS 1.0/1.1)."},
            "RULE-CLEARTEXT-AUTH": {"points": 30.0, "reason": "Cleartext authentication credentials transmitted."},
            "RULE-CIPHER-LEGACY": {"points": 25.0, "reason": "Use of legacy 64-bit block cipher (3DES)."},
            "RULE-NO-PFS": {"points": 20.0, "reason": "Static RSA key exchange lacks Perfect Forward Secrecy."},
            "RULE-CERT-EXPIRED": {"points": 25.0, "reason": "Expired X.509 server certificate."},
            "RULE-KEY-WEAK": {"points": 25.0, "reason": "Weak public key length (< 2048 bits)."},
            "RULE-SIG-WEAK": {"points": 15.0, "reason": "Weak certificate signature algorithm (MD5/SHA1)."}
        }

        applied_rule_ids = set()
        for r in triggered_rules:
            rid = r.get("rule_id")
            if rid in rule_weights and rid not in applied_rule_ids:
                w = rule_weights[rid]
                deductions.append({
                    "source": f"Rule: {rid}",
                    "points": -w["points"],
                    "reason": w["reason"]
                })
                base_score -= w["points"]
                applied_rule_ids.add(rid)

        # ML Anomaly contribution
        ml_risk_prob = ml_result.get("risk_probability", 0.0)
        ml_anomaly_pts = round(ml_risk_prob * 10.0, 1)
        if ml_anomaly_pts > 0 and len(deductions) == 0:
            deductions.append({
                "source": "ML Anomaly Engine",
                "points": -ml_anomaly_pts,
                "reason": f"Multi-feature statistical anomaly pattern detected (Risk Prob: {ml_risk_prob * 100:.1f}%)."
            })
            base_score -= ml_anomaly_pts

        # Bonus for modern TLS 1.3 & PFS
        tls_info = forensic_context.get("tls", {})
        if tls_info.get("negotiated_version") == "TLS 1.3" and tls_info.get("has_forward_secrecy"):
            bonus_points.append({
                "source": "Modern Cryptography",
                "points": 5.0,
                "reason": "TLS 1.3 modern handshake with enforced Ephemeral Diffie-Hellman PFS."
            })
            base_score = min(100.0, base_score + 5.0)

        final_score = max(0.0, min(100.0, round(base_score, 1)))

        # Risk Classification
        if final_score <= 24.0:
            risk_level = "CRITICAL RISK"
        elif final_score <= 49.0:
            risk_level = "HIGH RISK"
        elif final_score <= 74.0:
            risk_level = "MEDIUM RISK"
        elif final_score <= 89.0:
            risk_level = "LOW RISK"
        else:
            risk_level = "SECURE"

        completeness = forensic_context.get("completeness", {}).get("completeness_percentage", 100.0)
        confidence = min(99.0, max(40.0, round(completeness * 0.98, 1)))

        return PostureScorecard(
            overall_posture_score=final_score,
            risk_level=risk_level,
            confidence_score=confidence,
            score_deductions=deductions,
            bonus_points=bonus_points,
            ml_risk_probability=ml_risk_prob,
            ml_anomaly_contribution=ml_anomaly_pts
        )
