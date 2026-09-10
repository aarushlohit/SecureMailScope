"""
SecureMailScope - Hypothesis Engine
"""
import uuid
from typing import Dict, List, Optional
from securemailscope.evidence.models import Hypothesis, HypothesisStatus
from securemailscope.evidence.ledger import EvidenceLedger


class HypothesisEngine:
    """
    Manages threat and causality hypotheses during the forensic investigation.
    Allows evidence to SUPPORT, REFUTE, or LEAVE_UNCHANGED a hypothesis.
    """

    def __init__(self, ledger: EvidenceLedger, investigation_id: str):
        self.ledger = ledger
        self.investigation_id = investigation_id

    def create_hypothesis(self, title: str, description: str, initial_confidence: float = 0.5) -> Hypothesis:
        hyp_id = f"H-{uuid.uuid4().hex[:6].upper()}"
        hyp = Hypothesis(
            hypothesis_id=hyp_id,
            investigation_id=self.investigation_id,
            title=title,
            description=description,
            status=HypothesisStatus.PROPOSED,
            confidence=initial_confidence
        )
        self.ledger.save_hypothesis(hyp)
        return hyp

    def add_supporting_evidence(self, hypothesis_id: str, evidence_id: str, confidence_boost: float = 0.25, note: str = ""):
        hyp = self.ledger.get_hypothesis(hypothesis_id)
        if not hyp:
            return
        if evidence_id not in hyp.supporting_evidence_ids:
            hyp.supporting_evidence_ids.append(evidence_id)
        hyp.confidence = min(1.0, round(hyp.confidence + confidence_boost, 2))
        if hyp.confidence >= 0.85:
            hyp.status = HypothesisStatus.SUPPORTED
        if note:
            hyp.notes.append(f"[SUPPORTED] {note}")
        self.ledger.save_hypothesis(hyp)

    def add_refuting_evidence(self, hypothesis_id: str, evidence_id: str, confidence_penalty: float = 0.35, note: str = ""):
        hyp = self.ledger.get_hypothesis(hypothesis_id)
        if not hyp:
            return
        if evidence_id not in hyp.refuting_evidence_ids:
            hyp.refuting_evidence_ids.append(evidence_id)
        hyp.confidence = max(0.0, round(hyp.confidence - confidence_penalty, 2))
        if hyp.confidence <= 0.25:
            hyp.status = HypothesisStatus.REFUTED
        if note:
            hyp.notes.append(f"[REFUTED] {note}")
        self.ledger.save_hypothesis(hyp)

    def confirm_hypothesis(self, hypothesis_id: str, final_note: str = ""):
        hyp = self.ledger.get_hypothesis(hypothesis_id)
        if not hyp:
            return
        hyp.status = HypothesisStatus.CONFIRMED
        hyp.confidence = 1.0
        if final_note:
            hyp.notes.append(f"[CONFIRMED] {final_note}")
        self.ledger.save_hypothesis(hyp)

    def mark_inconclusive(self, hypothesis_id: str, reason: str = ""):
        hyp = self.ledger.get_hypothesis(hypothesis_id)
        if not hyp:
            return
        hyp.status = HypothesisStatus.INCONCLUSIVE
        if reason:
            hyp.notes.append(f"[INCONCLUSIVE] {reason}")
        self.ledger.save_hypothesis(hyp)
