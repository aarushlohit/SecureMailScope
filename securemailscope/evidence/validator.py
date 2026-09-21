"""
SecureMailScope - Finding Validator ("No Evidence -> No Finding" Gate)
"""
from typing import List, Tuple
from securemailscope.evidence.models import Finding, FindingStatus
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.core.exceptions import EvidenceValidationError


class FindingValidator:
    """
    Enforces the core architectural principle: No Evidence -> No Finding.
    Validates that every claim made in a Finding is substantiated by genuine,
    persisted evidence with non-empty provenance chains in the Evidence Ledger.
    """

    def __init__(self, ledger: EvidenceLedger):
        self.ledger = ledger

    def validate_and_register_finding(self, finding: Finding) -> Tuple[bool, str]:
        """
        Validates the finding against the ledger. If valid, persists the finding.
        Otherwise rejects it and raises EvidenceValidationError or returns (False, reason).
        """
        if not finding.evidence_ids or len(finding.evidence_ids) == 0:
            msg = f"FINDING REJECTED: Finding '{finding.finding_id}' contains NO supporting evidence IDs."
            raise EvidenceValidationError(msg)

        missing_evidence = []
        mismatched_investigation = []
        mismatched_user = []
        missing_provenance = []
        tampered_evidence = []

        inv = self.ledger.get_investigation(finding.investigation_id)
        finding_user_id = getattr(inv, "user_id", None) if inv else None

        from securemailscope.evidence.hasher import compute_hash_for_evidence, GENESIS_HASH

        for eid in finding.evidence_ids:
            ev = self.ledger.get_evidence(eid)
            if not ev:
                missing_evidence.append(eid)
                continue

            if ev.investigation_id != finding.investigation_id:
                mismatched_investigation.append(eid)

            if finding_user_id and ev.user_id and ev.user_id != finding_user_id:
                mismatched_user.append((eid, ev.user_id, finding_user_id))

            if not ev.provenance_chain or len(ev.provenance_chain) == 0:
                missing_provenance.append(eid)

            # Cryptographic hash verification if present
            if ev.entry_hash:
                expected_hash = compute_hash_for_evidence(ev, ev.previous_entry_hash or GENESIS_HASH)
                if ev.entry_hash != expected_hash:
                    tampered_evidence.append(eid)

        if missing_evidence:
            msg = f"FINDING REJECTED: Evidence IDs do not exist in Ledger: {missing_evidence}"
            raise EvidenceValidationError(msg)

        if mismatched_investigation:
            msg = f"FINDING REJECTED: Evidence IDs belong to a different investigation: {mismatched_investigation}"
            raise EvidenceValidationError(msg)

        if mismatched_user:
            msg = f"FINDING REJECTED: Cross-user evidence citation detected: {mismatched_user}"
            raise EvidenceValidationError(msg)

        if missing_provenance:
            msg = f"FINDING REJECTED: Evidence IDs lack valid provenance chains: {missing_provenance}"
            raise EvidenceValidationError(msg)

        if tampered_evidence:
            msg = f"FINDING REJECTED: Supporting evidence failed cryptographic integrity verification: {tampered_evidence}"
            raise EvidenceValidationError(msg)

        # Mark finding as verified once validated against persisted evidence (unless explicitly inconclusive)
        if finding.status != FindingStatus.INCONCLUSIVE:
            finding.status = FindingStatus.VERIFIED
        self.ledger.save_finding(finding)
        return True, f"Finding '{finding.finding_id}' successfully verified with {len(finding.evidence_ids)} evidence items."

