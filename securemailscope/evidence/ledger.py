"""
SecureMailScope - Evidence Ledger (Immutable Ground Truth Store)
Backed by both fast in-memory indexing, JSON ledger file, and persistent SQLAlchemy SQL database.
"""
import json
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional
from securemailscope.evidence.models import (
    Evidence,
    Hypothesis,
    Finding,
    ToolExecution,
    Investigation,
    TimelineEvent
)
from securemailscope.core.config import config
from securemailscope.core.exceptions import EvidenceMutationError
from securemailscope.evidence.hasher import compute_hash_for_evidence, GENESIS_HASH
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import (
    InvestigationModel,
    EvidenceModel,
    FindingModel,
    HypothesisModel,
    ToolExecutionModel,
    AuditEventModel
)



def _parse_dt(dt_val) -> datetime:
    if isinstance(dt_val, datetime):
        return dt_val
    if isinstance(dt_val, str):
        try:
            return datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
        except Exception:
            pass
    return datetime.now(timezone.utc)


class EvidenceLedger:
    """
    Thread-safe, persistent Evidence Ledger that stores all verified facts,
    tool executions, hypotheses, findings, and timeline events in SQL database.
    """
    _instance = None
    _lock = threading.RLock()

    def __init__(self, storage_path: Optional[Path] = None, session_factory=None):
        self.storage_path = storage_path or config.evidence_db_path
        if session_factory is not None:
            self._session_factory = session_factory
        elif storage_path is not None and storage_path.resolve() != config.evidence_db_path.resolve():
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            from securemailscope.db.session import Base, setup_evidence_triggers
            isolated_db_path = storage_path.parent / f"{storage_path.stem}.db"
            db_url = f"sqlite:///{isolated_db_path}"
            engine = create_engine(db_url, connect_args={"check_same_thread": False})
            Base.metadata.create_all(bind=engine)
            setup_evidence_triggers(engine)
            self._session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        else:
            self._session_factory = SessionLocal
        self._investigations: Dict[str, Investigation] = {}
        self._evidence: Dict[str, Evidence] = {}
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._findings: Dict[str, Finding] = {}
        self._tool_executions: Dict[str, ToolExecution] = {}
        self._timeline_events: Dict[str, List[TimelineEvent]] = {}
        self._last_entry_hash: str = GENESIS_HASH
        self._load_from_sql()
        self._load_from_json()

    @classmethod
    def get_instance(cls, storage_path: Optional[Path] = None) -> "EvidenceLedger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = EvidenceLedger(storage_path)
            return cls._instance

    def _load_from_sql(self):
        try:
            db = self._session_factory()
            try:
                # Load investigations
                for m in db.query(InvestigationModel).all():
                    inv = Investigation(
                        investigation_id=m.investigation_id,
                        artifact_name=m.artifact_name or "",
                        artifact_path=m.artifact_path or "",
                        artifact_sha256=m.artifact_sha256 or "",
                        artifact_md5=m.artifact_md5 or "",
                        artifact_size=m.artifact_size or 0,
                        file_type=m.file_type or "pcap",
                        status=m.status or "INGESTED",
                        created_at=m.created_at.isoformat() if m.created_at else "",
                        completed_at=m.completed_at.isoformat() if m.completed_at else None,
                        packet_count=m.packet_count or 0,
                        duration_seconds=m.duration_seconds or 0.0,
                        completeness_percentage=m.completeness_percentage or 100.0,
                        protocols_detected=m.protocols_detected or [],
                        streams_analyzed=m.streams_analyzed or 0
                    )
                    self._investigations[inv.investigation_id] = inv

                # Load evidence ordered chronologically for hash chain continuity
                for e in db.query(EvidenceModel).order_by(EvidenceModel.timestamp.asc(), EvidenceModel.evidence_id.asc()).all():
                    ev = Evidence(
                        evidence_id=e.evidence_id,
                        investigation_id=e.investigation_id,
                        user_id=e.user_id,
                        type=e.type,
                        claim=e.claim,
                        source_tool=e.source_tool,
                        tool_version=e.tool_version or "1.0",
                        tool_args=e.tool_args or {},
                        raw_artifact_ref=e.raw_artifact_ref or "",
                        timestamp=e.timestamp.isoformat() if e.timestamp else "",
                        confidence=e.confidence or 1.0,
                        severity=e.severity or "informational",
                        hypothesis_id=e.hypothesis_id,
                        provenance_chain=e.provenance_chain or [],
                        details=e.details or {},
                        previous_entry_hash=e.previous_entry_hash,
                        entry_hash=e.entry_hash
                    )
                    self._evidence[ev.evidence_id] = ev
                    if e.entry_hash:
                        self._last_entry_hash = e.entry_hash


                # Load findings
                for f in db.query(FindingModel).all():
                    fnd = Finding(
                        finding_id=f.finding_id,
                        investigation_id=f.investigation_id,
                        title=f.title,
                        description=f.description,
                        severity=f.severity,
                        status=f.status or "CANDIDATE",
                        confidence=f.confidence or 1.0,
                        evidence_ids=f.evidence_ids or [],
                        rule_id=f.rule_id,
                        hypothesis_id=f.hypothesis_id,
                        remediation=f.remediation,
                        created_at=f.created_at.isoformat() if f.created_at else ""
                    )
                    self._findings[fnd.finding_id] = fnd

                # Load hypotheses
                for h in db.query(HypothesisModel).all():
                    hyp = Hypothesis(
                        hypothesis_id=h.hypothesis_id,
                        investigation_id=h.investigation_id,
                        title=h.title,
                        description=h.description,
                        status=h.status or "PROPOSED",
                        confidence=h.confidence or 0.5,
                        supporting_evidence_ids=h.supporting_evidence_ids or [],
                        refuting_evidence_ids=h.refuting_evidence_ids or [],
                        notes=h.notes or [],
                        created_at=h.created_at.isoformat() if h.created_at else "",
                        updated_at=h.updated_at.isoformat() if h.updated_at else ""
                    )
                    self._hypotheses[hyp.hypothesis_id] = hyp

                # Load tool executions
                for t in db.query(ToolExecutionModel).all():
                    tx = ToolExecution(
                        execution_id=t.execution_id,
                        investigation_id=t.investigation_id,
                        tool=t.tool,
                        tool_version=t.tool_version or "1.0",
                        args=t.args or {},
                        status=t.status or "SUCCESS",
                        start_time=t.start_time.isoformat() if t.start_time else "",
                        end_time=t.end_time.isoformat() if t.end_time else "",
                        stdout_summary=t.stdout_summary or "",
                        stderr=t.stderr or "",
                        evidence_ids=t.evidence_ids or []
                    )
                    self._tool_executions[tx.execution_id] = tx
            finally:
                db.close()
        except Exception:
            pass

    def _load_from_json(self):
        if self.storage_path and self.storage_path.exists():
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for inv_data in data.get("investigations", []):
                        inv = Investigation(**inv_data)
                        self._investigations[inv.investigation_id] = inv
                    for ev_data in data.get("evidence", []):
                        ev = Evidence(**ev_data)
                        self._evidence[ev.evidence_id] = ev
                    for hyp_data in data.get("hypotheses", []):
                        hyp = Hypothesis(**hyp_data)
                        self._hypotheses[hyp.hypothesis_id] = hyp
                    for find_data in data.get("findings", []):
                        fnd = Finding(**find_data)
                        self._findings[fnd.finding_id] = fnd
                    for exec_data in data.get("tool_executions", []):
                        tx = ToolExecution(**exec_data)
                        self._tool_executions[tx.execution_id] = tx
                    for inv_id, events in data.get("timeline", {}).items():
                        self._timeline_events[inv_id] = [TimelineEvent(**e) for e in events]
            except Exception:
                pass

    def _save(self):
        if not self.storage_path:
            return
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "investigations": [i.model_dump() for i in self._investigations.values()],
                "evidence": [e.model_dump() for e in self._evidence.values()],
                "hypotheses": [h.model_dump() for h in self._hypotheses.values()],
                "findings": [f.model_dump() for f in self._findings.values()],
                "tool_executions": [t.model_dump() for t in self._tool_executions.values()],
                "timeline": {
                    inv_id: [e.model_dump() for e in events]
                    for inv_id, events in self._timeline_events.items()
                }
            }
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    # Investigation operations
    def save_investigation(self, inv: Investigation):
        with self._lock:
            self._investigations[inv.investigation_id] = inv
            self._save()
            try:
                db = self._session_factory()
                try:
                    m = db.query(InvestigationModel).filter_by(investigation_id=inv.investigation_id).first()
                    if not m:
                        m = InvestigationModel(
                            investigation_id=inv.investigation_id,
                            artifact_name=inv.artifact_name,
                            artifact_path=inv.artifact_path,
                            created_at=_parse_dt(inv.created_at)
                        )
                        db.add(m)
                    m.artifact_name = inv.artifact_name
                    m.artifact_path = inv.artifact_path
                    m.artifact_sha256 = inv.artifact_sha256
                    m.artifact_md5 = inv.artifact_md5
                    m.artifact_size = inv.artifact_size
                    m.file_type = inv.file_type
                    m.status = inv.status.value if hasattr(inv.status, "value") else str(inv.status)
                    m.packet_count = inv.packet_count
                    m.duration_seconds = inv.duration_seconds
                    m.completeness_percentage = inv.completeness_percentage
                    m.protocols_detected = inv.protocols_detected
                    m.streams_analyzed = inv.streams_analyzed
                    if inv.posture:
                        m.posture_score = inv.posture.overall_posture_score
                        m.risk_level = inv.posture.risk_level
                        m.confidence_score = inv.posture.confidence_score
                        m.posture_details = inv.posture.model_dump()
                    if inv.completed_at:
                        m.completed_at = _parse_dt(inv.completed_at)
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        with self._lock:
            return self._investigations.get(investigation_id)

    def list_investigations(self) -> List[Investigation]:
        with self._lock:
            return list(self._investigations.values())

    def _record_audit_event(
        self,
        actor: str,
        action: str,
        investigation_id: Optional[str] = None,
        success: bool = True,
        failure_reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        try:
            import uuid
            db = self._session_factory()
            try:
                ev = AuditEventModel(
                    event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                    investigation_id=investigation_id,
                    actor=actor,
                    action=action,
                    success=success,
                    failure_reason=failure_reason,
                    details=details or {}
                )
                db.add(ev)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

    # Evidence operations
    def record_evidence(self, ev: Evidence):
        with self._lock:
            # 1. Enforce append-only in-memory immutability
            if ev.evidence_id in self._evidence:
                self._record_audit_event(
                    actor="EVIDENCE_LEDGER",
                    action="MUTATION_ATTEMPT_BLOCKED",
                    investigation_id=ev.investigation_id,
                    success=False,
                    failure_reason=f"Rejected overwrite attempt for existing evidence '{ev.evidence_id}'."
                )
                raise EvidenceMutationError(
                    f"Evidence '{ev.evidence_id}' already exists in ledger. Evidence records are strictly immutable and append-only."
                )

            # 2. Derive user_id from investigation if missing
            if not ev.user_id and ev.investigation_id in self._investigations:
                inv = self._investigations[ev.investigation_id]
                ev.user_id = getattr(inv, "user_id", None)

            # 3. Deterministic hash chaining
            if not ev.previous_entry_hash:
                ev.previous_entry_hash = self._last_entry_hash
            if not ev.entry_hash:
                ev.entry_hash = compute_hash_for_evidence(ev, ev.previous_entry_hash)

            self._last_entry_hash = ev.entry_hash
            self._evidence[ev.evidence_id] = ev
            if ev.investigation_id in self._investigations:
                if ev.evidence_id not in self._investigations[ev.investigation_id].evidence_ids:
                    self._investigations[ev.investigation_id].evidence_ids.append(ev.evidence_id)
            self._save()

            # 4. Persist to SQL with database-level immutability enforcement
            db = self._session_factory()
            try:
                # Check DB duplicate
                existing = db.query(EvidenceModel).filter_by(evidence_id=ev.evidence_id).first()
                if existing:
                    self._record_audit_event(
                        actor="EVIDENCE_LEDGER",
                        action="MUTATION_ATTEMPT_BLOCKED",
                        investigation_id=ev.investigation_id,
                        success=False,
                        failure_reason=f"Evidence ID '{ev.evidence_id}' already exists in SQL database."
                    )
                    raise EvidenceMutationError(
                        f"Evidence '{ev.evidence_id}' already exists in database. Evidence records are strictly immutable."
                    )

                # Ensure investigation exists in SQL first for foreign key integrity
                inv_m = db.query(InvestigationModel).filter_by(investigation_id=ev.investigation_id).first()
                if not inv_m:
                    inv_obj = self._investigations.get(ev.investigation_id)
                    inv_m = InvestigationModel(
                        investigation_id=ev.investigation_id,
                        user_id=ev.user_id,
                        artifact_name=inv_obj.artifact_name if inv_obj else "unknown.pcap",
                        artifact_path=inv_obj.artifact_path if inv_obj else "/tmp/unknown.pcap",
                        created_at=_parse_dt(ev.timestamp)
                    )
                    db.add(inv_m)
                    db.flush()

                db_ev = EvidenceModel(
                    evidence_id=ev.evidence_id,
                    investigation_id=ev.investigation_id,
                    user_id=ev.user_id,
                    type=ev.type.value if hasattr(ev.type, "value") else str(ev.type),
                    claim=ev.claim,
                    source_tool=ev.source_tool,
                    tool_version=ev.tool_version,
                    tool_args=ev.tool_args,
                    raw_artifact_ref=ev.raw_artifact_ref,
                    timestamp=_parse_dt(ev.timestamp),
                    confidence=ev.confidence,
                    severity=ev.severity.value if hasattr(ev.severity, "value") else str(ev.severity),
                    hypothesis_id=ev.hypothesis_id,
                    provenance_chain=ev.provenance_chain,
                    details=ev.details,
                    previous_entry_hash=ev.previous_entry_hash,
                    entry_hash=ev.entry_hash
                )
                db.add(db_ev)
                db.commit()
            except EvidenceMutationError:
                raise
            except Exception:
                pass
            finally:
                db.close()


    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        with self._lock:
            return self._evidence.get(evidence_id)

    def get_evidence_for_investigation(self, investigation_id: str) -> List[Evidence]:
        with self._lock:
            return [e for e in self._evidence.values() if e.investigation_id == investigation_id]

    def get_all_evidence(self) -> List[Evidence]:
        with self._lock:
            return list(self._evidence.values())

    # Tool execution operations
    def record_tool_execution(self, tx: ToolExecution):
        with self._lock:
            self._tool_executions[tx.execution_id] = tx
            self._save()

            try:
                db = self._session_factory()
                try:
                    inv_m = db.query(InvestigationModel).filter_by(investigation_id=tx.investigation_id).first()
                    if not inv_m:
                        inv_obj = self._investigations.get(tx.investigation_id)
                        inv_m = InvestigationModel(
                            investigation_id=tx.investigation_id,
                            artifact_name=inv_obj.artifact_name if inv_obj else "unknown.pcap",
                            artifact_path=inv_obj.artifact_path if inv_obj else "/tmp/unknown.pcap",
                            created_at=_parse_dt(tx.start_time)
                        )
                        db.add(inv_m)
                        db.flush()

                    db_tx = db.query(ToolExecutionModel).filter_by(execution_id=tx.execution_id).first()
                    if not db_tx:
                        db_tx = ToolExecutionModel(
                            execution_id=tx.execution_id,
                            investigation_id=tx.investigation_id,
                            tool=tx.tool,
                            tool_version=tx.tool_version,
                            args=tx.args,
                            status=tx.status,
                            start_time=_parse_dt(tx.start_time),
                            end_time=_parse_dt(tx.end_time),
                            stdout_summary=tx.stdout_summary,
                            stderr=tx.stderr,
                            evidence_ids=tx.evidence_ids
                        )
                        db.add(db_tx)
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass

    def get_tool_executions(self, investigation_id: str) -> List[ToolExecution]:
        with self._lock:
            return [t for t in self._tool_executions.values() if t.investigation_id == investigation_id]

    # Hypothesis operations
    def save_hypothesis(self, hyp: Hypothesis):
        with self._lock:
            self._hypotheses[hyp.hypothesis_id] = hyp
            if hyp.investigation_id in self._investigations:
                if hyp.hypothesis_id not in self._investigations[hyp.investigation_id].hypothesis_ids:
                    self._investigations[hyp.investigation_id].hypothesis_ids.append(hyp.hypothesis_id)
            self._save()

            try:
                db = self._session_factory()
                try:
                    inv_m = db.query(InvestigationModel).filter_by(investigation_id=hyp.investigation_id).first()
                    if not inv_m:
                        inv_obj = self._investigations.get(hyp.investigation_id)
                        inv_m = InvestigationModel(
                            investigation_id=hyp.investigation_id,
                            artifact_name=inv_obj.artifact_name if inv_obj else "unknown.pcap",
                            artifact_path=inv_obj.artifact_path if inv_obj else "/tmp/unknown.pcap",
                            created_at=_parse_dt(hyp.created_at)
                        )
                        db.add(inv_m)
                        db.flush()

                    db_hyp = db.query(HypothesisModel).filter_by(hypothesis_id=hyp.hypothesis_id).first()
                    if not db_hyp:
                        db_hyp = HypothesisModel(
                            hypothesis_id=hyp.hypothesis_id,
                            investigation_id=hyp.investigation_id,
                            title=hyp.title,
                            description=hyp.description,
                            status=hyp.status.value if hasattr(hyp.status, "value") else str(hyp.status),
                            confidence=hyp.confidence,
                            supporting_evidence_ids=hyp.supporting_evidence_ids,
                            refuting_evidence_ids=hyp.refuting_evidence_ids,
                            notes=hyp.notes,
                            created_at=_parse_dt(hyp.created_at)
                        )
                        db.add(db_hyp)
                    else:
                        db_hyp.status = hyp.status.value if hasattr(hyp.status, "value") else str(hyp.status)
                        db_hyp.confidence = hyp.confidence
                        db_hyp.supporting_evidence_ids = hyp.supporting_evidence_ids
                        db_hyp.refuting_evidence_ids = hyp.refuting_evidence_ids
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass

    def get_hypotheses_for_investigation(self, investigation_id: str) -> List[Hypothesis]:
        with self._lock:
            return [h for h in self._hypotheses.values() if h.investigation_id == investigation_id]

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        with self._lock:
            return self._hypotheses.get(hypothesis_id)

    # Finding operations
    def save_finding(self, finding: Finding):
        with self._lock:
            self._findings[finding.finding_id] = finding
            if finding.investigation_id in self._investigations:
                if finding.finding_id not in self._investigations[finding.investigation_id].finding_ids:
                    self._investigations[finding.investigation_id].finding_ids.append(finding.finding_id)
            self._save()

            try:
                db = self._session_factory()
                try:
                    inv_m = db.query(InvestigationModel).filter_by(investigation_id=finding.investigation_id).first()
                    if not inv_m:
                        inv_obj = self._investigations.get(finding.investigation_id)
                        inv_m = InvestigationModel(
                            investigation_id=finding.investigation_id,
                            artifact_name=inv_obj.artifact_name if inv_obj else "unknown.pcap",
                            artifact_path=inv_obj.artifact_path if inv_obj else "/tmp/unknown.pcap",
                            created_at=_parse_dt(finding.created_at)
                        )
                        db.add(inv_m)
                        db.flush()

                    db_fnd = db.query(FindingModel).filter_by(finding_id=finding.finding_id).first()
                    if not db_fnd:
                        db_fnd = FindingModel(
                            finding_id=finding.finding_id,
                            investigation_id=finding.investigation_id,
                            title=finding.title,
                            description=finding.description,
                            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                            status=finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                            confidence=finding.confidence,
                            evidence_ids=finding.evidence_ids,
                            rule_id=finding.rule_id,
                            hypothesis_id=finding.hypothesis_id,
                            remediation=finding.remediation,
                            created_at=_parse_dt(finding.created_at)
                        )
                        db.add(db_fnd)
                    else:
                        db_fnd.status = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
                        db_fnd.confidence = finding.confidence
                        db_fnd.evidence_ids = finding.evidence_ids
                        db_fnd.remediation = finding.remediation
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self._lock:
            return self._findings.get(finding_id)

    def get_findings_for_investigation(self, investigation_id: str) -> List[Finding]:
        with self._lock:
            return [f for f in self._findings.values() if f.investigation_id == investigation_id]

    def get_all_findings(self) -> List[Finding]:
        with self._lock:
            return list(self._findings.values())

    # Timeline event operations
    def record_timeline_event(self, event: TimelineEvent, investigation_id: str):
        with self._lock:
            if investigation_id not in self._timeline_events:
                self._timeline_events[investigation_id] = []
            self._timeline_events[investigation_id].append(event)
            self._save()

    def get_timeline(self, investigation_id: str) -> List[TimelineEvent]:
        with self._lock:
            return self._timeline_events.get(investigation_id, [])

    def clear(self):
        with self._lock:
            self._investigations.clear()
            self._evidence.clear()
            self._hypotheses.clear()
            self._findings.clear()
            self._tool_executions.clear()
            self._timeline_events.clear()
            self._last_entry_hash = GENESIS_HASH
            self._save()

