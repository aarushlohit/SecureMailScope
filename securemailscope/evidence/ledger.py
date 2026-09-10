"""
SecureMailScope - Evidence Ledger (Immutable Ground Truth Store)
"""
import json
import threading
from pathlib import Path
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


class EvidenceLedger:
    """
    Thread-safe, persistent Evidence Ledger that stores all verified facts,
    tool executions, hypotheses, findings, and timeline events.
    """
    _instance = None
    _lock = threading.RLock()

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or config.evidence_db_path
        self._investigations: Dict[str, Investigation] = {}
        self._evidence: Dict[str, Evidence] = {}
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._findings: Dict[str, Finding] = {}
        self._tool_executions: Dict[str, ToolExecution] = {}
        self._timeline_events: Dict[str, List[TimelineEvent]] = {}
        self._load()

    @classmethod
    def get_instance(cls, storage_path: Optional[Path] = None) -> "EvidenceLedger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = EvidenceLedger(storage_path)
            return cls._instance

    def _load(self):
        if self.storage_path.exists():
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
            except Exception as e:
                # Log or fall back cleanly
                pass

    def _save(self):
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

    # Investigation operations
    def save_investigation(self, inv: Investigation):
        with self._lock:
            self._investigations[inv.investigation_id] = inv
            self._save()

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        with self._lock:
            return self._investigations.get(investigation_id)

    def list_investigations(self) -> List[Investigation]:
        with self._lock:
            return list(self._investigations.values())

    # Evidence operations
    def record_evidence(self, ev: Evidence):
        with self._lock:
            self._evidence[ev.evidence_id] = ev
            if ev.investigation_id in self._investigations:
                if ev.evidence_id not in self._investigations[ev.investigation_id].evidence_ids:
                    self._investigations[ev.investigation_id].evidence_ids.append(ev.evidence_id)
            self._save()

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
            self._save()
