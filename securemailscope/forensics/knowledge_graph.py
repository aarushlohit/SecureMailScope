"""
SecureMailScope - Evidence Knowledge Graph Engine
Builds interconnected forensic topology graphs linking:
Artifacts -> Reconstructed Sessions -> Executed Tools -> Evidence Ledger Claims -> Verified Findings -> ML Metrics
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.models import Investigation, Evidence, Finding
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import ArtifactModel, ForensicSessionModel, ToolExecutionModel, AgentStepModel


class KnowledgeGraphEngine:
    """
    Generates structured, visualizable Knowledge Graph payloads for an investigation.
    """

    @staticmethod
    def build_graph(investigation_id: str, ledger: Optional[EvidenceLedger] = None) -> Dict[str, Any]:
        if ledger is None:
            ledger = EvidenceLedger.get_instance()

        inv = ledger.get_investigation(investigation_id)
        evidence_items = ledger.get_evidence_for_investigation(investigation_id)
        findings = ledger.get_findings_for_investigation(investigation_id)

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        node_ids = set()

        def add_node(node_id: str, label: str, node_type: str, category: str, data: Dict[str, Any], icon: str = "box"):
            if node_id not in node_ids:
                node_ids.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "category": category,
                    "data": data,
                    "icon": icon
                })

        def add_edge(source: str, target: str, relationship: str, label: str = "", edge_type: str = "solid"):
            if source in node_ids and target in node_ids:
                edges.append({
                    "id": f"edge-{source}-{target}-{relationship}",
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                    "label": label or relationship,
                    "type": edge_type
                })

        # 1. Primary Artifact Node
        artifact_id = f"artifact-{investigation_id}"
        art_name = inv.artifact_name if inv else "capture.pcap"
        art_sha = inv.artifact_sha256 if inv else ""
        add_node(
            node_id=artifact_id,
            label=f"Artifact: {art_name}",
            node_type="artifact",
            category="input",
            data={
                "artifact_name": art_name,
                "sha256": art_sha,
                "packet_count": inv.packet_count if inv else 0,
                "protocols": inv.protocols_detected if inv else []
            },
            icon="file-code"
        )

        # 2. Database Sessions & TCP Streams Nodes
        db = SessionLocal()
        try:
            db_sessions = db.query(ForensicSessionModel).filter_by(investigation_id=investigation_id).all()
            for s in db_sessions:
                sess_node_id = f"session-{s.session_id}"
                label = f"{s.protocol} Stream {s.stream_id}"
                add_node(
                    node_id=sess_node_id,
                    label=label,
                    node_type="session",
                    category="transport",
                    data={
                        "stream_id": s.stream_id,
                        "protocol": s.protocol,
                        "client": f"{s.client_ip}:{s.client_port}",
                        "server": f"{s.server_ip}:{s.server_port}",
                        "tls_version": s.tls_version,
                        "cipher": s.cipher_suite
                    },
                    icon="network"
                )
                add_edge(artifact_id, sess_node_id, "RECONSTRUCTED_STREAM", "reconstructed")

            # 3. Executed Forensic Engines & Analyzers
            # Include tools that produced evidence or performed core forensic analysis
            db_tools = db.query(ToolExecutionModel).filter_by(investigation_id=investigation_id).all()
            seen_tools = set()

            # Find which tools directly produced evidence
            evidence_source_tools = {e.source_tool for e in evidence_items if e.source_tool}

            for t in db_tools:
                tool_name = t.tool
                if not tool_name or tool_name in seen_tools:
                    continue
                # Include tools that produced evidence, or core protocol/cryptographic engines
                is_evidence_producer = (tool_name in evidence_source_tools) or bool(t.evidence_ids)
                is_core_analyzer = any(k in tool_name for k in ["analyze", "handshake", "certificate", "completeness", "entropy", "rules", "explain", "cipher", "yara", "inspect", "tavily", "intel"])
                
                if not (is_evidence_producer or is_core_analyzer):
                    continue

                seen_tools.add(tool_name)
                tool_node_id = f"tool-{tool_name.replace('.', '-')}"
                duration = 0.0
                if t.start_time and t.end_time:
                    try:
                        duration = round((t.end_time - t.start_time).total_seconds() * 1000, 2)
                    except Exception:
                        duration = 0.0

                add_node(
                    node_id=tool_node_id,
                    label=f"Tool: {tool_name}",
                    node_type="tool",
                    category="engine",
                    data={
                        "tool_name": tool_name,
                        "status": t.status,
                        "duration_ms": duration,
                        "executed_at": t.start_time.isoformat() if t.start_time else None,
                        "arguments": t.args or {},
                        "result_summary": t.stdout_summary or "",
                        "evidence_ids": t.evidence_ids or []
                    },
                    icon="cpu"
                )

                # Link tool to relevant session or artifact
                linked_to_session = False
                stream_arg = (t.args or {}).get("stream_id")
                if stream_arg is not None:
                    target_sess = f"session-SESS-{investigation_id}-{stream_arg}"
                    if target_sess in node_ids:
                        add_edge(target_sess, tool_node_id, "ANALYZES_STREAM", "dissects")
                        linked_to_session = True
                
                if not linked_to_session:
                    add_edge(artifact_id, tool_node_id, "EXECUTED_ON", "analyzes")

        finally:
            db.close()

        # 4. Evidence Nodes (Ground Truth Ledger Claims)
        for e in evidence_items:
            ev_node_id = f"evidence-{e.evidence_id}"
            ev_type_label = e.type.value.replace("_", " ").title()
            add_node(
                node_id=ev_node_id,
                label=f"[{e.evidence_id}] {ev_type_label}",
                node_type="evidence",
                category="evidence",
                data={
                    "evidence_id": e.evidence_id,
                    "type": e.type.value,
                    "claim": e.claim,
                    "confidence": getattr(e, "confidence", 1.0),
                    "source_tool": e.source_tool,
                    "hash": getattr(e, "entry_hash", "") or getattr(e, "hash", ""),
                    "context": e.details or {}
                },
                icon="shield-check"
            )

            # Link evidence to tool if tool node exists or link to artifact
            tool_matches = [
                n for n in nodes
                if n["type"] == "tool" and (
                    n["data"].get("tool_name") == e.source_tool or
                    e.evidence_id in (n["data"].get("evidence_ids") or [])
                )
            ]
            if tool_matches:
                add_edge(tool_matches[0]["id"], ev_node_id, "PRODUCED_EVIDENCE", "proves")
            else:
                add_edge(artifact_id, ev_node_id, "OBSERVED_EVIDENCE", "proves")

            # Link to stream if details contains stream_id
            stream_id = (e.details or {}).get("stream_id") or (e.tool_args or {}).get("stream_id")
            if stream_id is not None:
                target_sess = f"session-SESS-{investigation_id}-{stream_id}"
                if target_sess in node_ids:
                    add_edge(target_sess, ev_node_id, "STREAM_EVIDENCE", "contains")

        # 5. ML Metric / SHAP Node (if available)
        if inv and inv.posture:
            ml_node_id = f"ml-metrics-{investigation_id}"
            ml_conf = getattr(inv.posture, "ml_risk_probability", 0.0) or getattr(inv.posture, "confidence_score", 0.0)
            add_node(
                node_id=ml_node_id,
                label=f"Posture: {inv.posture.overall_posture_score:.0f}/100 ({inv.posture.risk_level})",
                node_type="ml_metric",
                category="ai_explainability",
                data={
                    "risk_level": inv.posture.risk_level,
                    "ml_confidence": ml_conf,
                    "posture_score": inv.posture.overall_posture_score,
                    "explainability": "shap.TreeExplainer"
                },
                icon="brain"
            )
            add_edge(artifact_id, ml_node_id, "EVALUATED_BY_ML", "scores")

        # 6. Findings Nodes (Verified Security Conclusions)
        for f in findings:
            fnd_node_id = f"finding-{f.finding_id}"
            add_node(
                node_id=fnd_node_id,
                label=f"[{f.severity.value}] {f.title}",
                node_type="finding",
                category="finding",
                data={
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence_ids": f.evidence_ids
                },
                icon="alert-triangle"
            )

            # Link each cited evidence to the finding
            for eid in f.evidence_ids:
                ev_target = f"evidence-{eid}"
                if ev_target in node_ids:
                    add_edge(ev_target, fnd_node_id, "SUPPORTS_FINDING", "validates")

        return {
            "investigation_id": investigation_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
