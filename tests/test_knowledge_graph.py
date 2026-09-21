"""
Unit and Integration Tests for SecureMailScope Evidence Knowledge Graph
"""
import uuid
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from securemailscope.api.app import app
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.forensics.knowledge_graph import KnowledgeGraphEngine
from securemailscope.core.config import SAMPLES_DIR

client = TestClient(app)


def test_knowledge_graph_generation():
    ledger = EvidenceLedger.get_instance()
    agent = InvestigationAgent(ledger)

    sample_pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"
    assert sample_pcap.exists(), "Sample fixture missing"

    inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    inv = agent.run_investigation(inv_id, Path(sample_pcap))
    assert inv is not None
    assert inv.investigation_id == inv_id

    # 1. Direct Engine Generation
    graph = KnowledgeGraphEngine.build_graph(inv_id, ledger=ledger)
    assert graph is not None
    assert graph["investigation_id"] == inv_id
    assert graph["node_count"] > 0
    assert graph["edge_count"] > 0
    assert len(graph["nodes"]) == graph["node_count"]
    assert len(graph["edges"]) == graph["edge_count"]

    # Verify Category diversity
    categories = {n["category"] for n in graph["nodes"]}
    assert "input" in categories
    assert "evidence" in categories

    # Verify node structure
    for node in graph["nodes"]:
        assert "id" in node
        assert "label" in node
        assert "category" in node
        assert "type" in node
        assert "data" in node

    # Verify edge structure
    for edge in graph["edges"]:
        assert "id" in edge
        assert "source" in edge
        assert "target" in edge
        assert "relationship" in edge


from tests.conftest import make_authed_client

def test_knowledge_graph_api_endpoint():
    authed = make_authed_client()
    sample_pcap = SAMPLES_DIR / "mail_secure_tls13.pcap"
    assert sample_pcap.exists(), "Sample fixture missing"

    with open(sample_pcap, "rb") as f:
        resp_up = authed.post(
            "/api/investigations",
            files={"file": ("mail_secure_tls13.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    assert resp_up.status_code == 200
    inv_id = resp_up.json()["investigation_id"]

    # Test API endpoint
    response = authed.get(f"/api/investigations/{inv_id}/graph")
    assert response.status_code == 200
    data = response.json()

    assert data["investigation_id"] == inv_id
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0

    # Test non-existent investigation 404
    resp_404 = authed.get("/api/investigations/INV-NONEXISTENT/graph")
    assert resp_404.status_code == 404
