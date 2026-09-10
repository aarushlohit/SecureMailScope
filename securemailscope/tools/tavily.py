"""
SecureMailScope - Tavily External Threat Intelligence Tool
Provides external OSINT/search enrichment strictly through ToolGateway.
Results are categorized strictly as EXTERNAL_INTELLIGENCE and never
overwrite or substitute for passive network packet evidence.
"""
import time
import uuid
import httpx
from typing import Dict, Any, Optional, List
from securemailscope.core.config import config
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import ExternalEvidenceModel, AuditEventModel


class TavilySearchTool:
    """
    Tavily external search tool handler.
    Complies with strict sandboxing and configuration constraints:
    - Only executes if TAVILY_ENABLED and ALLOW_EXTERNAL_INTEL are True
    - Stored as EXTERNAL_INTELLIGENCE
    - Logs retrieval metadata, URLs, titles, and snippets
    """

    ENDPOINT = "https://api.tavily.com/search"

    @classmethod
    def execute(
        cls,
        investigation_id: str,
        query: str,
        max_results: int = 5,
        search_depth: str = "basic",
        hypothesis_id: Optional[str] = None
    ) -> Dict[str, Any]:
        # Enforce administrative permissions
        if not config.tavily_enabled:
            return {
                "status": "DISABLED",
                "error": "Tavily search is administratively disabled (TAVILY_ENABLED=false)."
            }

        if not config.allow_external_intel:
            return {
                "status": "DISALLOWED",
                "error": "External intelligence queries are disabled by policy (ALLOW_EXTERNAL_INTEL=false)."
            }

        if not config.tavily_api_key:
            return {
                "status": "UNCONFIGURED",
                "error": "TAVILY_API_KEY environment variable is missing."
            }

        # Validate arguments
        query = str(query).strip()
        if not query or len(query) < 3:
            return {"status": "ERROR", "error": "Query string too short."}

        max_results = max(1, min(10, int(max_results)))
        if search_depth not in ("basic", "advanced"):
            search_depth = "basic"

        payload = {
            "api_key": config.tavily_api_key,
            "query": query,
            "max_results": max_results,
            "search_depth": search_depth,
            "include_answer": True
        }

        start_time = time.perf_counter()
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(cls.ENDPOINT, json=payload)
                lat = (time.perf_counter() - start_time) * 1000

                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    urls = [r.get("url") for r in results if r.get("url")]
                    titles = [r.get("title") for r in results if r.get("title")]
                    snippets = [r.get("content") for r in results if r.get("content")]
                    answer = data.get("answer", "")

                    ext_id = f"EXT-{uuid.uuid4().hex[:8].upper()}"

                    # Persist ExternalEvidence in DB
                    db = SessionLocal()
                    try:
                        rec = ExternalEvidenceModel(
                            external_id=ext_id,
                            investigation_id=investigation_id,
                            hypothesis_id=hypothesis_id,
                            query=query,
                            provider="tavily",
                            urls=urls,
                            titles=titles,
                            snippets=snippets,
                            retrieval_metadata={
                                "latency_ms": lat,
                                "search_depth": search_depth,
                                "result_count": len(results),
                                "answer": answer
                            }
                        )
                        db.add(rec)
                        db.commit()
                    finally:
                        db.close()

                    return {
                        "status": "SUCCESS",
                        "external_id": ext_id,
                        "query": query,
                        "answer": answer,
                        "results_count": len(results),
                        "results": [
                            {"title": t, "url": u, "snippet": s}
                            for t, u, s in zip(titles, urls, snippets)
                        ],
                        "evidence_classification": "EXTERNAL_INTELLIGENCE",
                        "timestamp": time.time()
                    }
                else:
                    return {
                        "status": "API_ERROR",
                        "error": f"Tavily returned HTTP {resp.status_code}: {resp.text}"
                    }

        except Exception as e:
            return {"status": "NETWORK_ERROR", "error": str(e)}
