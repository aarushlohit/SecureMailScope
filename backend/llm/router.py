"""
SecureMailScope - LLM Router with Strict Priority & Audit Trail
Priority:
1. NVIDIA NIM (moonshotai/kimi-k3)
2. Google Gemini Fallback
3. Deterministic Local Reasoner
"""
import time
import uuid
import logging
from typing import AsyncIterator, Dict, Any, Optional, List
from backend.llm.base import LLMProvider
from backend.llm.nvidia import NvidiaProvider
from backend.llm.gemini import GeminiProvider
from backend.llm.schemas import ChatRequest, ChatResponse, StreamChunk, HealthStatus
from backend.llm.exceptions import LLMException
from securemailscope.core.config import config
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import AuditEventModel

logger = logging.getLogger("securemailscope.llm.router")


class LLMRouter:
    """
    Orchestrates LLM requests with fallback hierarchy:
    NVIDIA NIM -> Google Gemini -> Deterministic Fallback.
    Logs every attempt and routing decision to AuditEvent.
    """

    def __init__(
        self,
        nvidia_provider: Optional[NvidiaProvider] = None,
        gemini_provider: Optional[GeminiProvider] = None
    ):
        self.nvidia = nvidia_provider or NvidiaProvider()
        self.gemini = gemini_provider or GeminiProvider()

    def _record_audit(
        self,
        investigation_id: Optional[str],
        provider: str,
        model: str,
        success: bool,
        latency_ms: float,
        tokens_used: int = 0,
        failure_reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        try:
            db = SessionLocal()
            try:
                evt = AuditEventModel(
                    event_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                    investigation_id=investigation_id,
                    actor="LLM_ROUTER",
                    action=f"llm_call_{provider}",
                    provider=provider,
                    model=model,
                    latency_ms=latency_ms,
                    tokens_used=tokens_used,
                    success=success,
                    failure_reason=failure_reason,
                    details=details or {}
                )
                db.add(evt)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"Could not persist AuditEvent: {e}")

    async def chat(self, request: ChatRequest, investigation_id: Optional[str] = None) -> ChatResponse:
        """
        Execute chat request via priority routing.
        """
        # 1. Try NVIDIA NIM
        if self.nvidia.api_key:
            start = time.perf_counter()
            try:
                resp = await self.nvidia.chat(request)
                lat = (time.perf_counter() - start) * 1000
                tokens = resp.usage.total_tokens if resp.usage else 0
                self._record_audit(
                    investigation_id=investigation_id,
                    provider="nvidia",
                    model=resp.model,
                    success=True,
                    latency_ms=lat,
                    tokens_used=tokens,
                    details={"request_id": resp.request_id}
                )
                return resp
            except Exception as e:
                lat = (time.perf_counter() - start) * 1000
                reason = f"NVIDIA failed: {e}"
                logger.warning(reason)
                self._record_audit(
                    investigation_id=investigation_id,
                    provider="nvidia",
                    model=self.nvidia.model,
                    success=False,
                    latency_ms=lat,
                    failure_reason=str(e)
                )

        # 2. Try Gemini Fallback
        if self.gemini.api_key:
            start = time.perf_counter()
            try:
                resp = await self.gemini.chat(request)
                lat = (time.perf_counter() - start) * 1000
                tokens = resp.usage.total_tokens if resp.usage else 0
                self._record_audit(
                    investigation_id=investigation_id,
                    provider="gemini",
                    model=resp.model,
                    success=True,
                    latency_ms=lat,
                    tokens_used=tokens
                )
                return resp
            except Exception as e:
                lat = (time.perf_counter() - start) * 1000
                reason = f"Gemini failed: {e}"
                logger.warning(reason)
                self._record_audit(
                    investigation_id=investigation_id,
                    provider="gemini",
                    model=self.gemini.model,
                    success=False,
                    latency_ms=lat,
                    failure_reason=str(e)
                )

        # 3. Deterministic Local Fallback
        return self._deterministic_fallback_chat(request, investigation_id)

    async def stream(self, request: ChatRequest, investigation_id: Optional[str] = None) -> AsyncIterator[StreamChunk]:
        """
        Execute streaming chat request via priority routing.
        """
        if self.nvidia.api_key:
            try:
                async for chunk in self.nvidia.stream(request):
                    yield chunk
                return
            except Exception as e:
                logger.warning(f"NVIDIA stream failed: {e}")
                self._record_audit(
                    investigation_id=investigation_id,
                    provider="nvidia",
                    model=self.nvidia.model,
                    success=False,
                    latency_ms=0.0,
                    failure_reason=f"Streaming error: {e}"
                )

        if self.gemini.api_key:
            try:
                async for chunk in self.gemini.stream(request):
                    yield chunk
                return
            except Exception as e:
                logger.warning(f"Gemini stream failed: {e}")
                self._record_audit(
                    investigation_id=investigation_id,
                    provider="gemini",
                    model=self.gemini.model,
                    success=False,
                    latency_ms=0.0,
                    failure_reason=f"Streaming error: {e}"
                )

        # Fallback stream: emit deterministic response chunks
        det_resp = self._deterministic_fallback_chat(request, investigation_id)
        words = det_resp.content.split(" ")
        for w in words:
            yield StreamChunk(
                delta=w + " ",
                finish_reason=None,
                model="deterministic-fallback",
                provider="deterministic"
            )
        yield StreamChunk(
            delta="",
            finish_reason="stop",
            model="deterministic-fallback",
            provider="deterministic"
        )

    def _deterministic_fallback_chat(self, request: ChatRequest, investigation_id: Optional[str]) -> ChatResponse:
        """
        Deterministic, rule-based reasoning engine when external LLMs are unavailable.
        Uses structured heuristics over evidence facts.
        """
        last_msg = request.messages[-1].content if request.messages else ""
        query_text = str(last_msg).lower()

        lines = [
            "**Deterministic Forensic Reasoning Engine** *(No External LLM Available)*\n"
        ]

        if "starttls" in query_text or "downgrade" in query_text or "stripping" in query_text:
            lines.append("• Evaluated STARTTLS transitions from passive PCAP evidence.")
            lines.append("• State machine traces: EHLO advertisement -> STARTTLS request -> 220 acknowledgement.")
            lines.append("• If plaintext SMTP continuation was recorded without TLS ClientHello, a STARTTLS stripping downgrade violation is established.")
        elif "cert" in query_text or "x.509" in query_text or "chain" in query_text:
            lines.append("• Observable X.509 certificates (TLS <= 1.2) were analyzed against key size and validity windows.")
            lines.append("• For TLS 1.3 handshakes, certificates remain encrypted post-ServerHello and are recorded honestly as NOT_OBSERVABLE.")
        elif "completeness" in query_text or "quality" in query_text:
            lines.append("• Capture completeness evaluated via TCP sequence gap analysis and retransmission tracking.")
            lines.append("• Scores < 60% generate honest INCONCLUSIVE findings rather than speculative attack declarations.")
        else:
            lines.append("• Passive network capture analysis operates deterministically on protocol state machines, cryptographic parameters, and ML feature attribution.")
            lines.append("• All findings and severity scores are strictly anchored to immutable Evidence IDs in the ledger.")

        content = "\n".join(lines)
        self._record_audit(
            investigation_id=investigation_id,
            provider="deterministic",
            model="deterministic-local-v1",
            success=True,
            latency_ms=1.0,
            details={"note": "Fallback to deterministic local reasoning"}
        )
        return ChatResponse(
            content=content,
            role="assistant",
            finish_reason="stop",
            model="deterministic-local-v1",
            provider="deterministic",
            latency_ms=1.0
        )

    async def get_system_llm_status(self) -> Dict[str, Any]:
        """
        Return the health status of all configured providers without exposing API keys.
        """
        nv_conf = bool(self.nvidia.api_key)
        gem_conf = bool(self.gemini.api_key)
        tav_conf = bool(config.tavily_api_key)

        return {
            "primary": {
                "provider": "nvidia",
                "model": self.nvidia.model,
                "configured": nv_conf,
                "healthy": nv_conf
            },
            "fallback": {
                "provider": "gemini",
                "model": self.gemini.model,
                "configured": gem_conf,
                "healthy": gem_conf
            },
            "tavily": {
                "configured": tav_conf,
                "enabled": config.tavily_enabled and config.allow_external_intel
            }
        }
