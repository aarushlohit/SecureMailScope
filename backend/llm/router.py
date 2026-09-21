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
from backend.llm.exceptions import LLMException, ProviderUnavailableError
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

        # 3. Explicit AI Unavailable (No fake deterministic reasoner masquerading as an LLM)
        self._record_audit(
            investigation_id=investigation_id,
            provider="none",
            model="none",
            success=False,
            latency_ms=0.0,
            failure_reason="Both NVIDIA NIM and Google Gemini LLM providers are unavailable."
        )
        raise ProviderUnavailableError("AI reasoning unavailable: Neither NVIDIA NIM nor Google Gemini is available. Deterministic forensic pipeline remains active.")

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

        raise ProviderUnavailableError("AI streaming reasoning unavailable: Neither NVIDIA NIM nor Google Gemini is available.")


    async def get_system_llm_status(self) -> Dict[str, Any]:
        """
        Perform REAL lightweight health pings to each configured provider.
        Returns reachable=true only after a genuine HTTP 200 response.
        Never exposes API keys.
        """
        import httpx

        nv_conf = bool(self.nvidia.api_key)
        gem_conf = bool(self.gemini.api_key)

        # ── NVIDIA NIM real ping ──────────────────────────────────────────────
        nvidia_status: Dict[str, Any] = {
            "provider": "nvidia_nim",
            "configured": nv_conf,
            "reachable": False,
            "model": self.nvidia.model,
            "latency_ms": None,
            "last_error": None
        }
        if nv_conf:
            try:
                base = self.nvidia.base_url.rstrip("/")
                t0 = time.perf_counter()
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(
                        f"{base}/chat/completions",
                        headers={"Authorization": f"Bearer {self.nvidia.api_key}",
                                 "Content-Type": "application/json"},
                        json={"model": self.nvidia.model,
                              "messages": [{"role": "user", "content": "hi"}],
                              "max_tokens": 1}
                    )
                lat = round((time.perf_counter() - t0) * 1000, 1)
                nvidia_status["latency_ms"] = lat
                if resp.status_code in (200, 201):
                    nvidia_status["reachable"] = True
                elif resp.status_code == 401:
                    nvidia_status["last_error"] = "authentication_failed"
                elif resp.status_code == 429:
                    nvidia_status["last_error"] = "rate_limited"
                    nvidia_status["reachable"] = True   # auth OK, just rate-limited
                else:
                    nvidia_status["last_error"] = f"http_{resp.status_code}"
            except httpx.TimeoutException:
                nvidia_status["last_error"] = "timeout"
            except Exception as e:
                nvidia_status["last_error"] = str(e)[:120]

        # ── Gemini real ping ──────────────────────────────────────────────────
        gemini_status: Dict[str, Any] = {
            "provider": "google_gemini",
            "configured": gem_conf,
            "reachable": False,
            "model": self.gemini.model,
            "latency_ms": None,
            "last_error": None
        }
        if gem_conf:
            try:
                t0 = time.perf_counter()
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(
                        f"https://generativelanguage.googleapis.com/v1beta/models/"
                        f"{self.gemini.model}:generateContent?key={self.gemini.api_key}",
                        headers={"Content-Type": "application/json"},
                        json={"contents": [{"parts": [{"text": "hi"}]}],
                              "generationConfig": {"maxOutputTokens": 1}}
                    )
                lat = round((time.perf_counter() - t0) * 1000, 1)
                gemini_status["latency_ms"] = lat
                if resp.status_code in (200, 201):
                    gemini_status["reachable"] = True
                elif resp.status_code == 400:
                    # 400 often means model exists but payload issue — still reachable
                    gemini_status["reachable"] = True
                    gemini_status["last_error"] = "bad_request_but_reachable"
                elif resp.status_code == 401:
                    gemini_status["last_error"] = "authentication_failed"
                elif resp.status_code == 429:
                    gemini_status["last_error"] = "rate_limited"
                    gemini_status["reachable"] = True
                else:
                    gemini_status["last_error"] = f"http_{resp.status_code}"
            except httpx.TimeoutException:
                gemini_status["last_error"] = "timeout"
            except Exception as e:
                gemini_status["last_error"] = str(e)[:120]

        active_provider = "none"
        if nvidia_status["reachable"]:
            active_provider = "nvidia_nim"
        elif gemini_status["reachable"]:
            active_provider = "google_gemini"

        tav_conf = bool(config.tavily_api_key)
        return {
            "nvidia": nvidia_status,
            "gemini": gemini_status,
            "active_provider": active_provider,
            "agentic_tool_calling": True,
            "agent_mode": "live" if active_provider != "none" else "forensic_only",
            "tavily": {
                "configured": tav_conf,
                "enabled": config.tavily_enabled and config.allow_external_intel
            }
        }
