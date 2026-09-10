"""
SecureMailScope - Google Gemini Fallback LLM Provider
"""
import json
import time
import asyncio
from typing import AsyncIterator, Dict, Any, Optional
import httpx
from backend.llm.base import LLMProvider
from backend.llm.schemas import ChatRequest, ChatResponse, StreamChunk, HealthStatus, TokenUsage
from backend.llm.exceptions import (
    AuthenticationError,
    RateLimitError,
    TimeoutError,
    ProviderUnavailableError,
    ProviderError
)
from securemailscope.core.config import config


class GeminiProvider(LLMProvider):
    """
    Fallback LLM provider using Google Gemini REST API.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 45.0
    ):
        self.api_key = api_key or config.gemini_api_key
        self.model = model or config.gemini_model or "gemini-1.5-flash"
        self.timeout = timeout

    def _convert_messages(self, messages):
        contents = []
        system_instruction = None
        for m in messages:
            if m.role == "system":
                system_instruction = {"parts": [{"text": str(m.content)}]}
                continue
            role = "user" if m.role in ("user", "tool") else "model"
            text_val = m.content if isinstance(m.content, str) else json.dumps(m.content)
            contents.append({
                "role": role,
                "parts": [{"text": text_val}]
            })
        return contents, system_instruction

    async def chat(self, request: ChatRequest) -> ChatResponse:
        if not self.api_key:
            raise AuthenticationError("GEMINI_API_KEY is not configured.")

        model = request.model or self.model
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        contents, system_instruction = self._convert_messages(request.messages)

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": request.temperature,
                "maxOutputTokens": request.max_tokens
            }
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload)
                latency = (time.perf_counter() - start_time) * 1000

                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    text = ""
                    finish_reason = "stop"
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        text = "".join(p.get("text", "") for p in parts)
                        finish_reason = candidates[0].get("finishReason", "stop")

                    usage_meta = data.get("usageMetadata", {})
                    return ChatResponse(
                        content=text,
                        role="assistant",
                        finish_reason=finish_reason,
                        model=model,
                        provider="gemini",
                        latency_ms=latency,
                        usage=TokenUsage(
                            prompt_tokens=usage_meta.get("promptTokenCount", 0),
                            completion_tokens=usage_meta.get("candidatesTokenCount", 0),
                            total_tokens=usage_meta.get("totalTokenCount", 0)
                        )
                    )
                elif resp.status_code in (401, 403):
                    raise AuthenticationError(f"Gemini authentication failed ({resp.status_code}): {resp.text}")
                elif resp.status_code == 429:
                    raise RateLimitError(f"Gemini rate limit exceeded: {resp.text}")
                elif resp.status_code >= 500:
                    raise ProviderUnavailableError(f"Gemini server error ({resp.status_code}): {resp.text}")
                else:
                    raise ProviderError(f"Gemini API error ({resp.status_code}): {resp.text}")

        except httpx.TimeoutException:
            raise TimeoutError(f"Gemini request timed out after {self.timeout}s")
        except (AuthenticationError, RateLimitError, ProviderUnavailableError, ProviderError):
            raise
        except Exception as e:
            raise ProviderError(f"Unexpected error communicating with Gemini: {e}")

    async def stream(self, request: ChatRequest) -> AsyncIterator[StreamChunk]:
        if not self.api_key:
            raise AuthenticationError("GEMINI_API_KEY is not configured.")

        model = request.model or self.model
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent?alt=sse&key={self.api_key}"
        contents, system_instruction = self._convert_messages(request.messages)

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": request.temperature,
                "maxOutputTokens": request.max_tokens
            }
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", url, json=payload) as resp:
                    if resp.status_code != 200:
                        raise ProviderError(f"Gemini stream returned HTTP {resp.status_code}")

                    async for line in resp.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        data_str = line[6:].strip()
                        try:
                            chunk = json.loads(data_str)
                            candidates = chunk.get("candidates", [])
                            if candidates:
                                parts = candidates[0].get("content", {}).get("parts", [])
                                text = "".join(p.get("text", "") for p in parts)
                                yield StreamChunk(
                                    delta=text,
                                    finish_reason=candidates[0].get("finishReason"),
                                    model=model,
                                    provider="gemini"
                                )
                        except Exception:
                            continue
        except httpx.TimeoutException:
            raise TimeoutError("Gemini stream timed out")

    async def structured(self, request: ChatRequest, schema: Dict[str, Any]) -> Dict[str, Any]:
        req = request.model_copy(deep=True)
        schema_instruction = f"\nOutput ONLY valid JSON strictly matching schema:\n{json.dumps(schema, indent=2)}"
        last_msg = req.messages[-1]
        if isinstance(last_msg.content, str):
            last_msg.content += schema_instruction
        res = await self.chat(req)
        content = res.content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.endswith("```"):
            content = content[:-3]
        return json.loads(content.strip())

    async def health_check(self) -> HealthStatus:
        if not self.api_key:
            return HealthStatus(
                provider="gemini",
                model=self.model,
                configured=False,
                healthy=False,
                error="GEMINI_API_KEY not set"
            )
        start = time.perf_counter()
        try:
            req = ChatRequest(
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
                temperature=0.0
            )
            res = await self.chat(req)
            return HealthStatus(
                provider="gemini",
                model=self.model,
                configured=True,
                healthy=True,
                latency_ms=res.latency_ms
            )
        except Exception as e:
            return HealthStatus(
                provider="gemini",
                model=self.model,
                configured=True,
                healthy=False,
                latency_ms=(time.perf_counter() - start) * 1000,
                error=str(e)
            )
