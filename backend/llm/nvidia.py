"""
SecureMailScope - NVIDIA NIM LLM Provider (moonshotai/kimi-k3)
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


class NvidiaProvider(LLMProvider):
    """
    Production NVIDIA NIM provider for moonshotai/kimi-k3.
    Communicates via standard OpenAI-compatible completions API with streaming,
    structured output, and multimodal support.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: int = 0
    ):
        self.api_key = api_key or config.nvidia_api_key
        self.model = model or config.nvidia_model or "moonshotai/kimi-k3"
        self.base_url = (base_url or config.nvidia_base_url or "https://integrate.api.nvidia.com/v1").rstrip("/")
        self.timeout = timeout if timeout is not None else float(config.nvidia_timeout_seconds)
        self.max_retries = max_retries

    async def health(self) -> HealthStatus:
        if not self.api_key:
            return HealthStatus(provider="nvidia", model=self.model, configured=False, healthy=False)
        try:
            t0 = time.perf_counter()
            url = f"{self.base_url}/models"
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(url, headers={"Authorization": f"Bearer {self.api_key}"})
                lat = (time.perf_counter() - t0) * 1000
                is_ok = res.status_code == 200
                return HealthStatus(provider="nvidia", model=self.model, configured=True, healthy=is_ok, latency_ms=lat)
        except Exception:
            return HealthStatus(provider="nvidia", model=self.model, configured=True, healthy=False)

    def _headers(self, stream: bool = False) -> Dict[str, str]:
        if not self.api_key:
            raise AuthenticationError("NVIDIA_API_KEY is not configured.")
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if stream else "application/json"
        }

    def _format_messages(self, messages) -> list:
        formatted = []
        for m in messages:
            content = m.content
            # Multimodal support
            if isinstance(content, list):
                c_list = []
                for p in content:
                    if hasattr(p, "type") and p.type == "text":
                        c_list.append({"type": "text", "text": p.text})
                    elif hasattr(p, "type") and p.type == "image_url":
                        c_list.append({"type": "image_url", "image_url": p.image_url})
                    elif isinstance(p, dict):
                        c_list.append(p)
                formatted.append({"role": m.role, "content": c_list})
            else:
                entry = {"role": m.role, "content": str(content)}
                if m.tool_call_id:
                    entry["tool_call_id"] = m.tool_call_id
                if m.tool_calls:
                    entry["tool_calls"] = m.tool_calls
                if m.name:
                    entry["name"] = m.name
                formatted.append(entry)
        return formatted

    def _build_payload(self, request: ChatRequest, stream: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": request.model or self.model,
            "messages": self._format_messages(request.messages),
            "max_tokens": min(request.max_tokens, 16384),
            "temperature": request.temperature,
            "stream": stream
        }
        if request.reasoning_parameters:
            for k, v in request.reasoning_parameters.items():
                payload[k] = v
        if request.tools:
            payload["tools"] = request.tools
        if request.tool_choice:
            payload["tool_choice"] = request.tool_choice
        if request.response_format:
            payload["response_format"] = request.response_format
        return payload

    async def chat(self, request: ChatRequest) -> ChatResponse:
        url = f"{self.base_url}/chat/completions"
        headers = self._headers(stream=False)
        payload = self._build_payload(request, stream=False)

        start_time = time.perf_counter()
        attempt = 0
        last_error = None

        while attempt <= self.max_retries:
            attempt += 1
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, headers=headers, json=payload)
                    latency = (time.perf_counter() - start_time) * 1000

                    if resp.status_code == 200:
                        data = resp.json()
                        choice = data["choices"][0]
                        msg = choice.get("message", {})
                        usage_data = data.get("usage", {})

                        return ChatResponse(
                            content=msg.get("content") or "",
                            role=msg.get("role", "assistant"),
                            finish_reason=choice.get("finish_reason", "stop"),
                            model=data.get("model", self.model),
                            provider="nvidia",
                            latency_ms=latency,
                            usage=TokenUsage(
                                prompt_tokens=usage_data.get("prompt_tokens", 0),
                                completion_tokens=usage_data.get("completion_tokens", 0),
                                total_tokens=usage_data.get("total_tokens", 0)
                            ),
                            tool_calls=msg.get("tool_calls"),
                            request_id=data.get("id")
                        )

                    elif resp.status_code in (401, 403):
                        raise AuthenticationError(f"NVIDIA API auth failed ({resp.status_code}): {resp.text}")
                    elif resp.status_code == 429:
                        if attempt <= self.max_retries:
                            await asyncio.sleep(1.5 * attempt)
                            continue
                        raise RateLimitError(f"NVIDIA API rate limit exceeded: {resp.text}")
                    elif resp.status_code >= 500:
                        if attempt <= self.max_retries:
                            await asyncio.sleep(1.0 * attempt)
                            continue
                        raise ProviderUnavailableError(f"NVIDIA NIM server error ({resp.status_code}): {resp.text}")
                    else:
                        raise ProviderError(f"NVIDIA API error ({resp.status_code}): {resp.text}")

            except httpx.TimeoutException as te:
                last_error = TimeoutError(f"NVIDIA API request timed out after {self.timeout}s: {te}")
                if attempt <= self.max_retries:
                    await asyncio.sleep(1.0)
                    continue
            except (AuthenticationError, RateLimitError, ProviderUnavailableError, ProviderError):
                raise
            except Exception as e:
                last_error = ProviderError(f"Unexpected error communicating with NVIDIA NIM: {e}")
                if attempt <= self.max_retries:
                    await asyncio.sleep(1.0)
                    continue

        if last_error:
            raise last_error
        raise ProviderError("NVIDIA request failed after retries.")

    async def stream(self, request: ChatRequest) -> AsyncIterator[StreamChunk]:
        url = f"{self.base_url}/chat/completions"
        headers = self._headers(stream=True)
        payload = self._build_payload(request, stream=True)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", url, headers=headers, json=payload) as resp:
                    if resp.status_code in (401, 403):
                        raise AuthenticationError(f"NVIDIA API auth failed: {resp.status_code}")
                    if resp.status_code == 429:
                        raise RateLimitError("NVIDIA API rate limit exceeded")
                    if resp.status_code >= 500:
                        raise ProviderUnavailableError(f"NVIDIA server error: {resp.status_code}")
                    if resp.status_code != 200:
                        raise ProviderError(f"NVIDIA stream failed ({resp.status_code})")

                    async for line in resp.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            choice = chunk["choices"][0]
                            delta = choice.get("delta", {}).get("content") or ""
                            yield StreamChunk(
                                delta=delta,
                                finish_reason=choice.get("finish_reason"),
                                model=chunk.get("model", self.model),
                                provider="nvidia",
                                tool_calls=choice.get("delta", {}).get("tool_calls")
                            )
                        except Exception:
                            continue
        except httpx.TimeoutException:
            raise TimeoutError("NVIDIA stream timed out.")

    async def structured(self, request: ChatRequest, schema: Dict[str, Any]) -> Dict[str, Any]:
        req = request.model_copy(deep=True)
        # Instruct model to respond with strict JSON adhering to schema
        schema_instruction = f"\nYou MUST output valid JSON conforming strictly to this schema:\n```json\n{json.dumps(schema, indent=2)}\n```\nDo not include commentary outside the JSON block."
        last_msg = req.messages[-1]
        if isinstance(last_msg.content, str):
            last_msg.content += schema_instruction
        req.response_format = {"type": "json_object"}
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
                provider="nvidia",
                model=self.model,
                configured=False,
                healthy=False,
                error="NVIDIA_API_KEY not set"
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
                provider="nvidia",
                model=self.model,
                configured=True,
                healthy=True,
                latency_ms=res.latency_ms
            )
        except Exception as e:
            return HealthStatus(
                provider="nvidia",
                model=self.model,
                configured=True,
                healthy=False,
                latency_ms=(time.perf_counter() - start) * 1000,
                error=str(e)
            )
