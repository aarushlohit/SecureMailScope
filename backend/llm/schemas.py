"""
SecureMailScope - LLM Provider Schemas
"""
from typing import List, Dict, Any, Optional, Union, Literal
from pydantic import BaseModel, Field


class ContentPart(BaseModel):
    type: Literal["text", "image_url"]
    text: Optional[str] = None
    image_url: Optional[Dict[str, str]] = None  # e.g. {"url": "https://..." or "data:image/png;base64,..."}


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: Union[str, List[ContentPart], List[Dict[str, Any]]]
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    stream: bool = False
    reasoning_parameters: Optional[Dict[str, Any]] = None
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    response_format: Optional[Dict[str, Any]] = None


class ChatResponse(BaseModel):
    content: str
    role: str = "assistant"
    finish_reason: Optional[str] = "stop"
    model: str
    provider: str
    latency_ms: float = 0.0
    usage: Optional[TokenUsage] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    request_id: Optional[str] = None


class StreamChunk(BaseModel):
    delta: str
    finish_reason: Optional[str] = None
    model: str
    provider: str
    tool_calls: Optional[List[Dict[str, Any]]] = None


class HealthStatus(BaseModel):
    provider: str
    model: str
    configured: bool
    healthy: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None
