"""
SecureMailScope - Base LLM Provider Abstraction
"""
from abc import ABC, abstractmethod
from typing import AsyncIterator, Dict, Any
from backend.llm.schemas import ChatRequest, ChatResponse, StreamChunk, HealthStatus


class LLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    All providers must implement chat, stream, structured, and health_check.
    """

    @abstractmethod
    async def chat(self, request: ChatRequest) -> ChatResponse:
        """Execute a standard non-streaming chat completion."""
        pass

    @abstractmethod
    async def stream(self, request: ChatRequest) -> AsyncIterator[StreamChunk]:
        """Execute a streaming chat completion yielding StreamChunks."""
        pass

    @abstractmethod
    async def structured(self, request: ChatRequest, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Execute structured completion returning parsed JSON conforming to schema."""
        pass

    @abstractmethod
    async def health_check(self) -> HealthStatus:
        """Perform a lightweight health check on the provider endpoint and key."""
        pass
