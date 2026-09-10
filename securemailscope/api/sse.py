"""
SecureMailScope - Real Server-Sent Events (SSE) Event Bus
Dispatches live forensic and agent lifecycle events to connected clients.
"""
import asyncio
import json
from typing import Dict, List, Any, Optional
from sse_starlette.sse import ServerSentEvent


class SSEEventBus:
    """
    In-memory async pub-sub bus for real-time investigation events.
    """
    _subscribers: Dict[str, List[asyncio.Queue]] = {}

    @classmethod
    def subscribe(cls, investigation_id: str) -> asyncio.Queue:
        if investigation_id not in cls._subscribers:
            cls._subscribers[investigation_id] = []
        queue = asyncio.Queue()
        cls._subscribers[investigation_id].append(queue)
        return queue

    @classmethod
    def unsubscribe(cls, investigation_id: str, queue: asyncio.Queue):
        if investigation_id in cls._subscribers:
            if queue in cls._subscribers[investigation_id]:
                cls._subscribers[investigation_id].remove(queue)
            if not cls._subscribers[investigation_id]:
                del cls._subscribers[investigation_id]

    @classmethod
    async def publish(cls, investigation_id: str, event_type: str, data: Dict[str, Any]):
        if investigation_id not in cls._subscribers:
            return
        msg = ServerSentEvent(
            event=event_type,
            data=json.dumps(data)
        )
        for queue in list(cls._subscribers[investigation_id]):
            await queue.put(msg)

    @classmethod
    def publish_sync(cls, investigation_id: str, event_type: str, data: Dict[str, Any]):
        if investigation_id not in cls._subscribers:
            return
        msg = ServerSentEvent(
            event=event_type,
            data=json.dumps(data)
        )
        for queue in list(cls._subscribers[investigation_id]):
            try:
                queue.put_nowait(msg)
            except Exception:
                pass

