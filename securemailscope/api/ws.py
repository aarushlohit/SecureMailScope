"""
SecureMailScope - WebSocket Real-Time Broadcast Manager
"""
import json
from typing import Dict, List
from fastapi import WebSocket


class ConnectionManager:
    """
    Manages active WebSocket connections to stream real-time forensic events
    (investigation.started, rule.triggered, hypothesis.updated, etc.) to the UI.
    """

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, investigation_id: str):
        await websocket.accept()
        if investigation_id not in self.active_connections:
            self.active_connections[investigation_id] = []
        self.active_connections[investigation_id].append(websocket)

    def disconnect(self, websocket: WebSocket, investigation_id: str):
        if investigation_id in self.active_connections:
            if websocket in self.active_connections[investigation_id]:
                self.active_connections[investigation_id].remove(websocket)

    async def broadcast(self, investigation_id: str, message: dict):
        if investigation_id in self.active_connections:
            data = json.dumps(message)
            for connection in self.active_connections[investigation_id]:
                try:
                    await connection.send_text(data)
                except Exception:
                    pass


ws_manager = ConnectionManager()
