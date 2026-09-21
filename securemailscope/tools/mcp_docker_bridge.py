"""
SecureMailScope - Docker MCP Stdio Bridge
Integrates Docker-backed Security MCP servers (such as bugbounty-mcp:2.2.0) via stdio JSON-RPC.
Provides tool invocation for domain verification, parameter analysis, secret pattern detection,
header security checks, and sub-domain security analysis.
"""
import json
import subprocess
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("securemailscope.tools.mcp_bridge")

DOCKER_IMAGE = "bugbounty-mcp:2.2.0"


class DockerMCPBridge:
    def __init__(self, image: str = DOCKER_IMAGE):
        self.image = image
        self._available_tools: Optional[List[Dict[str, Any]]] = None

    def _run_jsonrpc(self, method: str, params: Dict[str, Any], req_id: int = 1) -> Dict[str, Any]:
        """
        Executes a single JSON-RPC call against the Docker MCP container via stdio.
        """
        try:
            proc = subprocess.Popen(
                ["docker", "run", "--rm", "-i", self.image, "serve"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # 1. Initialize
            init_req = {
                "jsonrpc": "2.0",
                "id": 100,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "SecureMailScope", "version": "1.0.0"}
                }
            }
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()
            _ = proc.stdout.readline()

            # 2. Main Method
            req = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params
            }
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()

            raw_resp = proc.stdout.readline()
            proc.kill()

            if not raw_resp:
                return {"error": "Empty response from Docker MCP"}

            return json.loads(raw_resp)
        except Exception as e:
            logger.error(f"Docker MCP RPC failed: {e}")
            return {"error": str(e)}

    def list_tools(self) -> List[Dict[str, Any]]:
        if self._available_tools is not None:
            return self._available_tools

        res = self._run_jsonrpc("tools/list", {})
        if "result" in res and "tools" in res["result"]:
            self._available_tools = res["result"]["tools"]
            return self._available_tools
        return []

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        res = self._run_jsonrpc("tools/call", {"name": tool_name, "arguments": arguments})
        if "result" in res:
            return res["result"]
        elif "error" in res:
            return {"error": res["error"]}
        return {"status": "unknown", "raw": res}


_bridge_instance = DockerMCPBridge()


def call_docker_mcp(tool_name: str, **kwargs) -> Dict[str, Any]:
    return _bridge_instance.call_tool(tool_name, kwargs)


def list_docker_mcp_tools() -> List[Dict[str, Any]]:
    return _bridge_instance.list_tools()
