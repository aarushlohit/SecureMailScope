"""
SecureMailScope - Live NVIDIA NIM Validation Script
Strictly validates NVIDIA NIM API integration, model response, and structured tool calling.
Fails explicitly if NVIDIA NIM times out or is unreachable (NO silent Gemini fallback).
"""
import sys
import os
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, Tuple

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from securemailscope.core.config import config
from backend.llm.nvidia import NvidiaProvider
from backend.llm.schemas import ChatRequest, ChatMessage
from securemailscope.forensics.capture import CaptureEngine


SAMPLE_PATH = ROOT_DIR / "samples" / "wireshark_real_smtp.pcap"
TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "check_completeness",
        "description": "Calculates capture completeness score, sequence gaps, retransmissions, and truncation for the approved sample capture.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Must be the approved sample path samples/wireshark_real_smtp.pcap"
                }
            },
            "required": ["file_path"],
            "additionalProperties": False
        }
    }
}


def _parse_tool_call(tool_call: Dict[str, Any]) -> Tuple[str, Dict[str, Any], str]:
    fn = tool_call.get("function") or {}
    name = fn.get("name")
    raw_args = fn.get("arguments") or "{}"
    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
    if not isinstance(args, dict):
        raise ValueError("Tool arguments are not a JSON object.")
    call_id = tool_call.get("id") or "call_securemailscope_live_validation"
    return name, args, call_id


def _execute_allowed_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name != "check_completeness":
        raise ValueError(f"Tool '{name}' is not allowed for live validation.")

    if isinstance(args.get("parameters"), dict):
        args = args["parameters"]
    requested = args.get("file_path")
    allowed_values = {str(SAMPLE_PATH), str(SAMPLE_PATH.relative_to(ROOT_DIR))}
    if requested not in allowed_values:
        raise ValueError("Tool argument file_path is not the approved local sample.")
    if not SAMPLE_PATH.exists():
        raise FileNotFoundError("Approved sample PCAP is missing.")

    meta = CaptureEngine.inspect_capture(SAMPLE_PATH)
    completeness = meta.get("completeness", {})
    return {
        "tool": name,
        "sample": SAMPLE_PATH.name,
        "sha256": meta.get("artifact_sha256"),
        "size_bytes": meta.get("artifact_size"),
        "packet_count": meta.get("packet_count"),
        "duration_seconds": meta.get("duration_seconds"),
        "completeness": {
            "percentage": completeness.get("completeness_percentage"),
            "assessment": completeness.get("assessment"),
            "sequence_gaps": completeness.get("sequence_gaps"),
            "retransmissions": completeness.get("retransmissions"),
            "truncated_packets": completeness.get("truncated_packets"),
            "is_complete": completeness.get("is_complete"),
        },
    }


async def run_nvidia_validation():
    print("=" * 65)
    print("     SECUREMAILSCOPE — LIVE NVIDIA NIM VALIDATION")
    print("=" * 65)

    api_key = config.nvidia_api_key
    if not api_key:
        print("[FAIL] NVIDIA_API_KEY or NVIDIA_NIM_API_KEY is not set in environment or .env.")
        return 1

    # Credential presence is enough for diagnostics; never disclose a key or
    # identifying prefix/suffix in validation output.
    print("API Key:       configured")
    print(f"Base URL:      {config.nvidia_base_url}")
    print(f"Model:         {config.nvidia_model}")
    print("-" * 65)

    provider = NvidiaProvider(timeout=config.nvidia_timeout_seconds)

    # Step 1: Real Health Check (Ping / Catalog)
    print("[1/3] Testing NVIDIA NIM endpoint connectivity...")
    try:
        health = await provider.health()
        print(f"      Connectivity: OK (healthy={health.healthy}, latency={health.latency_ms:.1f}ms)")
    except Exception as e:
        print(f"[FAIL] Health check failed: {e}")
        return 1

    # Step 2: Real Chat Completion without tools
    print("[2/3] Sending minimal test completion (max_tokens=15)...")
    req_simple = ChatRequest(
        messages=[
            ChatMessage(role="system", content="You are a forensic network analysis agent. Reply concisely."),
            ChatMessage(role="user", content="State the primary risk of plaintext SMTP over port 25.")
        ],
        max_tokens=30,
        temperature=0.1
    )

    try:
        resp_simple = await provider.chat(req_simple)
        print(f"      Response received in {resp_simple.latency_ms:.1f}ms from {resp_simple.model}")
        print(f"      Snippet: {resp_simple.content.strip()[:100]}...")
    except Exception as e:
        print(f"[FAIL] Inference request failed or timed out: {e}")
        print("      (NVIDIA NIM inference timed out. No fake response or fallback permitted.)")
        return 1

    # Step 3: Real Structured Function/Tool Calling Round Trip
    print("[3/3] Testing structured tool-call round trip...")
    req_tools = ChatRequest(
        messages=[
            ChatMessage(
                role="system",
                content=(
                    "You are SecureMailScope's Forensic Agent. "
                    "Call check_completeness exactly once for the approved sample. "
                    "Do not answer from memory before the tool result is provided."
                )
            ),
            ChatMessage(
                role="user",
                content="Please check capture completeness for samples/wireshark_real_smtp.pcap."
            )
        ],
        tools=[TOOL_SCHEMA],
        tool_choice={"type": "function", "function": {"name": "check_completeness"}},
        max_tokens=256,
        temperature=0.1
    )

    try:
        print("      Initial provider request: PENDING")
        resp_tools = await provider.chat(req_tools)
        print("      Initial provider request: SUCCESS")
        tool_calls = resp_tools.tool_calls or []
        if not tool_calls:
            print("      Tool call received: FAILURE")
            print("[FAIL] Model did not return a tool call.")
            return 1
        print("      Tool call received: SUCCESS")

        name, args, call_id = _parse_tool_call(tool_calls[0])
        print(f"      Tool validation: PENDING ({name})")
        tool_result = _execute_allowed_tool(name, args)
        print("      Tool validation: SUCCESS")
        print("      Local tool execution: SUCCESS")
        print(
            "      Tool result summary: "
            f"packets={tool_result['packet_count']} "
            f"complete={tool_result['completeness']['percentage']}% "
            f"sha256={tool_result['sha256'][:16]}..."
        )

        final_req = ChatRequest(
            messages=[
                *req_tools.messages,
                ChatMessage(role="assistant", content=resp_tools.content or "", tool_calls=tool_calls),
                ChatMessage(
                    role="tool",
                    name=name,
                    tool_call_id=call_id,
                    content=json.dumps(tool_result, separators=(",", ":"))[:4000],
                ),
                ChatMessage(
                    role="user",
                    content=(
                        "Use the tool result above to provide the final validation summary. "
                        "Mention the packet count and completeness percentage. Do not call another tool."
                    ),
                ),
            ],
            tools=[TOOL_SCHEMA],
            tool_choice="none",
            max_tokens=256,
            temperature=0.1,
        )
        print("      Tool result submission: PENDING")
        final_resp = await provider.chat(final_req)
        print("      Tool result submission: SUCCESS")
        final_text = final_resp.content.strip()
        if not final_text or len(final_text) < 10 or "60" not in final_text or "80" not in final_text:
            print("      Final model response: FAILURE")
            return 1
        print("      Final model response: SUCCESS")
        print(f"      Final snippet: {final_text[:180]}")
        print("\n[PASS] NVIDIA NIM complete tool-call round trip succeeded.")
        print("      Overall round trip: PASS")
        print("=" * 65)
        return 0
    except Exception as e:
        print(f"[FAIL] Tool-call round trip failed: {e}")
        print("      Overall round trip: FAIL")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_nvidia_validation())
    sys.exit(exit_code)
