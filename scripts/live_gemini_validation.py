"""
SecureMailScope - Live Google Gemini Validation Script
Strictly validates Google Gemini API integration, model response, and structured tool calling.
"""
import sys
import os
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, Tuple
import httpx

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from securemailscope.core.config import config
from backend.llm.gemini import GeminiProvider
from backend.llm.schemas import ChatRequest, ChatMessage
from securemailscope.forensics.capture import CaptureEngine


SAMPLE_PATH = ROOT_DIR / "samples" / "wireshark_real_smtp.pcap"
FUNCTION_DECLARATION = {
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
        "required": ["file_path"]
    }
}


def _extract_function_call(data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    candidates = data.get("candidates") or []
    if not candidates:
        raise ValueError("Gemini response contained no candidates.")
    for part in candidates[0].get("content", {}).get("parts", []):
        if "functionCall" in part:
            fc = part["functionCall"]
            args = fc.get("args") or {}
            if not isinstance(args, dict):
                raise ValueError("Function-call args are not an object.")
            return fc.get("name"), args
    raise ValueError("Gemini response did not include a functionCall part.")


def _execute_allowed_function(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name != "check_completeness":
        raise ValueError(f"Function '{name}' is not allowed for live validation.")
    requested = args.get("file_path")
    allowed_values = {str(SAMPLE_PATH), str(SAMPLE_PATH.relative_to(ROOT_DIR))}
    if requested not in allowed_values:
        raise ValueError("Function argument file_path is not the approved local sample.")
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


async def run_gemini_validation():
    print("=" * 65)
    print("     SECUREMAILSCOPE — LIVE GOOGLE GEMINI VALIDATION")
    print("=" * 65)

    api_key = config.gemini_api_key
    if not api_key:
        print("[FAIL] GEMINI_API_KEY is not set in environment or .env.")
        return 1

    # Credential presence is enough for diagnostics; never disclose a key or
    # identifying prefix/suffix in validation output.
    print("API Key:       configured")
    print(f"Model:         {config.gemini_model}")
    print("-" * 65)

    provider = GeminiProvider()

    # Step 1: Health check
    print("[1/3] Testing Gemini API health...")
    try:
        health = await provider.health()
        print(f"      Connectivity: OK (healthy={health.healthy}, latency={health.latency_ms:.1f}ms)")
    except Exception as e:
        print(f"[FAIL] Health check failed: {e}")
        return 1

    # Step 2: Real Chat Completion
    print("[2/3] Sending minimal test completion...")
    req_simple = ChatRequest(
        messages=[
            ChatMessage(role="system", content="You are a forensic email security agent. Answer in one sentence."),
            ChatMessage(role="user", content="What is STARTTLS stripping?")
        ],
        max_tokens=40,
        temperature=0.1
    )

    try:
        resp_simple = await provider.chat(req_simple)
        print(f"      Response received in {resp_simple.latency_ms:.1f}ms from {resp_simple.model}")
        print(f"      Snippet: {resp_simple.content.strip()[:100]}...")
    except Exception as e:
        print(f"[FAIL] Chat request failed: {e}")
        return 1

    # Step 3: Native Gemini function-call round trip
    print("[3/3] Testing native Gemini function-call round trip...")
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.gemini_model}:generateContent?key={api_key}"
        initial_payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                "Call check_completeness for samples/wireshark_real_smtp.pcap. "
                                "Do not answer before calling the function."
                            )
                        }
                    ],
                }
            ],
            "tools": [{"functionDeclarations": [FUNCTION_DECLARATION]}],
            "toolConfig": {
                "functionCallingConfig": {
                    "mode": "ANY",
                    "allowedFunctionNames": ["check_completeness"],
                }
            },
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 256},
        }

        print("      Initial provider request: PENDING")
        async with httpx.AsyncClient(timeout=config.gemini_timeout_seconds) as client:
            initial_resp = await client.post(url, json=initial_payload)
            if initial_resp.status_code != 200:
                print(f"      Initial provider request: FAILURE ({initial_resp.status_code})")
                return 1
            initial_data = initial_resp.json()
        print("      Initial provider request: SUCCESS")

        name, args = _extract_function_call(initial_data)
        print("      Function call received: SUCCESS")
        print(f"      Function validation: PENDING ({name})")
        function_result = _execute_allowed_function(name, args)
        print("      Function validation: SUCCESS")
        print("      Local function execution: SUCCESS")
        print(
            "      Function result summary: "
            f"packets={function_result['packet_count']} "
            f"complete={function_result['completeness']['percentage']}% "
            f"sha256={function_result['sha256'][:16]}..."
        )

        model_content = initial_data["candidates"][0]["content"]
        final_payload = {
            "contents": [
                initial_payload["contents"][0],
                model_content,
                {
                    "role": "user",
                    "parts": [
                        {
                            "functionResponse": {
                                "name": name,
                                "response": function_result,
                            }
                        },
                        {
                            "text": "Based on this tool result, provide the final forensic summary mentioning packet count and completeness percentage."
                        }
                    ],
                },
            ],
            "tools": [{"functionDeclarations": [FUNCTION_DECLARATION]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 256},
        }

        print("      Function response submission: PENDING")
        async with httpx.AsyncClient(timeout=config.gemini_timeout_seconds) as client:
            final_resp = await client.post(url, json=final_payload)
            if final_resp.status_code != 200:
                print(f"      Function response submission: FAILURE ({final_resp.status_code})")
                return 1
            final_data = final_resp.json()
        print("      Function response submission: SUCCESS")

        final_text = ""
        for part in final_data.get("candidates", [{}])[0].get("content", {}).get("parts", []):
            final_text += part.get("text", "")
        if len(final_text.strip()) < 10:
            print("      Final model response: FAILURE")
            return 1
        print("      Final model response: SUCCESS")
        print(f"      Final snippet: {final_text.strip()[:180]}")
        print("\n[PASS] Google Gemini complete function-call round trip succeeded.")
        print("      Overall round trip: PASS")
        print("=" * 65)
        return 0
    except Exception as e:
        print(f"[FAIL] Function-call round trip failed: {e}")
        print("      Overall round trip: FAIL")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_gemini_validation())
    sys.exit(exit_code)
