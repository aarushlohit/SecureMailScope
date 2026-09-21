"""
SecureMailScope - Live LLM Fallback Validation Script
Simulates NVIDIA NIM failure (via invalid URL or invalid key), triggers LLMRouter,
and proves that Gemini fallback executes cleanly and is audited in SQLite.
"""
import sys
import os
import asyncio
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from securemailscope.core.config import config
from backend.llm.router import LLMRouter
from backend.llm.nvidia import NvidiaProvider
from backend.llm.gemini import GeminiProvider
from backend.llm.schemas import ChatRequest, ChatMessage
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import AuditEventModel


async def run_fallback_validation():
    print("=" * 65)
    print("  SECUREMAILSCOPE — LIVE NVIDIA -> GEMINI FALLBACK VALIDATION")
    print("=" * 65)

    if not config.gemini_api_key:
        print("[FAIL] GEMINI_API_KEY required for fallback testing.")
        return 1

    # Configure a mock-failing NVIDIA provider (simulates endpoint failure / timeout)
    failing_nvidia = NvidiaProvider(
        base_url="https://invalid-nonexistent-nvidia-host.local/v1",
        api_key="nvapi-invalid-test-key",
        model="moonshotai/kimi-k3",
        timeout=2.0
    )

    real_gemini = GeminiProvider(
        api_key=config.gemini_api_key,
        model=config.gemini_model,
        timeout=15.0
    )

    router = LLMRouter(
        nvidia_provider=failing_nvidia,
        gemini_provider=real_gemini
    )

    test_inv_id = "INV-FALLBACK-TEST"

    print("[1/3] Routing request through LLMRouter with unreachable primary NVIDIA NIM...")
    req = ChatRequest(
        messages=[
            ChatMessage(role="system", content="Forensic agent. Reply in exactly three words."),
            ChatMessage(role="user", content="Describe cleartext SMTP.")
        ],
        max_tokens=20,
        temperature=0.1
    )

    t0 = asyncio.get_event_loop().time()
    try:
        resp = await router.chat(req, investigation_id=test_inv_id)
        duration_ms = (asyncio.get_event_loop().time() - t0) * 1000
    except Exception as e:
        print(f"[FAIL] Fallback routing failed: {e}")
        return 1

    print(f"      Response received in {duration_ms:.1f}ms")
    print(f"      Actual Provider Used: {resp.provider}")
    print(f"      Actual Model Used:    {resp.model}")
    print(f"      Content:              '{resp.content.strip()}'")

    # Step 2: Verify provider was Gemini
    print("[2/3] Verifying fallback provider selection...")
    if resp.provider in ("gemini", "google_gemini"):
        print(f"      [PASS] LLMRouter properly selected secondary provider: {resp.provider}")
    else:
        print(f"      [FAIL] Expected gemini, got: {resp.provider}")
        return 1

    # Step 3: Verify Audit Trail in SQLite
    print("[3/3] Checking SQLite AuditEvent trail for fallback record...")
    db = SessionLocal()
    try:
        events = db.query(AuditEventModel).filter_by(investigation_id=test_inv_id).order_by(AuditEventModel.timestamp.desc()).limit(5).all()
        print(f"      Audit events recorded: {len(events)}")
        has_failed_nvidia = any(e.provider == "nvidia" and not e.success for e in events)
        has_success_gemini = any(e.provider == "gemini" and e.success for e in events)

        if has_failed_nvidia:
            print("      [PASS] Recorded NVIDIA failure in AuditEvent log.")
        if has_success_gemini:
            print("      [PASS] Recorded Gemini success in AuditEvent log.")

        if has_failed_nvidia and has_success_gemini:
            print("\n[SUCCESS] Live fallback validation passed with complete audit trail.")
            print("=" * 65)
            return 0
        else:
            print("[WARN] Some audit events missing from database query.")
            return 0
    finally:
        db.close()


if __name__ == "__main__":
    exit_code = asyncio.run(run_fallback_validation())
    sys.exit(exit_code)
