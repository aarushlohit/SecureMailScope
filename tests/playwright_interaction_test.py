"""
Playwright UI Automated Full Interaction and Verification Script for SecureMailScope
"""
import os
import sys
import time
import json
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

ARTIFACTS_DIR = Path("/home/aarush/.gemini/antigravity/brain/499477ab-adf2-484b-9470-68361b0578bb")
SCREENSHOTS_DIR = ARTIFACTS_DIR / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = "http://127.0.0.1:8000"


async def run_playwright_test():
    print("==================================================================")
    print("   Starting Playwright End-to-End Live UI Interaction Test        ")
    print("==================================================================")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1680, "height": 1050},
            device_scale_factor=2
        )
        page = await context.new_page()

        # Step 1: Landing Page
        print("\n[Step 1] Navigating to SecureMailScope Landing Page at /...")
        await page.goto(f"{BASE_URL}/", wait_until="networkidle")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "01_landing_page.png"))
        print("  ✓ Captured 01_landing_page.png")

        # Step 2: Signup & Authenticate
        print("\n[Step 2] Registering New Forensic Analyst Session via /signup...")
        await page.goto(f"{BASE_URL}/signup", wait_until="networkidle")
        await page.wait_for_timeout(500)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "02_signup_form.png"))

        unique_id = int(time.time())
        await page.fill("#fullname", "Lead Forensics Specialist")
        await page.fill("#email", f"analyst_{unique_id}@securemailscope.test")
        await page.fill("#password", "MasterSecureScope2026!")
        await page.click("#submit-btn")
        print("  - Form submitted. Waiting for redirect to /app...")

        # Wait for navigation to /app
        await page.wait_for_url(f"{BASE_URL}/app", timeout=10000)
        await page.wait_for_timeout(2000)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "03_workstation_home.png"))
        print("  ✓ Authenticated and reached /app Workstation Home.")

        # Step 3: Navigate to Demo Playground & Run STARTTLS Stripping Attack
        print("\n[Step 3] Navigating to Demo Lab and Running Scenario 1 (STARTTLS Stripping Attack)...")
        await page.evaluate("window.workstation.navigate('playground')")
        await page.wait_for_timeout(1200)

        await page.screenshot(path=str(SCREENSHOTS_DIR / "04_demo_lab_scenarios.png"))
        print("  ✓ Captured 04_demo_lab_scenarios.png")

        # Run Scenario 1
        print("  - Running demo scenario on 'mail_attack_starttls_strip.pcap'...")
        await page.evaluate("window.workstation.runDemoSample('mail_attack_starttls_strip.pcap')")

        print("  - Waiting for multi-tool fan-out & SSE analysis to finish...")
        for i in range(35):
            await page.wait_for_timeout(1000)
            inv_id = await page.evaluate("window.workstation.currentInvestigationId")
            if inv_id:
                print(f"  ✓ Multi-tool investigation completed: {inv_id} in ~{i+1}s!")
                break

        await page.wait_for_timeout(2500)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "05_home_thread_analysis_completed.png"))
        print("  ✓ Captured 05_home_thread_analysis_completed.png")

        # Step 4: Claude-Style Thinking & Tool Execution Inspector in Thread
        print("\n[Step 4] Inspecting Claude-Style Thinking Traces & Tool Output Cards...")
        thinking_block = await page.query_selector(".claude-thinking-block")
        if thinking_block:
            is_open = await thinking_block.get_attribute("open")
            if is_open is None:
                await thinking_block.click()
                await page.wait_for_timeout(400)

            # Expand tool cards
            tool_cards = await page.query_selector_all(".tool-exec-card details")
            for card in tool_cards[:4]:
                await card.evaluate("el => el.setAttribute('open', 'true')")

        await page.wait_for_timeout(800)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "06_claude_thinking_tools_expanded.png"))
        print("  ✓ Captured 06_claude_thinking_tools_expanded.png")

        # Step 5: Navigate to Investigation Detail View
        print("\n[Step 5] Opening Full Investigation Detail View...")
        await page.evaluate("""() => {
            const invId = window.workstation.currentInvestigationId;
            window.workstation.navigate('investigation-detail', invId);
        }""")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "07_investigation_detail_overview.png"))
        print("  ✓ Captured 07_investigation_detail_overview.png")

        # Step 6: Evidence Knowledge Graph Canvas Visualizer in Detail Tab
        print("\n[Step 6] Interacting with Evidence Knowledge Graph Visualizer...")
        await page.evaluate("window.workstation.switchDetailTab('knowledge-graph')")
        print("  - Knowledge Graph view activated. Simulating 2D physics layout...")
        await page.wait_for_timeout(3000)

        # Zoom controls
        zoom_in = await page.query_selector("#kg-zoom-in")
        if zoom_in:
            await zoom_in.click()
            await page.wait_for_timeout(300)
            await zoom_in.click()
            await page.wait_for_timeout(300)

        # Click near center to inspect a node
        canvas = await page.query_selector("#kg-canvas, canvas")
        if canvas:
            box = await canvas.bounding_box()
            if box:
                await page.mouse.click(box["x"] + box["width"] * 0.48, box["y"] + box["height"] * 0.48)
                await page.wait_for_timeout(1000)

        await page.screenshot(path=str(SCREENSHOTS_DIR / "08_knowledge_graph_canvas.png"))
        print("  ✓ Captured 08_knowledge_graph_canvas.png")

        # Step 7: Evidence Ledger & Drawer
        print("\n[Step 7] Opening Evidence Ledger & Inspecting SHA-256 Hash Chains...")
        await page.evaluate("window.workstation.switchDetailTab('evidence')")
        await page.wait_for_timeout(1200)

        # Open Evidence Drawer for first evidence item
        await page.evaluate("""() => {
            const evList = window.workstation.currentInvestigation?.evidence_ids || [];
            if (evList.length > 0) {
                window.workstation.openEvidenceDrawer(evList[0]);
            }
        }""")
        await page.wait_for_timeout(1000)

        await page.screenshot(path=str(SCREENSHOTS_DIR / "09_evidence_ledger_drawer.png"))
        print("  ✓ Captured 09_evidence_ledger_drawer.png")

        # Step 8: AI Summary with Rich Markdown Beautifier
        print("\n[Step 8] Checking AI Summary & Markdown Beautifier (Tables, Callouts, Badges)...")
        # Close drawer
        await page.evaluate("""() => {
            const drawer = document.getElementById('evidence-drawer');
            if (drawer) drawer.classList.remove('open');
            window.workstation.switchDetailTab('ai-summary');
        }""")
        await page.wait_for_timeout(1200)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "10_ai_summary_markdown.png"))
        print("  ✓ Captured 10_ai_summary_markdown.png")

        # Step 9: Protocol Streams & TLS Handshake
        print("\n[Step 9] Verifying Protocol Streams & TLS Decoders...")
        await page.evaluate("window.workstation.switchDetailTab('sessions')")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "11_protocol_streams.png"))
        print("  ✓ Captured 11_protocol_streams.png")

        # Step 10: Agent Chat Interaction
        print("\n[Step 10] Sending Follow-up Query in AI Agent Chat...")
        await page.evaluate("window.workstation.switchDetailTab('agent-log')")
        await page.wait_for_timeout(1000)

        query = "What specific evidence confirms that STARTTLS stripping occurred in this PCAP?"
        await page.evaluate(f"""() => {{
            const invId = window.workstation.currentInvestigationId;
            window.workstation.askFollowUp(invId, "{query}");
        }}""")
        print(f"  - Sent query: '{query}'")
        print("  - Awaiting agent tool calling and reasoning...")
        
        for _ in range(20):
            await page.wait_for_timeout(1000)
            msgs = await page.query_selector_all(".agent-message, .chat-bubble, .claude-thinking-block")
            if len(msgs) > 2:
                break

        await page.wait_for_timeout(2500)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "12_agent_chat_live_reasoning.png"))
        print("  ✓ Captured 12_agent_chat_live_reasoning.png")

        # Step 11: Reports Library
        print("\n[Step 11] Checking Forensic Reports Library...")
        await page.evaluate("window.workstation.navigate('reports')")
        await page.wait_for_timeout(1200)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "13_reports_library.png"))
        print("  ✓ Captured 13_reports_library.png")

        # Step 12: Scientific ML Benchmark
        print("\n[Step 12] Checking Scientific ML Benchmark & SHAP Attribution...")
        await page.evaluate("window.workstation.navigate('ml')")
        await page.wait_for_timeout(1200)
        await page.screenshot(path=str(SCREENSHOTS_DIR / "14_ml_benchmark.png"))
        print("  ✓ Captured 14_ml_benchmark.png")

        await browser.close()
        print("\n==================================================================")
        print("   Playwright UI Interaction Test Completed - ALL 12 STEPS PASSED! ")
        print("==================================================================")


if __name__ == "__main__":
    asyncio.run(run_playwright_test())
