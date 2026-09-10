"""
SecureMailScope - Standalone CLI
"""
import sys
import argparse
import json
from pathlib import Path
from securemailscope.core.config import config, SAMPLES_DIR, REPORTS_DIR
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter
from securemailscope.ml.dataset_generator import DatasetGenerator
from securemailscope.ml.benchmark import BenchmarkEngine


def main():
    parser = argparse.ArgumentParser(
        description="SecureMailScope - Agentic Cryptographic Forensics for Email Communications (SIH26159 - NTRO)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Run adaptive investigation on a PCAP file")
    analyze_parser.add_argument("pcap_file", type=str, help="Path to PCAP capture file")
    analyze_parser.add_argument("--report-dir", type=str, default=str(REPORTS_DIR), help="Directory to save forensic reports")
    analyze_parser.add_argument("--json", action="store_true", help="Print result summary in JSON")

    # Generate samples command
    gen_parser = subparsers.add_parser("generate-samples", help="Synthesize all 6 SIH demo PCAP captures")

    # Benchmark command
    bm_parser = subparsers.add_parser("benchmark", help="Run Rule-Only vs Rule+ML scientific evaluation")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Launch FastAPI Web Investigation Console")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number")

    args = parser.parse_args()

    if args.command == "generate-samples":
        print("[*] Synthesizing SIH demonstration PCAP captures in 'samples/'...")
        DatasetGenerator.generate_all_samples()
        print("[+] 6 demo PCAP captures successfully created:")
        for p in SAMPLES_DIR.glob("*.pcap"):
            print(f"    - {p.name} ({p.stat().st_size} bytes)")

    elif args.command == "benchmark":
        print("[*] Evaluating Rule-Only Baseline vs Rule+ML Engine on 800 test samples...")
        results = BenchmarkEngine.evaluate_benchmark(num_samples=800)
        print("\n=======================================================")
        print("          SCIENTIFIC BENCHMARK EVALUATION")
        print("=======================================================")
        print(f"Rule-Only Accuracy:   {results['rule_only_baseline']['accuracy']*100:.1f}% | F1: {results['rule_only_baseline']['f1_score']*100:.1f}%")
        print(f"Rule + ML Accuracy:   {results['rule_plus_ml']['accuracy']*100:.1f}% | F1: {results['rule_plus_ml']['f1_score']*100:.1f}%")
        print(f"Empirical F1 Gain:    +{results['improvement']['f1_gain']}%")
        print("=======================================================\n")

    elif args.command == "analyze":
        pcap_path = Path(args.pcap_file)
        if not pcap_path.exists():
            print(f"[-] Error: File '{pcap_path}' not found.", file=sys.stderr)
            sys.exit(1)

        import uuid
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        ledger = EvidenceLedger.get_instance()
        agent = InvestigationAgent(ledger)

        print(f"[*] Analyzing PCAP: {pcap_path.name} (Investigation ID: {inv_id})...")
        inv = agent.run_investigation(inv_id, pcap_path)

        rep_dir = Path(args.report_dir)
        json_path = rep_dir / f"{inv_id}_report.json"
        html_path = rep_dir / f"{inv_id}_report.html"
        pdf_path = rep_dir / f"{inv_id}_report.pdf"

        JSONReporter.generate_report(inv_id, ledger, json_path)
        HTMLReporter.generate_report(inv_id, ledger, html_path)
        PDFReporter.generate_report(inv_id, ledger, pdf_path)

        post = inv.posture
        findings = ledger.get_findings_for_investigation(inv_id)
        evidence = ledger.get_evidence_for_investigation(inv_id)

        # Detect protocol / TLS / STARTTLS statistics
        protocols_str = ", ".join(inv.protocols_detected) if inv.protocols_detected else "TCP"
        smtp_evs = [e for e in evidence if "starttls" in e.claim.lower()]
        tls_evs = [e for e in evidence if "tls" in e.claim.lower()]

        print("\n" + "="*60)
        print("SecureMailScope")
        print("Real PCAP Passive Forensic Analysis")
        print("="*60)
        print(f"Artifact:         {inv.artifact_name}")
        print(f"SHA256:           {inv.artifact_sha256}")
        print(f"Packets:          {inv.packet_count}")
        print(f"Protocols:        {protocols_str}")
        print(f"Email Sessions:   {inv.streams_analyzed}")
        print(f"Capture Quality:  {inv.completeness_percentage}%")
        print(f"Security Posture: {post.overall_posture_score}/100 [{post.risk_level}]")
        print(f"Confidence:       {post.confidence_score}%")
        print(f"Investigation:    {inv.investigation_id}")
        print("-" * 60)

        print(f"Verified Findings ({len(findings)}):")
        if not findings:
            print("  [NONE] No security rule violations detected.")
        for f in findings:
            print(f"  [{f.severity.value.upper():<6}] {f.title}")
            print(f"          Supporting Evidence: {', '.join(f.evidence_ids)}")
            if f.remediation:
                print(f"          Remediation: {f.remediation}")

        print("-" * 60)
        print("Forensic Reports Generated:")
        print(f"  - JSON: {json_path}")
        print(f"  - HTML: {html_path}")
        print(f"  - PDF:  {pdf_path}")
        print("="*60 + "\n")

    elif args.command == "serve":
        from securemailscope.api.app import start_server
        print(f"[*] Starting SecureMailScope Web Console on http://{args.host}:{args.port}")
        start_server(host=args.host, port=args.port)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
