"""
SecureMailScope - Standalone CLI
Provides forensic analysis, artifact inspection, session reconstruction,
evidence auditing, report export, database integrity validation, and system verification.
"""
import sys
import os
import argparse
import json
from pathlib import Path
from typing import List, Dict, Any

from securemailscope.core.config import config, SAMPLES_DIR, REPORTS_DIR
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter
from securemailscope.ml.dataset_generator import DatasetGenerator
from securemailscope.ml.benchmark import BenchmarkEngine
from securemailscope.forensics.capture import CaptureEngine
from securemailscope.forensics.tcp_stream import TCPReconstructionEngine
from securemailscope.forensics.system_tools import SystemToolDiscovery
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import (
    UserModel,
    InvestigationModel,
    EvidenceModel,
    FindingModel,
    ForensicSessionModel,
    ArtifactModel
)


def run_system_check():
    """Reports status and versions of all system binaries, Python packages, and DB."""
    import platform
    print("\n" + "=" * 65)
    print("       SECUREMAILSCOPE — SYSTEM & DEPENDENCY AUDIT")
    print("=" * 65)

    # Python & System
    print(f"Platform:              {platform.platform()}")
    print(f"Python Version:        {sys.version.split()[0]}")

    # Binary tools via SystemToolDiscovery
    tools = SystemToolDiscovery.discover_all()
    for tname in ("tshark", "capinfos", "openssl", "zeek"):
        tinfo = tools.get(tname, {})
        status_str = f"INSTALLED ({tinfo.get('version', '')[:40]})" if tinfo.get("installed") else "UNAVAILABLE (gracefully degraded)"
        print(f"Binary [{tname:<9}]:    {status_str}")

    # Python packages
    try:
        import scapy
        scapy_ver = getattr(scapy, "__version__", "installed")
        print(f"Package [scapy]:       INSTALLED ({scapy_ver})")
    except ImportError:
        print("Package [scapy]:       NOT FOUND")

    try:
        import xgboost
        print(f"Package [xgboost]:     INSTALLED ({xgboost.__version__})")
    except ImportError:
        print("Package [xgboost]:     NOT FOUND")

    try:
        import sklearn
        print(f"Package [sklearn]:     INSTALLED ({sklearn.__version__})")
    except ImportError:
        print("Package [sklearn]:     NOT FOUND")

    try:
        import shap
        print(f"Package [shap]:        INSTALLED ({shap.__version__})")
    except ImportError:
        print("Package [shap]:        NOT FOUND (TreeExplainer unavailable)")

    try:
        try:
            import mailparser
            mp_ver = getattr(mailparser, "__version__", "installed")
        except ImportError:
            import mail_parser as mailparser
            mp_ver = getattr(mailparser, "__version__", "installed")
        print(f"Package [mail-parser]: INSTALLED ({mp_ver})")
    except ImportError:
        print("Package [mail-parser]: NOT FOUND (falling back to stdlib email)")

    try:
        import dns.resolver
        print(f"Package [dnspython]:   INSTALLED ({getattr(dns, '__version__', 'ok')})")
    except ImportError:
        print("Package [dnspython]:   NOT FOUND")

    try:
        import sse_starlette
        print(f"Package [sse-starlette]: INSTALLED ({sse_starlette.__version__})")
    except ImportError:
        print("Package [sse-starlette]: NOT FOUND")

    # LLM configurations
    nv_key = bool(config.nvidia_api_key)
    gem_key = bool(config.gemini_api_key)
    print("-" * 65)
    print(f"LLM Primary (NVIDIA):  {'CONFIGURED (' + config.nvidia_model + ')' if nv_key else 'NOT CONFIGURED'}")
    print(f"LLM Fallback (Gemini): {'CONFIGURED (' + config.gemini_model + ')' if gem_key else 'NOT CONFIGURED'}")

    # DB Connection
    try:
        db = SessionLocal()
        user_count = db.query(UserModel).count()
        inv_count = db.query(InvestigationModel).count()
        db.close()
        print(f"Database:              CONNECTED ({config.database_url.split('://')[0]}) | Users: {user_count}, Invs: {inv_count}")
    except Exception as dberr:
        print(f"Database:              CONNECTION FAILED ({dberr})")

    print("=" * 65 + "\n")


def run_validate_db() -> int:
    """
    Validates database referential integrity:
    - Orphan investigations
    - Orphan evidence
    - Orphan findings
    - Findings without evidence
    - Cross-investigation evidence citations
    - Duplicate emails
    Returns 0 if all checks pass, non-zero if violations exist.
    """
    print("\n" + "=" * 65)
    print("      SECUREMAILSCOPE — DATABASE INTEGRITY AUDIT")
    print("=" * 65)

    violations: List[str] = []
    db = SessionLocal()

    try:
        # 1. Duplicate emails
        emails = [u.email for u in db.query(UserModel.email).all()]
        dup_emails = set([e for e in emails if emails.count(e) > 1])
        if dup_emails:
            violations.append(f"Duplicate user emails found: {dup_emails}")
        else:
            print("[PASS] User email uniqueness: No duplicate accounts.")

        # 2. Orphan investigations (user_id pointing to non-existent user)
        users = set(u.user_id for u in db.query(UserModel.user_id).all())
        invs = db.query(InvestigationModel).all()
        inv_ids = set(inv.investigation_id for inv in invs)

        orphan_user_invs = [inv.investigation_id for inv in invs if inv.user_id and inv.user_id not in users]
        if orphan_user_invs:
            violations.append(f"Investigations with orphaned user_id: {orphan_user_invs}")
        else:
            print("[PASS] User-Investigation FK integrity: No orphan investigations.")

        # 3. Orphan evidence (evidence with unknown investigation_id)
        evs = db.query(EvidenceModel).all()
        orphan_evs = [e.evidence_id for e in evs if e.investigation_id not in inv_ids]
        if orphan_evs:
            violations.append(f"Evidence items with orphaned investigation_id: {orphan_evs}")
        else:
            print("[PASS] Evidence-Investigation FK integrity: Zero orphan evidence records.")

        # 4. Orphan findings (findings with unknown investigation_id)
        fnds = db.query(FindingModel).all()
        orphan_fnds = [f.finding_id for f in fnds if f.investigation_id not in inv_ids]
        if orphan_fnds:
            violations.append(f"Findings with orphaned investigation_id: {orphan_fnds}")
        else:
            print("[PASS] Finding-Investigation FK integrity: Zero orphan findings.")

        # 5. Findings without evidence
        ev_id_set = set(e.evidence_id for e in evs)
        no_ev_fnds = []
        cross_inv_fnds = []

        for f in fnds:
            eids = f.evidence_ids or []
            if not eids:
                no_ev_fnds.append(f.finding_id)
            else:
                # Check if evidence exists and belongs to same investigation
                for eid in eids:
                    if eid not in ev_id_set:
                        violations.append(f"Finding {f.finding_id} cites non-existent evidence {eid}")
                    else:
                        ev_item = db.query(EvidenceModel).filter_by(evidence_id=eid).first()
                        if ev_item and ev_item.investigation_id != f.investigation_id:
                            cross_inv_fnds.append((f.finding_id, eid, f.investigation_id, ev_item.investigation_id))

        if no_ev_fnds:
            violations.append(f"Findings violating 'No Evidence -> No Finding' rule: {no_ev_fnds}")
        else:
            print("[PASS] Finding Evidence Grounding: All findings cite valid Evidence IDs.")

        if cross_inv_fnds:
            violations.append(f"Cross-investigation evidence citations detected: {cross_inv_fnds}")
        else:
            print("[PASS] Investigation Isolation: No cross-investigation evidence leakage.")

        # 6. Orphan sessions
        sessions = db.query(ForensicSessionModel).all()
        orphan_sess = [s.session_id for s in sessions if s.investigation_id not in inv_ids]
        if orphan_sess:
            violations.append(f"Forensic sessions with orphaned investigation_id: {orphan_sess}")
        else:
            print("[PASS] Forensic Session FK integrity: Zero orphan sessions.")

    finally:
        db.close()

    print("-" * 65)
    if violations:
        print(f"[FAIL] Integrity audit failed with {len(violations)} violation(s):")
        for v in violations:
            print(f"  - {v}")
        print("=" * 65 + "\n")
        return 1
    else:
        print("[SUCCESS] All database referential integrity checks passed cleanly.")
        print("=" * 65 + "\n")
        return 0


def run_verify_ledger(session_factory=None, json_storage_path=None) -> int:
    """
    Verifies Evidence Ledger integrity:
    - Unique evidence IDs
    - Referenced investigations and users exist
    - Ownership and isolation (investigation & user)
    - Canonical entry hashes and previous-entry hash links
    - Sequential hash chain continuity and tamper detection
    - Finding citations grounding in evidence
    - Cross-investigation and cross-user citations
    - Safe handling of malformed or empty datasets
    Returns 0 if all checks pass, non-zero if violations exist.
    """
    from securemailscope.evidence.hasher import compute_hash_for_evidence, GENESIS_HASH

    print("\n" + "=" * 65)
    print("      SECUREMAILSCOPE — EVIDENCE LEDGER INTEGRITY AUDIT")
    print("=" * 65)

    violations: List[str] = []
    sess_fact = session_factory or SessionLocal
    db = sess_fact()

    ledger_entries_checked = 0
    hash_chain_entries_checked = 0
    invalid_hashes = 0
    broken_links = 0
    orphan_evidence = 0
    invalid_finding_citations = 0
    cross_investigation_citations = 0
    cross_user_citations = 0

    try:
        invs = db.query(InvestigationModel).all()
        inv_map = {i.investigation_id: i for i in invs}
        users = set(u.user_id for u in db.query(UserModel.user_id).all())

        evs = db.query(EvidenceModel).order_by(EvidenceModel.timestamp.asc(), EvidenceModel.evidence_id.asc()).all()
        fnds = db.query(FindingModel).all()

        ledger_entries_checked = len(evs)

        # 1. Check duplicate evidence IDs
        seen_eids = set()
        for e in evs:
            if not e.evidence_id or not str(e.evidence_id).strip():
                violations.append("Malformed row: evidence record with empty evidence_id")
                broken_links += 1
            elif e.evidence_id in seen_eids:
                violations.append(f"Duplicate evidence ID detected: '{e.evidence_id}'")
                broken_links += 1
            else:
                seen_eids.add(e.evidence_id)

        # 2. Check referenced investigations and users
        for e in evs:
            if e.investigation_id not in inv_map:
                violations.append(f"Orphan evidence: '{e.evidence_id}' references missing investigation '{e.investigation_id}'")
                orphan_evidence += 1
            else:
                parent_inv = inv_map[e.investigation_id]
                if e.user_id:
                    if e.user_id not in users:
                        violations.append(f"Orphan user reference: Evidence '{e.evidence_id}' cites non-existent user '{e.user_id}'")
                        broken_links += 1
                    if parent_inv.user_id and parent_inv.user_id != e.user_id:
                        violations.append(f"Evidence user mismatch: Evidence '{e.evidence_id}' user '{e.user_id}' != investigation user '{parent_inv.user_id}'")
                        broken_links += 1

            # Check provenance chain safely
            try:
                p_chain = e.provenance_chain or []
                if isinstance(p_chain, list):
                    for item in p_chain:
                        if isinstance(item, str) and item.startswith("E-") and item != e.evidence_id:
                            parent_ev = db.query(EvidenceModel).filter_by(evidence_id=item).first()
                            if not parent_ev:
                                violations.append(f"Evidence '{e.evidence_id}' provenance cites missing parent '{item}'")
                                broken_links += 1
                            elif parent_ev.investigation_id != e.investigation_id:
                                violations.append(f"Cross-investigation provenance: '{e.evidence_id}' cites parent '{item}' from another investigation")
                                broken_links += 1
            except Exception as pe:
                violations.append(f"Malformed provenance chain on evidence '{e.evidence_id}': {pe}")
                broken_links += 1

        # 3. Canonical hash chain & tamper detection
        prev_hash = GENESIS_HASH
        for idx, e in enumerate(evs):
            hash_chain_entries_checked += 1
            try:
                # Verify link to previous entry
                if e.previous_entry_hash and e.previous_entry_hash != prev_hash:
                    violations.append(f"Broken hash link at '{e.evidence_id}': previous_entry_hash {e.previous_entry_hash[:12]}... != expected {prev_hash[:12]}...")
                    broken_links += 1

                # Verify entry hash against canonical payload
                expected_hash = compute_hash_for_evidence(e, e.previous_entry_hash or prev_hash)
                if not e.entry_hash:
                    violations.append(f"Missing entry_hash on evidence '{e.evidence_id}'")
                    invalid_hashes += 1
                elif e.entry_hash != expected_hash:
                    violations.append(f"Tampered entry hash at '{e.evidence_id}': stored {e.entry_hash[:12]}... != computed {expected_hash[:12]}...")
                    invalid_hashes += 1

                prev_hash = e.entry_hash or expected_hash
            except Exception as he:
                violations.append(f"Malformed entry causing hash evaluation error on '{e.evidence_id}': {he}")
                invalid_hashes += 1

        # 4. JSON Ledger store cross-check
        json_path = json_storage_path or config.evidence_db_path
        if json_path and json_path.exists():
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                json_evs = data.get("evidence", [])
                db_ev_map = {e.evidence_id: e for e in evs}
                for je in json_evs:
                    jid = je.get("evidence_id")
                    if jid in db_ev_map:
                        dbe = db_ev_map[jid]
                        if dbe.claim != je.get("claim"):
                            violations.append(f"Tampered evidence in JSON store: claim mismatch on '{jid}'")
                            broken_links += 1
                        if dbe.entry_hash and je.get("entry_hash") and dbe.entry_hash != je.get("entry_hash"):
                            violations.append(f"Tampered evidence in JSON store: entry_hash mismatch on '{jid}'")
                            invalid_hashes += 1
            except Exception as jerr:
                violations.append(f"Malformed JSON ledger file: {jerr}")
                broken_links += 1

        # 5. Finding citations integrity (No Evidence -> No Finding)
        ev_id_set = set(e.evidence_id for e in evs)
        for f in fnds:
            eids = f.evidence_ids or []
            if not eids:
                violations.append(f"Finding '{f.finding_id}' violates 'No Evidence -> No Finding' rule (empty citations)")
                invalid_finding_citations += 1
            else:
                f_inv = inv_map.get(f.investigation_id)
                f_user_id = f_inv.user_id if f_inv else None

                for eid in eids:
                    if eid not in ev_id_set:
                        violations.append(f"Finding '{f.finding_id}' cites non-existent evidence ID '{eid}'")
                        invalid_finding_citations += 1
                    else:
                        target_ev = next((e for e in evs if e.evidence_id == eid), None)
                        if target_ev:
                            if target_ev.investigation_id != f.investigation_id:
                                violations.append(f"Cross-investigation citation: Finding '{f.finding_id}' cites '{eid}' from investigation '{target_ev.investigation_id}'")
                                cross_investigation_citations += 1
                            if f_user_id and target_ev.user_id and target_ev.user_id != f_user_id:
                                violations.append(f"Cross-user citation: Finding '{f.finding_id}' (user '{f_user_id}') cites '{eid}' (user '{target_ev.user_id}')")
                                cross_user_citations += 1

    finally:
        db.close()

    is_valid = (
        len(violations) == 0
        and invalid_hashes == 0
        and broken_links == 0
        and orphan_evidence == 0
        and invalid_finding_citations == 0
        and cross_investigation_citations == 0
        and cross_user_citations == 0
    )

    status_str = "VALID" if is_valid else "INVALID"

    print(f"Ledger entries checked: {ledger_entries_checked}")
    print(f"Hash-chain entries checked: {hash_chain_entries_checked}")
    print(f"Invalid hashes: {invalid_hashes}")
    print(f"Broken links: {broken_links}")
    print(f"Orphan evidence: {orphan_evidence}")
    print(f"Invalid finding citations: {invalid_finding_citations}")
    print(f"Cross-investigation citations: {cross_investigation_citations}")
    print(f"Cross-user citations: {cross_user_citations}")
    print(f"Status: {status_str}")

    if not is_valid:
        print("\nLedger Integrity Violations:")
        for v in violations[:25]:
            print(f"  - {v}")
        if len(violations) > 25:
            print(f"  ... and {len(violations) - 25} more violations.")
        print("=" * 65 + "\n")
        return 1
    else:
        print("=" * 65 + "\n")
        return 0



def main():
    parser = argparse.ArgumentParser(
        description="SecureMailScope - Agentic Cryptographic Forensics for Email Communications (SIH26159 - NTRO)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Run adaptive investigation on a capture file")
    analyze_parser.add_argument("pcap_file", type=str, help="Path to PCAP/PCAPNG/EML file")
    analyze_parser.add_argument("--report-dir", type=str, default=str(REPORTS_DIR), help="Directory to save forensic reports")
    analyze_parser.add_argument("--json", action="store_true", help="Print result summary in JSON")

    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect capture framing, hashes, and completeness")
    inspect_parser.add_argument("file_path", type=str, help="Path to PCAP or EML file")

    # Sessions command
    sess_parser = subparsers.add_parser("sessions", help="List reconstructed TCP/email sessions from PCAP")
    sess_parser.add_argument("file_path", type=str, help="Path to PCAP file")

    # Evidence command
    ev_parser = subparsers.add_parser("evidence", help="Query Evidence Ledger for an investigation")
    ev_parser.add_argument("investigation_id", type=str, help="Investigation ID")

    # Report command
    rep_parser = subparsers.add_parser("report", help="Generate or export a forensic report")
    rep_parser.add_argument("investigation_id", type=str, help="Investigation ID")
    rep_parser.add_argument("--format", choices=["json", "html", "pdf"], default="json", help="Report format")
    rep_parser.add_argument("--output", type=str, default=None, help="Output destination file path")

    # Validate DB command
    subparsers.add_parser("validate-db", help="Verify SQLite database referential integrity and orphan records")

    # Verify Ledger command
    subparsers.add_parser("verify-ledger", help="Verify Evidence Ledger integrity, hash chain, and citations")

    # System check command
    subparsers.add_parser("system-check", help="Audit all system tools, dependencies, and LLM provider states")

    # Benchmark command
    subparsers.add_parser("benchmark", help="Run Rule-Only vs Rule+ML scientific evaluation")

    # Generate samples command
    subparsers.add_parser("generate-samples", help="Synthesize SIH demo PCAP captures")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Launch FastAPI Web Investigation Console")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number")

    args = parser.parse_args()

    if args.command == "system-check":
        run_system_check()

    elif args.command == "validate-db":
        sys.exit(run_validate_db())

    elif args.command == "verify-ledger":
        sys.exit(run_verify_ledger())

    elif args.command == "inspect":
        target = Path(args.file_path)
        if not target.exists():
            print(f"[-] Error: File '{target}' not found.", file=sys.stderr)
            sys.exit(1)

        if target.suffix.lower() == ".eml":
            from securemailscope.forensics.email_parser import EMLParser
            res = EMLParser.parse_eml(target)
            print(json.dumps(res, indent=2, default=str))
        else:
            meta = CaptureEngine.inspect_capture(target)
            print(json.dumps(meta, indent=2, default=str))

    elif args.command == "sessions":
        target = Path(args.file_path)
        if not target.exists():
            print(f"[-] Error: File '{target}' not found.", file=sys.stderr)
            sys.exit(1)
        streams = TCPReconstructionEngine.reconstruct_streams(str(target))
        print(f"\nDiscovered {len(streams)} reconstructed streams in {target.name}:")
        for s in streams:
            print(f"  Stream {s.stream_id:>2}: {s.protocol_hint:<6} | {s.client_endpoint} -> {s.server_endpoint} | {s.total_bytes} bytes")
        print()

    elif args.command == "evidence":
        ledger = EvidenceLedger.get_instance()
        evs = ledger.get_evidence_for_investigation(args.investigation_id)
        print(f"\nEvidence Ledger for {args.investigation_id} ({len(evs)} items):")
        for e in evs:
            print(f"  [{e.evidence_id}] ({e.type.value}): {e.claim}")
        print()

    elif args.command == "report":
        ledger = EvidenceLedger.get_instance()
        inv_id = args.investigation_id
        fmt = args.format.lower()
        out_path = Path(args.output) if args.output else (REPORTS_DIR / f"{inv_id}_report.{fmt}")

        if fmt == "json":
            res = JSONReporter.generate_report(inv_id, ledger, out_path)
        elif fmt == "html":
            res = HTMLReporter.generate_report(inv_id, ledger, out_path)
        elif fmt == "pdf":
            res = PDFReporter.generate_report(inv_id, ledger, out_path)

        print(f"[+] {fmt.upper()} report generated at: {out_path} ({out_path.stat().st_size} bytes)")

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

        print(f"[*] Analyzing capture: {pcap_path.name} (Investigation ID: {inv_id})...")
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

        protocols_str = ", ".join(inv.protocols_detected) if inv.protocols_detected else "TCP"

        print("\n" + "=" * 60)
        print("SecureMailScope — Real Forensic Analysis")
        print("=" * 60)
        print(f"Artifact:         {inv.artifact_name}")
        print(f"SHA256:           {inv.artifact_sha256}")
        print(f"Packets:          {inv.packet_count}")
        print(f"Protocols:        {protocols_str}")
        print(f"Email Sessions:   {inv.streams_analyzed}")
        print(f"Capture Quality:  {inv.completeness_percentage}%")
        print(f"Security Posture: {post.overall_posture_score if post else 100}/100 [{post.risk_level if post else 'INFO'}]")
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
        print("=" * 60 + "\n")

    elif args.command == "serve":
        from securemailscope.api.app import start_server
        print(f"[*] Starting SecureMailScope Web Console on http://{args.host}:{args.port}")
        start_server(host=args.host, port=args.port)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
