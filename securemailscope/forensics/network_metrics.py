"""
SecureMailScope - Network Metrics, Flow Analyzers & IDS Rule Exporter
Provides packet length histograms, IP fragmentation checks, TCP flag anomaly analysis,
protocol ratios, session duration metrics, and Suricata/Zeek rule exporters.
"""
import hashlib
from pathlib import Path
from typing import Dict, Any, List
from scapy.all import rdpcap, TCP, IP, IPv6


class NetworkMetricsEngine:
    """Calculates network flow metrics, protocol ratios, and IDS export rules."""

    @staticmethod
    def verify_pcap_integrity(file_path: Path) -> Dict[str, Any]:
        p = Path(file_path)
        if not p.exists():
            return {"valid": False, "error": f"File not found: {file_path}"}
        data = p.read_bytes()
        return {
            "valid": True,
            "filename": p.name,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest()
        }

    @staticmethod
    def analyze_protocol_ratios(file_path: Path) -> Dict[str, Any]:
        try:
            packets = rdpcap(str(file_path))
        except Exception as e:
            return {"error": str(e), "total_packets": 0, "ratios": {}}

        counts = {"SMTP": 0, "IMAP": 0, "POP3": 0, "TLS": 0, "OTHER": 0}
        for pkt in packets:
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                ports = {sport, dport}
                if 25 in ports or 587 in ports or 465 in ports:
                    counts["SMTP"] += 1
                elif 143 in ports or 993 in ports:
                    counts["IMAP"] += 1
                elif 110 in ports or 995 in ports:
                    counts["POP3"] += 1
                elif 443 in ports or 8443 in ports:
                    counts["TLS"] += 1
                else:
                    counts["OTHER"] += 1

        total = len(packets) or 1
        ratios = {k: round(v / total, 4) for k, v in counts.items()}
        return {"total_packets": len(packets), "counts": counts, "ratios": ratios}

    @staticmethod
    def inspect_tcp_flags(file_path: Path) -> Dict[str, Any]:
        try:
            packets = rdpcap(str(file_path))
        except Exception as e:
            return {"error": str(e), "flags": {}}

        flag_counts = {"SYN": 0, "FIN": 0, "RST": 0, "ACK": 0, "PSH": 0, "URG": 0}
        rst_post_starttls = False

        for pkt in packets:
            if pkt.haslayer(TCP):
                f = pkt[TCP].flags
                if f.S: flag_counts["SYN"] += 1
                if f.F: flag_counts["FIN"] += 1
                if f.R: flag_counts["RST"] += 1
                if f.A: flag_counts["ACK"] += 1
                if f.P: flag_counts["PSH"] += 1
                if f.U: flag_counts["URG"] += 1

        return {
            "total_tcp_packets": sum(flag_counts.values()),
            "flag_distribution": flag_counts,
            "has_rst_anomalies": flag_counts["RST"] > 0
        }

    @staticmethod
    def calculate_packet_histogram(file_path: Path) -> Dict[str, Any]:
        try:
            packets = rdpcap(str(file_path))
        except Exception as e:
            return {"error": str(e), "buckets": {}}

        buckets = {"0-128": 0, "129-512": 0, "513-1024": 0, "1025-1500": 0, "1500+": 0}
        for pkt in packets:
            l = len(pkt)
            if l <= 128: buckets["0-128"] += 1
            elif l <= 512: buckets["129-512"] += 1
            elif l <= 1024: buckets["513-1024"] += 1
            elif l <= 1500: buckets["1025-1500"] += 1
            else: buckets["1500+"] += 1

        return {"total_packets": len(packets), "size_buckets": buckets}

    @staticmethod
    def detect_ip_fragmentation(file_path: Path) -> Dict[str, Any]:
        try:
            packets = rdpcap(str(file_path))
        except Exception as e:
            return {"error": str(e), "fragments_found": 0}

        frags = 0
        for pkt in packets:
            if pkt.haslayer(IP) and (pkt[IP].flags == 1 or pkt[IP].frag > 0):
                frags += 1

        return {
            "is_fragmented": frags > 0,
            "fragment_count": frags,
            "evasion_risk": "HIGH" if frags > 0 else "LOW"
        }

    @staticmethod
    def export_suricata_and_zeek_rules(investigation_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        suricata_rules = []
        zeek_scripts = []

        for idx, f in enumerate(findings, 1001):
            title = f.get("title", "Forensic Anomaly")
            sev = f.get("severity", "HIGH")
            sid = 2000000 + idx

            # Generate Suricata Rule
            rule = (
                f'alert tcp any any -> any [25,587,110,143] (msg:"SECUREMAILSCOPE {sev} - {title}"; '
                f'flow:established,to_server; content:"STARTTLS"; classtype:policy-violation; sid:{sid}; rev:1;)'
            )
            suricata_rules.append(rule)

            # Generate Zeek Notice Script
            zeek = (
                f'event smtp_request(c: connection, is_orig: bool, command: string, arg: string) {{\n'
                f'    if ( command == "STARTTLS" ) {{\n'
                f'        NOTICE([$note=SMTP::Suspicious_STARTTLS, $msg="{title}", $conn=c]);\n'
                f'    }}\n'
                f'}}'
            )
            zeek_scripts.append(zeek)

        return {
            "investigation_id": investigation_id,
            "suricata_rules": suricata_rules,
            "zeek_scripts": zeek_scripts,
            "rule_count": len(suricata_rules)
        }
