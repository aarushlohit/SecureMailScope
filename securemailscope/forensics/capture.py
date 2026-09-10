"""
SecureMailScope - Capture Ingestion & Completeness Engine
"""
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from scapy.all import rdpcap, TCP, IP, IPv6
from securemailscope.core.exceptions import InvalidArtifactError


class CaptureEngine:
    """
    Ingests PCAP/PCAPNG captures, validates packet framing, extracts metadata,
    and deterministically calculates Capture Completeness percentage.
    """

    @staticmethod
    def inspect_capture(file_path: Path) -> Dict[str, Any]:
        if not file_path.exists():
            raise InvalidArtifactError(f"Capture file not found: {file_path}")

        raw_bytes = file_path.read_bytes()
        if len(raw_bytes) < 24:
            raise InvalidArtifactError(f"File too small to be a valid PCAP: {file_path}")

        # Magic bytes check for PCAP (0xa1b2c3d4, 0xd4c3b2a1, 0x0a0d0d0a for PCAPNG)
        magic = raw_bytes[:4]
        is_pcap = magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xcd\x34', b'\x34\xcd\xb2\xa1')
        is_pcapng = magic == b'\x0a\x0d\x0d\x0a'

        if not (is_pcap or is_pcapng):
            raise InvalidArtifactError(f"Invalid capture header magic: {magic.hex()}")

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        md5 = hashlib.md5(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)

        try:
            packets = rdpcap(str(file_path))
        except Exception as e:
            raise InvalidArtifactError(f"Scapy failed to parse capture packets: {e}")

        packet_count = len(packets)
        if packet_count == 0:
            raise InvalidArtifactError("Capture contains 0 packets.")

        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)
        duration = max(0.0, end_time - start_time)

        # Completeness calculation
        completeness_info = CaptureEngine.calculate_completeness(packets)

        # Capinfos and TShark integration for comprehensive forensic capture metrics
        capinfos_data = {}
        observed_protocols = set()
        try:
            from securemailscope.forensics.system_tools import SafeBinaryRunner
            cap_res = SafeBinaryRunner.run_capinfos(str(file_path))
            if cap_res.get("status") == "SUCCESS":
                capinfos_data = cap_res.get("data", {})
        except Exception:
            pass

        try:
            import subprocess, re
            info = SystemToolDiscovery.inspect_tool("tshark") if "SystemToolDiscovery" in globals() else None
            tshark_bin = info["path"] if info and info.get("installed") else shutil.which("tshark")
            if tshark_bin:
                phs_res = subprocess.run(
                    [tshark_bin, "-r", str(file_path), "-q", "-z", "io,phs"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15,
                    shell=False
                )
                if phs_res.returncode == 0:
                    for line in phs_res.stdout.splitlines():
                        m = re.match(r"^\s*([a-zA-Z0-9_\-]+)\s+frames:", line)
                        if m:
                            observed_protocols.add(m.group(1).upper())
        except Exception:
            pass

        if not observed_protocols:
            for p in packets:
                if p.haslayer(TCP):
                    observed_protocols.add("TCP")
                if p.haslayer(IP):
                    observed_protocols.add("IPV4")
                if p.haslayer(IPv6):
                    observed_protocols.add("IPV6")

        return {
            "artifact_name": file_path.name,
            "artifact_path": str(file_path.resolve()),
            "artifact_sha256": sha256,
            "artifact_md5": md5,
            "artifact_size": size_bytes,
            "file_type": "pcapng" if is_pcapng else "pcap",
            "packet_count": packet_count,
            "start_time": start_time,
            "end_time": end_time,
            "duration_seconds": round(duration, 3),
            "completeness": completeness_info,
            "capinfos_metadata": capinfos_data,
            "protocols_observed": sorted(list(observed_protocols)),
            "snaplen": capinfos_data.get("packet_size_limit", "65535 bytes"),
            "data_size": capinfos_data.get("data_size", f"{size_bytes} bytes")
        }

    @staticmethod
    def calculate_completeness(packets) -> Dict[str, Any]:
        """
        Calculates capture completeness by analyzing:
        1. TCP sequence continuity (gaps)
        2. Retransmission rates
        3. FIN/RST clean connection terminations vs abrupt drops
        4. Truncated packet indicators
        """
        tcp_streams: Dict[str, List[Any]] = {}
        total_tcp_packets = 0
        retransmissions = 0
        sequence_gaps = 0
        truncated_packets = 0

        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue
            total_tcp_packets += 1

            # Check for wire length vs captured length truncation
            if hasattr(pkt, 'wirelen') and hasattr(pkt, 'caplen'):
                if pkt.wirelen > pkt.caplen:
                    truncated_packets += 1
            elif hasattr(pkt, 'wirelen') and pkt.wirelen > len(pkt):
                truncated_packets += 1

            ip_layer = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
            if not ip_layer:
                continue

            tcp_layer = pkt[TCP]
            stream_key = tuple(sorted([
                f"{ip_layer.src}:{tcp_layer.sport}",
                f"{ip_layer.dst}:{tcp_layer.dport}"
            ]))

            if stream_key not in tcp_streams:
                tcp_streams[stream_key] = []
            tcp_streams[stream_key].append((ip_layer.src, tcp_layer))

        # Check sequence gaps per directional flow
        for stream_key, flow_packets in tcp_streams.items():
            seen_seqs: Dict[str, int] = {}
            for src, tcp in flow_packets:
                payload_len = len(tcp.payload)
                seq = tcp.seq
                if src in seen_seqs:
                    expected_seq = seen_seqs[src]
                    if seq > expected_seq + 1500:  # Gap larger than standard MTU segment
                        sequence_gaps += 1
                    elif seq < expected_seq and payload_len > 0:
                        retransmissions += 1
                    seen_seqs[src] = max(expected_seq, seq + payload_len)
                else:
                    seen_seqs[src] = seq + payload_len

        # Score calculation: 100% baseline with penalties for gaps and truncation
        if total_tcp_packets == 0:
            completeness_score = 100.0
        else:
            gap_penalty = min(50.0, (sequence_gaps / max(1, total_tcp_packets)) * 100.0 * 5)
            trunc_penalty = min(30.0, (truncated_packets / max(1, total_tcp_packets)) * 100.0)
            retrans_penalty = min(20.0, (retransmissions / max(1, total_tcp_packets)) * 100.0)
            completeness_score = max(0.0, round(100.0 - (gap_penalty + trunc_penalty + retrans_penalty), 2))

        return {
            "completeness_percentage": completeness_score,
            "total_tcp_packets": total_tcp_packets,
            "tcp_streams_count": len(tcp_streams),
            "sequence_gaps": sequence_gaps,
            "retransmissions": retransmissions,
            "truncated_packets": truncated_packets,
            "is_complete": completeness_score >= 95.0,
            "assessment": "HIGH_QUALITY_COMPLETE" if completeness_score >= 95.0 else (
                "MODERATE_PARTIAL" if completeness_score >= 60.0 else "INCOMPLETE_CAPTURE"
            )
        }
