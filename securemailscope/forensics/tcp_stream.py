"""
SecureMailScope - TCP Stream Reconstruction Engine
"""
from typing import Dict, List, Any, Optional
from scapy.all import rdpcap, TCP, IP, IPv6, Raw


class ReconstructedSegment:
    def __init__(self, direction: str, src: str, dst: str, seq: int, timestamp: float, payload: bytes):
        self.direction = direction  # "CLIENT_TO_SERVER" or "SERVER_TO_CLIENT"
        self.src = src
        self.dst = dst
        self.seq = seq
        self.timestamp = timestamp
        self.payload = payload


class TCPStream:
    def __init__(self, stream_id: str, client_endpoint: str, server_endpoint: str):
        self.stream_id = stream_id
        self.client_endpoint = client_endpoint
        self.server_endpoint = server_endpoint
        self.segments: List[ReconstructedSegment] = []
        self.protocol_hint: str = "UNKNOWN"
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    @property
    def client_payload(self) -> bytes:
        return b"".join(s.payload for s in self.segments if s.direction == "CLIENT_TO_SERVER")

    @property
    def server_payload(self) -> bytes:
        return b"".join(s.payload for s in self.segments if s.direction == "SERVER_TO_CLIENT")

    @property
    def total_bytes(self) -> int:
        return sum(len(s.payload) for s in self.segments)

    def to_dict(self) -> Dict[str, Any]:
        transcript = []
        for s in self.segments:
            if not s.payload:
                continue
            text_preview = ""
            try:
                text_preview = s.payload.decode("utf-8", errors="replace")
            except Exception:
                text_preview = s.payload[:100].hex()

            transcript.append({
                "direction": s.direction,
                "src": s.src,
                "dst": s.dst,
                "seq": s.seq,
                "timestamp": round(s.timestamp, 4),
                "length": len(s.payload),
                "preview": text_preview[:200],
                "is_binary": any(b < 32 and b not in (9, 10, 13) for b in s.payload[:50])
            })

        return {
            "stream_id": self.stream_id,
            "client_endpoint": self.client_endpoint,
            "server_endpoint": self.server_endpoint,
            "protocol_hint": self.protocol_hint,
            "segment_count": len(self.segments),
            "total_bytes": self.total_bytes,
            "duration_seconds": round(max(0.0, self.end_time - self.start_time), 4),
            "transcript": transcript
        }


class TCPReconstructionEngine:
    """
    Reconstructs TCP conversations, segments client/server payloads,
    and identifies email protocols (SMTP, IMAP, POP3).
    """

    @staticmethod
    def reconstruct_streams(file_path: str) -> List[TCPStream]:
        packets = rdpcap(file_path)
        raw_streams: Dict[str, List[Any]] = {}
        stream_endpoints: Dict[str, Dict[str, str]] = {}

        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue

            ip_layer = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
            if not ip_layer:
                continue

            tcp = pkt[TCP]
            src_ep = f"{ip_layer.src}:{tcp.sport}"
            dst_ep = f"{ip_layer.dst}:{tcp.dport}"

            # Standard canonical key
            pair = sorted([src_ep, dst_ep])
            key = f"{pair[0]}<->{pair[1]}"

            if key not in raw_streams:
                raw_streams[key] = []
                # Determine client vs server from SYN packet or well-known server ports
                server_ports = (25, 587, 465, 143, 993, 110, 995)
                if tcp.dport in server_ports or (tcp.flags & 0x02 and not tcp.flags & 0x10):  # SYN
                    stream_endpoints[key] = {"client": src_ep, "server": dst_ep}
                elif tcp.sport in server_ports:
                    stream_endpoints[key] = {"client": dst_ep, "server": src_ep}
                else:
                    stream_endpoints[key] = {"client": src_ep, "server": dst_ep}

            raw_streams[key].append((pkt, ip_layer, tcp))

        reconstructed: List[TCPStream] = []
        stream_idx = 1

        for key, pkt_list in raw_streams.items():
            eps = stream_endpoints[key]
            stream = TCPStream(
                stream_id=f"TCP-{stream_idx:04d}",
                client_endpoint=eps["client"],
                server_endpoint=eps["server"]
            )
            stream_idx += 1

            for pkt, ip_layer, tcp in pkt_list:
                src_ep = f"{ip_layer.src}:{tcp.sport}"
                direction = "CLIENT_TO_SERVER" if src_ep == eps["client"] else "SERVER_TO_CLIENT"
                payload = bytes(tcp.payload) if tcp.haslayer(Raw) else b""
                ts = float(pkt.time)

                if stream.start_time == 0.0 or ts < stream.start_time:
                    stream.start_time = ts
                if ts > stream.end_time:
                    stream.end_time = ts

                if payload:
                    stream.segments.append(
                        ReconstructedSegment(
                            direction=direction,
                            src=src_ep,
                            dst=f"{ip_layer.dst}:{tcp.dport}",
                            seq=tcp.seq,
                            timestamp=ts,
                            payload=payload
                        )
                    )

            # Detect protocol signature
            stream.protocol_hint = TCPReconstructionEngine.detect_protocol(stream)
            reconstructed.append(stream)

        return reconstructed

    @staticmethod
    def detect_protocol(stream: TCPStream) -> str:
        all_payload = stream.client_payload + stream.server_payload
        text = all_payload[:500].decode("latin-1", errors="ignore")

        # Port-based hints
        server_port = int(stream.server_endpoint.split(":")[-1])
        if server_port in (25, 587, 465):
            return "SMTP"
        elif server_port in (143, 993):
            return "IMAP"
        elif server_port in (110, 995):
            return "POP3"

        # Content-based heuristics
        if "220" in text and ("SMTP" in text or "ESMTP" in text or "Postfix" in text or "Exim" in text):
            return "SMTP"
        if "EHLO" in text or "HELO" in text or "STARTTLS" in text and ("250" in text or "MAIL FROM" in text):
            return "SMTP"
        if "* OK" in text and ("IMAP" in text or "CAPABILITY" in text):
            return "IMAP"
        if "+OK" in text and ("POP3" in text or "STLS" in text or "USER" in text or "PASS" in text):
            return "POP3"
        if b"\x16\x03" in all_payload[:10]:  # TLS record header
            return "TLS"

        return "GENERIC_TCP"
