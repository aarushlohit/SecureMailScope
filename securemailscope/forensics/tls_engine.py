"""
SecureMailScope - TLS Handshake Forensic Engine (TLS 1.0 to 1.3)
"""
import struct
from typing import Dict, Any, List, Optional, Tuple
from securemailscope.forensics.tcp_stream import TCPStream

# Known cipher suite lookup table with security attributes
CIPHER_SUITE_DB = {
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "pfs": False, "strength": "BROKEN", "symmetric": "RC4", "kex": "RSA"},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "pfs": False, "strength": "BROKEN", "symmetric": "RC4", "kex": "RSA"},
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "pfs": False, "strength": "LEGACY", "symmetric": "3DES", "kex": "RSA"},
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "pfs": False, "strength": "WEAK", "symmetric": "AES-CBC", "kex": "RSA"},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "pfs": False, "strength": "WEAK", "symmetric": "AES-CBC", "kex": "RSA"},
    0x009C: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "pfs": False, "strength": "MODERATE", "symmetric": "AES-GCM", "kex": "RSA"},
    0xC013: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "pfs": True, "strength": "MODERATE", "symmetric": "AES-CBC", "kex": "ECDHE"},
    0xC014: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "pfs": True, "strength": "MODERATE", "symmetric": "AES-CBC", "kex": "ECDHE"},
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "pfs": True, "strength": "STRONG", "symmetric": "AES-GCM", "kex": "ECDHE"},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "pfs": True, "strength": "STRONG", "symmetric": "AES-GCM", "kex": "ECDHE"},
    0xCCA8: {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "pfs": True, "strength": "STRONG", "symmetric": "CHACHA20", "kex": "ECDHE"},
    0xCCA9: {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "pfs": True, "strength": "STRONG", "symmetric": "CHACHA20", "kex": "ECDHE"},
    # TLS 1.3 Ciphers (PFS always enforced in TLS 1.3)
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "pfs": True, "strength": "STRONG", "symmetric": "AES-GCM", "kex": "TLS13_KEY_SHARE"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "pfs": True, "strength": "STRONG", "symmetric": "AES-GCM", "kex": "TLS13_KEY_SHARE"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "pfs": True, "strength": "STRONG", "symmetric": "CHACHA20", "kex": "TLS13_KEY_SHARE"}
}

TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3"
}


class TLSHandshakeAnalysis:
    def __init__(self):
        self.handshake_observed: bool = False
        self.client_hello_observed: bool = False
        self.server_hello_observed: bool = False
        self.handshake_completed: bool = False
        self.record_version: Optional[str] = None
        self.negotiated_version: Optional[str] = None
        self.client_offered_versions: List[str] = []
        self.client_ciphers: List[Dict[str, Any]] = []
        self.selected_cipher: Optional[Dict[str, Any]] = None
        self.sni: Optional[str] = None
        self.alpn: List[str] = []
        self.supported_groups: List[str] = []
        self.key_share_group: Optional[str] = None
        self.has_forward_secrecy: bool = False
        self.raw_certificates_bytes: List[bytes] = []
        self.certificate_observable: bool = False
        self.certificate_note: str = ""
        self.client_hello_ts: Optional[float] = None
        self.server_hello_ts: Optional[float] = None
        self.handshake_rtt_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handshake_observed": self.handshake_observed,
            "client_hello_observed": self.client_hello_observed,
            "server_hello_observed": self.server_hello_observed,
            "handshake_completed": self.handshake_completed,
            "record_version": self.record_version,
            "negotiated_version": self.negotiated_version,
            "client_offered_versions": self.client_offered_versions,
            "client_cipher_count": len(self.client_ciphers),
            "selected_cipher": self.selected_cipher,
            "sni": self.sni,
            "alpn": self.alpn,
            "supported_groups": self.supported_groups,
            "key_share_group": self.key_share_group,
            "has_forward_secrecy": self.has_forward_secrecy,
            "certificate_observable": self.certificate_observable,
            "certificate_count": len(self.raw_certificates_bytes),
            "certificate_note": self.certificate_note,
            "handshake_rtt_ms": self.handshake_rtt_ms
        }


class TLSEngine:
    """
    Forensic parser for TLS 1.0, 1.1, 1.2, and 1.3 handshakes.
    Accurately extracts versions, cipher suites, extensions, and raw certificates when observable.
    """

    @staticmethod
    def analyze_stream(stream: TCPStream) -> TLSHandshakeAnalysis:
        analysis = TLSHandshakeAnalysis()
        client_data = b""
        server_data = b""

        for seg in stream.segments:
            if seg.direction == "CLIENT_TO_SERVER":
                client_data += seg.payload
                if not analysis.client_hello_ts and TLSEngine._has_client_hello(seg.payload):
                    analysis.client_hello_ts = seg.timestamp
            else:
                server_data += seg.payload
                if not analysis.server_hello_ts and TLSEngine._has_server_hello(seg.payload):
                    analysis.server_hello_ts = seg.timestamp

        if analysis.client_hello_ts and analysis.server_hello_ts:
            analysis.handshake_rtt_ms = round((analysis.server_hello_ts - analysis.client_hello_ts) * 1000.0, 2)

        # Parse ClientHello from client stream
        TLSEngine._parse_client_records(client_data, analysis)

        # Parse ServerHello and Certificate from server stream
        TLSEngine._parse_server_records(server_data, analysis)

        # Evaluate TLS 1.3 certificate observability constraints
        if analysis.negotiated_version == "TLS 1.3":
            analysis.certificate_observable = False
            analysis.certificate_note = (
                "X.509 Certificate is encrypted post-ServerHello in TLS 1.3 passive captures "
                "and is NOT observable without private keys or ephemeral SSLKEYLOGFILE."
            )
            analysis.has_forward_secrecy = True
        elif analysis.negotiated_version in ("TLS 1.0", "TLS 1.1", "TLS 1.2"):
            if len(analysis.raw_certificates_bytes) > 0:
                analysis.certificate_observable = True
                analysis.certificate_note = f"Observable {len(analysis.raw_certificates_bytes)} X.509 certificate(s) extracted from plaintext TLS handshake."
            else:
                analysis.certificate_observable = False
                analysis.certificate_note = "Certificate message was truncated or not captured in the TCP stream."

        if analysis.selected_cipher:
            analysis.has_forward_secrecy = analysis.selected_cipher.get("pfs", False)

        return analysis

    @staticmethod
    def _has_client_hello(data: bytes) -> bool:
        idx = 0
        while idx + 5 < len(data):
            if data[idx] == 0x16:  # Handshake
                rec_len = struct.unpack("!H", data[idx+3:idx+5])[0]
                if idx + 5 + rec_len <= len(data):
                    body = data[idx+5:idx+5+rec_len]
                    if len(body) > 0 and body[0] == 0x01:  # ClientHello
                        return True
                idx += 5 + rec_len
            else:
                idx += 1
        return False

    @staticmethod
    def _has_server_hello(data: bytes) -> bool:
        idx = 0
        while idx + 5 < len(data):
            if data[idx] == 0x16:
                rec_len = struct.unpack("!H", data[idx+3:idx+5])[0]
                if idx + 5 + rec_len <= len(data):
                    body = data[idx+5:idx+5+rec_len]
                    if len(body) > 0 and body[0] == 0x02:  # ServerHello
                        return True
                idx += 5 + rec_len
            else:
                idx += 1
        return False

    @staticmethod
    def _parse_client_records(data: bytes, analysis: TLSHandshakeAnalysis):
        idx = 0
        while idx + 5 <= len(data):
            content_type = data[idx]
            if content_type != 0x16:  # TLS Handshake Record
                idx += 1
                continue

            version_code = struct.unpack("!H", data[idx+1:idx+3])[0]
            rec_len = struct.unpack("!H", data[idx+3:idx+5])[0]
            analysis.handshake_observed = True
            analysis.record_version = TLS_VERSION_NAMES.get(version_code, f"Unknown ({hex(version_code)})")

            if idx + 5 + rec_len > len(data):
                break

            record_body = data[idx+5:idx+5+rec_len]
            TLSEngine._parse_client_handshake_body(record_body, analysis)
            idx += 5 + rec_len

    @staticmethod
    def _parse_client_handshake_body(body: bytes, analysis: TLSHandshakeAnalysis):
        b_idx = 0
        while b_idx + 4 <= len(body):
            msg_type = body[b_idx]
            msg_len = struct.unpack("!I", b"\x00" + body[b_idx+1:b_idx+4])[0]
            if msg_type == 0x01:  # ClientHello
                analysis.client_hello_observed = True
                msg_body = body[b_idx+4:b_idx+4+msg_len]
                if len(msg_body) >= 34:
                    client_ver = struct.unpack("!H", msg_body[0:2])[0]
                    analysis.client_offered_versions.append(TLS_VERSION_NAMES.get(client_ver, hex(client_ver)))
                    # Session ID
                    sess_id_len = msg_body[34] if len(msg_body) > 34 else 0
                    p = 35 + sess_id_len
                    if p + 2 <= len(msg_body):
                        cipher_suites_len = struct.unpack("!H", msg_body[p:p+2])[0]
                        p += 2
                        for c_idx in range(p, min(len(msg_body), p + cipher_suites_len), 2):
                            if c_idx + 2 <= len(msg_body):
                                c_code = struct.unpack("!H", msg_body[c_idx:c_idx+2])[0]
                                c_info = CIPHER_SUITE_DB.get(c_code, {
                                    "name": f"UNKNOWN_CIPHER_0x{c_code:04X}",
                                    "pfs": False,
                                    "strength": "UNKNOWN",
                                    "symmetric": "UNKNOWN",
                                    "kex": "UNKNOWN"
                                })
                                analysis.client_ciphers.append({"code": hex(c_code), **c_info})
                        p += cipher_suites_len

                    # Compression methods
                    if p < len(msg_body):
                        comp_len = msg_body[p]
                        p += 1 + comp_len

                    # Extensions
                    if p + 2 <= len(msg_body):
                        ext_total_len = struct.unpack("!H", msg_body[p:p+2])[0]
                        p += 2
                        ext_end = min(len(msg_body), p + ext_total_len)
                        while p + 4 <= ext_end:
                            ext_type = struct.unpack("!H", msg_body[p:p+2])[0]
                            ext_len = struct.unpack("!H", msg_body[p+2:p+4])[0]
                            ext_body = msg_body[p+4:p+4+ext_len]

                            if ext_type == 0x0000:  # SNI
                                if len(ext_body) >= 5:
                                    server_name_len = struct.unpack("!H", ext_body[3:5])[0]
                                    analysis.sni = ext_body[5:5+server_name_len].decode("utf-8", errors="ignore")
                            elif ext_type == 0x002B:  # supported_versions (TLS 1.3)
                                if len(ext_body) > 1:
                                    s_len = ext_body[0]
                                    for v_idx in range(1, min(len(ext_body), 1 + s_len), 2):
                                        v_code = struct.unpack("!H", ext_body[v_idx:v_idx+2])[0]
                                        v_name = TLS_VERSION_NAMES.get(v_code, hex(v_code))
                                        if v_name not in analysis.client_offered_versions:
                                            analysis.client_offered_versions.append(v_name)

                            p += 4 + ext_len
            b_idx += 4 + msg_len

    @staticmethod
    def _parse_server_records(data: bytes, analysis: TLSHandshakeAnalysis):
        idx = 0
        while idx + 5 <= len(data):
            content_type = data[idx]
            if content_type != 0x16:
                idx += 1
                continue

            rec_len = struct.unpack("!H", data[idx+3:idx+5])[0]
            if idx + 5 + rec_len > len(data):
                break

            record_body = data[idx+5:idx+5+rec_len]
            TLSEngine._parse_server_handshake_body(record_body, analysis)
            idx += 5 + rec_len

    @staticmethod
    def _parse_server_handshake_body(body: bytes, analysis: TLSHandshakeAnalysis):
        b_idx = 0
        while b_idx + 4 <= len(body):
            msg_type = body[b_idx]
            msg_len = struct.unpack("!I", b"\x00" + body[b_idx+1:b_idx+4])[0]
            msg_body = body[b_idx+4:b_idx+4+msg_len]

            if msg_type == 0x02:  # ServerHello
                analysis.server_hello_observed = True
                if len(msg_body) >= 34:
                    server_ver = struct.unpack("!H", msg_body[0:2])[0]
                    analysis.negotiated_version = TLS_VERSION_NAMES.get(server_ver, hex(server_ver))

                    sess_id_len = msg_body[34] if len(msg_body) > 34 else 0
                    p = 35 + sess_id_len
                    if p + 2 <= len(msg_body):
                        sel_cipher_code = struct.unpack("!H", msg_body[p:p+2])[0]
                        c_info = CIPHER_SUITE_DB.get(sel_cipher_code, {
                            "name": f"UNKNOWN_CIPHER_0x{sel_cipher_code:04X}",
                            "pfs": False,
                            "strength": "UNKNOWN",
                            "symmetric": "UNKNOWN",
                            "kex": "UNKNOWN"
                        })
                        analysis.selected_cipher = {"code": hex(sel_cipher_code), **c_info}
                        p += 3  # cipher suite (2) + compression (1)

                    # Check for TLS 1.3 supported_versions in extensions
                    if p + 2 <= len(msg_body):
                        ext_total_len = struct.unpack("!H", msg_body[p:p+2])[0]
                        p += 2
                        ext_end = min(len(msg_body), p + ext_total_len)
                        while p + 4 <= ext_end:
                            ext_type = struct.unpack("!H", msg_body[p:p+2])[0]
                            ext_len = struct.unpack("!H", msg_body[p+2:p+4])[0]
                            ext_body = msg_body[p+4:p+4+ext_len]
                            if ext_type == 0x002B and len(ext_body) == 2:  # supported_versions
                                tls13_code = struct.unpack("!H", ext_body)[0]
                                if tls13_code == 0x0304:
                                    analysis.negotiated_version = "TLS 1.3"
                            p += 4 + ext_len

            elif msg_type == 0x0B:  # Certificate (TLS <= 1.2)
                if len(msg_body) >= 3:
                    certs_total_len = struct.unpack("!I", b"\x00" + msg_body[0:3])[0]
                    cp = 3
                    cert_end = min(len(msg_body), 3 + certs_total_len)
                    while cp + 3 < cert_end:
                        c_len = struct.unpack("!I", b"\x00" + msg_body[cp:cp+3])[0]
                        cp += 3
                        if cp + c_len <= cert_end:
                            cert_bytes = msg_body[cp:cp+c_len]
                            analysis.raw_certificates_bytes.append(cert_bytes)
                        cp += c_len

            elif msg_type == 0x0E:  # ServerHelloDone
                analysis.handshake_completed = True

            b_idx += 4 + msg_len

    analyze_handshake = analyze_stream
