"""
SecureMailScope - POP3 Protocol State Machine & STLS Engine
"""
from typing import Dict, Any, List, Optional
from securemailscope.forensics.tcp_stream import TCPStream


class POP3AnalysisResult:
    def __init__(self):
        self.banner: str = ""
        self.stls_advertised: bool = False
        self.stls_requested: bool = False
        self.stls_accepted: bool = False
        self.tls_handshake_observed: bool = False
        self.plaintext_after_stls: bool = False
        self.auth_in_plaintext: bool = False
        self.anomalies: List[str] = []
        self.transition_log: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "banner": self.banner,
            "stls_advertised": self.stls_advertised,
            "stls_requested": self.stls_requested,
            "stls_accepted": self.stls_accepted,
            "tls_handshake_observed": self.tls_handshake_observed,
            "plaintext_after_stls": self.plaintext_after_stls,
            "auth_in_plaintext": self.auth_in_plaintext,
            "anomalies": self.anomalies,
            "transition_log": self.transition_log
        }


class POP3Analyzer:
    """
    Analyzes a POP3 TCP stream (e.g. port 110/995) to track CAPA,
    STLS commands, +OK responses, TLS transitions, and plain text credentials.
    """

    @staticmethod
    def analyze_stream(stream: TCPStream) -> POP3AnalysisResult:
        result = POP3AnalysisResult()

        for segment in stream.segments:
            raw = segment.payload
            if not raw:
                continue

            if len(raw) >= 5 and raw[0] == 0x16 and raw[1] == 0x03:
                result.tls_handshake_observed = True
                continue

            lines = raw.decode("latin-1", errors="ignore").splitlines()
            for line in lines:
                line_clean = line.strip()
                if not line_clean:
                    continue

                if segment.direction == "SERVER_TO_CLIENT":
                    if line_clean.startswith("+OK") and not result.banner:
                        result.banner = line_clean
                        result.transition_log.append({"type": "BANNER", "line": line_clean, "dir": "S->C"})

                    elif "STLS" in line_clean.upper():
                        result.stls_advertised = True
                        result.transition_log.append({"type": "CAPA_STLS", "line": line_clean, "dir": "S->C"})

                    elif line_clean.startswith("+OK") and result.stls_requested:
                        result.stls_accepted = True
                        result.transition_log.append({"type": "STLS_ACCEPTED", "line": line_clean, "dir": "S->C"})

                elif segment.direction == "CLIENT_TO_SERVER":
                    upper = line_clean.upper()
                    if upper == "STLS":
                        result.stls_requested = True
                        result.transition_log.append({"type": "STLS_REQUESTED", "line": line_clean, "dir": "C->S"})

                    elif upper.startswith("USER") or upper.startswith("PASS") or upper.startswith("AUTH"):
                        if not result.tls_handshake_observed:
                            result.auth_in_plaintext = True
                            result.anomalies.append(f"Cleartext POP3 {line_clean.split()[0]} command sent over unencrypted channel.")
                        result.transition_log.append({"type": "AUTH", "line": f"{line_clean.split()[0]} ***", "dir": "C->S"})

                    elif upper.startswith("STAT") or upper.startswith("LIST") or upper.startswith("RETR"):
                        if result.stls_accepted and not result.tls_handshake_observed:
                            result.plaintext_after_stls = True
                            result.anomalies.append(f"POP3 {line_clean.split()[0]} command executed in plaintext after STLS negotiation.")
                        result.transition_log.append({"type": "COMMAND_FALLBACK", "line": line_clean, "dir": "C->S"})

        return result
