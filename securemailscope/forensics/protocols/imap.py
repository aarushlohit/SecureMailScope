"""
SecureMailScope - IMAP Protocol State Machine & STARTTLS Engine
"""
from typing import Dict, Any, List, Optional
from securemailscope.forensics.tcp_stream import TCPStream


class IMAPAnalysisResult:
    def __init__(self):
        self.banner: str = ""
        self.capabilities: List[str] = []
        self.starttls_advertised: bool = False
        self.starttls_requested: bool = False
        self.starttls_accepted: bool = False
        self.tls_handshake_observed: bool = False
        self.plaintext_after_starttls: bool = False
        self.auth_in_plaintext: bool = False
        self.anomalies: List[str] = []
        self.transition_log: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "banner": self.banner,
            "capabilities": self.capabilities,
            "starttls_advertised": self.starttls_advertised,
            "starttls_requested": self.starttls_requested,
            "starttls_accepted": self.starttls_accepted,
            "tls_handshake_observed": self.tls_handshake_observed,
            "plaintext_after_starttls": self.plaintext_after_starttls,
            "auth_in_plaintext": self.auth_in_plaintext,
            "anomalies": self.anomalies,
            "transition_log": self.transition_log
        }


class IMAPAnalyzer:
    """
    Analyzes an IMAP TCP stream (e.g. port 143/993) to track CAPABILITY,
    STARTTLS commands, OK responses, TLS transitions, and plain text auth.
    """

    @staticmethod
    def analyze_stream(stream: TCPStream) -> IMAPAnalysisResult:
        result = IMAPAnalysisResult()

        for segment in stream.segments:
            raw = segment.payload
            if not raw:
                continue

            # Check if binary TLS record
            if len(raw) >= 5 and raw[0] == 0x16 and raw[1] == 0x03:
                result.tls_handshake_observed = True
                continue

            lines = raw.decode("latin-1", errors="ignore").splitlines()
            for line in lines:
                line_clean = line.strip()
                if not line_clean:
                    continue

                if segment.direction == "SERVER_TO_CLIENT":
                    if line_clean.startswith("* OK") and not result.banner:
                        result.banner = line_clean
                        if "STARTTLS" in line_clean.upper():
                            result.starttls_advertised = True
                        result.transition_log.append({"type": "BANNER", "line": line_clean, "dir": "S->C"})

                    elif "CAPABILITY" in line_clean.upper():
                        caps = line_clean.split()
                        for c in caps:
                            if c.upper() == "STARTTLS":
                                result.starttls_advertised = True
                            if c not in ("*", "CAPABILITY", "OK"):
                                result.capabilities.append(c)
                        result.transition_log.append({"type": "CAPABILITY", "line": line_clean, "dir": "S->C"})

                    elif "OK" in line_clean.upper() and ("BEGIN TLS" in line_clean.upper() or "STARTTLS" in line_clean.upper() or result.starttls_requested):
                        result.starttls_accepted = True
                        result.transition_log.append({"type": "STARTTLS_ACCEPTED", "line": line_clean, "dir": "S->C"})

                elif segment.direction == "CLIENT_TO_SERVER":
                    parts = line_clean.split()
                    cmd = parts[1].upper() if len(parts) > 1 else parts[0].upper()

                    if cmd == "STARTTLS":
                        result.starttls_requested = True
                        result.transition_log.append({"type": "STARTTLS_REQUESTED", "line": line_clean, "dir": "C->S"})

                    elif cmd in ("LOGIN", "AUTHENTICATE"):
                        if not result.tls_handshake_observed:
                            result.auth_in_plaintext = True
                            result.anomalies.append("Cleartext IMAP LOGIN / AUTH command observed over unencrypted channel.")
                        result.transition_log.append({"type": "AUTH", "line": f"{parts[0]} {cmd} ***", "dir": "C->S"})

                    elif cmd in ("SELECT", "FETCH", "LIST") and result.starttls_accepted and not result.tls_handshake_observed:
                        result.plaintext_after_starttls = True
                        result.anomalies.append(f"IMAP {cmd} command issued in plaintext after STARTTLS negotiation.")
                        result.transition_log.append({"type": "COMMAND_FALLBACK", "line": line_clean, "dir": "C->S"})

        return result
