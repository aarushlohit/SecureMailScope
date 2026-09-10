"""
SecureMailScope - SMTP Protocol State Machine & STARTTLS Engine
"""
from enum import Enum
from typing import Dict, Any, List, Optional
from securemailscope.forensics.tcp_stream import TCPStream


class SMTPState(str, Enum):
    CONNECTED = "CONNECTED"
    GREETING = "GREETING"
    EHLO = "EHLO"
    CAPABILITY_DISCOVERY = "CAPABILITY_DISCOVERY"
    STARTTLS_ADVERTISED = "STARTTLS_ADVERTISED"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    STARTTLS_ACCEPTED = "STARTTLS_ACCEPTED"
    TLS_NEGOTIATION = "TLS_NEGOTIATION"
    ENCRYPTED = "ENCRYPTED"
    PLAINTEXT_FALLBACK = "PLAINTEXT_FALLBACK"
    AUTH = "AUTH"
    MAIL_TRANSACTION = "MAIL_TRANSACTION"
    TERMINATED = "TERMINATED"


class SMTPAnalysisResult:
    def __init__(self):
        self.states_traversed: List[SMTPState] = []
        self.banner: str = ""
        self.client_ehlo: str = ""
        self.advertised_extensions: List[str] = []
        self.starttls_advertised: bool = False
        self.starttls_requested: bool = False
        self.starttls_accepted: bool = False
        self.starttls_stripped: bool = False
        self.tls_handshake_observed: bool = False
        self.plaintext_after_starttls: bool = False
        self.auth_in_plaintext: bool = False
        self.mail_from: Optional[str] = None
        self.rcpt_to: List[str] = []
        self.anomalies: List[str] = []
        self.transition_log: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "states_traversed": [s.value for s in self.states_traversed],
            "banner": self.banner,
            "client_ehlo": self.client_ehlo,
            "advertised_extensions": self.advertised_extensions,
            "starttls_advertised": self.starttls_advertised,
            "starttls_requested": self.starttls_requested,
            "starttls_accepted": self.starttls_accepted,
            "starttls_stripped": self.starttls_stripped,
            "tls_handshake_observed": self.tls_handshake_observed,
            "plaintext_after_starttls": self.plaintext_after_starttls,
            "auth_in_plaintext": self.auth_in_plaintext,
            "mail_from": self.mail_from,
            "rcpt_to": self.rcpt_to,
            "anomalies": self.anomalies,
            "transition_log": self.transition_log
        }


class SMTPAnalyzer:
    """
    Analyzes an SMTP TCP stream to track protocol state transitions,
    STARTTLS negotiation, plaintext continuation, and stripping attacks.
    """

    @staticmethod
    def analyze_stream(stream: TCPStream) -> SMTPAnalysisResult:
        result = SMTPAnalysisResult()
        current_state = SMTPState.CONNECTED
        result.states_traversed.append(current_state)

        for segment in stream.segments:
            raw = segment.payload
            if not raw:
                continue

            # Check if this segment is binary TLS record (ContentType 0x16 Handshake)
            if len(raw) >= 5 and raw[0] == 0x16 and raw[1] == 0x03:
                result.tls_handshake_observed = True
                if current_state in (SMTPState.STARTTLS_ACCEPTED, SMTPState.STARTTLS_REQUESTED):
                    current_state = SMTPState.TLS_NEGOTIATION
                    result.states_traversed.append(current_state)
                continue
            elif len(raw) >= 5 and raw[0] in (0x17, 0x14, 0x15) and raw[1] == 0x03:
                # TLS Application Data or ChangeCipherSpec
                current_state = SMTPState.ENCRYPTED
                if SMTPState.ENCRYPTED not in result.states_traversed:
                    result.states_traversed.append(current_state)
                continue

            # Plaintext text line parsing
            lines = raw.decode("latin-1", errors="ignore").splitlines()
            for line in lines:
                line_clean = line.strip()
                if not line_clean:
                    continue

                if segment.direction == "SERVER_TO_CLIENT":
                    if line_clean.startswith("220") and current_state == SMTPState.CONNECTED:
                        result.banner = line_clean
                        current_state = SMTPState.GREETING
                        result.states_traversed.append(current_state)
                        result.transition_log.append({"state": current_state.value, "line": line_clean, "dir": "S->C"})

                    elif line_clean.startswith("250"):
                        if "STARTTLS" in line_clean.upper():
                            result.starttls_advertised = True
                            if SMTPState.STARTTLS_ADVERTISED not in result.states_traversed:
                                current_state = SMTPState.STARTTLS_ADVERTISED
                                result.states_traversed.append(current_state)
                        
                        # Collect capabilities
                        if "-" in line_clean or " " in line_clean:
                            parts = line_clean.split(maxsplit=1)
                            if len(parts) > 1:
                                result.advertised_extensions.append(parts[1].strip())
                        
                        result.transition_log.append({"state": current_state.value, "line": line_clean, "dir": "S->C"})

                    elif line_clean.startswith("220") and current_state == SMTPState.STARTTLS_REQUESTED:
                        # 220 2.0.0 Ready to start TLS
                        result.starttls_accepted = True
                        current_state = SMTPState.STARTTLS_ACCEPTED
                        result.states_traversed.append(current_state)
                        result.transition_log.append({"state": current_state.value, "line": line_clean, "dir": "S->C"})

                elif segment.direction == "CLIENT_TO_SERVER":
                    upper = line_clean.upper()
                    if upper.startswith("EHLO") or upper.startswith("HELO"):
                        result.client_ehlo = line_clean
                        current_state = SMTPState.EHLO
                        result.states_traversed.append(current_state)
                        result.transition_log.append({"state": current_state.value, "line": line_clean, "dir": "C->S"})

                    elif upper.startswith("STARTTLS"):
                        result.starttls_requested = True
                        current_state = SMTPState.STARTTLS_REQUESTED
                        result.states_traversed.append(current_state)
                        result.transition_log.append({"state": current_state.value, "line": line_clean, "dir": "C->S"})

                    elif upper.startswith("AUTH"):
                        if current_state != SMTPState.ENCRYPTED:
                            result.auth_in_plaintext = True
                            result.anomalies.append("Cleartext SMTP AUTH attempted over unencrypted channel.")
                        current_state = SMTPState.AUTH
                        result.states_traversed.append(current_state)
                        result.transition_log.append({"state": current_state.value, "line": "AUTH ***", "dir": "C->S"})

                    elif upper.startswith("MAIL FROM:"):
                        result.mail_from = line_clean
                        if current_state in (SMTPState.STARTTLS_ACCEPTED, SMTPState.STARTTLS_REQUESTED) or (
                            result.starttls_accepted and not result.tls_handshake_observed
                        ):
                            result.plaintext_after_starttls = True
                            current_state = SMTPState.PLAINTEXT_FALLBACK
                            result.states_traversed.append(current_state)
                            result.anomalies.append("Plaintext MAIL FROM command observed after STARTTLS negotiation.")
                        else:
                            current_state = SMTPState.MAIL_TRANSACTION
                            result.states_traversed.append(current_state)
                        result.transition_log.append({"state": current_state.value, "line": line_clean, "dir": "C->S"})

                    elif upper.startswith("RCPT TO:"):
                        result.rcpt_to.append(line_clean)
                        if result.starttls_accepted and not result.tls_handshake_observed:
                            result.plaintext_after_starttls = True
                        result.transition_log.append({"state": current_state.value, "line": line_clean, "dir": "C->S"})

        # Final anomaly checks
        if result.starttls_advertised and not result.starttls_requested and not result.tls_handshake_observed:
            if result.mail_from or result.auth_in_plaintext:
                result.anomalies.append("Client bypassed advertised STARTTLS; sent credentials/mail in cleartext.")

        if result.starttls_requested and result.starttls_accepted and not result.tls_handshake_observed:
            result.anomalies.append("STARTTLS accepted by server, but TLS ClientHello was absent; connection fell back to plaintext.")

        return result
