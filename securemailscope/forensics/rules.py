"""
SecureMailScope - Deterministic Cryptographic Rule Engine
"""
from typing import Dict, Any, List, Optional
from securemailscope.evidence.models import SeverityLevel


class RuleEvaluation:
    def __init__(self, rule_id: str, title: str, description: str, severity: SeverityLevel, triggered: bool, details: Dict[str, Any], remediation: str):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.triggered = triggered
        self.details = details
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "triggered": self.triggered,
            "details": self.details,
            "remediation": self.remediation
        }


class CryptoRuleEngine:
    """
    Version-controlled, deterministic cryptographic rule engine.
    Evaluates protocol state, TLS handshakes, cipher suites, and certificates.
    """
    RULE_SET_VERSION = "2026.1"

    @classmethod
    def evaluate(cls, forensic_context: Dict[str, Any]) -> List[RuleEvaluation]:
        results: List[RuleEvaluation] = []
        tls_info = forensic_context.get("tls", {})
        smtp_info = forensic_context.get("smtp", {})
        imap_info = forensic_context.get("imap", {})
        pop3_info = forensic_context.get("pop3", {})
        cert_info = forensic_context.get("certificate", {})

        # Rule 1: Deprecated TLS Version
        neg_ver = tls_info.get("negotiated_version")
        if neg_ver in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
            results.append(RuleEvaluation(
                rule_id="RULE-TLS-DEPRECATED",
                title=f"Deprecated TLS Protocol ({neg_ver})",
                description=f"Connection negotiated {neg_ver}, which is officially deprecated by RFC 8996 and vulnerable to POODLE / BEAST attacks.",
                severity=SeverityLevel.HIGH,
                triggered=True,
                details={"negotiated_version": neg_ver},
                remediation="Upgrade server and client configuration to enforce TLS 1.2 or TLS 1.3 exclusively."
            ))

        # Rule 2: Broken Cipher Suite (e.g. RC4)
        sel_cipher = tls_info.get("selected_cipher") or {}
        cipher_name = sel_cipher.get("name", "")
        cipher_strength = sel_cipher.get("strength", "")
        if "RC4" in cipher_name or cipher_strength == "BROKEN":
            results.append(RuleEvaluation(
                rule_id="RULE-CIPHER-BROKEN",
                title=f"Cryptographically Broken Cipher ({cipher_name})",
                description="RC4 stream cipher is susceptible to keystream bias attacks (Bar Mitzvah attack).",
                severity=SeverityLevel.CRITICAL,
                triggered=True,
                details={"cipher": cipher_name},
                remediation="Disable RC4 cipher suites immediately in mail server configuration. Use AES-GCM or ChaCha20-Poly1305."
            ))

        # Rule 3: Legacy Cipher Suite (e.g. 3DES)
        if "3DES" in cipher_name or "DES" in cipher_name or cipher_strength == "LEGACY":
            results.append(RuleEvaluation(
                rule_id="RULE-CIPHER-LEGACY",
                title=f"Legacy 64-bit Block Cipher ({cipher_name})",
                description="3DES uses a 64-bit block size vulnerable to Sweet32 collision attacks.",
                severity=SeverityLevel.HIGH,
                triggered=True,
                details={"cipher": cipher_name},
                remediation="Disable 3DES cipher suites. Transition to modern 128/256-bit AEAD ciphers."
            ))

        # Rule 4: No Forward Secrecy (PFS)
        has_pfs = tls_info.get("has_forward_secrecy", False)
        if tls_info.get("handshake_observed") and not has_pfs and sel_cipher.get("kex") == "RSA":
            results.append(RuleEvaluation(
                rule_id="RULE-NO-PFS",
                title="Lack of Perfect Forward Secrecy (PFS)",
                description="Session uses static RSA key exchange. If the server private key is compromised in the future, past captured traffic can be decrypted.",
                severity=SeverityLevel.MEDIUM,
                triggered=True,
                details={"key_exchange": sel_cipher.get("kex", "RSA"), "cipher": cipher_name},
                remediation="Configure Ephemeral Diffie-Hellman (ECDHE or DHE) key exchange cipher suites."
            ))

        # Rule 5: STARTTLS Plaintext Continuation (CRITICAL)
        smtp_pt = smtp_info.get("plaintext_after_starttls", False)
        imap_pt = imap_info.get("plaintext_after_starttls", False)
        pop3_pt = pop3_info.get("plaintext_after_stls", False)
        if smtp_pt or imap_pt or pop3_pt:
            results.append(RuleEvaluation(
                rule_id="RULE-STARTTLS-PLAINTEXT-VIOLATION",
                title="STARTTLS Protocol Downgrade / Plaintext Continuation",
                description="STARTTLS was advertised and accepted, but the session fell back to plaintext transmission. Sensitive commands/credentials were exposed on the wire.",
                severity=SeverityLevel.CRITICAL,
                triggered=True,
                details={"smtp_violation": smtp_pt, "imap_violation": imap_pt, "pop3_violation": pop3_pt},
                remediation="Enforce mandatory TLS (Reject plaintext fallback) and enable MTA-STS / DANE DNSSEC records."
            ))

        # Rule 6: Cleartext Authentication Bypass
        auth_pt = smtp_info.get("auth_in_plaintext", False) or imap_info.get("auth_in_plaintext", False) or pop3_info.get("auth_in_plaintext", False)
        if auth_pt:
            results.append(RuleEvaluation(
                rule_id="RULE-CLEARTEXT-AUTH",
                title="Cleartext Authentication Transmitted",
                description="User credentials (LOGIN/AUTH/USER/PASS) were observed unencrypted across the network wire.",
                severity=SeverityLevel.HIGH,
                triggered=True,
                details={"auth_in_plaintext": True},
                remediation="Prohibit cleartext authentication over unencrypted ports. Require explicit STARTTLS before AUTH."
            ))

        # Rule 7: Expired or Invalid X.509 Certificate
        if cert_info.get("is_expired"):
            results.append(RuleEvaluation(
                rule_id="RULE-CERT-EXPIRED",
                title="Expired X.509 Certificate",
                description=f"Certificate expired on {cert_info.get('not_after')}.",
                severity=SeverityLevel.HIGH,
                triggered=True,
                details={"not_after": cert_info.get("not_after")},
                remediation="Renew and deploy a valid SSL/TLS certificate from an accredited Certificate Authority."
            ))

        # Rule 8: Weak Public Key
        if cert_info.get("has_weak_key"):
            results.append(RuleEvaluation(
                rule_id="RULE-KEY-WEAK",
                title=f"Weak Public Key Length ({cert_info.get('public_key_bits')} bits)",
                description=f"Public key size ({cert_info.get('public_key_bits')} bits) is insufficient against modern factorization capabilities.",
                severity=SeverityLevel.HIGH,
                triggered=True,
                details={"key_bits": cert_info.get("public_key_bits")},
                remediation="Generate new RSA keys with at least 2048 (preferably 4096) bits, or migrate to ECDSA (P-256/P-384)."
            ))

        # Rule 9: Weak Signature Algorithm
        if cert_info.get("has_weak_signature"):
            results.append(RuleEvaluation(
                rule_id="RULE-SIG-WEAK",
                title=f"Vulnerable Signature Algorithm ({cert_info.get('signature_algorithm')})",
                description="Certificate signed using deprecated hash function (MD5/SHA-1) vulnerable to collision forgery.",
                severity=SeverityLevel.HIGH,
                triggered=True,
                details={"signature_algorithm": cert_info.get("signature_algorithm")},
                remediation="Re-issue certificate using SHA-256 or SHA-384 signature algorithms."
            ))

        return results
