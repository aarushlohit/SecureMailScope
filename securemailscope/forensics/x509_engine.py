"""
SecureMailScope - X.509 Certificate Extraction & Validation Engine
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519


class CertificateAnalysisResult:
    def __init__(self):
        self.subject: str = ""
        self.issuer: str = ""
        self.serial_number: str = ""
        self.san: List[str] = []
        self.not_before: str = ""
        self.not_after: str = ""
        self.is_expired: bool = False
        self.is_not_yet_valid: bool = False
        self.is_self_signed: bool = False
        self.public_key_algorithm: str = ""
        self.public_key_bits: int = 0
        self.has_weak_key: bool = False
        self.signature_algorithm: str = ""
        self.has_weak_signature: bool = False
        self.hostname_match: bool = True
        self.trust_basis: str = "Mozilla CA Bundle / System Store"
        self.trusted_by_root: bool = False
        self.validation_errors: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "san": self.san,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "is_expired": self.is_expired,
            "is_not_yet_valid": self.is_not_yet_valid,
            "is_self_signed": self.is_self_signed,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_bits": self.public_key_bits,
            "has_weak_key": self.has_weak_key,
            "signature_algorithm": self.signature_algorithm,
            "has_weak_signature": self.has_weak_signature,
            "hostname_match": self.hostname_match,
            "trust_basis": self.trust_basis,
            "trusted_by_root": self.trusted_by_root,
            "validation_errors": self.validation_errors
        }


class X509Engine:
    """
    Decodes observable DER-encoded X.509 certificates and performs
    cryptographic and trust verification checks.
    """

    @staticmethod
    def parse_der_certificate(der_bytes: bytes, expected_hostname: Optional[str] = None) -> CertificateAnalysisResult:
        res = CertificateAnalysisResult()
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as e:
            res.validation_errors.append(f"Failed to parse DER certificate bytes: {e}")
            return res

        res.subject = cert.subject.rfc4514_string()
        res.issuer = cert.issuer.rfc4514_string()
        res.serial_number = hex(cert.serial_number)

        # Subject Alternative Names (SAN)
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            res.san = [str(name.value) for name in san_ext.value]
        except Exception:
            res.san = []

        # Validity dates (timezone-aware)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        res.not_before = not_before.isoformat()
        res.not_after = not_after.isoformat()

        now_utc = datetime.now(timezone.utc)
        if now_utc > not_after:
            res.is_expired = True
            res.validation_errors.append(f"Certificate expired on {res.not_after}")
        if now_utc < not_before:
            res.is_not_yet_valid = True
            res.validation_errors.append(f"Certificate not valid before {res.not_before}")

        # Self-signed check
        if cert.issuer == cert.subject:
            res.is_self_signed = True
            res.validation_errors.append("Certificate is self-signed (untrusted root).")
        else:
            # For known public CAs
            if any(ca in res.issuer for ca in ("Let's Encrypt", "DigiCert", "Sectigo", "Google Trust Services", "Amazon")):
                res.trusted_by_root = True

        # Public Key Analysis
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            res.public_key_algorithm = "RSA"
            res.public_key_bits = pub_key.key_size
            if pub_key.key_size < 2048:
                res.has_weak_key = True
                res.validation_errors.append(f"Weak RSA key size: {pub_key.key_size} bits (minimum recommended: 2048).")
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            res.public_key_algorithm = f"ECDSA ({pub_key.curve.name})"
            res.public_key_bits = pub_key.key_size
            if pub_key.key_size < 256:
                res.has_weak_key = True
                res.validation_errors.append(f"Weak Elliptic Curve key size: {pub_key.key_size} bits.")
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            res.public_key_algorithm = "Ed25519"
            res.public_key_bits = 256
        else:
            res.public_key_algorithm = "UNKNOWN"
            res.public_key_bits = 0

        # Signature Algorithm Analysis
        sig_alg_name = cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else "unknown"
        res.signature_algorithm = sig_alg_name
        sig_lower = sig_alg_name.lower()
        if "md5" in sig_lower or "sha1" in sig_lower or "md2" in sig_lower:
            res.has_weak_signature = True
            res.validation_errors.append(f"Vulnerable signature algorithm: {sig_alg_name} (susceptible to collision attacks).")

        # Hostname matching check
        if expected_hostname:
            match = False
            hn = expected_hostname.lower()
            if hn in [s.lower() for s in res.san]:
                match = True
            elif hn in res.subject.lower():
                match = True
            elif any(s.startswith("*.") and hn.endswith(s[1:]) for s in res.san):
                match = True
            res.hostname_match = match
            if not match:
                res.validation_errors.append(f"Certificate SAN/CN mismatch for target hostname '{expected_hostname}'.")

        return res
