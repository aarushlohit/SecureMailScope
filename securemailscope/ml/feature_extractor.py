"""
SecureMailScope - Cryptographic Feature Extractor
"""
from typing import Dict, Any, List


class FeatureExtractor:
    """
    Extracts structured, tabular numerical and boolean features
    from forensic analysis objects for the Machine Learning engine.
    """
    FEATURE_NAMES = [
        "tls_version_num",
        "cipher_strength_score",
        "has_pfs",
        "cert_key_bits",
        "is_self_signed",
        "is_cert_expired",
        "has_weak_sig",
        "starttls_advertised",
        "starttls_requested",
        "starttls_accepted",
        "plaintext_after_starttls",
        "auth_in_plaintext",
        "capture_completeness",
        "handshake_rtt_ms",
        "stream_total_bytes"
    ]

    @staticmethod
    def extract_features(forensic_context: Dict[str, Any]) -> Dict[str, float]:
        tls = forensic_context.get("tls", {})
        smtp = forensic_context.get("smtp", {})
        imap = forensic_context.get("imap", {})
        pop3 = forensic_context.get("pop3", {})
        cert = forensic_context.get("certificate", {})
        completeness = forensic_context.get("completeness", {})
        stream = forensic_context.get("stream", {})

        # TLS Version
        ver_str = tls.get("negotiated_version")
        ver_map = {"TLS 1.3": 1.3, "TLS 1.2": 1.2, "TLS 1.1": 1.1, "TLS 1.0": 1.0, "SSL 3.0": 0.3}
        tls_ver = ver_map.get(ver_str, 0.0)

        # Cipher Strength
        sel_cipher = tls.get("selected_cipher") or {}
        c_strength_str = sel_cipher.get("strength", "UNKNOWN")
        c_strength_map = {"STRONG": 1.0, "MODERATE": 0.6, "WEAK": 0.3, "LEGACY": 0.2, "BROKEN": 0.0}
        cipher_strength = c_strength_map.get(c_strength_str, 0.5 if tls_ver >= 1.2 else 0.0)

        # PFS
        has_pfs = 1.0 if tls.get("has_forward_secrecy", False) else 0.0

        # Certificate Features
        cert_key_bits = float(cert.get("public_key_bits", 2048 if tls_ver >= 1.2 else 0))
        is_self_signed = 1.0 if cert.get("is_self_signed", False) else 0.0
        is_cert_expired = 1.0 if cert.get("is_expired", False) else 0.0
        has_weak_sig = 1.0 if cert.get("has_weak_signature", False) else 0.0

        # Protocol State Features
        st_adv = 1.0 if (smtp.get("starttls_advertised") or imap.get("starttls_advertised") or pop3.get("stls_advertised")) else 0.0
        st_req = 1.0 if (smtp.get("starttls_requested") or imap.get("starttls_requested") or pop3.get("stls_requested")) else 0.0
        st_acc = 1.0 if (smtp.get("starttls_accepted") or imap.get("starttls_accepted") or pop3.get("stls_accepted")) else 0.0
        pt_after = 1.0 if (smtp.get("plaintext_after_starttls") or imap.get("plaintext_after_starttls") or pop3.get("plaintext_after_stls")) else 0.0
        auth_pt = 1.0 if (smtp.get("auth_in_plaintext") or imap.get("auth_in_plaintext") or pop3.get("auth_in_plaintext")) else 0.0

        # Capture Quality
        comp_val = float(completeness.get("completeness_percentage", 100.0))
        rtt_val = float(tls.get("handshake_rtt_ms") or 45.0)
        bytes_val = float(stream.get("total_bytes", 1500))

        return {
            "tls_version_num": tls_ver,
            "cipher_strength_score": cipher_strength,
            "has_pfs": has_pfs,
            "cert_key_bits": cert_key_bits,
            "is_self_signed": is_self_signed,
            "is_cert_expired": is_cert_expired,
            "has_weak_sig": has_weak_sig,
            "starttls_advertised": st_adv,
            "starttls_requested": st_req,
            "starttls_accepted": st_acc,
            "plaintext_after_starttls": pt_after,
            "auth_in_plaintext": auth_pt,
            "capture_completeness": comp_val,
            "handshake_rtt_ms": rtt_val,
            "stream_total_bytes": bytes_val
        }

    @staticmethod
    def to_vector(feature_dict: Dict[str, float]) -> List[float]:
        return [feature_dict[name] for name in FeatureExtractor.FEATURE_NAMES]
