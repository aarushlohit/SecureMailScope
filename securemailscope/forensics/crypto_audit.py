"""
SecureMailScope - Advanced Cryptographic & Forensic Audit Helpers
Audits cipher suites, key exchange strength, certificate revocation status,
evidence contradictions, and posture scoring.
"""
from typing import Dict, Any, List


class CryptoAuditor:
    """Evaluates cryptographic primitives and posture risk levels."""

    @staticmethod
    def evaluate_cipher_suite(cipher_name: str) -> Dict[str, Any]:
        c_upper = (cipher_name or "").upper()
        is_weak = any(w in c_upper for w in ("RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "ANON"))
        has_pfs = any(k in c_upper for k in ("ECDHE", "DHE", "CHACHA20", "GCM"))
        
        score = 0
        if "AES_256_GCM" in c_upper or "CHACHA20" in c_upper:
            score = 100
        elif "AES_128_GCM" in c_upper:
            score = 90
        elif "CBC" in c_upper:
            score = 50
        elif is_weak:
            score = 10

        return {
            "cipher_name": cipher_name,
            "is_weak": is_weak,
            "has_forward_secrecy": has_pfs,
            "security_score": score,
            "recommendation": "Migrate to TLS 1.3 with AES-256-GCM / CHACHA20-POLY1305" if is_weak or score < 80 else "Cipher suite meets modern cryptographic standards"
        }

    @staticmethod
    def audit_key_exchange(tls_version: str, selected_cipher: str) -> Dict[str, Any]:
        ver = str(tls_version or "").upper()
        c = str(selected_cipher or "").upper()

        if "1.3" in ver:
            return {"status": "SECURE", "key_exchange": "ECDHE (X25519/SECP256R1)", "bit_strength": 256, "forward_secrecy": True}
        elif "ECDHE" in c:
            return {"status": "ACCEPTABLE", "key_exchange": "ECDHE", "bit_strength": 256, "forward_secrecy": True}
        elif "DHE" in c:
            return {"status": "ACCEPTABLE", "key_exchange": "DHE", "bit_strength": 2048, "forward_secrecy": True}
        elif "RSA" in c:
            return {"status": "INSECURE", "key_exchange": "Static RSA (No Forward Secrecy)", "bit_strength": 2048, "forward_secrecy": False}
        return {"status": "UNKNOWN", "key_exchange": "Unknown", "bit_strength": 0, "forward_secrecy": False}

    @staticmethod
    def detect_contradictions(evidence_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Scans evidence claims for logical contradictions (e.g. claim of TLS 1.3 alongside cleartext payload).
        """
        has_tls13 = any("TLS 1.3" in str(e.get("claim", "")) for e in evidence_items)
        has_cleartext = any("cleartext" in str(e.get("claim", "")).lower() or "stripping" in str(e.get("claim", "")).lower() for e in evidence_items)

        contradictions = []
        if has_tls13 and has_cleartext:
            contradictions.append({
                "type": "CONFIDENTIALITY_CONTRADICTION",
                "detail": "Simultaneous evidence of TLS 1.3 session alongside plaintext email commands detected."
            })

        return {
            "has_contradictions": len(contradictions) > 0,
            "contradiction_count": len(contradictions),
            "contradictions": contradictions
        }
