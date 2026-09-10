"""
Unit tests for Deterministic Cryptographic Rule Engine
"""
from securemailscope.forensics.rules import CryptoRuleEngine


def test_rule_deprecated_tls():
    ctx = {
        "tls": {"negotiated_version": "TLS 1.0", "handshake_observed": True},
        "smtp": {}, "imap": {}, "pop3": {}, "certificate": {}
    }
    rules = CryptoRuleEngine.evaluate(ctx)
    triggered = [r.rule_id for r in rules if r.triggered]
    assert "RULE-TLS-DEPRECATED" in triggered


def test_rule_broken_cipher_rc4():
    ctx = {
        "tls": {
            "negotiated_version": "TLS 1.2",
            "selected_cipher": {"name": "TLS_RSA_WITH_RC4_128_MD5", "strength": "BROKEN", "kex": "RSA"},
            "handshake_observed": True,
            "has_forward_secrecy": False
        },
        "smtp": {}, "imap": {}, "pop3": {}, "certificate": {}
    }
    rules = CryptoRuleEngine.evaluate(ctx)
    triggered = [r.rule_id for r in rules if r.triggered]
    assert "RULE-CIPHER-BROKEN" in triggered
    assert "RULE-NO-PFS" in triggered


def test_rule_starttls_plaintext_violation():
    ctx = {
        "tls": {},
        "smtp": {"plaintext_after_starttls": True},
        "imap": {}, "pop3": {}, "certificate": {}
    }
    rules = CryptoRuleEngine.evaluate(ctx)
    triggered = [r.rule_id for r in rules if r.triggered]
    assert "RULE-STARTTLS-PLAINTEXT-VIOLATION" in triggered
