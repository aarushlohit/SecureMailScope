"""
Unit tests for SecureMailScope Forensic Engines
"""
import pytest
from pathlib import Path
from securemailscope.core.config import SAMPLES_DIR
from securemailscope.forensics.capture import CaptureEngine
from securemailscope.forensics.tcp_stream import TCPReconstructionEngine
from securemailscope.forensics.protocols.smtp import SMTPAnalyzer
from securemailscope.forensics.tls_engine import TLSEngine
from securemailscope.forensics.rules import CryptoRuleEngine


def test_capture_inspection():
    pcap = SAMPLES_DIR / "mail_secure_tls13.pcap"
    meta = CaptureEngine.inspect_capture(pcap)
    assert meta["packet_count"] > 0
    assert len(meta["artifact_sha256"]) == 64
    assert meta["completeness"]["completeness_percentage"] > 0


def test_tcp_reconstruction_smtp():
    pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"
    streams = TCPReconstructionEngine.reconstruct_streams(str(pcap))
    assert len(streams) > 0
    s0 = streams[0]
    assert s0.protocol_hint == "SMTP"
    assert len(s0.segments) > 0


def test_smtp_analyzer_starttls_anomaly():
    pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"
    streams = TCPReconstructionEngine.reconstruct_streams(str(pcap))
    res = SMTPAnalyzer.analyze_stream(streams[0])
    assert res.starttls_advertised is True
    assert res.starttls_requested is True
    assert res.plaintext_after_starttls is True
    assert len(res.anomalies) > 0


def test_tls_engine_tls13_handshake():
    pcap = SAMPLES_DIR / "mail_secure_tls13.pcap"
    streams = TCPReconstructionEngine.reconstruct_streams(str(pcap))
    tls_res = TLSEngine.analyze_stream(streams[0])
    assert tls_res.handshake_observed is True
    assert tls_res.negotiated_version == "TLS 1.3"
    assert tls_res.certificate_observable is False  # Explicit TLS 1.3 passive limitation
    assert tls_res.has_forward_secrecy is True


def test_tls_engine_tls10_weak_cipher():
    pcap = SAMPLES_DIR / "mail_weak_crypto_tls10_rc4.pcap"
    streams = TCPReconstructionEngine.reconstruct_streams(str(pcap))
    tls_res = TLSEngine.analyze_stream(streams[0])
    assert tls_res.negotiated_version == "TLS 1.0"
    assert tls_res.selected_cipher["symmetric"] == "RC4"
    assert tls_res.has_forward_secrecy is False
