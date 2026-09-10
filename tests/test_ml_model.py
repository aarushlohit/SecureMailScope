"""
Unit tests for ML Classifier and Feature Extractor
"""
from securemailscope.ml.feature_extractor import FeatureExtractor
from securemailscope.ml.model import CryptoRiskClassifier
from securemailscope.ml.benchmark import BenchmarkEngine


def test_feature_extractor():
    ctx = {
        "tls": {"negotiated_version": "TLS 1.2", "has_forward_secrecy": True, "selected_cipher": {"strength": "STRONG"}},
        "smtp": {"starttls_advertised": True, "starttls_requested": True, "plaintext_after_starttls": False},
        "imap": {}, "pop3": {}, "certificate": {"public_key_bits": 2048, "is_expired": False},
        "completeness": {"completeness_percentage": 99.6},
        "stream": {"total_bytes": 3500}
    }
    feats = FeatureExtractor.extract_features(ctx)
    assert feats["tls_version_num"] == 1.2
    assert feats["has_pfs"] == 1.0
    assert feats["capture_completeness"] == 99.6
    vec = FeatureExtractor.to_vector(feats)
    assert len(vec) == len(FeatureExtractor.FEATURE_NAMES)


def test_ml_risk_classifier_inference():
    clf = CryptoRiskClassifier.get_instance()
    ctx_secure = {
        "tls": {"negotiated_version": "TLS 1.3", "has_forward_secrecy": True, "selected_cipher": {"strength": "STRONG"}},
        "smtp": {"starttls_advertised": True, "starttls_requested": True, "plaintext_after_starttls": False},
        "imap": {}, "pop3": {}, "certificate": {},
        "completeness": {"completeness_percentage": 100.0}
    }
    res_secure = clf.predict_risk(ctx_secure)
    assert "predicted_class" in res_secure
    assert "risk_probability" in res_secure

    ctx_attack = {
        "tls": {},
        "smtp": {"starttls_advertised": True, "starttls_requested": True, "plaintext_after_starttls": True},
        "imap": {}, "pop3": {}, "certificate": {},
        "completeness": {"completeness_percentage": 99.6}
    }
    res_attack = clf.predict_risk(ctx_attack)
    assert res_attack["risk_probability"] > 0.5


def test_benchmark_engine():
    res = BenchmarkEngine.evaluate_benchmark(num_samples=200)
    assert "rule_only_baseline" in res
    assert "rule_plus_ml" in res
    assert res["rule_plus_ml"]["accuracy"] >= res["rule_only_baseline"]["accuracy"]
