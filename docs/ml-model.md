# SecureMailScope — Machine Learning & SHAP Explainability Engine

## 1. Overview
SecureMailScope incorporates a gradient-boosted decision tree classifier (`CryptoRiskClassifier`) powered by XGBoost. The classifier acts as an auxiliary anomaly detector to capture subtle multi-feature cryptographic risk patterns across passive email conversations.

To avoid "black-box" predictions, the engine calculates real feature-level SHAP values using `shap.TreeExplainer`.

## 2. Feature Schema (`FeatureExtractor`)
The model extracts 15 numerical and binary features from passive forensic context:

| Feature Name | Type | Description |
|---|---|---|
| `tls_version_num` | Float | 0.0=None, 1.0=TLS 1.0, 1.1=TLS 1.1, 1.2=TLS 1.2, 1.3=TLS 1.3 |
| `is_tls_negotiated` | Binary | 1 if TLS handshake concluded |
| `starttls_advertised` | Binary | 1 if STARTTLS was offered in banner |
| `starttls_requested` | Binary | 1 if client issued STARTTLS |
| `starttls_accepted` | Binary | 1 if server acknowledged 220 Ready |
| `has_forward_secrecy`| Binary | 1 if ephemeral Diffie-Hellman used |
| `is_deprecated_tls` | Binary | 1 if TLS version < 1.2 |
| `is_broken_cipher` | Binary | 1 if RC4, 3DES, DES, or NULL cipher |
| `cert_is_expired` | Binary | 1 if certificate validity expired |
| `cert_is_self_signed`| Binary | 1 if subject equals issuer |
| `cert_key_size` | Float | Normalized RSA key length in bits |
| `stream_total_bytes` | Float | Log-normalized byte count |
| `packet_count` | Float | Total packets in TCP conversation |
| `cleartext_auth` | Binary | 1 if credentials observed in plaintext |
| `completeness_pct` | Float | Capture completeness percentage |

## 3. Classification Classes
The multi-class model predicts one of 5 distinct operational classes:
1. `SECURE_BASELINE`: TLS 1.2+ with forward secrecy, valid certificates, and no plaintext fallback.
2. `STARTTLS_STRIPPING`: STARTTLS advertised but bypassed in plaintext.
3. `DEPRECATED_CIPHER_SUITE`: Insecure or legacy cipher (RC4, 3DES) negotiated.
4. `EXPIRED_CERTIFICATE`: Observable X.509 certificate expired or self-signed.
5. `INCONCLUSIVE_DATA`: Capture quality too low or packets truncated.

## 4. SHAP TreeExplainer Attribution
When making an inference via `predict_risk()`:
1. `FeatureExtractor.extract_features()` normalizes input context.
2. The XGBoost model calculates class probabilities via `predict_proba()`.
3. `shap.TreeExplainer(self.model).shap_values(X_test)` computes exact Shapley values.
4. For the winning class, SHAP values are extracted across all 15 features.
5. Contributors are sorted by absolute SHAP contribution:
   - `direction: "risk"` if $SHAP > 0$ (increases risk probability)
   - `direction: "safe"` if $SHAP \le 0$ (reduces risk probability)
6. Returns the top 5 contributing features alongside the overall risk probability.

## 5. Scientific Benchmark (`BenchmarkEngine`)
The benchmark evaluates the empirical accuracy gain of combining deterministic rules with machine learning against a rule-only baseline:
- Uses `scikit-learn.model_selection.train_test_split` with stratification.
- Computes Precision, Recall, F1-Score, and Confusion Matrix.
- Verifiable via `python -m securemailscope.cli benchmark` or `GET /api/ml/benchmark`.
