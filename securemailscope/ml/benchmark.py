"""
SecureMailScope - Rule-Only vs Rule+ML Benchmark Evaluation
"""
import numpy as np
from typing import Dict, Any, List
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
import xgboost as xgb
from securemailscope.ml.dataset_generator import DatasetGenerator, CLASS_NAMES
from securemailscope.ml.feature_extractor import FeatureExtractor


class BenchmarkEngine:
    """
    Evaluates and compares the forensic effectiveness of:
    1. Rule-Only Baseline
    2. Rule + ML (XGBoost) Augmented Engine
    Across precision, recall, F1, and confusion matrix.
    """

    @staticmethod
    def evaluate_benchmark(num_samples: int = 1000) -> Dict[str, Any]:
        X, y = DatasetGenerator.generate_tabular_dataset(num_samples=num_samples)
        X_arr = np.array(X)
        y_arr = np.array(y)

        X_train, X_test, y_train, y_test = train_test_split(X_arr, y_arr, test_size=0.25, random_state=42, stratify=y_arr)

        # 1. Rule-Only Baseline Model
        # A static rule detector that checks basic threshold conditions (e.g. tls_ver < 1.2 or pt_after == 1)
        y_pred_rule = []
        for row in X_test:
            # Feature indices:
            # 0: tls_version_num, 1: cipher_strength, 2: has_pfs, 3: cert_key_bits, 4: is_self_signed,
            # 5: is_cert_expired, 6: has_weak_sig, 7: st_adv, 8: st_req, 9: st_acc, 10: pt_after,
            # 11: auth_pt, 12: completeness, 13: rtt_ms, 14: stream_bytes
            tls_ver = row[0]
            c_strength = row[1]
            cert_bits = row[3]
            cert_exp = row[5]
            pt_after = row[10]
            completeness = row[12]

            # Rule heuristic:
            if pt_after > 0.5:
                pred = CLASS_NAMES.index("PLAINTEXT_FALLBACK")
            elif tls_ver in (1.0, 1.1) and tls_ver > 0:
                pred = CLASS_NAMES.index("DEPRECATED_TLS")
            elif c_strength == 0.0 and tls_ver > 0:
                pred = CLASS_NAMES.index("WEAK_CIPHER")
            elif cert_exp > 0.5 or cert_bits < 1024:
                pred = CLASS_NAMES.index("WEAK_CERTIFICATE")
            elif completeness < 60.0:
                pred = CLASS_NAMES.index("INCOMPLETE_HANDSHAKE")
            elif tls_ver >= 1.2 and c_strength >= 0.6:
                pred = CLASS_NAMES.index("SECURE_BASELINE")
            else:
                # Rules miss complex multi-feature subtle anomalies (e.g. STARTTLS stripping vs handshake drop)
                pred = CLASS_NAMES.index("STARTTLS_STRIPPING")
            y_pred_rule.append(pred)

        # 2. Rule + ML Engine (XGBoost trained on features)
        model = xgb.XGBClassifier(
            n_estimators=120,
            max_depth=5,
            learning_rate=0.08,
            objective="multi:softprob",
            num_class=len(CLASS_NAMES),
            random_state=42
        )
        model.fit(X_train, y_train)
        y_pred_ml = model.predict(X_test)

        # Compute Metrics
        p_rule, r_rule, f1_rule, _ = precision_recall_fscore_support(y_test, y_pred_rule, average="weighted", zero_division=0)
        p_ml, r_ml, f1_ml, _ = precision_recall_fscore_support(y_test, y_pred_ml, average="weighted", zero_division=0)

        cm_rule = confusion_matrix(y_test, y_pred_rule).tolist()
        cm_ml = confusion_matrix(y_test, y_pred_ml).tolist()

        # Feature importances from XGBoost
        raw_importances = model.feature_importances_
        feature_names = FeatureExtractor.FEATURE_NAMES
        top_features = []
        for name, score in sorted(zip(feature_names, raw_importances), key=lambda x: x[1], reverse=True)[:5]:
            top_features.append({
                "feature_name": name,
                "name": name,
                "importance": round(float(score), 4),
                "weight": round(float(score), 4)
            })

        rule_and_ml_dict = {
            "precision": round(float(p_ml), 4),
            "recall": round(float(r_ml), 4),
            "f1_score": round(float(f1_ml), 4),
            "accuracy": round(float(np.mean(y_pred_ml == y_test)), 4),
            "confusion_matrix": cm_ml
        }

        return {
            "total_samples": num_samples,
            "test_samples_count": len(y_test),
            "classes": CLASS_NAMES,
            "rule_only_baseline": {
                "precision": round(float(p_rule), 4),
                "recall": round(float(r_rule), 4),
                "f1_score": round(float(f1_rule), 4),
                "accuracy": round(float(np.mean(np.array(y_pred_rule) == y_test)), 4),
                "confusion_matrix": cm_rule
            },
            "rule_plus_ml": rule_and_ml_dict,
            "rule_and_ml_engine": rule_and_ml_dict,
            "ml_engine": rule_and_ml_dict,
            "top_features": top_features,
            "improvement": {
                "precision_gain": round(float(p_ml - p_rule) * 100, 2),
                "recall_gain": round(float(r_ml - r_rule) * 100, 2),
                "f1_gain": round(float(f1_ml - f1_rule) * 100, 2)
            }
        }
