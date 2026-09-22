"""
SecureMailScope - XGBoost Cryptographic Risk Classifier & Real SHAP Explainability Engine
Trained on comprehensive multi-source real datasets (Wireshark Foundation captures +
EFF/Google STARTTLS Transparency empirical records + calibrated scenario fixtures).
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, accuracy_score
import xgboost as xgb

from securemailscope.core.config import config, DATA_DIR
from securemailscope.ml.feature_extractor import FeatureExtractor
from securemailscope.ml.dataset_generator import CLASS_NAMES
from securemailscope.ml.real_dataset_pipeline import RealDatasetPipeline

# Optional SHAP import
try:
    import shap as _shap_lib
    _SHAP_AVAILABLE = True
except ImportError:
    _shap_lib = None
    _SHAP_AVAILABLE = False

logger = logging.getLogger("securemailscope.ml.model")


class CryptoRiskClassifier:
    """
    Gradient-boosted tree model for identifying cryptographic anomalies.
    Trained on real PCAP captures, EFF transparency records, and calibrated scenario features.
    Uses real SHAP TreeExplainer for feature-level explanations when available.
    """
    _instance = None
    REPORT_PATH = DATA_DIR / "training_report.json"

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or config.ml_model_path
        self.model: Optional[xgb.XGBClassifier] = None
        self._shap_explainer = None
        self._training_report: Dict[str, Any] = {}
        self._load_or_train()

    @classmethod
    def get_instance(cls) -> "CryptoRiskClassifier":
        if cls._instance is None:
            cls._instance = CryptoRiskClassifier()
        return cls._instance

    def _load_or_train(self):
        if self.model_path.exists():
            try:
                self.model = xgb.XGBClassifier()
                self.model.load_model(str(self.model_path))
                self._init_shap_explainer()
                if self.REPORT_PATH.exists():
                    try:
                        self._training_report = json.loads(self.REPORT_PATH.read_text())
                    except Exception:
                        pass
                return
            except Exception as e:
                logger.warning(f"Could not load existing model from {self.model_path}: {e}")
        self.train_and_save()

    def _init_shap_explainer(self):
        """Initialize SHAP TreeExplainer if SHAP is available."""
        if _SHAP_AVAILABLE and self.model is not None:
            try:
                self._shap_explainer = _shap_lib.TreeExplainer(self.model)
            except Exception as e:
                logger.warning(f"SHAP TreeExplainer initialization failed: {e}")
                self._shap_explainer = None

    def train_and_save(self, num_synthetic: int = 1600) -> Dict[str, Any]:
        """
        Trains XGBoost on the comprehensive real dataset pipeline,
        evaluates performance metrics with stratified test split, and persists the model.
        """
        logger.info("Building real dataset training set...")
        X, y, stats = RealDatasetPipeline.build_comprehensive_training_set(num_synthetic=num_synthetic)
        X_arr = np.array(X)
        y_arr = np.array(y)

        # 80/20 Stratified Train/Test Split
        X_train, X_test, y_train, y_test = train_test_split(
            X_arr, y_arr, test_size=0.20, random_state=42, stratify=y_arr
        )

        self.model = xgb.XGBClassifier(
            n_estimators=120,
            max_depth=5,
            learning_rate=0.08,
            objective="multi:softprob",
            num_class=len(CLASS_NAMES),
            random_state=42,
            eval_metric="mlogloss"
        )
        self.model.fit(X_train, y_train)

        # Save model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save_model(str(self.model_path))
        self._init_shap_explainer()

        # Evaluate test metrics
        y_pred = self.model.predict(X_test)
        acc = float(accuracy_score(y_test, y_pred))
        p_wt, r_wt, f1_wt, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted", zero_division=0
        )
        p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
            y_test, y_pred, average="macro", zero_division=0
        )
        p_class, r_class, f1_class, supp_class = precision_recall_fscore_support(
            y_test, y_pred, average=None, zero_division=0, labels=list(range(len(CLASS_NAMES)))
        )

        per_class_metrics = {}
        for idx, c_name in enumerate(CLASS_NAMES):
            per_class_metrics[c_name] = {
                "precision": round(float(p_class[idx]), 4),
                "recall": round(float(r_class[idx]), 4),
                "f1_score": round(float(f1_class[idx]), 4),
                "support": int(supp_class[idx])
            }

        importances = self.model.feature_importances_
        feat_imp = {
            FeatureExtractor.FEATURE_NAMES[i]: float(round(importances[i], 4))
            for i in range(len(FeatureExtractor.FEATURE_NAMES))
        }

        self._training_report = {
            "status": "TRAINED",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "model_version": "CryptoRiskClassifier-v2-RealData",
            "classes": CLASS_NAMES,
            "dataset_stats": stats,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "metrics": {
                "accuracy": round(acc, 4),
                "precision_weighted": round(float(p_wt), 4),
                "recall_weighted": round(float(r_wt), 4),
                "f1_weighted": round(float(f1_wt), 4),
                "macro_f1": round(float(f1_macro), 4)
            },
            "per_class_metrics": per_class_metrics,
            "feature_importances": feat_imp,
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
        }

        try:
            self.REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.REPORT_PATH.write_text(json.dumps(self._training_report, indent=2))
        except Exception as e:
            logger.warning(f"Could not persist training report: {e}")

        return self._training_report

    def get_training_report(self) -> Dict[str, Any]:
        """Returns the latest training evaluation report and dataset statistics."""
        if not self._training_report and self.REPORT_PATH.exists():
            try:
                self._training_report = json.loads(self.REPORT_PATH.read_text())
            except Exception:
                pass
        return self._training_report or {"status": "UNINITIALIZED"}

    def _compute_shap_values(self, X_test: np.ndarray, pred_class_idx: int) -> Dict[str, Any]:
        """Compute real SHAP values using TreeExplainer for XGBoost multiclass."""
        if not _SHAP_AVAILABLE:
            return {
                "explanation_available": False,
                "reason": "SHAP library not installed. Install with: pip install shap"
            }
        if self._shap_explainer is None:
            return {
                "explanation_available": False,
                "reason": "SHAP explainer not initialized."
            }
        try:
            shap_values = self._shap_explainer.shap_values(X_test)
            sv = np.array(shap_values)
            if sv.ndim == 3:
                class_shap = sv[0, :, pred_class_idx]
            elif sv.ndim == 2:
                class_shap = sv[0]
            elif isinstance(shap_values, list):
                class_shap = np.array(shap_values[pred_class_idx])[0]
            else:
                class_shap = sv.flatten()[:len(FeatureExtractor.FEATURE_NAMES)]

            contributors = []
            for idx, fname in enumerate(FeatureExtractor.FEATURE_NAMES):
                sv_val = float(class_shap[idx]) if idx < len(class_shap) else 0.0
                fv = float(X_test[0][idx])
                contributors.append({
                    "feature": fname,
                    "value": fv,
                    "shap_value": round(sv_val, 4),
                    "contribution": round(abs(sv_val), 4),
                    "direction": "risk" if sv_val > 0 else "safe"
                })
            contributors.sort(key=lambda x: x["contribution"], reverse=True)

            return {
                "explanation_available": True,
                "method": "shap.TreeExplainer",
                "top_contributors": contributors[:5],
                "all_contributors": contributors
            }
        except Exception as e:
            return {
                "explanation_available": False,
                "reason": f"SHAP computation failed: {e}"
            }

    def predict_risk(self, forensic_context: Dict[str, Any]) -> Dict[str, Any]:
        if self.model is None:
            self._load_or_train()

        feat_dict = FeatureExtractor.extract_features(forensic_context)
        feat_vec = FeatureExtractor.to_vector(feat_dict)
        X_test = np.array([feat_vec])

        probs = self.model.predict_proba(X_test)[0]
        pred_class_idx = int(np.argmax(probs))
        pred_class_name = CLASS_NAMES[pred_class_idx]
        confidence = float(probs[pred_class_idx])

        # Overall risk probability (probability of not being baseline secure)
        secure_prob = float(probs[0])
        risk_probability = float(round(1.0 - secure_prob, 4))

        # Real SHAP explanations
        shap_result = self._compute_shap_values(X_test, pred_class_idx)

        return {
            "predicted_class": pred_class_name,
            "class_confidence": round(confidence, 4),
            "risk_probability": risk_probability,
            "is_anomalous": pred_class_name != "SECURE_BASELINE",
            "class_probabilities": {CLASS_NAMES[i]: round(float(probs[i]), 4) for i in range(len(CLASS_NAMES))},
            "top_features": shap_result.get("top_contributors", []),
            "extracted_features": feat_dict,
            "shap": shap_result,
            "model_version": "CryptoRiskClassifier-v2-RealData",
            "feature_schema_version": "v1"
        }
