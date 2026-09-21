"""
SecureMailScope - XGBoost Cryptographic Risk Classifier & Real SHAP Explainability Engine
"""
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional
import xgboost as xgb
from securemailscope.core.config import config
from securemailscope.ml.feature_extractor import FeatureExtractor
from securemailscope.ml.dataset_generator import DatasetGenerator, CLASS_NAMES

# Optional SHAP import
try:
    import shap as _shap_lib
    _SHAP_AVAILABLE = True
except ImportError:
    _shap_lib = None
    _SHAP_AVAILABLE = False


class CryptoRiskClassifier:
    """
    Gradient-boosted tree model for identifying cryptographic anomalies.
    Uses real SHAP TreeExplainer for feature-level explanations when available.
    """
    _instance = None

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or config.ml_model_path
        self.model: Optional[xgb.XGBClassifier] = None
        self._shap_explainer = None
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
                return
            except Exception:
                pass
        self.train_and_save()

    def _init_shap_explainer(self):
        """Initialize SHAP TreeExplainer if SHAP is available."""
        if _SHAP_AVAILABLE and self.model is not None:
            try:
                self._shap_explainer = _shap_lib.TreeExplainer(self.model)
            except Exception:
                self._shap_explainer = None

    def train_and_save(self) -> Dict[str, Any]:
        X, y = DatasetGenerator.generate_tabular_dataset(num_samples=1200)
        X_arr = np.array(X)
        y_arr = np.array(y)

        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.08,
            objective="multi:softprob",
            num_class=len(CLASS_NAMES),
            random_state=42,
            eval_metric="mlogloss"
        )
        self.model.fit(X_arr, y_arr)

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save_model(str(self.model_path))
        self._init_shap_explainer()

        importances = self.model.feature_importances_
        feat_imp = {
            FeatureExtractor.FEATURE_NAMES[i]: float(round(importances[i], 4))
            for i in range(len(FeatureExtractor.FEATURE_NAMES))
        }
        return {"status": "TRAINED", "classes": CLASS_NAMES, "feature_importances": feat_imp}

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
            # XGBoost multi:softprob returns shape (n_samples, n_features, n_classes)
            sv = np.array(shap_values)
            if sv.ndim == 3:
                # shape: (n_samples, n_features, n_classes) — pick predicted class
                class_shap = sv[0, :, pred_class_idx]
            elif sv.ndim == 2:
                # shape: (n_samples, n_features) — binary or single-output
                class_shap = sv[0]
            elif isinstance(shap_values, list):
                # older SHAP: list of arrays per class
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

        # Overall risk probability
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
            "model_version": "CryptoRiskClassifier-v1",
            "feature_schema_version": "v1"
        }
