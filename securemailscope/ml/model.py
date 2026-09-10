"""
SecureMailScope - XGBoost Cryptographic Risk Classifier & Explainability Engine
"""
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import xgboost as xgb
from securemailscope.core.config import config
from securemailscope.ml.feature_extractor import FeatureExtractor
from securemailscope.ml.dataset_generator import DatasetGenerator, CLASS_NAMES


class CryptoRiskClassifier:
    """
    Gradient-boosted tree model for identifying subtle cryptographic anomalies,
    multi-feature risk patterns, and providing explainable feature attributions.
    """
    _instance = None

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or config.ml_model_path
        self.model: Optional[xgb.XGBClassifier] = None
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
                return
            except Exception:
                pass

        # Train fresh model
        self.train_and_save()

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

        # Calculate feature importances
        importances = self.model.feature_importances_
        feat_imp = {
            FeatureExtractor.FEATURE_NAMES[i]: float(round(importances[i], 4))
            for i in range(len(FeatureExtractor.FEATURE_NAMES))
        }
        return {"status": "TRAINED", "classes": CLASS_NAMES, "feature_importances": feat_imp}

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

        # Overall risk probability (sum of probabilities of anomalous / insecure classes)
        # Class 0 is SECURE_BASELINE, others are risks
        secure_prob = float(probs[0])
        risk_probability = float(round(1.0 - secure_prob, 4))

        # Explainability: feature contribution relative to feature value
        feature_contributions = []
        importances = self.model.feature_importances_
        for idx, fname in enumerate(FeatureExtractor.FEATURE_NAMES):
            val = feat_vec[idx]
            imp = importances[idx]
            # If feature value indicates risk and model weights it heavily
            contribution_score = float(round(imp * (1.0 if val > 0 else 0.1), 4))
            feature_contributions.append({
                "feature": fname,
                "value": val,
                "importance": float(round(imp, 4)),
                "contribution": contribution_score
            })

        feature_contributions.sort(key=lambda x: x["contribution"], reverse=True)

        return {
            "predicted_class": pred_class_name,
            "class_confidence": round(confidence, 4),
            "risk_probability": risk_probability,
            "is_anomalous": pred_class_name != "SECURE_BASELINE",
            "class_probabilities": {CLASS_NAMES[i]: round(float(probs[i]), 4) for i in range(len(CLASS_NAMES))},
            "top_features": feature_contributions[:5],
            "extracted_features": feat_dict
        }
