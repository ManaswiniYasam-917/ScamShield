import os
import joblib
import numpy as np
from feature_extractor import extract_url_features, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.joblib")

_CACHED_MODEL = None

def get_ml_model():
    global _CACHED_MODEL
    if _CACHED_MODEL is not None:
        return _CACHED_MODEL
    if os.path.exists(MODEL_PATH):
        try:
            _CACHED_MODEL = joblib.load(MODEL_PATH)
            return _CACHED_MODEL
        except Exception:
            return None
    return None

def predict(url: str) -> dict:
    model = get_ml_model()
    feat_vector = extract_url_features(url)

    if model is None:
        return {
            "available": False,
            "status": "not_trained",
            "prediction": "unknown",
            "probability_percent": 0.0,
            "details": "ML model file not loaded. Training script available.",
            "top_features": []
        }

    try:
        X = np.array([feat_vector])
        pred_label = int(model.predict(X)[0])
        prob = 0.0
        if hasattr(model, "predict_proba"):
            prob = float(model.predict_proba(X)[0][1])

        prob_percent = round(prob * 100, 1)
        prediction_str = "suspicious" if pred_label == 1 or prob_percent >= 50.0 else "benign"

        # Explainable AI (XAI) feature attribution
        top_features = []
        feature_importance = getattr(model, "feature_importances_", None)
        if feature_importance is not None:
            # Multiply feature values by importance weights to estimate contribution
            contributions = []
            for name, val, imp in zip(FEATURE_NAMES, feat_vector, feature_importance):
                if val > 0:
                    contributions.append((name, round(val * imp * 100, 2), val))
            contributions.sort(key=lambda x: x[1], reverse=True)
            for name, score, raw in contributions[:5]:
                human_name = name.replace("_", " ").title()
                top_features.append({"name": human_name, "raw_value": raw, "impact": score})

        return {
            "available": True,
            "status": "ready",
            "prediction": prediction_str,
            "probability_percent": prob_percent,
            "details": f"Random Forest & Gradient Boosting ensemble predicts {prob_percent}% probability of malicious/phishing intent.",
            "top_features": top_features
        }
    except Exception as exc:
        return {
            "available": False,
            "status": "inference_error",
            "prediction": "unknown",
            "probability_percent": 0.0,
            "details": f"Inference error: {str(exc)}",
            "top_features": []
        }
