from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import joblib
import numpy as np

from .config import CLASS_MAPPING, MODEL_PATH, VECTORIZER_PATH


@dataclass
class InferenceResult:
    predicted_index: int
    predicted_label: str
    confidence: float
    probabilities: dict[str, float]


class MLEngine:
    def __init__(self, vectorizer_path=VECTORIZER_PATH, model_path=MODEL_PATH):
        self.vectorizer = joblib.load(vectorizer_path)
        self.model = self._load_model(model_path)

    @staticmethod
    def _load_model(model_path):
        try:
            from tensorflow import keras
        except ImportError as exc:
            raise RuntimeError(
                'TensorFlow no está instalado. Instala las dependencias del proyecto para cargar el modelo Keras.'
            ) from exc
        return keras.models.load_model(model_path)

    def predict(self, payload: str) -> InferenceResult:
        features = self.vectorizer.transform([payload])
        dense_features = features.toarray().astype(np.float32)
        probs = self.model.predict(dense_features, verbose=0)[0]
        pred_idx = int(np.argmax(probs))
        probabilities = {
            CLASS_MAPPING[idx]: float(prob)
            for idx, prob in enumerate(probs)
        }
        return InferenceResult(
            predicted_index=pred_idx,
            predicted_label=CLASS_MAPPING[pred_idx],
            confidence=float(probs[pred_idx]),
            probabilities=probabilities,
        )
