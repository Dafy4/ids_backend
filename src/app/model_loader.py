import joblib
import os
from tensorflow.keras.models import load_model
from pathlib import Path

# MODEL_PATH = "models/xgb_model.pkl"
# ENCODER_PATH = "models/label_encoder.pkl"
# PREPROCESSOR_PATH = "models/preprocessor.pkl"
# DNN_PATH = "models/dnn_model.h5"

MODELS_DIR = Path(__file__).parent.parent / 'models'

def load_artifacts():
    return {
        "xgb_model": joblib.load(MODELS_DIR / "xgb_model.pkl"),
        "label_encoder": joblib.load(MODELS_DIR / "label_encoder.pkl"),
        "preprocessor": joblib.load(MODELS_DIR / "preprocessor.pkl"),
        "dnn_model": load_model(MODELS_DIR / "dnn_model.h5")   # ou .keras
    }

