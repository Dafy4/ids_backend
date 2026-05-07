import joblib
import os
from tensorflow.keras.models import load_model

MODEL_PATH = "models/xgb_model.pkl"
ENCODER_PATH = "models/label_encoder.pkl"
PREPROCESSOR_PATH = "models/preprocessor.pkl"
DNN_PATH = "models/dnn_model.h5"

def load_artifacts():
    return {
        "xgb_model": joblib.load("models/xgb_model.pkl"),
        "label_encoder": joblib.load("models/label_encoder.pkl"),
        "preprocessor": joblib.load("models/preprocessor.pkl"),
        "dnn_model": load_model("models/dnn_model.h5")
    }