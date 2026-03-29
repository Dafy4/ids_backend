import joblib
import os
from tensorflow.keras.models import load_model

MODEL_PATH = "models/xgb_model.pkl"
ENCODER_PATH = "models/label_encoder.pkl"
PREPROCESSOR_PATH = "models/preprocessor.pkl"
DNN_PATH = "models/dnn_model.h5"

def load_artifacts():
    xgb_model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(PREPROCESSOR_PATH)
    preprocessor = joblib.load(PREPROCESSOR_PATH)
    dnn_model = load_model(DNN_PATH)

    return xgb_model, dnn_model, label_encoder, preprocessor