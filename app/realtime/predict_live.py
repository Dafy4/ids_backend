# app/realtime/predict_live.py

import pandas as pd
import joblib
from tensorflow.keras.models import load_model
import numpy as np

from pathlib import Path

# Load artifacts
# Dossier models = deux niveaux au-dessus de predict_live.py
MODELS_DIR = Path(__file__).parent.parent.parent / 'models'

xgb_model = joblib.load(MODELS_DIR / 'xgb_model.pkl')
label_encoder = joblib.load(MODELS_DIR / 'label_encoder.pkl')
preprocessor = joblib.load(MODELS_DIR / 'preprocessor.pkl')

def predict_packet(features):

    df = pd.DataFrame([features])

    X = preprocessor.transform(df)

    # XGBoost prediction
    pred = xgb_model.predict(X)
    proba = xgb_model.predict_proba(X)

    label = label_encoder.inverse_transform(pred)[0]
    confidence = float(np.max(proba))

    return label, confidence
    