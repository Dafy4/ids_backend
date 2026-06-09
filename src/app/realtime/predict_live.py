# app/realtime/predict_live.py

import pandas as pd
import numpy as np

def predict_live(features, model, label_encoder, preprocessor):
    """
    Prédiction en temps réel pour l'IDS
    
    Args:
        features: dict ou DataFrame des features extraites
        model: modèle XGBoost chargé
        label_encoder: label encoder pour décoder les prédictions
        preprocessor: préprocesseur pour scaler les features
    
    Returns:
        tuple: (label, confidence)
    """
    # Convertir en DataFrame si dict
    if isinstance(features, dict):
        df = pd.DataFrame([features])
    else:
        df = features
    
    # Prétraitement
    X = preprocessor.transform(df)
    
    # Prédiction XGBoost
    pred = model.predict(X)
    proba = model.predict_proba(X)
    
    # Décodage
    label = label_encoder.inverse_transform(pred)[0]
    confidence = float(np.max(proba))
    
    return label, confidence