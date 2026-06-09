import pandas as pd
import numpy as np
from app.realtime.post_processor import refine_prediction

def predict_live(features, model, label_encoder, preprocessor):
    if isinstance(features, dict):
        df = pd.DataFrame([features])
    else:
        df = features

    # Transformation et prédiction ML
    X = preprocessor.transform(df)
    pred = model.predict(X)
    proba = model.predict_proba(X)
    raw_label = label_encoder.inverse_transform(pred)[0]
    confidence = float(np.max(proba))

    # Post-traitement expert
    final_label, final_conf = refine_prediction(raw_label, confidence, features)

    # Debug optionnel (désactivable)
    if features.get('service') == 'http' and features.get('count', 0) > 10:
        print(f"[DEBUG] count={features['count']} srv_rate={features['same_srv_rate']:.2f} "
              f"serror={features['serror_rate']:.2f} -> ML={raw_label} -> Final={final_label}")

    return final_label, final_conf