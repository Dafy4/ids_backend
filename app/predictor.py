import numpy as np

def predict(data, xgb_model, dnn_model, label_encoder, preprocessor):

    X = preprocessor.transform(data)

    # ------------------------
    # XGBoost Prediction
    # ------------------------
    xgb_pred = xgb_model.predict(X)
    xgb_proba = xgb_model.predict_proba(X)

    # ------------------------
    # DNN Prediction
    # ------------------------
    if hasattr(X, "toarray"):
        X_dl = X.toarray()
    else:
        X_dl =  X
    
    dnn_proba = dnn_model.predict(X_dl)
    dnn_pred = np.argmax(dnn_proba, axis = 1)

    # ------------------------
    # Decode labels
    # ------------------------
    xgb_label = label_encoder.inverse_transform(xgb_pred)[0]
    dnn_label = label_encoder.inverse_transform(dnn_pred)[0]

    return {
        "xgboost": {
            "prediction": xgb_label,
            "confidence": float(np.max(xgb_proba))
        },
        "dnn": {
            "prediction": dnn_label,
            "confidence": float(np.max(dnn_proba))
        }
    }