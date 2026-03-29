from fastapi import FastAPI
from app.model_loader import load_artifacts
from app.schemas import NetworkRequest
from app.predictor import predict
import pandas as pd

app = FastAPI(title="IDS API")

#Charger le modèle au démarrage
model, label_encoder, preprocessor = load_artifacts()

@app.get("/")
def root():
    return {"message": "IDS API running"}

@app.post("/predict")
def predict_intrusion(request: NetworkRequest):
    
    data = pd.DataFrame([request.dict()])

    result = predict(data, model, label_encoder, preprocessor)

    return result