from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import json
import os
import pandas as pd

from app.model_loader import load_artifacts
from app.websocket_manager import manager
from app.schemas import NetworkRequest
from app.predictor import predict

app = FastAPI(title="IDS API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# STOCKAGE ET PERSISTANCE
# ============================================

ALERTS_FILE = "alerts.json"

def load_alerts():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r") as f:
                return json.load(f)
        except:
            return []
    return []

def save_alerts(alerts):
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts[-1000:], f, indent=2)

# Initialisation des stores
alerts_store = load_alerts()
stats_store = {
    "total": 0, 
    "attacks": 0, 
    "normal": 0,
    "attack_types": {} 
}
traffic_store = []

# ============================================
# CHARGEMENT DES MODÈLES ML
# ============================================

artifacts = load_artifacts()
model = artifacts["xgb_model"]
label_encoder = artifacts["label_encoder"]
preprocessor = artifacts["preprocessor"]
dnn_model = artifacts["dnn_model"]

print("[✓] Models loaded successfully")

# ============================================
# SCHEMAS
# ============================================

class AlertInput(BaseModel):
    attack_type: str
    confidence: float
    severity: str = "high"
    src_ip: str = "unknown"
    dst_ip: str = "unknown"

class PredictionRecord(BaseModel):
    label: str
    confidence: float
    src_ip: str = "unknown"
    dst_ip: str = "unknown"

# ============================================
# FONCTIONS UTILITAIRES
# ============================================

def get_severity(confidence: float) -> str:
    if confidence >= 0.90: return "critical"
    if confidence >= 0.75: return "high"
    if confidence >= 0.55: return "medium"
    return "low"

async def record_prediction(label: str, confidence: float,
                             src_ip: str = None, dst_ip: str = None):
    """
    Enregistre une prédiction et génère une alerte si c'est une attaque
    """
    global stats_store, alerts_store, traffic_store
    
    is_attack = label.lower() not in ["normal", "0"]
    
    stats_store["total"] += 1
    
    # Mettre à jour traffic store
    traffic_store.append({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "normal": stats_store["normal"],
        "attacks": stats_store["attacks"]
    })
    if len(traffic_store) > 60:
        traffic_store.pop(0)
    
    if is_attack:
        stats_store["attacks"] += 1
        stats_store["attack_types"][label] = \
            stats_store["attack_types"].get(label, 0) + 1
        
        # Créer une alerte
        alert = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": label,
            "confidence": round(confidence * 100, 1),
            "src_ip": src_ip or "unknown",
            "dst_ip": dst_ip or "unknown",
            "severity": get_severity(confidence),
            "status": "En cours"
        }
        alerts_store.append(alert)
        save_alerts(alerts_store)
        
        if len(alerts_store) > 500:
            alerts_store.pop(0)
        
        # Broadcast WebSocket
        await manager.broadcast({"type": "alert", "data": alert})
    else:
        stats_store["normal"] += 1

# ============================================
# ENDPOINTS
# ============================================

@app.get("/")
def root():
    return {"message": "IDS API running"}

@app.get("/api/traffic")
def get_traffic():
    return traffic_store[-60:]

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return alerts_store[-limit:][::-1]

@app.get("/api/stats")
def get_stats():
    total = stats_store["total"]
    attacks = stats_store["attacks"]
    return {
        "total_predictions": total,
        "attack_count": attacks,
        "normal_count": stats_store["normal"],
        "attack_rate": round(attacks / total * 100, 1) if total > 0 else 0,
        "normal_rate": round(stats_store["normal"] / total * 100, 1) if total > 0 else 0,
        "attack_types": stats_store["attack_types"]
    }

@app.get("/api/model-info")
def get_model_info():
    return {
        "model_type": "XGBoost + DNN",
        "dataset": "NSL-KDD",
        "accuracy": 97.4,
        "precision": 95.8,
        "recall": 96.1,
        "f1_score": 95.9,
        "classes": 5,
        "features": 42,
        "status": "loaded"
    }

@app.post("/api/alert")
async def add_alert(alert: AlertInput):
    """Endpoint pour ajouter manuellement une alerte"""
    new_alert = {
        "timestamp": datetime.now().isoformat(),
        "attack_type": alert.attack_type,
        "confidence": alert.confidence,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "severity": alert.severity,
        "status": "En cours"
    }
    alerts_store.append(new_alert)
    save_alerts(alerts_store)
    
    # Mettre à jour les stats
    stats_store["attacks"] += 1
    stats_store["attack_types"][alert.attack_type] = \
        stats_store["attack_types"].get(alert.attack_type, 0) + 1
    stats_store["total"] += 1
    
    # Broadcast WebSocket
    await manager.broadcast({"type": "alert", "data": new_alert})
    
    return {"status": "alert recorded", "id": len(alerts_store) - 1}

@app.post("/api/record")
async def record_prediction_endpoint(record: PredictionRecord):
    await record_prediction(
        label=record.label,
        confidence=record.confidence,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip
    )
    return {"status": "recorded"}

@app.post("/api/predict")
async def predict_intrusion(request: NetworkRequest):
    data = pd.DataFrame([request.dict()])
    
    result = predict(
        data,
        model,
        dnn_model,
        label_encoder,
        preprocessor
    )
    
    predicted_label = result["xgboost"]["prediction"]
    confidence_score = result["xgboost"]["confidence"]
    
    await record_prediction(
        label=predicted_label,
        confidence=confidence_score,
        src_ip=request.src_ip if hasattr(request, "src_ip") else None,
        dst_ip=request.dst_ip if hasattr(request, "dst_ip") else None
    )
    
    return result

# ============================================
# WEBSOCKET
# ============================================

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)