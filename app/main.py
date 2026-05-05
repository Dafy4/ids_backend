from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from app.model_loader import load_artifacts
from app.websocket_manager import manager
from app.schemas import NetworkRequest
from app.predictor import predict
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from app.main import record_prediction

app = FastAPI(title="IDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Stockage en mémoire des alertes ──────────────────────────────────
alerts_store: list = []
stats_store = {
    "total": 0, "attacks": 0, "normal": 0,
    "attack_types": {}
}


#Charger le modèle au démarrage
model, label_encoder, preprocessor = load_artifacts()

@app.get("/")
def root():
    return {"message": "IDS API running"}

@app.post("/predict")
def predict_intrusion(request: NetworkRequest):
    
    data = pd.DataFrame([request.dict()])

    result = predict(data, model, label_encoder, preprocessor)
    asyncio.create_task(record_prediction(
        label=predicted_label,
        confidence=confidence_score,
        src_ip=features.get("src_ip"),   # si présent dans l'input
        dst_ip=features.get("dst_ip")
    ))
    return result

# ── WebSocket temps réel ──────────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep-alive ping
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── GET /api/alerts ───────────────────────────────────────────────────
@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return alerts_store[-limit:][::-1]  # les plus récentes en premier


# ── GET /api/stats ────────────────────────────────────────────────────
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

# ── GET /api/model-info ───────────────────────────────────────────────
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

# ── Fonction utilitaire appelée par predict.py ────────────────────────
async def record_prediction(label: str, confidence: float,
                             src_ip: str = None, dst_ip: str = None):
    """
    À appeler depuis votre endpoint /predict après chaque prédiction.
    """
    is_attack = label.lower() not in ["normal", "0"]
    
    stats_store["total"] += 1
    if is_attack:
        stats_store["attacks"] += 1
        stats_store["attack_types"][label] = \
            stats_store["attack_types"].get(label, 0) + 1
    else:
        stats_store["normal"] += 1

    if is_attack:
        alert = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": label,
            "confidence": round(confidence * 100, 1),
            "src_ip": src_ip or "unknown",
            "dst_ip": dst_ip or "unknown",
            "severity": _get_severity(confidence),
            "status": "En cours"
        }
        alerts_store.append(alert)
        if len(alerts_store) > 500:
            alerts_store.pop(0)
        
        # Broadcast immédiat via WebSocket
        await manager.broadcast({"type": "alert", "data": alert})

def _get_severity(confidence: float) -> str:
    if confidence >= 0.90: return "critical"
    if confidence >= 0.75: return "high"
    if confidence >= 0.55: return "medium"
    return "low"