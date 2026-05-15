# =========================================
# IDS REAL-TIME EXECUTION SCRIPT
# =========================================

import time
from app.model_loader import load_artifacts
from app.realtime.sniffer import start_sniffer
import requests
# =========================================
# 1. INITIALISATION
# =========================================

def initialize_ids():
    print("===== IDS INITIALIZATION =====")

    # Chargement des artefacts ML
    # model, label_encoder, preprocessor = load_artifacts()

    artifacts = load_artifacts()

    model = artifacts["xgb_model"]
    label_encoder = artifacts["label_encoder"]
    preprocessor = artifacts["preprocessor"]
    dnn_model = artifacts["dnn_model"]
    
    print("[✓] Model loaded")
    print("[✓] Label encoder loaded")
    print("[✓] Preprocessor loaded")

    return model, label_encoder, preprocessor, dnn_model


# =========================================
# 2. CALLBACK DE TRAITEMENT TEMPS RÉEL
# =========================================

def process_packet(packet, model, label_encoder, preprocessor):
    """
    Fonction appelée pour chaque paquet capturé
    """

    from app.realtime.feature_extractor import extract_features
    from app.realtime.predict_live import predict_live

    try:
        # ---------------------------------
        # Extraction des features
        # ---------------------------------
        features = extract_features(packet)

        if features is None:
            return  # paquet ignoré

        # ---------------------------------
        # Prédiction
        # ---------------------------------
        start_time = time.time()

        prediction, confidence = predict_live(
            features,
            model,
            label_encoder,
            preprocessor
        )
        # Récupérer les IP (si le paquet a une couche IP)
        src_ip = packet[IP].src if IP in packet else "unknown"
        dst_ip = packet[IP].dst if IP in packet else "unknown"
        
        try:
            requests.post(
                "http://127.0.0.1:8000/api/record",
                json={
                    "label": prediction,
                    "confidence": confidence,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip
                },
                timeout=0.5
            )
        except Exception as e:
            print(f"[WARN] Échec envoi à l'API: {e}")
        if prediction != "normal":
            # Envoyer l'alerte à l'API FastAPI
            try:
                requests.post(
                    "http://127.0.0.1:8000/api/alert",
                    json={
                        "attack_type": prediction,
                        "confidence": confidence,
                        "src_ip": src_ip,    # à récupérer du paquet
                        "dst_ip": dst_ip
                    },
                    timeout=0.2
                )
            except Exception as e:
                print(f"[WARN] Échec envoi alerte : {e}")

        end_time = time.time()

        # ---------------------------------
        # Affichage console (IDS alert)
        # ---------------------------------
        print("\n[IDS ALERT]")
        print(f"Prediction : {prediction}")
        print(f"Confidence : {confidence:.4f}")
        print(f"Latency    : {(end_time - start_time):.4f}s")
        print("-" * 40)

    except Exception as e:
        print(f"[ERROR] Packet processing failed: {e}")


# =========================================
# 3. MAIN EXECUTION
# =========================================

def main():
    print("===== IDS PIPELINE START =====")

    # Initialisation
    # model, label_encoder, preprocessor = initialize_ids()
    model, label_encoder, preprocessor, dnn_model = initialize_ids()
    
    print("\n[INFO] Starting real-time packet capture...")

    # Lancement du sniffer
    start_sniffer(
        callback=lambda pkt: process_packet(
            pkt,
            model,
            label_encoder,
            preprocessor
        )
    )


# =========================================
# 4. ENTRY POINT
# =========================================

if __name__ == "__main__":
    main()