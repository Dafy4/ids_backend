import time
import requests
from scapy.all import IP
from app.model_loader import load_artifacts
from app.realtime.sniffer import start_sniffer
from app.realtime.state_manager import StateManager

def initialize_ids():
    print("===== IDS INITIALIZATION =====")
    artifacts = load_artifacts()
    model = artifacts["xgb_model"]
    label_encoder = artifacts["label_encoder"]
    preprocessor = artifacts["preprocessor"]
    dnn_model = artifacts["dnn_model"]
    print("[✓] Models loaded")
    return model, label_encoder, preprocessor, dnn_model

def create_callback(model, label_encoder, preprocessor, state_manager):
    def on_prediction(label, confidence, packet):
        src_ip = packet[IP].src if IP in packet else "unknown"
        dst_ip = packet[IP].dst if IP in packet else "unknown"

        # Envoi à l'API FastAPI
        try:
            requests.post("http://127.0.0.1:8001/api/record",
                          json={"label": label, "confidence": confidence,
                                "src_ip": src_ip, "dst_ip": dst_ip}, timeout=0.5)
        except Exception as e:
            print(f"[WARN] API record failed: {e}")

        if label != "normal":
            try:
                requests.post("http://127.0.0.1:8001/api/alert",
                              json={"attack_type": label, "confidence": confidence,
                                    "src_ip": src_ip, "dst_ip": dst_ip}, timeout=0.2)
            except Exception as e:
                print(f"[WARN] API alert failed: {e}")

        print(f"\n[IDS] {label} (conf={confidence:.2f}) {src_ip} -> {dst_ip}")
    return on_prediction

def main():
    print("===== IDS PIPELINE START =====")
    model, label_encoder, preprocessor, dnn_model = initialize_ids()
    state_manager = StateManager(window_host=2.0, window_service=2.0, window_dst_host=100.0)
    print("[✓] StateManager initialized")

    callback = create_callback(model, label_encoder, preprocessor, state_manager)
    start_sniffer(callback=callback, interface="wlp3s0",
                  model=model, label_encoder=label_encoder,
                  preprocessor=preprocessor, state_manager=state_manager)

if __name__ == "__main__":
    main()