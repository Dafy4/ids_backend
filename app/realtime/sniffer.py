from scapy.all import sniff
from app.realtime.feature_extractor import extract_features
from app.realtime.predict_live import predict_live

def process_packet(packet, model, label_encoder, preprocessor, state_manager, callback):
    features = extract_features(packet, state_manager)
    if features is None:
        return
    label, confidence = predict_live(features, model, label_encoder, preprocessor)
    if callback:
        callback(label, confidence, packet)

def start_sniffer(callback, interface="wlp3s0", model=None, label_encoder=None, preprocessor=None, state_manager=None):
    print(f"[*] Starting IDS on interface: {interface}")
    sniff(iface=interface,
          prn=lambda pkt: process_packet(pkt, model, label_encoder, preprocessor, state_manager, callback),
          store=False)