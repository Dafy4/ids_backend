# app/realtime/sniffer.py

from scapy.all import sniff
from app.realtime.feature_extractor import extract_features
from app.realtime.predict_live import predict_packet

def process_packet(packet):

    features = extract_features(packet)

    if features is None:
        return

    label, confidence = predict_packet(features)

    # Console output
    print(f"[ALERT] Prediction: {label} | Confidence: {confidence:.2f}, Starting IDS on interface: {interface}")

def start_sniffer(callback, interface="eth0"):

    print(f"[*] Starting IDS on interface: {interface}")

    sniff(
        iface=interface,
        # prn=process_packet,
        prn=callback,
        store=False
    )