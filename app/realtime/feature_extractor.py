# app/realtime/feature_extractor.py

from scapy.all import IP, TCP, UDP
from app.realtime.service_map import map_service

def extract_features(packet):

    if not packet.haslayer(IP):
        return None

    proto = "icmp"
    service = "other"
    flag = "SF"
    src_bytes = len(packet)
    dst_bytes = 0

    # Protocol detection
    if packet.haslayer(TCP):
        proto = "tcp"
        dport = packet[TCP].dport
        service = map_service(dport)

        # Simplified TCP flag
        flags = packet[TCP].flags
        flag = "SF" if flags == "S" else "S0"

    elif packet.haslayer(UDP):
        proto = "udp"
        dport = packet[UDP].dport
        service = map_service(dport)

    features = {
        "duration": 0,
        "protocol_type": proto,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes
    }

    return features