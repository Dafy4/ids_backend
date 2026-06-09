# app/realtime/feature_extractor.py

from scapy.all import IP, TCP, UDP, ICMP
from app.realtime.service_map import map_service

def extract_features(packet):
    """
    Extrait les 41 features NSL-KDD à partir d'un paquet Scapy
    """
    if not packet.haslayer(IP):
        return None

    # ==========================================
    # 1. FEATURES DE BASE (depuis le paquet)
    # ==========================================
    duration = 0
    
    # Protocol type
    if packet.haslayer(TCP):
        protocol_type = "tcp"
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Flag (état de la connexion TCP)
        if flags & 0x02:  # SYN
            if flags & 0x10:  # ACK
                flag = "SF"
            else:
                flag = "S0"
        elif flags & 0x04:  # RST
            flag = "RST"
        elif flags & 0x01:  # FIN
            flag = "FIN"
        else:
            flag = "OTH"
    elif packet.haslayer(UDP):
        protocol_type = "udp"
        dport = packet[UDP].dport
        flag = "SF"
    elif packet.haslayer(ICMP):
        protocol_type = "icmp"
        dport = 0
        flag = "SF"
    else:
        protocol_type = "other"
        dport = 0
        flag = "SF"
    
    # Service
    service = map_service(dport)
    
    # Bytes
    src_bytes = len(packet[IP]) if packet.haslayer(IP) else 0
    dst_bytes = 0

    # ==========================================
    # 2. FEATURES PAR DÉFAUT (0 pour la plupart)
    # ==========================================
    land = 0
    wrong_fragment = 0
    urgent = 0
    hot = 0
    num_failed_logins = 0
    logged_in = 1 if service in ["http", "https", "ssh", "ftp"] else 0
    num_compromised = 0
    root_shell = 0
    su_attempted = 0
    num_root = 0
    num_file_creations = 0
    num_shells = 0
    num_access_files = 0
    num_outbound_cmds = 0
    is_host_login = 0
    is_guest_login = 0
    count = 1
    srv_count = 1
    serror_rate = 0.0
    srv_serror_rate = 0.0
    rerror_rate = 0.0
    srv_rerror_rate = 0.0
    same_srv_rate = 1.0
    diff_srv_rate = 0.0
    srv_diff_host_rate = 0.0
    dst_host_count = 1
    dst_host_srv_count = 1
    dst_host_same_srv_rate = 1.0
    dst_host_diff_srv_rate = 0.0
    dst_host_same_src_port_rate = 0.0
    dst_host_srv_diff_host_rate = 0.0
    dst_host_serror_rate = 0.0
    dst_host_srv_serror_rate = 0.0
    dst_host_rerror_rate = 0.0
    dst_host_srv_rerror_rate = 0.0

    # ==========================================
    # 3. CONSTRUCTION DU DICTIONNAIRE (41 features)
    # ==========================================
    features = {
        'duration': duration,
        'protocol_type': protocol_type,
        'service': service,
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': land,
        'wrong_fragment': wrong_fragment,
        'urgent': urgent,
        'hot': hot,
        'num_failed_logins': num_failed_logins,
        'logged_in': logged_in,
        'num_compromised': num_compromised,
        'root_shell': root_shell,
        'su_attempted': su_attempted,
        'num_root': num_root,
        'num_file_creations': num_file_creations,
        'num_shells': num_shells,
        'num_access_files': num_access_files,
        'num_outbound_cmds': num_outbound_cmds,
        'is_host_login': is_host_login,
        'is_guest_login': is_guest_login,
        'count': count,
        'srv_count': srv_count,
        'serror_rate': serror_rate,
        'srv_serror_rate': srv_serror_rate,
        'rerror_rate': rerror_rate,
        'srv_rerror_rate': srv_rerror_rate,
        'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate,
        'srv_diff_host_rate': srv_diff_host_rate,
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
        'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
        'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate,
        'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_srv_serror_rate,
        'dst_host_rerror_rate': dst_host_rerror_rate,
        'dst_host_srv_rerror_rate': dst_host_srv_rerror_rate,
    }
    
    return features