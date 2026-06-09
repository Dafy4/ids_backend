from scapy.all import IP, TCP, UDP, ICMP
from app.realtime.service_map import map_service
from app.realtime.state_manager import StateManager

def extract_features(packet, state_manager: StateManager = None):
    if not packet.haslayer(IP):
        return None

    # --- Protocole, flag, service ---
    if packet.haslayer(TCP):
        protocol_type = "tcp"
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        if flags & 0x02:  # SYN
            flag = "S0" if not (flags & 0x10) else "SF"
        elif flags & 0x04:
            flag = "RST"
        elif flags & 0x01:
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

    service = map_service(dport)
    src_bytes = len(packet[IP])
    dst_bytes = 0

    # --- Features statiques ---
    duration = 0
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

    # --- Features contextuelles (dynamiques) ---
    if state_manager is not None:
        dst_ip = packet[IP].dst
        state_manager.add_event(dst_ip, service, flag)
        host = state_manager.get_host_features(dst_ip, service)
        dst_host = state_manager.get_dst_host_features(dst_ip, service)
    else:
        host = {
            'count': 1, 'srv_count': 1, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0
        }
        dst_host = {
            'dst_host_count': 1, 'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0
        }

    # --- Assemblage final (41 features) ---
    return {
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
        'count': host['count'],
        'srv_count': host['srv_count'],
        'serror_rate': host['serror_rate'],
        'srv_serror_rate': host['srv_serror_rate'],
        'rerror_rate': host['rerror_rate'],
        'srv_rerror_rate': host['srv_rerror_rate'],
        'same_srv_rate': host['same_srv_rate'],
        'diff_srv_rate': host['diff_srv_rate'],
        'srv_diff_host_rate': 0.0,  # optionnel
        'dst_host_count': dst_host['dst_host_count'],
        'dst_host_srv_count': dst_host['dst_host_srv_count'],
        'dst_host_same_srv_rate': dst_host['dst_host_same_srv_rate'],
        'dst_host_diff_srv_rate': dst_host['dst_host_diff_srv_rate'],
        'dst_host_same_src_port_rate': dst_host['dst_host_same_src_port_rate'],
        'dst_host_srv_diff_host_rate': dst_host['dst_host_srv_diff_host_rate'],
        'dst_host_serror_rate': dst_host['dst_host_serror_rate'],
        'dst_host_srv_serror_rate': dst_host['dst_host_srv_serror_rate'],
        'dst_host_rerror_rate': dst_host['dst_host_rerror_rate'],
        'dst_host_srv_rerror_rate': dst_host['dst_host_srv_rerror_rate'],
    }