# app/realtime/service_map.py

PORT_SERVICE_MAP = {
    80: "http",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    443: "https"
}

def map_service(port):
    return PORT_SERVICE_MAP.get(port, "other")