import time
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple

class StateManager:
    """
    Gère les agrégations temporelles pour les features NSL-KDD :
    - count, srv_count, same_srv_rate, diff_srv_rate, serror_rate, ...
    - dst_host_count, dst_host_srv_count, ...
    """
    def __init__(self, window_host: float = 2.0, window_service: float = 2.0, window_dst_host: float = 100.0):
        self.window_host = window_host          # fenêtre pour count & co.
        self.window_service = window_service    # fenêtre pour srv_count
        self.window_dst_host = window_dst_host  # fenêtre large pour dst_host_*

        # historique : destination IP -> deque of (timestamp, service, is_error)
        self.host_history: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(lambda: deque())
        # historique : service (port) -> deque of (timestamp, dst_ip, is_error)
        self.service_history: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(lambda: deque())
        # historique large pour dst_host
        self.dst_host_history: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(lambda: deque())

        # flags considérés comme des erreurs (S0, RST, REJ)
        self.error_flags = {"S0", "RST", "REJ"}

    def add_event(self, dst_ip: str, service: str, flag: str, timestamp: float = None):
        """Ajoute un événement (paquet/connexion) pour mettre à jour les stats."""
        if timestamp is None:
            timestamp = time.time()
        is_error = 1 if flag in self.error_flags else 0

        # host_history (fenêtre courte)
        self.host_history[dst_ip].append((timestamp, service, is_error))
        self._clean_old(self.host_history[dst_ip], timestamp - self.window_host)

        # service_history (fenêtre courte)
        self.service_history[service].append((timestamp, dst_ip, is_error))
        self._clean_old(self.service_history[service], timestamp - self.window_service)

        # dst_host_history (fenêtre longue)
        self.dst_host_history[dst_ip].append((timestamp, service, is_error))
        self._clean_old(self.dst_host_history[dst_ip], timestamp - self.window_dst_host)

    @staticmethod
    def _clean_old(dq: Deque, cutoff: float):
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def get_host_features(self, dst_ip: str, service: str, current_time: float = None) -> dict:
        """Retourne count, srv_count, same_srv_rate, diff_srv_rate, serror_rate, ..."""
        if current_time is None:
            current_time = time.time()
        recent = [ev for ev in self.host_history.get(dst_ip, []) if current_time - ev[0] <= self.window_host]
        count = len(recent)

        if count == 0:
            return {
                'count': 1,
                'srv_count': 1,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0
            }

        srv_count = sum(1 for _, s, _ in recent if s == service)
        same_srv_rate = srv_count / count
        diff_srv_rate = 1.0 - same_srv_rate
        serror_count = sum(1 for _, _, err in recent if err == 1)
        serror_rate = serror_count / count

        srv_serror = sum(1 for _, s, err in recent if s == service and err == 1)
        srv_serror_rate = srv_serror / srv_count if srv_count > 0 else 0.0

        # rerror_rate = serror_rate (simplification, car même définition dans NSL-KDD)
        return {
            'count': count,
            'srv_count': srv_count,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'serror_rate': serror_rate,
            'srv_serror_rate': srv_serror_rate,
            'rerror_rate': serror_rate,
            'srv_rerror_rate': srv_serror_rate
        }

    def get_dst_host_features(self, dst_ip: str, service: str, current_time: float = None) -> dict:
        """Retourne dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, ..."""
        if current_time is None:
            current_time = time.time()
        recent = [ev for ev in self.dst_host_history.get(dst_ip, []) if current_time - ev[0] <= self.window_dst_host]
        count = len(recent)

        if count == 0:
            return {
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 0.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }

        srv_count = sum(1 for _, s, _ in recent if s == service)
        same_srv_rate = srv_count / count
        diff_srv_rate = 1.0 - same_srv_rate
        serror_count = sum(1 for _, _, err in recent if err == 1)
        serror_rate = serror_count / count

        srv_serror = sum(1 for _, s, err in recent if s == service and err == 1)
        srv_serror_rate = srv_serror / srv_count if srv_count > 0 else 0.0

        # same_src_port_rate nécessite de stocker le port source ; on le laisse à 0 par défaut
        return {
            'dst_host_count': count,
            'dst_host_srv_count': srv_count,
            'dst_host_same_srv_rate': same_srv_rate,
            'dst_host_diff_srv_rate': diff_srv_rate,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': serror_rate,
            'dst_host_srv_serror_rate': srv_serror_rate,
            'dst_host_rerror_rate': serror_rate,
            'dst_host_srv_rerror_rate': srv_serror_rate
        }