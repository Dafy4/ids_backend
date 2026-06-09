# ids_backend
Détection d'intrusion réseau avec Machine Learning
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001

python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

Autorisations : 
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.13

Lancement de sniffer : 
sudo ./venv/bin/python3 ids_backend/run_ids.py

cd "/run/media/voni/DonnéesWin1/Cours/Projet porte ouverte/M2/PORTE OUVERTE 2026/codes/ids_backend"
sudo ../venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

sudo /run/media/.../codes/venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000

RUN SNIFFER : 
sudo ./venv/bin/python3 ids_backend/run_ids.py

RUN FASTAPI :
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000



# IDS Backend - Système de Détection d'Intrusions Réseau avec Machine Learning

## 📋 Prérequis

- Ubuntu 22.04/24.04
- Python 3.12
- Environnement virtuel (venv)
- Interface réseau WiFi (wlp3s0) ou Ethernet

---

## 🚀 Installation et Configuration

### 1. Créer et activer l'environnement virtuel

```bash
cd ~/development/PO/ids_backend
python3 -m venv venv
source venv/bin/activate
```
###  2. Configurer les droits de capture réseau
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.12
```


### Terminal 1 - API FastAPI (Port 8001)
```bash

cd ~/development/PO/ids_backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```
API accessible sur : http://192.168.0.100:8001

### Terminal 2 - Sniffer IDS (Capture temps réel)
```bash

cd ~/development/PO/ids_backend
source venv/bin/activate
python run_ids.py
```