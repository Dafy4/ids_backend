# ids_backend
Détection d'intrusion réseau avec Machine Learning
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

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
