#!/usr/bin/env python3
"""
Script de simulation de trafic réseau pour l'IDS.
Envoie des prédictions aléatoires à l'API /api/record toutes les X secondes.
"""

import requests
import random
import time
from datetime import datetime

API_URL = "http://127.0.0.1:8000/api/record"

# Types d'attaques possibles (labels du modèle)
ATTACK_TYPES = ["dos", "probe", "r2l", "u2r", "normal"]

# Probabilités d'apparition (pour que le graphique soit varié)
PROBABILITIES = {
    "normal": 0.7,   # 70% de trafic normal
    "dos": 0.15,
    "probe": 0.08,
    "r2l": 0.05,
    "u2r": 0.02
}

def generate_random_ip():
    """Génère une adresse IP aléatoire (simulation)."""
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def send_prediction(label: str, confidence: float, src_ip: str, dst_ip: str):
    """Envoie une prédiction à l'API."""
    payload = {
        "label": label,
        "confidence": confidence,
        "src_ip": src_ip,
        "dst_ip": dst_ip
    }
    try:
        response = requests.post(API_URL, json=payload, timeout=1.0)
        if response.status_code == 200:
            print(f"[✓] {datetime.now().strftime('%H:%M:%S')} | {label:6} | conf={confidence:.2f} | {src_ip} -> {dst_ip}")
        else:
            print(f"[✗] Erreur HTTP {response.status_code}")
    except Exception as e:
        print(f"[✗] Échec envoi : {e}")

def main():
    print("===== SIMULATION DE TRAFIC RÉSEAU POUR IDS =====")
    print(f"Envoi des données à {API_URL}")
    print("Appuyez sur Ctrl+C pour arrêter.\n")

    try:
        while True:
            # Choisir un label selon les probabilités
            label = random.choices(
                population=list(PROBABILITIES.keys()),
                weights=list(PROBABILITIES.values()),
                k=1
            )[0]
            
            # Générer une confidence : plus élevée pour les attaques typiques
            if label == "normal":
                confidence = random.uniform(0.85, 0.99)
            else:
                confidence = random.uniform(0.70, 0.98)
            
            src_ip = generate_random_ip()
            dst_ip = generate_random_ip()
            
            send_prediction(label, confidence, src_ip, dst_ip)
            
            # Attendre entre 0.5 et 2.5 secondes avant le prochain paquet
            time.sleep(random.uniform(0.5, 2.5))
            
    except KeyboardInterrupt:
        print("\nSimulation arrêtée.")

if __name__ == "__main__":
    main()