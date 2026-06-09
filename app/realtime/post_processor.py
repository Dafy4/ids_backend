def refine_prediction(label: str, confidence: float, features: dict) -> tuple:
    """
    Post‑traitement pour corriger les faux négatifs du modèle.
    Basé sur des règles simples mais efficaces.
    """
    service = features.get('service', '')
    count = features.get('count', 1)
    srv_count = features.get('srv_count', 1)
    same_srv_rate = features.get('same_srv_rate', 1.0)
    diff_srv_rate = features.get('diff_srv_rate', 0.0)
    serror_rate = features.get('serror_rate', 0.0)
    flag = features.get('flag', 'SF')

    # --- Règle 1 : Scan de ports (Nmap, masscan) ---
    if diff_srv_rate > 0.5 and count > 10 and flag in ["S0", "RST"]:
        return "probe", max(confidence, 0.85)

    # --- Règle 2 : sqlmap / scan applicatif (rafale HTTP sans erreurs TCP) ---
    if service in ["http", "https"] and count > 15 and serror_rate < 0.2:
        return "sqlmap_scan", max(confidence, 0.80)

    # --- Règle 3 : DoS / flood (même port, beaucoup de connexions avortées) ---
    if same_srv_rate > 0.8 and count > 20 and serror_rate > 0.5:
        return "dos", max(confidence, 0.90)

    # --- Règle 4 : Attaque par injection (patterns SQL dans le flag n'existe pas, mais on peut ajouter plus tard) ---
    # Déjà couvert par la règle 2 si le trafic est suffisamment dense

    return label, confidence