"""Parser spécifique pour les détections de règles Sigma et analyse de logs (SOC / DFIR).

Reçoit le contenu d'un fichier de sortie JSON de détection de logs / Sigma
et extrait une liste standardisée d'items pour le normaliseur de findings AGNT.
"""

from __future__ import annotations

import json
from parsers import enregistrer


@enregistrer("sigma")
def extraire_items_sigma(texte: str) -> list[dict]:
    """Parse le texte JSON émis par un outil de détection Sigma/logs (ex: chainsaw, hayabusa, sigma-cli).

    Format attendu : tableau JSON de détections ou dictionnaire contenant un tableau 'detections' / 'matches'.
    """
    if not texte or not texte.strip():
        return []

    try:
        data = json.loads(texte)
    except json.JSONDecodeError:
        return []

    items = []
    matches = []
    if isinstance(data, list):
        matches = data
    elif isinstance(data, dict):
        matches = data.get("detections") or data.get("matches") or data.get("results") or [data]

    for m in matches:
        if not isinstance(m, dict):
            continue
        rule_id = m.get("rule_id") or m.get("id") or m.get("title") or "sigma_detection"
        rule_title = m.get("title") or m.get("rule_name") or rule_id
        fichier = m.get("file") or m.get("log_file") or m.get("source") or "system.log"
        ligne = m.get("line") or m.get("event_id") or 1
        severite = m.get("level") or m.get("severity") or "HIGH"
        message = m.get("description") or m.get("message") or f"Détection Sigma : {rule_title}"

        items.append({
            "regle": str(rule_id),
            "nom_regle": str(rule_title),
            "fichier": str(fichier),
            "ligne": int(ligne) if isinstance(ligne, int) else 1,
            "severite": str(severite).upper(),
            "message": str(message),
        })

    return items
