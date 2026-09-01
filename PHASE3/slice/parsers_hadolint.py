"""Parser spécifique — sortie JSON de hadolint (via le wrapper `hadolint_scan`).

SECOND NIVEAU de la promesse (voir `parsers_bandit.py`, contrat `parsers_detect_secrets.py`).
Motif d'existence : hadolint rentre presqu'en modèle plat, mais le wrapper (obligé :
pas de mode répertoire en 2.15.1, mesuré) écrit le JSON dans un fichier — et la
discipline du projet est de lire la sortie par une voie DÉCLARÉE, pas par une
déviation locale. Un parser nommé garde la lecture au même endroit que les autres.

Forme réelle de l'entrée (mesurée sur hadolint 2.15.1, 2026-09-01, --no-fail) :

    [{"code": "DL3007", "column": 1, "file": "…/Dockerfile", "level": "warning",
      "line": 1, "message": "Using latest is prone to errors…"}]

Tableau plat, un objet par finding. `level` (error/warning/info/style) est conservé
BRUT — pas de mappage inventé vers un vocabulaire que hadolint n'utilise pas.
"""

from __future__ import annotations

import json

from parsers import enregistrer


@enregistrer("hadolint")
def parse(texte: str) -> list[dict]:
    if not texte or not texte.strip():
        return []
    try:
        doc = json.loads(texte)
    except Exception:
        return []
    if not isinstance(doc, list):
        return []
    items: list[dict] = []
    for it in doc:
        if not isinstance(it, dict):
            continue
        ligne = it.get("line")
        items.append({
            "regle": str(it.get("code") or "").strip() or "DL-inconnu",
            "fichier": str(it.get("file") or ""),
            "ligne": ligne if isinstance(ligne, int) else None,
            "severite": str(it.get("level") or "").strip() or None,
            "message": str(it.get("message") or "").strip() or None,
        })
    return items
