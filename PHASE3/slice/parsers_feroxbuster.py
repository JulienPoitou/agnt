"""Parser feroxbuster — --json : JSONL d'événements TYPÉS (mesuré 2.13.1).

Lignes réelles (mesurées le 2026-09-05 sur feroxbuster 2.13.1, `--json -o`) :

    {"type":"configuration", ...}
    {"type":"response", "url": ".../.env", "original_url": ".../", "path": "/.env",
     "wildcard": false, "status": 200, "method": "GET", "content_length": 115,
     "line_count": 3, "word_count": 3, "headers": {...}, "extension": "",
     "truncated": false, "timestamp": 1788624995.4377134}
    {"type":"statistics", ...}

Seuls les événements type=="response" sont des constats : prendre chaque ligne
comme un item ferait des findings vides pour configuration/statistics — le mode
de défaillance nommé dans capabilities.yaml (nmap, 02/09/2026). Les réponses
filtrées par la calibration de l'outil n'apparaissent pas comme événements
response : ce que le parser retient est ce que l'OUTIL rapporte, pas ce qu'il a
reçu. La sévérité n'existe pas chez cet outil : absente, jamais inventée ici.
"""
from __future__ import annotations

import json

from parsers import enregistrer


@enregistrer("feroxbuster")
def parser_feroxbuster(stdout: str) -> list[dict]:
    items = []
    for brut in (stdout or "").splitlines():
        ligne = brut.strip()
        if not ligne:
            continue
        try:
            ev = json.loads(ligne)
        except ValueError:
            continue                      # ligne parasite : ignorée, pas devinée
        if not isinstance(ev, dict) or ev.get("type") != "response":
            continue
        statut = ev.get("status")
        items.append({
            "regle": ev.get("path"),
            "url": ev.get("url"),
            "message": f"statut HTTP {statut}" if statut is not None else None,
        })
    return items
