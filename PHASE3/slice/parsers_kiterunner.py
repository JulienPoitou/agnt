"""Parser kiterunner — JSONL kr, URL complète reconstruite (target + path).

kr 1.0.2 (-o json -q) rend un objet par résultat :
  {"method": "GET", "target": "http://h:port", "path": "/.env",
   "responses": [{"uri": "", "sc": 200, "len": 115}], "time": …}

`target` et `path` sont SÉPARÉS et aucun champ ne porte l'URL complète — or
l'oracle (location.url) exige une URL absolue : une URL relative est classée
hors_scope au rejeu (pipeline_web). Le parser reconstruit target+path : une
RECONSTRUCTION déclarée (les deux composants viennent de la sortie de l'outil),
pas une inférence. Une entrée `responses` par item ; une ligne illisible est
ignorée (convention lignes_json du cœur). La sévérité n'est pas portée par
l'outil — elle reste absente, jamais inventée ici.
"""
from __future__ import annotations

import json

from parsers import enregistrer


@enregistrer("kiterunner")
def parser_kiterunner(stdout: str) -> list[dict]:
    items: list[dict] = []
    for brut in (stdout or "").splitlines():
        ligne = brut.strip()
        if not ligne or not ligne.startswith("{"):
            continue
        try:
            obj = json.loads(ligne)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        cible = str(obj.get("target") or "")
        chemin = str(obj.get("path") or "")
        if not cible or not chemin:
            continue                          # incomplet : non déclaré, pas « None »
        url = cible + chemin
        for rep in obj.get("responses") or []:
            if not isinstance(rep, dict):
                continue
            sc = rep.get("sc")
            taille = rep.get("len")
            items.append({
                "regle": str(obj.get("method") or "GET"),
                "nom_regle": str(sc) if sc is not None else "",
                "url": url,
                "message": (f"{taille} octets" if taille is not None else ""),
                "preuve": chemin,
            })
    return items
