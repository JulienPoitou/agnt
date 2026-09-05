"""Parser x8 — array JSON -O json, UN item par paramètre caché trouvé.

x8 4.3.0 (-O json) mélange au stdout un en-tête texte (« urls: », « methods: »,
« GET … (200) », « [info] … ») avec l'array JSON final ; le fichier -o, lui,
est l'array pur :
  [{"method": "GET", "url": "…", "status": 200, "size": 194,
    "found_params": [], "injection_place": "Path"}]

Doctrine : UN item PAR paramètre trouvé. `found_params` vide → 0 item — un
constat « sans paramètre » serait un item déguisé en découverte. Le résultat
vide reste l'affaire du cœur (« aucun_item_lisible »), jamais du parser. La
sévérité n'est pas portée par l'outil — elle reste absente, jamais inventée.
"""
from __future__ import annotations

import json

from parsers import enregistrer


def _array_json(texte: str) -> list:
    """L'array JSON, tel quel (fichier -o) ou extrait du stdout mêlé de texte."""
    brut = (texte or "").strip()
    if brut.startswith("["):
        try:
            valeur = json.loads(brut)
            return valeur if isinstance(valeur, list) else []
        except ValueError:
            return []
    # stdout -O json : l'array est la première ligne qui commence par « [ »
    for ligne in brut.splitlines():
        ligne = ligne.strip()
        if ligne.startswith("["):
            try:
                valeur = json.loads(ligne)
                if isinstance(valeur, list):
                    return valeur
            except ValueError:
                continue
    return []


@enregistrer("x8")
def parser_x8(stdout: str) -> list[dict]:
    items: list[dict] = []
    for bloc in _array_json(stdout):
        if not isinstance(bloc, dict):
            continue
        url = str(bloc.get("url") or "")
        methode = str(bloc.get("method") or "")
        place = str(bloc.get("injection_place") or "")
        for param in bloc.get("found_params") or []:
            items.append({
                "regle": methode,
                "nom_regle": str(param),
                "url": url,
                "message": f"injection_place: {place}" if place else "",
            })
    return items
