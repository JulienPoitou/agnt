"""Parser nikto — rapport JSON (-F json) du wrapper nikto_scan (G1, vague-web/g1).

Sortie réelle (mesurée le 2026-09-05 sur nikto 2.6.1) : une LISTE de blocs par
hôte {"host", "ip", "port", "server_banner", "start_time", "end_time",
"sitename", "vulnerabilities": [{"id", "method", "msg", "references", "url"}]}.

Deux faits mesurés commandent ce parser :

· le rapport JSON de nikto 2.6.1 ne porte NI le schéma NI l'URL complète de la
  cible (clés host/ip/port seulement) : le wrapper nikto_scan écrit
  « sitename » = l'URL passée en argv (provenance mesurée, pas une déduction) —
  location.url est composée de sitename + le chemin RELATIF que nikto déclare ;
  le chemin brut reste porté par le champ « chemin » de l'item, et preuve
  concatène méthode HTTP + chemin (ex. « GET /.env ») ;

· la sévérité n'existe pas dans le rapport JSON de nikto 2.6.1 : absente,
  jamais inventée ici.

nikto n'a pas de nom de règle dans son rapport JSON (id numérique + message
uniquement) : source.nom_regle reste ABSENT — non déclaré, pas deviné.
"""
from __future__ import annotations

import json

from parsers import enregistrer


@enregistrer("nikto")
def parser_nikto(stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout or "[]")
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    items: list[dict] = []
    for bloc in data:
        if not isinstance(bloc, dict):
            continue
        cible = str(bloc.get("sitename") or "").rstrip("/")
        for vuln in bloc.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            chemin = str(vuln.get("url") or "")
            methode = str(vuln.get("method") or "")
            items.append({
                "regle": str(vuln.get("id") or ""),
                "url": f"{cible}{chemin}" if cible else chemin,
                "message": str(vuln.get("msg") or ""),
                "preuve": f"{methode} {chemin}".strip(),
                "chemin": chemin,
            })
    return items
