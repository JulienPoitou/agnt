"""Parser sslyze — JSON de sortie, un item par cible refusée / connexion échouée /
commande de scan rendue.

Structure (sslyze 6.3.1 — sslyze/json/json_output.py du paquet épinglé) : racine
{invalid_server_strings[], server_scan_results[], sslyze_version…}. Le parser ne retient
AUCUN contenu de certificat (les données de la cible ne traversent pas le registre, même
convention que git-dumper) : les items portent la STRUCTURE du scan, la charge reste
dans l'artefact brut. sslyze ne déclare pas de sévérité — absente, jamais inventée ici.
"""
from __future__ import annotations

import json

from parsers import enregistrer

REF = "https://github.com/nabla-c0d3/sslyze"


@enregistrer("sslyze")
def parser_sslyze(stdout: str) -> list[dict]:
    texte = (stdout or "").strip()
    if not texte:
        return []
    try:
        doc = json.loads(texte)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    items: list[dict] = []
    for invalide in doc.get("invalid_server_strings") or []:
        if not isinstance(invalide, dict):
            continue
        items.append({
            "regle": "sslyze-cible-refusee",
            "nom_regle": "cible refusée par l'outil",
            "message": str(invalide.get("error_message") or "raison non rendue par l'outil"),
            "url": str(invalide.get("server_string") or ""),
            "confiance": "confirmée",
            "reference": REF,
            "preuve": str(invalide.get("server_string") or ""),
        })
    for resultat in doc.get("server_scan_results") or []:
        if not isinstance(resultat, dict):
            continue
        location = resultat.get("server_location") or {}
        hote = str(location.get("hostname") or "") if isinstance(location, dict) else ""
        port = str(location.get("port") or "") if isinstance(location, dict) else ""
        url = f"{hote}:{port}" if hote and port else hote
        if resultat.get("connectivity_status") == "ERROR":
            items.append({
                "regle": "sslyze-connexion",
                "nom_regle": "connexion TLS impossible",
                "message": "échec de connectivité TLS (trace complète dans l'artefact brut)",
                "url": url,
                "reference": REF,
                "preuve": "connectivity_status=ERROR",
            })
            continue
        scan = resultat.get("scan_result")
        if not isinstance(scan, dict):
            continue
        for commande in sorted(scan):
            items.append({
                "regle": f"sslyze-{commande}",
                "nom_regle": str(commande),
                "message": "résultat de scan rendu (contenu dans l'artefact brut)",
                "url": url,
                "reference": REF,
                "preuve": f"scan_result.{commande}",
            })
    return items
