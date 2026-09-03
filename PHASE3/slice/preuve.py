"""Preuve portable : enveloppes scellées à empreinte sha256 (Stream D).

Un bundle de preuve répond à : "pourquoi AGNT affirme-t-il cela ?" sans
accès au serveur — cible, engagement, providers, vérification, horodatage,
le tout scellé par une empreinte calculée sur du JSON canonique
(clés triées, séparateurs compacts, UTF-8). Toute modification d'un octet
invalide le sceau (`verifier`).

Règles :
  · aucun secret dans un bundle : une référence contenant un userinfo est
    REFUSÉE (pas masquée en silence — le masquage a lieu en amont) ;
  · `sceller`/`verifier` sont purs et déterministes (même objet → même
    empreinte, quel que soit l'ordre d'insertion des clés) ;
  · l'enveloppe porte sa version (`agnt-preuve/v1`) pour les rotations futures.
"""
from __future__ import annotations

import hashlib
import json
import time

VERSION_ENVELOPPE = "agnt-preuve/v1"


def _canonique(objet: dict) -> bytes:
    """JSON canonique : clés triées, compact, UTF-8. Non-JSON → TypeError."""
    return json.dumps(objet, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def empreinte_de(objet: dict) -> str:
    """Empreinte sha256 hex de la forme canonique."""
    return hashlib.sha256(_canonique(objet)).hexdigest()


def sceller(objet: dict) -> dict:
    """Scelle un objet JSON dans une enveloppe vérifiable."""
    if not isinstance(objet, dict):
        raise TypeError(f"sceller : objet dict attendu, reçu {type(objet).__name__}")
    _canonique(objet)                                         # échoue tôt si non-JSON
    return {"enveloppe": VERSION_ENVELOPPE, "algorithme": "sha256",
            "objet": objet, "empreinte": empreinte_de(objet)}


def verifier(enveloppe) -> tuple[bool, str]:
    """Vérifie un sceau. Rend (True, "sceau_valide") ou (False, motif)."""
    if not isinstance(enveloppe, dict):
        return False, "enveloppe_non_objet"
    if enveloppe.get("enveloppe") != VERSION_ENVELOPPE:
        return False, f"version_inconnue : {enveloppe.get('enveloppe')!r}"
    objet = enveloppe.get("objet")
    if not isinstance(objet, dict):
        return False, "objet_non_dict"
    if enveloppe.get("algorithme") != "sha256":
        return False, f"algorithme_inconnu : {enveloppe.get('algorithme')!r}"
    try:
        attendu = empreinte_de(objet)
    except TypeError as e:
        return False, f"objet_non_canonique : {e}"
    if enveloppe.get("empreinte") != attendu:
        return False, "empreinte_invalide : contenu altéré"
    return True, "sceau_valide"


def _sans_secret(valeur: str) -> bool:
    """Vrai si aucune URI de la valeur ne porte de userinfo."""
    import re
    for m in re.finditer(r"[A-Za-z][A-Za-z0-9+.-]*://([^/\s?#]*)", valeur):
        if "@" in m.group(1):
            return False
    return True


def engagement_bundle(engagement: dict, horodatage: float | None = None) -> dict:
    """Bundle de preuve d'un engagement web (planifié ou terminé).

    Ne retient que les champs de preuve (pas `pose_le` interne, pas le brut
    de requête). Refuse tout secret (`ValueError`).
    """
    if not isinstance(engagement, dict):
        raise TypeError("engagement dict attendu")
    objet = {"type": "engagement_web",
             "url_canonique": engagement.get("url_canonique"),
             "hote": engagement.get("hote"),
             "intensity": engagement.get("intensity"),
             "providers_prevus": list(engagement.get("providers_prevus") or []),
             "verification": engagement.get("verification"),
             "statut": engagement.get("statut"),
             "horodatage": horodatage if horodatage is not None else time.time()}
    for cle, val in objet.items():
        if isinstance(val, str) and not _sans_secret(val):
            raise ValueError(f"secret détecté dans {cle} : userinfo interdit dans un bundle")
    return sceller(objet)


def export_markdown(enveloppe: dict) -> str:
    """Fiche de preuve lisible (le sceau reste vérifiable par `verifier`)."""
    ok, motif = verifier(enveloppe)
    if not ok:
        raise ValueError(f"enveloppe invalide : {motif}")
    o = enveloppe["objet"]
    lignes = ["# Preuve AGNT", "",
              f"- type : {o.get('type')}",
              f"- cible : {o.get('url_canonique') or o.get('hote')}",
              f"- statut : {o.get('statut')}",
              f"- vérification : {json.dumps(o.get('verification'), ensure_ascii=False)}",
              f"- empreinte : `{enveloppe['empreinte']}` ({enveloppe['algorithme']})",
              f"- enveloppe : {enveloppe['enveloppe']}"]
    return "\n".join(lignes) + "\n"
