"""Remédiation : workflow finding → retest → verdict (fondation, Stream J).

Ne génère AUCUN patch ici (`remediation.py` fait déjà cela, testé) : ce module
décide de la SUITE d'un finding remédié — quelle transition du cycle de vie
le résultat d'un retest autorise. Toute transition passe par
`cycle_vie.transition` : un retest ne peut ni confirmer ni fermer par décret.
"""
from __future__ import annotations

from cycle_vie import FIXED, VERIFIED, transition


class ErreurFlux(Exception):
    """Demande de retest inexploitable, nommée."""


def demander_retest(finding: dict, remediation: dict | None = None) -> dict:
    """Construit une demande de retest à partir d'un finding (+ remédiation).

    La demande reprend la cible et les providers d'origine : retester avec
    d'autres outils serait mesurer autre chose que le fix.
    """
    if not isinstance(finding, dict):
        raise ErreurFlux("finding dict attendu")
    fid = finding.get("id")
    if not fid:
        raise ErreurFlux("finding sans id — non retestable")
    location = finding.get("location") or {}
    cible = (location.get("url") or location.get("file")
             or (finding.get("source") or {}).get("cible"))
    if not cible:
        raise ErreurFlux("finding sans cible — non retestable")
    outil = ((finding.get("source") or {}).get("tool")
             or (finding.get("source") or {}).get("outil"))
    return {"finding_id": fid, "cible": cible,
            "providers": [outil] if outil else [],
            "remediation": remediation,
            "cycle_attendu": "retest_en_cours"}


def conclure_retest(demande: dict, etat_cycle: str,
                    encore_vulnerable: bool) -> tuple[str, str]:
    """Traduit le résultat d'un retest en événement du cycle (ou "aucun").

    - FIXED + encore vulnérable → `regresser` (le fix n'a pas tenu) ;
    - FIXED + propre → `aucun` (maintenu, pas de transition à jouer) ;
    - VERIFIED + encore vulnérable → `aucun` (toujours vérifié) ;
    - VERIFIED + propre → `corriger` (le fix est constaté).
    """
    if not isinstance(demande, dict) or not demande.get("finding_id"):
        raise ErreurFlux("demande invalide")
    if etat_cycle == FIXED:
        evt = "regresser" if encore_vulnerable else "aucun"
    elif etat_cycle == VERIFIED:
        evt = "aucun" if encore_vulnerable else "corriger"
    else:
        raise ErreurFlux(f"retest depuis {etat_cycle} : seul FIXED ou VERIFIED retestés")
    if evt != "aucun":
        transition(etat_cycle, evt)                     # lève si la table change
    motif = {"regresser": "retest : vulnérabilité toujours présente",
             "corriger": "retest : cible assainie",
             "aucun": "retest : état maintenu"}[evt]
    return evt, motif
