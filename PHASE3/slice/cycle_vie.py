"""Cycle de vie des findings : DISCOVERED → … → FIXED (Stream : findings).

Une détection ne devient JAMAIS une vulnérabilité confirmée par décret :
chaque passage d'état exige un événement nommé, et les sauts sont refusés
(`TransitionError`). Vocabulaire aligné sur `oracle.py` :
CANDIDATE≈POTENTIAL, VERIFIED≈CONFIRMED, REJECTED≈REFUTED.
"""
from __future__ import annotations


class TransitionError(Exception):
    """Transition invalide : état, événement et raison nommés."""


DISCOVERED = "discovered"
OBSERVED = "observed"
CANDIDATE = "candidate"
VERIFIED = "verified"
REJECTED = "rejected"
FIXED = "fixed"
REGRESSED = "regressed"

ETATS = (DISCOVERED, OBSERVED, CANDIDATE, VERIFIED, REJECTED, FIXED, REGRESSED)
TERMINAUX = (REJECTED,)          # seul REJECTED est terminal sans appel explicite

TRANSITIONS: dict[tuple[str, str], str] = {
    (DISCOVERED, "observer"): OBSERVED,
    (DISCOVERED, "rejeter"): REJECTED,
    (OBSERVED, "candidater"): CANDIDATE,
    (OBSERVED, "rejeter"): REJECTED,
    (CANDIDATE, "verifier_ok"): VERIFIED,
    (CANDIDATE, "verifier_ko"): REJECTED,
    (CANDIDATE, "rejeter"): REJECTED,
    (VERIFIED, "corriger"): FIXED,
    (VERIFIED, "regresser"): REGRESSED,
    (VERIFIED, "rejeter"): REJECTED,
    (FIXED, "regresser"): REGRESSED,
    (FIXED, "rouvrir"): CANDIDATE,
    (REGRESSED, "candidater"): CANDIDATE,
    (REGRESSED, "corriger"): FIXED,
    (REJECTED, "rouvrir"): CANDIDATE,
}

EVENEMENTS = sorted({e for _, e in TRANSITIONS})


def transition(etat: str, evenement: str) -> str:
    """État suivant, ou `TransitionError` nommée (jamais de saut silencieux)."""
    if etat not in ETATS:
        raise TransitionError(f"état inconnu : {etat!r} — admis : {list(ETATS)}")
    if evenement not in EVENEMENTS:
        raise TransitionError(f"événement inconnu : {evenement!r} — admis : {EVENEMENTS}")
    try:
        return TRANSITIONS[(etat, evenement)]
    except KeyError:
        raise TransitionError(f"transition interdite : {etat} + {evenement}") from None


def valider_historique(historique) -> tuple[bool, str]:
    """Une chaîne d'étapes est continue : chaque `depuis` égale le `vers`
    précédent, chaque pas est une transition légale. Rend (ok, motif)."""
    if not historique:
        return False, "historique_vide"
    if not isinstance(historique, list):
        return False, "historique_non_liste"
    attendu = None
    for i, pas in enumerate(historique):
        if not isinstance(pas, dict):
            return False, f"pas_{i}_non_objet"
        depuis, evt, vers = pas.get("depuis"), pas.get("evenement"), pas.get("vers")
        try:
            calcule = transition(depuis, evt)
        except TransitionError as e:
            return False, f"pas_{i}_illegal : {e}"
        if calcule != vers:
            return False, f"pas_{i}_incoherent : {depuis}+{evt}={calcule}, déclaré {vers}"
        if attendu is not None and depuis != attendu:
            return False, f"pas_{i}_rupture : {depuis} après {attendu}"
        attendu = vers
    if historique[0].get("depuis") != DISCOVERED:
        return False, f"origine : {historique[0].get('depuis')!r} au lieu de {DISCOVERED}"
    return True, "historique_valide"
