#!/usr/bin/env python3
"""Cycle de vie : transitions légales/illégales + continuité d'historique.

Usage : python PHASE3/test_cycle_vie.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

from cycle_vie import (CANDIDATE, DISCOVERED, FIXED, OBSERVED,  # noqa: E402
                       REGRESSED, REJECTED, VERIFIED, TransitionError,
                       transition, valider_historique)

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def cas_interdit(nom: str, etat: str, evt: str) -> None:
    try:
        transition(etat, evt)
        cas(nom, False, "acceptée")
    except TransitionError:
        cas(nom, True)
    except Exception as e:
        cas(nom, False, f"{type(e).__name__} au lieu de TransitionError")


def main() -> int:
    cas("découverte → observation", transition(DISCOVERED, "observer") == OBSERVED)
    cas("observation → candidat", transition(OBSERVED, "candidater") == CANDIDATE)
    cas("candidat vérifié → vérifié", transition(CANDIDATE, "verifier_ok") == VERIFIED)
    cas("candidat réfuté → rejeté", transition(CANDIDATE, "verifier_ko") == REJECTED)
    cas("vérifié → corrigé → régressé → candidat → vérifié",
        transition(REGRESSED, "candidater") == CANDIDATE
        and transition(FIXED, "regresser") == REGRESSED
        and transition(VERIFIED, "corriger") == FIXED)
    cas("rejeté → rouvert en candidat", transition(REJECTED, "rouvrir") == CANDIDATE)
    for nom, etat, evt in [
        ("saut direct en vérifié interdit", DISCOVERED, "verifier_ok"),
        ("vérifié ne redevient pas observé", VERIFIED, "observer"),
        ("corrigé sans vérification interdit", CANDIDATE, "corriger"),
        ("rejeté ne se corrige pas", REJECTED, "corriger"),
        ("observé ne se vérifie pas direct", OBSERVED, "verifier_ok"),
        ("état inconnu nommé", "fantome", "observer"),
        ("événement inconnu nommé", CANDIDATE, "approuver"),
    ]:
        cas_interdit(nom, etat, evt)
    bon = [{"depuis": DISCOVERED, "evenement": "observer", "vers": OBSERVED},
           {"depuis": OBSERVED, "evenement": "candidater", "vers": CANDIDATE},
           {"depuis": CANDIDATE, "evenement": "verifier_ok", "vers": VERIFIED},
           {"depuis": VERIFIED, "evenement": "corriger", "vers": FIXED}]
    cas("historique continu valide", valider_historique(bon) == (True, "historique_valide"))
    cas("historique vide refusé", valider_historique([])[0] is False)
    cas("rupture détectée", valider_historique(
        bon[:2] + [{"depuis": VERIFIED, "evenement": "corriger", "vers": FIXED}])[0] is False)
    cas("pas incohérent détecté", valider_historique(
        [{"depuis": DISCOVERED, "evenement": "observer", "vers": VERIFIED}])[0] is False)
    cas("origine non-découverte refusée", valider_historique(
        [{"depuis": OBSERVED, "evenement": "candidater", "vers": CANDIDATE}])[0] is False)

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
