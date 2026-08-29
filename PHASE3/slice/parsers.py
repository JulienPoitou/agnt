"""Registre de parsers — le second niveau de la promesse.

    outil JSON/SARIF standard    → manifest déclaratif uniquement      (aucun code)
    outil au format propriétaire → parser spécifique, AUCUN changement du cœur

Ce fichier n'est PAS le cœur. C'est un point d'enregistrement : le pipeline ne connaît
que la fonction `obtenir()`, et ne sait rien des outils.

Un parser est enregistré par le MANIFEST, pas par le code du pipeline :

    extraction:
      parser: bandit_custom

Contrat d'un parser — ce qu'il doit respecter pour ne pas casser le cœur :

    parse(texte: str) -> list[dict]

    · chaque dict porte au minimum : regle, fichier
    · les valeurs sont déjà assainies (le parser DOIT masquer les secrets)
    · aucune levée d'exception sur une entrée inattendue : retourner []

Si un parser ne respecte pas ce contrat, c'est le parser qui est faux, pas le cœur.
"""

from __future__ import annotations

import re

from assainissement import masquer_large

_REGISTRE = {}


def enregistrer(nom: str):
    """Décorateur d'enregistrement. Utilisé par les modules de parsers."""
    def _decorateur(fn):
        _REGISTRE[nom] = fn
        return fn
    return _decorateur


def obtenir(nom: str):
    """Retourne un parser par son nom, ou None.

    Importe paresseusement les parsers connus : le cœur ne les importe jamais lui-même.
    """
    if nom not in _REGISTRE:
        try:
            import parsers_bandit  # noqa: F401  (effet de bord : enregistrement)
        except ImportError:
            pass
    return _REGISTRE.get(nom)


def disponibles() -> list[str]:
    obtenir("__forcer_chargement__")
    return sorted(_REGISTRE)


# ------------------------------------------------------------------ utilitaires
LIGNE_CSV = re.compile(r"^(?P<fichier>[^,]+),(?P<ligne>\d+),(?P<regle>[^,]+),(?P<reste>.*)$")


def separer_csv(texte: str) -> list[dict]:
    """Découpe une sortie CSV simple. Utilitaire partagé par les parsers."""
    out = []
    for ligne in (texte or "").splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#"):
            continue
        m = LIGNE_CSV.match(ligne)
        if not m:
            continue
        out.append({
            "fichier": m.group("fichier").strip(),
            "ligne": int(m.group("ligne")) if m.group("ligne").isdigit() else None,
            "regle": m.group("regle").strip(),
            # Le reste est du TEXTE LIBRE : masquage large, parce qu'un outil peut y
            # mettre la valeur réelle d'un credential.
            "message": masquer_large(m.group("reste").strip())[0],
        })
    return out
