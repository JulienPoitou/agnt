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
import sys
from pathlib import Path

from assainissement import masquer_large

_REGISTRE = {}
_REGISTRE_CHARGÉ = False
# Nom du module → raison de l'échec. Lu par le test de cohérence : un module de parser
# qui ne s'importe pas est un trou de couverture, pas un détail.
_IMPORT_ÉCHOUÉ: dict[str, str] = {}


def enregistrer(nom: str):
    """Décorateur d'enregistrement. Utilisé par les modules de parsers."""
    def _decorateur(fn):
        _REGISTRE[nom] = fn
        return fn
    return _decorateur


def _charger_tous() -> None:
    """Importe TOUS les modules `parsers_*.py` du paquet — l'enregistrement est un effet
    de bord du décorateur `@enregistrer`.

    Pourquoi ce n'est plus une liste à la main : ajouter un outil devait jusqu'ici
    modifier CE fichier (le registre des parsers), ce qui contredisait la promesse —
    « un nouveau format = un fichier en plus, aucun changement du cœur ». La découverte
    est bornée au répertoire du paquet et ignore les modules cassés : un parser dont
    l'import échoue ne doit pas empêcher les autres de s'enregistrer, mais il est CONSIGNÉ
    (la variable `_import_échoué` est lue par le test de cohérence).
    """
    global _REGISTRE_CHARGÉ
    if _REGISTRE_CHARGÉ:
        return
    _REGISTRE_CHARGÉ = True
    repertoire = Path(__file__).resolve().parent
    for fichier in sorted(repertoire.glob("parsers_*.py")):
        nom = fichier.stem
        if nom not in sys.modules:
            try:
                __import__(nom)
            except Exception as e:                     # noqa: BLE001  (voir ci-dessus)
                _IMPORT_ÉCHOUÉ[nom] = f"{type(e).__name__}: {e}"


def obtenir(nom: str):
    """Retourne un parser par son nom, ou None."""
    if nom not in _REGISTRE:
        _charger_tous()
    return _REGISTRE.get(nom)


def disponibles() -> list[str]:
    _charger_tous()
    return sorted(_REGISTRE)


def echecs_import() -> dict[str, str]:
    """Modules de parser non chargés (nom → erreur). Vide attendu."""
    _charger_tous()
    return dict(_IMPORT_ÉCHOUÉ)


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
