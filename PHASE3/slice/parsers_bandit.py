"""Parser spécifique — format « custom » de Bandit (CSV).

Ceci est le SECOND NIVEAU de la promesse :

    outil au format propriétaire → parser spécifique, AUCUN changement du cœur

Ce fichier n'est PAS le cœur. Il s'enregistre dans `parsers.py`, et le manifest le
référence par son nom :

    extraction:
      parser: bandit_custom

Le pipeline ne connaît que `parsers.obtenir(nom)`. Il ne sait pas que Bandit existe,
ni ce qu'est un CSV.

Contrat respecté :
    parse(texte) -> list[dict] avec au minimum `regle` et `fichier`
    valeurs assainies
    aucune exception sur entrée inattendue
"""

from __future__ import annotations

from parsers import enregistrer, separer_csv


@enregistrer("bandit_custom")
def parse(texte: str) -> list[dict]:
    """Lit la sortie CSV de `bandit -f custom`.

    Format produit par :
        bandit -f custom --msg-template "{relpath},{line},{test_id},{msg}"

    `{msg}` est du TEXTE LIBRE : Bandit y met la valeur réelle d'un credential pour la
    règle B105. `separer_csv` applique donc le masquage large sur ce champ.
    """
    if not texte or not texte.strip():
        return []
    try:
        return separer_csv(texte)
    except Exception:
        # Un parser ne doit jamais faire tomber le pipeline : il retourne ce qu'il a.
        return []
