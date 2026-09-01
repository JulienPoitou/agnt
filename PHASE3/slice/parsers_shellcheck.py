"""Parser spécifique — sortie JSON de shellcheck (via le wrapper `shellcheck_scan`).

SECOND NIVEAU de la promesse (voir `parsers_bandit.py`, contrat `parsers_detect_secrets.py`).
Motif d'existence : shellcheck rend `code` NUMÉRIQUE (`2034`) — la règle canonique de
l'outil est `SC2034`, préfixe que le cœur ne devinerait pas, et que le modèle déclaratif
`champs` ne peut pas fabriquer (il copie un chemin, il ne compose pas).

Forme réelle de l'entrée (mesurée sur shellcheck 0.11.0, 2026-09-01, wrapper shellcheck_scan) :

    [{"file": "…/essai.sh", "line": 2, "endLine": 2, "column": 1, "endColumn": 6,
      "level": "warning", "code": 2034,
      "message": "TOKEN appears unused. Verify use (or export if used externally).",
      "fix": {"replacements": [...]} | null}]

Tableau plat, un objet par finding ; `fix` est volontairement IGNORÉ ici (correctif
shellcheck, pas un constat de sécurité — l'inclure ferait des findings porteurs de
 transformations exécutables).

`level` (error/warning/info/style) est conservé BRUT — le cœur passe en majuscules
et marque l'origine ; inventer un mappage vers HIGH/MEDIUM attribuerait à l'outil un
jugement qu'il n'a pas porté.
"""

from __future__ import annotations

import json

from parsers import enregistrer


@enregistrer("shellcheck")
def parse(texte: str) -> list[dict]:
    if not texte or not texte.strip():
        return []
    try:
        doc = json.loads(texte)
    except Exception:
        return []
    if not isinstance(doc, list):
        return []
    items: list[dict] = []
    for it in doc:
        if not isinstance(it, dict):
            continue
        code = it.get("code")
        if isinstance(code, int):
            regle = f"SC{code:04d}"
        else:
            regle = str(code or "").strip() or "SC-inconnu"
        ligne = it.get("line")
        items.append({
            "regle": regle,
            "fichier": str(it.get("file") or ""),
            "ligne": ligne if isinstance(ligne, int) else None,
            "severite": str(it.get("level") or "").strip() or None,
            "message": str(it.get("message") or "").strip() or None,
        })
    return items
