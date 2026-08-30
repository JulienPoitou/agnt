"""Parser spécifique — sortie JSON de `detect-secrets scan --all-files`.

SECOND NIVEAU de la promesse (voir `parsers_bandit.py`) : un outil dont la sortie ne
rentre dans aucun modèle s'enregistre ici, le cœur n'est pas modifié.

Forme réelle de l'entrée (mesurée sur detect-secrets 1.5.0, 30/08/2026) :

    {"version": "1.5.0", "plugins_used": [...], "filters_used": [...],
     "results": {"app.py": [{"type": "AWS Access Key", "filename": "app.py",
                             "hashed_secret": "d70eab…", "is_verified": false,
                             "line_number": 4}]},
     "generated_at": "…"}

`results` est un dictionnaire de listes, Indexé PAR FICHIER : ni « plat », ni « imbriqué
par chemin » (les deux modèles déclaratifs du manifest). C'est ce qui justifie un parser.

Deux propriétés de cet outil engagent ce parser :
· `hashed_secret` : l'outil NE REND JAMAIS le secret en clair — c'est une empreinte.
  Le message conserve le PRÉFIXE de cette empreinte (permet de raccorder deux findings au
  même secret sans porter la valeur).
· `is_verified: false` par défaut : la vérification (`--verify`) interroge le fournisseur
  du token, donc SORT SUR LE RÉSEAU. Elle n'est pas demandée ; le message le dit, sinon un
  « non vérifié » se lirait « confirmé ».
"""

from __future__ import annotations

import json

from parsers import enregistrer

_PREFIXE_EMPREINTE = 16


@enregistrer("detect_secrets_scan")
def parse(texte: str) -> list[dict]:
    if not texte or not texte.strip():
        return []
    try:
        doc = json.loads(texte)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    resultats = doc.get("results")
    if not isinstance(resultats, dict):
        return []
    items: list[dict] = []
    for fichier, liste in resultats.items():
        if not isinstance(liste, list):
            continue
        for it in liste:
            if not isinstance(it, dict):
                continue
            type_ = str(it.get("type") or "").strip() or "secret-détecté"
            empreinte = str(it.get("hashed_secret") or "")[:_PREFIXE_EMPREINTE]
            ligne = it.get("line_number")
            verif = ("vérifié" if it.get("is_verified")
                     else "non vérifié (l'outil n'a pas interrogé le fournisseur)")
            items.append({
                "regle": type_,
                "fichier": str(fichier or ""),
                "ligne": ligne if isinstance(ligne, int) else None,
                "message": f"{type_} — empreinte {empreinte} — {verif}",
            })
    return items
