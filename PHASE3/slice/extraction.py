"""Extraction générique — lit une sortie JSON selon une spécification DÉCLARATIVE.

Aucun nom d'outil n'apparaît dans ce fichier. C'est la condition de la promesse :
ajouter un outil au format standard ne doit pas demander de code ici.

Deux modèles couverts :

    plat      {"results": [ {...}, {...} ]}                            bandit, semgrep
    imbriqué  {"Results": [{"Target": t, "Vulnerabilities": [...]}]}   trivy

Un format qui ne rentre dans aucun des deux demande un parser spécifique. C'est le
second niveau de la promesse : parser spécifique, AUCUN changement du cœur.
"""

from __future__ import annotations

from provider_manifest import Extraction

# Les motifs de secret vivent dans assainissement.py — une seule source de vérité.
# Ce fichier ne fait que déléguer.
from assainissement import masquer_large, masquer_secrets  # noqa: F401


def _chemin(doc, chemin: str):
    """Suit un chemin pointé : 'a.b.c' ou 'a[0].b'. Renvoie None si absent.

    '$' désigne la racine elle-même : certains outils émettent une LISTE de blocs
    comme racine (un bloc par sous-analyse). Sans ce jeton, aucun chemin ne peut
    désigner la racine, et la liste est illisible en modèle déclaratif.
    """
    if chemin == "$":
        return doc
    if not chemin:
        return doc
    cur = doc
    for part in chemin.split("."):
        if cur is None:
            return None
        if "[" in part and part.endswith("]"):
            cle, idx = part[:-1].split("[")
            if cle:
                cur = cur.get(cle) if isinstance(cur, dict) else None
            if cur is None:
                return None
            try:
                cur = cur[int(idx)]
            except (ValueError, IndexError, TypeError):
                return None
        else:
            cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def extraire(brut, ex: Extraction) -> list[dict]:
    """Retourne une liste d'items bruts, aplatis selon le modèle déclaré."""
    if brut is None:
        return []

    if ex.modele == "imbriqué":
        if not ex.nested_from or not ex.nested_key:
            return []
        out = []
        groupes = _chemin(brut, ex.nested_from)
        # Certains outils émettent UN seul bloc (dict) là où ils en émettent une
        # liste quand plusieurs sous-analyses tournent. Les deux formes se lisent.
        if isinstance(groupes, dict):
            groupes = [groupes]
        for groupe in groupes or []:
            if not isinstance(groupe, dict):
                continue
            # nested_key suit un chemin pointé ('results.failed_checks'), pas
            # seulement une clé simple : des blocs peuvent nicher leurs items.
            for item in _chemin(groupe, ex.nested_key) or []:
                if not isinstance(item, dict):
                    continue
                plat = dict(item)
                # Le contexte déclaré est recopié dans chaque item : c'est ce qui
                # permet de relier une CVE à son fichier cible.
                for alias, source in ex.contexte.items():
                    if source in groupe:
                        plat[alias] = groupe[source]
                out.append(plat)
        return out

    # modèle plat
    items = _chemin(brut, ex.items_from)
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict)]


def champs(item: dict, ex: Extraction) -> dict:
    """Projette un item brut sur les champs normalisés, selon le mapping déclaré.

    Les valeurs sont passées par `masquer_secrets` : un outil peut renvoyer la valeur
    réelle d'un credential dans son message.
    """
    out = {}
    for alias, src in ex.champs.items():
        val = _chemin(item, src)
        if alias in ex.masquer_large:
            # Texte libre déclaré à risque : masquage LARGE. Un faux positif ici masque
            # un hachage dans un message — acceptable. Rater une clé ne l'est pas.
            val = masquer_large(val)[0] if isinstance(val, str) else masquer_secrets(val)
        else:
            val = masquer_secrets(val)
        out[alias] = val
    return out

