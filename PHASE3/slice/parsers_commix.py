"""Parser commix — journal terminal, marqueur lu dans le SOURCE épinglé.

commix 4.1 (déterminé sur l'épreuve : aucune faille de commande sur THAUMAS)
imprime son constat dans `checks.identified_vulnerable_param` du dépôt épinglé
(lu, ligne 2961) :

    info_msg = CHECKING_PARAMETER + " appears to be injectable via "
    info_msg += "(" + injection_type.split(" ")[0] + ") " + technique + "."
    …
    sub_content = str(url_decode(payload))
    settings.print_data_to_stdout(settings.print_sub_content(sub_content))

Un constat = la ligne « … appears to be injectable via … » suivie du payload
imprimé à la ligne suivante. La sévérité n'existe pas chez commix — absente,
jamais inventée. commix n'imprime PAS l'URL cible dans son journal (mesuré) :
les items n'ont pas d'url — jamais d'URL inventée. Le journal est colorisé
(colorama) même hors TTY : les séquences ANSI sont retirées avant lecture.
"""
from __future__ import annotations

import re

from parsers import enregistrer

ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_]|[()][0-9A-B])")
MARQUE = " appears to be injectable via "
RE_TECHNIQUE = re.compile(r"appears to be injectable via (.+?)\.\s*$")
RE_PARAMETRE = re.compile(r"'([^']+)'")


@enregistrer("commix")
def parser_commix(stdout: str) -> list[dict]:
    texte = ANSI.sub("", stdout or "")
    lignes = texte.splitlines()
    items: list[dict] = []
    for idx, brut in enumerate(lignes):
        ligne = brut.strip()
        if MARQUE not in ligne:
            continue
        m = RE_TECHNIQUE.search(ligne)
        technique = m.group(1).strip() if m else ""
        technique = technique.strip("() ").strip()
        avant = ligne.split(MARQUE, 1)[0]
        pm = RE_PARAMETRE.search(avant)
        # Le payload (sub_content) est imprimé à la ligne suivante (source).
        preuve = ""
        if idx + 1 < len(lignes):
            preuve = lignes[idx + 1].strip()
        items.append({
            "regle": f"injection-commande ({technique})" if technique else "injection-commande",
            "nom_regle": pm.group(1) if pm else "paramètre inconnu",
            "message": ligne,
            "confiance": "confirmée",
            "cwe": "CWE-78",
            "preuve": preuve,
        })
    return items
