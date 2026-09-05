"""Parser arjun — stdout texte, une ligne par paramètre détecté.

arjun 2.2.7 (mesuré) écrit sur stdout, par cible :

    [*] Scanning 0/1: http://127.0.0.1:8807/search?q=essai
    …
    [✓] parameter detected: q, based on: body length
    [+] Parameters found: q

et « No parameters were discovered. » quand il ne trouve rien (code 0 dans
les deux cas). Un item PAR ligne « parameter detected » : le nom du paramètre
et l'heuristique DÉCLARÉE par l'outil sont portés tels quels. La ligne
« Parameters found: » (récapitulatif) ne devient pas un item : elle ne porte
pas l'heuristique. Pas de sévérité (surface, pas vulnérabilité) — absente,
jamais inventée. L'URL vient de la ligne « Scanning N/M: … » ; sans elle,
l'item n'a pas d'url — jamais d'URL inventée. Le fichier -o JSON n'est PAS
créé sans résultat (mesuré) : le stdout est l'autorité. Séquences ANSI
retirées (arjun colorise hors TTY, mesuré).
"""
from __future__ import annotations

import re

from parsers import enregistrer

ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_]|[()][0-9A-B])")
RE_SCAN = re.compile(r"Scanning \d+/\d+:\s+(\S+)")
RE_DETECT = re.compile(r"parameter detected:\s+(\S+),\s+based on:\s+(.+?)\s*$")


@enregistrer("arjun")
def parser_arjun(stdout: str) -> list[dict]:
    texte = ANSI.sub("", stdout or "")
    url_cible = ""
    items: list[dict] = []
    for brut in texte.splitlines():
        ligne = brut.strip()
        m = RE_SCAN.search(ligne)
        if m:
            if not url_cible:
                url_cible = m.group(1)
            continue
        m = RE_DETECT.search(ligne)
        if m:
            items.append({
                "regle": "parametre-decouvert",
                "nom_regle": m.group(1),
                "message": f"paramètre détecté par arjun, heuristique : {m.group(2)}",
                "url": url_cible,
            })
    return items
