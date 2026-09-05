"""Parser sqlmap — bloc d'injection du journal terminal, un item par technique.

sqlmap (1.10 épinglé) n'a pas de sortie JSON de détection : son journal terminal
contient, pour une cible injectable, un bloc canonique (mesuré) :

    sqlmap identified the following injection point(s) with a total of 48 HTTP(s) requests:
    ---
    Parameter: id (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
        Payload: id=1 AND 8264=8264
    ---

Un item PAR (paramètre, technique) : la même faille peut être prouvée par
plusieurs techniques, chaque payload mesuré est une preuve distincte. La
sévérité n'existe pas chez sqlmap — absente, jamais inventée ici. Le journal
contient des séquences ANSI (sqlmap colorise même hors TTY, mesuré) : elles
sont retirées avant lecture. La cible est lue sur la ligne « testing URL '…' »
(elle aussi mesurée présente) ; sans elle, l'item n'a pas d'url — jamais
d'URL inventée.
"""
from __future__ import annotations

import re

from parsers import enregistrer

# Séquences d'échappement CSI/OSC/charset (mesurées : \x1b[?1049h, \x1b(B, colorama).
# L'alternative charset est BORNÉE à un seul caractère après ( ou ) : une forme
# \(…\) non bornée avalerait tout le journal jusqu'à la première parenthèse
# (défaut mesuré : la ligne « testing URL '…' » disparaissait — corrigé).
ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_]|[()][0-9A-B])")
RE_URL = re.compile(r"testing URL '([^']+)'")
RE_PARAM = re.compile(r"^Parameter:\s+(.+)$")


@enregistrer("sqlmap")
def parser_sqlmap(stdout: str) -> list[dict]:
    texte = ANSI.sub("", stdout or "")
    url_cible = ""
    items: list[dict] = []
    courant: dict | None = None
    for brut in texte.splitlines():
        ligne = brut.rstrip()
        if not ligne.strip():
            continue
        m = RE_URL.search(ligne)
        if m:
            if not url_cible:
                url_cible = m.group(1)
            continue
        if ligne.startswith("---"):
            continue
        m = RE_PARAM.match(ligne)
        if m:
            courant = {"parametre": m.group(1).strip()}
            continue
        if courant is None:
            continue
        reste = ligne.strip()
        if reste.startswith("Type: "):
            courant = dict(courant)                # nouvelle technique, même paramètre
            courant["type"] = reste[len("Type: "):].strip()
            items.append(courant)
            continue
        if items and reste.startswith("Title: "):
            items[-1]["titre"] = reste[len("Title: "):].strip()
            continue
        if items and reste.startswith("Payload: "):
            items[-1]["payload"] = reste[len("Payload: "):].strip()
            continue

    return [{
        "regle": e.get("type") or "injection-sql",
        "nom_regle": e["parametre"],
        "message": e.get("titre") or "",
        "url": url_cible,
        "confiance": "confirmée",
        "cwe": "CWE-89",
        "preuve": e.get("payload") or "",
    } for e in items]
