"""Parser gobuster — sortie TEXTE du mode dir (PAS de JSON en 3.8.2, mesuré).

Ligne réelle (mesurée le 2026-09-05 sur gobuster 3.8.2, flag -e requis pour que
l'URL soit complète) :

    http://127.0.0.1:8807/.env                 (Status: 200) [Size: 115]

Chaque ligne retenue est un chemin qui répond hors des exclusions de l'outil
(404 par défaut). Une redirection porte en plus « --> <location> » en fin de
ligne : le motif le tolère (match de préfixe) et n'invente rien sur la
redirection — elle n'est pas un champ du manifest. La sévérité n'existe pas
chez cet outil : absente, jamais inventée ici.
"""
from __future__ import annotations

import re

from parsers import enregistrer

LIGNE = re.compile(
    r"^(?P<url>\S+) \(Status: (?P<status>\d+)\) \[Size: (?P<taille>\d+)\]"
)


@enregistrer("gobuster")
def parser_gobuster(stdout: str) -> list[dict]:
    items = []
    for brut in (stdout or "").splitlines():
        m = LIGNE.match(brut.strip())
        if not m:
            continue
        url = m.group("url")
        statut = m.group("status")
        taille = m.group("taille")
        # Le « mot » testé est le chemin de l'URL (la wordlist est montée à
        # {REGLES}, les lignes -e portent l'URL complète).
        chemin = url.split("//", 1)[-1].split("/", 1)
        path = "/" + chemin[1] if len(chemin) > 1 else "/"
        items.append({
            "regle": path,
            "url": url,
            "message": f"statut HTTP {statut} (taille {taille})",
        })
    return items
