#!/usr/bin/env python3
"""
Teste parse_page() de enrich.py — le seul point où une mauvaise extraction de licence
pourrait faire basculer la gate G2 à tort.

Principe de conception vérifié ici : quand la licence n'est pas identifiable de façon
fiable, le parseur doit renvoyer "" (inconnu) et JAMAIS deviner. Une licence inconnue
déclenche G2, ce qui est le sens d'erreur acceptable : on refuse de réutiliser du code
dont on ne connaît pas la licence, alors qu'on peut toujours piloter l'outil en CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import enrich  # noqa: E402

CASES = [
    # (html, licence attendue, pourquoi)
    ('"spdxId":"Apache-2.0" bla', "Apache-2.0", "SPDX propre -> utilisé tel quel"),
    ('"spdxId":"NOASSERTION" et BSD-3-Clause license ensuite', "BSD-3-Clause",
     "SPDX NOASSERTION ignoré, repli texte valable"),
    ("Released under the MIT license for everyone", "MIT", "repli texte, mot-clé connu"),
    ("Texte avec actual license mentionnee", "", "'actual' est du prose, pas une licence"),
    ("under the current license terms", "", "'current' est du prose, pas une licence"),
    ('"license":{"name":"Actual license","spdxId":"NOASSERTION"}', "",
     "GitHub dit 'Actual license' = placeholder"),
    ('"license":{"name":"Other","spdxId":"NOASSERTION"}', "",
     "cas hashicorp/vault reel : 'Other' n'est pas un SPDX -> inconnu"),
    ("the Nmap Public Source License applies", "",
     "licence multi-mots : non fiable a extraire -> inconnu plutot que faux"),
    ("funded by a startup license program", "", "'startup' n'est pas une licence"),
]

STAR_CASES = [
    ('{"repository":{"stargazerCount":30872}}', 30872, "valeur exacte, pas '31k'"),
    ('{"repository":{"stargazerCount":0}}', 0, "repo a zero etoile"),
    ("pas de json ici", "", "absence -> vide, pas 0"),
]

ARCHIVED_CASES = [
    ('<span>Public archive</span>', "yes", "badge d'archivage"),
    ("This repository has been archived by the owner", "yes", "banniere d'archivage"),
    ("rien de particulier", "", "repo actif"),
]


def run() -> int:
    echecs = 0
    print("--- licence ---")
    for html, attendu, pourquoi in CASES:
        obtenu = enrich.parse_page(html)["licence"]
        ok = obtenu == attendu
        echecs += not ok
        print(f"  {'OK ' if ok else 'KO '} {obtenu!r:<16} attendu {attendu!r:<16} {pourquoi}")

    print("--- stars ---")
    for html, attendu, pourquoi in STAR_CASES:
        obtenu = enrich.parse_page(html)["stars"]
        ok = obtenu == attendu
        echecs += not ok
        print(f"  {'OK ' if ok else 'KO '} {obtenu!r:<16} attendu {attendu!r:<16} {pourquoi}")

    print("--- archivage ---")
    for html, attendu, pourquoi in ARCHIVED_CASES:
        obtenu = enrich.parse_page(html)["archived"]
        ok = obtenu == attendu
        echecs += not ok
        print(f"  {'OK ' if ok else 'KO '} {obtenu!r:<16} attendu {attendu!r:<16} {pourquoi}")

    total = len(CASES) + len(STAR_CASES) + len(ARCHIVED_CASES)
    print(f"\n{total - echecs}/{total} conformes")
    return 1 if echecs else 0


if __name__ == "__main__":
    raise SystemExit(run())
