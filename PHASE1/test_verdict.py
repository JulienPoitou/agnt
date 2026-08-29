#!/usr/bin/env python3
"""
Teste scoring.verdict() — la fonction qui transforme un score en décision.

C'est le point le plus sensible du pipeline : une erreur ici se propage silencieusement
dans toute la shortlist. Trois régressions réelles sont couvertes :
  - les gates G2 n'étaient pas appliquées du tout (AGPL sortait en INTEGRATE) ;
  - une gate de licence bloquait un simple pilotage CLI, ce qui est faux ;
  - la règle « usage prime » faisait remonter des repos faibles en ADAPT (archi),
    ce qui supprimait purement et simplement le verdict IGNORE.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import scoring  # noqa: E402

REF = "référence architecturale"
TOOL = "outil externe"
CODE = "code réutilisable"
INFRA = "composant d'infrastructure"

# (C1, C2, C3, gates, usage, verdict attendu, pourquoi)
CASES = [
    # --- base ---
    (5, 5, 5, [], TOOL, "INTEGRATE", "outil solide, aucune gate"),
    (5, 5, 5, [], CODE, "INTEGRATE", "code solide, licence propre"),
    (1, 1, 1, [], REF, "IGNORE", "faible partout : pas une référence"),

    # --- régression 1 : G2 doit bloquer la réutilisation de code ---
    (4, 4, 4, ["G2:copyleft-fort"], CODE, "ADAPT (archi)", "AGPL bloque l'import de code"),
    (4, 4, 4, ["G2:licence-inconnue"], CODE, "ADAPT (archi)", "licence inconnue bloque l'import"),

    # --- régression 2 : G2 ne bloque PAS un pilotage CLI ---
    (4, 4, 4, ["G2:copyleft"], TOOL, "INTEGRATE", "Semgrep en CLI : la licence ne s'applique pas"),
    (4, 4, 4, ["G2:copyleft-fort"], TOOL, "INTEGRATE", "outil AGPL piloté en API : toujours OK"),
    (4, 4, 4, ["G2:licence-inconnue"], INFRA, "ADAPT (archi)", "infra modifiable : licence applicable"),

    # --- régression 3 : usage prime, mais IGNORE reste possible ---
    (2, 3, 4, [], REF, "IGNORE", "score 2,7 et C1=2 : écarté malgré usage=référence"),
    (3, 3, 3, [], REF, "IGNORE", "score 3,0 et C1=3 : sous le seuil, écarté"),
    (4, 2, 2, [], REF, "ADAPT (archi)", "score 3,0 mais C1=4 : l'architecture vaut"),
    (5, 4, 4, [], REF, "ADAPT (archi)", "excellente archi, usage lecture -> jamais INTEGRATE"),
    (3, 2, 2, ["G1:inactif", "G5:archive"], REF, "IGNORE", "score 2,5 : écarté"),

    # --- G1 / G5 bloquent tout usage ---
    (5, 5, 5, ["G5:archive"], TOOL, "ADAPT (archi)", "archivé : même en outil, on n'intègre pas"),
    (5, 5, 5, ["G1:inactif"], CODE, "ADAPT (archi)", "inactif : pas de réutilisation"),

    # --- frontières exactes (CRITERES.md §3.5) ---
    (4, 4, 4, [], CODE, "INTEGRATE", "4,0 exactement = INTEGRATE"),
    (5, 1, 1, [], CODE, "ADAPT (archi)", "3,0 n'est pas INTEGRATE ; C1=5 -> l'archi vaut"),
    (3, 4, 4, [], CODE, "ADAPT", "3,8 avec C1=3 -> ADAPT simple"),
    (3, 4, 3, [], CODE, "ADAPT", "3,3 = ADAPT"),
    (4, 1, 1, [], CODE, "ADAPT (archi)", "2,6 mais C1=4 -> l'architecture vaut"),

    # --- absence de notes ---
    ("", "", "", [], TOOL, "A_NOTER", "pas de note -> pas de verdict inventé"),
]


def test_penalite() -> int:
    """G3 : la pénalité ne s'applique que si elle est renseignée, et ne descend pas sous 0."""
    cas = [(("4", "4", "4", ""), 4.0, "pénalité vide = pas d'effet"),
           (("4", "4", "4", "1"), 3.0, "problème confirmé -> -1"),
           (("0", "0", "0", "5"), 0.0, "plancher à 0, jamais négatif"),
           (("4", "4", "4", 1), 3.0, "pénalité en int acceptée")]
    echecs = 0
    print("--- pénalité G3 ---")
    for args, attendu, pourquoi in cas:
        obtenu = scoring.score(*args)
        ok = obtenu == attendu
        echecs += not ok
        print(f"  {'OK ' if ok else 'KO '} score{args} = {obtenu} (attendu {attendu})  {pourquoi}")
    try:
        scoring.score("4", "4", "4", "abc")
        print("  KO  pénalité invalide acceptée")
        echecs += 1
    except ValueError:
        print("  OK  pénalité invalide -> ValueError")
    return echecs


def run() -> int:
    echecs = test_penalite()
    for c1, c2, c3, gates, usage, attendu, pourquoi in CASES:
        total = scoring.score(c1, c2, c3)
        obtenu = scoring.verdict(c1, total, gates, usage)
        ok = obtenu == attendu
        echecs += not ok
        print(f"  {'OK ' if ok else 'KO '} C1={c1} score={str(total):<5} "
              f"{'/'.join(g.split(':')[0] for g in gates) or '-':<10} {usage[:22]:<24} "
              f"-> {obtenu:<15} (attendu {attendu})  {pourquoi}")

    n_cases = len(CASES) + 5  # + 5 cas de pénalité G3
    print(f"\n{n_cases - echecs}/{n_cases} conformes")

    # cohérence interne : les quatre verdicts doivent rester atteignables
    v = {
        scoring.verdict(5, 5.0, [], TOOL),
        scoring.verdict(4, 4.5, ["G5:archive"], REF),
        scoring.verdict(4, 3.5, [], CODE),
        scoring.verdict(2, 2.7, [], REF),
    }
    print("verdicts atteignables:", sorted(v))
    if len(v) != 4:
        print("KO: un verdict est devenu inaccessible")
        echecs += 1

    return 1 if echecs else 0


if __name__ == "__main__":
    raise SystemExit(run())
