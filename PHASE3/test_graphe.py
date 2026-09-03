#!/usr/bin/env python3
"""Graphe : types, dédup par empreinte, convergence, chemins, refus.

Usage : python PHASE3/test_graphe.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

from graphe import ErreurGraphe, Graphe                            # noqa: E402

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def main() -> int:
    g = Graphe()
    g.ajouter_noeud("target", "https://target.tld/")
    g.ajouter_noeud("asset", "url:https://target.tld/a")
    g.ajouter_noeud("execution", "run-1")
    g.ajouter_noeud("provider", "nuclei")
    f1 = g.ajouter_finding("nuclei:t1", ("url", "https://target.tld/a"),
                           "fp1", ["nuclei"])
    f2 = g.ajouter_finding("nuclei:t1", ("url", "https://target.tld/a"),
                           "fp1", ["zap_baseline"])
    cas("même empreinte → UN nœud, sources fusionnées",
        f1 is f2 and f2["attrs"]["sources"] == ["nuclei", "zap_baseline"]
        and len([n for n in g.noeuds if n[0] == "finding"]) == 1)
    g.ajouter_finding("nuclei:t2", ("url", "https://target.tld/a"), "fp2", ["nuclei"])
    g.ajouter_lien("finding", "fp1", "prouve", "execution", "run-1")
    g.ajouter_lien("execution", "run-1", "fournit", "provider", "nuclei")
    g.ajouter_lien("finding", "fp1", "expose", "target", "https://target.tld/")
    ch = g.chemin_attaque("fp1")
    cas("chemin à un saut depuis le finding, sans invention multi-sauts",
        [m.get("noeud") for m in ch] == [["finding", "fp1"], ["execution", "run-1"],
                                         ["target", "https://target.tld/"]],
        str(ch)[:160])
    g2 = Graphe()
    g2.ajouter_finding("r", ("url", "u"), "a", ["x"])
    g2.ajouter_finding("r", ("url", "u"), "b", ["y"])
    g2.ajouter_finding("r", ("url", "autre"), "c", ["z"])
    cas("convergence : même (règle, coordonnée) liée, le reste non",
        g2.relier_convergence() == 1 and len(g2.liens) == 1)
    try:
        g.ajouter_noeud("vaisseau", "x")
        cas("type inconnu → refus", False, "accepté")
    except ErreurGraphe:
        cas("type inconnu → refus", True)
    try:
        g.ajouter_noeud("target", "")
        cas("id vide → refus", False, "accepté")
    except ErreurGraphe:
        cas("id vide → refus", True)
    try:
        g.ajouter_lien("finding", "fp1", "prouve", "evidence", "absente")
        cas("lien vers nœud absent → refus", False, "accepté")
    except ErreurGraphe:
        cas("lien vers nœud absent → refus", True)
    try:
        g.chemin_attaque("introuvable")
        cas("chemin inconnu → refus", False, "accepté")
    except ErreurGraphe:
        cas("chemin inconnu → refus", True)
    d = g.to_dict()
    cas("export trié et complet (6 nœuds, 3 liens)",
        len(d["noeuds"]) == 6 and len(d["liens"]) == 3
        and [n["type"] for n in d["noeuds"]] == sorted(n["type"] for n in d["noeuds"]))

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
