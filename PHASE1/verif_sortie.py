#!/usr/bin/env python3
"""
Vérifie mécaniquement les huit conditions de sortie de la Phase 1 (CRITERES.md §8).

Renvoie 0 si toutes sont remplies, 1 sinon. L'objectif est que « la Phase 1 est terminée »
soit un fait vérifiable, pas une opinion.

Usage : python3 PHASE1/verif_sortie.py
"""

from __future__ import annotations

import csv
import re
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).parent

CONDITIONS = [
    "Les 324 entrées ont un statut de triage",
    "Les 38 repos de la shortlist ont une fiche complète",
    "Les 65 repos « Haute » restants ont une ligne de triage complète et un motif",
    "Les gates et signaux de risque sont cohérents avec le code",
    "La licence de la plateforme est décidée, au moins provisoirement",
    "La matrice de couverture est remplie",
    "03_ARCHI_REFERENCE.md répond aux cinq questions obligatoires",
    "Les décisions non prises sont transférées au backlog Phase 2",
]


def lit_csv(nom: str) -> list[dict]:
    p = BASE / nom
    if not p.exists():
        return []
    return list(csv.DictReader(p.open(encoding="utf-8-sig")))


def lit(nom: str) -> str:
    p = BASE / nom
    return p.read_text(encoding="utf-8") if p.exists() else ""


def c1() -> tuple[bool, str]:
    rows = lit_csv("02_TRIAGE.csv")
    if not rows:
        return False, "02_TRIAGE.csv absent"
    sans = [r.get("owner_repo") or r.get("nom") for r in rows if not r.get("statut")]
    if sans:
        return False, f"{len(sans)} lignes sans statut"
    return len(rows) == 324, f"{len(rows)} lignes avec statut (attendu 324)"


def c2() -> tuple[bool, str]:
    rows = lit_csv("NOTES.csv")
    if not rows:
        return False, "NOTES.csv absent"
    requis = ("C1", "C2", "C3", "usage", "mode_integration", "confiance", "preuve")
    incomplets = [r["owner_repo"] for r in rows if any(not r.get(k) for k in requis)]
    shortlist = [r for r in rows]
    return (not incomplets and len(shortlist) >= 38,
            f"{len(shortlist)} fiches, {len(incomplets)} incomplètes "
            f"(champs requis: {', '.join(requis)})")


def c3() -> tuple[bool, str]:
    rows = [r for r in lit_csv("02_TRIAGE.csv") if r.get("statut") == "TRIAGE-HAUTE"]
    sans = [r.get("owner_repo") or r.get("nom") for r in rows if not r.get("motif", "").strip()]
    return (bool(rows) and not sans,
            f"{len(rows)} repos en triage obligatoire, {len(sans)} sans motif")


def c4() -> tuple[bool, str]:
    """Les tests du pipeline doivent passer : c'est la seule preuve que gates et code concordent."""
    echecs = []
    for t in ("test_parse_page.py", "test_verdict.py"):
        r = subprocess.run([sys.executable, str(BASE / t)], capture_output=True, text=True)
        if r.returncode != 0:
            echecs.append(t)
    grille = lit_csv("01_GRILLE_TRI.csv")
    # aucune gate sur une entrée sans repo exploitable
    fantomes = [r["owner_repo"] for r in grille if r.get("etat") != "ok" and r.get("gate")]
    if fantomes:
        echecs.append(f"{len(fantomes)} gates fantômes sur des fiches sans repo")
    return (not echecs, "tests OK, aucune gate fantôme" if not echecs else "; ".join(echecs))


def c5() -> tuple[bool, str]:
    txt = lit("CRITERES.md")
    ok = "Apache-2.0" in txt and "décision provisoire" in txt.lower()
    return ok, "Apache-2.0 actée en §2.3" if ok else "licence non actée dans CRITERES.md"


def c6() -> tuple[bool, str]:
    txt = lit("06_MATRICE_COUVERTURE.md")
    if not txt:
        return False, "06_MATRICE_COUVERTURE.md absent"
    manque = [c for c in ("confiance", "preuve", "Axe", "capability") if c.lower() not in txt.lower()]
    return not manque, "matrice présente avec confiance et preuve" if not manque else f"manque: {manque}"


def c7() -> tuple[bool, str]:
    txt = lit("03_ARCHI_REFERENCE.md")
    qs = [f"Q{i}" for i in range(1, 6)]
    manque = [q for q in qs if not re.search(rf"^#+\s*{q}\b", txt, re.M)]
    return not manque, "les cinq questions sont traitées" if not manque else f"manque: {manque}"


def c8() -> tuple[bool, str]:
    """Les décisions non prises doivent être quelque part, nommément.

    Compter des titres de section ne prouve rien : on vérifie que chacune des décisions
    en attente de la Phase 2 apparaît dans le backlog OU dans l'architecture de référence.
    """
    txt = (lit("99_BACKLOG.md") + lit("03_ARCHI_REFERENCE.md")).lower()
    attendues = {
        "SARIF": "modèle de findings",
        "policy engine": "architecture du policy engine",
        "sandbox": "niveau d'isolation",
        "contextforge": "rôle de ContextForge",
        "orchestrat": "choix de l'orchestrateur",
    }
    manquantes = [v for k, v in attendues.items() if k.lower() not in txt]
    return not manquantes, ("les 5 décisions de Phase 2 sont tracées"
                            if not manquantes else f"manque: {manquantes}")


CHECKS = [c1, c2, c3, c4, c5, c6, c7, c8]


def main() -> int:
    print("CRITÈRE DE SORTIE — PHASE 1\n")
    ok_total = True
    for i, (cond, check) in enumerate(zip(CONDITIONS, CHECKS), 1):
        ok, detail = check()
        ok_total &= ok
        print(f"  [{'X' if ok else ' '}] {i}. {cond}")
        print(f"        → {detail}")
    print("\n" + ("PHASE 1 TERMINÉE" if ok_total else "PHASE 1 NON TERMINÉE"))
    return 0 if ok_total else 1


if __name__ == "__main__":
    raise SystemExit(main())
