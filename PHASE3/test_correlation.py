#!/usr/bin/env python3
"""Corrélation — MÉCANISME, sur fixture contrôlée.

Périmètre strict de ce fichier : le mécanisme de regroupement inter-outils.
Il ne prétend PAS mesurer la généralité — c'est le rôle de test_independant.py.

TROIS ÉTATS, JAMAIS MÉLANGÉS
    succès        → OK, compté
    échec         → ECHEC, et exit 1
    non évalué    → signalé comme tel, PAS compté comme un succès, PAS un échec

La version précédente de ce fichier affichait « 7 OK + 1 non satisfait » avec exit 0 :
un état non évalué noyé dans une suite verte. C'est corrigé — la partie « généralisation »
a été retirée d'ici et vit dans test_independant.py.

Usage : python3 PHASE3/test_correlation.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import pipeline  # noqa: E402

FIXTURE = RACINE / "testrepo_xtool"

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


# Scanners dont cette suite a besoin pour produire de vrais findings.
_OUTILS = ("semgrep", "bandit", "trivy", "grype", "gitleaks", "detect-secrets", "checkov")


def _outils_absents(*noms) -> bool:
    """Aucun des binaires nommés n'est résolvable : c'est l'environnement, pas le code."""
    import shutil
    return all(shutil.which(n) is None for n in (noms or _OUTILS))


def main() -> int:
    print("=== CORRÉLATION — MÉCANISME (fixture contrôlée) ===\n")
    if not FIXTURE.exists():
        print("  fixture absente :", FIXTURE)
        return 1

    e = pipeline.executer("Analyse la sécurité de mon dépôt", FIXTURE)
    if not e.plan and _outils_absents():
        # NON ÉVALUÉ, pas échec : sans outil installé, l'étape « disponibilité » écarte
        # tous les providers, la mission s'arrête AVANT le plan et `e.clusters` est vide.
        # Lever un KeyError ici masquait la cause réelle et bloquait toute la suite.
        # Aucune attente n'est relâchée : dès qu'un outil est résolvable, cette garde ne
        # se déclenche plus et un vrai défaut réapparaît en échec.
        print(f"NON ÉVALUÉ : aucun plan produit (arrêt {e.arret!r}) et aucun scanner "
              f"résolvable sur cette machine — la corrélation exige de vrais findings. "
              f"Installer les outils (bootstrap.sh) puis rejouer.")
        return 2
    inter = e.clusters.get("clusters_inter_outils", [])
    tous = e.clusters["clusters"]
    ids = {f["id"]: f for f in e.findings}

    cas("des findings sont produits", len(e.findings) > 0,
        f"{len(e.findings)} findings")

    cas("au moins un cluster inter-outils existe", len(inter) >= 1,
        f"{len(inter)} cluster(s) inter-outils sur {len(tous)}")

    if inter:
        c = inter[0]
        membres = [m for m in c["members"] if m in ids]
        outils = sorted({ids[m]["source"]["tool"] for m in membres})
        cas("le cluster mêle réellement deux outils", len(outils) >= 2,
            f"outils={outils} · clé={c['cle']}")
        cas("la relation est justifiée explicitement",
            "cross_tool" in c["reason"] and "same_package" in c["reason"],
            f"reason={c['reason']}")
        cas("les findings sources sont conservés", len(membres) >= 2,
            f"{len(membres)} membres : {membres}")
        cas("le cluster n'est pas présenté comme une confirmation",
            "confirmed" not in json.dumps(c).lower(),
            "aucun champ de confirmation : le cluster reste une relation")
    else:
        for lib in ("cluster mêle deux outils", "relation justifiée",
                    "findings sources conservés", "pas de confirmation"):
            cas(lib, False, "aucun cluster inter-outils")

    total = e.clusters["stats"]["findings_en_entree"]
    comptes = sum(len(c["members"]) for c in tous) + len(e.clusters["non_regroupe"])
    cas("aucune perte de findings", comptes == total and total > 0,
        f"{total} en entrée, {comptes} répartis")

    print(f"\n{'=' * 52}")
    print(f"  {PAS}/{PAS + ECHECS} · {ECHECS} échec(s)")
    print(f"{'=' * 52}")

    # Ce que ce fichier NE mesure PAS — dit explicitement, pas laissé deviner.
    print("\nNON ÉVALUÉ ICI (volontairement) :")
    print("  · généralité du mécanisme sur d'autres cibles  → test_independant.py")
    print("  · familles Node.js/Go, dépendances sans lien,  → travail de durcissement")
    print("    versions multiples d'une même dépendance        ultérieur, hors Phase 3.1")
    print("\nUne fixture construite pour provoquer un lien démontre le mécanisme,")
    print("pas sa généralité. Ne pas lire ce résultat comme une preuve générale.")

    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
