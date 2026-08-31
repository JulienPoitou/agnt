#!/usr/bin/env python3
"""Traçabilité — les cinq identifiants et la règle de comparaison.

    plan_id                   = hash du plan typé
    input_digest              = hash de la cible analysée
    execution_context_digest  = outils, règles, base, policy, registre, sandbox
    run_id                    = identité unique de l'exécution
    result_digest             = hash des findings canoniques TRIÉS

Critère exact :

    même plan + même cible + même contexte  → mêmes résultats canoniques
    même plan + autre cible                 → input_digest différent, PAS un rejeu comparable

Usage : python3 PHASE3/test_tracabilite.py
"""

from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import pipeline  # noqa: E402
import run as RUN  # noqa: E402

CIBLE_A = RACINE / "testrepo"
CIBLE_B = RACINE / "testrepo_xtool"

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


# Scanners dont cette suite a besoin pour qu'une mission aille jusqu'au plan puis au run.
_OUTILS = ("semgrep", "bandit", "trivy", "grype", "gitleaks", "detect-secrets", "checkov")


def _outils_absents(*noms) -> bool:
    """Aucun des binaires nommés n'est résolvable : c'est l'environnement, pas le code."""
    import shutil
    return all(shutil.which(n) is None for n in (noms or _OUTILS))


def main() -> int:
    print("=== TRAÇABILITÉ ===\n")

    a1 = pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE_A)
    a2 = pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE_A)
    b1 = pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE_B)

    if not a1.plan and _outils_absents():
        # NON ÉVALUÉ, pas échec : sans outil installé, la disponibilité écarte tous les
        # providers, la mission s'arrête AVANT le plan — il n'y a alors ni plan_id ni
        # run_id à tracer. Le KeyError que cela produisait masquait la cause réelle.
        # Aucune attente n'est relâchée : la garde ne se déclenche que si AUCUN scanner
        # n'est résolvable ; sinon un vrai défaut réapparaît en échec.
        print(f"NON ÉVALUÉ : aucun plan produit (arrêt {a1.arret!r}) et aucun scanner "
              f"résolvable sur cette machine — la traçabilité des cinq identifiants exige "
              f"une mission réelle. Installer les outils (bootstrap.sh) puis rejouer.")
        return 2

    # ------------------------------------------------ les cinq identifiants existent
    manque = [k for k in ("plan_id", "input_digest", "execution_context_digest",
                          "run_id", "result_digest")
              if k not in {"plan_id", "input_digest", "execution_context_digest",
                           "run_id", "result_digest"}]
    ctx = a1.contexte
    cinq = bool(a1.plan.get("plan_id")) and bool(ctx.get("input_digest")) \
        and bool(ctx.get("contexte_empreinte")) and bool(a1.run_id) and bool(a1.result_digest)
    cas("les cinq identifiants sont produits", cinq,
        f"plan={a1.plan.get('plan_id')} input={ctx.get('input_digest')} "
        f"ctx={ctx.get('contexte_empreinte')} run={a1.run_id} result={a1.result_digest}")

    # ------------------------------------------------ plan stable, run distinct
    cas("même plan_id sur deux exécutions", a1.plan["plan_id"] == a2.plan["plan_id"],
        f"{a1.plan['plan_id']} == {a2.plan['plan_id']}")
    cas("run_id distinct à chaque exécution", a1.run_id != a2.run_id,
        f"{a1.run_id} != {a2.run_id}")

    # ------------------------------------------------ input_digest sépare les cibles
    cas("input_digest diffère entre deux dépôts",
        a1.contexte["input_digest"] != b1.contexte["input_digest"],
        f"{a1.contexte['input_digest']} != {b1.contexte['input_digest']}")
    cas("input_digest stable pour un même dépôt",
        a1.contexte["input_digest"] == a2.contexte["input_digest"],
        f"{a1.contexte['input_digest']}")

    # ------------------------------------------------ le critère exact
    cas("même plan + même cible + même contexte → même result_digest",
        a1.result_digest == a2.result_digest and len(a1.findings) == len(a2.findings),
        f"{a1.result_digest} == {a2.result_digest} · {len(a1.findings)} findings")

    cas("autre cible → result_digest différent (pas un rejeu comparable)",
        a1.result_digest != b1.result_digest,
        f"{a1.result_digest} != {b1.result_digest}")

    # ------------------------------------------------ le tri rend la comparaison fiable
    # result_digest est calculé sur des tuples TRIÉS : permuter l'ordre des findings
    # ne doit pas changer l'empreinte.
    d1 = RUN.digest_resultats(a1.findings)
    d2 = RUN.digest_resultats(list(reversed(a1.findings)))
    cas("result_digest insensible à l'ordre brut des outils", d1 == d2,
        f"{d1} == {d2}")

    # ------------------------------------------------ .git exclu du digest
    # Le commit SHA est capturé à part ; le digest de l'arbre ne doit pas en dépendre.
    cas("le commit est capturé séparément du digest de l'arbre",
        "input_commit" in a1.contexte,
        f"input_commit={a1.contexte.get('input_commit') or '(dépôt sans .git)'}")

    # ------------------------------------------------ mapping de paquet déclaré
    f = a1.findings + b1.findings
    sans_carto = [x["id"] for x in f if "package_mapping" not in x["source"]]
    sans_orig = [x["id"] for x in f if not x["source"].get("original_rule_id")]
    methodes = sorted({x["source"]["package_mapping"]["method"] for x in f})
    cas("chaque finding déclare son original_rule_id", not sans_orig,
        f"{len(f)} findings, {len(sans_orig)} sans identifiant original")
    cas("chaque finding déclare méthode et confiance de mapping", not sans_carto,
        f"méthodes observées : {methodes}")

    inconnus = [x for x in f if x["source"]["package_mapping"]["method"] == "inconnu"]
    cas("un paquet inconnu est déclaré inconnu, pas deviné",
        all(x["source"]["package"] is None for x in inconnus),
        f"{len(inconnus)} findings à paquet inconnu, tous à package=null")

    print(f"\n{'=' * 50}\n  {PAS} OK · {ECHECS} échec(s)\n{'=' * 50}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
