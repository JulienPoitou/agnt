#!/usr/bin/env python3
"""TEST INDÉPENDANT — généralisation de la corrélation inter-outils.

Cible : anotherik/Config-Portal à un COMMIT FIXE. Dépôt public volontairement vulnérable,
indépendant de nos fixtures.

Règles du test, toutes imposées :

    · clone/checkout d'un commit fixe     → reproductible
    · scan PASSIF, hors réseau            → aucun exploit, l'application n'est jamais lancée
    · le moteur ne reçoit QUE             → « analyse la sécurité de ce dépôt »
      JAMAIS « cherche un lien PyYAML »

L'oracle est EXTERNE : c'est ce script, pas le moteur, qui sait ce qui doit être trouvé.
Le moteur, lui, ne reçoit aucune indication.

Trois résultats possibles, tous acceptables :

    cluster inter-outils trouvé          → la corrélation généralise
    findings corrects, aucun cluster     → mécanisme sain, le cas ne se présente pas
    finding attendu absent               → BUG à diagnostiquer

Usage : python3 PHASE3/test_independant.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import pipeline  # noqa: E402

# ------------------------------------------------------------------ cible épinglée
REPO_URL = "https://github.com/anotherik/Config-Portal"
COMMIT = "0ae503e6b6b37f11ed1bed5e917e19cb631ed041"
CIBLE = RACINE / "cible_independante"

# ------------------------------------------------------------------ oracle EXTERNE
# Ce que le dépôt contient, vérifié à la main AVANT le test. Le moteur n'en sait rien.
ORACLE = {
    "paquet_vulnerable": "pyyaml",
    "cve_attendues": {"CVE-2019-20477", "CVE-2020-1747", "CVE-2020-14343"},
    "regle_attendue": "avoid-pyyaml-load",
    "fichier": "app.py",
}

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def preparer() -> bool:
    """Clone et verrouille le commit. Le réseau n'est utilisé QUE ici, jamais au scan."""
    if not (CIBLE / ".git").exists():
        print(f"  clone de {REPO_URL}")
        r = subprocess.run(["git", "clone", "-q", REPO_URL, str(CIBLE)],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            print(f"  clone impossible : {r.stderr.strip()[:200]}")
            return False
    r = subprocess.run(["git", "-C", str(CIBLE), "checkout", "-q", COMMIT],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        print(f"  checkout impossible : {r.stderr.strip()[:200]}")
        return False
    head = subprocess.run(["git", "-C", str(CIBLE), "rev-parse", "HEAD"],
                          capture_output=True, text=True, timeout=60).stdout.strip()
    return head == COMMIT


def main() -> int:
    print("=== TEST INDÉPENDANT — Config-Portal ===\n")

    if not preparer():
        print("\n  cible indisponible : test non exécuté")
        return 1
    cas("cible verrouillée au commit attendu", True, COMMIT)

    # ---------------------------------------------------- le moteur ne sait rien
    # La requête est générique. Aucune mention de PyYAML, de yaml.load, ni de CVE.
    REQUETE = "analyse la sécurité de ce dépôt"
    assert "yaml" not in REQUETE.lower() and "cve" not in REQUETE.lower()

    e = pipeline.executer(REQUETE, CIBLE)

    cas("le scan s'exécute sans indication ciblée", not e.arret and len(e.findings) > 0,
        f"{len(e.findings)} findings, profil {e.profil}, run {e.run_id}")

    # ---------------------------------------------------- oracle : dépendance
    paquets = {f["source"].get("package") for f in e.findings}
    cve_trouvees = {f["source"]["original_rule_id"] for f in e.findings
                    if f["source"]["tool"] == "trivy"}
    attendues = ORACLE["cve_attendues"]
    cas("PyYAML vulnérable détecté par Trivy", ORACLE["paquet_vulnerable"] in paquets,
        f"paquets vus : {sorted(p for p in paquets if p)}")
    cas("les CVE documentées sont retrouvées", attendues <= cve_trouvees,
        f"attendues {sorted(attendues)} · trouvées {sorted(attendues & cve_trouvees)}"
        + (f" · manquantes {sorted(attendues - cve_trouvees)}" if attendues - cve_trouvees else ""))

    # ---------------------------------------------------- oracle : code
    regles = {f["source"]["original_rule_id"] for f in e.findings
              if f["source"]["tool"] == "semgrep"}
    dangereux = any(ORACLE["regle_attendue"] in r for r in regles)
    cas("usage dangereux de yaml.load détecté par Semgrep", dangereux,
        f"règles Semgrep : {sorted(r.split('.')[-2] + '.' + r.split('.')[-1] for r in regles)[:5]}")

    # ---------------------------------------------------- oracle : corrélation
    inter = e.clusters.get("clusters_inter_outils", [])
    ids = {f["id"]: f for f in e.findings}
    cluster_pyyaml = None
    for c in inter:
        outils = {ids[m]["source"]["tool"] for m in c["members"] if m in ids}
        paquets_c = {ids[m]["source"].get("package") for m in c["members"] if m in ids}
        if len(outils) >= 2 and ORACLE["paquet_vulnerable"] in paquets_c:
            cluster_pyyaml = c
            break

    if cluster_pyyaml:
        cas("relation inter-outils créée sur PyYAML", True,
            f"{cluster_pyyaml['cluster_id']} · {len(cluster_pyyaml['members'])} membres · "
            f"reason={cluster_pyyaml['reason']}")
        membres_outils = sorted({ids[m]["source"]["tool"]
                                 for m in cluster_pyyaml["members"] if m in ids})
        # MODIFIÉ le 2026-08-29 (étape 5, dogfooding). L'égalité stricte datait
        # d'avant l'étape 4 : DEPENDENCY_ANALYSIS est passé en fan_out, grype est
        # donc un second observateur des CVE sur paquets. Sur cette cible le
        # cluster PyYAML mêle désormais grype + semgrep + trivy — c'est le
        # comportement voulu du fan-out, pas une régression. L'intention du
        # contrôle (les DEUX outils de l'oracle sont bien reliés) est conservée ;
        # un outil supplémentaire ne l'invalide pas.
        cas("le cluster mêle bien Trivy et Semgrep",
            {"semgrep", "trivy"} <= set(membres_outils), f"outils={membres_outils}")
    else:
        # Résultat acceptable : le mécanisme est sain, le lien ne se présente pas.
        cas("relation inter-outils créée sur PyYAML", False,
            f"{len(inter)} cluster(s) inter-outils, aucun sur PyYAML. "
            f"À distinguer d'un bug : les deux findings sources existent-ils ?")

    # ---------------------------------------------------- intégrité
    total = e.clusters["stats"]["findings_en_entree"]
    comptes = sum(len(c["members"]) for c in e.clusters["clusters"]) \
        + len(e.clusters["non_regroupe"])
    cas("aucune perte de findings", comptes == total and total > 0,
        f"{total} en entrée, {comptes} répartis")

    fuites = [f["id"] for f in e.findings
              if "ghp_" in repr(f) or "AKIA" in repr(f)]
    cas("aucun secret en clair", not fuites, f"{len(fuites)} fuite(s)")

    # ---------------------------------------------------- reproductibilité
    e2 = pipeline.executer(REQUETE, CIBLE)
    cas("rejeu déterministe sur la même cible",
        e2.plan["plan_id"] == e.plan["plan_id"]
        and e2.result_digest == e.result_digest
        and e2.contexte["input_digest"] == e.contexte["input_digest"],
        f"plan {e.plan['plan_id']} · input {e.contexte['input_digest']} · "
        f"result {e.result_digest} · run {e.run_id} ≠ {e2.run_id}")

    print(f"\n{'=' * 56}")
    print(f"  {PAS} OK · {ECHECS} échec(s)")
    print(f"{'=' * 56}")
    if cluster_pyyaml:
        print("\nGÉNÉRALISATION : démontrée sur une cible indépendante de nos fixtures.")
    elif not ECHECS:
        print("\nGÉNÉRALISATION : non démontrée, mais aucun bug — les findings sont")
        print("corrects et le lien ne se présente pas sur cette cible.")
    else:
        print("\nUn finding attendu est absent : c'est un BUG à diagnostiquer,")
        print("pas une absence de lien.")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
