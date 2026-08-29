#!/usr/bin/env python3
"""
Batterie « rapport humain » — honnêteté des gravités.

Contrainte actée le 2026-08-28 : UNKNOWN ≠ LOW ≠ MEDIUM. Un outil qui ne fournit
aucune gravité (checkov OSS : severity null) ne doit JAMAIS voir ses observations
classées « secondaires » ou « faibles » par le rapport. Le rapport doit :

    · dire combien d'observations sont sans gravité, et pourquoi ;
    · expliquer qu'indéterminée ≠ faible ;
    · donner la conduite à tenir (impact, exposition, contexte) ;
    · ne fabriquer AUCUNE gravité.

Aucun outil n'est exécuté : generer() est appelé sur des findings synthétiques
construits sur le schéma réel de findings.json.

Usage: python3 PHASE3/test_rapport_humain.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import rapport_humain as RH  # noqa: E402

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def finding(fid, outil, sev, fichier, ligne, regle, msg="message de test"):
    f = {
        "id": fid,
        "source": {"tool": outil, "original_rule_id": regle,
                   "canonical_rule_id": f"{outil}:{regle}"},
        "location": {"asset": "repository", "file": fichier, "line": ligne,
                     "package": None},
        "evidence": {"message": msg, "cwe": None, "reference": None},
        "statut": "open",
    }
    if sev is not None:                       # None = clé absente (cas défensif)
        f["severity"] = {"value": sev, "origine": outil}
    return f


def cluster(cid, members, raison=("same_file", "ligne_proche")):
    return {"cluster_id": cid, "confidence": "medium", "reason": list(raison),
            "members": members, "cle": f"test:{cid}"}


def bundle(findings, clusters, non_regroupe=()):
    return SimpleNamespace(
        findings=findings,
        rapport={"clusters": clusters, "clusters_inter_outils": [],
                 "non_regroupe": list(non_regroupe), "plan_id": "plan-test",
                 "couverture": {"checkov": {"analysé": ["/main.tf"],
                                            "non_analysé": [], "limites": []}}},
        contexte={"input_commit": "c" * 40, "input_digest": "d" * 16,
                  "contexte_empreinte": "e" * 16},
        run_id="run-test", result_digest="res-test", profil="standard",
    )


def main() -> int:
    # ---- 1. Tout UNKNOWN (le cas checkov réel : 38 findings, aucune gravité)
    f_unk = [finding(f"ch-{i:04d}", "checkov", "UNKNOWN", "/k8s.yaml", i, "CKV_K8S_8")
             for i in range(3)]
    f_unk.append(finding("ch-9999", "checkov", None, "/main.tf", 1, "CKV_AWS_3"))
    rap = RH.generer(bundle(f_unk, [cluster("CL-001", [f["id"] for f in f_unk])]), "depot")

    cas("1a. section dédiée présente", "## Gravité « indéterminée »" in rap)
    cas("1b. le compte est dit (4, y compris la clé absente)", "4 observations" in rap,
        "extrait: " + rap[rap.find("Gravité « indéterminée »"):][:200])
    cas("1c. indéterminée ≠ faible est écrit", "≠ faible" in rap)
    cas("1d. conduite à tenir présente", "exposition" in rap and "contexte" in rap)
    cas("1e. AUCUNE gravité fabriquée",
        not any(s in rap for s in ("gravité faible", "gravité moyenne",
                                   "gravité haute", "gravité critique")))
    cas("1f. pas de « Aucun problème grave » mensonger", "Aucun problème grave" not in rap)
    cas("1g. l'outil responsable est nommé", "`checkov`" in rap)
    cas("1h. observations ≠ regroupements dans la phrase",
        "Aucune des 4 observations regroupées" in rap and "1 regroupement" in rap)

    # ---- 2. Gravités connues uniquement : la section ne doit PAS apparaître
    f_ok = [finding("tr-1", "trivy", "HIGH", "/lock", 1, "CVE-2024-0001"),
            finding("tr-2", "trivy", "LOW", "/lock", 2, "CVE-2024-0002")]
    rap2 = RH.generer(bundle(f_ok, [cluster("CL-001", ["tr-1", "tr-2"])]), "depot")
    cas("2a. section absente quand tout est évalué",
        "## Gravité « indéterminée »" not in rap2)
    cas("2b. tri et vocabulaire habituels intacts",
        "à traiter en priorité" in rap2 and "gravité haute" in rap2)

    # ---- 3. Mixte : la section compte SEULEMENT les non évaluées
    f_mix = f_ok + [finding("ch-1", "checkov", "UNKNOWN", "/k8s.yaml", 5, "CKV_K8S_8")]
    rap3 = RH.generer(bundle(f_mix, [cluster("CL-001", ["tr-1", "tr-2"]),
                                     cluster("CL-002", ["ch-1"])]), "depot")
    cas("3a. section présente en mixte", "## Gravité « indéterminée »" in rap3)
    cas("3b. compte exact (1 sur 3)", "1 observation de cette analyse" in rap3)
    cas("3c. les gravités connues restent dites", "gravité haute" in rap3)

    # ---- 4. Observation isolée sans gravité : visible ET expliquée
    rap4 = RH.generer(bundle([finding("ch-1", "checkov", "UNKNOWN", "/main.tf", 7,
                                      "CKV_AWS_3")], [], non_regroupe=["ch-1"]), "depot")
    cas("4a. l'isolée apparaît avec son étiquette honnête",
        "gravité indéterminée" in rap4 and "CKV_AWS_3" in rap4)
    cas("4b. section dédiée présente aussi", "## Gravité « indéterminée »" in rap4)

    # ---- 5. Zéro finding : comportement historique inchangé
    rap5 = RH.generer(bundle([], []), "depot")
    cas("5a. « Aucun problème signalé » toujours là", "## Aucun problème signalé" in rap5)
    cas("5b. pas de section gravité sans finding", "## Gravité « indéterminée »" not in rap5)

    # ---- 6. Vocabulaire : la table explique indéterminée dans TOUS les rapports
    cas("6. table de lecture complétée",
        "gravité indéterminée" in rap2 and "ni faible ni moyen" in rap2)

    for nom, cond, detail in CAS:
        print(("OK   " if cond else "ECHEC") + f" {nom}" + (f" — {detail}" if detail and not cond else ""))
    print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas vérifiés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
