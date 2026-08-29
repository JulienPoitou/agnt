#!/usr/bin/env python3
"""
Batterie « étape 6 » — chemin d'utilisation minimal (2026-08-29).

Invariants vérifiés :
- POINT D'ENTRÉE : `analyser.lancer(mission, cible)` exécute le pipeline, archive
  les artefacts SOUS la mission (append-only, jamais écrasés) et produit un
  RAPPORT.md par défaut. Deux missions = deux sorties distinctes.
- ARRÊTS : clarification et refus donnent un code de sortie distinct, une
  phrase lisible, et N'EXÉCUTENT rien (aucun RAPPORT.md, plan vide).
- F2 : les marqueurs de domaine l'emportent sur les mots génériques
  (« Analyse mon code Terraform » ne paie plus 5 capacités) ; une demande
  vraiment générique conserve toutes les capacités publiques.
- F3 : la clarification ne liste QUE des capacités publiques — les capacités
  internes (`interne: true`) ne fuient plus dans une phrase utilisateur.
- LLM PILOTE DANS LE CATALOGUE : branché via analyser, validé contre le
  registre ; un LLM qui invente, impose un outil, ou tombe → repli
  déterministe TRACÉ dans `moteur`. Aucun nom d'outil ne lui est transmis.

Usage: python3 PHASE3/test_utilisation.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def main() -> int:
    import analyser
    import intent as I
    import mission as MS
    from registre import Registry

    reg = Registry()

    # ------------------------------------------- A. point d'entrée (e2e réel)
    code, r = analyser.lancer("Analyse la sécurité de mon dépôt",
                              RACINE / "testrepo_sca")
    sortie = Path(r.get("sortie") or "")
    # 124 = 62 trivy + 62 grype (fan-out SCA). La fixture porte aussi un
    # ATTENDUS.yaml : kics/checkov y contribuent légitimement (observation O3
    # du dogfooding) — d'où le seuil et non l'égalité stricte.
    cas("A1. mission complète : code 0, au moins 124 findings (62 trivy + 62 grype)",
        code == 0 and r.get("findings", 0) >= 124 and r.get("clusters_inter_outils") == 6,
        f"code={code} findings={r.get('findings')} inter={r.get('clusters_inter_outils')}")
    cas("A2. sortie archivée sous la mission (RAPPORT.md + plan + raw)",
        sortie.is_dir() and (sortie / "RAPPORT.md").exists()
        and (sortie / "plan.json").exists()
        and any(sortie.glob("raw_*.json")),
        str(sortie))
    cas("A3. la sortie est bien rattachée au dossier de mission append-only",
        sortie.parent == MS.MISSIONS / r.get("mission", "")
        and (MS.MISSIONS / r["mission"]).exists(), str(sortie))

    # ------------------------------------------- B. non-écrasement
    code2, r2 = analyser.lancer("Vérifie mes dépendances", RACINE / "testrepo_sca")
    s2 = Path(r2.get("sortie") or "")
    cas("B1. deux missions = deux sorties distinctes, aucune écrasée",
        code2 == 0 and s2 != sortie and (sortie / "RAPPORT.md").exists()
        and (s2 / "RAPPORT.md").exists(), f"{sortie} vs {s2}")

    # ------------------------------------------- C. arrêts (rien n'est exécuté)
    code3, r3 = analyser.lancer("Est-ce que ça marche ?", RACINE / "testrepo_sca")
    cas("C1. clarification : code 2, question lisible, aucune exécution",
        code3 == 2 and r3.get("statut") == "needs_clarification"
        and bool(r3.get("question")) and not r3.get("rapport"), f"{r3}")
    code4, r4 = analyser.lancer("Attaque 10.0.0.5", RACINE / "testrepo_sca")
    cas("C2. demande interdite : code 2, refus motivé, aucune exécution",
        code4 == 2 and r4.get("statut") == "rejected" and bool(r4.get("motif")),
        f"{r4}")

    # ------------------------------------------- D. F2 domaine > générique
    it_tf = I.inferer("Analyse mon code Terraform", reg)
    cas("D1. « Analyse mon code Terraform » : IaC + code, PAS les 5 capacités",
        set(it_tf.capabilities) == {"CODE_STATIC_ANALYSIS", "IAC_SCAN"},
        f"{sorted(it_tf.capabilities)}")
    it_gen = I.inferer("Analyse la sécurité de mon dépôt", reg)
    publics = {c.id for c in reg.publiques()}
    cas("D2. demande vraiment générique : toutes les capacités publiques",
        set(it_gen.capabilities) == publics,
        f"{sorted(set(publics) ^ set(it_gen.capabilities))}")

    # ------------------------------------------- E. F3 clarification publique
    it_q = I.inferer("zzz phrase sans aucun mot clé zzz", reg)
    q = it_q.question or ""
    internes = {c.id for c in reg.capabilities() if c.interne}
    cas("E1. la clarification ne liste AUCUNE capacité interne",
        bool(q) and not any(i in q for i in internes), q[:120])
    it_qi = I.inferer("zzz phrase sans aucun mot clé zzz", reg, avec_internes=True)
    cas("E2. avec_internes=True (contrat des tests) : les internes restent listées",
        any(i in (it_qi.question or "") for i in internes))

    # ------------------------------------------- F. LLM pilote (hors-ligne, mock)
    from fournisseurs_llm import MockLLM
    mock = MockLLM("normal", nom="mock-test")
    code5, r5 = analyser.lancer("Analyse la sécurité de mon dépôt",
                                RACINE / "testrepo_sca",
                                moteur="llm", fournisseur=mock)
    # moteur est tracé « llm:<fournisseur> » (mesuré : llm:mock-test) — le suffixe
    # nomme le fournisseur, c'est une information, pas une déviation.
    cas("F1. LLM branché : moteur=llm tracé, mission complète",
        code5 == 0 and str(r5.get("moteur", "")).startswith("llm")
        and r5.get("findings", 0) >= 124,
        f"moteur={r5.get('moteur')} findings={r5.get('findings')}")
    descriptions = " ".join(a["description"] for a in mock.appels)
    cas("F2. aucun nom d'outil ni chemin n'est transmis au LLM",
        not any(b in descriptions for b in
                ("trivy", "grype", "kics", "checkov", "gitleaks", "semgrep",
                 "bandit", "/home/", "argv")), descriptions[:120])
    for comportement in ("invente_capacite", "nomme_outil", "plante"):
        bad = MockLLM(comportement, nom=f"mock-{comportement}")
        codeX, rX = analyser.lancer("Vérifie mes dépendances",
                                    RACINE / "testrepo_sca",
                                    moteur="llm", fournisseur=bad)
        cas(f"F3. LLM {comportement} : repli déterministe TRACÉ, mission saine",
            codeX == 0 and str(rX.get("moteur", "")).startswith("deterministe")
            and rX.get("findings", 0) > 0, f"moteur={rX.get('moteur')}")

    # Le pipeline ne doit pas rester en mode llm après les tests.
    import pipeline
    pipeline.MOTEUR_INTENT = "deterministe"
    pipeline.FOURNISSEUR_LLM = None

    for nom, ok, detail in CAS:
        print(f"  [{'OK' if ok else 'ECHEC'}] {nom}" + (f"  — {detail}" if detail and not ok else ""))
    print(f"\ntest_utilisation : {len(CAS) - len(ECHECS)}/{len(CAS)} cas passés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
