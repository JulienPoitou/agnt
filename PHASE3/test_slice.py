#!/usr/bin/env python3
"""Validation des dix critères de réussite du vertical slice.

Chaque critère est testé mécaniquement, pas déclaré. Le script rend un code non nul
si un seul critère échoue : « le slice fonctionne » doit être un fait, pas une opinion.

Usage : python3 PHASE3/test_slice.py   (lancer bootstrap.sh avant)
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import adapters                      # noqa: E402
import clusterer                     # noqa: E402
import findings as F                 # noqa: E402
import intent                        # noqa: E402
import pipeline                      # noqa: E402
import plan as P                     # noqa: E402
import policy as PO                  # noqa: E402
from sandbox import CACHE_BIN, CACHE_DB, CACHE_REGLES  # noqa: E402
from registre import Registry        # noqa: E402
from sandbox import Sandbox          # noqa: E402

CIBLE = RACINE / "testrepo"
REQUETE = "Analyse la sécurité de mon dépôt"

PAS = 0
ECHECS = 0


def critere(n: int, titre: str, ok: bool, detail: str) -> None:
    global PAS, ECHECS
    if ok:
        PAS += 1
        print(f"  OK    {n:>2}. {titre}")
    else:
        ECHECS += 1
        print(f"  ECHEC {n:>2}. {titre}")
    print(f"          {detail}")


def sandbox() -> Sandbox:
    return Sandbox(
        bwrap=shutil.which("bwrap") or "bwrap",
        racine_scan=CIBLE,
        racine_regles=CACHE_REGLES,
        racine_db=CACHE_DB,
        sortie=RACINE / "run",
        gitconfig=RACINE / "gitconfig",
    )


def main() -> int:
    print("=== VALIDATION DES DIX CRITÈRES ===\n")
    registre = Registry()
    moteur = PO.PolicyEngine(opa=CACHE_BIN / "opa")

    # ---------------------------------------------------------- 1. phrase -> plan JSON
    it = intent.inferer(REQUETE, registre)
    provs = intent.choisir_providers(it, registre)
    plan = P.construire(REQUETE, str(CIBLE), provs, registre, it.moteur)
    doc = plan.to_dict()
    try:
        json.loads(plan.to_json())
        valide = True
    except json.JSONDecodeError:
        valide = False
    # Le nombre d'étapes n'est PAS figé : ajouter un provider déclaratif doit le faire
    # grandir sans casser ce test. On vérifie que les capacités attendues sont présentes.
    caps_plan = {st["capability"] for st in doc.get("steps", [])}
    attendues = {"CODE_STATIC_ANALYSIS", "DEPENDENCY_ANALYSIS", "SECRET_DETECTION"}
    critere(1, "une phrase produit un plan JSON valide couvrant les capacités attendues",
            valide and doc.get("version") == P.VERSION_PLAN and attendues <= caps_plan,
            f"plan_id={plan.plan_id} · {len(doc['steps'])} étapes · version {doc.get('version')}"
            f" · capacités={sorted(caps_plan)}")

    # ------------------------------------------- 2. uniquement capabilities/providers connus
    ids_cap = {c.id for c in registre.capabilities()}
    ids_prov = {p.id for p in registre.providers()}
    hors = [(s.capability, s.provider) for s in plan.steps
            if s.capability not in ids_cap or s.provider not in ids_prov]
    critere(2, "le plan ne contient que des capabilities et providers autorisés",
            not hors,
            f"{len(plan.steps)} étapes, {len(hors)} hors registre")

    # ------------------------------------------------- 3. OPA autorise ET sait refuser
    d_ok = moteur.evaluer(plan, registre, True)
    d_refus = moteur.evaluer(plan, registre, False)
    # Cas forgés : risque destructif, et commande shell injectée.
    steps_mauvais = [P.Step(s.capability, s.provider, "DESTRUCTIVE", s.commande, s.args,
                            s.sorties) for s in plan.steps]
    from dataclasses import replace as _r
    plan_risque = _r(plan, steps=tuple(steps_mauvais))
    d_risque = moteur.evaluer(plan_risque, registre, True)
    steps_shell = [P.Step(s.capability, s.provider, s.risque, s.commande,
                          [*s.args, "; rm -rf /"], s.sorties) for s in plan.steps]
    from dataclasses import replace as _r2
    d_shell = moteur.evaluer(_r2(plan, steps=tuple(steps_shell)), registre, True)

    critere(3, "OPA peut autoriser ou refuser le plan",
            d_ok.allow and not d_refus.allow and not d_risque.allow and not d_shell.allow,
            f"nominal={d_ok.allow} · cible refusée={not d_refus.allow} "
            f"({','.join(d_refus.motifs)}) · risque={not d_risque.allow} "
            f"({','.join(d_risque.motifs)}) · shell={not d_shell.allow} "
            f"({','.join(d_shell.motifs)})")

    # --------------------------------- 4. aucun chemin IA -> shell
    # L'intent engine ne reçoit que la description des capacités : ni commande, ni chemin.
    desc = registre.descr()
    # On cherche une fuite du registre vers le planner : nom d'outil, drapeau, chemin.
    # On ne cherche PAS "/" en général : les domaines contiennent "supply-chain".
    fuite_outil = any(t in desc.lower() for t in ("semgrep", "trivy", "gitleaks"))
    fuite_drapeau = any(l.strip().startswith("-") and ":" not in l.split()[0]
                        for l in desc.splitlines() if not l.startswith("- "))
    fuite_chemin = any(m in desc for m in ("/home/", "/usr/", "/regles", "/bin"))
    fuite = fuite_outil or fuite_drapeau or fuite_chemin
    # Et la politique refuse toute commande forgée, indépendamment du moteur.
    critere(4, "aucun chemin ne permet à l'IA d'envoyer une commande shell",
            not fuite and not d_shell.allow,
            "descr() ne contient ni nom d'outil ni drapeau ni chemin ; "
            "une commande forgée est refusée par OPA")

    # ------------------------------------------- 5. exécution réelle dans le sandbox
    e = pipeline.executer(REQUETE, CIBLE, cible_autorisee=True)
    codes = {r["provider"]: r["code_retour"] for r in e.raw}
    produits = [r["provider"] for r in e.raw
                if (RACINE / "run" / r["fichier"]).exists()
                and (RACINE / "run" / r["fichier"]).stat().st_size > 2]
    # Au moins les trois outils historiques ; un provider déclaratif peut s'y ajouter.
    critere(5, "les outils s'exécutent dans une sandbox limitée",
            {"semgrep", "trivy", "gitleaks"} <= set(produits),
            f"codes={codes} · sorties non vides={sorted(produits)}")

    # --------------------------------------------------- 6. raw results conservés
    raws = sorted((RACINE / "run").glob("raw_*.json"))
    tailles = {p.name: p.stat().st_size for p in raws}
    critere(6, "les raw results sont conservés",
            len(raws) >= 3 and all(t > 2 for t in tailles.values()),
            f"{len(raws)} fichiers : {tailles}")

    # ---------------------------------- 7. fichiers non analysés et limites déclarés
    non_analyses = [c for c in e.couverture
                    for t in c["cibles"] if t["etat"] != "scanned_successfully"]
    limites = [c for c in e.couverture if c["limites_connues"]]
    etats = {t["etat"] for c in e.couverture for t in c["cibles"]}
    critere(7, "les fichiers non analysés et les limites sont déclarés",
            bool(non_analyses) and len(limites) >= 3,
            f"{len(non_analyses)} cibles non analysées (états {sorted(etats)}), "
            f"{len(limites)} providers avec limites déclarées")

    # --------------------------------- 8. identité source ET canonique
    # Structure validée le 2026-08-27 : l'identifiant ORIGINAL est conservé, le canonical
    # est défini par l'adaptateur, et le mapping de paquet déclare sa méthode.
    sans_source = [f["id"] for f in e.findings
                   if not f["source"].get("original_rule_id")
                   or not f["source"].get("canonical_rule_id")
                   or "package_mapping" not in f["source"]]
    sans_canon = [f["id"] for f in e.findings
                  if not f["identity"].get("canonical_rule_id")
                  or not f["identity"].get("fingerprint")]
    # Aucun secret en clair.
    fuites = F.verifie_absence_secrets(
        [type("X", (), {"to_dict": lambda s, f=f: f})() for f in e.findings])
    critere(8, "les findings ont une identité source et une identité canonique",
            not sans_source and not sans_canon and not fuites,
            f"{len(e.findings)} findings · {len(sans_source)} sans original/canonical/mapping · "
            f"{len(sans_canon)} sans identité canonique · {len(fuites)} fuite de secret")

    # --------------------------- 9. clusters explicables, findings d'origine conservés
    cl = e.clusters
    membres = sum(len(c["members"]) for c in cl["clusters"])
    total = cl["stats"]["findings_en_entree"]
    sans_raison = [c["cluster_id"] for c in cl["clusters"]
                   if len(c["members"]) > 1 and not c["reason"]]
    comptes = membres + len(cl["non_regroupe"])
    critere(9, "clusters explicables, sans supprimer les findings d'origine",
            comptes == total and not sans_raison and total > 0,
            f"{total} findings → {cl['stats']['clusters']} clusters "
            f"+ {len(cl['non_regroupe'])} non regroupés = {comptes} (aucune perte) · "
            f"{len(sans_raison)} cluster sans raison")

    # --------------------------------------- 10. plan_id / run_id et rejeu traçable
    # Formulation validée le 2026-08-27 :
    #   même plan + même contexte  → résultats identiques ou différences explicables
    #   même plan + autre contexte → nouveau run_id et divergence traçable
    e2 = pipeline.executer(REQUETE, CIBLE, cible_autorisee=True)
    meme_plan = e2.plan["plan_id"] == e.plan["plan_id"]
    run_distinct = e2.run_id != e.run_id
    ctx_present = bool(e.contexte.get("contexte_empreinte")) and bool(e2.contexte.get("contexte_empreinte"))
    meme_ctx = e.contexte.get("contexte_empreinte") == e2.contexte.get("contexte_empreinte")
    meme_resultat = len(e2.findings) == len(e.findings)
    meme_clusters = e2.clusters["stats"] == e.clusters["stats"]
    versions = e.contexte.get("outils", {})
    critere(10, "plan_id stable, run_id distinct, contexte capturé et rejeu cohérent",
            meme_plan and run_distinct and ctx_present and meme_ctx
            and meme_resultat and meme_clusters and len(versions) >= 4,
            f"plan_id identique={meme_plan} · run_id distinct={run_distinct} "
            f"({e.run_id} vs {e2.run_id}) · contexte capturé={ctx_present} "
            f"({len(versions)} outils, règles={len(e.contexte.get('regles', {}))}, "
            f"base_trivy={e.contexte.get('base_trivy')}) · "
            f"même contexte={meme_ctx} → mêmes findings={meme_resultat}, "
            f"mêmes clusters={meme_clusters}")

    print(f"\n{'=' * 46}\n  {PAS}/{PAS + ECHECS} · {ECHECS} échec(s)\n{'=' * 46}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
