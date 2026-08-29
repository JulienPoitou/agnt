#!/usr/bin/env python3
"""Phase 4 — une commande, un workflow complet, un rapport lisible.

    python3 PHASE3/analyser.py <dépôt> ["requête en langage naturel"]

Sortie : un bundle d'artefacts dans PHASE3/bundles/<plan_id>/
    rapport.md · manifeste.json · plan.json · findings.json · clusters.json
    run.json · raw_*.json · rapport.sarif

Aucune nouvelle capacité, aucun nouvel outil, aucun LLM. Le rapport est produit par du
code déterministe : à cible et contexte identiques, le texte est reproductible.

Codes de sortie :
    0  workflow exécuté
    1  erreur technique
    2  demande refusée ou nécessitant une clarification — AUCUNE exécution
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import assainissement as ASS  # noqa: E402
import rapport_humain as RH  # noqa: E402
import pipeline          # noqa: E402
import rapport as R      # noqa: E402
from sandbox import CACHE_BIN  # noqa: E402

# Index en trois niveaux :
#   artifacts/<input_digest>/<plan_id>/<run_id>/
# La cible d'abord, puis le plan canonique, puis l'exécution unique. Deux formulations
# d'une même intention tombent dans le MÊME plan_id — c'est le but de la canonicalisation.
ARTIFACTS = RACINE / "artifacts"


def sarif(findings: list[dict], run_id: str, plan_id: str) -> dict:
    """Export SARIF 2.1.0 des observations.

    SARIF porte des identifiants stables et des empreintes partielles, mais il ne relie
    pas deux outils entre eux : c'est le canonical_rule_id interne qui le fait. L'export
    est donc une vue d'échange, pas le modèle de référence.
    """
    regles = {}
    resultats = []
    for f in findings:
        canon = f["identity"]["canonical_rule_id"]
        if canon not in regles:
            regles[canon] = {
                "id": canon,
                "shortDescription": {"text": (f.get("evidence") or {}).get("message")
                                     or canon},
                "properties": {"outil": f["source"]["tool"]},
            }
        loc = f["location"]
        res = {
            "ruleId": canon,
            "level": "warning",
            "message": {"text": (f.get("evidence") or {}).get("message") or canon},
            "partialFingerprints": {"primary": f["identity"]["fingerprint"]},
            "properties": {
                "finding_id": f["id"],
                "outil_source": f["source"]["tool"],
                "regle_source": f["source"].get("original_rule_id"),
                "paquet": loc.get("package"),
            },
        }
        if loc.get("file"):
            region = {}
            if loc.get("line"):
                region["startLine"] = loc["line"]
            res["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": loc["file"]},
                **({"region": region} if region else {}),
            }}]
        resultats.append(res)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "plateforme-ia-cyber",
                "version": "3.1",
                "informationUri": "https://example.invalid/plateforme",
                "rules": list(regles.values()),
            }},
            "results": resultats,
            "properties": {"run_id": run_id, "plan_id": plan_id},
        }],
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1

    args = [a for a in argv[1:] if not a.startswith("--moteur")]
    moteur = "deterministe"
    for a in argv[1:]:
        if a.startswith("--moteur"):
            moteur = a.split("=", 1)[1] if "=" in a else "llm"
    if moteur not in ("deterministe", "llm"):
        print(f"ERREUR : moteur inconnu {moteur!r} (deterministe | llm)")
        return 1

    cible = Path(args[0]).resolve()
    requete = args[1] if len(args) > 1 else "Analyse la sécurité de mon dépôt"

    if moteur == "llm":
        import fournisseurs_llm
        pipeline.MOTEUR_INTENT = "llm"
        pipeline.FOURNISSEUR_LLM = fournisseurs_llm.MockLLM()

    if not cible.exists():
        print(f"ERREUR : cible introuvable : {cible}")
        return 1

    print(f"cible   : {cible}")
    print(f"requete : {requete}")
    print(f"moteur  : {moteur}\n")

    e = pipeline.executer(requete, cible)

    # ---------------------------------------------------- arrêt avant exécution
    if e.arret:
        print(f"STATUT : {e.arret}")
        if e.intent.get("question"):
            print(f"\nQUESTION : {e.intent['question']}")
        if e.intent.get("motif"):
            print(f"\nMOTIF : {e.intent['motif']}")
        print("\nAucune exécution, aucun plan, aucun outil lancé.")
        return 2

    # ---------------------------------------------------- bundle
    dossier = (ARTIFACTS / e.contexte["input_digest"] / e.plan["plan_id"] / e.run_id)
    dossier.mkdir(parents=True, exist_ok=True)

    # DEUX rapports, deux publics :
    #   rapport.md         l'ingénieur qui vérifie
    #   rapport_humain.md  la personne qui décide quoi corriger
    md = R.generer(e, cible)
    (dossier / "rapport.md").write_text(md, encoding="utf-8")
    (dossier / "rapport_humain.md").write_text(RH.generer(e, cible), encoding="utf-8")
    (dossier / "plan.json").write_text(
        json.dumps(e.plan, ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "findings.json").write_text(
        json.dumps(e.findings, ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "clusters.json").write_text(
        json.dumps(e.clusters, ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "run.json").write_text(
        json.dumps({"execution_profile": e.profil, "plan_id": e.plan["plan_id"],
                    "input_digest": e.contexte.get("input_digest"),
                    "input_commit": e.contexte.get("input_commit"),
                    "working_tree_dirty": e.contexte.get("working_tree_dirty"),
                    "execution_context_digest": e.contexte.get("contexte_empreinte"),
                    "run_id": e.run_id,
                    "result_digest": e.result_digest,
                    "contexte": e.contexte, "chemin": e.chemin},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "rapport.sarif").write_text(
        json.dumps(sarif(e.findings, e.run_id, e.plan["plan_id"]),
                   ensure_ascii=False, indent=2), encoding="utf-8")

    # ---------------------------------------------------------- politique de conservation
    # Conserver la donnée brute si elle est sûre ; sinon conserver son empreinte, ses
    # métadonnées et une version masquée. Un secret en clair dans nos artefacts serait
    # une fuite que NOUS créons — constaté pour de vrai avec Bandit.
    src_run = RACINE / "run"
    conservation = {}
    for f in sorted(src_run.glob("raw_*.json")):
        v = ASS.examiner_fichier(f)
        if v.sur:
            shutil.copy2(f, dossier / f.name)
        else:
            cible = dossier / f.name.replace(".json", ".redacted.json")
            cible.write_text(v.texte_masque, encoding="utf-8")
        conservation[f.name] = ({
            "raw_output": v.to_dict(),
            **({"sanitized_output": {
                "path": f.name.replace(".json", ".redacted.json"),
                "redactions": v.occurrences,
            }} if not v.sur else {}),
        })

    manifeste = {
        "genere_le": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "requete": requete,
        "requete_canonique": e.plan.get("requete_canonique"),
        "request_id": e.plan.get("request_id"),
        "cible": str(cible),
        "profil": e.profil,
        "moteur_intent": e.intent.get("moteur"),
        "identifiants": {
            "plan_id": e.plan["plan_id"],
            "input_digest": e.contexte.get("input_digest"),
            "input_commit": e.contexte.get("input_commit"),
            "execution_context_digest": e.contexte.get("contexte_empreinte"),
            "run_id": e.run_id,
            "result_digest": e.result_digest,
        },
        "intent": e.intent,
        "couverture": e.rapport.get("couverture"),
        "observations": len(e.findings),
        "clusters": len(e.rapport.get("clusters", [])),
        "clusters_inter_outils": len(e.clusters.get("clusters_inter_outils", [])),
        "non_regroupe": len(e.clusters.get("non_regroupe", [])),
        "conservation_des_sorties": conservation,
        "artefacts": sorted(p.name for p in dossier.iterdir()),
    }
    (dossier / "manifeste.json").write_text(
        json.dumps(manifeste, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---------------------------------------------------- résumé console
    print("=" * 62)
    print(f"  {len(e.findings)} observations · {len(e.rapport['clusters'])} clusters"
          f" · {len(e.clusters.get('clusters_inter_outils', []))} inter-outils")
    print(f"  plan {e.plan['plan_id']} · run {e.run_id} · result {e.result_digest}")
    print("=" * 62)
    print(f"\nartefacts : {dossier.relative_to(RACINE)}")
    for p in sorted(dossier.iterdir()):
        print(f"    {p.name:<20} {p.stat().st_size:>9,} o")
    print(f"\npour un humain   : {dossier / 'rapport_humain.md'}")
    print(f"rapport complet  : {dossier / 'rapport.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

