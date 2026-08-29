#!/usr/bin/env python3
"""Une commande, un workflow complet, un rapport lisible.

    python3 PHASE3/analyser.py <dépôt> ["requête en langage naturel"] [--moteur auto|deterministe|llm]

Sortie : un bundle d'artefacts dans PHASE3/artifacts/<input_digest>/<plan_id>/<run_id>/
    rapport.md · rapport_humain.md · manifeste.json · plan.json · findings.json
    clusters.json · run.json · raw_*.json · rapport.sarif
et, étape 6, une archive de mission sous PHASE3/artifacts/missions/<mission>/sortie/
    RAPPORT.md · intent.json + copie des JSON du bundle

L'ordre des arguments est celui de Phase 4 : LA CIBLE D'ABORD, la requête ensuite.
Elle est optionnelle — sans elle, la requête par défaut est un audit complet.
Le faire autrement casserait tout appel déjà écrit (`test_rapport.py`, `test_bundle.py`).

Étape 6 (2026-08-29) : le matching d'intention peut être confié à un LLM. Il ne pilote
QUE le catalogue : sa sortie est validée contre le registre, un échec retombe sur le
déterministe et le repli est tracé dans `intent.moteur`. Aucune logique de sécurité
n'est ajoutée ici.

Codes de sortie :
    0  workflow exécuté
    1  erreur technique
    2  demande refusée ou nécessitant une clarification — AUCUNE exécution
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import assainissement as ASS  # noqa: E402
import mission as MS  # noqa: E402
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



def _choisir_moteur(moteur: str) -> tuple[str, object, str]:
    """Résout `auto` et instancie le fournisseur. Retourne (moteur, fournisseur, note).

    `auto` n'est jamais une surprise : sans canal configuré on reste déterministe et on
    le DIT (la note est affichée). Silencieux, l'utilisateur croirait à un LLM.
    """
    if moteur == "llm":
        import fournisseurs_llm
        return "llm", fournisseurs_llm.Groq(), ""
    if moteur == "auto":
        if os.environ.get("GROQ_API_KEY"):
            import fournisseurs_llm
            return "llm", fournisseurs_llm.Groq(), ""
        return "deterministe", None, (
            "aucun canal LLM configuré (GROQ_API_KEY absent) — moteur déterministe")
    return "deterministe", None, ""


def _archiver_mission(e, cible: Path) -> Path | None:
    """Copie les preuves de l'exécution SOUS le dossier de la mission (append-only).

    Le bundle `artifacts/<digest>/<plan>/<run>/` reste la référence technique. Cette
    archive répond à une autre question — « qu'a produit CETTE mission ? » — et évite
    qu'une mission suivante écrase les preuves de la précédente. Les objets
    d'exécution (plan, findings, clusters, rapport, run) sont réécrits depuis `e` :
    `pipeline.executer()` les retourne sans les écrire, c'est ce module qui le fait.
    """
    if not e.mission:
        return None
    sortie = MS.MISSIONS / e.mission / "sortie"
    sortie.mkdir(parents=True, exist_ok=True)
    src_run = RACINE / "run"
    if src_run.exists():
        for f in sorted(src_run.iterdir()):
            if f.is_file():
                shutil.copy(f, sortie / f.name)
    for nom, objet in (("plan", e.plan), ("findings", e.findings),
                       ("clusters", e.clusters), ("rapport", e.rapport),
                       ("intent", e.intent)):
        (sortie / f"{nom}.json").write_text(
            json.dumps(objet, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8")
    (sortie / "run.json").write_text(json.dumps({
        "run_id": e.run_id, "profil": e.profil,
        "plan_id": e.plan.get("plan_id"),
        "input_digest": e.contexte.get("input_digest"),
        "input_commit": e.contexte.get("input_commit", ""),
        "working_tree_dirty": e.contexte.get("working_tree_dirty", False),
        "execution_context_digest": e.contexte.get("contexte_empreinte"),
        "result_digest": e.result_digest,
        "contexte": e.contexte, "chemin": e.chemin,
    }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if not e.arret:
        (sortie / "RAPPORT.md").write_text(RH.generer(e, cible), encoding="utf-8")
    return sortie


def lancer(mission: str, cible: Path, moteur: str = "auto",
           fournisseur=None) -> tuple[int, dict]:
    """Exécute une mission de bout en bout. Retourne (code_sortie, résumé).

    API pour les tests : elle ne passe PAS par le bundle Phase 4 (pas d'écriture dans
    artifacts/<digest>/), seulement par l'archive de mission. Le bundle est testé par
    test_bundle.py via la CLI.
    """
    cible = Path(cible)
    if not cible.exists():
        return 1, {"statut": "erreur", "motif": f"cible introuvable : {cible}"}

    if moteur == "auto":
        moteur, fournisseur_auto, _ = _choisir_moteur(moteur)
        if fournisseur is None:
            fournisseur = fournisseur_auto

    ancien_moteur, ancien_four = pipeline.MOTEUR_INTENT, pipeline.FOURNISSEUR_LLM
    try:
        pipeline.MOTEUR_INTENT = moteur
        pipeline.FOURNISSEUR_LLM = fournisseur if moteur == "llm" else None
        e = pipeline.executer(mission, cible)
    finally:
        pipeline.MOTEUR_INTENT, pipeline.FOURNISSEUR_LLM = ancien_moteur, ancien_four

    sortie = _archiver_mission(e, cible)
    resume = {
        "statut": e.arret or "complet",
        "moteur": (e.intent or {}).get("moteur", ""),
        "mission": e.mission,
        "findings": len(e.findings),
        "clusters_inter_outils": len((e.clusters or {}).get("clusters_inter_outils") or []),
        "question": (e.intent or {}).get("question", ""),
        "motif": (e.intent or {}).get("motif", "") or "; ".join(
            (e.decision or {}).get("motifs") or []),
        "rapport": str(sortie / "RAPPORT.md") if (sortie and not e.arret) else None,
        "sortie": str(sortie) if sortie else None,
    }
    return (0 if not e.arret else 2), resume


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1

    args = [a for a in argv[1:] if not a.startswith("--moteur")]
    moteur = "auto"
    for a in argv[1:]:
        if a.startswith("--moteur"):
            moteur = a.split("=", 1)[1] if "=" in a else "llm"
    if moteur not in ("auto", "deterministe", "llm"):
        print(f"ERREUR : moteur inconnu {moteur!r} (auto | deterministe | llm)")
        return 1

    cible = Path(args[0]).resolve()
    requete = args[1] if len(args) > 1 else "Analyse la sécurité de mon dépôt"

    moteur, fournisseur, note = _choisir_moteur(moteur)
    pipeline.MOTEUR_INTENT = moteur
    pipeline.FOURNISSEUR_LLM = fournisseur

    if not cible.exists():
        print(f"ERREUR : cible introuvable : {cible}")
        return 1

    print(f"cible   : {cible}")
    print(f"requete : {requete}")
    print(f"moteur  : {moteur}" + (f" ({note})" if note else "") + "\n")
    # Note : le moteur EFFECTIF n'est connu qu'après exécution — un LLM injoignable
    # retombe sur le déterministe. Il est affiché plus bas, dans le résumé.

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

    # Étape 6 : mêmes preuves, vues depuis la mission plutôt que depuis le plan.
    sortie_mission = _archiver_mission(e, cible)

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
    reel = e.intent.get("moteur", "")
    if reel and not reel.startswith(moteur):
        print(f"moteur effectif  : {reel}  (le {moteur} demandé n'a pas abouti)")
    print(f"\npour un humain   : {dossier / 'rapport_humain.md'}")
    print(f"rapport complet  : {dossier / 'rapport.md'}")
    if sortie_mission:
        print(f"mission {e.mission} : {sortie_mission.relative_to(RACINE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

