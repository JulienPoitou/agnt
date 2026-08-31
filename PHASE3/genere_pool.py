#!/usr/bin/env python3
"""
Génère pool.yaml — la VUE DÉRIVÉE du pool de providers (étape 2, 2026-08-29).

RÈGLE FONDAMENTALE (architecture gelée, invariant 20) :
    Ce fichier est une VUE. Il n'est JAMAIS une source de vérité du runtime —
    le registre (capabilities.yaml), la whitelist (provider_manifest) et OPA
    sont les seules autorités. Personne ne doit l'éditer à la main : le
    régénérer est la seule manière de le mettre à jour, et test_outils_pool_
    mission.py vérifie que le runtime l'ignore (falsification sans effet).

Entrées (toutes traçables par empreinte dans l'en-tête) :
    · PHASE1/07_CATALOGUE_INTEGRATION.csv — 324 lignes, verdicts Phase 1
    · PHASE1/08_FICHES_PROVIDERS.csv      — fiches qualifiées (69)
    · slice/capabilities.yaml             — providers réellement intégrés
    · slice/outils.py                     — registre des tools épinglés

Statuts (cycle de vie gelé, deux axes indépendants) :
    statut_technique   : discovered | prequalified | qualified | verified
    statut_operationnel: non_approuve | approved | integrated | suspended | retired
    Les tools intégrés aujourd'hui sont « verified / integrated » (harnais
    équivalent : artefacts capturés + ATTENDUS + batteries). Tout le reste du
    catalogue est « discovered / non_approuve » : rien n'a été exécuté, rien
    n'est autorisé — la fiche Phase 1 est une hypothèse, pas une mesure.

Usage: python3 PHASE3/genere_pool.py
"""
from __future__ import annotations

import csv
import hashlib
import sys
from datetime import date
from pathlib import Path

import yaml

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import outils  # noqa: E402
from registre import Registry  # noqa: E402

CATALOGUE = RACINE.parent / "PHASE1" / "07_CATALOGUE_INTEGRATION.csv"
FICHES = RACINE.parent / "PHASE1" / "08_FICHES_PROVIDERS.csv"
SORTIE = RACINE / "pool.yaml"

# Rattachement tool → dépôt source (vérifié : les 6 figurent au catalogue Phase 1).
REPO_DU_TOOL = {
    "trivy": "aquasecurity/trivy",
    "semgrep": "semgrep/semgrep",
    "gitleaks": "gitleaks/gitleaks",
    "bandit": "PyCQA/bandit",
    "checkov": "bridgecrewio/checkov",
    "opa": "open-policy-agent/opa",
    # Étape 4 (2026-08-29) : les 2 figurent au catalogue Phase 1 (vérifié).
    "grype": "anchore/grype",
    "kics": "Checkmarx/kics",
}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def main() -> int:
    lignes = list(csv.DictReader(open(CATALOGUE, encoding="utf-8")))
    fiches = {r["owner_repo"]: r
              for r in csv.DictReader(open(FICHES, encoding="utf-8"))}
    regs = outils.registre()
    r = Registry()

    # tool → providers intégrés (manifest : tool_id ; legacy : convention id = tool)
    provs_par_tool: dict[str, list[str]] = {}
    for p in r.providers():
        tid = p.manifest.tool_id if p.manifest is not None else p.id
        provs_par_tool.setdefault(tid, []).append(p.id)

    exclues = 0
    # 31/08/2026 — `REPO_DU_TOOL` était une SECONDE source de vérité : un outil
    # n'apparaissait « integrated » que si quelqu'un l'avait ajouté À LA MAIN dans cette
    # carte. Les sept providers déclarés par plugin (radon, ruff, eslint, npm, pip-audit,
    # detect-secrets, trufflehog3) étaient donc intégrés au registre — donc exécutables,
    # donc dans les plans — et ABSENTS de cette vue. Deux vérités concurrentes sur le même
    # fait, exactement ce que l'invariant 20 interdit.
    #
    # La source unique est le REGISTRE : est intégré tout tool auquel un provider est
    # rattaché. `REPO_DU_TOOL` ne sert plus qu'à l'attribution amont, et elle est
    # FACULTATIVE — un tool sans dépôt Phase 1 est déclaré quand même, avec sa provenance
    # dite, plutôt que passé sous silence.
    _tool_ids = sorted(provs_par_tool)
    entrees = []
    for l in sorted(lignes, key=lambda x: x["owner_repo"]):
        repo = (l["owner_repo"] or "").strip()
        if not repo:
            exclues += 1          # défaut de données Phase 1, documenté au journal
            continue
        tool_id = next((t for t, rp in REPO_DU_TOOL.items() if rp == repo), None)
        fiche = fiches.get(repo)
        entree = {
            "source": repo,
            "provenance": "phase1",
            "verdict_phase1": l["verdict_phase1"],
            "forme": l["forme_execution"] or None,
            "capacites": [c.strip() for c in (l["capacites"] or "").split("|") if c.strip()],
            "statut_technique": "verified" if tool_id else "discovered",
            "statut_operationnel": "integrated" if tool_id else "non_approuve",
            "providers": sorted(provs_par_tool.get(tool_id, [])) if tool_id else [],
            "tool": None,
        }
        if tool_id:
            t = regs[tool_id]
            entree["tool"] = {"id": t.id, "version": t.version,
                              "sha256": t.sha256 or None,
                              "distribution_hash": t.distribution_hash or None,
                              "licence": t.licence, "role": t.role}
        if fiche:
            entree["fiche"] = {"maturite": fiche["maturite"] or None,
                               "licence": fiche["licence"] or None,
                               "interet": fiche["interet_fonctionnel"] or None}
        entrees.append(entree)

    # Les outils intégrés QUE LE CATALOGUE PHASE 1 NE CONNAÎT PAS encore sont ajoutés
    # ici, d'après le registre — jamais d'après une liste recopiée.
    deja = {e["source"] for e in entrees if e["statut_operationnel"] == "integrated"}
    for tid in _tool_ids:
        if tid not in regs or tid in {t for t, rp in REPO_DU_TOOL.items()
                                      if rp in deja}:
            continue
        repo = REPO_DU_TOOL.get(tid)
        if repo is not None and repo in deja:
            continue
        t = regs[tid]
        entrees.append({
            "source": repo or f"hors-catalogue/{tid}",
            "provenance": "phase1" if repo else "registre",
            "verdict_phase1": None,
            "forme": "cli",
            "capacites": sorted({p.capability for p in r.providers()
                                 if p.id in provs_par_tool[tid] and p.capability}),
            "statut_technique": "verified",
            "statut_operationnel": "integrated",
            "providers": sorted(provs_par_tool[tid]),
            "tool": {"id": t.id, "version": t.version, "sha256": t.sha256 or None,
                     "distribution_hash": t.distribution_hash or None,
                     "licence": t.licence, "role": t.role},
        })
        deja.add(repo or f"hors-catalogue/{tid}")

    comptes: dict[str, int] = {}
    for e in entrees:
        comptes[e["statut_operationnel"]] = comptes.get(e["statut_operationnel"], 0) + 1

    doc = {
        "genere_le": str(date.today()),
        "lignes_catalogue": len(lignes),
        "lignes_exclues_sans_owner_repo": exclues,
        "comptes_statuts": comptes,
        "sources_lues": {
            str(p.relative_to(RACINE.parent)): _sha(p)
            for p in (CATALOGUE, FICHES, RACINE / "slice" / "capabilities.yaml")
        },
        "entrees": entrees,
    }
    entete = (
        "# ============================================================================\n"
        "# POOL — VUE DÉRIVÉE. NE JAMAIS ÉDITER CE FICHIER À LA MAIN.\n"
        "# Régénération : python3 PHASE3/genere_pool.py\n"
        "#\n"
        "# Le runtime NE LIT PAS ce fichier (vérifié par test_outils_pool_mission.py) :\n"
        "# registre (capabilities.yaml) + whitelist + OPA sont les seules autorités.\n"
        "# Un statut « integrated » ici est une CONSÉQUENCE de l'intégration réelle,\n"
        "# jamais une déclaration : il suit le registre, il ne le précède pas.\n"
        "# ============================================================================\n"
    )
    SORTIE.write_text(
        entete + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=100),
        encoding="utf-8")
    print(f"{SORTIE.name} : {len(entrees)} entrées ({comptes}) ; exclues sans owner_repo : {exclues}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
