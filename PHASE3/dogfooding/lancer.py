#!/usr/bin/env python3
"""
Étape 5 — dogfooding : faire UTILISER le système sur des cibles réelles
contrôlées et OBSERVER ce qui casse (2026-08-29).

Aucune architecture nouvelle ici : ce script exécute le pipeline existant,
mesure, et persiste les preuves. Les observations vont dans
OBSERVATIONS_dogfooding.md — une anomalie n'est pas une feature (consigne).

Usage: python3 PHASE3/dogfooding/lancer.py [nom_cible ...]
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

RACINE = Path(__file__).parent
PHASE3 = RACINE.parent
sys.path.insert(0, str(PHASE3 / "slice"))

import pipeline  # noqa: E402
import rapport_humain  # noqa: E402
import yaml  # noqa: E402

MISSION = "Analyse la sécurité de mon dépôt"


def _mem_dispo() -> int:
    return int(open("/proc/meminfo").read().split("MemAvailable:")[1].split()[0]) // 1024


def lancer(nom: str) -> dict:
    cible = RACINE / "cibles" / nom
    out = RACINE / "rapports" / nom
    out.mkdir(parents=True, exist_ok=True)

    mem_avant = _mem_dispo()
    t0 = time.monotonic()
    erreur = None
    e = None
    try:
        e = pipeline.executer(MISSION, cible)
    except BaseException as ex:  # observer, pas masquer
        erreur = f"{type(ex).__name__}: {ex}"
    duree = round(time.monotonic() - t0, 1)
    mem_apres = _mem_dispo()

    # Les raw vivent dans PHASE3/run, vidé à chaque exécution : on les sauve.
    for f in sorted((PHASE3 / "run").glob("raw_*.json")):
        shutil.copy(f, out / f.name)

    metriques = {"cible": nom, "commit": _commit(cible), "duree_s": duree,
                 "erreur": erreur, "mem_dispo_avant_mo": mem_avant,
                 "mem_dispo_apres_mo": mem_apres}
    if e is not None:
        metriques.update({
            "arret": e.arret,
            "providers": [s["provider"] for s in e.plan["steps"]],
            "codes_retour": {x["provider"]: x["code_retour"] for x in e.raw},
            "findings": len(e.findings),
            "findings_par_outil": _par_outil(e.findings),
            "clusters": (e.clusters or {}).get("stats", {}),
            "clusters_inter_outils": len((e.clusters or {}).get("clusters_inter_outils") or []),
            "applicabilite_ecartes": (e.plan.get("selection") or {}).get("applicabilite") or {},
            "couverture": _couverture(e),
        })
        (out / "plan.json").write_text(json.dumps(e.plan, ensure_ascii=False, indent=2,
                                                  default=str), encoding="utf-8")
        (out / "rapport.json").write_text(json.dumps(e.rapport, ensure_ascii=False, indent=2,
                                                     default=str), encoding="utf-8")
        (out / "clusters.json").write_text(json.dumps(e.clusters, ensure_ascii=False, indent=2,
                                                      default=str), encoding="utf-8")
        try:
            (out / "RAPPORT.md").write_text(rapport_humain.generer(e, cible), encoding="utf-8")
        except Exception as ex:
            metriques["rapport_humain_erreur"] = f"{type(ex).__name__}: {ex}"
    (out / "METRIQUES.yaml").write_text(
        yaml.safe_dump(metriques, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return metriques


def _commit(cible: Path) -> str:
    import subprocess
    try:
        return subprocess.run(["git", "-C", str(cible), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10).stdout.strip()[:12]
    except Exception:
        return "?"


def _par_outil(findings) -> dict:
    out: dict = {}
    for f in findings:
        t = (f.get("source") or {}).get("tool")
        out[t] = out.get(t, 0) + 1
    return out


def _couverture(e) -> dict:
    """Résumé honnête : ce qui a été analysé, ce qui ne l'a pas été, et pourquoi."""
    res = {}
    for c in e.couverture:
        res[c.get("provider")] = {
            "cibles": len(c.get("cibles") or []),
            "etats": sorted({t.get("etat") for t in (c.get("cibles") or [])}),
            "limites_connues": c.get("limites_connues") or [],
        }
    return res


def main() -> int:
    noms = sys.argv[1:] or ["mux", "terraform-aws-vpc", "requests", "mocha"]
    rc = 0
    for nom in noms:
        print(f"\n===== {nom} =====", flush=True)
        m = lancer(nom)
        print(yaml.safe_dump(m, allow_unicode=True, sort_keys=False), flush=True)
        if m.get("erreur"):
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
