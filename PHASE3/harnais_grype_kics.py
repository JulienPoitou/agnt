#!/usr/bin/env python3
"""
Qualification des deux premiers providers du pool — étape 4 (2026-08-29).

    grype 0.118.0 → DEPENDENCY_ANALYSIS (2e provider réel, fan-out trivy×grype)
    kics  2.1.20  → IAC_SCAN           (2e provider réel, fan-out checkov×kics)

Le harnais produit des PREUVES, pas un verdict : artefacts bruts (exécution
sandbox réelle), méta, stabilité de sortie, ATTENDUS régénérables, dossier de
qualification. L'approbation (statut pool, whitelist, manifeste) reste humaine.

Usage: python3 PHASE3/harnais_grype_kics.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE / "slice"))

import extraction as EX  # noqa: E402
import harnais as H  # noqa: E402
import yaml  # noqa: E402
from sandbox import Sandbox  # noqa: E402

GRYPE_ARGV = ["{BIN}", "dir:{TARGET}", "-o", "json"]
GRYPE_ENV = {"GRYPE_DB_CACHE_DIR": f"{Sandbox.M_DB}/grype"}
KICS_ARGV = ["{BIN}", "scan", "-p", "{TARGET}", "--report-formats", "json",
             "--output-path", "{OUT_DIR}", "--output-name", "kics",
             "-q", "{REGLES}/kics/queries", "--no-progress"]
TRIVY_ARGV = ["{BIN}", "fs", "--scanners=vuln", "--skip-db-update",
              "--skip-java-db-update", "--disable-telemetry", "--format=json",
              "--no-progress", "--cache-dir", "{DB}/trivy", "{TARGET}"]

SPECS = {
    "grype": {
        "modele": "plat",
        "items_from": "matches",
        "champs": {"regle": "vulnerability.id", "paquet": "artifact.name",
                   "severite": "vulnerability.severity",
                   "message": "vulnerability.description"},
        "masquer_large": ["message"],
    },
    "kics": {
        "modele": "imbriqué",
        "nested_from": "queries",
        "nested_key": "files",
        "contexte": {"regle_q": "query_name", "severite_q": "severity",
                     "message_q": "description"},
        "champs": {"regle": "regle_q", "fichier": "file_name", "ligne": "line",
                   "severite": "severite_q", "message": "message_q"},
        "masquer_large": ["message"],
    },
    "trivy_sca": {
        "modele": "imbriqué",
        "nested_from": "Results",
        "nested_key": "Vulnerabilities",
        "contexte": {"cible_r": "Target"},
        "champs": {"regle": "VulnerabilityID", "paquet": "PkgName",
                   "fichier": "cible_r", "severite": "Severity"},
    },
}


def _extraction(nom: str) -> EX.Extraction:
    s = SPECS[nom]
    return EX.Extraction(
        modele=s["modele"],
        items_from=s.get("items_from", "results"),
        nested_from=s.get("nested_from", ""),
        nested_key=s.get("nested_key", ""),
        contexte=dict(s.get("contexte") or {}),
        champs=dict(s["champs"]),
        masquer_large=list(s.get("masquer_large") or []),
    )


def _attendus(nom: str, donnees) -> dict:
    ex = _extraction(nom)
    items = EX.extraire(donnees, ex)
    champs = [EX.champs(i, ex) for i in items]
    par_cle: dict[str, set] = {}
    for c in champs:
        cle = str(c.get("paquet") or c.get("fichier") or "?")
        par_cle.setdefault(cle, set()).add(str(c.get("regle")))
    return {"compte": len(items),
            "par_cle": {k: sorted(v) for k, v in sorted(par_cle.items())}}


def main() -> int:
    dossiers = {}

    # ---- grype sur testrepo_sca (+ trivy de référence sur la MÊME fixture)
    cap_sca = RACINE / "testrepo_sca" / "artefacts_captures"
    m = H.capturer("grype", "grype", GRYPE_ARGV, RACINE / "testrepo_sca",
                   cap_sca, env=GRYPE_ENV)
    stab = H.stabilite("grype", "grype", GRYPE_ARGV, RACINE / "testrepo_sca",
                       cap_sca, env=GRYPE_ENV,
                       normaliser=lambda d: _attendus("grype", d))
    mt = H.capturer("trivy_sca", "trivy", TRIVY_ARGV, RACINE / "testrepo_sca", cap_sca)
    dossiers["grype"] = {"meta": {k: v for k, v in m.items() if k != "_donnees"},
                         "stabilite": stab,
                         "attendus": _attendus("grype", m["_donnees"])}
    dossiers["trivy_sca_reference"] = {
        "meta": {k: v for k, v in mt.items() if k != "_donnees"},
        "attendus": _attendus("trivy_sca", mt["_donnees"])}

    # ---- kics sur testrepo_iac
    cap_iac = RACINE / "testrepo_iac" / "artefacts_captures"
    k = H.capturer("kics", "kics", KICS_ARGV, RACINE / "testrepo_iac", cap_iac)
    stab_k = H.stabilite("kics", "kics", KICS_ARGV, RACINE / "testrepo_iac", cap_iac,
                         normaliser=lambda d: _attendus("kics", d))
    dossiers["kics"] = {"meta": {kk: v for kk, v in k.items() if kk != "_donnees"},
                        "stabilite": stab_k,
                        "attendus": _attendus("kics", k["_donnees"])}

    # Fait mesuré : grype identifie en GHSA-*, trivy en CVE-* (pas d'alias dans sa
    # sortie). La convergence se mesure donc sur les PAQUETS (clé du clusterer),
    # pas sur les identifiants de règle.
    paquets_g, paquets_t = set(dossiers["grype"]["attendus"]["par_cle"]), \
        set(dossiers["trivy_sca_reference"]["attendus"]["par_cle"])
    dossiers["grype"]["note_convergence"] = (
        "grype=GHSA-* / trivy=CVE-* : convergence inter-outils par PAQUET "
        f"({len(paquets_g & paquets_t)} paquets communs), pas par identifiant.")

    # ---- ATTENDUS + dossiers
    H.generer_attendus(RACINE / "testrepo_sca" / "ATTENDUS.yaml", {
        "genere_le": "2026-08-29",
        "genere_par": "harnais_grype_kics.py (grype 0.118.0 · trivy 0.74.0)",
        "methode": "EXTRAIT d'exécutions sandbox réelles. Régénérer, ne pas éditer.",
        "attendus": {"grype": dossiers["grype"]["attendus"],
                     "trivy": dossiers["trivy_sca_reference"]["attendus"]},
    })
    # kics : fusionné dans l'ATTENDUS existant de testrepo_iac (clé dédiée)
    att_iac_path = RACINE / "testrepo_iac" / "ATTENDUS.yaml"
    att_iac = yaml.safe_load(att_iac_path.read_text(encoding="utf-8"))
    att_iac.setdefault("attendus_kics", {})
    att_iac["attendus_kics"] = {
        "genere_le": "2026-08-29",
        "genere_par": "harnais_grype_kics.py (kics 2.1.20)",
        **dossiers["kics"]["attendus"],
    }
    H.generer_attendus(att_iac_path, att_iac)

    H.dossier(RACINE / "testrepo_sca" / "artefacts_captures" / "DOSSIER_grype.yaml",
              {"outil": "grype", **dossiers["grype"],
               "note": "PREUVES de qualification — l'approbation est humaine."})
    H.dossier(RACINE / "testrepo_iac" / "artefacts_captures" / "DOSSIER_kics.yaml",
              {"outil": "kics", **dossiers["kics"],
               "note": "PREUVES de qualification — l'approbation est humaine."})

    g = dossiers["grype"]["attendus"]
    t = dossiers["trivy_sca_reference"]["attendus"]
    kk = dossiers["kics"]["attendus"]
    print(f"grype : {g['compte']} findings | trivy réf : {t['compte']} | "
          f"kics : {kk['compte']}")
    regles_g = {r for v in g["par_cle"].values() for r in v}
    regles_t = {r for v in t["par_cle"].values() for r in v}
    # Fait mesuré : grype identifie en GHSA-*, trivy en CVE-* (pas d'alias dans sa
    # sortie). La convergence se mesure donc sur les PAQUETS (clé du clusterer),
    # pas sur les identifiants de règle.
    print(f"paquets communs grype∩trivy : {len(paquets_g & paquets_t)} "
          f"(grype {len(paquets_g)}, trivy {len(paquets_t)})")
    print(f"règles communes grype∩trivy : {len(regles_g & regles_t)} — namespaces "
          f"différents (GHSA vs CVE), convergence par paquet")
    print(f"stabilité grype : {dossiers['grype']['stabilite']}")
    print(f"stabilité kics  : {dossiers['kics']['stabilite']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
