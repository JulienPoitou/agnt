#!/usr/bin/env python3
"""
Régénère ATTENDUS.yaml depuis les artefacts capturés de testrepo_go.

Les artefacts (artefacts_captures/) sont les sorties RÉELLES des outils sur cette
fixture, capturées une fois et versionnées : les tests les relisent sans jamais
ré-exécuter les outils. ATTENDUS.yaml en est la projection lisible.

Usage: python3 PHASE3/testrepo_go/genere_attendus.py
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

ICI = Path(__file__).parent
CAP = ICI / "artefacts_captures"
SORTIE = ICI / "ATTENDUS.yaml"


def main() -> int:
    semgrep = json.loads((CAP / "semgrep_go.json").read_text(encoding="utf-8"))
    trivy = json.loads((CAP / "trivy.json").read_text(encoding="utf-8"))
    gitleaks = json.loads((CAP / "gitleaks.json").read_text(encoding="utf-8"))

    sg = {}
    for r in semgrep.get("results") or []:
        cle = f'{r["path"]}:{r["start"]["line"]}'
        sg.setdefault(cle, []).append(r["check_id"])

    tv = {}
    for res in trivy.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            tv.setdefault(f'{res["Target"]}:{v["PkgName"]}', []).append(
                {"cve": v["VulnerabilityID"], "severite": v.get("Severity"),
                 "installee": v.get("InstalledVersion")})

    gl = [{"regle": x["RuleID"], "fichier": x["File"], "ligne": x["StartLine"]}
          for x in gitleaks]

    doc = {
        "genere_le": "2026-08-29",
        "genere_par": "semgrep (p/golang épinglé) · trivy 0.74.0 · gitleaks 8.30.1",
        "methode": (
            "EXTRAIT d'exécutions réelles sur cette fixture. Ne pas éditer à la main : "
            "régénérer via genere_attendus.py depuis artefacts_captures/."
        ),
        "attendus": {
            "semgrep_go": {"par_emplacement": {k: sorted(v) for k, v in sorted(sg.items())},
                           "compte": len(semgrep.get("results") or [])},
            "trivy": {"par_paquet": {k: sorted(v, key=lambda x: x["cve"])
                                     for k, v in sorted(tv.items())},
                      "compte": sum(len(v) for v in tv.values())},
            "gitleaks": gl,
        },
        "note_perimetre": (
            "Le provider Go déclaré est semgrep_go (règles p/golang épinglées) : "
            "gosec, analyse plus profonde, exige le toolchain Go dans l'isolateur — "
            "reporté et documenté (mesuré le 2026-08-29 : 'go command required'). "
            "La clé AWS d'exemple (documentation AWS) est sur liste blanche gitleaks : "
            "le jeton factice ghp_ sert de secret de référence, comme dans testrepo."
        ),
        "convergence_attendue": (
            "gitleaks (main.go:59) et semgrep_go (main.go:22, 33) signalent le MÊME "
            "fichier : occasion de regroupement inter-outils mesurée par test_go.py."
        ),
    }
    SORTIE.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=100),
                      encoding="utf-8")
    print(f"{SORTIE} : semgrep_go {doc['attendus']['semgrep_go']['compte']}, "
          f"trivy {doc['attendus']['trivy']['compte']}, gitleaks {len(gl)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
