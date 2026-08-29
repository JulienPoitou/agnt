#!/usr/bin/env python3
"""
Régénère ATTENDUS.yaml depuis l'artefact checkov capturé.

L'artefact (artefacts_captures/checkov_multiframework.json) est la sortie RÉELLE
de checkov sur cette fixture — capturé une fois, versionné, relu par les tests
sans jamais ré-exécuter l'outil ni le réseau. ATTENDUS.yaml en est la projection
lisible : par framework, par fichier, les règles attendues.

Usage: python3 PHASE3/testrepo_iac/genere_attendus.py
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

ICI = Path(__file__).parent
ARTEFACT = ICI / "artefacts_captures" / "checkov_multiframework.json"
SORTIE = ICI / "ATTENDUS.yaml"


def main() -> int:
    brut = json.loads(ARTEFACT.read_text(encoding="utf-8"))
    version = subprocess.run(["checkov", "--version"], capture_output=True, text=True,
                             timeout=120).stdout.strip().splitlines()[-1].strip()

    attendus: dict = {}
    for bloc in brut:
        cadre = bloc["check_type"]
        par_fichier: dict[str, dict] = {}
        for item in bloc["results"]["failed_checks"]:
            f = par_fichier.setdefault(item["file_path"], {"checks": []})
            if item["check_id"] not in f["checks"]:
                f["checks"].append(item["check_id"])
        for f in par_fichier.values():
            f["checks"].sort()
            f["compte"] = len(f["checks"])
        if par_fichier:
            attendus[cadre] = dict(sorted(par_fichier.items()))

    doc = {
        "genere_le": "2026-08-28",
        "genere_par": f"checkov {version} (pip)",
        "methode": (
            "EXTRAIT d'une exécution réelle sur cette fixture — résultats identiques "
            "avec et sans réseau (bwrap --unshare-net). Ne pas éditer à la main : "
            "régénérer via genere_attendus.py depuis artefacts_captures/."
        ),
        "attendus_provider": attendus,
        "note_perimetre": (
            "Depuis le 2026-08-28 la déclaration checkov est MULTI-FRAMEWORK "
            "(plus de --framework terraform) : attendus_provider couvre tous les "
            "frameworks que l'outil détecte sur cette cible. terraform_plan est "
            "détecté mais vide (aucun fichier .plan.json dans la fixture) : son "
            "absence de findings est un résultat, pas un oubli."
        ),
        "verification_secret": (
            "La valeur de mot_de_passe_admin (main.tf) n'apparaît dans aucune sortie "
            "checkov — vérifié le 2026-08-28 sur les JSON réseau et hors ligne."
        ),
    }
    SORTIE.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=100),
                      encoding="utf-8")
    total = sum(f["compte"] for fw in attendus.values() for f in fw.values())
    print(f"{SORTIE} régénéré : {total} findings attendus sur {len(attendus)} frameworks "
          f"({', '.join(attendus)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
