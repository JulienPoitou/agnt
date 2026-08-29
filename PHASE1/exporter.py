#!/usr/bin/env python3
"""Regroupe tout le projet en UN SEUL fichier .md, pour transfert de session.

Le zip n'est pas accepté par l'interface de téléversement. Un .md passe partout.
Chaque fichier est encadré par un en-tête `## FICHIER : <chemin>` et des barres de code,
pour que la session suivante puisse recréer l'arborescence.
"""
from __future__ import annotations

import pathlib

RACINE = pathlib.Path(__file__).resolve().parent.parent

DOCS = [
    "PROJET_ETAT.md",
    "MASTER_PROMPT.md",
    "PHASE1/CRITERES.md",
    "PHASE3/CONTRAT_PUBLIC.md",
    "PHASE2/ARCHITECTURE.md",
]
CSVS = [
    "PHASE1/09_MATRICE_COUVERTURE_PROVIDERS.csv",
    "PHASE1/08_FICHES_PROVIDERS.csv",
]
CODES = [
    "PHASE3/bootstrap.sh",
    "PHASE3/analyser.py",
    "PHASE3/manifeste_dependances.yaml",
    "PHASE3/policy/policy.rego",
    "PHASE3/slice/capabilities.yaml",
    "PHASE3/slice/mapping_regles.yaml",
    "PHASE3/slice/registre.py",
    "PHASE3/slice/intent.py",
    "PHASE3/slice/intent_llm.py",
    "PHASE3/slice/plan.py",
    "PHASE3/slice/policy.py",
    "PHASE3/slice/pipeline.py",
    "PHASE3/slice/findings.py",
    "PHASE3/slice/clusterer.py",
    "PHASE3/slice/extraction.py",
    "PHASE3/slice/provider_manifest.py",
    "PHASE3/slice/rapport.py",
    "PHASE3/slice/rapport_humain.py",
    "PHASE3/slice/sandbox.py",
    "PHASE3/slice/profils.py",
    "PHASE3/slice/isolateur_oci.py",
    "PHASE3/slice/fournisseurs_llm.py",
    "PHASE3/slice/assainissement.py",
    "PHASE3/extraire_mapping.py",
    "PHASE1/catalogue.py",
    "PHASE1/matrice_providers.py",
]

LANG = {"sh": "bash", "py": "python", "yaml": "yaml", "rego": "rego",
        "md": "markdown", "csv": "csv"}


def main() -> int:
    out = [
        "# PROJET COMPLET — transfert de session",
        "",
        "Ce fichier contient **tout le projet**. Chaque bloc commence par un en-tête",
        "`## FICHIER : <chemin>` suivi du contenu entre barres de code.",
        "",
        "**Recrée l'arborescence telle quelle**, puis lance `bash PHASE3/bootstrap.sh`",
        "(il reconstruit le cache des outils, 1,6 Go, avec vérification SHA-256).",
        "",
        "**Ordre de lecture : `PROJET_ETAT.md` (section REPRISE DE SESSION), puis",
        "`MASTER_PROMPT.md` section 12.**",
        "",
        "---",
        "",
    ]
    total, manquants = 0, []

    for chemin in DOCS + CSVS + CODES:
        p = RACINE / chemin
        if not p.exists():
            manquants.append(chemin)
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        total += len(txt)
        lang = LANG.get(chemin.rsplit(".", 1)[-1], "")
        out += [f"## FICHIER : `{chemin}`", "", f"```{lang}", txt, "```", ""]

    dest = RACINE / "PROJET_COMPLET.md"
    dest.write_text("\n".join(out), encoding="utf-8")

    print(f"écrit : {dest.name}  ({dest.stat().st_size / 1024:.0f} Ko)")
    print(f"contenu : {total / 1024:.0f} Ko, {len(DOCS) + len(CSVS) + len(CODES) - len(manquants)} fichiers")
    if manquants:
        print("\nMANQUANTS :")
        for m in manquants:
            print(f"  {m}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
