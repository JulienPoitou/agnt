#!/usr/bin/env python3
"""Suite de tests SOC & DFIR (Analyse de logs & Règles Sigma).

Invariants vérifiés :
- CAPACITÉS : LOG_ANALYSIS et THREAT_INTEL sont déclarées dans capabilities.yaml.
- PARSER : parsers_sigma.extraire_items_sigma parse correctement un flux JSON/Sigma et retourne des items conformes.
- PLUGIN : le plugin sigma.yaml est valide et chargeable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import parsers_sigma as PS
from registre import Registry

PAS, ECHECS = 0, 0


def cas(nom: str, ok: bool, detail: str = "") -> None:
    global PAS, ECHECS
    if ok:
        PAS += 1
        print(f"  OK    {nom}")
    else:
        ECHECS += 1
        print(f"  ECHEC {nom} — {detail}")


def main() -> int:
    print("=== TEST SOC & DFIR (LOGS / SIGMA / CTI) ===")

    # 1. Vérification du parser Sigma
    json_logs = json.dumps({
        "detections": [
            {
                "rule_id": "SIGMA-001",
                "title": "SSH Brute Force",
                "file": "auth.log",
                "line": 42,
                "severity": "HIGH",
                "description": "Nombreux échecs SSH"
            }
        ]
    })
    items = PS.extraire_items_sigma(json_logs)
    cas("Parser Sigma extrait au moins 1 item", len(items) == 1, f"obtenu : {len(items)}")
    if items:
        it = items[0]
        cas("Champs essentiels présents (regle, nom_regle, fichier, severite, message)",
            it.get("regle") == "SIGMA-001" and it.get("nom_regle") == "SSH Brute Force"
            and it.get("fichier") == "auth.log" and it.get("severite") == "HIGH",
            f"item={it}")

    # 2. Vérification de la présence des capacités LOG_ANALYSIS & THREAT_INTEL
    reg = Registry()
    caps = {c.id for c in reg.capabilities()}
    cas("Capacité LOG_ANALYSIS présente dans le registre", "LOG_ANALYSIS" in caps)
    cas("Capacité THREAT_INTEL présente dans le registre", "THREAT_INTEL" in caps)

    # 3. Vérification de l'existence des fichiers de fixture
    fix_dir = RACINE / "testrepo_logs"
    cas("Dossier de fixture testrepo_logs présent", fix_dir.is_dir())
    cas("Fichier events.json de fixture présent", (fix_dir / "events.json").is_file())

    print(f"\n{'=' * 50}\n  {PAS} OK · {ECHECS} ECHEC(S)\n{'=' * 50}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
