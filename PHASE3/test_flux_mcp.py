#!/usr/bin/env python3
"""Remediation workflow + gouvernance MCP : transitions retest, classification, audit.

Usage : python PHASE3/test_flux_mcp.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import gouvernance_mcp as GM                                          # noqa: E402
import remediation_flux as RF                                         # noqa: E402
from cycle_vie import FIXED, VERIFIED, transition                      # noqa: E402

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def finding(**kw):
    base = {"id": "f1", "location": {"url": "https://target.tld/a"},
            "source": {"tool": "nuclei"}}
    base.update(kw)
    return base


def main() -> int:
    # ------------------------------------------------------- remediation flux
    d = RF.demander_retest(finding(), {"type": "config_fix"})
    cas("demande reprend cible + outil d'origine",
        d["finding_id"] == "f1" and d["cible"] == "https://target.tld/a"
        and d["providers"] == ["nuclei"], str(d)[:120])
    try:
        RF.demander_retest({"location": {}})
        cas("finding sans id → refus", False, "accepté")
    except RF.ErreurFlux:
        cas("finding sans id → refus", True)
    try:
        RF.demander_retest({"id": "x", "location": {}})
        cas("finding sans cible → refus", False, "accepté")
    except RF.ErreurFlux:
        cas("finding sans cible → refus", True)
    for nom, etat, vuln, evt_attendu in [
        ("FIXED + encore vulnérable → regresser", FIXED, True, "regresser"),
        ("FIXED + propre → aucun", FIXED, False, "aucun"),
        ("VERIFIED + encore → aucun", VERIFIED, True, "aucun"),
        ("VERIFIED + propre → corriger", VERIFIED, False, "corriger"),
    ]:
        evt, motif = RF.conclure_retest(d, etat, vuln)
        cas(nom, evt == evt_attendu and bool(motif),
            f"{evt} : {motif}")
        if evt != "aucun":
            cas(f"  événement {evt} valide au cycle",
                transition(etat, evt) in ("regressed", "fixed"))
    try:
        RF.conclure_retest(d, "candidate", True)
        cas("retest depuis candidate → refus", False, "accepté")
    except RF.ErreurFlux:
        cas("retest depuis candidate → refus", True)
    # ------------------------------------------------------- gouvernance MCP
    c = GM.classifier({"risque": "PASSIVE"})
    cas("outil passif local → PASSIVE, sans approbation",
        c == {"niveau": "PASSIVE", "signaux": [], "exige_egress": False,
              "exige_approbation": False}, str(c))
    c = GM.classifier({"risque": "ACTIVE", "reseau": True,
                       "endpoint": "https://tiers.example/mcp", "transport": "http"})
    cas("actif + réseau + distant → signaux + approbation",
        c["niveau"] == "ACTIVE" and "egress_requis" in c["signaux"]
        and "endpoint_distant" in c["signaux"] and c["exige_approbation"] is True,
        str(c))
    c = GM.classifier({"risque": "WEIRD"})
    cas("risque inconnu → ACTIVE fail-closed + signalé",
        c["niveau"] == "ACTIVE" and "risque_inconnu" in c["signaux"]
        and c["exige_approbation"] is True, str(c))
    tmp = Path(tempfile.mkdtemp(prefix="agnt-mcp-audit-"))
    journal = tmp / "mcp-audit.jsonl"
    entree = GM.auditer("refuse", "outil-tiers",
                        ["endpoint_distant"],
                        {"token": "SECRET-123", "cible": "https://t/"},
                        journal=journal)
    contenu = journal.read_text(encoding="utf-8")
    cas("audit : décision + digest, valeur secrète absente du journal",
        entree["decision"] == "refuse" and len(entree["args_digest"] or "") == 64
        and "SECRET-123" not in contenu and "args_digest" in contenu,
        contenu[:160])
    cas("digest stable", GM.empreinte_args({"b": 1, "a": 2}) == GM.empreinte_args({"a": 2, "b": 1}))
    try:
        GM.auditer("peut-etre", "x", [])
        cas("décision inconnue → ValueError", False, "acceptée")
    except ValueError:
        cas("décision inconnue → ValueError", True)
    try:
        GM.auditer("autorise", "", [])
        cas("outil vide → ValueError", False, "accepté")
    except ValueError:
        cas("outil vide → ValueError", True)

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
