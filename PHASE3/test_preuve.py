#!/usr/bin/env python3
"""Preuve portable : sceaux, altérations, secrets, export (+ adversarial).

Usage : python PHASE3/test_preuve.py
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

from preuve import (VERSION_ENVELOPPE, empreinte_de, engagement_bundle,  # noqa: E402
                    export_markdown, sceller, verifier)

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def main() -> int:
    eng = {"type": "web", "url_canonique": "https://target.tld/a", "hote": "target.tld",
           "intensity": "normal", "providers_prevus": ["httpx", "nuclei"],
           "verification": {"oracle": "http_response", "replay": 3}, "statut": "planifie"}
    # ------------------------------------------------------- déterminisme
    b1 = engagement_bundle(eng, horodatage=1700000000.0)
    b2 = engagement_bundle(dict(reversed(list(eng.items()))), horodatage=1700000000.0)
    cas("même objet, clés mélangées → même empreinte",
        b1["empreinte"] == b2["empreinte"] and len(b1["empreinte"]) == 64)
    cas("enveloppe versionnée", b1["enveloppe"] == VERSION_ENVELOPPE
        and b1["algorithme"] == "sha256")
    cas("sceau valide", verifier(b1) == (True, "sceau_valide"))
    # ------------------------------------------------------- altérations
    faux = copy.deepcopy(b1)
    faux["objet"]["statut"] = "verifie"
    cas("statut modifié → sceau invalide",
        verifier(faux) == (False, "empreinte_invalide : contenu altéré"))
    faux = copy.deepcopy(b1)
    faux["objet"]["providers_prevus"].append("zap_baseline")
    cas("provider ajouté → sceau invalide", verifier(faux)[0] is False)
    faux = copy.deepcopy(b1)
    faux["empreinte"] = "0" * 64
    cas("empreinte remplacée → invalide", verifier(faux)[0] is False)
    for nom, env, motif in [
        ("non-objet rejeté", [1, 2], "enveloppe_non_objet"),
        ("version inconnue rejetée", {**b1, "enveloppe": "x/v9"}, "version_inconnue"),
        ("objet manquant rejeté", {"enveloppe": VERSION_ENVELOPPE}, "objet_non_dict"),
    ]:
        cas(nom, verifier(env)[1].startswith(motif), verifier(env)[1])
    # ------------------------------------------------------- secrets
    try:
        engagement_bundle({**eng, "url_canonique": "https://u:p@target.tld/a"})
        cas("userinfo dans le bundle → refusé", False, "accepté")
    except ValueError as e:
        cas("userinfo dans le bundle → refusé", "userinfo" in str(e), str(e)[:80])
    try:
        sceller(["pas", "un", "dict"])
        cas("sceller non-dict → TypeError", False, "accepté")
    except TypeError:
        cas("sceller non-dict → TypeError", True)
    # ------------------------------------------------------- export
    md = export_markdown(b1)
    cas("export markdown : champs + empreinte",
        "https://target.tld/a" in md and b1["empreinte"] in md and md.endswith("\n"))
    try:
        export_markdown({**b1, "empreinte": "0" * 64})
        cas("export d'un faux → ValueError", False, "accepté")
    except ValueError:
        cas("export d'un faux → ValueError", True)
    # unicode stable
    u = engagement_bundle({**eng, "hote": "münchen.de",
                           "url_canonique": "https://münchen.de/"}, horodatage=1.0)
    cas("unicode stable et vérifiable", verifier(u)[0] is True
        and u["empreinte"] == empreinte_de(u["objet"]))

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
