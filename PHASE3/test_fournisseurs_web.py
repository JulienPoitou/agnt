#!/usr/bin/env python3
"""Providers web : planification manifest + interprétation fixtures (mockées).

Aucun binaire lancé : les sorties sont des FIXTURES textuelles (format réel
documenté : nuclei lignes_json v3.11.1, ZAP JSON, ffuf -of json).
`RUNTIME_VERIFIED` reste false — seul Linux + binaires le levera.

Si le registre est illisible ici, les cas dépendants sont NON ÉVALUÉS
(nommés, pas simulés).

Usage : python PHASE3/test_fournisseurs_web.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import fournisseurs_web as FW                                      # noqa: E402

CAS: list[tuple[str, bool | None, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, None if cond is None else bool(cond), detail))
    if not cond and cond is not None:
        ECHECS.append(nom)


NUCLEI_LIGNES = "\n".join([
    json.dumps({"template-id": "http-missing-security-headers",
                "name": "Missing Security Headers", "severity": "info",
                "description": "headers absents",
                "matched-at": "https://target.tld/", "type": "http"}),
    "CETTE LIGNE N'EST PAS DU JSON",
    json.dumps({"template-id": "cve-2024-1234", "name": "CVE_Test",
                "severity": "high", "description": "faille",
                "matched-at": "https://target.tld/admin"}),
])

ZAP_RAPPORT = json.dumps({"site": [{"@name": "https://target.tld/",
                                    "alerts": [{"pluginid": "10021",
                                                "alert": "X-Content-Type-Options",
                                                "riskdesc": "Low (Medium)",
                                                "confidencedesc": "Medium (High)",
                                                "cweid": "693",
                                                "instances": [{"uri": "https://target.tld/a"}]}]}]})

FFUF_JSON = json.dumps({"results": [
    {"url": "https://target.tld/admin", "input": {"FUZZ": "admin"},
     "status": 200, "length": 1234, "server": "nginx",
     "matcherstatus": "match"}]})


def main() -> int:
    cas("runtime scanners NON vérifié déclaré", FW.RUNTIME_VERIFIED is False)
    try:
        from registre import Registry
        reg = Registry()
        reg_ok: bool | None = True
    except Exception as e:
        reg = None  # type: ignore
        reg_ok = None
        cas("registre lisible ici", None, f"NON ÉVALUÉ : {type(e).__name__}")
    # ------------------------------------------------------- planification
    if reg_ok:
        try:
            plan = FW.planifier("nuclei", "https://target.tld/", "/tmp/agnt-out",
                                egress=True, registre=reg)
            cas("plan nuclei : argv avec URL, binaire non résolu, codes [0]",
                plan["argv"][0] == "nuclei" and "https://target.tld/" in plan["argv"]
                and plan["binaire_resolu"] is False and plan["codes_succes"] == [0]
                and plan["timeout_s"] >= 0,
                json.dumps(plan["argv"])[:120])
        except Exception as e:
            cas("plan nuclei", False, f"{type(e).__name__}: {e}")
        try:
            FW.planifier("nuclei", "https://target.tld/", "/tmp/agnt-out",
                         egress=False, registre=reg)
            cas("sans egress → refus nommé", False, "accepté")
        except FW.ErreurPlanification as e:
            cas("sans egress → refus nommé", "egress" in str(e), str(e)[:100])
        try:
            FW.planifier("outil-qui-nexiste-pas", "https://target.tld/", "/tmp/x",
                         egress=True, registre=reg)
            cas("provider inconnu → refus", False, "accepté")
        except FW.ErreurPlanification:
            cas("provider inconnu → refus", True)
        try:
            FW.planifier("bandit", "https://target.tld/", "/tmp/x",
                         egress=True, registre=reg)
            cas("provider local sur url → non applicable", False, "accepté")
        except FW.ErreurPlanification as e:
            cas("provider local sur url → non applicable", "non applicable" in str(e),
                str(e)[:100])
        try:
            zap = FW.planifier("zap_baseline", "https://target.tld/", "/tmp/agnt-out",
                               egress=True, registre=reg)
            cas("plan zap : codes [0,1,2] lus du script épinglé",
                zap["codes_succes"] == [0, 1, 2] and zap["timeout_s"] == 900,
                str(zap["codes_succes"]))
        except Exception as e:
            cas("plan zap", False, f"{type(e).__name__}: {e}")
    # ------------------------------------------------------- interprétation
    if reg_ok:
        r = FW.interpreter("nuclei", 0, NUCLEI_LIGNES, registre=reg)
        cas("nuclei : 2 findings, ligne parasite ignorée",
            len(r["findings"]) == 2 and r["echec"] is False,
            f"findings={len(r['findings'])} echec={r['echec']} {r['motif']}")
        if r["findings"]:
            f0 = r["findings"][0]
            cas("finding nuclei : règle template + url + sévérité",
                "http-missing-security-headers" in json.dumps(f0.identity, ensure_ascii=False)
                and "target.tld" in json.dumps(f0.location, ensure_ascii=False),
                json.dumps(f0.to_dict(), ensure_ascii=False)[:200])
        r = FW.interpreter("nuclei", 2, NUCLEI_LIGNES, registre=reg)
        cas("code 2 hors succès → échec nommé",
            r["echec"] is True and "code 2" in r["motif"], r["motif"])
        r = FW.interpreter("nuclei", 0, "", registre=reg)
        cas("sortie vide code 0 → échec (pas un scan propre)",
            r["echec"] is True and "vide" in r["motif"], r["motif"])
        r = FW.interpreter("zap_baseline", 1, ZAP_RAPPORT, registre=reg)
        cas("zap : 1 finding ZAP-10021, code 1 admis",
            len(r["findings"]) == 1 and r["echec"] is False
            and "ZAP-10021" in json.dumps(r["findings"][0].identity, ensure_ascii=False),
            f"findings={len(r['findings'])} echec={r['echec']} {r['motif']}")
        r = FW.interpreter("ffuf", 0, FFUF_JSON, registre=reg)
        cas("ffuf : 1 finding surface (pas une vulnérabilité)",
            len(r["findings"]) == 1 and r["echec"] is False,
            f"findings={len(r['findings'])} {r['motif']}")
        r = FW.interpreter("nuclei", 0, "{pas du json", registre=reg)
        cas("JSON illisible → 0 item, résultat vide nommé (doctrine core : code "
            "attendu + sortie lue = résultat, pas un scan propre)",
            r["items"] == [] and r["echec"] is False and "aucun_item" in r["motif"],
            r["motif"])

    print(f"\n{'=' * 50}\n  {len(CAS) - len([c for c in CAS if c[1] is False]) - len([c for c in CAS if c[1] is None])}/{len(CAS)} passent"
          + (f" (+{len([c for c in CAS if c[1] is None])} NON ÉVALUÉS)" if any(c[1] is None for c in CAS) else "")
          + f"\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if cond is False:
            print(f"  ÉCHEC · {nom}\n        {detail}")
        elif cond is None:
            print(f"  NON ÉVALUÉ · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
