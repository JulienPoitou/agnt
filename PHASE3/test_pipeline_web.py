#!/usr/bin/env python3
"""Pipeline web : scope, planification partielle honnête, propagation d'échec,
findings OBSERVED, rapport scellé — exécuteur FAUX (aucun binaire).

Usage : python PHASE3/test_pipeline_web.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import pipeline_web as PW                                            # noqa: E402
import preuve as PR                                                 # noqa: E402
import taches as TA                                                 # noqa: E402

CAS: list[tuple[str, bool | None, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, None if cond is None else bool(cond), detail))
    if not cond and cond is not None:
        ECHECS.append(nom)


NUCLEI_OK = "\n".join([
    json.dumps({"template-id": "t1", "name": "N1", "severity": "high",
                "description": "d", "matched-at": "https://target.tld/"}),
])

ZAP_OK = json.dumps({"site": [{"@name": "https://target.tld/", "alerts": [
    {"pluginid": "10021", "alert": "X", "riskdesc": "Low (M)",
     "instances": [{"uri": "https://target.tld/a"}]}]}]})


def faux_ok(sorties: dict):
    def executer(tache: TA.Tache) -> TA.Tache:
        tache.etat = TA.EN_COURS
        tache.tentatives += 1
        code, texte = sorties.get(tache.provider_id, (0, ""))
        tache.etat = TA.TERMINEE
        tache.resultat = TA.ResultatExecution(code, texte, "", 0.1)
        tache.fin = tache.debut + 0.1
        return tache
    return executer


def engagement(**kw):
    base = {"type": "web", "url_canonique": "https://target.tld/",
            "hote": "target.tld", "intensity": "normal", "egress": True,
            "cible_autorisee": True,
            "providers_prevus": ["nuclei", "zap_baseline"], "statut": "planifie"}
    base.update(kw)
    return base


def main() -> int:
    try:
        from registre import Registry
        reg = Registry()
        reg_ok: bool | None = True
    except Exception as e:
        reg = None  # type: ignore
        reg_ok = None
        cas("registre lisible ici", None, f"NON ÉVALUÉ : {type(e).__name__}")
    if reg_ok:
        rap = PW.derouler(engagement(), faux_ok({"nuclei": (0, NUCLEI_OK),
                                                 "zap_baseline": (1, ZAP_OK)}),
                          registre=reg, out_dir="/tmp/aw")
        cas("2 providers → findings agrégés, run terminé",
            rap["statut_run"] == "termine" and len(rap["findings"]) == 2
            and rap["providers_ecartes"] == [],
            f"run={rap['statut_run']} findings={len(rap['findings'])}")
        cas("findings naissent OBSERVED (jamais confirmés)",
            all(f.get("cycle", {}).get("etat") == "observed" for f in rap["findings"]))
        cas("rapport scellé vérifiable",
            PR.verifier(rap.get("preuve", {}))[0] is True)
        rap = PW.derouler(engagement(providers_prevus=["nuclei", "bandit"]),
                          faux_ok({"nuclei": (0, NUCLEI_OK)}),
                          registre=reg, out_dir="/tmp/aw")
        cas("provider inapplicable écarté avec motif, pas d'arrêt",
            rap["statut_run"] == "termine" and len(rap["findings"]) == 1
            and len(rap["providers_ecartes"]) == 1
            and "non applicable" in rap["providers_ecartes"][0]["motif"],
            json.dumps(rap["providers_ecartes"], ensure_ascii=False)[:140])
        rap = PW.derouler(engagement(), faux_ok({"nuclei": (5, "boom")}), registre=reg,
                          out_dir="/tmp/aw")
        det = [d for d in rap["details"] if d["provider"] == "nuclei"][0]
        cas("code hors succès → run continue, échec provider enregistré honnêtement",
            rap["statut_run"] == "termine" and rap["findings"] == []
            and "code 5" in det.get("motif", ""),
            json.dumps(det, ensure_ascii=False)[:140])
        rap = PW.derouler(engagement(egress=False),
                          faux_ok({"nuclei": (0, NUCLEI_OK)}), registre=reg, out_dir="/tmp/aw")
        cas("sans egress → tout écarté, run refusé nommé",
            rap["statut_run"] == "refuse" and rap["findings"] == []
            and all("egress" in e["motif"] for e in rap["providers_ecartes"]),
            rap["motif_run"][:120])
        try:
            PW.derouler(engagement(url_canonique="https://evil.tld/",
                                   hote="target.tld"), faux_ok({}), registre=reg)
            cas("scope incohérent → ErreurPipeline", False, "accepté")
        except PW.ErreurPipeline as e:
            cas("scope incohérent → ErreurPipeline", "scope" in str(e), str(e)[:100])
        try:
            PW.derouler({"type": "repository"}, faux_ok({}), registre=reg)
            cas("non-web → ErreurPipeline", False, "accepté")
        except PW.ErreurPipeline:
            cas("non-web → ErreurPipeline", True)

    print(f"\n{'=' * 50}\n  {len(CAS) - len([c for c in CAS if c[1] is False])}/{len(CAS)} passent"
          + (f" (+{len([c for c in CAS if c[1] is None])} NON ÉVALUÉS)"
             if any(c[1] is None for c in CAS) else "")
          + f"\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if cond is False:
            print(f"  ÉCHEC · {nom}\n        {detail}")
        elif cond is None:
            print(f"  NON ÉVALUÉ · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
