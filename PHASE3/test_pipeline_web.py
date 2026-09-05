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
                          registre=reg, out_dir="/tmp/aw", verifier_oracle=False, cage=False)
        cas("2 providers → findings agrégés, run terminé",
            rap["statut_run"] == "termine" and len(rap["findings"]) == 2
            and rap["providers_ecartes"] == [],
            f"run={rap['statut_run']} findings={len(rap['findings'])}")
        cas("findings naissent OBSERVED (jamais confirmés)",
            all(f.get("cycle", {}).get("etat") == "observed" for f in rap["findings"]))
        cas("oracle désactivé en unitaire : aucun rejeu réseau (verifications absent)",
            "verifications" not in rap)
        cas("rapport scellé vérifiable",
            PR.verifier(rap.get("preuve", {}))[0] is True)
        # --- reprise : diff de re-scan (empreintes stables inter-runs, mesuré)
        cas("reprise absente sans précédent fourni", "reprise" not in rap)
        # --- phases : l'ordre des tâches suit surface → endpoints → vuln,
        #     même quand l'engagement les demande dans un autre ordre
        rap_o = PW.derouler(engagement(providers_prevus=["nuclei", "httpx"]),
                            faux_ok({"nuclei": (0, NUCLEI_OK), "httpx": (0, "{}")}),
                            registre=reg, out_dir="/tmp/aw", verifier_oracle=False, cage=False)
        cas("phases : la surface (httpx) passe avant la vuln (nuclei) même si "
            "demandée en dernier",
            [d["provider"] for d in rap_o["details"]] == ["httpx", "nuclei"],
            json.dumps([d["provider"] for d in rap_o["details"]]))
        # --- scan authentifié v1 : rapport auth + motifs honnêtes (sans cookie)
        rap_a = PW.derouler(engagement(providers_prevus=["nuclei"]),
                            faux_ok({"nuclei": (0, NUCLEI_OK)}),
                            registre=reg, out_dir="/tmp/aw", verifier_oracle=False,
                            cage=False)
        cas("auth v1 : sans cookie → rapport auth.fournie false, motif nommé dans details",
            (rap_a.get("auth") or {}).get("fournie") is False
            and [d for d in rap_a["details"] if d["provider"] == "nuclei"][0]["auth"]
            == "non authentifié : aucun cookie fourni",
            json.dumps(rap_a.get("auth")) + " / "
            + json.dumps(rap_a["details"], ensure_ascii=False)[:140])
        # --- scan authentifié v1 AVEC cookie : fournie true, ZÉRO fuite de la valeur
        SECRET = "SESSION=secret-pipeline-77"
        rap_s = PW.derouler(engagement(providers_prevus=["nuclei", "whatweb"]),
                            faux_ok({"nuclei": (0, NUCLEI_OK)}),
                            registre=reg, out_dir="/tmp/aw", verifier_oracle=False,
                            cage=False, auth_cookies=SECRET)
        det_s = {d["provider"]: d for d in rap_s["details"]}
        cas("auth v1 : avec cookie → auth.fournie true, VALEUR absente du rapport "
            "sérialisé (preuve scellée incluse)",
            (rap_s.get("auth") or {}).get("fournie") is True
            and SECRET not in json.dumps(rap_s, default=str),
            json.dumps(rap_s.get("auth")) + " / " + json.dumps(rap_s)[:160])
        cas("auth v1 : motifs différenciés déclarant / non-déclarant",
            det_s.get("nuclei", {}).get("auth") == "authentifié"
            and det_s.get("whatweb", {}).get("auth")
            == "non authentifié : outil sans déclaration auth",
            json.dumps(rap_s["details"], ensure_ascii=False)[:180])
        cas("auth v1 : la note de limite v1 accompagne un run authentifié",
            any("auth_cookies v1" in str(l) for l in rap_s.get("limites_connues", [])),
            json.dumps(rap_s.get("limites_connues"), ensure_ascii=False)[:160])
        # --- plafond SYSTEMIC (leçon ZAP 2.17) : vue agrégée, findings intacts
        def faux_finding(n):
            return {"id": "x-%04d" % n,
                    "source": {"tool": "ffuf", "canonical_rule_id": "ffuf:x"},
                    "location": {"url": "https://target.tld/p%d" % n}}
        fakes = [faux_finding(i) for i in range(7)] + [
            {"id": "y-0001", "source": {"tool": "ffuf", "canonical_rule_id": "ffuf:y"},
             "location": {"url": "https://target.tld/un"}}]
        sysv = PW._systemique(fakes)
        cas("systemique : règle sur 7 URLs → UN agrégat, tronqué à 5 affichées",
            len(sysv) == 1 and sysv[0]["occurrences"] == 7
            and sysv[0]["urls_distinctes"] == 7 and len(sysv[0]["urls"]) == 5
            and sysv[0]["tronque"] is True,
            json.dumps(sysv, ensure_ascii=False)[:180])
        cas("systemique : règle sous le seuil → pas d'agrégat",
            all(s["regle"] != "ffuf:y" for s in sysv),
            json.dumps(sysv, ensure_ascii=False)[:120])
        # --- cage : la commande construite est du bwrap, egress paramétrable
        import shutil as _sh
        _httpx = _sh.which("httpx")
        if _httpx:
            exe_ok = PW.ExecuteurCage(lambda t: t, "/tmp/aw-cage", regles="",
                                      egress=True, racine_ph3=RACINE)
            argv_ok = exe_ok.prefixe([_httpx, "-u", "https://target.tld/"])
            cas("cage : argv wrappé par bwrap, réseau NON coupé (egress accordé)",
                argv_ok[0].endswith("bwrap") and "--unshare-net" not in argv_ok
                and _httpx in argv_ok,
                " ".join(argv_ok)[:180])
            exe_ko = PW.ExecuteurCage(lambda t: t, "/tmp/aw-cage", regles="",
                                      egress=False, racine_ph3=RACINE)
            argv_ko = exe_ko.prefixe([_httpx, "-u", "https://target.tld/"])
            cas("cage : egress refusé → --unshare-net présent (réseau coupé)",
                "--unshare-net" in argv_ko,
                " ".join(argv_ko)[:180])
            cas("cage : la sortie est montée en ÉCRITURE",
                any("--bind" in a for a in argv_ok),
                " ".join(argv_ok)[:180])
        else:
            cas("cage : httpx absent → construction NON ÉVALUÉE ici", None,
                "machine sans binaire, la preuve cage vit en test_web_cable")
        fp0 = rap["findings"][0]["identity"]["fingerprint"]
        rap_r = PW.derouler(engagement(), faux_ok({"nuclei": (0, NUCLEI_OK),
                                                  "zap_baseline": (1, ZAP_OK)}),
                            registre=reg, out_dir="/tmp/aw", verifier_oracle=False, cage=False,
                            precedent_id="e-avant",
                            precedents={fp0: {"regle": "t1", "url": "https://target.tld/",
                                              "etat": "verified"}})
        cas("reprise : empreinte re-détectée → persistant, référence au précédent",
            rap_r["reprise"]["persistants"] == 1 and rap_r["reprise"]["nouveaux"] == 1
            and rap_r["reprise"]["non_releves"] == 0
            and rap_r["reprise"]["engagement_precedent"] == "e-avant",
            json.dumps(rap_r["reprise"], ensure_ascii=False)[:160])
        rap_r2 = PW.derouler(engagement(), faux_ok({"nuclei": (0, NUCLEI_OK),
                                                    "zap_baseline": (1, ZAP_OK)}),
                             registre=reg, out_dir="/tmp/aw", verifier_oracle=False, cage=False,
                             precedents={"vieux-fp": {"regle": "ancienne-regle",
                                                      "url": "https://target.tld/a",
                                                      "etat": "observed"}})
        cas("reprise : empreinte du précédent absente → « non relevé », un fait rendu "
            "(jamais un verdict corrigé)",
            rap_r2["reprise"]["non_releves"] == 1 and rap_r2["reprise"]["nouveaux"] == 2
            and rap_r2["reprise"]["persistants"] == 0
            and rap_r2["reprise"]["details_non_releves"][0]["regle"] == "ancienne-regle",
            json.dumps(rap_r2["reprise"], ensure_ascii=False)[:200])
        rap = PW.derouler(engagement(providers_prevus=["nuclei", "bandit"]),
                          faux_ok({"nuclei": (0, NUCLEI_OK)}),
                          registre=reg, out_dir="/tmp/aw", verifier_oracle=False, cage=False)
        cas("provider inapplicable écarté avec motif, pas d'arrêt",
            rap["statut_run"] == "termine" and len(rap["findings"]) == 1
            and len(rap["providers_ecartes"]) == 1
            and "non applicable" in rap["providers_ecartes"][0]["motif"],
            json.dumps(rap["providers_ecartes"], ensure_ascii=False)[:140])
        rap = PW.derouler(engagement(), faux_ok({"nuclei": (5, "boom")}), registre=reg,
                          out_dir="/tmp/aw", verifier_oracle=False, cage=False)
        det = [d for d in rap["details"] if d["provider"] == "nuclei"][0]
        cas("code hors succès → run continue, échec provider enregistré honnêtement",
            rap["statut_run"] == "termine" and rap["findings"] == []
            and "code 5" in det.get("motif", ""),
            json.dumps(det, ensure_ascii=False)[:140])
        rap = PW.derouler(engagement(egress=False),
                          faux_ok({"nuclei": (0, NUCLEI_OK)}), registre=reg,
                          out_dir="/tmp/aw", verifier_oracle=False, cage=False)
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
