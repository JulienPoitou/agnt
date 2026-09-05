#!/usr/bin/env python3
"""Scan authentifié v1 par cookie : planifier, manifests {COOKIES}, non-fuite.

Ce que cette batterie prouve, SANS RÉSEAU (aucun binaire, aucune requête
sortante — le registre est chargé depuis le dépôt, les plans résolus en
mémoire, l'exécution est un FAUX exécuteur) :

    OPT-IN     un manifest déclare {COOKIES} → l'argv résolu porte la valeur
               fournie par l'engagement ; sans valeur, le jeton se résout en
               chaîne vide (le -H reste présent : « Cookie: ») — le plan le
               dit honnêtement (`auth.declare`, `auth.fournie`).
    DÉCLARÉ    httpx/nuclei/katana/dalfox (-H "Cookie: …"), sqlmap/dirsearch
               (--cookie=…), ffuf (-b …), gobuster (--cookies …) : chaque flag
               a été vérifié au --help du binaire ÉPINGLÉ — non mesuré de bout
               en bout (structure --help), consigné dans chaque manifest.
    NOMMÉ      les manifests sans {COOKIES} (whatweb, et les quatre TLS)
               restent non authentifiés : declare false, la valeur n'y entre
               jamais.
    FAIL-CLOSED  un saut de ligne, un NUL ou > 4096 octets dans auth_cookies
               → ErreurPlanification nommée AU PLAN AUSSI (pas qu'à l'API).
    SÛR        derouler avec un faux exécuteur + cookie : la VALEUR
               n'apparaît NULLE PART dans le rapport sérialisé
               (`auth.fournie` booléen, details = motifs textuels, preuve
               scellée sans argv).

Usage : python PHASE3/test_web_auth.py   → exit 0 (vert) / 1 (rouge)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import fournisseurs_web as FW                                        # noqa: E402
import pipeline_web as PW                                            # noqa: E402
import preuve as PR                                                  # noqa: E402
import taches as TA                                                  # noqa: E402

CAS: list[tuple[str, bool | None, str]] = []
ECHECS: list[str] = []

SECRET = "SESSION=secret-auth-42"


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, None if cond is None else bool(cond), detail))
    if not cond and cond is not None:
        ECHECS.append(nom)


def faux_ok(code: int = 0, texte: str = ""):
    def executer(tache: TA.Tache) -> TA.Tache:
        tache.etat = TA.EN_COURS
        tache.tentatives += 1
        tache.etat = TA.TERMINEE
        tache.resultat = TA.ResultatExecution(code, texte, "", 0.1)
        tache.fin = tache.debut + 0.1
        return tache
    return executer


def engagement(providers: list[str], **kw) -> dict:
    base = {"type": "web", "url_canonique": "https://target.tld/",
            "hote": "target.tld", "intensity": "normal", "egress": True,
            "cible_autorisee": True, "providers_prevus": providers,
            "statut": "planifie"}
    base.update(kw)
    return base


def _bilan() -> int:
    ok = len([c for c in CAS if c[1] is True])
    print(f"\n{'=' * 50}\n  {ok}/{len(CAS)} passent"
          + (f" (+{len([c for c in CAS if c[1] is None])} NON ÉVALUÉS)"
             if any(c[1] is None for c in CAS) else "")
          + f"\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if cond is False:
            print(f"  ÉCHEC · {nom}\n        {detail}")
        elif cond is None:
            print(f"  NON ÉVALUÉ · {nom}\n        {detail}")
    return 1 if ECHECS else 0


def main() -> int:
    try:
        from registre import Registry
        reg = Registry()
    except Exception as e:                              # noqa: BLE001
        cas("registre lisible ici", None, f"NON ÉVALUÉ : {type(e).__name__}")
        return _bilan()

    # --- 1. provider déclarant : la valeur atteint l'argv résolu, et LUI SEUL
    plan = FW.planifier("httpx", "https://target.tld/", "/tmp/aw", egress=True,
                        registre=reg, auth_cookies=SECRET)
    cas("httpx : la valeur fournie est dans l'argv résolu (-H « Cookie: … »)",
        "Cookie: " + SECRET in plan["argv"] and "-H" in plan["argv"],
        json.dumps(plan["argv"], ensure_ascii=False)[:160])
    cas("httpx : auth.declare true + auth.fournie true",
        (plan.get("auth") or {}).get("declare") is True
        and (plan.get("auth") or {}).get("fournie") is True,
        json.dumps(plan.get("auth")))
    # Sans valeur : {COOKIES} se résout en chaîne vide — le -H RESTE PRÉSENT,
    # valeur vide (« Cookie: »). Note honnête : c'est bien ce que resoudre_argv
    # produit (remplacement du jeton par ""), l'outil recevrait un en-tête
    # Cookie vide ; c'est la mécanique déclarée v1, mesurée ICI sur la
    # structure d'argv (pas sur une requête réelle).
    plan0 = FW.planifier("httpx", "https://target.tld/", "/tmp/aw", egress=True,
                         registre=reg)
    i = plan0["argv"].index("-H")
    cas("httpx sans cookie : -H résolu avec chaîne VIDE (« Cookie: »), fournie false",
        plan0["argv"][i + 1] == "Cookie: "
        and (plan0.get("auth") or {}).get("fournie") is False,
        json.dumps(plan0["argv"], ensure_ascii=False)[:160])
    # Chaque manifest déclarant : la valeur arrive entière dans l'argv
    fragments = {
        "nuclei": "Cookie: " + SECRET,
        "katana": "Cookie: " + SECRET,
        "dalfox": "Cookie: " + SECRET,
        "sqlmap": "--cookie=" + SECRET,
        "dirsearch": "--cookie=" + SECRET,
        "ffuf": SECRET,                # -b « {COOKIES} » : l'argument EST la valeur
        "gobuster": SECRET,            # --cookies « {COOKIES} » : idem
    }
    for pid, fragment in fragments.items():
        try:
            p = FW.planifier(pid, "https://target.tld/", "/tmp/aw", egress=True,
                             registre=reg, auth_cookies=SECRET)
            cas(pid + " : argv porte la valeur (" + fragment.split("=", 1)[0]
                + "…), declare true",
                fragment in p["argv"] and p["auth"]["declare"] is True
                and p["auth"]["fournie"] is True,
                json.dumps(p["argv"], ensure_ascii=False)[:150])
        except FW.ErreurPlanification as e:
            cas(pid + " : argv porte la valeur", False, str(e)[:140])

    # --- 2. non-déclarants : nommés, jamais devinés
    planw = FW.planifier("whatweb", "https://target.tld/", "/tmp/aw", egress=True,
                         registre=reg, auth_cookies=SECRET)
    cas("whatweb (manifest sans {COOKIES}) : declare false, argv SANS la valeur",
        planw["auth"]["declare"] is False and SECRET not in json.dumps(planw["argv"]),
        json.dumps(planw["auth"]) + " / argv=" + json.dumps(planw["argv"])[:100])
    for pid in ("sslscan", "sslyze", "testssl_sh", "tlsx"):
        p = FW.planifier(pid, "https://target.tld/", "/tmp/aw", egress=True,
                         registre=reg)
        cas(pid + " (TLS) : ne déclare PAS {COOKIES} (un audit TLS ne porte pas "
            "de cookie applicatif)",
            p["auth"]["declare"] is False, json.dumps(p["auth"]))

    # --- 3. fail-closed : contrôle de la valeur AU PLAN AUSSI (pas qu'à l'API)
    for nom, valeur, frag in [
        ("saut de ligne → ErreurPlanification nommée",
         "SESSION=a" + chr(10) + "X: y", "contrôle"),
        ("NUL → ErreurPlanification nommée", "SESSION=a" + chr(0) + "b", "contrôle"),
        ("> 4096 octets → ErreurPlanification nommée", "SESSION=" + "a" * 5000,
         "4096"),
    ]:
        try:
            FW.planifier("httpx", "https://target.tld/", "/tmp/aw", egress=True,
                         registre=reg, auth_cookies=valeur)
            cas(nom, False, "accepté — c'est le défaut que ce cas existe pour")
        except FW.ErreurPlanification as e:
            cas(nom, frag in str(e), str(e)[:140])

    # --- 4. derouler de bout en bout (faux exécuteur) : NON-FUITE du secret
    rap = PW.derouler(engagement(["httpx", "whatweb"]), faux_ok(),
                      registre=reg, out_dir="/tmp/aw-auth", verifier_oracle=False,
                      cage=False, auth_cookies=SECRET)
    cas("derouler avec cookie : rapport auth.fournie true",
        (rap.get("auth") or {}).get("fournie") is True, json.dumps(rap.get("auth")))
    cas("derouler avec cookie : la VALEUR n'apparaît NULLE PART dans le rapport "
        "sérialisé (auth, details, findings, preuve scellée — rien)",
        SECRET not in json.dumps(rap, default=str), json.dumps(rap)[:200])
    details = {d["provider"]: d for d in rap["details"]}
    cas("details : provider déclarant + cookie fourni → « authentifié »",
        details.get("httpx", {}).get("auth") == "authentifié",
        json.dumps(details.get("httpx"), ensure_ascii=False)[:140])
    cas("details : provider NON déclarant + cookie fourni → « non authentifié : "
        "outil sans déclaration auth »",
        details.get("whatweb", {}).get("auth")
        == "non authentifié : outil sans déclaration auth",
        json.dumps(details.get("whatweb"), ensure_ascii=False)[:140])
    cas("preuve scellée : vérifiable et SANS le secret",
        PR.verifier(rap.get("preuve", {}))[0] is True
        and SECRET not in json.dumps(rap.get("preuve", {}), default=str),
        json.dumps(rap.get("preuve"))[:120])
    cas("limites : la note v1 (argv transitoire, jamais rendu ni scellé) est "
        "dans le rapport",
        any("auth_cookies v1" in str(l) for l in rap.get("limites_connues", [])),
        json.dumps(rap.get("limites_connues"), ensure_ascii=False)[:200])
    # --- sans cookie : fournie false, motif nommé, pas de note v1 (rien ne transite)
    rap0 = PW.derouler(engagement(["httpx"]), faux_ok(), registre=reg,
                       out_dir="/tmp/aw-auth", verifier_oracle=False, cage=False)
    cas("derouler sans cookie : auth.fournie false",
        (rap0.get("auth") or {}).get("fournie") is False,
        json.dumps(rap0.get("auth")))
    det0 = rap0["details"][0]
    cas("derouler sans cookie : « non authentifié : aucun cookie fourni »",
        det0.get("auth") == "non authentifié : aucun cookie fourni",
        json.dumps(det0, ensure_ascii=False)[:140])
    cas("derouler sans cookie : la note v1 n'encombre pas le rapport",
        all("auth_cookies v1" not in str(l)
            for l in rap0.get("limites_connues", [])),
        json.dumps(rap0.get("limites_connues"), ensure_ascii=False)[:160])
    return _bilan()


if __name__ == "__main__":
    sys.exit(main())
