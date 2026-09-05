#!/usr/bin/env python3
"""Plugins G5 (CMS, API & divers) : registre + planification + interprétation.

Aucun réseau : les sorties sont celles ARCHIVÉES dans cible_web/qualif/<outil>/
(épreuve réelle du 2026-09-05 contre THAUMAS-WEB, cible locale d'épreuve) et des
FIXTURES ÉTIQUETÉS (structure mesurée, valeurs synthétiques).

Ce que la batterie prouve :
  1. les 5 épingles G5 se lisent (outils.registre) et les 5 plugins se chargent ;
  2. `planifier` résout l'argv (URL, wordlists épinglées, codes de succès) ;
  3. l'interpréteur retrouve les items depuis les sorties RÉELLES archivées —
     y compris les découvertes (kiterunner : /.env et /admin non liés ;
     gospider : les 3 liens liés) et les vides HONNÊTES MOTIVÉS (x8 : aucun
     paramètre CACHÉ sur /search ; cmseek : pas de CMS sur la cible ;
     dirhunt : la normalisation sans query et le rapport < 300 sont des
     limites de l'outil, nommées).

Note d'honnêteté (wpscan) : wpscan 4.1.0 n'est PAS installable sur cette
machine (extensions natives Ruby, ruby-dev absent, mesuré) — la capacité audit
CMS est portée par cmseek (épingle REMPLACANTE). La batterie vérifie que
l'épingle wpscan reste un placeholder SANS empreinte inventée.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

QUALIF = RACINE / "cible_web" / "qualif"
URL_CIBLE = "http://127.0.0.1:8807"
REGLES = RACINE / "regles_web"

CAS: list[tuple[str, bool | None, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, None if cond is None else bool(cond), detail))
    if not cond and cond is not None:
        ECHECS.append(nom)


def _lire(*parties: str) -> str:
    return (QUALIF.joinpath(*parties)).read_text(encoding="utf-8")


# FIXTURE x8 « paramètre caché trouvé » — structure MESURÉE (array JSON rendu
# par -O json, épreuve qualif/x8/) ; valeurs SYNTHÉTIQUES pour rester hors-ligne.
# ÉTIQUETÉ : pas une sortie de la cible d'épreuve.
X8_FIXTURE = json.dumps([{
    "method": "GET", "url": "http://exemple.test/app?a=1", "status": 200,
    "size": 512, "found_params": ["debug"], "injection_place": "Path"}]) + "\n"

# FIXTURE cmseek « CMS détecté » — structure MESURÉE (lignes [*] du journal,
# ANSI inclus comme l'outil les imprime) ; valeurs SYNTHÉTIQUES. ÉTIQUETÉ.
CMSEEK_FIXTURE = (
    "\x1b[H\x1b[2J\x1b[3J"
    "[i] Scanning Site: http://exemple.test\n"
    "\x1b[1m\x1b[32m[*] \x1b[0mCMS Detected, CMS ID: \x1b[1m\x1b[32mwordpress\x1b[0m, "
    "Detection method: \x1b[1m\x1b[94mgenerator_meta\x1b[0m\n"
)


def main() -> int:
    # ─────────────────────────────────────── 1. épingles & chargement des plugins
    import outils
    reg_tools = outils.registre()
    for tid, version in (("kr", "1.0.2"), ("gospider", "1.1.6"), ("dirhunt", "1.0.0"),
                         ("x8", "4.3.0"), ("cmseek", "1.1.3")):
        t = reg_tools.get(tid)
        cas(f"épingle {tid} porte {version}", t is not None and t.version == version
            and t.role == "outil", f"lu : {t.version if t else 'ABSENT'}")
    # kr : clé = nom d'exécutable (convention testssl.sh) ; projet assetnote/kiterunner
    cas("épingle kr note le projet assetnote/kiterunner",
        "kiterunner" in (reg_tools.get("kr").note or ""), "")
    for tid, dist in (("kr", False), ("gospider", False), ("x8", False),
                      ("cmseek", False), ("dirhunt", True)):
        t = reg_tools.get(tid)
        if t is None:
            cas(f"épingle {tid} : empreinte réelle", False, "absent")
            continue
        if dist:
            cas(f"épingle {tid} (pip) : distribution_hash réelle (pas un placeholder)",
                len(t.distribution_hash) == 64 and set(t.distribution_hash) != {"0"},
                t.distribution_hash[:16])
        cas(f"épingle {tid} : sha256 réelle (pas un placeholder)",
            len(t.sha256) == 64 and set(t.sha256) != {"0"}, t.sha256[:16])

    # wpscan : REMPLACEMENT MESURÉ (jamais d'empreinte inventée)
    w = reg_tools.get("wpscan")
    cas("wpscan : épingle toujours placeholder (installation Ruby impossible, mesurée — "
        "jamais d'empreinte inventée)",
        w is not None and set(w.sha256) == {"0"}
        and "ruby-dev" in (w.note or "") and "cmseek" in (w.note or ""),
        (w.note or "")[:60] if w else "absent")

    import parsers
    echecs = parsers.echecs_import()
    cas("aucun parser en échec d'import", not echecs, json.dumps(echecs))
    for nom in ("kiterunner", "x8", "cmseek"):
        cas(f"parser {nom} enregistré", parsers.obtenir(nom) is not None)

    from registre import Registry
    reg_ok = True
    try:
        reg = Registry()
    except Exception as e:                                 # noqa: BLE001
        reg, reg_ok = None, None                           # type: ignore
        cas("registre lisible ici", None, f"NON ÉVALUÉ : {type(e).__name__}: {e}")

    priorites: list[int] = []
    if reg_ok:
        for pid in ("kiterunner", "gospider", "dirhunt", "x8", "cmseek"):
            prov = reg.provider(pid)
            cas(f"provider {pid} chargé, cibles ['url']",
                prov is not None and list(prov.manifest.cibles) == ["url"],
                f"cibles={list(prov.manifest.cibles) if prov else 'ABSENT'}")
            if prov is not None:
                priorites.append(prov.priorite)
        cas("priorités G5 distinctes et dans [120, 160]",
            len(priorites) == len(set(priorites))
            and all(120 <= p <= 160 for p in priorites),
            f"priorités={sorted(priorites)}")

        # ─────────────────────────────── 2. planification : l'argv se résout
        import fournisseurs_web as FW
        attendus_argv = {
            "kiterunner": ("dossiers-mini.txt", "{URL} nu, wordlist épinglée"),
            "gospider": ("--json", "{URL} nu, crawl JSONL sur stdout"),
            "dirhunt": ("--to-file", "{URL} nu, rapport JSON au fichier"),
            "x8": ("parametres-mini.txt", "{URL}/search?q=, wordlist épinglée"),
            "cmseek": ("--batch", "{URL} nu, non interactif"),
        }
        for pid, (fragment, _) in attendus_argv.items():
            try:
                plan = FW.planifier(pid, URL_CIBLE, "/tmp/agnt-g5-test", egress=True,
                                    registre=reg, regles=str(REGLES))
                argv_str = json.dumps(plan["argv"], ensure_ascii=False)
                cas(f"plan {pid} : argv résolu avec {fragment}",
                    URL_CIBLE in argv_str and fragment in argv_str
                    and "{URL}" not in argv_str and "{OUT}" not in argv_str
                    and "{REGLES}" not in argv_str
                    and plan["binaire_resolu"] is False,
                    argv_str[:110])
                cas(f"plan {pid} : code de succès déclaré",
                    plan["codes_succes"] == [0], str(plan["codes_succes"]))
            except Exception as e:                         # noqa: BLE001
                cas(f"plan {pid}", False, f"{type(e).__name__}: {e}")
            try:
                FW.planifier(pid, URL_CIBLE, "/tmp/agnt-g5-test", egress=False,
                             registre=reg, regles=str(REGLES))
                cas(f"plan {pid} sans egress → refus nommé", False, "accepté")
            except FW.ErreurPlanification as e:
                cas(f"plan {pid} sans egress → refus nommé", "egress" in str(e), str(e)[:90])

    # ─────────────────── 3. interprétation des sorties RÉELLES archivées (sans réseau)
    if reg_ok:
        import fournisseurs_web as FW

        def _urls(r) -> set:
            return {str(fd.location.get("url") or "") for fd in r["findings"]}

        # — kiterunner : les chemins NON LIÉS /.env (T-ENV-001) et /admin
        #   (T-ADMIN-001), URL complète reconstruite par le parser, code 0
        brut = _lire("kiterunner", "kiterunner.jsonl")
        r = FW.interpreter("kiterunner", 0, brut, registre=reg)
        cas("kiterunner : 2 items lus du JSONL archivé (1 par réponse), code 0 → non-échec",
            len(r["items"]) == 2 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        cas("kiterunner : /.env (T-ENV-001) et /admin (T-ADMIN-001) découverts",
            _urls(r) == {URL_CIBLE + "/.env", URL_CIBLE + "/admin"},
            f"urls={sorted(_urls(r))}")
        if r["items"]:
            item = r["items"][0]
            cas("kiterunner : méthode GET, code 200, taille de réponse portée",
                item.get("regle") == "GET" and item.get("nom_regle") == "200"
                and "octets" in str(item.get("message")),
                json.dumps({k: item.get(k) for k in ("regle", "nom_regle", "message")},
                           ensure_ascii=False))
        if r["findings"]:
            cas("kiterunner : sévérité non déclarée par l'outil → UNKNOWN (jamais inventée)",
                {f.severity.get("value") for f in r["findings"]} == {"UNKNOWN"}, "")
        r = FW.interpreter("kiterunner", 3, brut, registre=reg)
        cas("kiterunner : code 3 hors succès [0] → échec nommé",
            r["echec"] is True and "code 3" in r["motif"], r["motif"])

        # — gospider : les chemins LIÉS (3 liens + graine), code 0
        brut = _lire("gospider", "gospider.jsonl")
        r = FW.interpreter("gospider", 0, brut, registre=reg)
        cas("gospider : 6 items lus du JSONL archivé (graine + 2×(form,url) + lien non "
            "récupéré), code 0 → non-échec",
            len(r["items"]) == 6 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        cas("gospider : les 3 liens LIÉS retrouvés (T-XSS-001, T-SQLI-001, "
            "T-TRAVERSAL-001) + graine",
            _urls(r) == {URL_CIBLE,
                         URL_CIBLE + "/search?q=THAUMAS",
                         URL_CIBLE + "/users?id=1",
                         URL_CIBLE + "/download?file=notes.txt"},
            f"urls={sorted(_urls(r))}")
        if r["items"]:
            forms = [i for i in r["items"] if i.get("type") == "form"]
            cas("gospider : statut 0 = URL extraite SANS être récupérée (jamais un code d'erreur)",
                len(forms) == 3 and all(str(i.get("status")) == "0" for i in forms),
                f"form={len(forms)}")
        r = FW.interpreter("gospider", 2, brut, registre=reg)
        cas("gospider : code 2 hors succès [0] → échec nommé",
            r["echec"] is True and "code 2" in r["motif"], r["motif"])

        # — dirhunt : rapport JSON (réponses < 300), normalisation sans query NOMMÉE
        brut = _lire("dirhunt", "dirhunt.json")
        r = FW.interpreter("dirhunt", 0, brut, registre=reg)
        cas("dirhunt : 2 items lus du rapport archivé (réponses < 300 seulement), code 0 → non-échec",
            len(r["items"]) == 2 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        cas("dirhunt : graine rendue (address sans slash + version slashée)",
            _urls(r) == {URL_CIBLE, URL_CIBLE + "/"},
            f"urls={sorted(_urls(r))}")
        cas("dirhunt : /users et /download ABSENTS du rapport (500/404 <300 seulement — "
            "limite de l'outil, jamais une preuve d'absence)",
            not any("/users" in u or "/download" in u for u in _urls(r)),
            f"urls={sorted(_urls(r))}")
        r = FW.interpreter("dirhunt", 2, brut, registre=reg)
        cas("dirhunt : code 2 hors succès [0] → échec nommé",
            r["echec"] is True and "code 2" in r["motif"], r["motif"])

        # — x8 : vide HONNÊTE motivé (aucun paramètre CACHÉ sur /search), code 0
        r = FW.interpreter("x8", 0, _lire("x8", "x8.custom"), registre=reg)
        cas("x8 : found_params [] → 0 item, code 0 → résultat vide NOMMÉ (pas un échec)",
            r["items"] == [] and r["echec"] is False
            and "aucun_item_lisible" in r["motif"],
            f"items={len(r['items'])} echec={r['echec']} motif={r['motif']!r}")
        r = FW.interpreter("x8", 0, X8_FIXTURE, registre=reg)
        cas("x8 fixture (étiqueté) : UN item par paramètre caché trouvé — jamais un item vide",
            len(r["items"]) == 1 and r["items"][0].get("nom_regle") == "debug"
            and r["items"][0].get("url") == "http://exemple.test/app?a=1",
            json.dumps(r["items"], ensure_ascii=False)[:120])
        r = FW.interpreter("x8", 1, _lire("x8", "x8.custom"), registre=reg)
        cas("x8 : code 1 (usage erroné, mesuré sur -t invalide) hors succès [0] → échec nommé",
            r["echec"] is True and "code 1" in r["motif"], r["motif"])

        # — cmseek : vide HONNÊTE motivé (pas de CMS sur la cible), code 0
        r = FW.interpreter("cmseek", 0, _lire("cmseek", "cmseek.txt"), registre=reg)
        cas("cmseek : « CMS Detection failed » → 0 item, code 0 → résultat vide NOMMÉ "
            "(THAUMAS n'est pas un CMS, attendu)",
            r["items"] == [] and r["echec"] is False
            and "aucun_item_lisible" in r["motif"],
            f"items={len(r['items'])} echec={r['echec']} motif={r['motif']!r}")
        r = FW.interpreter("cmseek", 0, CMSEEK_FIXTURE, registre=reg)
        cas("cmseek fixture (étiqueté) : CMS détecté → 1 item, ID/porteur/méthode de "
            "l'outil, ANSI retirés, PAS de sévérité",
            len(r["items"]) == 1 and r["items"][0].get("nom_regle") == "wordpress"
            and "generator_meta" in str(r["items"][0].get("message"))
            and r["items"][0].get("url") == "http://exemple.test"
            and "severite" not in r["items"][0],
            json.dumps(r["items"], ensure_ascii=False)[:140])
        r = FW.interpreter("cmseek", 3, _lire("cmseek", "cmseek.txt"), registre=reg)
        cas("cmseek : code 3 hors succès [0] → échec nommé",
            r["echec"] is True and "code 3" in r["motif"], r["motif"])

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
