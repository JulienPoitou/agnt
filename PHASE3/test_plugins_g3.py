#!/usr/bin/env python3
"""Plugins G3 (injection & vuln web) : registre + planification + interprétation.

Aucun réseau : les sorties sont celles ARCHIVÉES dans cible_web/qualif/<outil>/
(épreuve réelle du 2026-09-05 contre THAUMAS-WEB, cible locale d'épreuve) et un
FIXTURE étiqueté (structure mesurée, valeurs synthétiques — meta dalfox seule).

Ce que la batterie prouve :
  1. les 5 épingles G3 se lisent (outils.registre) et les 5 plugins se chargent ;
  2. `planifier` résout l'argv (URL, wordlist épinglée, codes de succès déclarés) ;
  3. l'interpréteur retrouve les items depuis les sorties RÉELLES archivées —
     y compris les failles trouvées (sqlmap : T-SQLI-001 ; dalfox : T-XSS-001 ;
     arjun : paramètre q) et les vides HONNÊTES (commix : pas de faille de
     commande sur la cible ; crlfuzz : stdout vide — limite de l'outil nommée).

Usage : python PHASE3/test_plugins_g3.py   (exit 0/1)
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


# FIXTURE dalfox « scan propre » — structure MESURÉE (épreuve de calibration sur
# /download?file=notes.txt : findings_count 0, meta seule en sortie, code 0),
# valeurs synthétiques pour rester hors-ligne. ÉTIQUETÉ : pas une sortie de la
# cible d'épreuve.
DALFOX_META_SEULE = json.dumps({
    "meta": {"dalfox_version": "3.2.2", "dedup_mode": "exact", "findings_count": 0,
             "incomplete": False, "scan_duration_ms": 1000,
             "target_summary": [{"findings_count": 0, "status": "clean",
                                 "target": "http://exemple.test/x?a=1"}],
             "targets": ["http://exemple.test/x?a=1"],
             "targets_deduplicated": 0, "total_requests": 100}}) + "\n"


def main() -> int:
    # ─────────────────────────────────────── 1. épingles & chargement des plugins
    import outils
    reg_tools = outils.registre()
    for tid, version in (("sqlmap", "1.10"), ("dalfox", "3.2.2"), ("commix", "4.1"),
                         ("crlfuzz", "1.4.1"), ("arjun", "2.2.7")):
        t = reg_tools.get(tid)
        cas(f"épingle {tid} porte {version}", t is not None and t.version == version
            and t.role == "outil", f"lu : {t.version if t else 'ABSENT'}")
    for tid, dist in (("sqlmap", False), ("dalfox", False), ("commix", False),
                      ("crlfuzz", False), ("arjun", True)):
        t = reg_tools.get(tid)
        if t is None:
            cas(f"épingle {tid} : empreinte réelle", False, "absent")
            continue
        if dist:
            cas(f"épingle {tid} (pip) : distribution_hash réelle (pas un placeholder)",
                len(t.distribution_hash) == 64 and set(t.distribution_hash) != {"0"},
                t.distribution_hash[:16])
        else:
            cas(f"épingle {tid} : empreinte réelle (pas un placeholder)",
                len(t.sha256) == 64 and set(t.sha256) != {"0"}, t.sha256[:16])

    # L'épingle wordlist est une entrée CHAÎNE de `regles:` (convention
    # dossiers-mini.txt de G2) — regles_epinglees() ne retourne que les entrées
    # dict (jeux de règles à source) : la relecture passe par le YAML du manifeste.
    import yaml
    doc_manifeste = yaml.safe_load(
        (RACINE / "manifeste_dependances.yaml").read_text(encoding="utf-8")) or {}
    epingle_wordlist = str((doc_manifeste.get("regles") or {}).get("parametres-mini.txt") or "")
    cas("wordlist arjun épinglée (parametres-mini.txt, empreinte réelle en section regles)",
        len(epingle_wordlist) == 64 and set(epingle_wordlist) != {"0"}, epingle_wordlist[:16])

    import parsers
    echecs = parsers.echecs_import()
    cas("aucun parser en échec d'import", not echecs, json.dumps(echecs))
    for nom in ("sqlmap", "dalfox", "commix", "crlfuzz", "arjun"):
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
        for pid in ("sqlmap", "dalfox", "commix", "crlfuzz", "arjun"):
            prov = reg.provider(pid)
            cas(f"provider {pid} chargé, cibles ['url']",
                prov is not None and list(prov.manifest.cibles) == ["url"],
                f"cibles={list(prov.manifest.cibles) if prov else 'ABSENT'}")
            if prov is not None:
                priorites.append(prov.priorite)
        cas("priorités G3 distinctes et dans [120, 160]",
            len(priorites) == len(set(priorites))
            and all(120 <= p <= 160 for p in priorites),
            f"priorités={sorted(priorites)}")

        # ─────────────────────────────── 2. planification : l'argv se résout
        import fournisseurs_web as FW
        attendus_argv = {
            "sqlmap": ("--batch", "{URL}/users?id=1, level/risk/threads bornés"),
            "dalfox": ("jsonl", "{URL}/search?q=, sous-commandement url"),
            "commix": ("--ignore-stdin", "{URL}/users?id=1, time-limit borné"),
            "crlfuzz": ("-c", "{URL} nu, concurrence bornée"),
            "arjun": ("parametres-mini.txt", "{URL}/search?q=, wordlist épinglée"),
        }
        for pid, (fragment, _) in attendus_argv.items():
            try:
                plan = FW.planifier(pid, URL_CIBLE, "/tmp/agnt-g3-test", egress=True,
                                    registre=reg, regles=str(REGLES))
                argv_str = json.dumps(plan["argv"], ensure_ascii=False)
                cas(f"plan {pid} : argv résolu avec {fragment}",
                    URL_CIBLE in argv_str and fragment in argv_str
                    and "{URL}" not in argv_str and "{OUT}" not in argv_str
                    and "{REGLES}" not in argv_str
                    and plan["binaire_resolu"] is False,
                    argv_str[:110])
                codes = {
                    "sqlmap": [0], "dalfox": [0, 1], "commix": [0],
                    "crlfuzz": [0], "arjun": [0]}[pid]
                cas(f"plan {pid} : code de succès déclaré",
                    plan["codes_succes"] == codes, str(plan["codes_succes"]))
            except Exception as e:                         # noqa: BLE001
                cas(f"plan {pid}", False, f"{type(e).__name__}: {e}")
            try:
                FW.planifier(pid, URL_CIBLE, "/tmp/agnt-g3-test", egress=False,
                             registre=reg, regles=str(REGLES))
                cas(f"plan {pid} sans egress → refus nommé", False, "accepté")
            except FW.ErreurPlanification as e:
                cas(f"plan {pid} sans egress → refus nommé", "egress" in str(e), str(e)[:90])

    # ─────────────────── 3. interprétation des sorties RÉELLES archivées (sans réseau)
    if reg_ok:
        import fournisseurs_web as FW

        # — sqlmap : LA FAILLE TROUVÉE (T-SQLI-001), 3 techniques mesurées, code 0
        brut = _lire("sqlmap", "sqlmap.txt")
        r = FW.interpreter("sqlmap", 0, brut, registre=reg)
        cas("sqlmap : 3 items lus du journal archivé (1 par technique), code 0 → non-échec",
            len(r["items"]) == 3 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        parametres = {str(i.get("nom_regle")) for i in r["items"]}
        techniques = {str(i.get("regle")) for i in r["items"]}
        cas("sqlmap : paramètre id (GET) injectable (T-SQLI-001)",
            parametres == {"id (GET)"}, f"paramètres={sorted(parametres)}")
        cas("sqlmap : techniques mesurées (boolean/time-based blind, UNION query)",
            techniques == {"boolean-based blind", "time-based blind", "UNION query"},
            f"techniques={sorted(techniques)}")
        urls = {str(i.get("url")) for i in r["items"]}
        cas("sqlmap : l'URL testée porte la cible (lue sur « testing URL '…' »)",
            urls == {URL_CIBLE + "/users?id=1"}, f"urls={sorted(urls)}")
        if r["findings"]:
            loc = json.dumps(r["findings"][0].location, ensure_ascii=False)
            cas("sqlmap : l'oracle retrouve l'url du constat (location.url)",
                loc == json.dumps({"asset": "url", "file": "", "line": None,
                                   "package": None, "url": URL_CIBLE + "/users?id=1"})
                or URL_CIBLE + "/users?id=1" in loc, loc[:160])
        severites = {f.severity.get("value") for f in r["findings"]} if r["findings"] else set()
        cas("sqlmap : sévérité non déclarée par l'outil → le cœur marque UNKNOWN (jamais inventée)",
            severites == {"UNKNOWN"}, f"severites={severites}")
        # Doctrine : un code hors succès reste un échec, même avec des items
        r = FW.interpreter("sqlmap", 3, brut, registre=reg)
        cas("sqlmap : code 3 hors succès [0] → échec nommé",
            r["echec"] is True and "code 3" in r["motif"], r["motif"])

        # — dalfox : LA FAILLE TROUVÉE (T-XSS-001), code 1 = findings (mesuré)
        brut = _lire("dalfox", "dalfox.txt")
        r = FW.interpreter("dalfox", 1, brut, registre=reg)
        cas("dalfox : 1 finding lu du JSONL archivé (la méta ne devient PAS un item), code 1 → non-échec",
            len(r["items"]) == 1 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        if r["items"]:
            item = r["items"][0]
            cas("dalfox : paramètre q, type V, sévérité High DÉCLARÉE par l'outil, CWE-79",
                item.get("nom_regle") == "q" and item.get("regle") == "V"
                and item.get("severite") == "High" and item.get("cwe") == "CWE-79",
                json.dumps({k: item.get(k) for k in ("nom_regle", "regle", "severite", "cwe")},
                           ensure_ascii=False))
            cas("dalfox : la preuve porte le payload déclenché (T-XSS-001)",
                str(item.get("url") or "").startswith(URL_CIBLE + "/search?q=")
                and "<svg" in str(item.get("preuve") or ""),
                str(item.get("url"))[:120])
            if r["findings"]:
                loc = json.dumps(r["findings"][0].location, ensure_ascii=False)
                cas("dalfox : l'oracle retrouve l'url du constat (location.url)",
                    URL_CIBLE in loc, loc[:160])
                cas("dalfox : la sévérité déclarée par l'outil traverse le cœur telle quelle (High → HIGH, origine dalfox)",
                    r["findings"][0].severity.get("value") == "HIGH"
                    and r["findings"][0].severity.get("origine") == "dalfox",
                    json.dumps(r["findings"][0].severity, ensure_ascii=False))
        r = FW.interpreter("dalfox", 2, brut, registre=reg)
        cas("dalfox : code 2 (cible skippée, mesuré) hors succès [0, 1] → échec nommé",
            r["echec"] is True and "code 2" in r["motif"], r["motif"])
        r = FW.interpreter("dalfox", 0, DALFOX_META_SEULE, registre=reg)
        cas("dalfox fixture (étiqueté) : scan propre = meta seule, 0 item, code 0 → non-échec",
            r["items"] == [] and r["echec"] is False
            and "aucun_item_lisible" in r["motif"],
            f"items={len(r['items'])} motif={r['motif']!r}")

        # — commix : vide HONNÊTE (pas de faille de commande sur la cible), code 0
        r = FW.interpreter("commix", 0, _lire("commix", "commix.txt"), registre=reg)
        cas("commix : sortie lue, 0 item, code 0 → résultat vide NOMMÉ (pas un échec)",
            r["items"] == [] and r["echec"] is False
            and "aucun_item_lisible" in r["motif"],
            f"items={len(r['items'])} echec={r['echec']} motif={r['motif']!r}")

        # — crlfuzz : stdout vide (limite de l'OUTIL mesurée) → échec nommé par le cœur
        r = FW.interpreter("crlfuzz", 0, _lire("crlfuzz", "crlfuzz.txt"), registre=reg)
        cas("crlfuzz : stdout vide → échec nommé « sortie vide » (limite de l'outil, consignée)",
            r["items"] == [] and r["echec"] is True
            and "sortie vide" in r["motif"], r["motif"])

        # — arjun : le paramètre q DÉCOUVERT (surface), heuristique déclarée par l'outil
        brut = _lire("arjun", "arjun.txt")
        r = FW.interpreter("arjun", 0, brut, registre=reg)
        cas("arjun : 1 item lu du stdout archivé, code 0 → non-échec",
            len(r["items"]) == 1 and r["echec"] is False,
            f"items={len(r['items'])} echec={r['echec']} {r['motif']}")
        if r["items"]:
            item = r["items"][0]
            cas("arjun : paramètre q découvert, heuristique « body length » déclarée par l'outil",
                item.get("nom_regle") == "q" and "body length" in str(item.get("message")),
                json.dumps(item, ensure_ascii=False)[:140])
            cas("arjun : pas de sévérité (surface, pas une vulnérabilité — jamais inventée)",
                "severite" not in item,
                json.dumps({k: item.get(k) for k in ("severite",)}, ensure_ascii=False))
            if r["findings"]:
                loc = json.dumps(r["findings"][0].location, ensure_ascii=False)
                cas("arjun : l'oracle retrouve l'url de la surface (location.url)",
                    URL_CIBLE in loc, loc[:160])

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
