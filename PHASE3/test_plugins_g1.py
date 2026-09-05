#!/usr/bin/env python3
"""Batterie des plugins G1 (vague-web/g1) — whatweb, webanalyze, wafw00f, nikto.

Surface et détection web de base : trois sondes WEB_HTTP_PROBE (whatweb 126,
webanalyze 127, wafw00f 128) et un détecteur actif WEB_VULN_SCAN_ACTIVE
(nikto 140, via le wrapper nikto_scan). Le cinquième outil du groupe,
gowitness, est REFUSÉ (qualif/gowitness/REFUS.md) — la batterie vérifie aussi
cet état : PAS de provider, PAS de plugin, PAS d'épingle.

AUTONOME ET SANS RÉSEAU : le registre est chargé depuis le dépôt, les plans
sont résolus en mémoire, et l'interprétation rejoue les sorties RÉELLES
conservées dans cible_web/qualif/<outil>/ (exécutions du 2026-09-05 contre
THAUMAS-WEB — voir les <outil>.meta.yaml). Rien ne sort sur le réseau :
l'épreuve rejoue des octets déjà mesurés.

Ce que la batterie prouve, par outil :
    1. le plugin se CHARGE au registre (épingle, licence, version, cibles) ;
    2. `fournisseurs_web.planifier` résout un argv complet ({REGLES} monté pour
       webanalyze — sa base technologies.json est une donnée épinglée, {OUT}
       nommé, URL dans l'argv) ;
    3. l'interpréteur du cœur retrouve les items dans la sortie sauvegardée et
       les convertit en findings normalisés (location.url portée — coordonnée
       lue par l'oracle ; pour webanalyze, l'URL vient de la RACINE du rapport
       et est recopiée par le contexte déclaré : sans elle, constat muet) ;
    4. les attendus de l'épreuve sont COINCIDENTS (ni plus ni moins, à
       l'exclusion des comportements documentés) ;
    5. la sévérité n'est déclarée par AUCUN de ces outils : absente du manifest,
       jamais inventée.

Usage : python PHASE3/test_plugins_g1.py   → exit 0 (vert) / 1 (rouge)
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import yaml

import fournisseurs_web as FW                                      # noqa: E402
import outils as OUT                                               # noqa: E402

QUALIF = RACINE / "cible_web" / "qualif"
REGLES = RACINE / "regles_web"
CIBLE = "http://127.0.0.1:8807"

OUTILS = ("whatweb", "webanalyze", "wafw00f", "nikto")

# Épingle manifeste par outil — nikto s'exécute par le WRAPPER nikto_scan
# (convention hakrawler_scan : XML::Writer fournie hors système, sitename injecté).
EPINGLES = {"whatweb": "whatweb", "webanalyze": "webanalyze",
            "wafw00f": "wafw00f", "nikto": "nikto_scan"}

CAPACITES = {"whatweb": "WEB_HTTP_PROBE", "webanalyze": "WEB_HTTP_PROBE",
             "wafw00f": "WEB_HTTP_PROBE", "nikto": "WEB_VULN_SCAN_ACTIVE"}

# Sortie sauvegardée par outil + URL distinctes attendues dans les findings
# (le nombre d'ITEMS est vérifié séparément : nikto rend 11 constats sur 4 URL
# distinctes — huit sur la racine).
SORTIES = {
    "whatweb": ("whatweb.json", 1, [
        "http://127.0.0.1:8807",
    ]),
    "webanalyze": ("webanalyze.json", 1, [
        "http://127.0.0.1:8807",
    ]),
    "wafw00f": ("wafw00f.json", 1, [
        "http://127.0.0.1:8807",
    ]),
    "nikto": ("nikto.custom", 11, [
        "http://127.0.0.1:8807/",
        "http://127.0.0.1:8807/.env",
        "http://127.0.0.1:8807/.git/HEAD",
        "http://127.0.0.1:8807/.git/index",
    ]),
}
# webanalyze lit sa base de technologies MONTÉE à {REGLES} — donnée épinglée.
DONNEE_EPINGLEE = "technologies.json"

CAS: list[tuple[str, bool | None, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, None if cond is None else bool(cond), detail))
    if not cond and cond is not None:
        ECHECS.append(nom)


def main() -> int:
    # ------------------------------------------------------------- registre
    try:
        from registre import Registry
        reg = Registry()
        cas("registre lisible (plugins G1 compris)", True)
    except Exception as e:                                    # noqa: BLE001
        cas("registre lisible (plugins G1 compris)", False, f"{type(e).__name__}: {e}")
        return _sortie()

    charges = set(reg.plugins["fichiers"])
    for outil in OUTILS:
        cas(f"{outil} : plugin chargé", f"{outil}.yaml" in charges, sorted(charges))

    # Chargement des parsers (nikto) — un module cassé est consigné, pas un
    # échec silencieux.
    import parsers
    echecs_parsers = parsers.echecs_import()
    cas("parsers G1 importables sans erreur", not echecs_parsers, str(echecs_parsers))
    cas("parser nikto enregistré", parsers.obtenir("nikto") is not None)

    # ------------------------------------------------------------- pings de base
    epingles = OUT.registre()
    for outil in OUTILS:
        tool_id = EPINGLES[outil]
        try:
            t = epingles[tool_id]
            cas(f"{outil} : épingle {tool_id!r} présente (version {t.version}, "
                f"licence {t.licence})", True)
        except KeyError:
            cas(f"{outil} : épingle {tool_id!r} présente", False, "absente du manifeste")
    cas("épingle 'nikto' (dépôt perl) distincte du wrapper",
        "nikto" in epingles and "nikto_scan" in epingles, sorted(epingles)[:3])

    # Donnée épinglée : empreinte du manifeste == celle du fichier du dépôt.
    # Dans la section `regles:`, l'entrée est la chaîne d'empreinte elle-même
    # (convention du manifeste : `dossiers-mini.txt: "59a2d4c9…"`).
    manifeste = yaml.safe_load((RACINE / "manifeste_dependances.yaml")
                               .read_text(encoding="utf-8")) or {}
    epinglee = (manifeste.get("regles") or {}).get(DONNEE_EPINGLEE)
    reel = hashlib.sha256((REGLES / DONNEE_EPINGLEE).read_bytes()).hexdigest()
    cas(f"base {DONNEE_EPINGLEE} : empreinte manifeste == fichier dépôt",
        epinglee == reel, f"manifeste={epinglee} fichier={reel}")

    # --------------------------- REFUS gowitness : état VÉRIFIÉ, pas supposé
    # Le cinquième outil du groupe est refusé nommément (qualif/gowitness/REFUS.md,
    # motifs mesurés) : l'état attendu du registre est l'ABSENCE — pas de provider,
    # pas de plugin, pas d'épingle — et le dossier de refus est présent.
    try:
        reg.provider("gowitness")
        cas("gowitness : REFUSÉ → pas de provider au registre", False,
            "provider résolu (le refus n'est pas appliqué)")
    except Exception as e:                                # noqa: BLE001
        cas("gowitness : REFUSÉ → pas de provider au registre",
            "inconnu" in str(e), str(e)[:80])
    cas("gowitness : REFUSÉ → pas de plugin", "gowitness.yaml" not in charges,
        "plugins/gowitness.yaml existant")
    cas("gowitness : REFUSÉ → pas d'épingle", "gowitness" not in epingles,
        "épingle présente dans le manifeste")
    cas("gowitness : REFUSÉ → dossier de refus documenté",
        (QUALIF / "gowitness" / "REFUS.md").exists(),
        str(QUALIF / "gowitness" / "REFUS.md"))

    # ------------------------------------------------- par outil : plan + rejeu
    priorites: dict[str, int] = {}
    for outil in OUTILS:
        try:
            prov = reg.provider(outil)
            cas(f"{outil} : provider au registre", prov is not None)
            if prov is None:
                continue
            mani = prov.manifest
            cas(f"{outil} : cibles = url (exigence chaîne web)",
                "url" in tuple(mani.cibles), str(list(mani.cibles)))
            cas(f"{outil} : capacité déclarée {CAPACITES[outil]}",
                mani.capability == CAPACITES[outil], mani.capability)
            cas(f"{outil} : risque ACTIVE déclaré", prov.risque == "ACTIVE", prov.risque)
            cas(f"{outil} : aucun champ severite projeté (absente, jamais inventée)",
                "severite" not in (mani.extraction.champs or {}),
                str(sorted(mani.extraction.champs or {})))
            priorites[outil] = int(prov.priorite)

            # 1. plan — argv résolu, URL présente, {REGLES} pour la donnée épinglée
            plan = FW.planifier(outil, CIBLE, "/tmp/agnt-g1-test",
                                egress=True, registre=reg, regles=str(REGLES))
            argv = plan["argv"]
            cas(f"{outil} : argv résolu non vide", bool(argv), json.dumps(argv)[:120])
            cas(f"{outil} : URL cible dans l'argv", CIBLE in argv)
            cas(f"{outil} : timeout déclaré", plan["timeout_s"] >= 300,
                str(plan["timeout_s"]))
            if outil == "webanalyze":
                cas(f"{outil} : base technologies.json montée à {{REGLES}}",
                    f"{REGLES}/{DONNEE_EPINGLEE}" in argv, json.dumps(argv))
            # sans egress → refus nommé (outils réseau)
            try:
                FW.planifier(outil, CIBLE, "/tmp/agnt-g1-test",
                             egress=False, registre=reg, regles=str(REGLES))
                cas(f"{outil} : sans egress → refus nommé", False, "accepté")
            except FW.ErreurPlanification as e:
                cas(f"{outil} : sans egress → refus nommé", "egress" in str(e),
                    str(e)[:100])

            # 2. rejeu de la sortie réelle sauvegardée
            nom_fichier, n_items, attendus_urls = SORTIES[outil]
            fichier = QUALIF / outil / nom_fichier
            cas(f"{outil} : sortie brute de qualification présente", fichier.exists(),
                str(fichier))
            if not fichier.exists():
                continue
            texte = fichier.read_text(encoding="utf-8")
            meta_texte = (QUALIF / outil / f"{outil}.meta.yaml")
            cas(f"{outil} : meta de qualification présente", meta_texte.exists(),
                str(meta_texte))
            cas(f"{outil} : attendus d'épreuve présents",
                (QUALIF / outil / "attendus.yaml").exists(),
                str(QUALIF / outil / "attendus.yaml"))
            # Sortie ILLISIBLE = échec nommé, jamais un scan propre (leçon
            # whatweb : le journal est APPENDÉ par l'outil, un fichier sale se
            # voit ici immédiatement).
            if outil == "whatweb":
                try:
                    doc = json.loads(texte)
                    cas(f"{outil} : sortie JSON lisible (journal non appendé)",
                        isinstance(doc, list))
                except ValueError as e:
                    cas(f"{outil} : sortie JSON lisible (journal non appendé)",
                        False, f"JSON invalide : {e}")
            r = FW.interpreter(outil, 0, texte, registre=reg)
            cas(f"{outil} : rejeu sans échec", r["echec"] is False, r["motif"])
            cas(f"{outil} : items retrouvés ({len(r['items'])})",
                len(r["items"]) == n_items,
                f"{len(r['items'])} items / {n_items} attendus")
            cas(f"{outil} : findings normalisés ({len(r['findings'])})",
                len(r["findings"]) == n_items,
                f"{len(r['findings'])} findings / {n_items} attendus")
            urls_vues = set()
            # source.tool = le BINAIRE exécuté (convention du cœur) : pour
            # nikto c'est le WRAPPER nikto_scan, comme au registre.
            tool_attendu = prov.manifest.binaire
            severite_outil = set()
            for f in r["findings"]:
                d = f.to_dict()
                urls_vues.add(str(d.get("location", {}).get("url") or ""))
                if d.get("source", {}).get("tool") != tool_attendu:
                    cas(f"{outil} : source.tool == {tool_attendu}", False,
                        str(d.get("source", {}).get("tool")))
                severite_outil.add(str(d.get("severity", {}).get("value")))
                if str(d.get("severity", {}).get("value")) != "UNKNOWN":
                    cas(f"{outil} : sévérité absente (UNKNOWN)", False,
                        str(d.get("severity", {}).get("value")))
            cas(f"{outil} : sévérité UNKNOWN sur tous les constats (jamais inventée)",
                severite_outil <= {"UNKNOWN"}, str(severite_outil))
            manquants = [u for u in attendus_urls if u not in urls_vues]
            cas(f"{outil} : attendus COINCIDENTS (location.url)", not manquants,
                f"manquants : {manquants} · vus : {sorted(urls_vues)}")
            # code hors succès → échec NOMMÉ (jamais un scan propre)
            r2 = FW.interpreter(outil, 2, texte, registre=reg)
            cas(f"{outil} : code 2 hors succès → échec nommé",
                r2["echec"] is True and "code 2" in r2["motif"], r2["motif"])
        except Exception as e:                                # noqa: BLE001
            cas(f"{outil} : batterie", False, f"{type(e).__name__}: {e}")

    # ------------------------------------------------- mesures d'épreuve nommées
    # whatweb : la bannière T-SRV-001 est lue dans le chemin imbriqué déclaré
    # (plugins.HTTPServer.string[0]) — la preuve que le chemin pointé existe.
    try:
        texte = (QUALIF / "whatweb" / "whatweb.json").read_text(encoding="utf-8")
        r = FW.interpreter("whatweb", 0, texte, registre=reg)
        messages = [f.to_dict().get("evidence", {}).get("message") for f in r["findings"]]
        cas("whatweb : bannière T-SRV-001 lue (HTTPServer imbriqué)",
            any("THAUMAS-WEB/1.0" in str(m) for m in messages), str(messages))
    except Exception as e:                                    # noqa: BLE001
        cas("whatweb : bannière T-SRV-001 lue (HTTPServer imbriqué)", False,
            f"{type(e).__name__}: {e}")

    # webanalyze : l'URL vient de la RACINE du rapport (hostname) recopiée par
    # le contexte déclaré — sans lui, location.url est None (mesuré au rejeu) :
    # garde-fou de régression sur la COORDONNÉE, pas seulement sur le compte.
    try:
        texte = (QUALIF / "webanalyze" / "webanalyze.json").read_text(encoding="utf-8")
        r = FW.interpreter("webanalyze", 0, texte, registre=reg)
        d = r["findings"][0].to_dict() if r["findings"] else {}
        cas("webanalyze : location.url portée (contexte root→item)",
            d.get("location", {}).get("url") == CIBLE,
            str(d.get("location", {}).get("url")))
        cas("webanalyze : Python 3.12.3 nommé (T-SRV-001)",
            d.get("source", {}).get("original_rule_id") == "Python"
            and d.get("evidence", {}).get("message") == "3.12.3",
            json.dumps(d.get("source", {}), default=str)[:120])
    except Exception as e:                                    # noqa: BLE001
        cas("webanalyze : location.url portée (contexte root→item)", False,
            f"{type(e).__name__}: {e}")

    # wafw00f : la mesure est un booléen détecté=False (cible SANS WAF) —
    # une mesure, pas une vulnérabilité et pas une garantie d'absence.
    try:
        texte = (QUALIF / "wafw00f" / "wafw00f.json").read_text(encoding="utf-8")
        r = FW.interpreter("wafw00f", 0, texte, registre=reg)
        d = r["findings"][0].to_dict() if r["findings"] else {}
        msg = d.get("evidence", {}).get("message")
        cas("wafw00f : mesure detected=False (firewall 'None')",
            msg in (False, "False"), repr(msg))
    except Exception as e:                                    # noqa: BLE001
        cas("wafw00f : mesure detected=False (firewall 'None')", False,
            f"{type(e).__name__}: {e}")

    # nikto : les trois failles PLANTÉES de la cible sont retrouvées comme
    # MATCHES de la base nikto (T-ENV-001, T-GIT-001, T-GIT-002) + T-SRV-001.
    try:
        texte = (QUALIF / "nikto" / "nikto.custom").read_text(encoding="utf-8")
        r = FW.interpreter("nikto", 0, texte, registre=reg)
        url_regles: dict[str, set[str]] = {}
        for f in r["findings"]:
            d = f.to_dict()
            url = str(d.get("location", {}).get("url") or "")
            url_regles.setdefault(url, set()).add(
                str(d.get("source", {}).get("original_rule_id")))
        for url, id_attendu in (
            ("http://127.0.0.1:8807/.env", "007226"),          # T-ENV-001
            ("http://127.0.0.1:8807/.git/HEAD", "006609"),     # T-GIT-001
            ("http://127.0.0.1:8807/.git/index", "006530"),    # T-GIT-002
        ):
            cas(f"nikto : {url.split('8807')[1]} matché (id {id_attendu})",
                id_attendu in url_regles.get(url, set()),
                str(sorted(url_regles.get(url, set()))))
        cas("nikto : bannière obsolète (600652, T-SRV-001)",
            "600652" in url_regles.get("http://127.0.0.1:8807/", set()),
            str(sorted(url_regles.get("http://127.0.0.1:8807/", set()))))
        # XSS/SQLi/traversal NE sont PAS dans la base matchée : 11 constats
        # seulement, aucun sur /search, /users, /download — la détection
        # d'exploitabilité relève de sqlmap/dotdotpwn/nuclei.
        hors_portee = [u for u in url_regles
                       if "/search" in u or "/users" in u or "/download" in u]
        cas("nikto : pas de constat d'exploitation (XSS/SQLi/traversal hors base)",
            not hors_portee, str(hors_portee))
    except Exception as e:                                    # noqa: BLE001
        cas("nikto : failles plantées retrouvées", False, f"{type(e).__name__}: {e}")

    # priorités DISTINCTES, dans la plage des sondes de surface (120 < p < 150 ;
    # 120 = ffuf au cœur, 121 = katana, 130 = httpx/sqlmap — voisins des autres
    # vagues, jamais repris).
    if priorites:
        cas("priorités distinctes 120-150 (ffuf=120 au cœur)",
            len(set(priorites.values())) == len(priorites)
            and all(120 < p < 150 for p in priorites.values()),
            json.dumps(priorites))

    return _sortie()


def _sortie() -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
