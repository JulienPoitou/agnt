#!/usr/bin/env python3
"""Batterie des plugins G2 (vague-web/g2) — katana, gobuster, feroxbuster,
dirsearch, hakrawler sur WEB_ENDPOINT_DISCOVERY_ACTIVE.

AUTONOME ET SANS RÉSEAU : le registre est chargé depuis le dépôt, les plans sont
résolus en mémoire, et l'interprétation rejoue les sorties RÉELLES conservées
dans cible_web/qualif/<outil>/ (exécutions du 2026-09-05 contre THAUMAS-WEB —
voir les <outil>.meta.yaml). Rien ne sort sur le réseau : l'épreuve rejoue des
octets déjà mesurés.

Ce que la batterie prouve, par outil :
    1. le plugin se CHARGE au registre (épingle, licence, version, cibles) ;
    2. `fournisseurs_web.planifier` résout un argv complet ({REGLES} monté pour
       les fuzzers, {OUT} nommé, URL dans l'argv) ;
    3. l'interpréteur du cœur retrouve les items dans la sortie sauvegardée et
       les convertit en findings normalisés (location.url portée — coordonnée
       lue par l'oracle) ;
    4. les attendus de l'épreuve sont COINCIDENTS (ni plus ni moins, à
       l'exclusion des comportements documentés) ;
    5. la sévérité n'est déclarée par AUCUN de ces outils : absente du manifest,
       jamais inventée.

Usage : python PHASE3/test_plugins_g2.py   → exit 0 (vert) / 1 (rouge)
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

OUTILS = ("katana", "gobuster", "feroxbuster", "dirsearch", "hakrawler")

# Sortie sauvegardée par outil + attendus de l'épreuve (qualif/<outil>/attendus.yaml).
SORTIES = {
    "katana": ("katana.jsonl", [
        "http://127.0.0.1:8807",
        "http://127.0.0.1:8807/search?q=THAUMAS",
        "http://127.0.0.1:8807/users?id=1",
        "http://127.0.0.1:8807/download?file=notes.txt",
    ]),
    "gobuster": ("gobuster.custom", [
        "http://127.0.0.1:8807/.env",
        "http://127.0.0.1:8807/admin",
    ]),
    "feroxbuster": ("feroxbuster.custom", [
        "http://127.0.0.1:8807/.env",
        "http://127.0.0.1:8807/admin",
        "http://127.0.0.1:8807/search",
        "http://127.0.0.1:8807/users",
        "http://127.0.0.1:8807/download",
        "http://127.0.0.1:8807/",
    ]),
    "dirsearch": ("dirsearch.json", [
        "http://127.0.0.1:8807/admin",
        "http://127.0.0.1:8807/.env",
    ]),
    "hakrawler": ("hakrawler.jsonl", [
        "http://127.0.0.1:8807/search?q=THAUMAS",
        "http://127.0.0.1:8807/users?id=1",
        "http://127.0.0.1:8807/download?file=notes.txt",
    ]),
}
# Fuzzers : la wordlist épinglée DOIT apparaître dans l'argv, montée à {REGLES}.
FUZZERS = ("gobuster", "feroxbuster", "dirsearch")
WORDLIST = "dossiers-mini.txt"

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
        cas("registre lisible (plugins G2 compris)", True)
    except Exception as e:                                    # noqa: BLE001
        cas("registre lisible (plugins G2 compris)", False, f"{type(e).__name__}: {e}")
        return _sortie()

    charges = set(reg.plugins["fichiers"])
    for outil in OUTILS:
        cas(f"{outil} : plugin chargé", f"{outil}.yaml" in charges, sorted(charges))

    # Chargement des parsers nommés (gobuster, feroxbuster) — un module cassé est
    # consigné, pas un échec silencieux.
    import parsers
    echecs_parsers = parsers.echecs_import()
    cas("parsers G2 importables sans erreur", not echecs_parsers, str(echecs_parsers))
    cas("parser gobuster enregistré", parsers.obtenir("gobuster") is not None)
    cas("parser feroxbuster enregistré", parsers.obtenir("feroxbuster") is not None)

    # ------------------------------------------------------------- pings de base
    epingles = OUT.registre()
    for outil in OUTILS:
        tool_id = outil if outil != "hakrawler" else "hakrawler_scan"
        try:
            t = epingles[tool_id]
            cas(f"{outil} : épingle {tool_id!r} présente (version {t.version}, "
                f"licence {t.licence})", True)
        except KeyError:
            cas(f"{outil} : épingle {tool_id!r} présente", False, "absente du manifeste")

    # wordlist épinglée : empreinte du manifeste == celle du fichier du dépôt.
    # Dans la section `regles:`, l'entrée est la chaîne d'empreinte elle-même
    # (convention du manifeste : `dossiers-mini.txt: "59a2d4c9…"`) — pas un dict.
    manifeste = yaml.safe_load((RACINE / "manifeste_dependances.yaml")
                               .read_text(encoding="utf-8")) or {}
    epinglee = (manifeste.get("regles") or {}).get(WORDLIST)
    reel = hashlib.sha256((REGLES / WORDLIST).read_bytes()).hexdigest()
    cas(f"wordlist {WORDLIST} : empreinte manifeste == fichier dépôt",
        epinglee == reel, f"manifeste={epinglee} fichier={reel}")

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
            cas(f"{outil} : risque ACTIVE déclaré", prov.risque == "ACTIVE", prov.risque)
            cas(f"{outil} : aucun champ severite projeté (absente, jamais inventée)",
                "severite" not in (mani.extraction.champs or {}),
                str(sorted(mani.extraction.champs or {})))
            priorites[outil] = int(prov.priorite)

            # 1. plan — argv résolu, {REGLES} pour les fuzzers, URL présente
            plan = FW.planifier(outil, CIBLE, "/tmp/agnt-g2-test",
                                egress=True, registre=reg, regles=str(REGLES))
            argv = plan["argv"]
            cas(f"{outil} : argv résolu non vide", bool(argv), json.dumps(argv)[:120])
            cas(f"{outil} : URL cible dans l'argv", CIBLE in argv)
            cas(f"{outil} : timeout déclaré", plan["timeout_s"] >= 300,
                str(plan["timeout_s"]))
            if outil in FUZZERS:
                cas(f"{outil} : wordlist épinglée montée à {{REGLES}}",
                    f"{REGLES}/{WORDLIST}" in argv, json.dumps(argv))
            # sans egress → refus nommé (outil réseau)
            try:
                FW.planifier(outil, CIBLE, "/tmp/agnt-g2-test",
                             egress=False, registre=reg, regles=str(REGLES))
                cas(f"{outil} : sans egress → refus nommé", False, "accepté")
            except FW.ErreurPlanification as e:
                cas(f"{outil} : sans egress → refus nommé", "egress" in str(e),
                    str(e)[:100])

            # 2. rejeu de la sortie réelle sauvegardée
            nom_fichier, attendus_urls = SORTIES[outil]
            fichier = QUALIF / outil / nom_fichier
            cas(f"{outil} : sortie brute de qualification présente", fichier.exists(),
                str(fichier))
            if not fichier.exists():
                continue
            texte = fichier.read_text(encoding="utf-8")
            meta_texte = (QUALIF / outil / f"{outil}.meta.yaml")
            cas(f"{outil} : meta de qualification présente", meta_texte.exists(),
                str(meta_texte))
            r = FW.interpreter(outil, 0, texte, registre=reg)
            cas(f"{outil} : rejeu sans échec", r["echec"] is False, r["motif"])
            cas(f"{outil} : items retrouvés ({len(r['items'])})",
                len(r["items"]) == len(attendus_urls),
                f"{len(r['items'])} items / {len(attendus_urls)} attendus")
            cas(f"{outil} : findings normalisés ({len(r['findings'])})",
                len(r["findings"]) == len(attendus_urls),
                f"{len(r['findings'])} findings / {len(attendus_urls)} attendus")
            urls_vues = set()
            # source.tool = le BINAIRE exécuté (convention du cœur) : pour
            # hakrawler c'est le WRAPPER hakrawler_scan, comme au registre.
            tool_attendu = prov.manifest.binaire
            for f in r["findings"]:
                d = f.to_dict()
                urls_vues.add(str(d.get("location", {}).get("url") or ""))
                # chaque finding porte l'outil d'origine (convergence inter-outils)
                if d.get("source", {}).get("tool") != tool_attendu:
                    cas(f"{outil} : source.tool == {tool_attendu}", False,
                        str(d.get("source", {}).get("tool")))
            manquants = [u for u in attendus_urls if u not in urls_vues]
            cas(f"{outil} : attendus COINCIDENTS (location.url)", not manquants,
                f"manquants : {manquants} · vus : {sorted(urls_vues)}")
            # code hors succès → échec NOMMÉ (jamais un scan propre)
            r2 = FW.interpreter(outil, 2, texte, registre=reg)
            cas(f"{outil} : code 2 hors succès → échec nommé",
                r2["echec"] is True and "code 2" in r2["motif"], r2["motif"])
        except Exception as e:                                # noqa: BLE001
            cas(f"{outil} : batterie", False, f"{type(e).__name__}: {e}")

    # priorités DISTINCTES, dans la plage attendue, sans collision avec ffuf (120)
    if priorites:
        cas("priorités distinctes 120-160 (ffuf=120 au cœur)",
            len(set(priorites.values())) == len(priorites)
            and all(120 <= p <= 160 for p in priorites.values())
            and all(p != 120 for p in priorites.values()),
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
