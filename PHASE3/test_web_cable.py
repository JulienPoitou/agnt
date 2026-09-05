#!/usr/bin/env python3
"""Batterie machine de référence — câblage RÉEL de l'engagement web (hors CI).

Ce que cette batterie prouve, par HTTP, avec un VRAI httpx et la VRAIE cible :
    CÂBLÉ   POST /api/engagements/web executer:true → 202 en_file → termine ;
            rapport_web scellé sur disque ; finding httpx OBSERVED portant le
            statut 200, le titre et la bannière de THAUMAS-WEB — la tranche
            ①-b/httpx du câble chat→moteur.
    HONNÊTE preuve vérifiable (`preuve.verifier`), sorties brutes conservées
            (dossier d'archive), détails par provider lisibles.

Pré-requis (machine de référence, pas un runner CI — même statut que
test_slice/test_securite) :
    - httpx résolvable dans le PATH (cache bootstrap :
      `PATH="$HOME/.cache/arena_secops/bin:$PATH"`) ;
    - la cible THAUMAS-WEB est démarrée ICI sur un port éphémère : aucun réseau
      extérieur, rien ne quitte la machine.

Usage : PATH="$HOME/.cache/arena_secops/bin:$PATH" python PHASE3/test_web_cable.py
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))
sys.path.insert(0, str(RACINE / "interface"))

import api                                                    # noqa: E402
import preuve as PR                                           # noqa: E402

RESULTATS: list[tuple[str, bool | None, str]] = []


def verifie(nom: str, cond, detail: str = "") -> None:
    RESULTATS.append((nom, None if cond is None else bool(cond), detail))


def http(base: str, chemin: str, corps: dict | None = None):
    donnees = json.dumps(corps).encode() if corps is not None else None
    req = urllib.request.Request(base + chemin, data=donnees,
                                 method="POST" if donnees else "GET")
    if donnees:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            texte = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(texte) if "json" in (r.headers.get("Content-Type") or "") else texte)
    except urllib.error.HTTPError as e:
        texte = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(texte)
        except json.JSONDecodeError:
            return e.code, texte
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


class Silencieux(api.Gestionnaire):
    def log_message(self, *a):
        pass


def port_libre() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> int:
    if shutil.which("httpx") is None:
        print("httpx absent du PATH : batterie machine de référence, retirée — "
              "elle ne dit ni verte ni rouge, elle ne dit rien.")
        return 0

    # --- cible THAUMAS-WEB éphémère
    port_cible = port_libre()
    base_cible = f"http://127.0.0.1:{port_cible}"
    cible_proc = subprocess.Popen(
        [sys.executable, str(RACINE / "cible_web" / "serveur.py"), str(port_cible)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # --- API en processus + worker de file
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), Silencieux)
    base = f"http://127.0.0.1:{serveur.server_address[1]}"
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    threading.Thread(target=api._travail, daemon=True).start()
    try:
        vivant = False
        for _ in range(50):
            try:
                with urllib.request.urlopen(base_cible + "/", timeout=2) as r:
                    vivant = r.status == 200
                    break
            except Exception:
                time.sleep(0.2)
        verifie("cible THAUMAS-WEB éphémère vivante", vivant, base_cible)

        code, eng = http(base, "/api/engagements/web",
                         {"url": base_cible, "cible_autorisee": True,
                          "executer": True, "providers": ["httpx"], "egress": True})
        verifie("engagement exécutable → 202 + en_file + execution file",
                code == 202 and isinstance(eng, dict)
                and eng.get("statut") == "en_file" and eng.get("execution") == "file",
                f"code={code} corps={json.dumps(eng, ensure_ascii=False)[:200]}")
        eid = eng.get("id") if isinstance(eng, dict) else None
        if not eid:
            return _bilan()

        terminal, lu = None, None
        for _ in range(180):
            code, lu = http(base, f"/api/runs/{eid}")
            if isinstance(lu, dict) and lu.get("statut") in ("termine", "refuse", "erreur"):
                terminal = lu.get("statut")
                break
            time.sleep(0.5)
        verifie("run d'engagement terminé (httpx réel, ~0,5 s attendu)",
                terminal == "termine",
                f"terminal={terminal} dernier={json.dumps(lu, ensure_ascii=False)[:220]}")
        if not (isinstance(lu, dict) and lu.get("rapport")):
            return _bilan()

        rap = lu["rapport"]
        verifie("rapport_web : type + statut_run + chaîne terminee",
                rap.get("type") == "rapport_web" and rap.get("statut_run") == "termine"
                and rap.get("motif_run") == "",
                json.dumps(rap, ensure_ascii=False)[:220])
        details = rap.get("details") or []
        verifie("détail httpx : tâche terminée, ≥ 1 finding interprété",
                any(d.get("provider") == "httpx" and d.get("etat") == "terminee"
                    and d.get("findings", 0) >= 1 for d in details),
                json.dumps(details, ensure_ascii=False)[:200])
        verifie("httpx a tourné SOUS CAGE (bwrap au runtime, détail porte le drapeau)",
                all(d.get("cage") is True for d in details),
                json.dumps(details, ensure_ascii=False)[:200])

        findings = rap.get("findings") or []
        f0 = findings[0] if findings else None
        if f0 is None:
            verifie("au moins un finding (cage)", False,
                    "findings vides — détails : "
                    + json.dumps(rap.get("details"), ensure_ascii=False)[:300])
            return _bilan()
        brut = json.dumps(f0, ensure_ascii=False)
        verifie("finding httpx VÉRIFIÉ par l'oracle : rejeu réel confirmé + témoin respecté",
                bool(f0) and (f0.get("cycle") or {}).get("etat") == "verified"
                and ((f0.get("verification") or {}).get("jugement") or {}).get("verdict") == "confirmed"
                and ((f0.get("verification") or {}).get("jugement") or {}).get("temoin_respecte") is True,
                brut[:260])
        verifie("cycle de vie complet : observer → candidater → verifier_ok",
                [h.get("evenement") for h in ((f0.get("cycle") or {}).get("historique") or [])]
                == ["observer", "candidater", "verifier_ok"],
                json.dumps((f0.get("cycle") or {}).get("historique"), ensure_ascii=False)[:220])
        verifie("recette = statut DÉCLARÉ (httpx → 200), rejeu 3/3 en normal",
                (f0.get("verification") or {}).get("recette") == "statut_declare"
                and ((f0.get("verification") or {}).get("jugement") or {}).get("replay") == "3/3",
                json.dumps(f0.get("verification"), ensure_ascii=False)[:240])
        verifie("seconde recette ARMÉE : le titre déclaré par le manifest doit être "
                "dans le corps (leçon XBOW — preuve mesurée, jamais auto-évaluation)",
                "THAUMAS" in str((f0.get("evidence") or {}).get("extrait_attendu") or "")
                and str((f0.get("verification") or {}).get("extrait_attendu") or "") != ""
                and all(o.get("extrait") is True for o in (f0.get("verification") or {}).get("observations") or []),
                json.dumps(f0.get("verification"), ensure_ascii=False)[:280])
        verifie("finding porte la sonde réelle (statut 200, titre, bannière)",
                "200" in brut and "THAUMAS" in brut and "Python" in brut,
                brut[:220])
        verifie("rapport porte les comptes de vérification (rejeu_reel, tout vérifié)",
                (rap.get("verifications") or {}).get("rejeu_reel") is True
                and (rap.get("verifications") or {}).get("verifies", 0) >= 1
                and (rap.get("verifications") or {}).get("non_verifiables") == 0
                and (rap.get("verifications") or {}).get("inconclusifs") == 0,
                json.dumps(rap.get("verifications"), ensure_ascii=False))

        preuve = rap.get("preuve")
        verifie("preuve scellée et vérifiable",
                isinstance(preuve, dict) and PR.verifier(preuve) == (True, "sceau_valide"),
                json.dumps(preuve, ensure_ascii=False)[:200] if preuve else "absente")

        dossier = Path(lu.get("sortie") or "")
        verifie("archive disque : rapport_web.json + sortie brute httpx.jsonl",
                (dossier / "rapport_web.json").is_file()
                and (dossier / "httpx.jsonl").is_file()
                and (dossier / "journal.jsonl").is_file(),
                f"dossier={dossier} contenu={sorted(p.name for p in dossier.iterdir()) if dossier.is_dir() else 'ABSENT'}")
    finally:
        serveur.shutdown()
        cible_proc.terminate()

    return _bilan()


def _bilan() -> int:
    ok = sum(1 for _, c, _ in RESULTATS if c is True)
    ko = [n for n, c, _ in RESULTATS if c is False]
    print(f"\n{'=' * 50}\n  {ok}/{len(RESULTATS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in RESULTATS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ko else 0


if __name__ == "__main__":
    sys.exit(main())
