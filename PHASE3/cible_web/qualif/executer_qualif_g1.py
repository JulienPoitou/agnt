#!/usr/bin/env python3
"""Exécution réelle des outils G1 contre THAUMAS-WEB (qualif, 2026-09-05).

Un seul run par outil, timeout borné, rates modestes. Les argv sont CEUX RENDUS
par fournisseurs_web.planifier (validation registre faite avant, voir
valider_registre_g1.py) ; {BIN} est résolu par le PATH préfixé du staging.
Sortie brute, stdout, stderr conservés dans qualif/<outil>/ — la batterie
rejouera ces fichiers SANS réseau.

Cas particulier webanalyze : l'outil n'a PAS de drapeau -o (mesuré) — sa sortie
json va sur stdout ; le harnais sauvegarde le stdout dans le fichier nom_sortie
(webanalyze.json) et la meta documente sortie_origine = stdout capturé.

gowitness : REFUSÉ — pas d'exécution, voir qualif/gowitness/REFUS.md.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path("/home/julie/agnt-g1/PHASE3")
QUALIF = RACINE / "cible_web" / "qualif"
REGLES = RACINE / "regles_web"
CIBLE = "http://127.0.0.1:8807"
sys.path.insert(0, str(RACINE / "slice"))

STAGING = Path("/home/julie/.cache/arena_secops/staging")

STAGE_BIN = {
    "whatweb": STAGING / "whatweb" / "WhatWeb-0.6.4",
    "webanalyze": STAGING / "webanalyze",
    "wafw00f": STAGING / "wafw00f" / "venv" / "bin",
    "nikto": STAGING / "nikto",
}

TIMEOUTS = {"whatweb": 240, "webanalyze": 240, "wafw00f": 240, "nikto": 600}


def main() -> int:
    import fournisseurs_web as FW

    for outil in ("whatweb", "webanalyze", "wafw00f", "nikto"):
        dossier = QUALIF / outil
        dossier.mkdir(parents=True, exist_ok=True)
        plan = FW.planifier(outil, CIBLE, str(dossier), egress=True,
                            regles=str(REGLES))
        nom_sortie = plan["nom_sortie"]
        fichier_sortie = dossier / nom_sortie
        # Purge avant run : certains outils CONCATÈNENT leur journal (whatweb
        # --log-json, mesuré) — un seul run doit correspondre à un seul fichier.
        fichier_sortie.unlink(missing_ok=True)
        env = dict(os.environ)
        env["PATH"] = f"{STAGE_BIN[outil]}:{env['PATH']}"
        env.pop("AGNT_PLUGINS", None)
        debut = time.monotonic()
        try:
            r = subprocess.run(plan["argv"], capture_output=True, text=True,
                               timeout=TIMEOUTS[outil], env=env)
            code, stdout, stderr = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            code = 124
            stdout = (e.stdout or b"").decode(errors="replace")
            stderr = (e.stderr or b"").decode(errors="replace")
        duree = round(time.monotonic() - debut, 2)

        # L'outil n'écrit pas de fichier quand le chemin de sortie résolu n'apparaît
        # pas dans l'argv (webanalyze : pas de -o, mesuré) → la sortie de référence
        # EST le stdout. Sinon, ne JAMAIS écraser la sortie de l'outil.
        if str(fichier_sortie) not in " ".join(plan["argv"]):
            fichier_sortie.write_text(stdout, encoding="utf-8")
            origine = "stdout capturé (l'outil n'écrit pas de fichier : pas de -o, mesuré)"
        elif fichier_sortie.exists():
            origine = str(fichier_sortie)
        else:
            raise SystemExit(f"{outil} : sortie attendue absente : {fichier_sortie}")

        (dossier / "stdout.txt").write_text(stdout, encoding="utf-8")
        (dossier / "stderr.txt").write_text(stderr, encoding="utf-8")
        meta = {
            "outil": outil,
            "argv": plan["argv"],
            "argv_source": "fournisseurs_web.planifier (validation registre : "
                           "valider_registre_g1.py) — {BIN} résolu par le PATH du staging",
            "code_retour": code,
            "duree_s": duree,
            "sortie_origine": origine,
            "cible": CIBLE,
            "sandbox": "exécution DIRECTE hors cage (staging) — qualification bwrap "
                       "centralisée à suivre",
            "date": "2026-09-05",
            "timeout_s": TIMEOUTS[outil],
        }
        (dossier / f"{outil}.meta.yaml").write_text(
            "\n".join([
                f"# Métadonnées de l'exécution de qualification (G1, 2026-09-05).",
                f"# argv = rendu EXACT de fournisseurs_web.planifier({outil!r}, …) ;",
                "# {BIN} résolu par le PATH du staging (~/.cache/arena_secops/staging).",
                json.dumps(meta, ensure_ascii=False, indent=2),
            ]) + "\n", encoding="utf-8")
        taille = fichier_sortie.stat().st_size if fichier_sortie.exists() else 0
        print(f"{outil:12s} rc={code} durée={duree:>6}s sortie={taille} o "
              f"({nom_sortie})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
