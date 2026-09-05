#!/usr/bin/env python3
"""Exécution réelle des 5 outils G2 contre THAUMAS-WEB (qualif, 2026-09-05).

Un seul run par outil, timeout borné, rates modestes. Les argv sont EXACTEMENT
ceux rendus par fournisseurs_web.planifier (validation registre faite avant) ;
{BIN} est résolu par le PATH préfixé du staging. Sortie brute, stdout, stderr
conservés dans qualif/<outil>/ — la batterie relit ces fichiers SANS réseau.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

RACINE = Path("/home/julie/agnt-g2/PHASE3")
QUALIF = RACINE / "cible_web" / "qualif"
REGLES = RACINE / "regles_web"
CIBLE = "http://127.0.0.1:8807"
STAGING = Path("/home/julie/.cache/arena_secops/staging")

STAGE_BIN = {
    "katana": STAGING / "katana",
    "gobuster": STAGING / "gobuster",
    "feroxbuster": STAGING / "feroxbuster",
    "dirsearch": STAGING / "dirsearch" / "venv" / "bin",
    "hakrawler": STAGING / "hakrawler",
}

RUNS = {
    "katana": (["katana", "-u", CIBLE, "-jsonl", "-o", "{OUT}", "-nc", "-silent",
                "-d", "2", "-c", "4", "-rl", "40", "-timeout", "10"],
               "katana.jsonl", 240),
    "gobuster": (["gobuster", "dir", "-u", CIBLE, "-w", f"{REGLES}/dossiers-mini.txt",
                  "-t", "4", "-q", "--no-error", "--no-progress", "-e", "-o", "{OUT}"],
                 "gobuster.custom", 240),
    "feroxbuster": (["feroxbuster", "-u", CIBLE, "-w", f"{REGLES}/dossiers-mini.txt",
                     "-t", "4", "--rate-limit", "40", "-q", "--json", "-o", "{OUT}",
                     "--no-state"],
                    "feroxbuster.custom", 240),
    "dirsearch": (["dirsearch", "-u", CIBLE, "-w", f"{REGLES}/dossiers-mini.txt",
                   "-t", "4", "-q", "--no-color", "--full-url", "-O", "json",
                   "-o", "{OUT}"],
                  "dirsearch.json", 240),
    "hakrawler": (["hakrawler_scan", CIBLE, "{OUT}"],
                  "hakrawler.jsonl", 240),
}


def main() -> int:
    for outil, (argv, nom_sortie, timeout) in RUNS.items():
        dossier = QUALIF / outil
        dossier.mkdir(parents=True, exist_ok=True)
        fichier_sortie = dossier / nom_sortie
        cmd = [a if a != "{OUT}" else str(fichier_sortie) for a in argv]
        env = dict(os.environ)
        env["PATH"] = f"{STAGE_BIN[outil]}:{env['PATH']}"
        env.pop("AGNT_PLUGINS", None)
        debut = time.monotonic()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            code, stdout, stderr = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            code, stdout, stderr = 124, (e.stdout or b"").decode(errors="replace"), (e.stderr or b"").decode(errors="replace")
        duree = round(time.monotonic() - debut, 2)
        (dossier / "stdout.txt").write_text(stdout, encoding="utf-8")
        (dossier / "stderr.txt").write_text(stderr, encoding="utf-8")
        meta = {
            "outil": outil,
            "argv": cmd,
            "code_retour": code,
            "duree_s": duree,
            "sortie_origine": str(fichier_sortie),
            "cible": CIBLE,
            "sandbox": "exécution DIRECTE hors cage (staging) — qualification bwrap "
                       "centralisée à suivre",
            "date": "2026-09-05",
            "timeout_s": timeout,
        }
        (dossier / f"{outil}.meta.yaml").write_text(
            "\n".join([
                "# Métadonnées de l'exécution de qualification (G2, 2026-09-05).",
                f"# argv = argv résolu par fournisseurs_web.planifier({outil!r}, …) ;",
                "# {BIN} résolu par le PATH du staging (~/.cache/arena_secops/staging).",
                json.dumps(meta, ensure_ascii=False, indent=2),
            ]) + "\n", encoding="utf-8")
        taille = fichier_sortie.stat().st_size if fichier_sortie.exists() else 0
        print(f"{outil:12s} rc={code} durée={duree:>6}s sortie={taille} o")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
