#!/usr/bin/env python3
"""Exécution réelle des 5 outils G5 contre THAUMAS-WEB (qualif, 2026-09-05).

Un seul run par outil, timeout borné, concurrence modeste. Les argv sont
EXACTEMENT ceux rendus par fournisseurs_web.planifier (validation registre faite
avant) ; {BIN} est résolu par le PATH préfixé du staging. Sortie brute, stdout,
stderr conservés dans qualif/<outil>/ — la batterie relit ces fichiers SANS
réseau. Scan UNIQUEMENT sur http://127.0.0.1:8807 (cible d'épreuve autorisée).
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

RACINE = Path("/home/julie/agnt-g5/PHASE3")
QUALIF = RACINE / "cible_web" / "qualif"
REGLES = RACINE / "regles_web"
CIBLE = "http://127.0.0.1:8807"
STAGING = Path("/home/julie/.cache/arena_secops/staging")

STAGE_BIN = {
    "kiterunner": STAGING / "kiterunner",
    "gospider": STAGING / "gospider",
    "dirhunt": STAGING / "dirhunt",
    "x8": STAGING / "x8",
    "cmseek": STAGING / "cmseek",
}

# (argv planifié, nom du fichier de sortie brute, timeout s, type d'origine)
RUNS = {
    "kiterunner": (["kr", "brute", CIBLE,
                    "-w", f"{REGLES}/dossiers-mini.txt",
                    "-x", "3", "-j", "2", "-t", "5s",
                    "--success-status-codes", "200,204,301,302,307,401,403,405,500",
                    "-o", "json", "-q"],
                   "kiterunner.jsonl", 240, "stdout"),
    "gospider": (["gospider", "-s", CIBLE, "-d", "2", "-c", "2", "-t", "2",
                  "-m", "8", "--json", "--no-redirect"],
                 "gospider.jsonl", 240, "stdout"),
    "dirhunt": (["dirhunt", CIBLE, "--threads", "4", "--timeout", "8",
                 "--exclude-sources",
                 "robots,virustotal,google,commoncrawl,crtsh,certificatessl,wayback",
                 "--progress-disabled", "--not-follow-subdomains", "--to-file", "{OUT}"],
                "dirhunt.json", 240, "fichier"),
    "x8": (["x8", "-u", f"{CIBLE}/search?q=THAUMAS",
            "-w", f"{REGLES}/parametres-mini.txt",
            "-c", "2", "--timeout", "10", "--disable-progress-bar",
            "--disable-colors", "-O", "json", "-o", "{OUT}"],
           "x8.custom", 240, "fichier"),
    "cmseek": (["cmseek", "-u", CIBLE, "--random-agent", "--batch"],
               "cmseek.txt", 240, "stdout"),
}


def main() -> int:
    for outil, (argv, nom_sortie, timeout, origine) in RUNS.items():
        dossier = QUALIF / outil
        dossier.mkdir(parents=True, exist_ok=True)
        fichier_sortie = dossier / nom_sortie
        cmd = [a if a != "{OUT}" else str(fichier_sortie) for a in argv]
        env = dict(os.environ)
        env["PATH"] = f"{STAGE_BIN[outil]}:{env['PATH']}"
        env.pop("AGNT_PLUGINS", None)
        debut = time.monotonic()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, env=env, stdin=subprocess.DEVNULL)
            code, stdout, stderr = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            code = 124
            stdout = (e.stdout or b"").decode(errors="replace")
            stderr = (e.stderr or b"").decode(errors="replace")
        duree = round(time.monotonic() - debut, 2)
        (dossier / "stdout.txt").write_text(stdout, encoding="utf-8")
        (dossier / "stderr.txt").write_text(stderr, encoding="utf-8")
        if origine == "fichier":
            brut = fichier_sortie.read_text(encoding="utf-8") if fichier_sortie.exists() else ""
        else:
            brut = stdout
            fichier_sortie.write_text(stdout, encoding="utf-8")
        meta = {
            "outil": outil,
            "argv": cmd,
            "code_retour": code,
            "duree_s": duree,
            "sortie_origine": ("stdout:" + nom_sortie) if origine == "stdout" else str(fichier_sortie),
            "cible": CIBLE,
            "sandbox": "exécution DIRECTE hors cage (staging) — qualification bwrap "
                       "centralisée à suivre",
            "date": "2026-09-05",
            "timeout_s": timeout,
        }
        (dossier / f"{outil}.meta.yaml").write_text(
            "\n".join([
                "# Métadonnées de l'exécution de qualification (G5, 2026-09-05).",
                f"# argv = argv résolu par fournisseurs_web.planifier({outil!r}, …) ;",
                "# {BIN} résolu par le PATH du staging (~/.cache/arena_secops/staging).",
                json.dumps(meta, ensure_ascii=False, indent=2),
            ]) + "\n", encoding="utf-8")
        taille = len(brut.encode("utf-8"))
        print(f"{outil:12s} rc={code} durée={duree:>6}s sortie_brute={taille} o → {nom_sortie}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
