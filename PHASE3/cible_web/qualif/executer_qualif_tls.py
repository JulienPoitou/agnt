#!/usr/bin/env python3
"""Qualification TLS POSITIVE — les 4 outils TLS contre la cible d'épreuve en HTTPS
(mode --tls de serveur.py, certificat auto-signé CN=thaumas-web-epreuve).

Contexte : les 4 outils TLS étaient qualifiés sur REFUS NOMMÉ (la cible n'avait pas de
TLS). Ce run prouve le chemin positif, mesuré le 2026-09-05 : chaque outil voit une
surface TLS réelle et rend des items. Les argv sont EXACTEMENT ceux rendus par
fournisseurs_web.planifier (registre chargé avant) ; {BIN} est résolu vers le répertoire
des binaires promus. Exécution DIRECTE hors cage (staging), comme les qualif G1-G5 —
la cage runtime est prouvée ailleurs (pipeline_web.ExecuteurCage, test_web_cable).

Archives (relues par test_plugins_g4.py SANS réseau) :
    qualif/testssl.sh/testssl_sh_https.json + .stderr + .meta.yaml
    qualif/sslyze/sslyze_https.json      + .stderr + .meta.yaml
    qualif/sslscan/sslscan_https.xml     + .stderr + .meta.yaml
    qualif/tlsx/tlsx_https.txt           + .stderr + .meta.yaml

Usage : python3 executer_qualif_tls.py   (cible : https://127.0.0.1:8443 — autorisée)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent.parent   # PHASE3/
sys.path.insert(0, str(RACINE / "slice"))

CIBLE = "https://127.0.0.1:8443/"
OUT_TMP = Path("/tmp/agnt-qualif-tls")

# (provider_id, extension du fichier {OUT} attendu ou None si stdout, sortie brute à écrire)
OUTILS = [
    ("sslscan",    ".xml",  "stdout"),
    ("sslyze",     ".json", "stdout"),
    ("testssl_sh", ".json", "fichier"),
    ("tlsx",       ".txt",  "fichier"),
]


def binaire_dir() -> str:
    import adapters
    return str(adapters.BIN_DIR)


def main() -> int:
    from registre import Registry
    import fournisseurs_web as FW

    reg = Registry()
    # Répertoire de sortie possédé par CE run : reparti à zéro. Mesuré : testssl.sh
    # refuse d'écraser un --jsonfile non vide sans --append (« Either use "--append"
    # or (re)move it », code 253) — un restant d'un run interrompu ferait archiver
    # l'épreuve d'AVANT à la place de celle-ci.
    if OUT_TMP.exists():
        shutil.rmtree(OUT_TMP)
    OUT_TMP.mkdir(parents=True, exist_ok=True)
    bin_dir = binaire_dir()
    echecs = []
    for pid, suffixe, origine in OUTILS:
        plan = FW.planifier(pid, CIBLE, str(OUT_TMP), egress=True, registre=reg)
        # Convention pipeline : l'argv porte le binaire par son NOM (chemins["BIN"]
        # = mani.binaire) — la résolution passe par un PATH PRÉFIXÉ au répertoire des
        # binaires promus (jamais la version apt/PATH système : l'épingle fait foi).
        argv = [a.replace("{BIN}", bin_dir) for a in plan["argv"]]
        env = dict(os.environ)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
        resolu = shutil.which(argv[0], path=env["PATH"])
        if resolu is None:
            print(f"{pid} : binaire {argv[0]} introuvable dans {bin_dir}")
            return 1
        debut = time.monotonic()
        run = subprocess.run(argv, capture_output=True, text=True,
                             timeout=plan["timeout_s"], cwd=str(OUT_TMP),
                             env=env, check=False)
        duree_ms = int((time.monotonic() - debut) * 1000)
        dossier = Path(__file__).resolve().parent / pid.replace("testssl_sh", "testssl.sh")
        brut = dossier / f"{pid}_https{suffixe}"
        if origine == "fichier":
            attendu = Path(plan["nom_sortie"]) if not plan["nom_sortie"].startswith("/") \
                else Path(plan["nom_sortie"])
            # {OUT} = OUT_TMP/<id>.<format> — le contenu déclaré fait foi.
            f_out = OUT_TMP / plan["nom_sortie"]
            if f_out.is_file():
                brut.write_bytes(f_out.read_bytes())
            else:
                echecs.append(f"{pid} : fichier {plan['nom_sortie']} absent")
        else:
            brut.write_text(run.stdout, encoding="utf-8")
        (dossier / f"{pid}_https.stderr").write_text(run.stderr, encoding="utf-8")
        meta = (f"# Meta d'épreuve TLS POSITIVE — {pid} contre {CIBLE} (2026-09-05)\n"
                f"tool: {pid}\n"
                f"argv:\n" + "".join(f"- {a!r}\n" for a in plan["argv"]) +
                f"code_retour: {run.returncode}\n"
                f"binaire_resolu: {resolu}\n"
                f"duree_ms: {duree_ms}\n"
                f"cible: {CIBLE}\n"
                f"certificat_cible: auto-signé CN=thaumas-web-epreuve (serveur.py --tls)\n"
                f"sandbox: exécution DIRECTE hors cage (staging) — même convention que G1-G5\n"
                f"stdout_octets: {len(run.stdout)}\n"
                f"sortie_brute: {brut.name}\n")
        (dossier / f"{pid}_https.meta.yaml").write_text(meta, encoding="utf-8")
        taille = brut.stat().st_size
        print(f"{pid:12s} code={run.returncode:3d} {duree_ms:7d} ms  {brut.name} {taille} o")
        if run.returncode != plan["codes_succes"][0]:
            echecs.append(f"{pid} : code {run.returncode} hors succès {plan['codes_succes']}")
    if echecs:
        print("ÉCHECS :", "; ".join(echecs))
        return 1
    print("qualification TLS positive : 4/4 codes dans le succès, sorties archivées.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
