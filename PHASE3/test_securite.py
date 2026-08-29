#!/usr/bin/env python3
"""PORTE BLOQUANTE DE SÉCURITÉ — Phase 3.

Ce script doit passer AVANT toute conclusion sur la corrélation ou toute autre
fonctionnalité. Un échec ici arrête le pipeline : c'est le sens de « porte bloquante ».

Il teste les deux couches séparément, parce qu'elles n'ont pas les mêmes garanties :

    Couche POLITIQUE (OPA)      : ce qui est demandé est-il autorisé ?
    Couche EXÉCUTION (garde)    : ce qui est réellement accessible est-il autorisé ?

OPA ne voit que des chaînes : il ne peut pas détecter un symlink. Les cas de symlink
et de sortie hors répertoire relèvent donc exclusivement de la couche exécution.

Usage : python3 PHASE3/test_securite.py    (exit non nul = porte fermée)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import garde_chemin as G          # noqa: E402
from sandbox import (CACHE_BIN, CACHE_DB, CACHE_REGLES,  # noqa: E402
                     Sandbox)

CIBLE = RACINE / "testrepo"
LABO = RACINE / "labo_securite"
SORTIE = RACINE / "run"

PAS = 0
ECHECS = 0


def cas(nom: str, attendu: str, obtenu: str, detail: str = "") -> None:
    """attendu/obtenu sont des étiquettes : 'bloque' ou 'laisse_passer'."""
    global PAS, ECHECS
    ok = attendu == obtenu
    if ok:
        PAS += 1
    else:
        ECHECS += 1
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}")
    print(f"          attendu={attendu} obtenu={obtenu}" + (f" · {detail}" if detail else ""))


def prepare_labo() -> None:
    """Construit un laboratoire avec de vrais symlinks sortants."""
    if LABO.exists():
        shutil.rmtree(LABO)
    (LABO / "interne").mkdir(parents=True)
    (LABO / "interne" / "sain.py").write_text("x = 1\n", encoding="utf-8")

    # Fichier et répertoire HORS du laboratoire, mais dans le workspace.
    secret = RACINE / "hors_labo.txt"
    secret.write_text("contenu hors workspace de test\n", encoding="utf-8")
    dossier = RACINE / "hors_labo_dir"
    dossier.mkdir(exist_ok=True)
    (dossier / "autre.py").write_text("y = 2\n", encoding="utf-8")

    os.symlink(secret, LABO / "interne" / "lien_fichier")
    os.symlink(dossier, LABO / "interne" / "lien_dossier")
    os.symlink(LABO / "interne" / "sain.py", LABO / "interne" / "lien_interne")


def sandbox() -> Sandbox:
    return Sandbox(bwrap=shutil.which("bwrap") or "bwrap", racine_scan=CIBLE,
                   racine_regles=CACHE_REGLES,
                   racine_db=CACHE_DB,
                   sortie=SORTIE, gitconfig=RACINE / "gitconfig")


def main() -> int:
    print("=== PORTE BLOQUANTE DE SÉCURITÉ ===\n")
    prepare_labo()
    autorise = [CIBLE, LABO]

    # ------------------------------------------------ 1. cible ../hors-workspace
    print("--- couche exécution : chemins ---")
    try:
        G.verifier_cible(CIBLE / ".." / ".." / "etc", autorise)
        cas("cible ../hors-workspace", "bloque", "laisse_passer")
    except G.CheminInterdit as e:
        cas("cible ../hors-workspace", "bloque", "bloque", str(e)[:90])

    # ------------------------------------------------ 2. symlink vers un fichier hors workspace
    try:
        r = G.verifier_cible(LABO, autorise)
        cas("symlink vers un fichier hors workspace", "bloque", "laisse_passer",
            f"sortants={r.symlinks_sortants}")
    except G.CheminInterdit as e:
        cas("symlink vers un fichier hors workspace", "bloque", "bloque", str(e)[:90])

    # ------------------------------------------ 3. symlink sortant retiré → interne autorisé
    (LABO / "interne" / "lien_fichier").unlink()
    (LABO / "interne" / "lien_dossier").unlink()
    try:
        r = G.verifier_cible(LABO, autorise)
        cas("symlink INTERNE autorisé (option 2)", "laisse_passer", "laisse_passer",
            f"internes={r.symlinks_internes}")
    except G.CheminInterdit as e:
        cas("symlink INTERNE autorisé (option 2)", "laisse_passer", "bloque", str(e)[:90])

    # ------------------------------------------------ 4. chemin absolu hors racines
    try:
        G.verifier_cible("/etc", autorise)
        cas("chemin absolu hors racines", "bloque", "laisse_passer")
    except G.CheminInterdit as e:
        cas("chemin absolu hors racines", "bloque", "bloque", str(e)[:90])

    # ------------------------------------------------ 5. sortie hors répertoire autorisé
    print("\n--- couche exécution : sortie ---")
    try:
        G.verifier_sortie("/tmp/eva.json", SORTIE)
        cas("sortie hors répertoire autorisé", "bloque", "laisse_passer")
    except G.CheminInterdit as e:
        cas("sortie hors répertoire autorisé", "bloque", "bloque", str(e)[:90])
    try:
        G.verifier_sortie(SORTIE / "ok.json", SORTIE)
        cas("sortie dans le répertoire autorisé", "laisse_passer", "laisse_passer")
    except G.CheminInterdit as e:
        cas("sortie dans le répertoire autorisé", "laisse_passer", "bloque", str(e)[:80])

    # ------------------------------------------------ 6-10. arguments hostiles
    print("\n--- arguments hostiles ---")
    hostiles = {
        "argument contenant ;": ["--x", "a; rm -rf /"],
        "argument contenant &&": ["--x", "a && id"],
        "argument contenant $(...)": ["--x", "$(id)"],
        "argument avec retour à la ligne": ["--x", "a\nid"],
        "argument avec octet NUL": ["--x", "a\x00b"],
    }
    for nom, args in hostiles.items():
        p = G.verifier_args(args)
        cas(nom, "bloque", "bloque" if p else "laisse_passer",
            (p[0][:70] if p else ""))

    # Argument légitime : ne doit PAS être bloqué, sinon on casse les outils.
    p = G.verifier_args(["--config=/regles/python.yaml", "--format=json", "--quiet"])
    cas("argument légitime non bloqué", "laisse_passer", "laisse_passer" if not p else "bloque",
        (p[0][:70] if p else ""))

    # ------------------------------------------------ 11. écriture dans le dépôt
    print("\n--- isolation à l'exécution ---")
    sbx = sandbox()
    r = sbx.exec(["/bin/sh", "-c", f"touch {Sandbox.M_SCAN}/intrusion 2>&1 || echo BLOQUE"])
    ecrit = (CIBLE / "intrusion").exists()
    cas("outil qui écrit dans le dépôt d'entrée", "bloque",
        "laisse_passer" if ecrit else "bloque",
        (r.stdout or r.stderr).strip()[:70])
    if ecrit:
        (CIBLE / "intrusion").unlink()

    # ------------------------------------------------ 12. processus enfant après timeout
    t0 = time.time()
    r = sbx.exec(["/bin/sh", "-c", "sleep 30 & sleep 30"], env={})
    duree = time.time() - t0
    from dataclasses import replace as _r
    sbx_court = _r(sbx, timeout=2)
    t0 = time.time()
    r2 = sbx_court.exec(["/bin/sh", "-c", "sleep 30"])
    duree2 = time.time() - t0
    cas("timeout coupe l'exécution", "bloque",
        "bloque" if (r2.code == 124 and duree2 < 10) else "laisse_passer",
        f"code={r2.code} en {duree2:.1f}s")

    # Survie des enfants : --die-with-parent doit les tuer.
    sbx_court.exec(["/bin/sh", "-c", "sleep 60 & sleep 60 & wait"])
    time.sleep(1)
    # On filtre la commande pgrep elle-même, dont la ligne de commande contient le motif.
    ps = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True).stdout
    survivants = [l for l in ps.splitlines()
                  if "sleep 60" in l and "pgrep" not in l and "ps -eo" not in l]
    cas("processus enfant ne survit pas au timeout", "bloque",
        "bloque" if not survivants else "laisse_passer",
        f"survivants={len(survivants)} {survivants[0][:60] if survivants else ''}")

    # ------------------------------------------------ 13. prolifération de processus
    r4 = sbx.exec(["/bin/sh", "-c",
                   'n=0; while [ $n -lt 500 ]; do sleep 30 & n=$((n+1)); done; echo LANCES:$n'])
    cas("création excessive de processus", "bloque",
        "bloque" if "Cannot fork" in (r4.stderr or "") or "LANCES:500" not in (r4.stdout or "")
        else "laisse_passer",
        (r4.stderr or r4.stdout).strip()[:70])
    subprocess.run(["pkill", "-f", "sleep 30"], capture_output=True)

    # ------------------------------------------------ 14. garde-fou secrets — faux positifs
    # Bug du dogfooding (2026-08-28, campagne 1) : le motif « 40 caractères base64 »
    # du jeu LARGE incluait '/' dans sa classe et matchait les URL d'advisories
    # GitHub — '…/security/advisories/GHSA' fait exactement 40 caractères. Sur le
    # dépôt réel axios, une vraie vulnérabilité (vite, CVE-2026-53571) portait une
    # telle référence : le garde-fou a bloqué TOUTE l'analyse. Le principe « échouer
    # plutôt que fuir » est conservé ; c'est le détecteur qui est corrigé.
    import assainissement as A                       # noqa: E402
    import findings as F                             # noqa: E402

    url_ghsa = "https://github.com/vitejs/vite/security/advisories/GHSA-fx2h-pf6j-xcff"
    url_fedora = ("https://lists.fedoraproject.org/archives/list/package-announce@"
                  "lists.fedoraproject.org/thread/N4YQZJ4Q3RA6HOKT5VHYO4X2VKKRHQME7BQ5ZBRYQC3XW4T6L2AU/")
    chemin_artefact = ("/home/user/PHASE3/artifacts/e8c0c0a783c8b58e/a0fee424b6fd41d2/"
                       "b6db164f06ae1f77/raw_trivy.json")
    cle_40 = "wJalrXUtnFEMI7K9MDENG8bPxRfiCY4EXAMPLEKEY9"  # 42 car., casse mixte, chiffres
    n_ghsa = A.contient_secret(url_ghsa, large=True)
    cas("URL d'advisory GitHub : pas un secret (jeu large)", "0", str(n_ghsa))
    n_fedora = A.contient_secret(url_fedora, large=True)
    cas("URL Fedora avec identifiant 40+ caractères : pas un secret", "0", str(n_fedora))
    n_chemin = A.contient_secret(f'"chemin": "{chemin_artefact}"', large=True)
    cas("chemin d'artefact du projet : pas un secret", "0", str(n_chemin))
    n_url_ghp = A.contient_secret("https://hote.exemple/callback?token=ghp_"
                                  + "A1b2C3d4E5f6G7h8I9j0K1l2", large=True)
    cas("jeton ghp_ DANS une URL : toujours détecté (strict intégral)", "détecté",
        "détecté" if n_url_ghp >= 1 else "manqué")
    n_cle = A.contient_secret(cle_40, large=True)
    cas("clé 40+ caractères avec chiffres : toujours détectée", "détectée",
        "détectée" if n_cle >= 1 else "manquée")
    n_ghp = A.contient_secret("jeton ghp_" + "A1b2C3d4E5f6G7h8I9j0" + " fin", large=False)
    cas("jeu strict inchangé : ghp_ toujours détecté", "détecté",
        "détecté" if n_ghp >= 1 else "manqué")

    # Bout en bout : le garde-fou du pipeline sur des findings trivy synthétiques
    # construits sur la forme réelle (mêmes références que l'incident axios).
    # NB : la clé est placée dans Title, pas Description — le normaliseur trivy ne
    # conserve pas Description (vérifié sur le dump réel tv-0002). Un test qui cache
    # le secret dans un champ jeté testerait le vide, pas le garde-fou.
    def doc_trivy(titre: str) -> dict:
        return {"Results": [{
            "Target": "docs/package-lock.json", "Class": "lang-pkgs", "Type": "npm",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-53571", "PkgName": "vite",
                "InstalledVersion": "5.4.21", "Severity": "HIGH",
                "Title": titre, "Description": "champ non conservé par le normaliseur",
                "References": [
                    url_ghsa,
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-53571"]}]}]}

    ok = F.normaliser("trivy", doc_trivy("vite: server.fs.deny bypass"))
    fuites_ok = F.verifie_absence_secrets(ok)
    cas("finding trivy avec référence GHSA : garde-fou laisse passer", "passe",
        "passe" if not fuites_ok else f"bloque ({fuites_ok[0][:50]})")
    ko = F.normaliser("trivy", doc_trivy(f"clé exposée {cle_40} dans la config"))
    fuites_ko = F.verifie_absence_secrets(ko)
    cas("finding avec clé 40 caractères : garde-fou bloque toujours", "bloque",
        "bloque" if fuites_ko else "passe")

    print(f"\n{'=' * 50}\n  {PAS} OK · {ECHECS} ÉCHEC(S)\n{'=' * 50}")
    if ECHECS:
        print("\nPORTE FERMÉE : aucune conclusion sur la corrélation n'est permise.")
        return 1
    print("\nPORTE OUVERTE : l'exécution est contenue pour ces cas.")
    print("Rappel : la mémoire n'est PAS limitée (RLIMIT_AS casse Trivy et Gitleaks).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
