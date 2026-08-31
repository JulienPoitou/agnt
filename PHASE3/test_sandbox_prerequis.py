#!/usr/bin/env python3
"""Sandbox — les prérequis sont CONDITIONNELS à l'outil réellement exécuté.

Le défaut mesuré (31/08/2026, blocage du dogfood navigateur) : `Sandbox.verifie()`
exigeait les CINQ ressources à chaque exécution — dépôt, règles, base de vulnérabilités,
sortie, gitconfig — et `commande()` les montait toutes. Un run bandit sur un dépôt Python,
qui n'ouvre ni règle Semgrep ni base Trivy, tombait donc sur « base Trivy introuvable »
(1,3 Go à télécharger) avant le premier Popen. Faux prérequis : il faisait échouer un run
qui n'en avait pas besoin, ET il masquait l'obstacle suivant, réel celui-là.

Ce que cette batterie fige, sans `bwrap`, sans outil installé, sans réseau :

  1. provider sans base ni règles      → l'absence de base NE bloque PAS ;
  2. provider qui cite la base (argv)  → l'absence de base ÉCHOUE, avec le motif ;
  2b. provider qui cite la base (env)  → même refus (grype la configure par variable) ;
  3. provider qui cite les règles      → l'absence de règles ÉCHOUE, avec le motif ;
  4. binaire absent                    → refus explicite inchangé (`adapters._exe`) ;
  5. aucun faux succès                 → refus AVANT tout Popen, jamais un code 0 vide ;
  6. le mur suivant reste visible      → montages du bootstrap et `bwrap` absent ;
  7. `verifie()` sans argument         → strict, comme avant (diagnostic complet) ;
  8. `commande()` sans besoins         → montages historiques inchangés (rétro-compat).

Usage : python3 PHASE3/test_sandbox_prerequis.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import adapters as A                                          # noqa: E402
import sandbox as SB                                          # noqa: E402

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def _terrain(tmp: Path, *, avec_db: bool, avec_regles: bool) -> tuple[SB.Sandbox, Path]:
    """Une cage complète SAUF ce qu'on veut voir manquer. `bwrap` est un faux binaire
    qui touche un témoin : s'il tourne, c'est prouvé ; s'il ne tourne pas, aussi."""
    scan = tmp / "scan"
    out = tmp / "out"
    regles = tmp / "cache" / "rules"
    db = tmp / "cache" / "trivy-cache"
    monteurs = tmp / "mt"
    for d in (scan, out, monteurs):
        d.mkdir(parents=True, exist_ok=True)
    if avec_regles:
        regles.mkdir(parents=True, exist_ok=True)
    if avec_db:
        (db / "trivy").mkdir(parents=True, exist_ok=True)
    gitconfig = tmp / "gitconfig"
    gitconfig.write_text("[safe]\n", encoding="utf-8")
    for nom in ("mt-scan", "mt-regles", "mt-db", "mt-out"):
        (monteurs / nom).mkdir(exist_ok=True)
    (monteurs / "gitconfig.ro").write_text("[safe]\n", encoding="utf-8")

    temoin = tmp / "temoin-popen"
    faux_bwrap = tmp / "faux-bwrap"
    faux_bwrap.write_text(f"#!/bin/sh\ntouch {temoin}\nexit 0\n", encoding="utf-8")
    faux_bwrap.chmod(0o755)

    sbx = SB.Sandbox(
        bwrap=str(faux_bwrap),
        racine_scan=scan, racine_regles=regles, racine_db=db,
        sortie=out, gitconfig=gitconfig,
        M_SCAN=str(monteurs / "mt-scan"), M_REGLES=str(monteurs / "mt-regles"),
        M_DB=str(monteurs / "mt-db"), M_OUT=str(monteurs / "mt-out"),
        M_GITCONF=str(monteurs / "gitconfig.ro"))
    return sbx, temoin


def main() -> int:
    print("=== SANDBOX : PRÉREQUIS CONDITIONNELS AU PROVIDER EXÉCUTÉ ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="agnt-prereq-"))
    try:
        # ---------------------------------------------------------------- 1. sans base
        # Base Trivy ABSENTE, règles absentes : un outil qui ne cite ni l'une ni l'autre
        # (bandit, ruff, detect-secrets…) doit passer.
        sbx, temoin = _terrain(tmp / "a", avec_db=False, avec_regles=False)
        argv_simple = ["bandit", "-r", "-f", "json", "-o", f"{sbx.M_OUT}/bandit.json", sbx.M_SCAN]
        besoins = sbx.besoins(argv_simple)
        cas("1. provider sans base ni règles : aucun besoin dérivé, aucun prérequis manquant",
            besoins == frozenset() and sbx.verifie(besoins) == []
            and not Path(sbx.racine_db).exists(),
            f"besoins={sorted(besoins)} problemes={sbx.verifie(besoins)}")
        r = sbx.exec(argv_simple)
        cmd = sbx.commande(argv_simple, besoins)
        cas("1b. il va jusqu'au Popen, et la cage ne monte NI la base NI les règles absentes",
            r.code == 0 and temoin.exists()
            and sbx.M_DB not in cmd and sbx.M_REGLES not in cmd
            and sbx.M_SCAN in cmd and sbx.M_OUT in cmd and sbx.M_GITCONF in cmd,
            " ".join(cmd[:12]))

        # ---------------------------------------------------------------- 2. base citée en argv
        argv_db = ["trivy", "fs", f"--cache-dir={sbx.M_DB}/trivy", "--format", "json", sbx.M_SCAN]
        besoins_db = sbx.besoins(argv_db)
        probs = sbx.verifie(besoins_db)
        temoin.unlink(missing_ok=True)
        refus = ""
        try:
            sbx.exec(argv_db)
        except SB.SandboxError as exc:
            refus = str(exc)
        cas("2. provider qui CITE la base : absence = refus explicite, jamais un scan vide",
            besoins_db == frozenset({"db"})
            and any("base Trivy introuvable" in p for p in probs)
            and "base Trivy introuvable" in refus and refus.startswith("sandbox inutilisable"),
            refus[:160])
        cas("2a. aucun faux succès : le refus tombe AVANT tout Popen (aucun processus lancé)",
            not temoin.exists())

        # ---------------------------------------------------------------- 2b. base citée en env
        argv_grype = ["grype", f"dir:{sbx.M_SCAN}", "-o", "json"]
        env_grype = {"GRYPE_DB_CACHE_DIR": f"{sbx.M_DB}/grype"}
        besoins_env = sbx.besoins(argv_grype, env_grype)
        refus_env = ""
        try:
            sbx.exec(argv_grype, env=env_grype)
        except SB.SandboxError as exc:
            refus_env = str(exc)
        cas("2b. base citée par VARIABLE D'ENVIRONNEMENT (grype) : même besoin, même refus",
            besoins_env == frozenset({"db"}) and "base Trivy introuvable" in refus_env,
            refus_env[:120])

        # ---------------------------------------------------------------- 3. règles citées
        argv_semgrep = ["semgrep", "scan", f"--config={sbx.M_REGLES}/python.yaml",
                        "--json", sbx.M_SCAN]
        besoins_reg = sbx.besoins(argv_semgrep)
        refus_reg = ""
        try:
            sbx.exec(argv_semgrep)
        except SB.SandboxError as exc:
            refus_reg = str(exc)
        cas("3. provider à règles requises : absence des règles = refus explicite",
            besoins_reg == frozenset({"regles"})
            and "règles introuvable" in refus_reg,
            refus_reg[:140])
        cas("3b. et le refus des règles ne réclame PAS la base, qui ne le concerne pas",
            "base Trivy" not in refus_reg, refus_reg[:140])

        # ---------------------------------------------------------------- 4. binaire absent
        prov_absent = types.SimpleNamespace(id="outil_fantome",
                                            commande=["outil_fantome_zzz"], manifest=None)
        erreur_bin = ""
        try:
            A._exe(prov_absent)
        except FileNotFoundError as exc:
            erreur_bin = str(exc)
        cas("4. binaire absent : refus explicite inchangé, avant toute exécution",
            "outil introuvable" in erreur_bin and A.exe_de(prov_absent) is None,
            erreur_bin[:120])

        # ---------------------------------------------------------------- 5. base présente
        sbx_ok, temoin_ok = _terrain(tmp / "b", avec_db=True, avec_regles=True)
        argv_db_ok = ["trivy", "fs", f"--cache-dir={sbx_ok.M_DB}/trivy", sbx_ok.M_SCAN]
        r_ok = sbx_ok.exec(argv_db_ok)
        cmd_ok = sbx_ok.commande(argv_db_ok, sbx_ok.besoins(argv_db_ok))
        cas("5. base présente et citée : elle est bien exigée ET montée (rien n'est adouci)",
            r_ok.code == 0 and temoin_ok.exists()
            and cmd_ok.count("--ro-bind") == 4 and sbx_ok.M_DB in cmd_ok
            and sbx_ok.M_REGLES not in cmd_ok,
            " ".join(cmd_ok[:14]))

        # ---------------------------------------------------------------- 6. murs réels
        sbx_sans_mont, _ = _terrain(tmp / "c", avec_db=False, avec_regles=False)
        shutil.rmtree(Path(sbx_sans_mont.M_SCAN))
        probs_mont = sbx_sans_mont.verifie(frozenset())
        cas("6. le mur RÉEL reste visible : montage du bootstrap absent, dit par son nom",
            any("point de montage absent" in p and "mt-scan" in p for p in probs_mont),
            str(probs_mont))

        import dataclasses as _dc
        sbx_sans_bwrap, _ = _terrain(tmp / "d", avec_db=False, avec_regles=False)
        cage = _dc.replace(sbx_sans_bwrap, bwrap="bwrap_absent_zzz")
        mur_bwrap = ""
        try:
            cage.exec(["bandit", cage.M_SCAN])
        except FileNotFoundError as exc:
            mur_bwrap = str(exc)
        except SB.SandboxError as exc:                        # pas ce qu'on veut voir ici
            mur_bwrap = "PRÉREQUIS: " + str(exc)
        cas("6b. `bwrap` absent = mur réel au Popen, PAS un faux prérequis en amont",
            "bwrap_absent_zzz" in mur_bwrap and not mur_bwrap.startswith("PRÉREQUIS"),
            mur_bwrap[:140])

        # ---------------------------------------------------------------- 7/8. rétro-compat
        sbx_diag, _ = _terrain(tmp / "e", avec_db=False, avec_regles=False)
        probs_diag = sbx_diag.verifie()
        cas("7. `verifie()` sans argument reste STRICT : le diagnostic complet ne change pas",
            any("base Trivy introuvable" in p for p in probs_diag)
            and any("règles introuvable" in p for p in probs_diag),
            str(probs_diag))
        cmd_hist = sbx_diag.commande(["true"])
        cas("8. `commande()` sans besoins : montages historiques (5 ro-bind + 1 bind), "
            "l'autorité egress est intacte",
            cmd_hist.count("--ro-bind") == 5 and cmd_hist.count("--bind") == 1
            and sbx_diag.M_DB in cmd_hist and sbx_diag.M_REGLES in cmd_hist
            and "--unshare-net" in cmd_hist,
            " ".join(cmd_hist[:10]))

        import conditions as COND
        cas("8b. l'autorité `conditions.egress_de` lit toujours la commande construite",
            COND.egress_de(sbx_diag, ["true"]) is False,
            "cage fermée par défaut")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n=== {PAS} OK, {ECHECS} ECHEC(S) ===")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
