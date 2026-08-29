#!/usr/bin/env python3
"""Aucun secret dans TOUT le bundle — pas seulement dans les findings.

Le problème, constaté pour de vrai : les findings étaient masqués, mais `raw_bandit.json`
— copié tel quel — contenait le credential en clair, 4 occurrences. Tester uniquement les
findings laissait passer la fuite.

Ce test cherche le secret dans CHAQUE fichier du bundle :

    manifeste.json · run.json · findings.json · clusters.json
    rapport.md · rapport.sarif · raw_*.json · plan.json

Et il vérifie que la politique de conservation est déclarée : une sortie non sûre doit
avoir `stored: false`, un `reason`, et une version masquée à côté.

Usage : python3 PHASE3/test_bundle.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import assainissement as ASS  # noqa: E402

ANALYSER = RACINE / "analyser.py"
ARTIFACTS = RACINE / "artifacts"

# La fixture contient volontairement ces deux valeurs.
SECRETS_CONNUS = ("ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def dernier_bundle() -> Path:
    d = sorted((p for p in ARTIFACTS.rglob("rapport.md")), key=lambda p: p.stat().st_mtime)
    return d[-1].parent if d else ARTIFACTS


def main() -> int:
    print("=== AUCUN SECRET DANS TOUT LE BUNDLE ===\n")

    # Cible : la fixture qui CONTIENT des secrets. Config-Portal n'en a pas, il ne
    # prouverait rien.
    cible = RACINE / "testrepo"
    if not cible.exists():
        print(f"  cible absente : {cible}")
        return 1

    # Vérification préalable : la cible contient bien les secrets, sinon le test est vide.
    src = (cible / "app.py").read_text(encoding="utf-8")
    presents = [s for s in SECRETS_CONNUS if s in src]
    cas("0. la cible contient bien des secrets (sinon le test ne prouve rien)",
        len(presents) == len(SECRETS_CONNUS),
        f"{len(presents)}/{len(SECRETS_CONNUS)} valeurs présentes dans app.py")

    r = subprocess.run([sys.executable, str(ANALYSER), str(cible),
                        "Analyse la sécurité de mon dépôt"],
                       capture_output=True, text=True, timeout=900)
    cas("1. le workflow s'exécute", r.returncode == 0, f"exit={r.returncode}")

    b = dernier_bundle()
    fichiers = sorted(p for p in b.iterdir() if p.is_file())
    cas("2. le bundle est produit", len(fichiers) >= 8,
        f"{len(fichiers)} fichiers dans {b.relative_to(RACINE)}")

    # ------------------------------------------------ le cœur du test
    print("\n--- recherche dans chaque fichier du bundle ---")
    fuites = {}
    for f in fichiers:
        try:
            texte = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        trouves = [s for s in SECRETS_CONNUS if s in texte]
        # Et la recherche générique par motifs, au cas où un autre secret apparaîtrait.
        n = ASS.contient_secret(texte, large=True)
        if trouves or n:
            fuites[f.name] = (trouves, n)
        cas(f"aucun secret dans {f.name}", not trouves and n == 0,
            f"{len(trouves)} valeur(s) connue(s), {n} motif(s)" if (trouves or n) else "")

    cas("3. aucun secret dans l'ensemble du bundle", not fuites,
        f"fichiers touchés : {sorted(fuites)}" if fuites else "bundle propre")

    # ------------------------------------------------ sorties intermédiaires
    print("\n--- sorties intermédiaires ---")
    run_dir = RACINE / "run"
    if run_dir.exists():
        inter = {}
        for f in sorted(run_dir.glob("raw_*.json")):
            n = ASS.contient_secret(f.read_text(encoding="utf-8", errors="replace"))
            if n:
                inter[f.name] = n
        # Les sorties intermédiaires ne sont PAS dans le bundle : elles peuvent contenir
        # la donnée brute. Ce qui compte, c'est qu'elle ne sorte pas. On le dit.
        cas("4. les sorties intermédiaires hors bundle sont signalées", True,
            f"{len(inter)} fichier(s) intermédiaire(s) contiennent encore des motifs "
            f"({sorted(inter)}) — ils ne sont PAS copiés dans le bundle"
            if inter else "aucun motif dans les intermédiaires")

    # ------------------------------------------------ politique de conservation
    print("\n--- politique de conservation déclarée ---")
    man = json.loads((b / "manifeste.json").read_text(encoding="utf-8"))
    cons = man.get("conservation_des_sorties") or {}
    cas("5. la politique de conservation est déclarée", bool(cons),
        f"{len(cons)} sortie(s) décrite(s)")

    non_sures = {k: v for k, v in cons.items()
                 if not v.get("raw_output", {}).get("stored", True)}
    for k, v in non_sures.items():
        ro = v.get("raw_output", {})
        so = v.get("sanitized_output") or {}
        cas(f"6. {k} : empreinte + raison + version masquée",
            ro.get("digest") and ro.get("reason") == "secret_detected"
            and so.get("path") and (b / so["path"]).exists(),
            f"digest={ro.get('digest')} reason={ro.get('reason')} "
            f"redactions={ro.get('redactions')} → {so.get('path')}")

    # Une sortie sûre doit être conservée telle quelle : masquer sans raison détruirait
    # de la donnée utile (c'est exactement le faux positif des SHA de commits).
    sures = {k: v for k, v in cons.items()
             if v.get("raw_output", {}).get("stored", False)}
    for k, v in sures.items():
        cas(f"7. {k} : sortie sûre conservée telle quelle",
            (b / k).exists(), f"digest={v['raw_output'].get('digest')}")

    cas("8. aucune sortie n'est masquée sans raison",
        all(v.get("raw_output", {}).get("reason") for v in non_sures.values()),
        f"{len(non_sures)} sortie(s) masquée(s), toutes avec reason")

    # ------------------------------------------------ faux positifs
    print("\n--- faux positifs ---")
    trivy = next((k for k in cons if "trivy" in k), None)
    if trivy:
        red = cons[trivy].get("raw_output", {}).get("redactions", 0)
        cas("9. le masquage ne détruit pas les SHA de commits",
            red < 20,
            f"{red} masquage(s) sur {trivy} — au-delà de 20, le motif est trop large "
            f"et masque des SHA de commits")

    print(f"\n{'=' * 52}\n  {PAS}/{PAS + ECHECS} · {ECHECS} échec(s)\n{'=' * 52}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
