#!/usr/bin/env python3
"""Test de l'isolateur OCI — SANS Docker.

Ce test ne lance aucun conteneur : il n'y a pas de runtime OCI dans l'environnement de
développement. Il vérifie ce qui est vérifiable sans Docker :

    · la commande impose bien les dix limites
    · elle ne passe par aucun shell
    · elle est IDENTIQUE à celle de test_oci.sh

Le dernier point est le plus important. Si les deux commandes divergent, le harnais teste
un confinement qui n'est pas celui qui tournera en production — et un test qui ne teste pas
la production ne vaut rien.

Ce que ce test ne prouve PAS : que les limites tiennent réellement. Ça, c'est le rôle de
test_oci.sh, sur une machine avec Docker.

Usage : python3 PHASE3/test_isolateur.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import isolateur_oci as OCI  # noqa: E402

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def drapeaux(argv: list[str]) -> set[str]:
    """Les drapeaux de confinement, sans leurs valeurs."""
    out = set()
    for a in argv:
        if a.startswith("--"):
            out.add(a.split("=", 1)[0])
        elif a in ("--rm", "--read-only"):
            out.add(a)
    return out


def main() -> int:
    print("=== ISOLATEUR OCI — vérification sans Docker ===\n")

    lim = OCI.Limites()
    cmd = OCI.construire("python:3.13-slim", ["python", "-c", "print('ok')"], lim)

    # ------------------------------------------------ 1. les dix limites
    problemes = OCI.verifier_conformite(cmd.argv)
    cas("1. les dix limites sont imposées", not problemes,
        "\n          ".join(problemes) if problemes else cmd.en_ligne()[:110])

    # ------------------------------------------------ 2. aucun shell
    # On cherche les paires « sh -c », pas le drapeau -c seul : « python -c » est
    # légitime et n'est pas un shell.
    shell = [f"{cmd.argv[i]} -c" for i in range(len(cmd.argv) - 1)
             if cmd.argv[i] in ("sh", "bash", "dash") and cmd.argv[i + 1] == "-c"]
    cas("2. aucun shell dans la commande", not shell,
        f"trouvé : {shell}" if shell else "« python -c » est légitime, pas un shell")
    # Et un vrai shell doit bien être détecté.
    cmd_shell = OCI.construire("img", ["sh", "-c", "id"])
    pb = OCI.verifier_conformite(cmd_shell.argv)
    cas("2b. un vrai shell est détecté", any("shell" in x for x in pb),
        "; ".join(pb)[:80])

    # ------------------------------------------------ 3. commande interne en liste
    try:
        OCI.construire("img", "echo coucou")
        cas("3. une chaîne shell est refusée", False, "acceptée")
    except ValueError as e:
        cas("3. une chaîne shell est refusée", True, str(e)[:80])

    try:
        OCI.construire("img", ["echo", "a; rm -rf /"])
        pb = OCI.verifier_conformite(OCI.construire("img", ["echo", "a; rm -rf /"]).argv)
        cas("4. un métacaractère est détecté", any("métacaractère" in p for p in pb),
            "; ".join(pb)[:90])
    except ValueError:
        cas("4. un métacaractère est détecté", True, "refusé à la construction")

    # ------------------------------------------------ 5. conformité au harnais
    harnais = RACINE / "test_oci.sh"
    if not harnais.exists():
        cas("5. conformité au harnais test_oci.sh", False, "harnais absent")
    else:
        texte = harnais.read_text(encoding="utf-8")
        # Les drapeaux imposés par le harnais, extraits de sa fonction run().
        drapeaux_harnais = set(re.findall(r'(--[a-z-]+)=', texte))
        drapeaux_harnais |= {"--rm", "--read-only"}
        # --image et --timeout ne sont pas des drapeaux docker
        drapeaux_harnais -= {"--image", "--timeout"}

        drapeaux_adaptateur = drapeaux(cmd.argv)
        manquants = drapeaux_harnais - drapeaux_adaptateur
        cas("5. mêmes drapeaux que le harnais", not manquants,
            f"absents de l'adaptateur : {sorted(manquants)}" if manquants
            else f"{len(drapeaux_adaptateur)} drapeaux identiques")

        # Les valeurs doivent correspondre aussi.
        valeurs = {"--memory": lim.memoire, "--pids-limit": str(lim.pids),
                   "--cpus": lim.cpus,
                   "--ulimit": f"fsize={lim.fsize}:{lim.fsize}"}
        ecarts = []
        for d, attendu in valeurs.items():
            reel = next((a.split("=", 1)[1] for a in cmd.argv if a.startswith(d + "=")), None)
            if reel != attendu:
                ecarts.append(f"{d}={reel} (attendu {attendu})")
        cas("6. mêmes valeurs que le harnais", not ecarts,
            "; ".join(ecarts) if ecarts else "memory, pids, cpus, fsize identiques")

    # ------------------------------------------------ 7. swap borné
    mem = next(a.split("=", 1)[1] for a in cmd.argv if a.startswith("--memory="))
    swap = next(a.split("=", 1)[1] for a in cmd.argv if a.startswith("--memory-swap="))
    cas("7. swap égal à la mémoire (swap interdit)", mem == swap,
        f"memory={mem} memory-swap={swap}")

    # ------------------------------------------------ 8. réseau coupé par défaut
    cas("8. réseau coupé par défaut", "--network=none" in cmd.argv,
        "profil passif")
    cmd_actif = OCI.construire("img", ["outil"], OCI.Limites(reseau=True))
    cas("8b. réseau autorisé seulement si demandé",
        "--network=bridge" in cmd_actif.argv,
        "outils actifs, à n'autoriser qu'avec validation humaine")

    # ------------------------------------------------ 9. montages en lecture seule
    cmd_m = OCI.construire("img", ["outil"], montages={"/hote/depot": "/scan"})
    cas("9. les montages sont en lecture seule",
        any(a == "/hote/depot:/scan:ro" for a in cmd_m.argv),
        next((a for a in cmd_m.argv if a.startswith("/hote")), "aucun"))

    print(f"\n{'=' * 52}\n  {PAS}/{PAS + ECHECS} · {ECHECS} échec(s)\n{'=' * 52}")
    if not ECHECS:
        print("\nLa commande est correcte. Elle n'est PAS éprouvée :")
        print("  ./PHASE3/test_oci.sh   ← sur une machine avec Docker")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
