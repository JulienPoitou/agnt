#!/usr/bin/env python3
"""Contrat de transport d'exécution — un provider n'est plus synonyme de binaire local.

Ce que la commande du 2026-08-30 demande au cœur :

    « le cœur doit distinguer clairement Capability, Provider, Execution Backend,
      Transport, Target, Result, Finding, Policy. Un provider ne doit pas être
      implicitement synonyme de binaire local. »

Avant ce lot, la seule façon d'exécuter un provider était un sous-processus dans la cage
bwrap, et ce couplage n'était écrit nulle part. Ce lot ajoute un `transport` DÉCLARATIF
au manifest, validé au chargement et dispatché à l'exécution :

    sandbox_cli   fourni par le cœur (sous-processus sandboxé) — défaut, inchangé
    <autre>       enregistré par un agent (builder-mcp, builder-tools) via
                  transports.enregistrer(nom, exécuteur) ; refusé sinon.

Ce que cette batterie mesure, et seulement ça :

  1. un manifest sans `transport` reste valide (compatibilité ascendante) ;
  2. `transport: sandbox_cli` est accepté ;
  3. un transport NON fourni est refusé au chargement (défaut fermé, jamais deviné) ;
  4. un transport enregistré devient chargeable et se lit sur le Provider ;
  5. l'exécution DÉLÈGUE au transport enregistré, sans rabattre sur le sous-processus ;
  6. `transports.enregistrer` refuse les entrées invalides (nom vide, non appelable,
     nom réservé au cœur).

Aucun `opa` ni `bwrap` n'est requis : le chargement du registre et la délégation se
jouent sur des exécuteurs faux.

Usage : python3 PHASE3/test_transports.py
"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import adapters                       # noqa: E402
import provider_manifest as PM        # noqa: E402
import transports as TR               # noqa: E402
from registre import Provider, Registry  # noqa: E402

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


BON = {
    "id": "outil_de_transport",
    "binaire": "bandit",                 # binaire autorisé par le cœur
    "argv": ["{BIN}", "-f", "json", "-r", "{TARGET}"],
    "output": {"format": "json"},
    "extraction": {"modele": "plat", "items_from": "results",
                   "champs": {"regle": "test_id", "fichier": "filename"}},
    "risk": "PASSIVE",
}


def main() -> int:
    print("=== CONTRAT DE TRANSPORT D'EXÉCUTION ===\n")

    # ------------------------------------------------------------ 1. défaut et explicite
    print("--- 1. défaut sandbox_cli, compatible avec l'existant ---")
    m0 = PM.valider(dict(BON), "TEST")
    cas("1. un manifest sans transport vaut sandbox_cli", m0.transport == "sandbox_cli",
        f"transport={m0.transport!r}")
    m1 = PM.valider({**BON, "transport": "sandbox_cli"}, "TEST")
    cas("1b. transport sandbox_cli explicite accepté", m1.transport == "sandbox_cli",
        f"transport={m1.transport!r}")

    # ------------------------------------------------------------ 2. défaut fermé
    print("\n--- 2. un transport non fourni est refusé au chargement ---")
    try:
        PM.valider({**BON, "transport": "mcp"}, "TEST")
        cas("2. transport non fourni refusé", False, "accepté alors qu'il doit être refusé")
    except PM.ManifestError as e:
        cas("2. transport non fourni refusé", "non fourni" in str(e).lower(),
            f"refusé : {str(e)[:110]}")

    # ------------------------------------------------------------ 3. enregistrement
    print("\n--- 3. un agent enregistre un transport, puis le manifest charge ---")
    marque = {"appele": 0}

    def _executeur_mcp(prov, sbx):
        marque["appele"] += 1
        marque["prov"] = prov.id
        marque["transport"] = getattr(prov, "transport", None)
        return "RESULTAT-MCP"

    TR.enregistrer("mcp", _executeur_mcp)
    try:
        cas("3. le transport mcp est désormais connu", TR.fournit("mcp"),
            f"connus : {list(TR.connus())}")
        m2 = PM.valider({**BON, "transport": "mcp"}, "TEST")
        cas("3b. le manifest mcp charge une fois le transport enregistré",
            m2.transport == "mcp", f"transport={m2.transport!r}")

        # ------------------------------------------------------ 4. le registre porte le transport
        print("\n--- 4. le Provider porte le transport de SON manifest ---")
        reg = Registry()
        prov_historique = reg.provider("semgrep")          # adaptateur historique, sans manifest
        prov_declaratif = reg.provider("bandit")           # manifest, sans transport déclaré
        cas("4. un adaptateur historique est sandbox_cli",
            prov_historique.transport == "sandbox_cli",
            f"transport={prov_historique.transport!r}")
        cas("4b. un provider déclaratif sans transport déclaré est sandbox_cli",
            prov_declaratif.transport == "sandbox_cli",
            f"transport={prov_declaratif.transport!r}")

        # ------------------------------------------------------ 5. délégation à l'exécution
        print("\n--- 5. l'exécution délègue au transport, sans rabattre ---")
        prov_mcp = Provider(id="outil_mcp", capability="TEST", kind="tool", mode="CLI",
                            risque="PASSIVE", commande=["mcp-run"], manifest=None,
                            transport="mcp")
        r = adapters.executer(prov_mcp, sbx=None)
        cas("5. le transport enregistré a exécuté le provider",
            r == "RESULTAT-MCP" and marque.get("prov") == "outil_mcp"
            and marque.get("transport") == "mcp",
            f"retour={r!r} · marque={marque}")
        # Le point critique : sans enregistrement, pas de repli silencieux sur sandbox_cli.
        prov_orphelin = replace(prov_mcp, transport="remote_inexistant")
        try:
            adapters.executer(prov_orphelin, sbx=None)
            cas("5b. transport non enregistré → pas de repli sur le sous-processus",
                False, "exécuté alors qu'il doit être refusé")
        except TR.TransportError as e:
            cas("5b. transport non enregistré → pas de repli sur le sous-processus",
                "non fourni" in str(e).lower(), f"refusé : {str(e)[:110]}")
    finally:
        # Le test laisse le registre des transports propre : `mcp` ne doit pas devenir un
        # transport de la plateforme parce qu'une batterie l'a enregistré.
        TR._EXECUTEURS.pop("mcp", None)

    # ------------------------------------------------------------ 6. enregistrement gardé
    print("\n--- 6. enregistrer() refuse les entrées invalides ---")
    for nom, ex, attendu in (("", lambda p, s: None, "nom de transport invalide"),
                             ("x", None, "doit être appelable"),
                             ("sandbox_cli", lambda p, s: None, "réservé au cœur")):
        try:
            TR.enregistrer(nom, ex)
            cas(f"6. enregistrer({nom!r}) refuse", False, "accepté alors qu'il doit être refusé")
        except TR.TransportError as e:
            cas(f"6. enregistrer({nom!r}) refuse", attendu in str(e).lower(),
                f"refusé : {str(e)[:90]}")

    print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
    sys.exit(1 if ECHECS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
