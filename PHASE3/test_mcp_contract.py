#!/usr/bin/env python3
"""Contrat provider externe — registre, plan et policy, sans serveur réel.

Ce test est une preuve ``INTEGRATION SIMULATED`` du contrat de données : aucun
serveur MCP n'est lancé. Il vérifie que le premier couplage bloquant (un provider
obligatoirement assimilé à une commande locale) est supprimé sans donner à la
réponse ``tools/list`` une autorisation implicite.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import conditions as COND  # noqa: E402
import plan as PL  # noqa: E402
import policy as PO  # noqa: E402
from provider_contract import ProviderIdentity, Target  # noqa: E402
from registre import Registry, RegistryError  # noqa: E402


YAML = """
version: 1
capabilities:
  - id: CODE_REVIEW
    description: Revue statique du code
    domaines: [code]
    entree: [cible]
    sortie: finding/code-issue
    providers:
      - id: review_mcp
        transport: mcp
        kind: api
        mode: MCP
        risque: PASSIVE
        priorite: 20
        mcp:
          server:
            id: review-server
            version: 2.4.0
            transport: http
            endpoint: https://mcp.example.test/v1
            auth_env: REVIEW_MCP_TOKEN
          tool:
            name: review_code
            version: '7'
            inputSchema:
              type: object
              properties:
                arbitrary: {type: string}
          protocol_version: '2025-06-18'
          trust: untrusted_remote
          target_types: [repository]
          target_argument: repository
          argument_schema:
            type: object
            properties:
              repository: {type: string, maxLength: 200}
            required: [repository]
            additionalProperties: false
          result:
            format: json
            extraction:
              modele: plat
              items_from: results
              champs:
                regle: rule
                fichier: file
                ligne: line
                message: message
          limite: serveur distant non fiable
"""


def charge(texte: str = YAML) -> Registry:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(texte)
        nom = f.name
    return Registry(nom)


def main() -> int:
    cas: list[tuple[str, bool, str]] = []

    def ok(nom: str, condition: bool, detail: str = "") -> None:
        cas.append((nom, bool(condition), detail))
        print(("OK    " if condition else "ECHEC ") + nom + (f" — {detail}" if detail else ""))

    reg = charge()
    prov = reg.provider("review_mcp")
    ok("1. provider MCP chargé sans commande locale", prov.transport == "mcp" and prov.commande == [])
    ok("2. identité serveur/outil/version/protocole stable",
       prov.identity == ProviderIdentity(
           provider_id="review_mcp", transport="mcp", server_id="review-server",
           server_version="2.4.0", tool="review_code", tool_version="7",
           protocol_version="2025-06-18", trust="untrusted_remote"),
       str(prov.identity.to_dict()))
    ok("3. conditions réseau imposées par HTTP",
       COND.declarees(prov)["reseau"] is True,
       str(COND.declarees(prov)))
    ok("4. schéma distant inputSchema n'élargit pas le schéma approuvé",
       list(prov.manifest.argument_schema["properties"]) == ["repository"])

    target = Target("repository", "repo://fixture")
    args = prov.manifest.arguments_for(target)
    ok("5. le moteur construit l'argument cible", args == {"repository": "repo://fixture"})
    try:
        prov.manifest.arguments_for(target, {"arbitrary": "commande"})
        validation = False
    except Exception as exc:  # le type précis est couvert par le backend du lot suivant
        validation = "non autorisées" in str(exc) or "non autorisée" in str(exc)
    ok("6. argument hors schéma refusé avant transport", validation)
    try:
        prov.manifest.arguments_for(target, {"repository": "autre-cible"})
        reserve = False
    except Exception as exc:
        reserve = "réservé" in str(exc)
    ok("7. l'appelant ne peut pas écraser la cible du moteur", reserve)

    plan = PL.construire(
        "Analyse le code", "/tmp/repo", ["review_mcp"], reg, "deterministe")
    step = plan.steps[0]
    ok("8. le plan porte le contrat, pas une commande inventée",
       step.transport == "mcp" and step.server_id == "review-server"
       and step.tool == "review_code" and step.commande == [])
    entree = PO.PolicyEngine.entree(plan, reg, True)
    detail = next(x for x in entree["registre"]["providers_detail"] if x["id"] == "review_mcp")
    ok("9. la policy reçoit le binding MCP structuré",
       detail["transport"] == "mcp" and detail["identity"]["server_id"] == "review-server"
       and detail["identity"]["tool"] == "review_code")

    try:
        charge(YAML.replace("name: review_code", "name: review code"))
        malformed = False
    except RegistryError:
        malformed = True
    ok("10. une déclaration MCP malformée est refusée au chargement", malformed)
    try:
        charge(YAML.replace("          limite:", "          allow_shell:") )
        cle_inconnue = False
    except RegistryError:
        cle_inconnue = True
    ok("11. une clé MCP inconnue ne peut pas désarmer silencieusement une garde", cle_inconnue)

    echecs = [nom for nom, condition, _ in cas if not condition]
    print(f"\n{len(cas) - len(echecs)}/{len(cas)} cas passent")
    return 1 if echecs else 0


if __name__ == "__main__":
    raise SystemExit(main())
