#!/usr/bin/env python3
"""Garde policy/egress MCP — tests contrôlés sans OPA ni réseau.

Ces cas ne prétendent pas exécuter OPA. Ils injectent un double de la frontière policy
pour prouver l'ordre du pipeline : un refus ou une policy indisponible arrive avant le
transport, et l'egress fermé écarte le provider avant même la consultation policy.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import mission as MS  # noqa: E402
import pipeline as P  # noqa: E402
import policy as PO  # noqa: E402
import mcp_bootstrap as MB  # noqa: E402
from registre import Registry  # noqa: E402
import transports  # noqa: E402

YAML = """
version: 1
capabilities:
  - id: CODE_STATIC_ANALYSIS
    description: Analyse statique contrôlée
    domaines: [code]
    entree: [cible]
    sortie: finding/code-issue
    providers:
      - id: gate_mcp
        transport: mcp
        kind: api
        risque: PASSIVE
        mcp:
          server: {id: gate-server, transport: http, endpoint: http://127.0.0.1:9/mcp}
          tool: {name: review_code, version: '1'}
          target_types: [repository]
          target_argument: repository
          argument_schema:
            type: object
            properties: {repository: {type: string}}
            required: [repository]
            additionalProperties: false
          timeout_s: 1
          result:
            format: json
            extraction:
              modele: plat
              items_from: results
              champs: {regle: rule, fichier: file, message: message}
"""


class PolicyDouble:
    def __init__(self, *, allow=True, error=None):
        self.allow = allow
        self.error = error
        self.calls = 0

    def evaluer(self, *args, **kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return types.SimpleNamespace(allow=self.allow, motifs=("double_refus",) if not self.allow else ())


class TransportFactoryDouble:
    def __init__(self):
        self.calls = 0

    def __call__(self, manifest):
        self.calls += 1
        raise AssertionError("le transport MCP a été atteint avant la garde")


def main() -> int:
    cases = []

    def case(name, condition, detail=""):
        cases.append((name, bool(condition), detail))
        print(("OK    " if condition else "ECHEC ") + name
              + (f" — {detail}" if detail else ""))

    if not transports.enregistre("mcp"):
        MB.initialiser_mcp(transports)
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write(YAML)
    f.close()
    reg = Registry(f.name)
    cible_tmp = Path(tempfile.mkdtemp(prefix="agnt-mcp-gate-target-"))
    old_missions = MS.MISSIONS
    missions = Path(tempfile.mkdtemp(prefix="agnt-mcp-gate-missions-"))
    MS.MISSIONS = missions
    try:
        # Egress fermé : la condition réseau est refusée avant que policy ou transport
        # ne soient consultés. C'est intentionnel : la sortie est une précondition de plan.
        policy = PolicyDouble(allow=True)
        factory = TransportFactoryDouble()
        execution = P.executer(
            "Analyse le code", cible_tmp, egress=False, registre=reg,
            policy_engine=policy, transport_factories={"gate_mcp": factory}, escalade=False)
        case("1. egress fermé bloque avant policy et transport",
             execution.arret == "conditions" and policy.calls == 0 and factory.calls == 0,
             execution.arret)

        # Egress accordé permet d'atteindre la policy ; un refus policy ne construit pas
        # de sandbox et ne contacte jamais l'endpoint MCP.
        policy = PolicyDouble(allow=False)
        factory = TransportFactoryDouble()
        execution = P.executer(
            "Analyse le code", cible_tmp, egress=True, registre=reg,
            policy_engine=policy, transport_factories={"gate_mcp": factory}, escalade=False)
        case("2. refus policy bloque avant l'invocation MCP",
             execution.arret == "policy" and policy.calls == 1 and factory.calls == 0,
             str(execution.decision))

        # Une policy indisponible est un refus fail-closed, pas un passage direct au
        # backend. Le test conserve aussi l'état structuré attaché à l'exception.
        policy = PolicyDouble(error=PO.PolicyError("OPA simulé indisponible"))
        factory = TransportFactoryDouble()
        try:
            P.executer("Analyse le code", cible_tmp, egress=True, registre=reg,
                       policy_engine=policy,
                       transport_factories={"gate_mcp": factory}, escalade=False)
            raised = None
        except PO.PolicyError as exc:
            raised = exc
        case("3. policy indisponible bloque fail-closed avant transport",
             raised is not None and policy.calls == 1 and factory.calls == 0
             and getattr(raised, "agnt_refus", {}).get("motif") == "policy_injoignable")
    finally:
        MS.MISSIONS = old_missions
        shutil.rmtree(cible_tmp, ignore_errors=True)
        shutil.rmtree(missions, ignore_errors=True)
        Path(f.name).unlink(missing_ok=True)

    failures = [name for name, condition, _ in cases if not condition]
    print(f"\n{len(cases) - len(failures)}/{len(cases)} cas passent")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
