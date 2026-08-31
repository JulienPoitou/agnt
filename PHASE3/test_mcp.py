#!/usr/bin/env python3
"""MCP provider backend — INTEGRATION SIMULATED.

Le serveur n'est pas réel : un transport en mémoire joue le handshake MCP, la
liste d'outils et l'appel JSON-RPC. Cela prouve le contrat AGNT, la validation, les
statuts, la normalisation et le ledger, pas la disponibilité d'un serveur MCP tiers.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import adapters as A  # noqa: E402
import cible as CIB  # noqa: E402
import findings as F  # noqa: E402
import mcp_bootstrap as MB  # noqa: E402
import mission as MS  # noqa: E402
import pipeline as P  # noqa: E402
import plan as PL  # noqa: E402
import policy as PO  # noqa: E402
import statuts as ST  # noqa: E402
import transports  # noqa: E402
from mcp_provider import MCPBackend, backend_for  # noqa: E402
from mcp_transport import (  # noqa: E402
    MCPRemoteError,
    MCPTransportCancelled,
    MCPTransportTimeout,
    MCPTransportUnavailable,
)
from provider_contract import ArgumentValidationError, Target  # noqa: E402
from registre import Registry  # noqa: E402


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
            version: '2.4.0'
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
                severite: severity
          coverage:
            declares_files: true
          limite: serveur distant non fiable
"""


def registry() -> Registry:
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write(YAML)
    f.close()
    return Registry(f.name)


class FakeTransport:
    def __init__(self, *, tools=None, mode="ok", message=None):
        self.tools = [{"name": x} for x in (["review_code"] if tools is None else tools)]
        self.mode = mode
        self.message = message
        self.calls = []
        self.closed = False

    def request(self, method, params=None, **kwargs):
        self.calls.append((method, dict(params or {})))
        if self.mode == "timeout":
            raise MCPTransportTimeout("simulated timeout")
        if self.mode == "down":
            raise OSError("simulated server failure")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": 1, "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "simulated-review", "version": "2.4.0"},
            }}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": 2, "result": {"tools": self.tools}}
        if method == "tools/call":
            payload = {"results": [{
                "rule": "review.no-eval", "file": "src/app.py", "line": 12,
                "message": self.message or "avoid eval", "severity": "HIGH",
            }]}
            return {"jsonrpc": "2.0", "id": 3, "result": {
                "content": [{"type": "text", "text": json.dumps(payload)}],
            }}
        raise AssertionError(method)

    def notify(self, method, params=None):
        self.calls.append((method, dict(params or {})))

    def close(self):
        self.closed = True


class Factory:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.instances = []

    def __call__(self, manifest):
        t = FakeTransport(**self.kwargs)
        self.instances.append(t)
        return t


class CancelTransport(FakeTransport):
    def request(self, method, params=None, **kwargs):
        raise MCPTransportCancelled("simulated cancellation")


class RemoteErrorTransport(FakeTransport):
    def request(self, method, params=None, **kwargs):
        if method == "tools/call":
            raise MCPRemoteError("erreur distante simulée avec ghp_" + "B" * 36)
        return super().request(method, params, **kwargs)


class ServerDownTransport(FakeTransport):
    def request(self, method, params=None, **kwargs):
        raise MCPTransportUnavailable("serveur simulé indisponible")


class MalformedTransport(FakeTransport):
    def request(self, method, params=None, **kwargs):
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": 3, "result": ["not", "an", "object"]}
        return super().request(method, params, **kwargs)


class OneTransportFactory:
    def __init__(self, transport):
        self.transport = transport
        self.calls = 0

    def __call__(self, manifest):
        self.calls += 1
        return self.transport


def main() -> int:
    cases: list[tuple[str, bool, str]] = []

    def case(name, condition, detail=""):
        cases.append((name, bool(condition), detail))
        print(("OK    " if condition else "ECHEC ") + name
              + (f" — {detail}" if detail else ""))

    # Le transport est enregistré explicitement avant le Registry, comme dans le
    # bootstrap CORE ; le test ne dépend pas d'un import magique de MCP.
    MB.initialiser_mcp(transports)
    reg = registry()
    prov = reg.provider("review_mcp")
    target = Target("repository", "repo://fixture")

    # ----------------------------------------------------------- backend contract
    factory = Factory()
    result = backend_for(prov, transport_factory=factory).execute(target=target)
    transport = factory.instances[0]
    case("1. handshake MCP puis tools/list puis tools/call",
         result.status == "succeeded"
         and [x[0] for x in transport.calls] == [
             "initialize", "notifications/initialized", "tools/list", "tools/call"],
         str([x[0] for x in transport.calls]))
    call = next(p for m, p in transport.calls if m == "tools/call")
    case("2. le nom d'outil vient du binding enregistré", call["name"] == "review_code")
    case("3. la cible est injectée par le moteur", call["arguments"] == {"repository": "repo://fixture"})
    case("3bis. l'identifiant JSON-RPC final est corrélé au résultat",
         result.request_id == "3" and result.correlation_id == "review_mcp:review_code")
    case("4. la découverte ne peut pas élargir le schéma d'arguments",
         "arbitrary" not in call["arguments"] and result.output["results"][0]["rule"] == "review.no-eval")
    case("5. le résultat typé distingue provider, transport et versions",
         result.identity.server_id == "review-server"
         and result.identity.tool == "review_code"
         and result.identity.tool_version == "7"
         and result.identity.transport == "mcp"
         and result.availability is not None
         and result.availability.status == "available")

    # ----------------------------------------------------------- refus / pannes
    down_factory = Factory(tools=[])
    unavailable = backend_for(prov, transport_factory=down_factory).execute(target=target)
    calls_down = down_factory.instances[0].calls
    case("6. outil absent de tools/list = unavailable explicite, aucun appel arbitraire",
         unavailable.status == "unavailable"
         and not any(m == "tools/call" for m, _ in calls_down),
         f"{unavailable.status} {calls_down}")

    timeout_factory = Factory(mode="timeout")
    timed = backend_for(prov, transport_factory=timeout_factory).execute(target=target)
    case("7. timeout MCP = timed_out explicite", timed.status == "timed_out", timed.error)

    bad_factory = Factory()
    try:
        backend_for(prov, transport_factory=bad_factory).execute(
            target=target, arguments={"arbitrary": "not allowed"})
        bad = False
    except ArgumentValidationError:
        bad = True
    case("8. argument invalide refusé avant de construire le transport", bad
         and not bad_factory.instances)

    secret = "ghp_" + "A" * 36
    safe_factory = Factory(message=f"remote says {secret}")
    safe_result = backend_for(prov, transport_factory=safe_factory).execute(target=target)
    case("9. une valeur secrète dans une réponse distante est masquée avant stockage",
         secret not in json.dumps(safe_result.to_dict(), ensure_ascii=False)
         and secret not in json.dumps(safe_result.raw, ensure_ascii=False)
         and "<masqué>" in json.dumps(safe_result.output, ensure_ascii=False))

    cancel_factory = OneTransportFactory(CancelTransport())
    cancelled = backend_for(prov, transport_factory=cancel_factory).execute(
        target=target, cancel_event=types.SimpleNamespace(is_set=lambda: False))
    case("10. annulation de transport = cancelled explicite",
         cancelled.status == "cancelled" and cancel_factory.transport.closed)

    remote_factory = OneTransportFactory(RemoteErrorTransport())
    remote_error = backend_for(prov, transport_factory=remote_factory).execute(target=target)
    case("11. erreur fonctionnelle de l'outil = failed, serveur considéré joignable",
         remote_error.status == "failed"
         and remote_error.availability is not None
         and remote_error.availability.status == "available"
         and "<masqué>" in remote_error.error
         and "BBBB" not in remote_error.error)

    unavailable_factory = OneTransportFactory(ServerDownTransport())
    server_error = backend_for(prov, transport_factory=unavailable_factory).execute(target=target)
    case("12. indisponibilité serveur = unavailable sans commande de repli",
         server_error.status == "unavailable"
         and server_error.availability is not None
         and server_error.availability.status == "unavailable")

    malformed_factory = OneTransportFactory(MalformedTransport())
    malformed = backend_for(prov, transport_factory=malformed_factory).execute(target=target)
    case("13. réponse MCP non conforme = invalid, pas de finding vide",
         malformed.status == "invalid" and malformed.output is None)

    isolation_factory = Factory()
    isolated_backend = backend_for(prov, transport_factory=isolation_factory)
    first = isolated_backend.execute(target=target)
    second = isolated_backend.execute(target=target)
    case("14. chaque exécution obtient et ferme une session isolée",
         first.status == "succeeded" and second.status == "succeeded"
         and len(isolation_factory.instances) == 2
         and isolation_factory.instances[0] is not isolation_factory.instances[1]
         and all(t.closed for t in isolation_factory.instances))

    # Ce cas ne lance pas OPA : il vérifie seulement la frontière d'entrée. La validation
    # d'OPA reste signalée comme bloquée si le binaire n'est pas installé dans l'image.
    # MCP-004 : le type de cible n'est plus un littéral passé à la policy. OPA lit le
    # descripteur STRUCTURÉ porté par le plan (`cible_descr` = Cible.to_dict()), donc le
    # type RÉEL de la cible. Le plan de test porte donc un vrai descripteur.
    descr_repo = CIB.normaliser(RACINE).to_dict()
    policy_plan = PL.construire("revue MCP", "repo://fixture", ["review_mcp"],
                                reg, "test-mcp", cible_descr=descr_repo)
    policy_input = PO.PolicyEngine.entree(policy_plan, reg, True)
    detail = policy_input["registre"]["providers_detail"][0]
    case("15. l'entrée OPA porte le binding enregistré, sans endpoint ni credential",
         detail["identity"]["server_id"] == "review-server"
         and detail["identity"]["tool"] == "review_code"
         and "endpoint" not in detail and "auth_env" not in detail
         and policy_input["cible"]["type"] == "repository"
         and policy_input["plan"]["steps"][0]["transport"] == "mcp")

    # La preuve que plus rien n'est codé en dur : une cible FICHIER doit annoncer
    # `filesystem` à OPA. Avec l'ancien littéral "repository", ce cas était impossible.
    descr_fichier = CIB.normaliser(Path(__file__)).to_dict()
    entree_fichier = PO.PolicyEngine.entree(
        PL.construire("revue MCP", "repo://fixture", ["review_mcp"], reg, "test-mcp",
                      cible_descr=descr_fichier), reg, True)
    case("15bis. le type de cible suit le descripteur réel, pas un littéral",
         entree_fichier["cible"]["type"] == "filesystem"
         and policy_input["cible"]["type"] == "repository",
         f"repo={policy_input['cible']['type']} fichier={entree_fichier['cible']['type']}")

    # ----------------------------------------------------------- adaptateur + normaliseur
    tmp = Path(tempfile.mkdtemp(prefix="agnt-mcp-simulated-"))
    adapter_factory = Factory()
    sbx = types.SimpleNamespace(timeout=60, racine_scan=Path("/tmp/repo"),
                                M_SCAN="/mnt/scan", sortie=tmp / "sandbox-sortie")
    sbx.sortie.mkdir(parents=True, exist_ok=True)
    brut = A.mcp(prov, sbx, target=target, transport_factory=adapter_factory)
    findings = F.normaliser(prov.id, brut.donnees, mani=prov.manifest, racines=())
    case("16. l'adaptateur produit le ResultatBrut commun", brut.statut == "succeeded"
         and brut.transport == "mcp" and brut.code_retour == 0)
    case("17. la sortie MCP passe par le normaliseur générique", len(findings) == 1
         and findings[0].source["tool"] == "review_code"
         and findings[0].source["provider"] == "review_mcp"
         and findings[0].source["transport"] == "mcp")
    case("18. la couverture porte la cible et l'état scanned_successfully",
         brut.couverture.to_dict()["cibles"] == [{
             "chemin": "repo://fixture", "etat": "scanned_successfully", "raison": ""}])

    # ----------------------------------------------------------- chemin pipeline existant
    old_missions = MS.MISSIONS
    try:
        MS.MISSIONS = tmp / "missions"
        miss = MS.ouvrir("Revue le code", "revue le code", Path("/tmp/repo"))
        sortie = tmp / "sortie"
        sortie.mkdir()
        execution = P.Execution(
            plan={"plan_id": "p-mcp", "steps": [{"provider": "review_mcp", "capability": "CODE_REVIEW"}],
                  "selection": {}},
            decision={"allow": True, "motifs": []}, profil="simulated")
        ctx = types.SimpleNamespace(outils={})
        tous = []
        trouves = {}
        V = P._ContexteVague(
            miss=miss, registre=reg, exec_=execution, sbx=sbx, cible=Path("/tmp/repo"),
            sortie=sortie, ctx=ctx, trouves=trouves, tous_findings=tous,
            domaines={"review_mcp": "code"}, binaires={"review_mcp": "review_code"},
            transport_factories={"review_mcp": Factory()})
        step = types.SimpleNamespace(provider="review_mcp")
        P._vague([step], V, execution.plan, execution.decision,
                 "2026-08-30T00:00:00+00:00", 1)
        ledger = ST.construire(reg, execution.plan, execution.decision,
                               execution.raw, execution.couverture, trouves)
        entry = ledger[0]
        case("19. le pipeline existant consigne un appel MCP sans second orchestrateur",
             len(tous) == 1 and execution.raw[0]["transport"] == "mcp"
             and entry["transport"] == "mcp" and entry["statut"] == "execute"
             and entry["disponibilite"]["status"] == "available")
        case("20. brut reconstruit et sortie MCP brute sont archivés séparément",
             (sortie / "raw_review_mcp.json").is_file()
             and (sortie / "brut_review_mcp.json").is_file())
        case("21. corrélation mission/provider/outil conservée",
             execution.raw[0]["correlation_id"] == "review_mcp:review_code"
             and execution.raw[0]["request_id"] == "3"
             and execution.raw[0]["identite_provider"]["server_id"] == "review-server")
        case("22. la vue finding expose la version MCP hors contexte binaire local",
             F.vue_unifiee(tous[0])["version_outil"] == "7"
             and F.vue_unifiee(tous[0])["outil_provider"]["name"] == "review_code")
    finally:
        MS.MISSIONS = old_missions
        shutil.rmtree(tmp, ignore_errors=True)

    failures = [name for name, condition, _ in cases if not condition]
    print(f"\n{len(cases) - len(failures)}/{len(cases)} cas passent")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
