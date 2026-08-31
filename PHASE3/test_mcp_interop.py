#!/usr/bin/env python3
"""Interop MCP contre le SDK Python officiel, dans un processus stdio isolé.

INTEGRATION REAL INDEPENDENT : le framing JSON-RPC, le handshake, la validation des
messages et le serveur MCP sont fournis par ``mcp==2.1.1``. Le fichier temporaire
créé par ce test ne fait qu'enregistrer deux fonctions-outils déterministes et un
marqueur d'audit minimal ; il ne réimplémente ni MCP ni son transport.

La dépendance reste volontairement hors du dépôt. Reproduction :

    python -m venv /tmp/agnt-mcp-interop-venv
    /tmp/agnt-mcp-interop-venv/bin/python -m pip install --no-cache-dir 'mcp==2.1.1'
    MCP_INTEROP_PYTHON=/tmp/agnt-mcp-interop-venv/bin/python \
      PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python \
      PHASE3/test_mcp_interop.py

Le test échoue honnêtement avec le statut ``BLOCKED`` si le chemin du venv n'est
pas fourni ou si le SDK n'est pas disponible. Aucun serveur public ou credential
n'est utilisé.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import types
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import mission as MS  # noqa: E402
import mcp_bootstrap as MB  # noqa: E402
import mcp_provider as MP  # noqa: E402
import pipeline as PIPE  # noqa: E402
import policy as PO  # noqa: E402
from mcp_transport import StdioMCPTransport  # noqa: E402
from provider_contract import Target  # noqa: E402
from registre import Registry  # noqa: E402
import transports  # noqa: E402


SDK_VERSION = "2.1.1"
PROTOCOL_VERSION = "2025-06-18"
TARGET_VALUE = "independent-sdk-fixture"

# Ce code est exécuté par le Python du venv MCP, pas par l'interpréteur AGNT. Le
# protocole et le serveur proviennent du SDK indépendant ; seuls les outils de test
# et le marqueur d'audit sont définis ici.
INDEPENDENT_SERVER = r'''
from __future__ import annotations

import importlib.metadata
import json
import os
import sys
import time
from pathlib import Path

from mcp.server.mcpserver import MCPServer

SDK_VERSION = "2.1.1"
if importlib.metadata.version("mcp") != SDK_VERSION:
    raise RuntimeError("unexpected mcp SDK version")

mode = sys.argv[1]
audit_path = Path(sys.argv[2])


def audit(tool: str) -> None:
    # Aucun argument, chemin de cible ou payload n'est écrit dans l'artefact : le
    # test n'a besoin que de savoir quelle fonction du serveur a été invoquée.
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"tool": tool}, separators=(",", ":")) + "\n")


server = MCPServer(name="official-python-sdk", version=SDK_VERSION)

if mode != "missing":
    @server.tool(name="review_code", description="Deterministic local review",
                 structured_output=True)
    def review_code(repository: str, remote_canary: str | None = None) -> dict[str, object]:
        audit("review_code")
        if mode == "reject":
            raise RuntimeError("deterministic independent rejection")
        if mode == "timeout":
            time.sleep(2.0)
        if mode == "close":
            os._exit(0)
        return {
            "results": [{
                "rule": "interop.no-eval",
                "file": "src/independent.py",
                "line": 7,
                "message": "avoid eval",
                "severity": "HIGH",
            }],
            "called_tool": "review_code",
            "repository_seen": repository,
            "remote_canary_seen": remote_canary,
            "sdk_version": SDK_VERSION,
        }


@server.tool(name="rogue_tool", description="Must not be called",
             structured_output=False)
def rogue_tool(repository: str) -> str:
    audit("rogue_tool")
    return "rogue-called"


if __name__ == "__main__":
    server.run("stdio")
'''

YAML_TEMPLATE = """
version: 1
capabilities:
  - id: CODE_REVIEW
    description: Revue fournie par une implémentation MCP indépendante
    domaines: [code]
    entree: [cible]
    sortie: finding/code-issue
    providers:
      - id: independent_sdk
        transport: mcp
        kind: api
        risque: PASSIVE
        mcp:
          server:
            id: official-python-sdk
            version: '2.1.1'
            transport: stdio
            command: COMMAND
          tool: {name: review_code, version: '1'}
          protocol_version: '2025-06-18'
          trust: untrusted_local
          target_types: [repository]
          target_argument: repository
          argument_schema:
            type: object
            properties: {repository: {type: string, maxLength: 200}}
            required: [repository]
            additionalProperties: false
          timeout_s: 3
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
"""


class RecordingStdioTransport(StdioMCPTransport):
    """Observateur passif du transport AGNT, sans modifier le protocole."""

    def __init__(self, command):
        super().__init__(command)
        self.methods: list[str] = []
        self.notifications: list[str] = []
        self.initialize_response: dict | None = None
        self.tools_response: dict | None = None
        self.process = None

    def _demarrer(self):
        state = super()._demarrer()
        self.process = state.process
        return state

    def request(self, method, params=None, **kwargs):
        self.methods.append(method)
        response = super().request(method, params, **kwargs)
        if method == "initialize":
            self.initialize_response = response
        elif method == "tools/list":
            self.tools_response = response
        return response

    def notify(self, method, params=None):
        self.notifications.append(method)
        return super().notify(method, params)



class AllowPolicy:
    def evaluer(self, *args, **kwargs):
        return types.SimpleNamespace(allow=True, motifs=())


class UnavailablePolicy:
    def evaluer(self, *args, **kwargs):
        raise PO.PolicyError("OPA absent dans le test d'interopérabilité")


class CountingFactory:
    def __init__(self):
        self.calls = 0
        self.transports: list[RecordingStdioTransport] = []

    def __call__(self, manifest):
        self.calls += 1
        transport = RecordingStdioTransport(manifest.command)
        self.transports.append(transport)
        return transport


def _quote_command(parts: list[str]) -> str:
    return "[" + ", ".join(json.dumps(str(part), ensure_ascii=False) for part in parts) + "]"


def registry_for(root: Path, python: Path, server: Path, mode: str,
                 audit: Path, label: str) -> Registry:
    command = _quote_command([str(python), str(server), mode, str(audit)])
    config = root / f"{label}.yaml"
    config.write_text(YAML_TEMPLATE.replace("COMMAND", command), encoding="utf-8")
    return Registry(config)


def audit_tools(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [json.loads(line)["tool"] for line in path.read_text(encoding="utf-8").splitlines()
            if line]


def result_json(result) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True)


def run_backend(root: Path, python: Path, server: Path, mode: str, label: str,
                *, timeout: float = 3, cancel_event=None):
    audit = root / f"{label}.audit"
    registry = registry_for(root, python, server, mode, audit, label)
    provider = registry.provider("independent_sdk")
    factory = CountingFactory()
    result = MP.backend_for(provider, transport_factory=factory).execute(
        target=Target("repository", TARGET_VALUE),
        timeout=timeout,
        cancel_event=cancel_event,
    )
    transport = factory.transports[0] if factory.transports else None
    return result, transport, audit, registry, provider, factory


def main() -> int:
    python_value = os.environ.get("MCP_INTEROP_PYTHON", "")
    if not python_value:
        print("BLOCKED: MCP_INTEROP_PYTHON n'est pas défini")
        return 2
    # Ne pas appeler ``resolve()`` ici : les venv Python sont souvent un lien
    # symbolique vers le binaire système, et sa résolution ferait perdre les
    # site-packages du SDK indépendant.
    python = Path(python_value).expanduser()
    if not python.is_file() or not os.access(python, os.X_OK):
        print(f"BLOCKED: interpréteur MCP introuvable ou non exécutable: {python}")
        return 2

    cases: list[tuple[str, bool, str]] = []

    def case(name: str, condition: bool, detail: str = "") -> None:
        cases.append((name, bool(condition), detail))
        print(("OK    " if condition else "ECHEC ") + name
              + (f" — {detail}" if detail else ""))

    if not transports.fournit("mcp"):
        MB.initialiser_mcp(transports)

    root = Path(tempfile.mkdtemp(prefix="agnt-mcp-interop-"))
    server = root / "independent_server.py"
    server.write_text(INDEPENDENT_SERVER, encoding="utf-8")
    try:
        # ---------------------------------------------------------- cycle réel SDK
        result, transport, audit, _, provider, _ = run_backend(
            root, python, server, "ok", "success")
        output = result.output or {}
        initialization = transport.initialize_response if transport else {}
        init_result = (initialization or {}).get("result") or {}
        case("1. SDK indépendant chargé dans le processus enfant",
             output.get("sdk_version") == SDK_VERSION
             and provider.manifest.server_id == "official-python-sdk")
        case("2. handshake accepté avec la version demandée",
             result.status == "succeeded"
             and init_result.get("protocolVersion") == PROTOCOL_VERSION
             and (init_result.get("serverInfo") or {}).get("name") == "official-python-sdk")
        case("3. request_id et correlation_id restent corrélés",
             result.request_id == "3"
             and result.correlation_id == "independent_sdk:review_code"
             and provider.manifest.protocol_version == PROTOCOL_VERSION)
        case("4. séquence MCP réelle du SDK : initialize/list/call + initialized",
             transport is not None
             and transport.methods == ["initialize", "tools/list", "tools/call"]
             and transport.notifications == ["notifications/initialized"])

        tools_result = transport.tools_response if transport else {}
        tools = ((tools_result or {}).get("result") or {}).get("tools") or []
        tool_names = [tool.get("name") for tool in tools if isinstance(tool, dict)]
        review_description = next((tool for tool in tools
                                   if isinstance(tool, dict)
                                   and tool.get("name") == "review_code"), {})
        remote_properties = ((review_description.get("inputSchema") or {})
                             .get("properties") or {})
        case("5. tools/list du SDK annonce l'outil autorisé et un outil rogue",
             "review_code" in tool_names and "rogue_tool" in tool_names
             and "remote_canary" in remote_properties)
        case("6. découverte informative : rogue_tool n'est jamais appelé",
             tool_names.count("rogue_tool") == 1
             and audit_tools(audit) == ["review_code"]
             and output.get("called_tool") == "review_code")
        case("7. binding et schéma AGNT ne sont pas élargis par tools/list",
             list(provider.manifest.argument_schema["properties"]) == ["repository"]
             and output.get("repository_seen") == TARGET_VALUE
             and output.get("remote_canary_seen") is None)
        case("8. réponse SDK valide, résultat et secrets restent bornés",
             result.status == "succeeded"
             and output.get("results", [{}])[0].get("rule") == "interop.no-eval"
             and str(root) not in result_json(result)
             and str(root) not in json.dumps(result.raw, ensure_ascii=False)
             and result_json(result).count("remote_canary") == 1)

        # ------------------------------------------------------ pipeline / ledger
        pipeline_audit = root / "pipeline.audit"
        pipeline_registry = registry_for(root, python, server, "ok", pipeline_audit, "pipeline")
        target = root / "repository"
        target.mkdir()
        missions = root / "missions"
        # `pipeline.SORTIE` n'existe plus (CORE : artefacts par mission dans
        # `<mission>/run`) ; rediriger MS.MISSIONS suffit.
        old_missions = MS.MISSIONS
        MS.MISSIONS = missions
        pipeline_factory = CountingFactory()
        try:
            execution = PIPE.executer(
                "Analyse le code", target, egress=False,
                registre=pipeline_registry, policy_engine=AllowPolicy(), escalade=False,
                transport_factories={"independent_sdk": pipeline_factory},
            )
            journal = MS.journal(MS.relire(execution.mission))
            stat_events = [event for event in journal if event.get("type") == "statuts"]
            stat_tools = [tool for event in stat_events for tool in event.get("outils", [])]
            case("9. appel SDK indépendant traverse le pipeline normalisé",
                 execution.arret == ""
                 and len(execution.findings) == 1
                 and execution.findings[0]["source"]["server_id"] == "official-python-sdk"
                 and execution.findings[0]["source"]["tool"] == "review_code")
            case("10. ledger, rapport et corrélation sont conservés",
                 execution.raw
                 and execution.raw[0]["statut"] == "succeeded"
                 and execution.raw[0]["request_id"] == "3"
                 and execution.raw[0]["correlation_id"] == "independent_sdk:review_code"
                 and any(tool.get("request_id") == "3" for tool in stat_tools)
                 and execution.rapport["providers"][0]["server"]["id"] == "official-python-sdk"
                 and execution.rapport["providers"][0]["tool"]["name"] == "review_code")
            case("11. egress fermé est tracé, sans endpoint HTTP pour le profil stdio",
                 execution.rapport["egress"]["autorise"] is False
                 and pipeline_registry.provider("independent_sdk").manifest.endpoint == "")
        finally:
            MS.MISSIONS = old_missions

        # ------------------------------------------------------ outil absent
        missing, missing_transport, missing_audit, _, _, _ = run_backend(
            root, python, server, "missing", "missing")
        missing_tools = ((missing_transport.tools_response or {}).get("result") or {}).get("tools", []) \
            if missing_transport else []
        case("12. outil autorisé absent = unavailable, sans appel rogue",
             missing.status == "unavailable"
             and missing.availability is not None
             and missing.availability.status == "unavailable"
             and [tool.get("name") for tool in missing_tools] == ["rogue_tool"]
             and audit_tools(missing_audit) == []
             and missing_transport is not None
             and missing_transport.methods == ["initialize", "tools/list"])

        # ---------------------------------------------------------- erreur distante
        rejected, _rejected_transport, rejected_audit, _, _, _ = run_backend(
            root, python, server, "reject", "reject")
        case("13. rejet fonctionnel du SDK = failed, serveur disponible",
             rejected.status == "failed"
             and rejected.availability is not None
             and rejected.availability.status == "available"
             and audit_tools(rejected_audit) == ["review_code"]
             and SDK_VERSION not in rejected.error
             and str(root) not in result_json(rejected)
             and str(root) not in json.dumps(rejected.raw, ensure_ascii=False))

        # -------------------------------------------------------------- timeout
        timed, timed_transport, timed_audit, _, _, _ = run_backend(
            root, python, server, "timeout", "timeout", timeout=1)
        case("14. outil SDK lent = timed_out, pas failed ni succeeded",
             timed.status == "timed_out"
             and timed.status not in ("failed", "succeeded")
             and audit_tools(timed_audit) == ["review_code"])
        case("15. timeout rejoint et récolte le processus SDK",
             timed_transport is not None
             and timed_transport.process is not None
             and timed_transport.process.poll() is not None
             and timed_transport._state is None)

        # ---------------------------------------------------------- fermeture
        closed, closed_transport, closed_audit, _, _, _ = run_backend(
            root, python, server, "close", "close")
        case("16. fermeture inattendue du processus SDK = unavailable",
             closed.status == "unavailable"
             and closed.availability is not None
             and closed.availability.status == "unavailable"
             and audit_tools(closed_audit) == ["review_code"]
             and closed_transport is not None
             and closed_transport.process is not None
             and closed_transport.process.poll() is not None)

        # ---------------------------------------------------------- serveur absent
        absent_script = root / "server_absent.py"
        absent, absent_transport, absent_audit, _, _, _ = run_backend(
            root, python, absent_script, "ok", "absent")
        case("17. serveur absent = unavailable sans succès vide",
             absent.status == "unavailable"
             and absent.output is None
             and absent_transport is not None
             and absent_transport.process is not None
             and absent_transport.process.poll() is not None
             and audit_tools(absent_audit) == [])

        # ------------------------------------------------ annulation avant spawn
        cancel = threading.Event()
        cancel.set()
        early, early_transport, early_audit, _, _, early_factory = run_backend(
            root, python, server, "ok", "early_cancel", cancel_event=cancel)
        case("18. annulation pré-invocation = cancelled sans processus SDK",
             early.status == "cancelled"
             and early_transport is None
             and early_factory.calls == 0
             and audit_tools(early_audit) == [])

        # ---------------------------------------------- policy unavailable gate
        gate_audit = root / "policy.audit"
        gate_registry = registry_for(root, python, server, "ok", gate_audit, "policy")
        gate_target = root / "policy-repository"
        gate_target.mkdir()
        gate_missions = root / "policy-missions"
        old_missions = MS.MISSIONS
        MS.MISSIONS = gate_missions
        gate_factory = CountingFactory()
        try:
            try:
                PIPE.executer(
                    "Analyse le code", gate_target, egress=False,
                    registre=gate_registry, policy_engine=UnavailablePolicy(), escalade=False,
                    transport_factories={"independent_sdk": gate_factory},
                )
                policy_error = None
            except PO.PolicyError as exc:
                policy_error = exc
            case("19. policy indisponible = zéro lancement du SDK indépendant",
                 policy_error is not None
                 and gate_factory.calls == 0
                 and audit_tools(gate_audit) == [])
        finally:
            MS.MISSIONS = old_missions

        # ---------------------------------------------------- appel successif
        following, following_transport, following_audit, _, _, _ = run_backend(
            root, python, server, "ok", "following")
        case("20. appel successif = nouvelle session sans contamination",
             following.status == "succeeded"
             and following.request_id == "3"
             and following_transport is not None
             and following_transport.methods == ["initialize", "tools/list", "tools/call"]
             and audit_tools(following_audit) == ["review_code"])

        # Les scénarios de réponse JSON-RPC malformée et d'incompatibilité de protocole
        # ne sont pas fabriqués ici : le SDK indépendant ne fournit pas une API de test
        # supportée pour violer son propre framing. Ils restent NOT EXERCISED.
    finally:
        shutil.rmtree(root, ignore_errors=True)

    failures = [name for name, condition, _ in cases if not condition]
    print(f"\n{len(cases) - len(failures)}/{len(cases)} cas passent")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
