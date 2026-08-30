#!/usr/bin/env python3
"""Intégration MCP HTTP locale réelle — INTEGRATION REAL CONTROLLED.

Le serveur est une ``ThreadingHTTPServer`` démarrée par ce test, sur loopback et port
éphémère. Il n'y a ni serveur tiers, ni Internet, ni credential. La batterie distingue
ce qui traverse réellement HTTP/JSON-RPC de l'intégration simulée de ``test_mcp.py``.
"""
from __future__ import annotations

import atexit
import dataclasses
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import findings as F  # noqa: E402
import mission as MS  # noqa: E402
import pipeline as PIPE  # noqa: E402
import mcp_bootstrap as MB  # noqa: E402
from mcp_provider import backend_for  # noqa: E402
from mcp_transport import HTTPMCPTransport  # noqa: E402
from provider_contract import Target  # noqa: E402
from registre import Registry  # noqa: E402
import transports  # noqa: E402


SECRET = "ghp_" + "R" * 36
YAML_TEMPLATE = """
version: 1
capabilities:
  - id: CODE_STATIC_ANALYSIS
    description: Revue contrôlée
    domaines: [code]
    entree: [cible]
    sortie: finding/code-issue
    providers:
      - id: review_http
        transport: mcp
        kind: api
        risque: PASSIVE
        mcp:
          server:
            id: controlled-http-server
            version: '1.0'
            transport: SERVER_TRANSPORT
            endpoint: ENDPOINT
            auth_env: MCP_TEST_TOKEN
          tool:
            name: review_code
            version: '1'
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
          timeout_s: 1
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


class ControlledMCPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):  # noqa: N802 - API http.server
        server: ControlledMCPServer = self.server  # type: ignore[assignment]
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        server.requests.append({"headers": dict(self.headers), "body": body})
        try:
            request = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._bytes(b"not-json", "text/plain")
            return
        method = request.get("method")
        server.methods.append(method)
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if server.scenario == "slow" and method == "tools/call":
            time.sleep(0.35)
        if server.scenario == "handshake_error" and method == "initialize":
            self._json({"jsonrpc": "2.0", "id": request.get("id"),
                        "result": {"serverInfo": {"name": "broken"}}})
            return
        if server.scenario == "malformed" and method == "tools/list":
            self._bytes(b"{malformed", "application/json")
            return
        if server.scenario == "too_large" and method == "tools/list":
            self._json({"jsonrpc": "2.0", "id": request.get("id"),
                        "result": {"tools": [{"name": "review_code",
                                                "description": "X" * 4000}]}})
            return
        if server.scenario == "http_timeout" and method == "tools/list":
            self.send_response(504)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if server.scenario == "remote_error" and method == "tools/call":
            self._json({"jsonrpc": "2.0", "id": request.get("id"),
                        "error": {"code": -32001,
                                  "message": f"remote failure {SECRET}"}})
            return
        if method == "initialize":
            self._json({"jsonrpc": "2.0", "id": request.get("id"),
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "serverInfo": {"name": "controlled-http-server", "version": "1.0"},
                        }})
        elif method == "tools/list":
            tools = [{"name": "review_code", "inputSchema": {
                "type": "object", "properties": {"remote_canary": {"type": "string"}},
            }}, {"name": "rogue_tool", "description": "never authorized"}]
            if server.scenario == "missing_tool":
                tools = [{"name": "rogue_tool"}]
            self._json({"jsonrpc": "2.0", "id": request.get("id"),
                        "result": {"tools": tools}})
        elif method == "tools/call":
            server.tool_calls.append(request.get("params") or {})
            params = request.get("params") or {}
            payload = {"results": [{
                "rule": "review.no-eval", "file": "src/app.py", "line": 12,
                "message": (f"remote output contains {SECRET}"
                             if server.scenario == "secret" else "avoid eval"),
                "severity": "HIGH",
            }]}
            self._json({"jsonrpc": "2.0", "id": request.get("id"),
                        "result": {"structuredContent": payload,
                                   "_untrusted": params.get("arguments", {})}})
        else:
            self._json({"jsonrpc": "2.0", "id": request.get("id"),
                        "error": {"code": -32601, "message": "unknown method"}})

    def _json(self, value: dict):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        if self.server.scenario == "streamable":
            body = b"event: message\ndata: " + body + b"\n\n"
            self._bytes(body, "text/event-stream")
            return
        self._bytes(body, "application/json")

    def _bytes(self, body: bytes, content_type: str):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "controlled-session")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            # Le client a volontairement abandonné la réponse lente après timeout.
            pass

    def log_message(self, *_args):
        return


class ControlledMCPServer(ThreadingHTTPServer):
    # Les handlers sont joints par server_close : même le scénario lent ne laisse
    # pas de thread de serveur après le test.
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def __init__(self, scenario="ok"):
        super().__init__(("127.0.0.1", 0), ControlledMCPHandler)
        self.scenario = scenario
        self.requests: list[dict] = []
        self.methods: list[str] = []
        self.tool_calls: list[dict] = []
        self.thread = threading.Thread(target=self.serve_forever,
                                        name="agnt-controlled-mcp", daemon=True)
        self.thread.start()

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise AssertionError("serveur MCP de test encore vivant")



_CONFIGS: list[Path] = []


def _nettoyer_configs() -> None:
    for chemin in _CONFIGS:
        chemin.unlink(missing_ok=True)


atexit.register(_nettoyer_configs)


def registry_for(endpoint: str, server_transport: str = "http") -> Registry:
    # ``Registry.empreinte()`` relit la déclaration au moment du plan. Le fichier
    # temporaire reste donc présent jusqu'à la fin de la batterie, puis est supprimé
    # par le nettoyage normal/atexit.
    handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    try:
        handle.write(YAML_TEMPLATE.replace("ENDPOINT", endpoint)
                     .replace("SERVER_TRANSPORT", server_transport))
        handle.close()
        reg = Registry(handle.name)
        _CONFIGS.append(Path(handle.name))
        return reg
    except Exception:
        handle.close()
        Path(handle.name).unlink(missing_ok=True)
        raise


def main() -> int:
    cases: list[tuple[str, bool, str]] = []

    def case(name, condition, detail=""):
        cases.append((name, bool(condition), detail))
        print(("OK    " if condition else "ECHEC ") + name
              + (f" — {detail}" if detail else ""))

    # Le transport CORE est enregistré une fois avant les registres de test.
    if not transports.fournit("mcp"):
        MB.initialiser_mcp(transports)

    # --------------------------------------------------------------- cycle réel
    server = ControlledMCPServer()
    try:
        reg = registry_for(server.endpoint)
        prov = reg.provider("review_http")
        result = backend_for(prov).execute(target=Target("repository", "repo://controlled"))
        calls = [json.loads(x["body"].decode("utf-8")) for x in server.requests
                 if json.loads(x["body"].decode("utf-8")).get("id") is not None]
        call = next((x for x in calls if x.get("method") == "tools/call"), {})
        case("1. serveur MCP HTTP local réel : cycle initialize/list/call",
             result.status == "succeeded"
             and server.methods == ["initialize", "notifications/initialized",
                                    "tools/list", "tools/call"],
             str(server.methods))
        case("2. notification initialized et session MCP sont réellement transportées",
             all(x["headers"].get("Mcp-Session-Id") == "controlled-session"
                 for x in server.requests[1:]))
        case("3. serveur réel ne peut pas choisir l'outil",
             call.get("params", {}).get("name") == "review_code"
             and not any(x.get("params", {}).get("name") == "rogue_tool" for x in calls))
        case("4. cible et arguments atteignent tools/call via le binding enregistré",
             call.get("params", {}).get("arguments") == {"repository": "repo://controlled"})
        findings = F.normaliser(prov.id, result.output, mani=prov.manifest, racines=())
        case("5. réponse HTTP réelle normalisée en finding AGNT",
             len(findings) == 1
             and findings[0].source["transport"] == "mcp"
             and findings[0].source["tool"] == "review_code"
             and findings[0].source["server_id"] == "controlled-http-server")

        # Une passe contrôlée par le pipeline unique vérifie que le cycle réseau ci-dessus
        # ne contourne ni mission, ni ledger, ni rapport. Le profil réseau est remplacé
        # uniquement dans le test par une valeur explicitement autorisée ; le profil réel
        # du checkout reste fermé et le cas policy/egress est couvert séparément.
        class AllowPolicy:
            def evaluer(self, *args, **kwargs):
                return types.SimpleNamespace(allow=True, motifs=())

        pipeline_tmp = Path(tempfile.mkdtemp(prefix="agnt-mcp-pipeline-"))
        target = pipeline_tmp / "repo"
        target.mkdir()
        old_missions, old_sortie = MS.MISSIONS, PIPE.SORTIE
        old_profile = PIPE.profils.CONTROLLED_DEV
        MS.MISSIONS = pipeline_tmp / "missions"
        PIPE.SORTIE = pipeline_tmp / "sortie"
        PIPE.profils.CONTROLLED_DEV = dataclasses.replace(
            old_profile, reseau_autorise=True,
            commentaire="profil réseau explicitement activé par le test local")
        try:
            execution = PIPE.executer(
                "Analyse le code", target, egress=True, registre=reg,
                policy_engine=AllowPolicy(), escalade=False)
            journal = MS.journal(MS.relire(execution.mission))
            case("6. pipeline unique HTTP réel : mission, ledger et finding",
                 execution.arret == "" and len(execution.findings) == 1
                 and execution.raw[0]["transport"] == "mcp"
                 and execution.raw[0]["correlation_id"] == "review_http:review_code"
                 and any(x.get("type") == "statuts" for x in journal))
            case("7. pipeline unique rapporte l'identité MCP structurée",
                 execution.rapport["providers"][0]["transport"] == "mcp"
                 and execution.rapport["providers"][0]["server"]["id"]
                 == "controlled-http-server"
                 and execution.findings[0]["source"]["tool"] == "review_code")
        finally:
            MS.MISSIONS, PIPE.SORTIE = old_missions, old_sortie
            PIPE.profils.CONTROLLED_DEV = old_profile
            shutil.rmtree(pipeline_tmp, ignore_errors=True)
    finally:
        server.close()

    # ------------------------------------------------------------ Streamable HTTP
    streamable = ControlledMCPServer("streamable")
    try:
        reg = registry_for(streamable.endpoint, "streamable_http")
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"))
        case("8. Streamable HTTP réel : événement SSE JSON accepté",
             result.status == "succeeded"
             and streamable.methods == ["initialize", "notifications/initialized",
                                        "tools/list", "tools/call"],
             str(streamable.methods))
    finally:
        streamable.close()

    # --------------------------------------------------------- refus discovery
    missing = ControlledMCPServer("missing_tool")
    try:
        reg = registry_for(missing.endpoint)
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"))
        case("9. outil annoncé absent = unavailable, aucun tools/call réel",
             result.status == "unavailable" and not missing.tool_calls,
             result.error)
    finally:
        missing.close()

    # ---------------------------------------------------------- données hostiles
    secret_server = ControlledMCPServer("secret")
    old_token = os.environ.get("MCP_TEST_TOKEN")
    os.environ["MCP_TEST_TOKEN"] = SECRET
    try:
        reg = registry_for(secret_server.endpoint)
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"))
        authorization = [x["headers"].get("Authorization", "") for x in secret_server.requests]
        case("10. credential référencé par env transmis sans apparaître dans le résultat",
             authorization and authorization[0] == f"Bearer {SECRET}"
             and SECRET not in json.dumps(result.output, ensure_ascii=False)
             and SECRET not in json.dumps(result.raw, ensure_ascii=False)
             and "<masqué>" in json.dumps(result.output, ensure_ascii=False))
    finally:
        if old_token is None:
            os.environ.pop("MCP_TEST_TOKEN", None)
        else:
            os.environ["MCP_TEST_TOKEN"] = old_token
        secret_server.close()

    error_server = ControlledMCPServer("remote_error")
    try:
        reg = registry_for(error_server.endpoint)
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"))
        case("11. erreur JSON-RPC réelle = failed et message masqué",
             result.status == "failed" and SECRET not in result.error
             and "<masqué>" in result.error)
    finally:
        error_server.close()

    malformed = ControlledMCPServer("malformed")
    try:
        reg = registry_for(malformed.endpoint)
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"))
        case("12. JSON malformé réel = invalid sans finding", result.status == "invalid"
             and result.output is None)
    finally:
        malformed.close()

    too_large = ControlledMCPServer("too_large")
    try:
        reg = registry_for(too_large.endpoint)
        result = backend_for(reg.provider("review_http"),
                             transport_factory=lambda mani: HTTPMCPTransport(
                                 mani.endpoint, max_response_bytes=1024)).execute(
            target=Target("repository", "repo://controlled"))
        case("13. réponse HTTP réelle trop grande = invalid", result.status == "invalid")
    finally:
        too_large.close()

    # -------------------------------------------------------- disponibilité/temps
    handshake = ControlledMCPServer("handshake_error")
    try:
        reg = registry_for(handshake.endpoint)
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"))
        case("14. handshake réel incomplet = invalid", result.status == "invalid")
    finally:
        handshake.close()

    slow = ControlledMCPServer("slow")
    try:
        reg = registry_for(slow.endpoint)
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"), timeout=0.05)
        case("15. réponse HTTP réelle lente = timed_out", result.status == "timed_out")
    finally:
        slow.close()

    http_timeout = ControlledMCPServer("http_timeout")
    try:
        reg = registry_for(http_timeout.endpoint)
        result = backend_for(reg.provider("review_http")).execute(
            target=Target("repository", "repo://controlled"))
        case("16. HTTP 504 réel = timed_out, pas unavailable",
             result.status == "timed_out", result.error)
    finally:
        http_timeout.close()

    unavailable = ControlledMCPServer()
    endpoint = unavailable.endpoint
    unavailable.close()
    reg = registry_for(endpoint)
    result = backend_for(reg.provider("review_http")).execute(
        target=Target("repository", "repo://controlled"), timeout=0.2)
    case("17. endpoint local fermé = unavailable, distinct de timeout",
         result.status == "unavailable", result.error)

    # Les artefacts de mission du passage pipeline sont temporaires et supprimés ; la
    # fermeture de chaque serveur est la preuve de nettoyage du test transport.
    failures = [name for name, condition, _ in cases if not condition]
    _nettoyer_configs()
    print(f"\n{len(cases) - len(failures)}/{len(cases)} cas passent")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
