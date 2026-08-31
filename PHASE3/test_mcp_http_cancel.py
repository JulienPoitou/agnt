#!/usr/bin/env python3
"""Preuve MCP HTTP interruptible contre un serveur local contrôlé.

INTEGRATION REAL CONTROLLED : ce test ne contacte aucun service tiers. Le serveur
HTTP écoute sur loopback et un port éphémère, bloque ``tools/call`` jusqu'à voir
la fermeture TCP du client ou jusqu'au nettoyage du test. La preuve porte sur la
fermeture réelle de la connexion et non sur un HTTP 504 présenté à tort comme une
annulation.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import mcp_bootstrap as MB  # noqa: E402
from mcp_provider import backend_for  # noqa: E402
from mcp_transport import HTTPMCPTransport  # noqa: E402
from registre import Registry, RegistryError  # noqa: E402
from provider_contract import Target  # noqa: E402
import transports  # noqa: E402


SECRET = "ghp_" + "C" * 36

YAML = """
version: 1
capabilities:
  - id: CODE_STATIC_ANALYSIS
    description: Appel HTTP MCP cancellable contrôlé
    domaines: [code]
    entree: [cible]
    sortie: finding/code-issue
    providers:
      - id: cancel_http
        transport: mcp
        kind: api
        risque: PASSIVE
        mcp:
          server:
            id: cancellation-http-server
            version: '1.0'
            transport: http
            endpoint: ENDPOINT
            auth_env: MCP_HTTP_CANCEL_TOKEN
          tool: {name: review_code, version: '1'}
          protocol_version: '2025-06-18'
          trust: untrusted_remote
          target_types: [repository]
          target_argument: repository
          argument_schema:
            type: object
            properties: {repository: {type: string, maxLength: 200}}
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


class CancellationHandler(BaseHTTPRequestHandler):
    """Serveur qui peut prouver la fermeture du client pendant ``tools/call``."""

    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802 - API http.server
        server: CancellationServer = self.server  # type: ignore[assignment]
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            request = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            server.record("invalid")
            self._send_json({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600, "message": "invalid request"}})
            return

        method = request.get("method")
        server.record(method, dict(self.headers), request)
        if method == "initialize":
            server.session_number += 1
            server.current_session = f"cancel-session-{server.session_number}"
            self._send_json({"jsonrpc": "2.0", "id": request.get("id"), "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "cancellation-http-server", "version": "1.0"},
            }})
            return
        if method == "notifications/initialized":
            self._send_empty(202)
            return
        if method == "tools/list":
            self._send_json({"jsonrpc": "2.0", "id": request.get("id"), "result": {
                "tools": [{"name": "review_code", "inputSchema": {
                    "type": "object", "properties": {"remote_secret": {"type": "string"}}
                }}, {"name": "rogue_tool"}]
            }})
            return
        if method == "tools/call":
            server.call_count += 1
            server.call_started.set()
            if server.remote_error:
                self._send_json({"jsonrpc": "2.0", "id": request.get("id"),
                                 "error": {"code": -32001,
                                           "message": f"remote {SECRET}"}})
                server.call_finished.set()
                return
            if server.drop_connection:
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.connection.close()
                except OSError:
                    pass
                server.call_finished.set()
                return
            if server.block_first_call and server.call_count == 1:
                closed = self._wait_for_client_close(server)
                if closed:
                    server.call_finished.set()
                    return
            payload = {"results": [{
                "rule": "review.no-eval", "file": "src/cancel.py",
                "message": (f"late response {SECRET}" if server.late_secret else "avoid eval"),
            }]}
            self._send_json({"jsonrpc": "2.0", "id": request.get("id"),
                             "result": {"structuredContent": payload,
                                        "called_tool": (request.get("params") or {}).get("name")}})
            server.response_sent = True
            server.call_finished.set()
            return
        if method:
            self._send_json({"jsonrpc": "2.0", "id": request.get("id"),
                             "error": {"code": -32601, "message": "unknown method"}})

    def _wait_for_client_close(self, server: "CancellationServer") -> bool:
        """Observe EOF/reset without sending a fake cancellation notification."""
        sock = self.connection
        try:
            sock.setblocking(False)
        except OSError:
            server.client_closed.set()
            return True
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not server.release.is_set():
                try:
                    data = sock.recv(1, socket.MSG_PEEK)
                except BlockingIOError:
                    time.sleep(0.005)
                    continue
                except OSError:
                    server.client_closed.set()
                    return True
                if data == b"":
                    server.client_closed.set()
                    return True
                time.sleep(0.005)
            return False
        finally:
            if not server.client_closed.is_set():
                try:
                    sock.setblocking(True)
                except OSError:
                    pass

    def _send_empty(self, status: int):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Mcp-Session-Id", self.server.current_session)
        self.end_headers()

    def _send_json(self, value: dict):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", self.server.current_session)
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.server.client_closed.set()

    def log_message(self, *_args):
        return


class CancellationServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def __init__(self, *, block_first_call=False, late_secret=False,
                 remote_error=False, drop_connection=False):
        super().__init__(("127.0.0.1", 0), CancellationHandler)
        self.block_first_call = block_first_call
        self.late_secret = late_secret
        self.remote_error = remote_error
        self.drop_connection = drop_connection
        self.requests: list[dict] = []
        self.methods: list[str] = []
        self.session_headers: list[str] = []
        self.call_count = 0
        self.session_number = 0
        self.current_session = ""
        self.response_sent = False
        self.call_started = threading.Event()
        self.client_closed = threading.Event()
        self.call_finished = threading.Event()
        self.release = threading.Event()
        self.thread = threading.Thread(target=self.serve_forever,
                                        name="agnt-mcp-http-cancel-server", daemon=True)
        self.thread.start()

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"

    def record(self, method, headers=None, request=None):
        self.methods.append(method)
        if headers is not None:
            self.session_headers.append(headers.get("Mcp-Session-Id", ""))
            self.requests.append({"headers": headers, "request": request})

    def close(self):
        self.release.set()
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise AssertionError("serveur MCP HTTP d'annulation encore vivant")


def registry_for(endpoint: str) -> Registry:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        path = Path(handle.name)
        handle.write(YAML.replace("ENDPOINT", endpoint))
    try:
        return Registry(path)
    finally:
        path.unlink(missing_ok=True)


def no_http_worker_threads() -> bool:
    return not any(t.name == "agnt-mcp-http" and t.is_alive()
                   for t in threading.enumerate())


def main() -> int:
    cases: list[tuple[str, bool, str]] = []

    def case(name: str, condition: bool, detail: str = ""):
        cases.append((name, bool(condition), detail))
        print(("OK    " if condition else "ECHEC ") + name
              + (f" — {detail}" if detail else ""))

    if not transports.fournit("mcp"):
        MB.initialiser_mcp(transports)
    previous_token = os.environ.get("MCP_HTTP_CANCEL_TOKEN")
    os.environ["MCP_HTTP_CANCEL_TOKEN"] = SECRET
    try:
        # ----------------------------------------------------------- succès normal
        normal = CancellationServer()
        try:
            reg = registry_for(normal.endpoint)
            prov = reg.provider("cancel_http")
            normal_result = backend_for(prov).execute(
                target=Target("repository", "repo://normal"),
                cancel_event=threading.Event())
            case("1. requête HTTP cancellable normale = succès inchangé",
                 normal_result.status == "succeeded"
                 and normal_result.output["results"][0]["rule"] == "review.no-eval")
            case("2. succès normal conserve le cycle MCP et le token reste côté header",
                 normal.methods == ["initialize", "notifications/initialized",
                                    "tools/list", "tools/call"]
                 and normal.requests[0]["headers"].get("Authorization") == f"Bearer {SECRET}"
                 and SECRET not in json.dumps(normal_result.to_dict(), ensure_ascii=False))
        finally:
            normal.close()

        # ------------------------------------------------ annulation avant transport
        pre = CancellationServer()
        try:
            reg = registry_for(pre.endpoint)
            prov = reg.provider("cancel_http")
            created = []

            def pre_factory(mani):
                transport = HTTPMCPTransport(mani.endpoint, auth_env=mani.auth_env)
                created.append(transport)
                return transport

            pre_event = threading.Event()
            pre_event.set()
            pre_result = backend_for(prov, transport_factory=pre_factory).execute(
                target=Target("repository", "repo://pre"), cancel_event=pre_event)
            case("3. annulation précoce = cancelled sans invocation réseau",
                 pre_result.status == "cancelled" and not pre.requests and not created)
        finally:
            pre.close()

        # ------------------------------------------- annulation pendant tools/call
        blocking = CancellationServer(block_first_call=True, late_secret=True)
        shared_transport = HTTPMCPTransport(blocking.endpoint, auth_env="MCP_HTTP_CANCEL_TOKEN")
        shared_factory_calls = []

        def shared_factory(mani):
            shared_factory_calls.append(mani.id)
            return shared_transport

        result_box = {}
        cancel_event = threading.Event()

        def invoke_cancelled():
            result_box["cancelled"] = backend_for(
                registry_for(blocking.endpoint).provider("cancel_http"),
                transport_factory=shared_factory).execute(
                    target=Target("repository", "repo://blocking"),
                    cancel_event=cancel_event, timeout=2)

        call_thread = threading.Thread(target=invoke_cancelled,
                                       name="agnt-mcp-http-caller", daemon=False)
        call_thread.start()
        started = blocking.call_started.wait(2)
        t0 = time.monotonic()
        if started:
            cancel_event.set()
        call_thread.join(timeout=2)
        elapsed = time.monotonic() - t0
        cancelled = result_box.get("cancelled")
        closed = blocking.client_closed.wait(2)
        finished = blocking.call_finished.wait(2)
        case("4. serveur confirme tools/call bloquant avant annulation", started)
        case("5. annulation HTTP réelle retourne cancelled, rapidement",
             cancelled is not None and cancelled.status == "cancelled"
             and elapsed < 1.0,
             getattr(cancelled, "error", "appel toujours bloqué"))
        case("6. request_id de la requête annulée et correlation_id sont conservés",
             cancelled is not None and cancelled.request_id == "3"
             and cancelled.correlation_id == "cancel_http:review_code")
        case("7. le serveur observe EOF/reset et termine son handler",
             closed and finished and not blocking.response_sent
             and "notifications/cancelled" not in blocking.methods)
        case("8. aucune réponse tardive n'entre dans le résultat annulé",
             cancelled is not None and cancelled.output is None
             and "results" not in json.dumps(cancelled.raw, ensure_ascii=False)
             and SECRET not in json.dumps(cancelled.to_dict(), ensure_ascii=False))
        case("9. aucun retry après annulation et aucun worker HTTP vivant",
             blocking.call_count == 1 and shared_factory_calls == ["cancel_http"]
             and not any(t.name == "agnt-mcp-http-caller" and t.is_alive()
                         for t in threading.enumerate())
             and no_http_worker_threads())

        # ----------------------------------------------- session suivante saine
        followup = backend_for(
            registry_for(blocking.endpoint).provider("cancel_http"),
            transport_factory=shared_factory).execute(
                target=Target("repository", "repo://followup"),
                cancel_event=threading.Event(), timeout=1)
        case("10. une nouvelle requête après annulation réussit",
             followup.status == "succeeded"
             and followup.output["results"][0]["rule"] == "review.no-eval")
        init_headers = [x for x, method in zip(blocking.session_headers, blocking.methods)
                        if method == "initialize"]
        case("11. nouvelle session sans contamination et request_id distinct",
             len(init_headers) >= 2 and init_headers[0] == init_headers[1] == ""
             and followup.request_id != cancelled.request_id
             and blocking.call_count == 2)
        blocking.close()

        # --------------------------------------------------------- timeout réel
        timeout_server = CancellationServer(block_first_call=True)
        try:
            reg = registry_for(timeout_server.endpoint)
            result = backend_for(reg.provider("cancel_http")).execute(
                target=Target("repository", "repo://timeout"),
                cancel_event=threading.Event(), timeout=0.05)
            timeout_server.client_closed.wait(2)
            timeout_server.call_finished.wait(2)
            case("12. timeout réel reste timed_out, distinct de cancelled",
                 result.status == "timed_out" and result.status != "cancelled")
            case("13. timeout ferme le handle et nettoie le worker",
                 timeout_server.client_closed.is_set() and timeout_server.call_finished.is_set()
                 and no_http_worker_threads())
        finally:
            timeout_server.close()

        # ---------------------------------------------------------- serveur fermé
        unexpected = CancellationServer()
        endpoint = unexpected.endpoint
        unexpected.close()
        reg = registry_for(endpoint)
        result = backend_for(reg.provider("cancel_http")).execute(
            target=Target("repository", "repo://closed"),
            cancel_event=threading.Event(), timeout=0.2)
        case("14. endpoint fermé = unavailable sans retry",
             result.status == "unavailable")

        # ----------------------------------------------- fermeture serveur inattendue
        dropped = CancellationServer(drop_connection=True)
        try:
            reg = registry_for(dropped.endpoint)
            result = backend_for(reg.provider("cancel_http")).execute(
                target=Target("repository", "repo://drop"),
                cancel_event=threading.Event(), timeout=1)
            dropped.call_finished.wait(2)
            case("15. fermeture serveur inattendue = unavailable sans fuite",
                 result.status == "unavailable" and dropped.call_finished.is_set()
                 and no_http_worker_threads())
        finally:
            dropped.close()

        # --------------------------------------------------------- erreur distante
        error_server = CancellationServer(remote_error=True)
        try:
            reg = registry_for(error_server.endpoint)
            result = backend_for(reg.provider("cancel_http")).execute(
                target=Target("repository", "repo://error"),
                cancel_event=threading.Event(), timeout=1)
            case("16. erreur JSON-RPC réelle = failed sans fuite du faux secret",
                 result.status == "failed" and SECRET not in result.error
                 and SECRET not in json.dumps(result.to_dict(), ensure_ascii=False))
        finally:
            error_server.close()
    finally:
        if previous_token is None:
            os.environ.pop("MCP_HTTP_CANCEL_TOKEN", None)
        else:
            os.environ["MCP_HTTP_CANCEL_TOKEN"] = previous_token

    # URL avec userinfo : le client doit refuser avant toute connexion et sans recopier
    # la valeur sensible dans l'exception.
    try:
        HTTPMCPTransport(f"http://user:{SECRET}@127.0.0.1:1/mcp")
        url_refused = False
    except Exception as exc:
        url_refused = SECRET not in str(exc)
    case("17. URL avec faux secret refusée sans fuite", url_refused)

    failures = [name for name, condition, _ in cases if not condition]
    print(f"\n{len(cases) - len(failures)}/{len(cases)} cas passent")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
