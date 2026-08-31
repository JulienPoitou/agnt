#!/usr/bin/env python3
"""Intégration MCP stdio locale réelle — INTEGRATION REAL CONTROLLED.

Le serveur est un processus Python écrit dans un répertoire temporaire et lancé avec
``shell=False`` par ``StdioMCPTransport``. Le script ne contacte aucun réseau et le
transport doit récolter le processus après un succès comme après un timeout.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import threading
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import mcp_bootstrap as MB  # noqa: E402
from mcp_provider import backend_for  # noqa: E402
from mcp_transport import StdioMCPTransport  # noqa: E402
from provider_contract import Target  # noqa: E402
from registre import Registry  # noqa: E402
import transports  # noqa: E402


SERVER = r'''
import json
import os
import sys
import time

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        response = {"jsonrpc": "2.0", "id": request.get("id"), "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "controlled-stdio-server", "version": "1.0"},
        }}
    elif method == "tools/list":
        response = {"jsonrpc": "2.0", "id": request.get("id"), "result": {
            "tools": [
                {"name": "review_code", "inputSchema": {
                    "type": "object", "properties": {"remote_canary": {"type": "string"}}
                }},
                {"name": "rogue_tool"},
            ]
        }}
    elif method == "tools/call":
        if os.environ.get("MCP_SLOW") == "1":
            time.sleep(0.3)
        params = request.get("params") or {}
        response = {"jsonrpc": "2.0", "id": request.get("id"), "result": {
            "structuredContent": {"results": [{
                "rule": "review.no-eval", "file": "src/stdio.py", "line": 4,
                "message": "avoid eval", "severity": "HIGH",
            }], "called_tool": params.get("name"),
                     "arguments_seen": params.get("arguments")},
        }}
    else:
        response = {"jsonrpc": "2.0", "id": request.get("id"),
                    "error": {"code": -32601, "message": "unknown method"}}
    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
    sys.stdout.flush()
'''

YAML_TEMPLATE = """
version: 1
capabilities:
  - id: CODE_REVIEW
    description: Revue stdio contrôlée
    domaines: [code]
    entree: [cible]
    sortie: finding/code-issue
    providers:
      - id: review_stdio
        transport: mcp
        kind: api
        risque: PASSIVE
        mcp:
          server:
            id: controlled-stdio-server
            version: '1.0'
            transport: stdio
            command: [PYTHON, SCRIPT]
          tool: {name: review_code, version: '1'}
          protocol_version: '2025-06-18'
          trust: untrusted_local
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
              champs:
                regle: rule
                fichier: file
                ligne: line
                message: message
                severite: severity
"""


class RecordingTransport(StdioMCPTransport):
    def __init__(self, command, *, slow=False):
        super().__init__(command, env={"MCP_SLOW": "1"} if slow else {})
        self.process = None

    def _demarrer(self):
        state = super()._demarrer()
        self.process = state.process
        return state


def registry_for(tmp: Path, script: Path) -> Registry:
    config = tmp / "capabilities.yaml"
    config.write_text(YAML_TEMPLATE.replace("PYTHON", sys.executable)
                      .replace("SCRIPT", str(script)), encoding="utf-8")
    return Registry(config)


def main() -> int:
    cases = []

    def case(name, condition, detail=""):
        cases.append((name, bool(condition), detail))
        print(("OK    " if condition else "ECHEC ") + name
              + (f" — {detail}" if detail else ""))

    if not transports.fournit("mcp"):
        MB.initialiser_mcp(transports)
    tmp = Path(tempfile.mkdtemp(prefix="agnt-mcp-stdio-"))
    script = tmp / "server.py"
    script.write_text(SERVER, encoding="utf-8")
    try:
        reg = registry_for(tmp, script)
        prov = reg.provider("review_stdio")
        created: list[RecordingTransport] = []

        def factory(mani):
            transport = RecordingTransport(mani.command)
            created.append(transport)
            return transport

        result = backend_for(prov, transport_factory=factory).execute(
            target=Target("repository", "repo://stdio"))
        called = result.output or {}
        finding = called["results"][0] if called.get("results") else {}
        case("1. processus stdio réel : initialize/list/call réussi",
             result.status == "succeeded" and finding["rule"] == "review.no-eval")
        case("2. le processus stdio réel reçoit l'outil du binding, jamais rogue_tool",
             called.get("called_tool") == "review_code")
        case("3. la cible structurée est le seul argument ajouté",
             called.get("arguments_seen") == {"repository": "repo://stdio"})
        case("4. close récolte le processus stdio après succès",
             len(created) == 1 and created[0].process is not None
             and created[0].process.poll() is not None and created[0]._state is None)

        slow_created: list[RecordingTransport] = []

        def slow_factory(mani):
            transport = RecordingTransport(mani.command, slow=True)
            slow_created.append(transport)
            return transport

        timed = backend_for(prov, transport_factory=slow_factory).execute(
            target=Target("repository", "repo://stdio"), timeout=0.05)
        slow_process = slow_created[0].process if slow_created else None
        case("5. réponse stdio lente = timed_out",
             timed.status == "timed_out")
        case("6. timeout stdio tue et récolte le processus",
             slow_process is not None and slow_process.poll() is not None
             and slow_created[0]._state is None)

        cancelled_created: list[RecordingTransport] = []

        def cancelled_factory(mani):
            transport = RecordingTransport(mani.command, slow=True)
            cancelled_created.append(transport)
            return transport

        cancel_event = threading.Event()
        timer = threading.Timer(0.08, cancel_event.set)
        timer.start()
        cancelled = backend_for(prov, transport_factory=cancelled_factory).execute(
            target=Target("repository", "repo://stdio"), timeout=1,
            cancel_event=cancel_event)
        timer.join(timeout=1)
        cancelled_process = (cancelled_created[0].process
                             if cancelled_created else None)
        case("7. annulation stdio réelle = cancelled",
             cancelled.status == "cancelled")
        case("8. annulation stdio réelle récolte le processus",
             cancelled_process is not None and cancelled_process.poll() is not None
             and cancelled_created[0]._state is None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failures = [name for name, condition, _ in cases if not condition]
    print(f"\n{len(cases) - len(failures)}/{len(cases)} cas passent")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
