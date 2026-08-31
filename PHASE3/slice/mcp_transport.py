"""Transports MCP minimaux, derrière un contrat JSON-RPC commun.

Le reste d'AGNT ne connaît ni stdio ni HTTP. Il ne voit qu'un backend provider qui
retourne un ``ProviderResult``. Les transports de ce module ne décident jamais si un
oùtil est autorisé : ils transportent une requête déjà validée par le registre et la
policy.

Implémentation volontairement sans SDK externe :

* ``StdioMCPTransport`` parle JSON-RPC ligne par ligne à un serveur configuré ;
* ``HTTPMCPTransport`` utilise le transport HTTP MCP/Streamable HTTP avec une
  éventuelle session ;
* ``MCPClient`` implémente le handshake, la découverte et ``tools/call``.

Les erreurs et les réponses sont traitées comme des données distantes non fiables.
Les secrets d'authentification sont lus depuis l'environnement, utilisés dans l'en-tête
HTTP seulement, et ne sont jamais inclus dans une exception ou une trace.
"""

from __future__ import annotations

import http.client
import json
import os
import select
import socket
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import assainissement as ASS


MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_HTTP_RESPONSE_BYTES = 32 * 1024 * 1024
DEFAULT_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2024-11-05", "2024-10-07")


class MCPTransportError(Exception):
    """Erreur de transport, sans donnée sensible dans le message."""


class MCPTransportUnavailable(MCPTransportError):
    pass


class MCPTransportTimeout(MCPTransportError):
    pass


class MCPTransportCancelled(MCPTransportError):
    def __init__(self, message: str = "appel MCP annulé", *, request_id: str = ""):
        super().__init__(message)
        # L'identifiant est une donnée JSON-RPC courte, jamais une URL, un header
        # ou un payload. Il permet au ProviderResult annulé de rester corrélé.
        self.request_id = str(request_id)[:128]


class MCPProtocolError(MCPTransportError):
    pass


class MCPRemoteError(MCPTransportError):
    pass


class MCPTransport(Protocol):
    def request(self, method: str, params: Mapping[str, Any] | None = None,
                *, timeout: float, cancel_event: Any = None) -> dict:
        ...

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        ...

    def close(self) -> None:
        ...



def _assainir_texte(value: Any, limite: int = 1000) -> str:
    """Message d'erreur court et sans secret connu."""
    texte = str(value or "")[:limite]
    return ASS.masquer(texte)[0]


def _json_sans_secret(value: Any) -> Any:
    """Assainit une réponse avant de la conserver dans un résultat.

    Le transport ne fait pas confiance à ``content`` ni aux erreurs du serveur. Le
    JSON est sérialisé puis passé par le jeu large : si une réponse distante contient
    une clé, elle ne doit pas entrer dans le ledger, le brut ou le finding.
    """
    try:
        texte = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"error": "réponse MCP non sérialisable"}
    verdict = ASS.examiner(texte)
    if verdict.sur:
        return value
    try:
        return json.loads(verdict.texte_masque)
    except (TypeError, ValueError):
        return {"error": "réponse MCP masquée", "raw_digest": verdict.digest}


def _valider_reponse(obj: Any) -> dict:
    if not isinstance(obj, dict):
        raise MCPProtocolError("réponse JSON-RPC MCP non objet")
    if obj.get("jsonrpc") != "2.0":
        raise MCPProtocolError("réponse MCP sans version JSON-RPC 2.0")
    if "error" in obj:
        erreur = obj.get("error") or {}
        if isinstance(erreur, dict):
            code = erreur.get("code", "?")
            message = _assainir_texte(erreur.get("message", "erreur distante"))
            raise MCPRemoteError(f"erreur MCP distante ({code}) : {message}")
        raise MCPRemoteError("erreur MCP distante")
    if "result" not in obj:
        raise MCPProtocolError("réponse MCP sans result")
    return _json_sans_secret(obj)


class _CompteurJSONRPC:
    def __init__(self) -> None:
        self._verrou = threading.Lock()
        self._id = 0

    def suivant(self) -> int:
        with self._verrou:
            self._id += 1
            return self._id


class MCPClient:
    """Client protocolaire sans politique d'autorisation.

    ``approved_tool`` est obligatoire dans la construction du client : le nom donné
    à ``call_tool`` est comparé à ce binding local. La réponse de ``tools/list`` peut
    donc être affichée et tracée, mais elle ne peut pas élargir la surface autorisée.
    """

    def __init__(self, transport: MCPTransport, *, approved_tool: str,
                 protocol_version: str = DEFAULT_PROTOCOL_VERSION,
                 client_name: str = "agnt", client_version: str = "0",
                 timeout: float = 30.0) -> None:
        if not approved_tool or not isinstance(approved_tool, str):
            raise MCPProtocolError("outil MCP approuvé manquant")
        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise MCPProtocolError(
                f"version de protocole MCP non supportée : {protocol_version!r}")
        self.transport = transport
        self.approved_tool = approved_tool
        self.protocol_version = protocol_version
        self.client_name = client_name
        self.client_version = client_version
        self.timeout = max(0.001, float(timeout))
        self._ids = _CompteurJSONRPC()
        self.server_protocol_version = ""
        self.server_info: dict[str, Any] = {}
        self.discovered_tools: tuple[dict, ...] = ()
        self.last_request_id: str = ""
        self._initialise = False

    def _call(self, method: str, params: Mapping[str, Any] | None = None,
              *, timeout: float | None = None, cancel_event: Any = None) -> dict:
        if cancel_event is not None and cancel_event.is_set():
            self.last_request_id = ""
            raise MCPTransportCancelled("appel MCP annulé")
        try:
            result = self.transport.request(method, params, timeout=timeout or self.timeout,
                                            cancel_event=cancel_event)
        except MCPTransportCancelled as exc:
            request_id = getattr(exc, "request_id", "")
            # Ne jamais réutiliser l'identifiant d'une requête précédente si
            # l'annulation a eu lieu avant qu'un nouvel appel ne parte.
            self.last_request_id = str(request_id)[:128] if request_id else ""
            raise
        if isinstance(result, dict) and result.get("id") is not None:
            self.last_request_id = str(result["id"])[:128]
        return result

    def initialize(self, *, cancel_event: Any = None) -> dict:
        if self._initialise:
            return {"protocolVersion": self.server_protocol_version,
                    "serverInfo": dict(self.server_info)}
        result = self._call(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": self.client_name, "version": self.client_version},
            },
            cancel_event=cancel_event,
        )
        server_version = result.get("result", {}).get("protocolVersion")
        if not isinstance(server_version, str) or not server_version:
            raise MCPProtocolError("handshake MCP sans protocolVersion serveur")
        if server_version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise MCPProtocolError(
                f"version de protocole MCP serveur non supportée : {server_version!r}")
        result_obj = result.get("result") or {}
        self.server_protocol_version = server_version
        self.server_info = _json_sans_secret(result_obj.get("serverInfo") or {})
        self.transport.notify("notifications/initialized", {})
        self._initialise = True
        return result_obj

    def list_tools(self, *, cancel_event: Any = None) -> tuple[dict, ...]:
        self.initialize(cancel_event=cancel_event)
        result = self._call("tools/list", {}, cancel_event=cancel_event)
        payload = result.get("result") or {}
        tools = payload.get("tools") if isinstance(payload, dict) else None
        if not isinstance(tools, list):
            raise MCPProtocolError("réponse tools/list MCP sans liste tools")
        # La découverte est descriptive. Elle n'ajoute aucun nom à approved_tool.
        propres = []
        for tool in tools:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                propres.append(_json_sans_secret(tool))
        self.discovered_tools = tuple(propres)
        return self.discovered_tools

    def call_tool(self, arguments: Mapping[str, Any], *, cancel_event: Any = None) -> dict:
        self.initialize(cancel_event=cancel_event)
        # Le nom n'est jamais pris dans la réponse de tools/list ni dans une entrée
        # utilisateur : il vient du binding validé par le registre.
        result = self._call(
            "tools/call",
            {"name": self.approved_tool, "arguments": dict(arguments)},
            cancel_event=cancel_event,
        )
        payload = result.get("result")
        if not isinstance(payload, dict):
            raise MCPProtocolError("réponse tools/call MCP sans objet result")
        payload = _json_sans_secret(payload)
        if payload.get("isError") is True:
            # Une erreur fonctionnelle distante n'est pas une sortie vide exploitable.
            raise MCPRemoteError("l'outil MCP a signalé une erreur")
        return payload

    def close(self) -> None:
        self.transport.close()


@dataclass
class _ProcessState:
    process: subprocess.Popen
    stderr: list[str]
    stderr_thread: threading.Thread | None = None
    stdout_buffer: bytearray = field(default_factory=bytearray)


class StdioMCPTransport:
    """Transport stdio MCP, sans shell et avec arrêt du groupe au timeout."""

    def __init__(self, command: Sequence[str], *, env: Mapping[str, str] | None = None,
                 max_stderr_bytes: int = 256 * 1024) -> None:
        if isinstance(command, (str, bytes)) or not command:
            raise MCPTransportError("commande stdio MCP : liste non vide requise")
        self.command = tuple(str(x) for x in command)
        if any(not x or any(f in x for f in (";", "&&", "||", "|", "`", "$(", "\x00", "\n"))
               for x in self.command):
            raise MCPTransportError("commande stdio MCP contenant un fragment interdit")
        self.env = dict(env or {})
        self.max_stderr_bytes = max(1024, int(max_stderr_bytes))
        self._state: _ProcessState | None = None
        self._verrou = threading.RLock()
        self._ids = _CompteurJSONRPC()

    def _demarrer(self) -> _ProcessState:
        if self._state is not None:
            p = self._state.process
            if p.poll() is None:
                return self._state
            raise MCPTransportUnavailable("serveur MCP stdio arrêté")
        # Pas de `os.environ` complet : un serveur externe ne doit pas hériter de
        # credentials AGNT par défaut. Le backend ajoute explicitement ses variables.
        safe = {k: os.environ[k] for k in (
            "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "NO_COLOR"
        ) if k in os.environ}
        safe.update(self.env)
        try:
            proc = subprocess.Popen(
                list(self.command), shell=False, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=safe,
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            raise MCPTransportUnavailable("serveur MCP stdio indisponible") from exc
        state = _ProcessState(proc, [])

        def lire_stderr() -> None:
            try:
                while proc.stderr is not None:
                    ligne = proc.stderr.readline()
                    if not ligne:
                        break
                    # Ne pas conserver une sortie distante illimitée. Le texte est
                    # assaini avant d'être exposé par `stderr()`.
                    actuel = sum(len(x) for x in state.stderr)
                    if actuel < self.max_stderr_bytes:
                        state.stderr.append(ligne[: self.max_stderr_bytes - actuel])
            except (OSError, ValueError):
                pass

        state.stderr_thread = threading.Thread(target=lire_stderr, daemon=True,
                                                name="agnt-mcp-stderr")
        state.stderr_thread.start()
        self._state = state
        return state

    @staticmethod
    def _tuer(proc: subprocess.Popen) -> None:
        """Arrête et récolte le processus : pas de zombie après un timeout/close."""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            # Le processus est déjà isolé dans son groupe ; il n'est pas relancé
            # et le transport ne retourne jamais avec une session encore active.
            try:
                proc.kill()
                proc.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                pass

    def _fermer(self, state: _ProcessState) -> None:
        self._tuer(state.process)
        if state.stderr_thread is not None:
            state.stderr_thread.join(timeout=1)

    def _lire_ligne(self, state: _ProcessState, timeout: float,
                    cancel_event: Any = None) -> str:
        proc = state.process
        if proc.stdout is None:
            raise MCPTransportUnavailable("sortie du serveur MCP stdio absente")
        fd = proc.stdout.fileno()
        debut = time.monotonic()
        while True:
            try:
                # LF : le framing MCP stdio est ligne par ligne.
                fin = state.stdout_buffer.index(10)
            except ValueError:
                fin = -1
            if fin >= 0:
                ligne = bytes(state.stdout_buffer[:fin + 1])
                del state.stdout_buffer[:fin + 1]
                if len(ligne) > MAX_MESSAGE_BYTES:
                    raise MCPProtocolError("message MCP stdio trop volumineux")
                return ligne.decode("utf-8", "replace")
            if len(state.stdout_buffer) > MAX_MESSAGE_BYTES:
                raise MCPProtocolError("message MCP stdio trop volumineux")
            if cancel_event is not None and cancel_event.is_set():
                raise MCPTransportCancelled("appel MCP annulé")
            restant = float(timeout) - (time.monotonic() - debut)
            if restant <= 0:
                raise MCPTransportTimeout("serveur MCP stdio : délai dépassé")
            attente = min(restant, 0.05) if cancel_event is not None else restant
            pret, _, _ = select.select([fd], [], [], attente)
            if not pret:
                if cancel_event is not None and cancel_event.is_set():
                    raise MCPTransportCancelled("appel MCP annulé")
                if attente < restant:
                    continue
                raise MCPTransportTimeout("serveur MCP stdio : délai dépassé")
            try:
                morceau = os.read(fd, min(64 * 1024,
                                         MAX_MESSAGE_BYTES + 1 - len(state.stdout_buffer)))
            except OSError as exc:
                raise MCPTransportUnavailable("sortie du serveur MCP stdio illisible") from exc
            if not morceau:
                raise MCPTransportUnavailable("serveur MCP stdio fermé sans réponse")
            state.stdout_buffer.extend(morceau)

    def request(self, method: str, params: Mapping[str, Any] | None = None,
                *, timeout: float, cancel_event: Any = None) -> dict:
        with self._verrou:
            state = self._demarrer()
            proc = state.process
            if proc.stdin is None:
                raise MCPTransportUnavailable("entrée du serveur MCP stdio absente")
            ident = self._ids.suivant()
            demande = {"jsonrpc": "2.0", "id": ident, "method": method,
                       "params": dict(params or {})}
            try:
                proc.stdin.write(json.dumps(demande, ensure_ascii=False) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._fermer(state)
                self._state = None
                raise MCPTransportUnavailable("serveur MCP stdio non disponible") from exc
            debut = time.monotonic()
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    self._fermer(state)
                    self._state = None
                    raise MCPTransportCancelled("appel MCP annulé")
                restant = float(timeout) - (time.monotonic() - debut)
                if restant <= 0:
                    self._fermer(state)
                    self._state = None
                    raise MCPTransportTimeout("serveur MCP stdio : délai dépassé")
                try:
                    ligne = self._lire_ligne(state, restant, cancel_event)
                except MCPTransportCancelled as exc:
                    self._fermer(state)
                    self._state = None
                    raise MCPTransportCancelled(str(exc), request_id=str(ident)) from None
                except MCPTransportTimeout:
                    self._fermer(state)
                    self._state = None
                    raise
                try:
                    objet = json.loads(ligne)
                except json.JSONDecodeError:
                    # Les logs stdout ne sont pas des réponses MCP : ils ne sont pas
                    # interprétés comme une sortie de finding.
                    continue
                if isinstance(objet, dict) and objet.get("id") == ident:
                    return _valider_reponse(objet)
                # notifications et réponses d'un autre id sont ignorées ; un seul
                # appel est en vol grâce au verrou.

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        with self._verrou:
            state = self._demarrer()
            if state.process.stdin is None:
                raise MCPTransportUnavailable("entrée du serveur MCP stdio absente")
            try:
                state.process.stdin.write(json.dumps({
                    "jsonrpc": "2.0", "method": method, "params": dict(params or {})
                }, ensure_ascii=False) + "\n")
                state.process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._fermer(state)
                self._state = None
                raise MCPTransportUnavailable("serveur MCP stdio non disponible") from exc

    def stderr(self) -> str:
        state = self._state
        if state is None:
            return ""
        return _assainir_texte("".join(state.stderr), 4000)

    def close(self) -> None:
        with self._verrou:
            if self._state is not None:
                state = self._state
                self._fermer(state)
                self._state = None


@dataclass
class _HTTPCallState:
    """État privé d'un appel HTTP cancellable.

    L'état appartient à une invocation et non au module : il n'existe donc pas de
    table globale de requêtes ni de session partagée entre missions. Le worker est
    uniquement une aide de la stdlib pour que le thread appelant puisse fermer la
    connexion pendant ``getresponse``/``read``.
    """

    connection: http.client.HTTPConnection | None = None
    verrou: threading.Lock = field(default_factory=threading.Lock)
    annule: bool = False
    termine: threading.Event = field(default_factory=threading.Event)
    resultat: tuple[int, dict[str, str], bytes] | None = None
    erreur: BaseException | None = None


class HTTPMCPTransport:
    """Transport HTTP MCP avec session et token référencé par nom d'environnement."""

    def __init__(self, endpoint: str, *, auth_env: str = "", user_agent: str = "agnt-mcp/1",
                 max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES) -> None:
        self.endpoint = str(endpoint)
        parts = urlsplit(self.endpoint)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise MCPTransportError("endpoint MCP HTTP invalide")
        if parts.username or parts.password or parts.fragment or any(
                ord(c) < 32 for c in self.endpoint):
            raise MCPTransportError("endpoint MCP HTTP contient une donnée interdite")
        self.auth_env = str(auth_env or "")
        self.user_agent = user_agent
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.session_id = ""
        self._ids = _CompteurJSONRPC()
        self._verrou = threading.RLock()

    def _decoder(self, data: bytes, content_type: str = "") -> dict:
        if len(data) > self.max_response_bytes:
            raise MCPProtocolError("réponse MCP HTTP trop volumineuse")
        if "text/event-stream" in (content_type or "").lower():
            # Streamable HTTP peut rendre un ou plusieurs événements SSE. Seuls les
            # événements `data:` JSON sont candidats ; les commentaires sont ignorés.
            objets = []
            for ligne in data.decode("utf-8", "replace").splitlines():
                if not ligne.startswith("data:"):
                    continue
                texte = ligne[5:].strip()
                if not texte or texte == "[DONE]":
                    continue
                try:
                    objets.append(json.loads(texte))
                except json.JSONDecodeError:
                    continue
            if not objets:
                raise MCPProtocolError("flux MCP HTTP sans événement JSON")
            return objets[-1]
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPProtocolError("réponse MCP HTTP non JSON") from exc

    def _corps(self, response) -> dict:
        data = response.read(self.max_response_bytes + 1)
        try:
            content_type = (response.headers.get("Content-Type") or "").lower()
        except AttributeError:
            content_type = ""
        return self._decoder(data, content_type)

    def _endpoint(self) -> tuple[object, str]:
        parts = urlsplit(self.endpoint)
        chemin = parts.path or "/"
        if parts.query:
            chemin += "?" + parts.query
        return parts, chemin

    @staticmethod
    def _tete(entetes: Mapping[str, str], nom: str) -> str:
        """Lit un header HTTP sans dépendre de sa casse."""
        attendu = nom.casefold()
        return next((str(v) for k, v in entetes.items()
                     if str(k).casefold() == attendu), "")

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": self.user_agent,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.auth_env:
            token = os.environ.get(self.auth_env)
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    @staticmethod
    def _fermer_appel_http(state: _HTTPCallState) -> None:
        """Ferme le handle de l'appel courant, sans conserver d'état global."""
        with state.verrou:
            state.annule = True
            connection = state.connection
        if connection is not None:
            # ``HTTPResponse`` peut lire depuis un ``makefile`` interne : fermer
            # uniquement HTTPConnection n'interrompt pas toujours ce lecteur sur
            # toutes les versions Python. Le shutdown TCP réveille d'abord la
            # lecture, puis close libère le handle.
            sock = getattr(connection, "sock", None)
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            try:
                connection.close()
            except OSError:
                pass

    def _nouvelle_connexion(self, parts, timeout: float) -> http.client.HTTPConnection:
        try:
            port = parts.port
        except ValueError:
            raise MCPTransportUnavailable("endpoint MCP HTTP indisponible") from None
        if not parts.hostname:
            raise MCPTransportUnavailable("endpoint MCP HTTP indisponible")
        classe = (http.client.HTTPSConnection
                  if parts.scheme == "https" else http.client.HTTPConnection)
        return classe(parts.hostname, port, timeout=max(0.001, float(timeout)))

    def _request_cancellable(self, payload: bytes, headers: dict[str, str],
                             *, timeout: float, cancel_event: Any,
                             request_id: str) -> dict:
        """Exécute un appel HTTP dont la socket peut être fermée par l'appelant.

        ``urllib`` ne rend pas son socket disponible pendant ``read``. Ici, un worker
        court possède une connexion ``http.client`` par invocation ; le thread appelant
        observe ``cancel_event``, ferme cette connexion, puis attend la fin du worker.
        La fermeture est donc réelle côté TCP, et aucune réponse du worker annulé n'est
        remise au décodage MCP.
        """
        parts, chemin = self._endpoint()
        state = _HTTPCallState()

        def travailler() -> None:
            connection = None
            try:
                connection = self._nouvelle_connexion(parts, timeout)
                with state.verrou:
                    state.connection = connection
                    deja_annule = state.annule
                if deja_annule:
                    return
                connection.connect()
                with state.verrou:
                    deja_annule = state.annule
                if deja_annule:
                    return
                # La socket reçoit le délai de l'appel. L'annulation, elle, passe
                # par close() depuis le thread appelant et reste donc distincte.
                if connection.sock is not None:
                    connection.sock.settimeout(max(0.001, float(timeout)))
                connection.request("POST", chemin, body=payload,
                                   headers={**headers, "Connection": "close"})
                response = connection.getresponse()
                data = response.read(self.max_response_bytes + 1)
                entetes = {str(k): str(v) for k, v in response.getheaders()}
                with state.verrou:
                    if not state.annule:
                        state.resultat = (int(response.status), entetes, data)
            except BaseException as exc:  # la classification reste dans le thread appelant
                with state.verrou:
                    if not state.annule:
                        state.erreur = exc
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass
                state.termine.set()

        worker = threading.Thread(target=travailler, name="agnt-mcp-http", daemon=False)
        worker.start()
        while not state.termine.wait(0.01):
            if cancel_event is not None and cancel_event.is_set():
                self._fermer_appel_http(state)
                worker.join()
                raise MCPTransportCancelled(request_id=request_id) from None
        # ``termine`` est posé après fermeture de la connexion ; join est normalement
        # immédiat et rend la garantie de nettoyage observable par le test.
        worker.join()
        with state.verrou:
            erreur = state.erreur
            resultat = state.resultat
        if cancel_event is not None and cancel_event.is_set() and resultat is None:
            self._fermer_appel_http(state)
            raise MCPTransportCancelled(request_id=request_id) from None
        if erreur is not None:
            if isinstance(erreur, (socket.timeout, TimeoutError)):
                raise MCPTransportTimeout("endpoint MCP HTTP : délai dépassé") from None
            raise MCPTransportUnavailable("endpoint MCP HTTP indisponible") from None
        if resultat is None:
            raise MCPTransportUnavailable("endpoint MCP HTTP indisponible") from None
        status, entetes, data = resultat
        if status in (408, 504):
            raise MCPTransportTimeout("endpoint MCP HTTP : délai dépassé") from None
        if status >= 400:
            raise MCPTransportUnavailable(
                f"endpoint MCP HTTP indisponible (HTTP {status})") from None
        sid = self._tete(entetes, "Mcp-Session-Id")
        if sid:
            self.session_id = sid[:512]
        return _valider_reponse(self._decoder(data, self._tete(entetes, "Content-Type")))

    def request(self, method: str, params: Mapping[str, Any] | None = None,
                *, timeout: float, cancel_event: Any = None) -> dict:
        if cancel_event is not None and cancel_event.is_set():
            raise MCPTransportCancelled("appel MCP annulé")
        with self._verrou:
            ident = self._ids.suivant()
            payload = json.dumps({"jsonrpc": "2.0", "id": ident, "method": method,
                                  "params": dict(params or {})}, ensure_ascii=False).encode()
            headers = self._headers()
            if cancel_event is not None:
                return self._request_cancellable(
                    payload, headers, timeout=max(0.001, float(timeout)),
                    cancel_event=cancel_event, request_id=str(ident))
            req = Request(self.endpoint, data=payload, headers=headers, method="POST")
            try:
                with urlopen(req, timeout=max(0.001, float(timeout))) as response:
                    sid = response.headers.get("Mcp-Session-Id")
                    if sid:
                        # Le serveur fournit l'identifiant : il n'est jamais dérivé
                        # d'un nom d'hôte ou d'un ordre de découverte.
                        self.session_id = str(sid)[:512]
                    objet = self._corps(response)
            except HTTPError as exc:
                # Ne pas reprendre le corps ou l'URL : les deux peuvent contenir des
                # erreurs distantes et des informations d'authentification. Un 408/504
                # est un délai ; un 4xx/5xx de connexion est une indisponibilité.
                if exc.code in (408, 504):
                    raise MCPTransportTimeout("endpoint MCP HTTP : délai dépassé") from None
                raise MCPTransportUnavailable(
                    f"endpoint MCP HTTP indisponible (HTTP {exc.code})") from None
            except URLError as exc:
                # `URLError` couvre aussi ConnectionRefusedError : ne pas transformer
                # une adresse fermée en timeout, faute de quoi la disponibilité serait
                # fausse dans le ledger.
                cause = getattr(exc, "reason", None)
                if isinstance(cause, (socket.timeout, TimeoutError)):
                    raise MCPTransportTimeout("endpoint MCP HTTP : délai dépassé") from None
                raise MCPTransportUnavailable("endpoint MCP HTTP indisponible") from None
            except (socket.timeout, TimeoutError):
                raise MCPTransportTimeout("endpoint MCP HTTP : délai dépassé") from None
            except OSError:
                raise MCPTransportUnavailable("endpoint MCP HTTP indisponible") from None
            return _valider_reponse(objet)

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        # Une notification MCP ne demande pas de réponse. On l'envoie avec le même
        # endpoint, en n'exposant jamais le token dans l'exception.
        if not method:
            raise MCPProtocolError("notification MCP sans méthode")
        with self._verrou:
            headers = {"Content-Type": "application/json", "User-Agent": self.user_agent}
            if self.session_id:
                headers["Mcp-Session-Id"] = self.session_id
            if self.auth_env and os.environ.get(self.auth_env):
                headers["Authorization"] = f"Bearer {os.environ[self.auth_env]}"
            req = Request(self.endpoint, data=json.dumps({
                "jsonrpc": "2.0", "method": method, "params": dict(params or {})
            }).encode(), headers=headers, method="POST")
            try:
                with urlopen(req, timeout=10) as response:
                    response.read(1024)
            except HTTPError as exc:
                if exc.code in (408, 504):
                    raise MCPTransportTimeout("notification MCP HTTP : délai dépassé") from None
                raise MCPTransportUnavailable("notification MCP HTTP échouée") from None
            except URLError as exc:
                cause = getattr(exc, "reason", None)
                if isinstance(cause, (socket.timeout, TimeoutError)):
                    raise MCPTransportTimeout("notification MCP HTTP : délai dépassé") from None
                raise MCPTransportUnavailable("notification MCP HTTP échouée") from None
            except (socket.timeout, TimeoutError):
                raise MCPTransportTimeout("notification MCP HTTP : délai dépassé") from None
            except OSError:
                raise MCPTransportUnavailable("notification MCP HTTP échouée") from None

    def close(self) -> None:
        # HTTP est sans socket conservée par ce client ; la session logique est
        # abandonnée au niveau de la mission, jamais partagée avec une autre.
        self.session_id = ""
