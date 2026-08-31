"""Contrat déclaratif d'un provider MCP et backend d'invocation AGNT.

Un bloc ``mcp`` du registre lie explicitement :

    capability AGNT ↔ provider logique ↔ serveur MCP ↔ outil MCP

La découverte ``tools/list`` est informative. Elle ne peut jamais créer un provider
ou changer le nom de l'outil autorisé : le binding ci-dessous est validé au chargement
du registre et réutilisé à chaque appel.

Le module ne contient pas d'orchestrateur. ``MCPBackend`` implémente seulement le même
contrat d'exécution qu'un adaptateur local et retourne un ``ProviderResult``. Le pipeline
principal garde donc ses étapes policy → exécution → normalisation → ledger.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

import assainissement as ASS
import conditions as COND
import provider_manifest as PM
from provider_contract import (
    ArgumentValidationError,
    Availability,
    InvalidProviderResult,
    ProviderIdentity,
    ProviderResult,
    ProviderTimeout,
    ProviderUnavailable,
    Target,
)
from mcp_transport import (
    DEFAULT_PROTOCOL_VERSION,
    HTTPMCPTransport,
    MCPClient,
    MCPProtocolError,
    MCPRemoteError,
    MCPTransportCancelled,
    MCPTransportError,
    MCPTransportUnavailable,
    MCPTransportTimeout,
    StdioMCPTransport,
)


class MCPProviderError(Exception):
    """Contrat MCP invalide : le registre refuse le provider avant exécution."""


MCP_SERVER_TRANSPORTS = ("stdio", "http", "streamable_http")
MCP_SCHEMA_KEYS = (
    "type", "properties", "required", "additionalProperties", "enum",
    "minLength", "maxLength", "minItems", "maxItems", "items",
)
_MCP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_SHELL_FRAGMENTS = (";", "&&", "||", "|", "`", "$(", ">", "<", "\x00", "\n", "\r")
# Contrats fermés : une clé MCP inconnue ne doit pas ressembler à une garantie
# exécutée alors qu'elle est simplement ignorée par le backend.
_MCP_SPEC_KEYS = frozenset({
    "server", "server_id", "transport", "endpoint", "command", "auth_env",
    "tool", "provider_version", "server_version", "tool_version", "protocol_version",
    "trust", "target_types", "targets", "target_argument", "target_encoding",
    "argument_schema", "arguments_schema", "result", "timeout_s", "call_timeout_s",
    "connect_timeout_s", "requires_network", "privileges", "base_fichiers", "coverage",
    "applicabilite", "limite",
})
_MCP_SERVER_KEYS = frozenset({
    "id", "version", "transport", "endpoint", "command", "auth_env", "protocol_version",
})
_MCP_TOOL_KEYS = frozenset({"name", "version", "inputSchema", "description", "annotations"})
_MCP_RESULT_KEYS = frozenset({"format", "extraction"})
_MCP_EXTRACTION_KEYS = frozenset({
    "modele", "items_from", "nested_from", "nested_key", "contexte", "champs",
    "paquet_depuis_regle", "nettoyage_regle", "jetons_outil", "masquer_large",
    "separateur", "parser",
})


def _texte(doc: Mapping[str, Any], key: str, *, default: str = "") -> str:
    value = doc.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise MCPProviderError(f"MCP: {key!r} doit être une chaîne")
    return value


def _refuser_clefs(doc: Mapping[str, Any], admises: frozenset[str], label: str) -> None:
    inconnues = sorted(set(doc) - admises)
    if inconnues:
        raise MCPProviderError(
            f"MCP: {label} contient des clés inconnues {inconnues} — "
            "contrat fermé, aucune garantie implicite")


def _identifiant(value: str, label: str) -> str:
    if not value or not _MCP_ID.fullmatch(value):
        raise MCPProviderError(
            f"MCP: {label} invalide — identifiant stable attendu (lettres, chiffres, . _ : -)")
    return value


def _liste_texte(value: Any, label: str, *, non_vide: bool = False) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise MCPProviderError(f"MCP: {label} doit être une liste de chaînes")
    out = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise MCPProviderError(f"MCP: {label} contient une valeur non textuelle")
        out.append(item)
    if non_vide and not out:
        raise MCPProviderError(f"MCP: {label} ne peut pas être vide")
    return tuple(out)


def _valider_endpoint(endpoint: str) -> str:
    if not endpoint:
        raise MCPProviderError("MCP HTTP: endpoint obligatoire")
    parts = urlsplit(endpoint)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise MCPProviderError("MCP HTTP: endpoint http(s) invalide")
    if parts.username or parts.password or parts.fragment or any(ord(c) < 32 for c in endpoint):
        raise MCPProviderError(
            "MCP HTTP: endpoint sans credentials, fragment ni caractère de contrôle")
    # Un endpoint est une adresse déclarée, jamais un template ou une commande.
    if any(x in endpoint for x in ("{", "}", "\n", "\r")):
        raise MCPProviderError("MCP HTTP: endpoint dynamique interdit")
    return endpoint


def _valider_schema(schema: Any, chemin: str = "schema") -> dict:
    """Valide le sous-ensemble JSON Schema exécuté par le cœur.

    Le schéma approuvé est une déclaration locale. Un schéma reçu de ``tools/list``
    n'est jamais passé à cette fonction ni utilisé pour accorder une permission.
    """
    if not isinstance(schema, dict):
        raise MCPProviderError(f"MCP: {chemin} doit être un objet JSON Schema")
    inconnues = [k for k in schema if k not in MCP_SCHEMA_KEYS]
    if inconnues:
        raise MCPProviderError(
            f"MCP: {chemin} contient des mots-clés de schéma non supportés {inconnues}")
    typ = schema.get("type", "object")
    if typ not in ("object", "array", "string", "number", "integer", "boolean", "null"):
        raise MCPProviderError(f"MCP: {chemin}.type non supporté")
    if "enum" in schema:
        if not isinstance(schema["enum"], list) or not schema["enum"]:
            raise MCPProviderError(f"MCP: {chemin}.enum doit être une liste non vide")
        try:
            json.dumps(schema["enum"], ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise MCPProviderError(f"MCP: {chemin}.enum non sérialisable") from exc
    for key in ("minLength", "maxLength", "minItems", "maxItems"):
        if key in schema:
            value = schema[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise MCPProviderError(f"MCP: {chemin}.{key} doit être un entier >= 0")
    if "minLength" in schema and "maxLength" in schema \
            and schema["minLength"] > schema["maxLength"]:
        raise MCPProviderError(f"MCP: {chemin}: bornes de longueur incohérentes")
    if "minItems" in schema and "maxItems" in schema \
            and schema["minItems"] > schema["maxItems"]:
        raise MCPProviderError(f"MCP: {chemin}: bornes de tableau incohérentes")
    if typ == "object":
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise MCPProviderError(f"MCP: {chemin}.properties doit être un objet")
        for name, child in properties.items():
            if not isinstance(name, str) or not name or not _MCP_ID.fullmatch(name):
                raise MCPProviderError(f"MCP: propriété d'argument invalide {name!r}")
            _valider_schema(child, f"{chemin}.properties.{name}")
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(x, str) for x in required):
            raise MCPProviderError(f"MCP: {chemin}.required doit être une liste de noms")
        inconnus_required = [x for x in required if x not in properties]
        if inconnus_required:
            raise MCPProviderError(
                f"MCP: {chemin}.required référence des propriétés absentes {inconnus_required}")
        additional = schema.get("additionalProperties", False)
        if not isinstance(additional, bool):
            # Accepter un schéma supplémentaire ferait entrer un mini-moteur JSON
            # Schema dans le cœur et rendrait la surface autorisée moins lisible.
            raise MCPProviderError(f"MCP: {chemin}.additionalProperties doit être booléen")
    elif "properties" in schema or "required" in schema:
        raise MCPProviderError(f"MCP: {chemin}: properties/required réservés au type object")
    if typ == "array" and "items" in schema:
        _valider_schema(schema["items"], f"{chemin}.items")
    return copy.deepcopy(schema)


def _type_ok(value: Any, typ: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }[typ]


def _valider_valeur(value: Any, schema: Mapping[str, Any], chemin: str) -> None:
    typ = schema.get("type", "object")
    if not _type_ok(value, typ):
        raise ArgumentValidationError(f"argument invalide à {chemin}: type attendu {typ}")
    if "enum" in schema and value not in schema["enum"]:
        raise ArgumentValidationError(f"argument invalide à {chemin}: valeur non autorisée")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ArgumentValidationError(f"argument invalide à {chemin}: chaîne trop courte")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ArgumentValidationError(f"argument invalide à {chemin}: chaîne trop longue")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ArgumentValidationError(f"argument invalide à {chemin}: tableau trop court")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ArgumentValidationError(f"argument invalide à {chemin}: tableau trop long")
        if "items" in schema:
            for i, item in enumerate(value):
                _valider_valeur(item, schema["items"], f"{chemin}[{i}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise ArgumentValidationError(
                f"arguments invalides: propriétés obligatoires absentes {missing}")
        if not schema.get("additionalProperties", False):
            unknown = [key for key in value if key not in properties]
            if unknown:
                raise ArgumentValidationError(
                    f"arguments invalides: propriétés non autorisées {unknown}")
        for key, child in properties.items():
            if key in value:
                _valider_valeur(value[key], child, f"arguments.{key}")


def _extraction(doc: Mapping[str, Any], ident: str) -> tuple[str, PM.Extraction]:
    result = doc.get("result") or {}
    if not isinstance(result, dict):
        raise MCPProviderError("MCP: result doit être un objet")
    _refuser_clefs(result, _MCP_RESULT_KEYS, "result")
    fmt = result.get("format", "json")
    if fmt not in PM.FORMATS_SORTIE:
        raise MCPProviderError(f"MCP: format de résultat {fmt!r} non supporté")
    ex = result.get("extraction") or {}
    if not isinstance(ex, dict):
        raise MCPProviderError("MCP: result.extraction doit être un objet")
    _refuser_clefs(ex, _MCP_EXTRACTION_KEYS, "result.extraction")
    modele = str(ex.get("modele", "plat") or "plat")
    if modele not in PM.MODELES_LECTURE:
        raise MCPProviderError(f"MCP: modèle d'extraction {modele!r} inconnu")
    attendus = PM.PairesFormatModele.get(fmt, ())
    if fmt != "custom" and attendus and modele not in attendus:
        raise MCPProviderError(
            f"MCP: format {fmt!r} incompatible avec modèle {modele!r}")
    parser = ex.get("parser", "")
    if fmt == "custom":
        if not parser:
            raise MCPProviderError("MCP: format custom sans parser")
        import parsers
        if parsers.obtenir(parser) is None:
            raise MCPProviderError(
                f"MCP: parser {parser!r} introuvable — disponibles {parsers.disponibles()}")
    jetons = list(ex.get("jetons_outil") or [])
    # Un résultat MCP ne résout aucun placeholder : les jetons outil ne sont pas
    # nécessaires pour le protocole, mais sont conservés afin de réutiliser le même
    # extracteur si un outil rend un format texte déclaré.
    extraction = PM.Extraction(
        modele=modele,
        items_from=str(ex.get("items_from", "results")),
        nested_from=str(ex.get("nested_from", "")),
        nested_key=str(ex.get("nested_key", "")),
        contexte=dict(ex.get("contexte") or {}),
        champs=dict(ex.get("champs") or {}),
        paquet_depuis_regle=list(ex.get("paquet_depuis_regle") or []),
        nettoyage_regle=str(ex.get("nettoyage_regle", "")),
        jetons_outil=jetons,
        masquer_large=list(ex.get("masquer_large") or []),
        separateur=str(ex.get("separateur", ",") or ","),
        parser=str(parser or ""),
    )
    # Reprendre les contrôles de cohérence des manifests CLI sans exiger binaire/argv.
    if extraction.nettoyage_regle not in PM.NETTOYAGES_REGLE_AUTORISES:
        raise MCPProviderError(f"MCP: nettoyage_regle inconnu {extraction.nettoyage_regle!r}")
    if not extraction.champs and fmt != "custom":
        raise MCPProviderError(
            "MCP: result.extraction.champs obligatoire — la sortie distante n'est pas "
            "un finding de confiance par défaut")
    return fmt, extraction


@dataclass(frozen=True)
class MCPManifest:
    """Vue compatible avec le normaliseur générique de findings.py."""

    id: str
    capability: str
    kind: str
    mode: str
    binaire: str                 # nom de l'outil MCP, pas un exécutable local
    argv: tuple[str, ...]
    sortie_format: str
    extraction: PM.Extraction
    risque: str
    cibles: tuple[str, ...]
    code_succes: tuple[int, ...] = (0,)
    declare_fichiers: bool = False
    limite: str = ""
    tool_id: str = ""
    applicable_globs: tuple[str, ...] = ()
    reseau: bool = True
    base_fichiers: tuple[str, ...] = ()
    timeout_s: int = 30
    privileges: str = "aucun"
    env: tuple[tuple[str, str], ...] = ()
    transport: str = "mcp"
    provider_version: str = ""
    server_id: str = ""
    server_version: str = ""
    tool: str = ""
    tool_version: str = ""
    protocol_version: str = DEFAULT_PROTOCOL_VERSION
    trust: str = "untrusted_remote"
    server_transport: str = "http"
    endpoint: str = ""
    command: tuple[str, ...] = ()
    auth_env: str = ""
    argument_schema: dict = field(default_factory=lambda: {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    })
    target_argument: str = ""
    target_encoding: str = "value"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "capability": self.capability,
            "transport": self.transport,
            "server": {
                "id": self.server_id,
                "version": self.server_version,
                "transport": self.server_transport,
                "endpoint": self.endpoint,
                "auth_env": self.auth_env,
            },
            "tool": {"name": self.tool, "version": self.tool_version},
            "protocol_version": self.protocol_version,
            "trust": self.trust,
            "target_types": list(self.cibles),
            "target_argument": self.target_argument,
            "argument_schema": copy.deepcopy(self.argument_schema),
            "result": {"format": self.sortie_format,
                       "extraction": self.extraction.to_dict()},
            "conditions": {"reseau": self.reseau, "timeout_s": self.timeout_s,
                           "privileges": self.privileges},
        }

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id=self.id, transport="mcp", provider_version=self.provider_version,
            server_id=self.server_id, server_version=self.server_version,
            tool=self.tool, tool_version=self.tool_version,
            protocol_version=self.protocol_version, trust=self.trust,
        )

    def arguments_for(self, target: Target, supplied: Mapping[str, Any] | None = None) -> dict:
        """Construit et valide les arguments autorisés, avant tout transport.

        Le target est fourni par le moteur et la propriété qui le porte est déclarée
        dans le registre. Une valeur de target apportée par l'appelant ne peut pas
        écraser celle du moteur.
        """
        if not isinstance(target, Target):
            raise ArgumentValidationError("cible structurée requise")
        if target.kind not in self.cibles:
            raise ArgumentValidationError(
                f"type de cible {target.kind!r} non autorisé pour le provider MCP")
        if supplied is None:
            supplied = {}
        if not isinstance(supplied, Mapping):
            raise ArgumentValidationError("arguments MCP : objet requis")
        try:
            arguments = copy.deepcopy(dict(supplied))
            json.dumps(arguments, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise ArgumentValidationError("arguments MCP non sérialisables") from exc
        if self.target_argument:
            if self.target_argument in arguments:
                raise ArgumentValidationError(
                    f"argument cible {self.target_argument!r} réservé au moteur")
            arguments[self.target_argument] = (
                target.to_dict() if self.target_encoding == "object" else target.value)
        _valider_valeur(arguments, self.argument_schema, "arguments")
        return arguments

    def transport_instance(self, *, env: Mapping[str, str] | None = None):
        if self.server_transport == "stdio":
            return StdioMCPTransport(self.command, env=env)
        return HTTPMCPTransport(self.endpoint, auth_env=self.auth_env)



def _server_doc(spec: Mapping[str, Any]) -> tuple[dict, dict]:
    serveur = spec.get("server") or {}
    outil = spec.get("tool") or {}
    if not isinstance(serveur, dict):
        raise MCPProviderError("MCP: server doit être un objet")
    _refuser_clefs(serveur, _MCP_SERVER_KEYS, "server")
    if isinstance(outil, str):
        outil = {"name": outil}
    if not isinstance(outil, dict):
        raise MCPProviderError("MCP: tool doit être un nom ou un objet")
    _refuser_clefs(outil, _MCP_TOOL_KEYS, "tool")
    # Les formes imbriquée et plate sont acceptées, mais le contrat interne est
    # toujours un objet. Ne jamais appeler une validation texte sur un dictionnaire
    # uniquement parce qu'une valeur par défaut Python a été évaluée trop tôt.
    serveur = dict(serveur)
    outil = dict(outil)
    if "id" not in serveur and spec.get("server_id") is not None:
        serveur["id"] = spec.get("server_id")
    if "name" not in outil and isinstance(spec.get("tool"), str):
        outil["name"] = spec.get("tool")
    return serveur, outil


def valider(spec: Any, capability: str, provider_id: str,
            risque: str = "PASSIVE") -> MCPManifest:
    """Valide une déclaration MCP sans contacter le serveur.

    La validation ne fait aucune découverte réseau : charger un registre ne doit pas
    exécuter un serveur ni donner une autorisation à partir de sa réponse.
    """
    if not isinstance(spec, dict):
        raise MCPProviderError(f"{provider_id}: contrat MCP doit être un objet")
    _refuser_clefs(spec, _MCP_SPEC_KEYS, "contrat")
    for cle, admises, label in (
        ("coverage", frozenset({"declares_files"}), "coverage"),
        ("applicabilite", frozenset({"globs"}), "applicabilite"),
    ):
        valeur = spec.get(cle)
        if valeur is not None:
            if not isinstance(valeur, dict):
                raise MCPProviderError(f"MCP: {label} doit être un objet")
            _refuser_clefs(valeur, admises, label)
    if "requires_network" in spec and not isinstance(spec["requires_network"], bool):
        raise MCPProviderError("MCP: requires_network doit être booléen")
    coverage = spec.get("coverage") or {}
    if "declares_files" in coverage and not isinstance(coverage["declares_files"], bool):
        raise MCPProviderError("MCP: coverage.declares_files doit être booléen")
    applicable = spec.get("applicabilite") or {}
    if "globs" in applicable:
        _liste_texte(applicable["globs"], "applicabilite.globs")
    serveur, outil = _server_doc(spec)
    server_value = serveur.get("id", spec.get("server_id", ""))
    tool_value = outil.get("name", spec.get("tool", ""))
    server_id = _identifiant(_texte({"value": server_value}, "value"), "server_id")
    tool = _identifiant(_texte({"value": tool_value}, "value"), "tool")
    transport_value = serveur.get("transport", spec.get("transport", "http"))
    server_transport = _texte({"value": transport_value}, "value")
    if server_transport not in MCP_SERVER_TRANSPORTS:
        raise MCPProviderError(
            f"{provider_id}: transport serveur MCP {server_transport!r} inconnu — "
            f"admis : {list(MCP_SERVER_TRANSPORTS)}")
    endpoint_value = serveur.get("endpoint", spec.get("endpoint", ""))
    endpoint = _texte({"value": endpoint_value}, "value")
    command_value = serveur.get("command", spec.get("command", ()))
    command = _liste_texte(command_value, "server.command", non_vide=True) if \
        server_transport == "stdio" else ()
    if server_transport == "stdio":
        if any(any(fragment in arg for fragment in _SHELL_FRAGMENTS) for arg in command):
            raise MCPProviderError("MCP stdio: server.command contient un fragment shell")
        endpoint = ""
    else:
        endpoint = _valider_endpoint(endpoint)
    auth_env = _texte(serveur, "auth_env", default=_texte(spec, "auth_env"))
    if auth_env and not _ENV_NAME.fullmatch(auth_env):
        raise MCPProviderError("MCP: auth_env doit être un nom de variable MAJUSCULES_CHIFFRES_")
    protocol = _texte(spec, "protocol_version", default=_texte(serveur, "protocol_version",
                                                                 default=DEFAULT_PROTOCOL_VERSION))
    if protocol not in ("2025-06-18", "2024-11-05", "2024-10-07"):
        raise MCPProviderError(f"MCP: protocol_version non supportée {protocol!r}")
    trust = _texte(spec, "trust", default=(
        "untrusted_local" if server_transport == "stdio" else "untrusted_remote"))
    if trust not in ("trusted_local", "untrusted_local", "trusted_remote", "untrusted_remote"):
        raise MCPProviderError(f"MCP: niveau de confiance inconnu {trust!r}")
    target_types_value = spec.get("target_types", spec.get("targets", ["repository"]))
    target_types = _liste_texte(target_types_value, "target_types", non_vide=True)
    from provider_contract import TARGET_KINDS, TRUST_LEVELS
    invalides = [x for x in target_types if x not in TARGET_KINDS]
    if invalides:
        raise MCPProviderError(f"MCP: target_types inconnus {invalides}")
    argument_schema = spec.get("argument_schema", spec.get("arguments_schema"))
    if argument_schema is None:
        argument_schema = {"type": "object", "properties": {}, "required": [],
                           "additionalProperties": False}
    argument_schema = _valider_schema(argument_schema, "argument_schema")
    if argument_schema.get("type") != "object":
        raise MCPProviderError("MCP: argument_schema doit être de type object")
    target_argument = _texte(spec, "target_argument")
    target_encoding = _texte(spec, "target_encoding", default="value")
    if target_encoding not in ("value", "object"):
        raise MCPProviderError("MCP: target_encoding doit être value ou object")
    if target_argument:
        properties = argument_schema.get("properties", {})
        if target_argument not in properties:
            raise MCPProviderError(
                f"MCP: target_argument {target_argument!r} absent de argument_schema.properties")
        if target_argument not in argument_schema.get("required", []):
            raise MCPProviderError(
                f"MCP: target_argument {target_argument!r} doit être required")
    fmt, extraction = _extraction(spec, provider_id)
    timeout_s = spec.get("timeout_s", spec.get("call_timeout_s", 30))
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int) or timeout_s < 1 or timeout_s > 1800:
        raise MCPProviderError("MCP: timeout_s doit être un entier entre 1 et 1800")
    connect_timeout = spec.get("connect_timeout_s", timeout_s)
    if isinstance(connect_timeout, bool) or not isinstance(connect_timeout, int) \
            or connect_timeout < 1 or connect_timeout > 1800:
        raise MCPProviderError("MCP: connect_timeout_s doit être un entier entre 1 et 1800")
    conditions = {"reseau": server_transport != "stdio" or bool(spec.get("requires_network", False)),
                  "timeout_s": timeout_s,
                  "privileges": spec.get("privileges", "aucun"),
                  "base_fichiers": spec.get("base_fichiers", [])}
    try:
        conditions = COND.valider({"id": provider_id, "conditions": conditions})
    except (TypeError, ValueError) as exc:
        raise MCPProviderError(str(exc)) from None
    if risque not in ("PASSIVE", "ACTIVE", "INTRUSIVE", "DESTRUCTIVE"):
        raise MCPProviderError(f"MCP: risque inconnu {risque!r}")
    # `tool.inputSchema` n'est pas lu volontairement : c'est la métadonnée distante,
    # non l'autorité locale. Le champ approuvé est explicitement `argument_schema`.
    limite = _texte(spec, "limite")
    if not limite:
        limite = "serveur MCP externe non fiable par défaut ; sortie distante normalisée par AGNT"
    return MCPManifest(
        id=provider_id,
        capability=capability,
        kind="api",
        mode="MCP",
        binaire=tool,
        argv=(),
        sortie_format=fmt,
        extraction=extraction,
        risque=risque,
        cibles=target_types,
        code_succes=(0,),
        declare_fichiers=bool((spec.get("coverage") or {}).get("declares_files", False)),
        limite=limite,
        tool_id=tool,
        applicable_globs=tuple((spec.get("applicabilite") or {}).get("globs") or []),
        reseau=conditions["reseau"],
        base_fichiers=tuple(conditions["base_fichiers"]),
        timeout_s=conditions["timeout_s"],
        privileges=conditions["privileges"],
        transport="mcp",
        provider_version=_texte(spec, "provider_version"),
        server_id=server_id,
        server_version=_texte(serveur, "version", default=_texte(spec, "server_version")),
        tool=tool,
        tool_version=_texte(outil, "version", default=_texte(spec, "tool_version")),
        protocol_version=protocol,
        trust=trust,
        server_transport=server_transport,
        endpoint=endpoint,
        command=command,
        auth_env=auth_env,
        argument_schema=argument_schema,
        target_argument=target_argument,
        target_encoding=target_encoding,
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _erreur_sure(value: Any) -> str:
    """Réduit et masque tout message remonté par la frontière distante."""
    return ASS.masquer(str(value or "")[:1000])[0]


def _output_from_call(payload: Mapping[str, Any]) -> Any:
    """Transforme le result MCP en données pour l'extracteur, sans l'afficher brut."""
    structured = payload.get("structuredContent")
    if structured is not None:
        return structured
    content = payload.get("content")
    if isinstance(content, list):
        textes = [item.get("text") for item in content
                  if isinstance(item, dict) and item.get("type") == "text"
                  and isinstance(item.get("text"), str)]
        texte = "\n".join(textes)
        if texte.strip():
            try:
                return json.loads(texte)
            except json.JSONDecodeError:
                return {"texte": ASS.masquer_large(texte)[0]}
        # Une liste de contenus sans texte est une sortie valide mais non lisible
        # par le normaliseur : elle ne devient pas un finding de confiance.
        return None
    # Certains serveurs renvoient directement un objet métier dans result.
    return {k: v for k, v in payload.items() if k not in ("isError",)}


class MCPBackend:
    """Backend provider : validation locale, handshake, appel, résultat typé."""

    def __init__(self, manifest: MCPManifest, *, transport_factory=None,
                 client_version: str = "1") -> None:
        self.manifest = manifest
        self.transport_factory = transport_factory
        self.client_version = client_version

    def _transport(self):
        if self.transport_factory is not None:
            return self.transport_factory(self.manifest)
        return self.manifest.transport_instance()

    def execute(self, *, target: Target, arguments: Mapping[str, Any] | None = None,
                timeout: float | None = None, cancel_event: Any = None) -> ProviderResult:
        # Cette ligne est la barrière essentielle : aucun transport n'est construit
        # avant la validation des arguments et de la cible.
        args = self.manifest.arguments_for(target, arguments)
        debut = _now()
        # Une annulation déjà demandée ne crée ni transport, ni session, ni socket.
        # La cible et les arguments restent validés avant cette sortie anticipée :
        # l'annulation ne contourne jamais le contrat MCP.
        if cancel_event is not None and cancel_event.is_set():
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="cancelled", error="appel MCP annulé",
                raw={"error": "appel MCP annulé"},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id="", started_at=debut, finished_at=_now(), target=target,
                availability=Availability("unknown", "annulation avant invocation", _now()),
            )
        transport = None
        client = None
        try:
            transport = self._transport()
            client = MCPClient(
                transport, approved_tool=self.manifest.tool,
                protocol_version=self.manifest.protocol_version,
                client_version=self.client_version,
                timeout=float(timeout or self.manifest.timeout_s),
            )
            # Découverte optionnelle mais systématique lorsqu'elle est disponible : elle
            # est tracée comme observation, jamais comme source d'autorisation. Un serveur
            # ancien qui ne supporte pas tools/list peut être utilisé pour l'appel approuvé
            # si son handshake et tools/call fonctionnent.
            try:
                tools = client.list_tools(cancel_event=cancel_event)
                if not any(t.get("name") == self.manifest.tool for t in tools):
                    raise ProviderUnavailable(
                        "outil MCP approuvé absent de la découverte du serveur")
            except MCPRemoteError as exc:
                if "method" not in str(exc).lower() and "unknown" not in str(exc).lower():
                    raise
            payload = client.call_tool(args, cancel_event=cancel_event)
            output = _output_from_call(payload)
            if output is None:
                raise InvalidProviderResult("outil MCP : aucune sortie structurée ou textuelle")
            raw = payload
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="succeeded", output=output, raw=raw,
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("available", "handshake et appel réussis", _now()),
            )
        except (MCPTransportTimeout, ProviderTimeout) as exc:
            erreur = _erreur_sure(exc)
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="timed_out", error=erreur, raw={"error": erreur},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("unavailable", "timeout MCP", _now()),
            )
        except MCPTransportCancelled as exc:
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="cancelled", error="appel MCP annulé", raw={"error": "appel MCP annulé"},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("unknown", "appel annulé", _now()),
            )
        except MCPRemoteError as exc:
            # Le serveur est joignable, mais l'outil a rejeté la demande : ce n'est
            # pas une indisponibilité de transport. Le message a déjà été assaini
            # par MCPTransport._valider_reponse.
            erreur = _erreur_sure(exc)
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="failed", error=erreur, raw={"error": erreur},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("available", "erreur distante de l'outil", _now()),
            )
        except MCPProtocolError as exc:
            erreur = _erreur_sure(exc)
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="invalid", error=erreur, raw={"error": erreur},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("unknown", "réponse MCP non conforme", _now()),
            )
        except (ProviderUnavailable, MCPTransportUnavailable, MCPTransportError) as exc:
            erreur = _erreur_sure(exc)
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="unavailable", error=erreur, raw={"error": erreur},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("unavailable", erreur, _now()),
            )
        except InvalidProviderResult as exc:
            erreur = _erreur_sure(exc)
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="invalid", error=erreur, raw={"error": erreur},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("available", "réponse MCP non conforme", _now()),
            )
        except Exception as exc:  # le message est assaini avant de rejoindre le journal
            erreur = ASS.masquer(str(exc)[:1000])[0]
            return ProviderResult(
                identity=self.manifest.identity(), capability=self.manifest.capability,
                status="failed", error=erreur, raw={"error": erreur},
                correlation_id=f"{self.manifest.id}:{self.manifest.tool}",
                request_id=getattr(client, "last_request_id", ""),
                started_at=debut, finished_at=_now(), target=target,
                availability=Availability("unknown", "échec d'appel MCP", _now()),
            )
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass


def backend_for(provider, *, transport_factory=None) -> MCPBackend:
    manifest = getattr(provider, "manifest", None)
    if not isinstance(manifest, MCPManifest):
        raise MCPProviderError(f"{getattr(provider, 'id', '?')}: manifest MCP attendu")
    return MCPBackend(manifest, transport_factory=transport_factory)
