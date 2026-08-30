"""Contrat commun des providers et de leurs backends d'exécution.

Le pipeline AGNT ne doit pas avoir à savoir si une capacité est servie par un
binaire local, un serveur MCP ou, demain, une API HTTP. Ce module porte uniquement
les objets de frontière :

* une identité stable de provider (distincte du serveur, de l'outil et du protocole) ;
* une cible structurée (distincte du transport) ;
* un résultat d'invocation avec un statut explicite ;
* un contrat minimal de backend.

Les classes sont volontairement synchrones : le pipeline actuel est synchrone par
provider et parallélise les providers au niveau de ses vagues. Un backend peut
utiliser de l'asynchrone en interne plus tard, sans changer le plan ni le modèle de
résultat.

Ce contrat ne donne aucune autorisation. L'autorisation reste dans le registre, le
plan et la policy. Les données retournées par un provider sont toujours considérées
comme non fiables.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol, Sequence

import transports


# MCP-004 : il n'y a plus de liste de transports codée en dur ici. La seule autorité
# est le registre canonique du cœur (`transports.fournit` / `transports.connus`) : un
# agent qui ajoute un transport l'ENREGISTRE, il ne vient pas s'ajouter à un tuple.
TRUST_LEVELS = (
    "trusted_local",
    "untrusted_local",
    "trusted_remote",
    "untrusted_remote",
)

TARGET_KINDS = (
    "repository",
    "filesystem",
    "url",
    "host",
    "network",
    "container",
    "image",
    "cloud_resource",
    "finding",
)

RESULT_STATUSES = (
    "succeeded",
    "failed",
    "unavailable",
    "timed_out",
    "invalid",
    "cancelled",
)


class ProviderContractError(Exception):
    """Erreur de contrat, détectable avant ou pendant une invocation."""


class ArgumentValidationError(ProviderContractError):
    """Les arguments structurés ne respectent pas le contrat autorisé."""


class ProviderUnavailable(ProviderContractError):
    """Le backend ne peut pas joindre le provider ou la capacité."""


class ProviderTimeout(ProviderContractError):
    """Le délai de connexion ou d'appel a été dépassé."""


class ProviderInvocationError(ProviderContractError):
    """Le provider a répondu par une erreur d'exécution."""


class InvalidProviderResult(ProviderContractError):
    """La réponse du provider ne respecte pas le contrat de résultat."""


@dataclass(frozen=True)
class ProviderIdentity:
    """Identité logique et versions, sans dépendre d'un PID ou d'une adresse.

    `provider_id` est l'identité enregistrée et stable. Les autres champs décrivent
    les acteurs de la chaîne séparément : un serveur MCP et un outil MCP ne sont pas
    le provider logique AGNT, et leurs versions ne doivent pas être concaténées dans
    un seul champ ambigu.
    """

    provider_id: str
    transport: str = "local"
    provider_version: str = ""
    server_id: str = ""
    server_version: str = ""
    tool: str = ""
    tool_version: str = ""
    protocol_version: str = ""
    trust: str = "trusted_local"

    def __post_init__(self) -> None:
        if not self.provider_id or not isinstance(self.provider_id, str):
            raise ProviderContractError("provider_id doit être une chaîne non vide")
        if not transports.fournit(self.transport):
            raise ProviderContractError(
                f"transport non fourni : {self.transport!r} — transports connus : "
                f"{list(transports.connus())}")
        if self.trust not in TRUST_LEVELS:
            raise ProviderContractError(
                f"niveau de confiance inconnu : {self.trust!r} — "
                f"admis : {list(TRUST_LEVELS)}")
        if self.transport == "mcp" and not self.server_id:
            raise ProviderContractError("un provider MCP doit déclarer server_id")
        if self.transport == "mcp" and not self.tool:
            raise ProviderContractError("un provider MCP doit déclarer l'outil approuvé")

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "transport": self.transport,
            "provider_version": self.provider_version,
            "server_id": self.server_id,
            "server_version": self.server_version,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "protocol_version": self.protocol_version,
            "trust": self.trust,
        }


@dataclass(frozen=True)
class Target:
    """Cible structurée, indépendante de la manière de joindre le provider."""

    kind: str
    value: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in TARGET_KINDS:
            raise ProviderContractError(
                f"type de cible inconnu : {self.kind!r} — admis : {list(TARGET_KINDS)}")
        if not isinstance(self.value, str) or not self.value:
            raise ProviderContractError("la valeur de cible doit être une chaîne non vide")
        # La cible est une donnée JSON, jamais un fragment de commande. Refuser les
        # valeurs non sérialisables ici permet aux backends de ne pas faire de coercion
        # implicite dangereuse.
        try:
            json.dumps(dict(self.metadata), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise ProviderContractError("metadata de cible non sérialisable") from exc

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value,
                "metadata": dict(self.metadata)}


@dataclass(frozen=True)
class Availability:
    """État de disponibilité, sans le confondre avec la sélection ou l'autorisation."""

    status: str  # available | unavailable | unknown
    reason: str = ""
    checked_at: str = ""

    def __post_init__(self) -> None:
        if self.status not in ("available", "unavailable", "unknown"):
            raise ProviderContractError(f"statut de disponibilité inconnu : {self.status!r}")

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason,
                "checked_at": self.checked_at}


@dataclass(frozen=True)
class ProviderResult:
    """Résultat indépendant du protocole et prêt à être normalisé par AGNT.

    `output` est une donnée structurée non fiable. `raw` est la réponse transport
    déjà assainie, conservée pour la traçabilité ; aucun backend ne doit y placer un
    secret d'authentification.
    """

    identity: ProviderIdentity
    capability: str
    status: str
    output: Any = None
    raw: Any = None
    error: str = ""
    request_id: str = ""
    correlation_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    target: Target | None = None
    availability: Availability | None = None

    def __post_init__(self) -> None:
        if self.status not in RESULT_STATUSES:
            raise ProviderContractError(f"statut de résultat inconnu : {self.status!r}")
        if not self.capability:
            raise ProviderContractError("un résultat doit référencer une capability")
        # Un résultat réussi sans sortie est autorisé (certains providers ne rendent
        # qu'un accusé), mais il est toujours distingué par `status`; le normaliseur
        # décidera alors qu'il n'y a aucune observation, jamais que l'appel n'a eu lieu.
        for nom, objet in (("output", self.output), ("raw", self.raw)):
            if objet is None:
                continue
            try:
                json.dumps(objet, ensure_ascii=False, default=str)
            except (TypeError, ValueError) as exc:
                raise ProviderContractError(f"{nom} n'est pas sérialisable") from exc

    @property
    def ok(self) -> bool:
        return self.status == "succeeded"

    def to_dict(self) -> dict[str, Any]:
        d = {
            "provider": self.identity.to_dict(),
            "capability": self.capability,
            "status": self.status,
            "error": self.error,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target": self.target.to_dict() if self.target else None,
            "availability": self.availability.to_dict() if self.availability else None,
        }
        # Le résultat canonique est exportable séparément du brut. Ne pas remplacer
        # `None` par {} : l'absence d'une sortie est un fait utile pour le ledger.
        d["output"] = self.output
        return d


class ExecutionBackend(Protocol):
    """Contrat minimal consommé par le pipeline, quel que soit le transport."""

    def execute(
        self,
        *,
        target: Target,
        arguments: Mapping[str, Any] | None = None,
        timeout: float | None = None,
        cancel_event: Any = None,
    ) -> ProviderResult:
        ...


TransportFactory = Callable[..., Any]


@dataclass(frozen=True)
class ProviderDescriptor:
    """Vue commune utile aux backends et aux consommateurs (web, ledger, policy)."""

    identity: ProviderIdentity
    capability: str
    target_types: tuple[str, ...] = ("repository",)
    risk: str = "PASSIVE"
    availability: Availability = field(
        default_factory=lambda: Availability("unknown", "non vérifiée"))

    def __post_init__(self) -> None:
        invalides = [x for x in self.target_types if x not in TARGET_KINDS]
        if invalides:
            raise ProviderContractError(f"types de cible inconnus : {invalides}")
        if self.risk not in ("PASSIVE", "ACTIVE", "INTRUSIVE", "DESTRUCTIVE"):
            raise ProviderContractError(f"niveau de risque inconnu : {self.risk!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "capability": self.capability,
            "target_types": list(self.target_types),
            "risk": self.risk,
            "availability": self.availability.to_dict(),
        }
