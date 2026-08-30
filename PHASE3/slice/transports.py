"""Extension point générique des transports du CORE.

Ce module ne contient aucune logique MCP. Il expose le registre minimal attendu par le
cœur : un transport externe s'enregistre une fois avec ``enregistrer`` puis le dispatch
du pipeline le résout par son nom. Dans un checkout qui reçoit le registre CORE canonique,
ce fichier doit être remplacé par (ou aligné sur) l'implémentation CORE, jamais doublé par
un registre MCP.

Le registre est volontairement fail-closed : un nom inconnu ou une double inscription
lève une erreur. Aucun fallback vers ``sandbox_cli`` ou un exécutable local n'est fourni
ici ; le transport local est une responsabilité distincte du CORE.
"""

from __future__ import annotations

from threading import RLock
from typing import Any, Callable


class TransportRegistryError(Exception):
    """Le contrat générique de transports n'autorise pas l'opération demandée."""


class UnknownTransport(TransportRegistryError):
    """Aucun executor n'est enregistré pour ce transport."""


class DuplicateTransport(TransportRegistryError):
    """Un nom ne peut pas être réenregistré ou écrasé silencieusement."""


_EXECUTEURS: dict[str, Callable[..., Any]] = {}
_VERROU = RLock()


def _nom(nom: str) -> str:
    if not isinstance(nom, str) or not nom or nom != nom.strip():
        raise TransportRegistryError("nom de transport non vide requis")
    return nom


def enregistrer(nom: str, executeur: Callable[..., Any]) -> None:
    """Enregistre un executor unique pour ``nom``.

    L'appel est explicitement effectué par le bootstrap de l'application. Cette fonction
    n'est pas appelée pendant une requête et ne remplace jamais une entrée existante.
    """
    nom = _nom(nom)
    if not callable(executeur):
        raise TransportRegistryError(f"executor non appelable pour le transport {nom!r}")
    with _VERROU:
        if nom in _EXECUTEURS:
            raise DuplicateTransport(f"transport déjà enregistré : {nom}")
        _EXECUTEURS[nom] = executeur


def obtenir(nom: str) -> Callable[..., Any]:
    """Retourne l'executor ou refuse : le dispatch ne devine pas de fallback."""
    nom = _nom(nom)
    with _VERROU:
        try:
            return _EXECUTEURS[nom]
        except KeyError:
            raise UnknownTransport(f"transport non enregistré : {nom}") from None


def enregistre(nom: str) -> bool:
    """Indique si le transport est déjà enregistré, sans modifier le registre."""
    nom = _nom(nom)
    with _VERROU:
        return nom in _EXECUTEURS


def noms() -> tuple[str, ...]:
    """Vue immuable utile au diagnostic et aux tests."""
    with _VERROU:
        return tuple(sorted(_EXECUTEURS))


def _reinitialiser_pour_test() -> None:
    """Réinitialisation strictement réservée aux tests isolés.

    Le runtime ne l'appelle jamais : effacer le registre en production serait un
    changement d'autorité et rendrait les missions dépendantes de l'ordre des tests.
    """
    with _VERROU:
        _EXECUTEURS.clear()
