"""Initialisation explicite de l'extension MCP du CORE.

Point d'intégration : l'application appelle une fois, avant le premier ``Registry()``
qui peut contenir un provider MCP::

    import transports
    from mcp_bootstrap import initialiser_mcp
    initialiser_mcp(transports)

Le module ne s'auto-enregistre pas à l'import et ne doit pas être appelé par chaque
requête Web. ``transports`` est injecté pour que builder-core reste l'autorité sur le
registre canonique : ce module ne connaît AUCUNE implementation de registre, il
n'utilise que ``enregistrer`` et ``fournit``.

MCP-004 : le petit registre de transports qui vivait dans ce checkout a été supprimé au
profit du module CORE canonique. Il n'y a donc plus d'API à deviner (``obtenir``,
``enregistre``, ``noms``) : le dispatch passe par ``transports.deleguer`` et la
validation par ``transports.fournit``.
"""

from __future__ import annotations

from typing import Any

# Nom du transport exposé par cette extension. Déclaré ici, pas recopié ailleurs.
TRANSPORT_MCP = "mcp"

# Vrai une fois que CETTE instance de module a enregistré l'exécuteur. Le registre
# canonique ne permet pas de relire un exécuteur enregistré (pas d'`obtenir`) : la
# seule façon honnête de distinguer « déjà enregistré par nous » de « enregistré par
# quelqu'un d'autre » est de se souvenir de notre propre enregistrement.
_ENREGISTRE_PAR_NOUS = False


class MCPBootstrapError(Exception):
    """Le point d'extension CORE ne respecte pas le contrat attendu."""


def _executeur(prov, sbx, *, target=None, arguments=None, transport_factory=None,
               cancel_event=None):
    """Exécuteur enregistré dans le registre canonique ; aucune sélection ni policy ici.

    La signature accepte le contexte par appel que ``transports.deleguer`` transmet
    (cible typée, arguments validés, fabrique de transport pour les tests, événement
    d'annulation). Le perdre en silence serait plus grave qu'un échec net : une
    annulation ignorée continuerait d'appeler un serveur distant après l'arrêt demandé.
    """
    # Import tardif : le bootstrap est appelé avant le module adapters, et ce dernier
    # importe le backend MCP.
    from adapters import mcp
    return mcp(prov, sbx, target=target, arguments=arguments,
               transport_factory=transport_factory, cancel_event=cancel_event)


def initialiser_mcp(transports: Any) -> None:
    """Enregistre le transport ``mcp`` une seule fois, sans écrasement.

    Trois issues, toutes fail-closed :

    · le registre injecté n'expose pas ``enregistrer``/``fournit`` → erreur (on ne
      devine pas une autre API, on ne retombe pas sur un CLI local) ;
    · ``mcp`` est déjà fourni par quelqu'un d'autre → erreur, jamais d'écrasement
      silencieux d'un transport homonyme ;
    · déjà enregistré par nous → retour idempotent (une application peut exposer
      plusieurs façades CLI/API dans le même process).
    """
    global _ENREGISTRE_PAR_NOUS

    enregistrer = getattr(transports, "enregistrer", None)
    fournit = getattr(transports, "fournit", None)
    if not callable(enregistrer) or not callable(fournit):
        raise MCPBootstrapError(
            "registre de transports CORE requis : enregistrer(nom, executeur) et "
            "fournit(nom) doivent être présents")

    if fournit(TRANSPORT_MCP):
        if _ENREGISTRE_PAR_NOUS:
            return
        raise MCPBootstrapError(
            f"transport {TRANSPORT_MCP!r} déjà enregistré par un autre exécuteur — "
            "aucun écrasement n'est tenté")
    try:
        enregistrer(TRANSPORT_MCP, _executeur)
    except Exception as exc:
        # Le registre CORE garde la décision d'enregistrement ; on ne tente aucun
        # remplacement ni fallback local.
        raise MCPBootstrapError(
            f"enregistrement du transport MCP refusé : {exc}") from None
    _ENREGISTRE_PAR_NOUS = True


def reinitialiser_pour_test() -> None:
    """Réarme le souvenir d'enregistrement — pour les tests uniquement.

    Le registre canonique ne retire jamais une entrée (un transport retiré à chaud
    casserait des manifests déjà chargés) ; seul ce module oublie qu'il a enregistré.
    """
    global _ENREGISTRE_PAR_NOUS
    _ENREGISTRE_PAR_NOUS = False


__all__ = ["MCPBootstrapError", "TRANSPORT_MCP", "initialiser_mcp",
           "reinitialiser_pour_test"]
