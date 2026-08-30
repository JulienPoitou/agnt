"""Initialisation explicite de l'extension MCP du CORE.

Point d'intégration : l'application appelle une fois, avant le premier ``Registry()``
qui peut contenir un provider MCP::

    import transports
    from mcp_bootstrap import initialiser_mcp
    initialiser_mcp(transports)

Le module ne s'auto-enregistre pas à l'import et ne doit pas être appelé par chaque
requête Web. ``transports`` est injecté pour que builder-core reste l'autorité sur le
registre générique ; le petit registre local de ce checkout expose la même API jusqu'à
ce que le CORE canonique soit présent sur la branche intégrée.
"""

from __future__ import annotations

from typing import Any


class MCPBootstrapError(Exception):
    """Le point d'extension CORE ne respecte pas le contrat attendu."""


def _executeur(prov, sbx, *, target=None, arguments=None, transport_factory=None,
               cancel_event=None):
    """Adapter enregistré dans le CORE ; aucune sélection ni policy ici."""
    # Import tardif : le bootstrap importe le registre générique avant le module
    # adapters, et ce dernier importe le backend MCP.
    from adapters import mcp
    return mcp(prov, sbx, target=target, arguments=arguments,
               transport_factory=transport_factory, cancel_event=cancel_event)


def initialiser_mcp(transports: Any) -> None:
    """Enregistre ``mcp`` une seule fois, sans écrasement.

    Une double initialisation est une erreur même si elle vient du même executor : cela
    rend visible un bootstrap placé par mégarde dans le chemin d'une requête. Le process
    d'application doit donc appeler cette fonction exactement une fois.
    """
    enregistrer = getattr(transports, "enregistrer", None)
    if not callable(enregistrer):
        raise MCPBootstrapError(
            "CORE transports requis : transports.enregistrer(nom, executeur) absent")
    # Une application peut exposer plusieurs façades (CLI/API) dans le même process de
    # test. La seconde initialisation ne réenregistre rien : elle vérifie seulement que
    # l'entrée existante est bien la nôtre. Une entrée d'un autre executor reste une
    # erreur, jamais un écrasement silencieux. ``enregistre`` est l'aide du raccord local;
    # ``obtenir`` permet la même vérification avec le CORE canonique s'il ne l'expose pas.
    deja = getattr(transports, "enregistre", None)
    obtenir = getattr(transports, "obtenir", None)
    present = False
    existant = None
    if callable(deja):
        present = bool(deja("mcp"))
    elif callable(obtenir):
        try:
            existant = obtenir("mcp")
            present = True
        except Exception:
            # Le CORE signale normalement l'inconnu par une exception dédiée. On
            # n'utilise pas cette erreur comme fallback d'exécution : elle sert
            # uniquement à savoir si l'inscription initiale est encore nécessaire.
            present = False
    if present:
        if existant is None and callable(obtenir):
            existant = obtenir("mcp")
        if existant is _executeur:
            return
        raise MCPBootstrapError("transport mcp déjà enregistré par un autre executor")
    try:
        enregistrer("mcp", _executeur)
    except Exception as exc:
        # Le registre CORE garde la décision de double enregistrement ; on ne tente
        # aucun remplacement ni fallback local.
        raise MCPBootstrapError(f"enregistrement du transport MCP refusé : {exc}") from None


__all__ = ["MCPBootstrapError", "initialiser_mcp"]
