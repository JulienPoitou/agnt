"""Transports d'exécution — la frontière entre un provider et la façon de l'exécuter.

La règle du projet (« le planner ne connaît pas Trivy, le registre connaît Trivy,
l'adaptateur sait exécuter Trivy ») laissait un implicite : l'adaptateur sait exécuter
Trivy PAR UN SOUS-PROCESSUS dans la cage bwrap. Le provider était donc synonyme de
« binaire local lancé en sous-processus », sans que ce couplage soit écrit nulle part.

Ce module rend la frontière EXPLICITE :

    Provider      → CE QU'ON VEUT    (argv, env, format de sortie, conditions)
    Transport     → COMMENT ON L'EXÉCUTE (sous-processus sandboxé, MCP, API distante…)

Le cœur fournit UN transport, `sandbox_cli` (sous-processus dans la cage bwrap, dans
`adapters.py`). Un agent qui veut un autre transport (builder-mcp pour les providers
externes, builder-tools pour des outils non-CLI) ENREGISTRE le sien ici :

    import transports
    transports.enregistrer("mcp", mon_executeur)   # mon_executeur(prov, sbx) -> ResultatBrut

Un provider déclare alors `transport: mcp` dans son manifest. Le registre le VALIDE au
chargement (un transport inconnu est refusé, jamais deviné) et l'exécution le DÉLÈGUE au
transport enregistré — sans que le cœur d'exécution change. Tant qu'aucun transport n'est
enregistré, un manifest qui en déclare un inconnu est refusé : c'est un défaut fermé, pas
une exécution silencieuse dans le mauvais transport.

Volontairement un petit module (pas d'import du slice) : il est importable par
`provider_manifest` (validation au chargement) et par `adapters` (délégation à
l'exécution) sans créer de cycle.

CONTRAT POUR LES AGENTS QUI BRANCHENT UN TRANSPORT (MCP-004)
------------------------------------------------------------
API canonique — quatre fonctions, UNE exception (`TransportError`) :

    enregistrer(nom: str, executeur) -> None     # pose l'exécuteur
    fournit(nom: str) -> bool                    # « est-ce exécutable ? »
    connus() -> tuple[str, ...]                  # diagnostic / messages de refus
    deleguer(nom: str, prov, sbx)                # exécute ET rend le résultat

Sémantique, point par point :

· **Appel de l'exécuteur** : `deleguer` appelle `executeur(prov, sbx)` — DEUX arguments
  positionnels, et rien d'autre. Des paramètres mot-clés supplémentaires à valeur par
  défaut (`*, target=None, arguments=None, transport_factory=None`) sont donc compatibles
  tels quels. Retour attendu : le même objet brut que `adapters.executer` produit.
· **Fail-closed, sans repli** : un nom non enregistré lève `TransportError`. Il n'y a
  AUCUN chemin qui rabatte sur un sous-processus local — un provider qui demande MCP
  exécuté en CLI local est exactement le mélange de concepts que ce module interdit.
· **Une seule exception** : le cœur ne distingue pas `UnknownTransport` /
  `DuplicateTransport`. Un raccord qui veut lever ses propres types doit les faire
  hériter de `TransportError`, sinon `adapters` ne les attrape pas.
· **Ré-enregistrement autorisé** : `enregistrer` ÉCRASE. Un bootstrap idempotent appelle
  donc `enregistrer("mcp", …)` sans condition ; pour tester une présence existante,
  c'est `fournit("mcp")` (pas `obtenir`, qui n'existe pas ici).
· **`sandbox_cli` est réservé** : `enregistrer("sandbox_cli", …)` est refusé. Il est
  exécuté nativement par `adapters.executer` et ne passe jamais par `deleguer`.
· **`connus()` inclut `sandbox_cli`** (c'est la liste des transports exécutables, utilisée
  dans les messages de refus) ; `fournit("sandbox_cli")` est donc `True`.
· **Aucun retrait** : un transport retiré à chaud casserait des manifests déjà chargés.
  La validation des manifests se fait au chargement contre `connus()`/`fournit()`.

Correspondance avec le registre provisoire de la branche MCP :

    MCP provisoire            CORE canonique
    enregistrer(nom, exec)    enregistrer(nom, exec)   — écrase au lieu de lever
    obtenir(nom)              (absent)                 — dispatch via deleguer(nom, …)
    enregistre(nom)           fournit(nom)
    noms()                    connus()                 — inclut `sandbox_cli`
    UnknownTransport          TransportError
    DuplicateTransport        (aucun équivalent : écrasement)
    TransportRegistryError    TransportError

"""
from __future__ import annotations


class TransportError(Exception):
    """Un provider demande un transport que le cœur ne fournit pas.

    Ce n'est ni une erreur d'outil ni un échec de scan : l'exécution n'a pas commencé,
    et le dire précisément est ce qui permet à l'agent concerné (builder-mcp, …) de
    brancher son transport plutôt que de voir un provider « silencieusement local ».
    """


# Nom du transport fourni par le cœur. Tout le reste doit être ENREGISTRÉ avant d'être
# déclaré dans un manifest — sinon le registre refuse au chargement.
TRANSPORT_SANDBOX_CLI = "sandbox_cli"

# Transport → callable(prov, sbx) -> ResultatBrut. Le cœur n'y met rien : `sandbox_cli`
# est exécuté nativement par `adapters.executer`. Les entrées sont posées par les agents
# qui ajoutent un transport (aucune entrée n'est retirée : un transport retiré à chaud
# casserait des manifests déjà chargés).
_EXECUTEURS: dict[str, object] = {}


def enregistrer(nom: str, executeur) -> None:
    """Enregistre un transport tiers. Deux gardes, toutes deux fail-closed :

    · le nom doit être non vide (un transport sans nom n'est pas déclarable) ;
    · l'exécuteur doit être appelable (un « transport » muet rendrait un faux résultat).
    """
    if not nom or not isinstance(nom, str):
        raise TransportError(f"nom de transport invalide : {nom!r}")
    if not callable(executeur):
        raise TransportError(f"transport {nom!r} : l'exécuteur doit être appelable")
    if nom == TRANSPORT_SANDBOX_CLI:
        raise TransportError(
            f"transport {nom!r} réservé au cœur — enregistrer un autre nom")
    _EXECUTEURS[nom] = executeur


def fournit(nom: str) -> bool:
    """Le cœur (ou un agent) sait-il exécuter ce transport ?"""
    return nom == TRANSPORT_SANDBOX_CLI or nom in _EXECUTEURS


def connus() -> tuple[str, ...]:
    """Les transports exécutables — pour les messages de refus et le diagnostic."""
    return tuple(sorted([TRANSPORT_SANDBOX_CLI, *_EXECUTEURS]))


def deleguer(nom: str, prov, sbx):
    """Exécute un provider via un transport TIERS enregistré.

    `sandbox_cli` ne passe jamais par ici : il est exécuté nativement par
    `adapters.executer`. Un nom inconnu lève `TransportError` (jamais un repli sur le
    sous-processus — un provider qui demande MCP exécuté en sous-processus local serait
    exactement le mélange de concepts que ce module existe pour empêcher).
    """
    fn = _EXECUTEURS.get(nom)
    if fn is None:
        raise TransportError(
            f"transport {nom!r} non fourni — transports connus : {list(connus())}. "
            f"Enregistrez-le avec transports.enregistrer({nom!r}, exécuteur) avant de "
            f"déclarer un provider qui l'exige.")
    return fn(prov, sbx)
