"""Registre de capacités et de providers — Phase 3, version minimale.

Règle de conception (CRITERES.md, MASTER_PROMPT §2) :

    Le planner ne connaît pas Trivy.
    Le registre connaît Trivy.
    L'adaptateur sait exécuter Trivy.

Le moteur ne contient AUCUN nom d'outil en dur. Tout vient de capabilities.yaml.

Périmètre assumé de cette version : analyse ponctuelle d'une cible. Ni surveillance
continue, ni enrichissement de finding, ni remédiation — voir
PHASE3/VALIDATION_GENERALISATION.md (G3, G4).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import provider_manifest as PM

REGISTRY_PATH = Path(__file__).parent / "capabilities.yaml"

RISQUES = ("PASSIVE", "ACTIVE", "INTRUSIVE", "DESTRUCTIVE")

# Les six états de couverture, imposés par la décision D2.
# Sans eux, « aucun problème trouvé » est indiscernable de « rien n'a été analysé ».
ETATS_COUVERTURE = (
    "scanned_successfully",
    "not_found",
    "not_applicable",
    "not_scanned",
    "excluded_by_policy",
    "unsupported",
)


class RegistryError(Exception):
    """Le registre est invalide : on refuse de démarrer plutôt que de deviner."""


@dataclass(frozen=True)
class Provider:
    id: str
    capability: str
    kind: str                      # cli | api | async_job | stream | recursive
    mode: str                      # CLI | API | SDK | conteneur
    risque: str
    commande: list[str]
    args_obligatoires: list[str] = field(default_factory=list)
    sorties: list[str] = field(default_factory=list)
    preconditions: dict = field(default_factory=dict)
    cout: str = "faible"
    # Sélection (décision 2026-08-28) : quand une capacité aura plusieurs providers
    # PASSIF, la plus petite valeur gagne ; à égalité, l'ordre de déclaration
    # (tri stable). Aujourd'hui chaque capacité n'a qu'un provider : le tri ne
    # décide rien, mais le choix cesse d'être un accident de l'ordre YAML, et le
    # motif est tracé dans plan.json (voir plan.construire).
    priorite: int = 100
    # Manifest déclaratif (Phase 5A). Présent → adaptateur générique, aucun code
    # spécifique à l'outil. Absent → adaptateur historique.
    manifest: object = None

    def __post_init__(self) -> None:
        if self.risque not in RISQUES:
            raise RegistryError(f"{self.id}: risque {self.risque!r} inconnu")
        # `tool` est un alias de `cli` : le manifest parle d'outil, le registre de forme
        # d'exécution. Les deux doivent dire la même chose.
        if self.kind not in ("cli", "tool", "api", "async_job", "stream", "recursive"):
            raise RegistryError(f"{self.id}: kind {self.kind!r} non supporté en Phase 3")
        if self.kind not in ("cli", "tool"):
            # Une seule forme d'exécution est implémentée en Phase 3. Prétendre le
            # contraire serait mentir : voir VALIDATION_GENERALISATION.md Q6.
            raise RegistryError(
                f"{self.id}: le kind {self.kind!r} n'est pas implémenté en Phase 3 "
                "(seul 'cli' l'est)"
            )
        if not self.commande:
            raise RegistryError(f"{self.id}: commande vide")


@dataclass(frozen=True)
class Capability:
    id: str
    description: str
    domaines: list[str]
    entree: tuple[str, ...]        # ('cible',) en analyse ponctuelle
    sortie: str
    providers: tuple[Provider, ...]
    # Une capacité interne sert à tester des providers. Elle décrit le MÊME besoin
    # utilisateur qu'une capacité publique, donc la proposer fausserait la sélection.
    interne: bool = False
    # FAN-OUT (étape 3) : « un_seul » (défaut = comportement historique) choisit le
    # provider PASSIF prioritaire ; « fan_out » en choisit jusqu'à max_providers,
    # dans l'ordre de priorité. Le motif du choix est tracé dans plan.json.
    mode_selection: str = "un_seul"
    max_providers: int = 1

    def __post_init__(self) -> None:
        if not self.providers:
            raise RegistryError(f"{self.id}: aucun provider déclaré")
        if self.mode_selection not in ("un_seul", "fan_out"):
            raise RegistryError(
                f"{self.id}: mode_selection {self.mode_selection!r} inconnu "
                f"(un_seul|fan_out)")
        if self.max_providers < 1:
            raise RegistryError(f"{self.id}: max_providers doit être >= 1")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class Registry:
    """Charge et valide capabilities.yaml. Échoue bruyamment si le schéma n'est pas respecté."""

    def __init__(self, chemin: Path | str = REGISTRY_PATH) -> None:
        self.chemin = Path(chemin)
        self._cap: dict[str, Capability] = {}
        self._prov: dict[str, Provider] = {}
        self._charge()

    def _charge(self) -> None:
        if not self.chemin.exists():
            raise RegistryError(f"registre introuvable : {self.chemin}")
        doc = yaml.safe_load(self.chemin.read_text(encoding="utf-8")) or {}
        bruts = doc.get("capabilities")
        if not bruts:
            raise RegistryError("registre vide ou clé 'capabilities' absente")

        for c in bruts:
            manquants = [k for k in ("id", "description", "domaines", "entree", "sortie", "providers")
                         if k not in c]
            if manquants:
                raise RegistryError(f"capacité {c.get('id', '?')}: champs manquants {manquants}")
            provs = []
            for p in c["providers"]:
                if "id" not in p or "commande" not in p:
                    raise RegistryError(f"capacité {c['id']}: provider sans id ou sans commande")
                # Un provider peut être déclaré par MANIFEST : il est validé ICI, au
                # chargement — donc avant toute exécution, et indépendamment d'OPA.
                mani = PM.valider(p["manifest"], c["id"]) if "manifest" in p else None
                try:
                    prio = int(p.get("priorite", 100))
                except (TypeError, ValueError):
                    raise RegistryError(
                        f"provider {p['id']} : 'priorite' doit être un entier "
                        f"(reçu : {p.get('priorite')!r})")
                prov = Provider(
                    id=p["id"],
                    capability=c["id"],
                    manifest=mani,
                    kind=p.get("kind", "cli"),
                    mode=p.get("mode", "CLI"),
                    risque=p.get("risque", "PASSIVE"),
                    commande=list(p["commande"]),
                    args_obligatoires=list(p.get("args_obligatoires", [])),
                    sorties=list(p.get("sorties", [])),
                    preconditions=dict(p.get("preconditions", {})),
                    cout=p.get("cout", "faible"),
                    priorite=prio,
                )
                if prov.id in self._prov:
                    raise RegistryError(f"provider en double : {prov.id}")
                self._prov[prov.id] = prov
                provs.append(prov)
            cap = Capability(
                id=c["id"],
                interne=bool(c.get("interne", False)),
                description=c["description"],
                domaines=list(c["domaines"]),
                entree=tuple(c["entree"]),
                sortie=c["sortie"],
                providers=tuple(provs),
                mode_selection=str(c.get("mode_selection", "un_seul")),
                max_providers=int(c.get("max_providers", 1)),
            )
            if cap.id in self._cap:
                raise RegistryError(f"capacité en double : {cap.id}")
            self._cap[cap.id] = cap

    # ------------------------------------------------------------------ accès
    def capabilities(self) -> list[Capability]:
        return list(self._cap.values())

    def capability(self, cid: str) -> Capability:
        if cid not in self._cap:
            raise RegistryError(f"capacité inconnue : {cid}")
        return self._cap[cid]

    def provider(self, pid: str) -> Provider:
        if pid not in self._prov:
            raise RegistryError(f"provider inconnu : {pid}")
        return self._prov[pid]

    def providers(self) -> list[Provider]:
        return list(self._prov.values())

    def empreinte(self) -> str:
        """Empreinte du registre : un plan rejoué doit pouvoir prouver qu'il a été
        autorisé contre la même version du registre."""
        return _sha(self.chemin.read_text(encoding="utf-8"))

    # ---------------------------------------------------- rendu pour le LLM
    def publiques(self) -> list[Capability]:
        """Capacités proposées à la sélection. Les internes en sont exclues."""
        return [c for c in self._cap.values() if not c.interne]

    def descr(self) -> str:
        """Description des capacités, destinée au contexte du LLM.

        Le LLM ne voit QUE l'identifiant de capacité, sa description et ses domaines.
        Ni nom d'outil, ni commande, ni chemin, ni drapeau. C'est ce qui garantit
        structurellement qu'il ne peut pas produire une commande shell — et c'est la
        règle du projet : « le planner ne connaît pas Trivy ».

        Les capacités INTERNES en sont exclues : elles décrivent le même besoin
        utilisateur qu'une capacité publique, et les proposer ferait sur-sélectionner.
        """
        lignes = []
        for c in self.publiques():
            lignes.append(f"- {c.id} : {c.description}")
            lignes.append(f"    domaines : {', '.join(c.domaines)}")
            lignes.append(f"    providers disponibles : {len(c.providers)}")
        return "\n".join(lignes)

