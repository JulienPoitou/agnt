"""Plan typé — la frontière de sécurité.

Le plan est l'objet que le policy engine autorise ou refuse. Trois propriétés le rendent
efficace comme frontière :

    1. il est TYPÉ      → on ne peut pas y glisser une commande arbitraire ;
    2. il est SÉRIALISABLE → il est auditable et stockable ;
    3. il est REJOUABLE  → mêmes entrées, même empreinte de registre, même résultat.

L'IA ne produit JAMAIS cet objet directement : elle produit une liste de capacités,
et le plan est construit à partir du registre. Une commande n'existe donc que si le
registre la déclare.

    AI PLANNER → PLAN → POLICY ENGINE → EXECUTOR
    et non
    AI → SHELL
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

import cible as CIB
from registre import Registry

VERSION_PLAN = "1.1"

# Budget global d'exécutions par plan (étape 3). Ordinal et volontairement large :
# c'est un garde-fou contre l'explosion combinatoire, pas un réglage fin — le
# coût vectoriel viendra plus tard (architecture gelée, §11).
MAX_ETAPES = 12


def verifier_budget(providers: list[str]) -> None:
    if len(providers) > MAX_ETAPES:
        raise PlanError(
            f"budget d'exécutions dépassé : {len(providers)} providers demandés "
            f"> {MAX_ETAPES} (garde-fou anti-explosion, étape 3)")


def inventaire(cible: Path, limite: int = 20000) -> list[str]:
    """Liste déterministe des fichiers de la cible (chemins relatifs, triés).

    `.git` est exclu (métadonnées, jamais analysées comme du code). La limite
    borne le coût sur les très gros dépôts : au-delà, la liste est tronquée —
    le filtrage d'applicabilité reste alors CONSERVATEUR (un provider peut
    rester éligible à tort, jamais écarté à tort par truncation… la troncature
    est appliquée APRÈS le tri, donc déterministe).
    """
    fichiers = []
    for p in sorted(cible.rglob("*")):
        if ".git" in p.parts or not p.is_file():
            continue
        fichiers.append(str(p.relative_to(cible)))
        if len(fichiers) >= limite:
            break
    return fichiers


def filtrer_applicabilite(providers: list[str], registre: Registry,
                          cible) -> tuple[list[str], dict[str, str]]:
    """Écarte AVANT exécution les providers déclarés inapplicables à la cible.

    Règles (architecture gelée) :
      · l'applicabilité est DÉCLARÉE au manifest (globs + target_types) — jamais devinée ;
      · sans déclaration, le provider reste éligible (une fausse exclusion est
        pire qu'un not_scanned honnête) ;
      · chaque exclusion porte un motif qui finit dans plan.json.

    Depuis le descripteur de cible (2026-08-30), DEUX conditions s'ajoutent sans se
    remplacer :
      · TARGET_TYPES : un provider n'est applicable qu'au TYPE de cible qu'il déclare
        (`cible.applicable`). C'est la règle unique entre le descripteur et les
        manifests — un provider local est écarté d'une cible `url`, jamais lancé
        dessus ;
      · GLOBS : inchangé, et seulement pour les cibles LOCALES — une cible non locale
        n'a pas d'inventaire de fichiers, donc pas de filtrage par glob.
    """
    cib = CIB.normaliser(cible)
    inv = inventaire(cib.chemin_local) if cib.est_local and cib.chemin_local else []
    eligibles, exclus = [], {}
    for pid in providers:
        prov = registre.provider(pid)
        types = CIB.types_applicables(prov)
        if not CIB.applicable(cib.type, types):
            exclus[pid] = (f"type de cible {cib.type!r} hors des types déclarés "
                           f"{list(types)} — provider non applicable à cette cible")
            continue
        globs = tuple(prov.manifest.applicable_globs) if prov.manifest else ()
        if cib.est_local and globs and not any(
                fnmatch.fnmatch(f, g) for f in inv for g in globs):
            exclus[pid] = (f"non applicable à cette cible : aucun fichier ne "
                           f"correspond aux globs déclarés {list(globs)}")
        else:
            eligibles.append(pid)
    return eligibles, exclus


def canonicaliser(requete: str) -> str:
    """Forme canonique d'une requête.

    Deux formulations de la MÊME intention doivent donner le même plan_id :

        « Analyse la sécurité de mon dépôt »
        « analyse la sécurité de mon depot »      → même plan

    En revanche deux intentions différentes restent différentes :

        « vérifie les dépendances »               → autre plan

    La phrase originale est conservée dans `requete` — c'est `requete_canonique` qui
    définit l'identité. Normalisation : minuscules, accents retirés, ponctuation
    supprimée, espaces réduits.
    """
    t = unicodedata.normalize("NFKD", requete or "")
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = t.lower()
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return " ".join(t.split())


class PlanError(Exception):
    pass


@dataclass(frozen=True)
class Step:
    capability: str
    provider: str
    risque: str
    commande: list[str]          # issue du registre, jamais de l'IA
    args: list[str]              # issue du registre (args_obligatoires)
    sorties: list[str] = field(default_factory=list)
    # Métadonnées du contrat provider. Elles décrivent la chaîne d'exécution sans
    # transformer un provider externe en commande locale. Les valeurs viennent du
    # registre, jamais de l'intention produite par l'IA.
    transport: str = "local"
    provider_version: str = ""
    server_id: str = ""
    server_version: str = ""
    tool: str = ""
    tool_version: str = ""
    protocol_version: str = ""
    trust: str = "trusted_local"
    target_types: tuple[str, ...] = ("repository",)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Plan:
    requete: str
    requete_canonique: str
    cible: str
    steps: tuple[Step, ...]
    registre_empreinte: str
    moteur_intent: str
    cree_le: str
    plan_id: str
    # Sélection tracée (décision 2026-08-28) : par capacité, qui a été choisi,
    # qui a été écarté, et POURQUOI. Hors empreinte : le motif se déduit du
    # registre, or le registre est déjà empreinté — le rejeu n'est pas affecté.
    selection: dict = field(default_factory=dict)
    # Descripteur STRUCTURÉ de la cible (2026-08-30) — additif, à côté du champ
    # `cible` (chaîne de compatibilité). C'est lui que le futur Web, les transports
    # distants et les règles policy liront pour savoir CE qui a été compris :
    # type, référence sûre, local ou non, chemin éventuel. `{}` = plan antérieur.
    cible_descr: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "version": VERSION_PLAN,
            "plan_id": self.plan_id,
            "request_id": self.request_id,
            "requete": self.requete,
            "requete_canonique": self.requete_canonique,
            "cible": self.cible,
            "cible_descr": self.cible_descr,
            "registre_empreinte": self.registre_empreinte,
            "moteur_intent": self.moteur_intent,
            "cree_le": self.cree_le,
            "steps": [s.to_dict() for s in self.steps],
            "selection": self.selection,
        }

    def to_json(self, **kw) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, **kw)

    @property
    def request_id(self) -> str:
        """Identité de la requête BRUTE. Distincte de plan_id : deux formulations de la
        même intention ont deux request_id mais un seul plan_id."""
        return hashlib.sha256((self.requete or "").encode("utf-8")).hexdigest()[:16]

    def empreinte(self) -> str:
        """Empreinte du contenu décisionnel du plan.

        Calcule sur la requête CANONIQUE, jamais sur la phrase brute : c'est ce qui fait
        que deux formulations d'une même intention produisent le même plan.

        Exclut volontairement l'horodatage et l'identifiant : deux exécutions du même
        plan doivent avoir la même empreinte, sinon le critère de rejeu ne vaut rien.
        """
        noyau = {
            "requete_canonique": self.requete_canonique,
            "cible": self.cible,
            "registre_empreinte": self.registre_empreinte,
            "steps": [s.to_dict() for s in self.steps],
        }
        return hashlib.sha256(
            json.dumps(noyau, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()


def construire(requete: str, cible: str, providers: list[str], registre: Registry,
               moteur_intent: str, exclus_applicabilite: dict | None = None,
               exclus_conditions: dict | None = None,
               exclus_disponibilite: dict | None = None,
               cible_descr: dict | None = None) -> Plan:
    """Construit le plan à partir du registre.

    Chaque étape refuse un provider qui n'appartient pas à la capacité demandée :
    c'est la protection contre un planner qui se tromperait de couple capacité/provider.
    """
    if not providers:
        raise PlanError("aucun provider à exécuter : plan vide refusé")
    verifier_budget(providers)

    par_id = {p.id: p for p in registre.providers()}
    steps = []
    for pid in providers:
        if pid not in par_id:
            raise PlanError(f"provider inconnu du registre : {pid}")
        p = par_id[pid]
        steps.append(Step(
            capability=p.capability,
            provider=p.id,
            risque=p.risque,
            commande=list(p.commande),
            args=list(p.args_obligatoires),
            sorties=list(p.sorties),
            transport=p.transport,
            provider_version=p.provider_version,
            server_id=p.server_id,
            server_version=p.server_version,
            tool=p.tool,
            tool_version=p.tool_version,
            protocol_version=p.protocol_version,
            trust=p.trust,
            target_types=tuple(p.target_types),
        ))

    # Sélection tracée (décision 2026-08-28) : le plan dit QUI a été choisi et
    # POURQUOI. Trois motifs possibles, et aucun ne ment :
    #   · un seul provider PASSIF     → le choix n'existait pas ;
    #   · plusieurs, priorité gagnante → les écartés sont nommés ;
    #   · choix imposé par l'appelant  → dit comme tel, même hors ordre.
    selection = {}
    for cap_id in dict.fromkeys(s.capability for s in steps):
        cap = registre.capability(cap_id)
        passifs = sorted([p for p in cap.providers if p.risque == "PASSIVE"],
                         key=lambda p: p.priorite)
        choisis = [s.provider for s in steps if s.capability == cap_id]
        ecartes = [{"id": p.id, "priorite": p.priorite}
                   for p in passifs if p.id not in choisis]
        if len(passifs) <= 1:
            motif = ("seul provider PASSIF déclaré pour cette capacité"
                     + (f" (priorité {passifs[0].priorite})" if passifs else ""))
        elif choisis == [passifs[0].id]:
            motif = (f"priorité déclarée la plus forte parmi {len(passifs)} providers "
                     f"PASSIF (priorité {passifs[0].priorite}) ; écartés : "
                     + ", ".join(f"{e['id']} (priorité {e['priorite']})" for e in ecartes))
        elif (cap.mode_selection == "fan_out"
              and choisis == [p.id for p in passifs[:len(choisis)]]):
            # Fan-out déclaré (étape 3) : les N premiers PASSIF dans l'ordre de
            # priorité — pas un choix implicite, le mode est dans le registre.
            motif = (f"fan_out déclaré (max {cap.max_providers}) : les {len(choisis)} "
                     f"premiers providers PASSIF dans l'ordre de priorité ; écartés : "
                     + (", ".join(f"{e['id']} (priorité {e['priorite']})" for e in ecartes)
                        or "aucun"))
        else:
            motif = (f"sélection imposée par l'appelant ({', '.join(choisis)}) — hors "
                     f"ordre de priorité déclarée (attendu : {passifs[0].id}, "
                     f"priorité {passifs[0].priorite})")
        selection[cap_id] = {"choisis": choisis, "ecartes": ecartes, "motif": motif}

    # Exclusions d'applicabilité (étape 3) : tracées dans le plan, à côté des
    # motifs de sélection — un provider écarté AVANT exécution est une décision,
    # elle se raconte comme les autres.
    if exclus_applicabilite:
        selection["applicabilite"] = dict(exclus_applicabilite)
    # Conditions d'exécution non remplies (2026-08-30) : un outil écarté parce qu'il lui
    # faut le réseau ou une base absente est une DÉCISION, pas un accident. Elle se lit au
    # même endroit que les écartements de sélection et d'applicabilité.
    if exclus_conditions:
        selection["conditions"] = dict(exclus_conditions)
    # Disponibilité (D10, 31/08/2026) : un outil absent de la machine est écarté AVANT la
    # troncature du fan-out, et son écartement est écrit ici plutôt que tu. Sans cette
    # ligne, « pourquoi ce scanner n'a rien rendu » restait une question sans réponse :
    # l'outil ne figure dans aucun step, donc aucune couverture ne le mentionne.
    if exclus_disponibilite:
        selection["disponibilite"] = dict(exclus_disponibilite)

    plan = Plan(
        requete=requete,
        requete_canonique=canonicaliser(requete),
        cible=cible,
        steps=tuple(steps),
        registre_empreinte=registre.empreinte(),
        moteur_intent=moteur_intent,
        cree_le=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        plan_id="",
        selection=selection,
        cible_descr=dict(cible_descr or {}),
    )
    # dataclasses.replace, PAS asdict(**...) : asdict convertit récursivement les Step
    # en dictionnaires, et le plan reconstruit perdrait ses objets typés.
    return replace(plan, plan_id=plan.empreinte()[:16])


def depuis_json(texte: str) -> dict:
    """Relit un plan sérialisé. Utilisé pour le rejeu (critère n°10)."""
    doc = json.loads(texte)
    if doc.get("version") != VERSION_PLAN:
        raise PlanError(f"version de plan non supportée : {doc.get('version')}")
    for cle in ("plan_id", "steps", "registre_empreinte"):
        if cle not in doc:
            raise PlanError(f"plan invalide : {cle} absent")
    return doc

