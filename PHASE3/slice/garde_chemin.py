"""Garde de chemins — la garantie que le filesystem impose, pas OPA.

Répartition des rôles, validée le 2026-08-27 :

    OPA décide        : la cible DEMANDÉE est-elle autorisée ?
    Le filesystem     : un symlink sort-il RÉELLEMENT du workspace ?

OPA ne voit que des chaînes. Il ne peut pas savoir qu'un chemin autorisé contient un lien
symbolique pointant vers /etc/shadow. Cette garantie doit être imposée par l'executor.

Politique retenue (option 2) :
    · symlink restant dans la cible  → autorisé
    · symlink sortant de la cible    → l'exécution est REFUSÉE, et le lien est signalé
      dans la couverture. On ne résout pas, on ne copie pas : on refuse et on le dit.

`Path.resolve()` n'est pas suffisant seul : il suit les liens sans vérifier qu'on reste
dans l'arbre autorisé. La vérification de containment est faite ici explicitement, et
`commonpath` est utilisé plutôt qu'un `startswith` — ce dernier accepterait
`/home/user/PHASE3/testrepo-malin` comme contenu dans `/home/user/PHASE3/testrepo`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class CheminInterdit(Exception):
    """Levée quand la cible ne peut pas être exécutée en sécurité."""


@dataclass
class RapportChemin:
    racine_reelle: str
    symlinks_internes: list[str] = field(default_factory=list)
    symlinks_sortants: list[str] = field(default_factory=list)
    cibles_hors_racine: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "racine_reelle": self.racine_reelle,
            "symlinks_internes": self.symlinks_internes,
            "symlinks_sortants": self.symlinks_sortants,
            "cibles_hors_racine": self.cibles_hors_racine,
        }


def _dans(racine: Path, chemin: Path) -> bool:
    """Vérification de containment par commonpath, pas par startswith.

    startswith("/a/b") accepte "/a/b-malin" : c'est exactement la faille à éviter.
    """
    try:
        return os.path.commonpath([str(racine), str(chemin)]) == str(racine)
    except ValueError:
        # Chemins sur des lecteurs/racines différents.
        return False


def verifier_cible(cible: Path | str, racines_autorisees: list[Path | str]) -> RapportChemin:
    """Vérifie qu'une cible est contenue dans une racine autorisée, liens compris.

    Lève CheminInterdit si :
      · le chemin résolu sort des racines autorisées ;
      · un symlink de l'arbre pointe hors de la cible.
    """
    cible = Path(cible)
    racines = [Path(r).resolve() for r in racines_autorisees]
    if not racines:
        raise CheminInterdit("aucune racine autorisée définie")

    reel = cible.resolve()
    if not any(_dans(r, reel) for r in racines):
        raise CheminInterdit(
            f"la cible résolue {reel} sort des racines autorisées {[str(r) for r in racines]}")

    rapport = RapportChemin(racine_reelle=str(reel))

    if not reel.is_dir():
        return rapport

    for chemin in reel.rglob("*"):
        if not chemin.is_symlink():
            continue
        relatif = str(chemin.relative_to(reel))
        destination = Path(os.path.realpath(chemin))
        if _dans(reel, destination):
            rapport.symlinks_internes.append(relatif)
        else:
            rapport.symlinks_sortants.append(f"{relatif} -> {destination}")

    if rapport.symlinks_sortants:
        raise CheminInterdit(
            f"{len(rapport.symlinks_sortants)} symlink(s) sortent de la cible : "
            + "; ".join(rapport.symlinks_sortants[:5]))

    return rapport


def verifier_args(args: list[str]) -> list[str]:
    """Rejette les arguments qu'aucun adaptateur légitime ne devrait produire.

    Seconde barrière, indépendante d'OPA : même si une règle Rego était contournée,
    ces arguments n'atteindraient pas l'exécution.
    """
    problemes = []
    for a in args:
        if not isinstance(a, str):
            problemes.append(f"argument non textuel : {type(a).__name__}")
            continue
        if "\x00" in a:
            problemes.append("argument contenant un octet NUL")
        if "\n" in a or "\r" in a:
            problemes.append(f"argument contenant un retour à la ligne : {a[:60]!r}")
        for motif in (";", "&&", "||", "|", "`", "$(", ">", "<"):
            if motif in a:
                problemes.append(f"argument contenant {motif!r} : {a[:60]!r}")
                break
    return problemes


def verifier_sortie(sortie: Path | str, repertoire_autorise: Path | str) -> None:
    """Le chemin de sortie doit rester dans le répertoire autorisé."""
    s = Path(sortie)
    # On ne résout PAS le fichier lui-même : il n'existe pas encore. On résout son parent.
    parent = s.parent.resolve()
    autorise = Path(repertoire_autorise).resolve()
    if not _dans(autorise, parent):
        raise CheminInterdit(
            f"la sortie {s} sort du répertoire autorisé {autorise} (parent réel {parent})")
