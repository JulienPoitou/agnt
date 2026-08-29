"""Profils d'exécution — ce que l'environnement AUTORISE, déclaré explicitement.

Le moteur DÉCLARE son profil ; OPA DÉCIDE. Cette séparation est la même que pour le
plan : aucune règle de sécurité ne vit dans le code Python.

Un profil n'est pas une description technique, c'est un CONTRAT : il dit quelle confiance
de cible et quel niveau de risque sont admissibles dans cet environnement. Tant que la
mémoire n'est pas bornée, `controlled_dev` est le seul profil honnête — et il interdit
les dépôts non fiables et les outils actifs.

La formulation à conserver :

    La mémoire n'est pas bornée.
    Le système refuse donc les dépôts non fiables et les outils actifs.

Ce n'est pas un détail qui peut attendre sans condition : un dépôt volumineux ou hostile
peut provoquer un problème de disponibilité même avec un outil passif.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Profil:
    nom: str
    memoire_bornee: bool
    confiance_cible_admise: tuple[str, ...]
    risques_admis: tuple[str, ...]
    durci: bool
    commentaire: str = ""

    def to_dict(self) -> dict:
        return {
            "execution_profile": self.nom,
            "memory_bounded": self.memoire_bornee,
            "allowed_target_trust": list(self.confiance_cible_admise),
            "allowed_risk": list(self.risques_admis),
            "hardened": self.durci,
            # Champs techniques sous-jacents, consommés par la policy.
            "cpu_borne": True,
            "processus_bornes": True,
            "temps_borne": True,
            "commentaire": self.commentaire,
        }


# ---------------------------------------------------------------- profils connus
CONTROLLED_DEV = Profil(
    nom="controlled_dev",
    memoire_bornee=False,
    confiance_cible_admise=("controlled",),
    risques_admis=("PASSIVE",),
    durci=False,
    commentaire=(
        "Profil actuel. La mémoire n'est PAS bornée : RLIMIT_AS casse Trivy (mmap boltdb) "
        "et Gitleaks (wazero), et cgroups v2 n'est pas accessible sans root. "
        "Suffisant pour une fixture locale contrôlée, des scanners passifs, un "
        "environnement de développement dédié, un risque accepté et explicitement limité. "
        "Insuffisant pour tout dépôt non fiable, tout service exposé, tout environnement "
        "multi-utilisateur, tout scan parallèle, tout outil actif ou intrusif."
    ),
)

# Nom volontairement « limites_a_prouver » et NON « hardened ».
# Le mot « durci » ne doit pas être employé tant que les dix points suivants n'ont pas
# été testés un par un : mémoire max, swap, CPU, PID, taille des fichiers, timeout,
# réseau, capabilities, no-new-privileges, nettoyage après arrêt.
# En l'état, seuls timeout, capabilities, réseau et taille des fichiers sont testés.
LIMITES_A_PROUVER = Profil(
    nom="limites_a_prouver",
    memoire_bornee=True,
    confiance_cible_admise=("controlled", "untrusted"),
    risques_admis=("PASSIVE", "ACTIVE"),
    durci=True,
    commentaire=(
        "Profil cible, NON DISPONIBLE et NON TESTÉ. Exige cgroups v2 ou un runtime OCI. "
        "Ne doit pas être utilisé : le déclarer sans limites appliquées désactiverait la "
        "garde de refus. Reste à tester : mémoire max, swap, CPU, PID, taille des "
        "fichiers, timeout, réseau, capabilities, no-new-privileges, nettoyage."
    ),
)

PROFILS = {p.nom: p for p in (CONTROLLED_DEV, LIMITES_A_PROUVER)}


def obtenir(nom: str) -> Profil:
    """Retourne un profil. `limites_a_prouver` est refusé à l'usage : il décrit une cible,
    pas un état réel."""
    if nom not in PROFILS:
        raise KeyError(f"profil inconnu : {nom!r} · disponibles : {sorted(PROFILS)}")
    if nom == LIMITES_A_PROUVER.nom:
        raise PermissionError(
            f"le profil {nom!r} n'est pas utilisable : ses limites ne sont ni appliquées "
            f"ni testées. L'utiliser désactiverait la garde de refus.")
    return PROFILS[nom]


def actif() -> Profil:
    """Profil réellement en vigueur.

    Déclarer un profil durci sans limites appliquées serait un mensonge qui désactiverait
    la garde de refus. Donc : tant que la mémoire n'est pas bornée, le profil actif est
    `controlled_dev`, quoi qu'on demande.
    """
    return CONTROLLED_DEV

