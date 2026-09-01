"""Profils d'exécution — ce que l'environnement AUTORISE, déclaré explicitement.

Le moteur DÉCLARE son profil ; OPA DÉCIDE. Cette séparation est la même que pour le
plan : aucune règle de sécurité ne vit dans le code Python.

Un profil n'est pas une description technique, c'est un CONTRAT : il dit quelle confiance
de cible et quel niveau de risque sont admissibles dans cet environnement. Le contrat court
dans le sens moteur → politique : c'est `policy.rego` qui lit, donc les noms de champs
produits ici sont CEUX QUE LA POLITIQUE ATTEND — un nom divergent désarme une garde sans
lever d'erreur (contrat de noms testé : G15, `test_utilisation.py`).

Tant que la mémoire n'est pas bornée, `controlled_dev` est le seul profil honnête — et il
interdit les dépôts non fiables et les outils actifs.

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
    # Le réseau est-il laissé aux outils ? FAUX en Phase 3, et ce n'est pas un réglage :
    # la cage passe `--unshare-net`. Le champ sert au PLAN pour écarter AVANT de proposer
    # un outil qui a besoin de sortir (`conditions.py`) — sinon l'outil rend un résultat
    # vide en code 0 et le rapport titrait « rien trouvé ».
    reseau_autorise: bool = False
    commentaire: str = ""

    def to_dict(self) -> dict:
        """Vue SOUMISE À OPA : les noms sont ceux que `policy.rego` lit, pas des noms
        de rapport. Mesuré le 2026-08-30 : `memoire_bornee` et `durci` s'écrivaient
        `memory_bounded` et `hardened`. OPA ne voyait donc jamais le champ, et
        `not <indéfini>` vaut vrai : la garde mémoire se déclenchait PAR ACCIDENT, et
        un profil à mémoire réellement bornée n'aurait jamais pu l'armer. D'où le test
        de contrat de noms (G15, PHASE3/test_utilisation.py)."""
        return {
            "nom_profil": self.nom,
            "memoire_bornee": self.memoire_bornee,
            "confiance_admise": list(self.confiance_cible_admise),
            "risques_admis": list(self.risques_admis),
            "durci": self.durci,
            # Champs techniques sous-jacents, consommés par la policy.
            "cpu_borne": True,
            "processus_bornes": True,
            "temps_borne": True,
            "reseau_autorise": self.reseau_autorise,
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
# ÉTAT AU 01/09/2026 : les dix limites sont désormais ÉPROUVÉES sur un vrai runtime
# OCI — `test_oci.sh` rend 12/12, sortie 0 (Docker Desktop 29.7.2 / WSL2 Ubuntu 24.04,
# cf. PROJET_ETAT.md, deux blocs datés du 01/09). Ce qui reste vrai : ce profil n'est
# PAS UTILISABLE tant que l'exécution du moteur ne passe pas par `isolateur_oci.py` —
# les limites sont prouvées SUR LE HARNAIS, pas encore APPLIQUÉES au chemin
# d'exécution. Déclarer `durci` maintenant désactiverait la garde de refus sans rien
# appliquer : le verrou de `obtenir()` reste donc fermé, et il ne s'ouvrira qu'avec
# le branchement de l'isolateur OCI dans le pipeline.
LIMITES_A_PROUVER = Profil(
    nom="limites_a_prouver",
    memoire_bornee=True,
    confiance_cible_admise=("controlled", "untrusted"),
    risques_admis=("PASSIVE", "ACTIVE"),
    durci=True,
    commentaire=(
        "Limites ÉPROUVÉES sur runtime OCI (test_oci.sh 12/12, 01/09/2026) mais NON "
        "APPLIQUÉES par le chemin d'exécution du moteur : l'exécution passe encore par "
        "la cage bwrap, qui ne sait pas borner la mémoire. Utilisable quand le pipeline "
        "routera les outils non fiables vers isolateur_oci.py (docker : mémoire, swap, "
        "CPU, PID, fsize, timeout, réseau, caps, no-new-privileges, nettoyage)."
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

