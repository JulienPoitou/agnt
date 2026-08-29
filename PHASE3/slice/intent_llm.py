"""Moteur d'intention LLM — branché DERRIÈRE le contrat existant.

LE LLM NE REMPLACE QUE LE MATCHING. Il ne remplace pas le contrat d'intention.

Ce qu'il fait :

    phrase utilisateur → intention structurée

Ce qu'il ne fait JAMAIS :

    · choisir un outil            → le registre résout les providers
    · construire le plan          → plan.construire(), à partir du registre
    · contourner OPA              → la policy évalue le plan, pas l'intention
    · modifier le registre        → il est en lecture seule
    · exécuter une commande       → l'executor seul

Il ne voit QUE la description des capacités — jamais un nom d'outil, un chemin, un
argument. Et sa sortie est VALIDÉE contre le registre : un identifiant de capacité
inconnu n'est pas deviné, il est rejeté.

Le déterministe reste la référence : `intent.moteur` indique lequel a tranché, et le
LLM peut être désactivé sans toucher au reste du pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass

from intent import AMBIGU, INTERDIT, Intent, STATUTS
from registre import Registry


class SortieInvalide(Exception):
    """La sortie du LLM ne respecte pas le contrat. On retombe sur le déterministe."""


@dataclass(frozen=True)
class ReponseLLM:
    """Réponse brute d'un fournisseur, avant validation."""
    statut: str
    capabilities: tuple = ()
    question: str = ""
    motif: str = ""
    brut: str = ""
    fournisseur: str = ""


def valider(rep: ReponseLLM, registre: Registry) -> Intent:
    """Valide une réponse LLM contre le registre et produit un Intent.

    Lève SortieInvalide si le contrat n'est pas respecté. On ne devine jamais :
    une capacité inconnue est rejetée, pas interprétée.
    """
    if rep.statut not in STATUTS:
        raise SortieInvalide(f"statut inconnu : {rep.statut!r}")

    connues = {c.id for c in registre.capabilities()}

    if rep.statut == "resolved":
        caps = tuple(rep.capabilities or ())
        if not caps:
            raise SortieInvalide("resolved sans capacités")
        inconnues = sorted(set(caps) - connues)
        if inconnues:
            # Le point critique : le LLM ne peut pas inventer une capacité.
            raise SortieInvalide(f"capacités inconnues du registre : {inconnues}")
        ordre = tuple(c.id for c in registre.capabilities() if c.id in set(caps))
        return Intent("resolved", "", capabilities=ordre, moteur=f"llm:{rep.fournisseur}")

    if rep.statut == "needs_clarification":
        if not rep.question:
            raise SortieInvalide("needs_clarification sans question")
        return Intent("needs_clarification", "", question=rep.question,
                      moteur=f"llm:{rep.fournisseur}")

    # rejected
    if not rep.motif:
        raise SortieInvalide("rejected sans motif")
    return Intent("rejected", "", motif=rep.motif, moteur=f"llm:{rep.fournisseur}")


def inferer(requete: str, registre: Registry, fournisseur) -> Intent:
    """Inférence LLM, avec repli déterministe.

    Trois raisons de retomber sur le déterministe, toutes tracées dans `moteur` :
      · le fournisseur est indisponible ou erreur
      · la sortie ne respecte pas le contrat
      · la sortie contient une capacité inconnue

    Le repli n'est pas silencieux : `moteur` vaut alors `deterministe` ou
    `deterministe(repli:…)`, ce qui permet de mesurer à posteriori la part du LLM.
    """
    from intent import inferer as inferer_deterministe

    try:
        rep = fournisseur.complet(requete, registre.descr())
    except Exception as e:
        it = inferer_deterministe(requete, registre)
        return Intent(it.statut, it.requete, it.capabilities, it.question, it.motif,
                      moteur=f"deterministe(repli:{type(e).__name__})", motifs=it.motifs)

    if rep is None:
        it = inferer_deterministe(requete, registre)
        return Intent(it.statut, it.requete, it.capabilities, it.question, it.motif,
                      moteur="deterministe(repli:reponse_vide)", motifs=it.motifs)

    try:
        it = valider(rep, registre)
    except SortieInvalide as e:
        dit = inferer_deterministe(requete, registre)
        return Intent(dit.statut, dit.requete, dit.capabilities, dit.question, dit.motif,
                      moteur=f"deterministe(repli:{e})", motifs=dit.motifs)

    # La requête originale est conservée : c'est elle qui définit request_id.
    return Intent(it.statut, requete, it.capabilities, it.question, it.motif,
                  moteur=it.moteur, motifs=it.motifs)


def garde_fous(requete: str, registre: Registry) -> Intent | None:
    """Garde-fous DÉTERMINISTES appliqués AVANT le LLM.

    Une demande explicitement interdite ne doit jamais être soumise à un modèle :
    le refus est une règle, pas une opinion.
    """
    bas = (requete or "").lower()
    for mot, motif in INTERDIT:
        if mot in bas:
            return Intent("rejected", requete, motif=f"demande interdite : {motif}",
                          moteur="deterministe(garde-fou)")
    if not bas.strip():
        return Intent("needs_clarification", requete,
                      question="Que dois-je analyser, et sur quel dépôt ?",
                      moteur="deterministe(garde-fou)")
    return None

