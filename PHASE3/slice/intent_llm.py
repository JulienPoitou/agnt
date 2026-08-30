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

from intent import AMBIGU, INTERDIT, Intent, STATUTS, interdit
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


def valider(rep: ReponseLLM, registre: Registry, avec_internes: bool = False) -> Intent:
    """Valide une réponse LLM contre le registre et produit un Intent.

    Lève SortieInvalide si le contrat n'est pas respecté. On ne devine jamais :
    une capacité inconnue est rejetée, pas interprétée.

    `avec_internes`, par défaut `False` : la comparaison se fait sur le catalogue qui a été
    PROPOSÉ au modèle (`registre.publiques()`, la même liste que `descr()`), pas sur le
    registre entier. Une capacité `interne: true` existe — elle sert à qualifier des
    providers — mais elle n'est jamais nommée dans la proposition : la valider contre le
    catalogue complet laissait le modèle élargir le périmètre tout seul, en citant un outil
    que personne ne lui avait montré (constat A2/A3 de la campagne adverse, 2026-08-30).

    Ce n'est pas une règle nouvelle : `intent.inferer(avec_internes=…)` l'applique déjà au
    chemin déterministe, avec le même drapeau et la même valeur par défaut. Les deux moteurs
    refusent donc pour la même raison. Le chemin qui mène à une capacité interne n'est pas
    supprimé — il devient explicite : un appelant qui la réclame le passe en argument.
    """
    if rep.statut not in STATUTS:
        raise SortieInvalide(f"statut inconnu : {rep.statut!r}")

    connues = {c.id for c in registre.capabilities()}
    proposees = connues if avec_internes else {c.id for c in registre.publiques()}

    if rep.statut == "resolved":
        caps = tuple(rep.capabilities or ())
        if not caps:
            raise SortieInvalide("resolved sans capacités")
        inconnues = sorted(set(caps) - connues)
        hors_proposition = sorted((set(caps) & connues) - proposees)
        if inconnues or hors_proposition:
            # Le point critique : le LLM ne peut ni inventer une capacité, ni en réclamer
            # une qui n'était pas dans la proposition. Les deux sont nommés séparément —
            # confondre « inconnue » et « interne » ferait chercher le bug du mauvais côté.
            morceaux = []
            if inconnues:
                morceaux.append(f"inconnues du registre : {inconnues}")
            if hors_proposition:
                morceaux.append(f"non proposées au modèle (internes) : {hors_proposition}")
            raise SortieInvalide("capacités refusées — " + " · ".join(morceaux))
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


# Ce qu'un fournisseur accepte de recevoir. Une demande de 120 000 caractères est une
# dépense, pas une question : elle part au tarif du modèle, elle est journalisée, et elle ne
# change rien à la capacité choisie. La borne est sur l'ENVOYÉ uniquement — `requete` reste
# entière, parce que c'est elle qui définit `request_id` et l'archive de mission : tronquer la
# trace pour économiser un appel serait falsifier le dossier au lieu de payer moins cher.
LIMITE_REQUETE_FOURNISSEUR = 6000


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

    # La borne porte sur ce qui SORT. `requete` reste entière plus bas : c'est elle qui définit
    # `request_id` et l'archive de mission, et tronquer la trace pour économiser un appel
    # reviendrait à falsifier le dossier au lieu de payer moins cher.
    envoyee = requete or ""
    borne: dict = {}
    if len(envoyee) > LIMITE_REQUETE_FOURNISSEUR:
        borne = {"longue_de": len(envoyee), "envoyee_a": LIMITE_REQUETE_FOURNISSEUR}
        envoyee = envoyee[:LIMITE_REQUETE_FOURNISSEUR]

    def trace(it):
        """La borne est tracée sur tous les retours, replis compris : ce qui est parti au
        fournisseur l'a été tronqué, et le lecteur a le droit de savoir qu'une partie de sa
        phrase n'a été lue par personne — y compris quand la décision, elle, vient du
        déterministe qui a lu la requête entière."""
        if not borne:
            return it
        return Intent(it.statut, it.requete, it.capabilities, it.question, it.motif,
                      moteur=it.moteur, motifs={**(it.motifs or {}), "requete_bornee": borne})

    try:
        rep = fournisseur.complet(envoyee, registre.descr())
    except Exception as e:
        it = inferer_deterministe(requete, registre)
        # l'étiquette du moteur est LE traceur du repli (cas E2 de la batterie) : `trace`
        # recopie `moteur`, il ne doit en aucun cas le choisir à la place de l'appelant
        return trace(Intent(it.statut, it.requete, it.capabilities, it.question, it.motif,
                            moteur=f"deterministe(repli:{type(e).__name__})", motifs=it.motifs))

    if rep is None:
        it = inferer_deterministe(requete, registre)
        return trace(Intent(it.statut, it.requete, it.capabilities, it.question, it.motif,
                            moteur="deterministe(repli:reponse_vide)", motifs=it.motifs))

    try:
        it = valider(rep, registre)
    except SortieInvalide as e:
        dit = inferer_deterministe(requete, registre)
        return Intent(dit.statut, dit.requete, dit.capabilities, dit.question, dit.motif,
                      moteur=f"deterministe(repli:{e})", motifs=dit.motifs)

    # La requête originale est conservée : c'est elle qui définit request_id.
    return trace(Intent(it.statut, requete, it.capabilities, it.question, it.motif,
                        moteur=it.moteur, motifs=it.motifs))


def garde_fous(requete: str, registre: Registry) -> Intent | None:
    """Garde-fous DÉTERMINISTES appliqués AVANT le LLM.

    Une demande explicitement interdite ne doit jamais être soumise à un modèle :
    le refus est une règle, pas une opinion.
    """
    # Une seule politique pour les deux chemins : `intent.interdit()`. La version precedente
    # faisait `mot in requete.lower()` — une sous-chaîne, donc ni accents pliés, ni
    # homoglyphes, ni lettres espacées. Le refus d'une demande interdite ne doit pas dépendre
    # du moteur qui a répondu (constat B6 de la campagne adverse, côté garde-fou).
    refuse = interdit(requete or "")
    if refuse:
        return Intent("rejected", requete, motif=f"demande interdite : {refuse[1]}",
                      moteur="deterministe(garde-fou)")
    if not (requete or "").strip():
        return Intent("needs_clarification", requete,
                      question="Que dois-je analyser, et sur quel dépôt ?",
                      moteur="deterministe(garde-fou)")
    return None

