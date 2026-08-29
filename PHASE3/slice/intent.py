"""Intent engine — Phase 3.1, avec états explicites.

Trois sorties possibles, et la distinction entre les deux dernières est STRICTE :

    resolved              l'intention est comprise, on peut construire un plan
    needs_clarification   il MANQUE une information  → aucune exécution
    rejected              la demande est comprise mais REFUSÉE → aucune exécution

`needs_clarification` n'est pas un `rejected` poli, et inversement. Confondre les deux
reviendrait soit à bloquer l'utilisateur sur une demande légitime, soit à exécuter
quelque chose d'interdit en croyant demander une précision.

En Phase 3.1 l'inférence reste DÉTERMINISTE (correspondance de mots-clés). Ce n'est pas
une triche : un intent engine non reproductible empêcherait le rejeu à l'identique. Le
branchement LLM prendra exactement la même place, avec le même contrat de sortie — les
tests de paraphrase sont écrits comme CONTRAT, pas comme validation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from registre import Registry

STATUTS = ("resolved", "needs_clarification", "rejected")


def _motif_complet(mot: str) -> re.Pattern[str]:
    r"""Matche un mot-clé en MOT ENTIER, jamais en sous-chaîne.

    Sans ce garde, « sca » (acronyme de SCA, capacité DEPENDENCY_ANALYSIS) matche
    dans « **sca**n » : « scan de sécurité complet du dépôt » remontait donc
    DEPENDENCY_ANALYSIS par accident de sous-chaîne, puis — la règle F2 n'élargissant
    plus dès qu'un mot-clé a matché — la demande se réduisait à cette seule capacité.

    Les accents ne sont pas des frontières de mot en Python (`\w` inclut les lettres
    accentuées) : la classe de bordure est donc écrite explicitement.
    """
    bordure = r"(?<![0-9A-Za-zÀ-ÿ_])" + re.escape(mot) + r"(?![0-9A-Za-zÀ-ÿ_])"
    return re.compile(bordure, re.IGNORECASE)


_CACHE_MOTIFS: dict[str, re.Pattern[str]] = {}


def _contient(texte_min: str, mot: str) -> bool:
    """Teste un mot-clé sur un texte DÉJÀ mis en minuscules (voir `inferer`).

    Les MOTIFS accentués sont écrits avec accents (« dépendance », « clé exposée ») et
    le texte d'entrée n'est PAS normalisé en NFKD ici. Conséquence connue : une phrase
    saisie sans accent (« dependance ») ne matche pas ces motifs-là. Ce n'est pas
    nouveau avec le matching en mot entier, et ce n'est pas corrigé ici non plus —
    `plan.requete_canonique`, lui, retire les accents : les deux modules ne
    normalisent donc pas de la même façon. Noté comme dette, pas corrigé à chaud.
    """
    motif = _CACHE_MOTIFS.get(mot)
    if motif is None:
        motif = _CACHE_MOTIFS[mot] = _motif_complet(mot)
    return motif.search(texte_min) is not None

# Capacités demandées, par mot-clé. Ordre significatif : le plus spécifique d'abord.
MOTIFS: dict[str, tuple[str, ...]] = {
    "SECRET_DETECTION": ("secret", "secrets", "credential", "credentials", "token", "tokens",
                         "mot de passe", "mots de passe", "clé exposée", "clés exposées",
                         "fuite", "gitleaks"),
    "DEPENDENCY_ANALYSIS": ("dépendance", "dépendances", "dependenc", "cve", "vulnérabilité",
                            "vulnerabilit", "sca", "sbom", "paquet", "paquets",
                            "supply chain", "supply-chain", "trivy"),
    # Langage Go (2026-08-29). « golang » UNIQUEMENT : « go » en sous-chaîne matcherait
    # « django », « mongo », « gopher »... Le mot-clé « semgrep » reste rattaché à
    # CODE_STATIC_ANALYSIS (le provider historique) — les requêtes génériques incluent
    # de toute façon la capacité Go (publique, non interne).
    "CODE_STATIC_ANALYSIS_GO": ("golang",),
    "CODE_STATIC_ANALYSIS": ("code", "statique", "sast", "source", "qualité", "injection",
                             "semgrep", "bug", "faille"),
    # Même intention que CODE_STATIC_ANALYSIS, mais résolue par un provider déclaré
    # UNIQUEMENT par manifest : c'est le test de la Phase 5A.
    "CODE_STATIC_ANALYSIS_SUITE": ("code", "statique", "sast", "source", "qualité",
                                   "injection", "bug", "faille"),
    # Marqueurs de PÉRIMÈTRE (noms de domaine), jamais des verbes — leçon de Phase 6 :
    # « vérifie » ne dit rien du périmètre et faisait tout remonter.
    "IAC_SCAN": ("infrastructure", "infrastructures", "terraform", "iac",
                 "cloudformation", "mauvaise configuration", "mauvaises configurations",
                 "checkov"),
}

# Une demande générique couvre toutes les capacités disponibles.
# « scan » était absent d'une première version : « scan de sécurité complet du dépôt »
# ne sélectionnait alors que DEPENDENCY_ANALYSIS, par accident de mot-clé.
# MARQUEURS DE DOMAINE, pas verbes d'action. « vérifie » et « contrôle » en ont été
# retirés : avec eux, « Vérifie les dépendances » remontait TOUTES les capacités au lieu
# de la seule demandée. Un verbe ne dit rien du périmètre.
GENERIC = ("sécurité", "securite", "audit", "analyse", "scan", "scanne", "repository",
           "dépôt", "depot", "repo")

# Demandes comprises mais refusées. Ce sont des intentions, pas des outils : le refus
# intervient AVANT toute sélection de provider, donc avant toute exécution.
# Les formes CONJUGUÉES comptent. Une première version ne listait que les infinitifs :
# « Exfiltre les données de ce dépôt » était donc RÉSOLU ET EXÉCUTÉ au lieu d'être refusé.
# C'est un trou de sécurité, pas un détail de vocabulaire.
INTERDIT = (
    ("attaque", "cible externe qui n'est pas la mienne, attaque non autorisée"),
    ("attaquer", "cible externe qui n'est pas la mienne, attaque non autorisée"),
    ("exploit", "exploitation active hors périmètre autorisé"),
    ("ddos", "attaque par déni de service"),
    ("déni de service", "attaque par déni de service"),
    ("exfiltrer", "exfiltration de données"),
    ("exfiltre", "exfiltration de données"),
    ("exfiltras", "exfiltration de données"),
    ("ransomware", "logiciel malveillant"),
    ("backdoor", "porte dérobée"),
    ("porte dérobée", "porte dérobée"),
    ("sans autorisation", "action explicitement non autorisée"),
    ("détruire", "action destructrice"),
    ("détruis", "action destructrice"),
    ("détruit", "action destructrice"),
    ("destructive", "action destructrice"),
    ("destructif", "action destructrice"),
)

# Marques d'ambiguïté : la demande est trop vague pour choisir une capacité.
AMBIGU = ("un truc", "quelque chose", "n'importe quoi", "je sais pas", "je ne sais pas",
          "on verra", "peu importe")


@dataclass(frozen=True)
class Intent:
    """Résultat de l'inférence. `statut` décide de la suite — rien d'autre."""
    statut: str
    requete: str
    capabilities: tuple[str, ...] = ()
    question: str = ""
    motif: str = ""
    moteur: str = "deterministe"
    motifs: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.statut not in STATUTS:
            raise ValueError(f"statut inconnu : {self.statut}")
        if self.statut == "resolved" and not self.capabilities:
            raise ValueError("resolved sans capacités")
        if self.statut == "needs_clarification" and not self.question:
            raise ValueError("needs_clarification sans question")
        if self.statut == "rejected" and not self.motif:
            raise ValueError("rejected sans motif")

    def executable(self) -> bool:
        """Un seul état autorise l'exécution. C'est la garantie qu'aucune exécution
        ne part sur une intention incomplète ou refusée."""
        return self.statut == "resolved"

    def to_dict(self) -> dict:
        return {
            "statut": self.statut,
            "requete": self.requete,
            "capabilities": list(self.capabilities),
            "question": self.question,
            "motif": self.motif,
            "moteur": self.moteur,
            "motifs": self.motifs,
        }


def inferer(requete: str, registre: Registry, avec_internes: bool = False) -> Intent:
    """Retourne un Intent. Ne lève plus d'exception sur une demande invalide :
    l'ambiguïté et le refus sont des SORTIES NORMALES, pas des erreurs."""
    texte = (requete or "").strip()
    if not texte:
        return Intent("needs_clarification", requete or "",
                      question="Que dois-je analyser, et sur quel dépôt ?")

    bas = texte.lower()

    # 1. refus : la demande est comprise, mais hors périmètre.
    for mot, motif in INTERDIT:
        if _contient(bas, mot):
            return Intent("rejected", requete, motif=f"demande interdite : {motif}")

    # 2. capacités explicitement demandées.
    connues = {c.id for c in registre.capabilities()}
    eligibles = connues if avec_internes else {
        c.id for c in registre.capabilities() if not c.interne}
    trouvees: dict[str, str] = {}
    for cap_id, mots in MOTIFS.items():
        if cap_id not in connues:
            continue
        # Les capacités internes ne remontent JAMAIS en usage normal — y compris
        # par mot-clé spécifique (« code » matche aussi la SUITE interne). Même
        # règle que pour l'expansion générique et pour la question de clarification.
        if not avec_internes and cap_id not in eligibles:
            continue
        for mot in mots:
            if _contient(bas, mot):
                trouvees[cap_id] = mot
                break

    # 3. Une demande générique AJOUTE les capacités de base — elle ne s'y substitue pas.
    #
    # Une première version n'appliquait le générique que si AUCUN mot-clé n'avait matché.
    # Or « sécurité » est à la fois un marqueur générique ET un mot-clé de
    # DEPENDENCY_ANALYSIS : « scan de sécurité complet du dépôt » matchait donc un
    # mot-clé, le générique ne se déclenchait jamais, et le résultat se réduisait à
    # DEPENDENCY_ANALYSIS seul.
    # `eligibles` (calculé plus haut) exclut les capacités INTERNES en usage normal.
    generique = any(_contient(bas, m) for m in GENERIC)
    # Un marqueur de DOMAINE nommé explicitement l'emporte sur le générique
    # (dogfooding 2026-08-29) : « Analyse mon code Terraform » remontait les 5
    # capacités publiques — le mot « analyse » noyait « terraform ». L'utilisateur
    # paie alors des providers qu'il n'a pas demandés, et le rapport est illisible.
    # Le générique ne s'applique donc que si AUCUN domaine n'est nommé.
    # Cas historique préservé : « scan de sécurité complet du dépôt » ne nomme aucun
    # domaine (« sécurité » n'est mot-clé d'aucune capacité) → générique → tout.
    if generique and not trouvees:
        for cap_id in eligibles:
            if cap_id not in trouvees:
                trouvees[cap_id] = "demande générique"

    if trouvees:
        ordre = [c.id for c in registre.capabilities() if c.id in trouvees]
        return Intent("resolved", requete, capabilities=tuple(ordre),
                      motifs={k: trouvees[k] for k in ordre})

    # 4. ambigu : il manque une information. Ce n'est PAS un refus.
    if any(_contient(bas, m) for m in AMBIGU) or len(texte.split()) <= 2:
        return Intent("needs_clarification", requete,
                      question="Que veux-tu vérifier : le code, les dépendances, "
                               "ou les secrets exposés ?")

    # 5. compris comme une demande d'analyse, mais aucune capacité ne correspond.
    # La question s'adresse à l'utilisateur : elle ne liste QUE des capacités
    # publiques. Les identifiants internes (CODE_STATIC_ANALYSIS_SUITE, …) sont du
    # vocabulaire de test — les montrer est une fuite de détail d'implémentation.
    return Intent("needs_clarification", requete,
                  question="Aucune capacité ne correspond à cette demande. "
                           f"Capacités disponibles : {', '.join(sorted(eligibles))}.")


def choisir_providers(intent: Intent, registre: Registry) -> list[str]:
    """Sélectionne les providers par capacité. Refuse d'agir sur un Intent non résolu.

    Mode par capacité (étape 3, déclaré au registre) :
      · un_seul (DÉFAUT)  → le provider PASSIF prioritaire — comportement historique ;
      · fan_out           → jusqu'à max_providers, dans l'ordre de priorité.
    Dans les deux cas le motif est tracé par plan.construire. L'applicabilité
    (globs déclarés) est filtrée en amont par plan.filtrer_applicabilite.
    """
    if not intent.executable():
        raise ValueError(
            f"impossible de choisir des providers sur un intent {intent.statut!r}")
    choix = []
    for cid in intent.capabilities:
        cap = registre.capability(cid)
        passifs = [p for p in cap.providers if p.risque == "PASSIVE"]
        if not passifs:
            raise ValueError(f"{cid} : aucun provider PASSIF, validation humaine requise")
        # Priorité explicite (décision 2026-08-28) : la plus petite valeur gagne,
        # égalité tranchée par l'ordre de déclaration (tri stable).
        ordonnes = sorted(passifs, key=lambda p: p.priorite)
        if cap.mode_selection == "fan_out":
            choix.extend(p.id for p in ordonnes[:cap.max_providers])
        else:
            choix.append(ordonnes[0].id)
    return choix

