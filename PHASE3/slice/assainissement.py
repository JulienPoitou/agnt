"""Assainissement des sorties — la politique de conservation.

LE PROBLÈME, constaté pour de vrai : Bandit renvoie la valeur réelle d'un credential dans
son champ `issue_text`. Les findings étaient masqués, mais `raw_bandit.json` — copié tel
quel dans le bundle — contenait le secret en clair, 4 occurrences.

LA RÈGLE :

    conserver la donnée brute si elle est sûre ;
    sinon conserver son empreinte, ses métadonnées et une version masquée.

Ce n'est pas une exception au principe « ne jamais détruire la donnée originale » : c'est
sa limite. Un secret conservé en clair dans nos artefacts est une fuite que nous créons.

Où le masquage s'applique — TOUS les points de sortie, pas seulement les findings :

    stdout et stderr capturés   → dès la capture, dans sandbox.py
    sorties brutes              → avant copie dans le bundle
    exceptions                  → le message est assaini
    rapport, SARIF, manifeste   → dérivés de données déjà assainies
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

MASQUE = "<masqué>"

# Motifs de secret. Le dernier est large volontairement : un faux positif qui masque un
# hachage coûte moins cher qu'une clé qui fuit.
# ---------------------------------------------------------------------------
# DEUX NIVEAUX, parce qu'ils n'ont pas le même coût d'erreur.
#
# PRÉCIS  → sert au MASQUAGE (findings, sorties brutes conservées).
#           Un faux positif détruit une donnée utile : constaté, 112 PURLs et chemins
#           masqués sur un seul scan Trivy.
#
# LARGE   → sert au GARDE-FOU, qui ne masque rien : il bloque l'exécution.
#           Un faux positif coûte un arrêt bruyant, pas une donnée. On préfère ça
#           à une clé qui passe.
# ---------------------------------------------------------------------------

MOTIFS_SECRETS = (
    r"ghp_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"gho_[A-Za-z0-9]{20,}",
    r"ghs_[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"sk-[A-Za-z0-9]{20,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    # Clé AWS étiquetée : reconnue par son étiquette, donc sans ambiguïté.
    r"(?i)(aws_secret_access_key|aws_secret|secret_access_key)\W{0,8}[A-Za-z0-9/+=]{40}",
)

# Uniquement pour le garde-fou. 40 caractères ET PLUS à casse mixte : attrape une clé
# base64 nue (AWS sans étiquette, clé de compte Azure de 88 caractères…).
#
# Trois leçons du dogfooding (2026-08-28, campagne 1) :
#   1. au moins UN CHIFFRE exigé — sans ça, le motif matchait les URL d'advisories
#      GitHub ('…/security/advisories/GHSA' = exactement 40 caractères) et bloquait
#      toute analyse npm légitime (incident axios). Une vraie clé de 40 caractères
#      sans chiffre : probabilité ~0.1 % ((54/64)^40) — perte négligeable.
#   2. {40,} au lieu de {40} — les bornes faisaient qu'une clé de 41 caractères et
#      plus ne matchait NULLE PART (trou révélé par le test).
#   3. Surtout : l'heuristique ne s'applique QU'HORS CONTEXTE INFRASTRUCTURE (URL et
#      chemins à 3 segments et plus) — voir _CONTEXTE_INFRA. Les régressions bundle
#      l'ont prouvé sitôt {40,} activé : URL Fedora (identifiants de fil de 40+
#      caractères) et chemins d'artefacts du projet matchaient. Les MOTIFS_SECRETS,
#      eux, restent évalués sur le texte INTÉGRAL : un jeton ghp_ dans une URL est
#      toujours pris. Ce qui est perdu : un blob base64 nu caché DANS une URL —
#      accepté et documenté, c'est le prix d'un moteur qui tourne sur le réel.
MOTIFS_LARGE = MOTIFS_SECRETS + (
    r"(?<![A-Za-z0-9/+=])(?=[A-Za-z0-9/+=]*[A-Z])(?=[A-Za-z0-9/+=]*[a-z])"
    r"(?=[A-Za-z0-9/+=]*[0-9])[A-Za-z0-9/+=]{40,}(?![A-Za-z0-9/+=])",
)

_COMPILES = tuple(re.compile(m) for m in MOTIFS_SECRETS)
_COMPILES_LARGE = tuple(re.compile(m) for m in MOTIFS_LARGE)
_HEUR_40 = _COMPILES_LARGE[-1]

# Contextes « explicables » : une URL ou un chemin à 3 segments et plus n'est pas un
# blob base64 suspect. L'heuristique 40 caractères les ignore ; les motifs stricts non.
_CONTEXTE_INFRA = re.compile(
    r"https?://[^\s\"'\\,]+|(?:[A-Za-z0-9_.~+-]+/){3,}[A-Za-z0-9_.~+-]*")


@dataclass(frozen=True)
class Verdict:
    """Décision de conservation pour une sortie."""
    sur: bool
    occurrences: int
    digest: str
    taille: int
    texte_masque: str = ""
    # 31/08/2026 — le masquage est VÉRIFIÉ, pas supposé.
    #
    # Mesuré sur le premier RUN réel : `raw_trufflehog3.redacted.json` contenait encore
    # `"secret": "16C7e42F292c6912E7710c838347Ae178B4a"` en clair. Le motif `ghp_…` ne
    # pouvait pas le voir — trufflehog3 rend la valeur SANS son préfixe dans ce champ —
    # et le nom du fichier affirmait néanmoins une réduction que nous n'avions pas
    # obtenue. Un artefact nommé « .redacted » qui fuit est pire qu'un artefact brut
    # assumé : il éteint la vigilance de celui qui le relit.
    assaini: bool = True

    def to_dict(self) -> dict:
        d = {"digest": self.digest, "size": self.taille, "stored": self.sur}
        if not self.sur:
            d["reason"] = "secret_detected" if self.assaini else "secret_non_masquable"
            d["redactions"] = self.occurrences
            d["sanitized"] = self.assaini
        return d



def nettoie_url(v: str) -> str:
    """Masque le userinfo (`user:pass@`) d'une URL, préserve le reste.

    Le masque général des secrets ne reconnaît pas cette forme parce qu'elle n'a pas
    de nom de variable ; or c'est exactement la forme qu'un opérateur colle dans une
    requête (`scan https://u:p@site`). Une autorité unique : `findings` l'utilise
    pour les findings, `mission` pour l'en-tête et le journal — la promesse « les
    artefacts ne stockent pas le login » est ainsi tenue AU POINT D'ÉCRITURE, pas à
    chaque lecteur (02/09/2026, trouvé par la revue adverse famille C).
    """
    if "://" not in v:
        return v
    tete, _, reste = v.partition("://")
    autorite, sep, suite = reste.partition("/")
    if "@" in autorite:
        autorite = "***@" + autorite.rsplit("@", 1)[1]
    return tete + "://" + autorite + (sep + suite if sep else "")

def masquer(texte: str) -> tuple[str, int]:
    """Masque les motifs de secret. Retourne (texte masqué, nombre de remplacements)."""
    if not texte:
        return texte or "", 0
    total = 0
    for motif in _COMPILES:
        texte, n = motif.subn(MASQUE, texte)
        total += n
    return texte, total


def masquer_large(texte: str) -> tuple[str, int]:
    """Masque avec le jeu LARGE.

    Réservé aux champs de TEXTE LIBRE déclarés à risque par le manifest. Un faux positif
    masque un hachage dans un message — acceptable. Rater une clé ne l'est pas.

    Les motifs stricts s'appliquent partout (un jeton ghp_ dans une URL est masqué) ;
    l'heuristique 40 caractères s'applique hors URL et hors chemins à 3 segments et
    plus (leçon n°3 du dogfooding : ces contextes ne sont pas des blobs suspects).
    """
    if not texte:
        return texte or "", 0
    total = 0
    for motif in _COMPILES:
        texte, n = motif.subn(MASQUE, texte)
        total += n
    # Heuristique : segment par segment, les contextes infrastructure étant épargnés.
    out = []
    pos = 0
    for m in _CONTEXTE_INFRA.finditer(texte):
        seg, n = _HEUR_40.subn(MASQUE, texte[pos:m.start()])
        total += n
        out.append(seg)
        out.append(m.group(0))
        pos = m.end()
    seg, n = _HEUR_40.subn(MASQUE, texte[pos:])
    total += n
    out.append(seg)
    return "".join(out), total


def _scalaires(obj):
    """Toutes les chaînes feuilles d'un objet JSON, quelle que soit la profondeur."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _scalaires(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _scalaires(v)


def valeurs_secretes(donnees, chemins) -> set[str]:
    """Récolte, dans une sortie DÉJÀ PARSÉE, les valeurs des champs DÉCLARÉS secrets.

    Le masquage par motif (`masquer`, `masquer_large`) devine ; celui-ci sait. Quand le
    manifest déclare `champs_secrets: [secret, context]`, l'outil nous a déjà dit où est
    la valeur — il n'y a plus rien à reconnaître, seulement à remplacer. C'est ce qui
    permet de masquer un jeton déshabillé de son préfixe, cas où AUCUN motif ne peut
    réussir (mesuré : `secret` rendu sans le `ghp_` par trufflehog3).

    Les valeurs trop courtes sont écartées : remplacer « 4 » ou « None » par `<masqué>`
    détruirait la lisibilité de l'artefact sans rien protéger.

    Les valeurs DÉJÀ masquées sont écartées aussi, et c'est plus subtil qu'il n'y
    paraît : la sortie d'un outil arrive souvent déjà partiellement masquée (masquage à
    la capture, `sandbox.py`). Récolter `<masqué>"` comme si c'était un secret, puis le
    remplacer par `<masqué>`, mange le guillemet fermant du JSON — mesuré le 31/08/2026 :
    `"secret": "<masqué>,` au lieu de `"secret": "<masqué>",`, donc un artefact invalide
    produit par le mécanisme même qui devait le protéger. Ce qui est déjà masqué n'est
    plus un secret : c'est la preuve que la protection a eu lieu.
    """
    out: set[str] = set()
    if not donnees or not chemins:
        return out
    items = donnees if isinstance(donnees, list) else [donnees]
    # Format `custom` : le cœur enveloppe les items dans {"parser", "items"}.
    if isinstance(donnees, dict) and isinstance(donnees.get("items"), list):
        items = donnees["items"]
    noms = {str(c) for c in chemins}

    def _visiter(obj) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k) in noms:
                    out.update(s for s in _scalaires(v)
                               if len(s.strip()) >= 6 and MASQUE not in s)
                else:
                    _visiter(v)
        elif isinstance(obj, list):
            for v in obj:
                _visiter(v)

    for it in items:
        _visiter(it)
    return out


def masquer_valeurs(texte: str, valeurs) -> tuple[str, int]:
    """Remplace des littéraux EXACTS. Retourne (texte, nombre de remplacements).

    Les valeurs les plus longues d'abord : deux secrets dont l'un est préfixe de l'autre
    ne doivent pas laisser un résidu après remplacement du plus court.
    """
    if not texte or not valeurs:
        return texte or "", 0
    total = 0
    for v in sorted({str(x) for x in valeurs if str(x).strip()}, key=len, reverse=True):
        if len(v) < 6 or MASQUE in v:
            # Voir `valeurs_secretes` : remplacer un masque par un masque ne protège rien
            # et casse la syntaxe du JSON environnant.
            continue
        n = texte.count(v)
        if n:
            texte = texte.replace(v, MASQUE)
            total += n
    return texte, total


def contient_secret(texte: str, large: bool = False) -> int:
    """Nombre d'occurrences de secret. 0 = sûr.

    `large=True` utilise le jeu étendu, pour le GARDE-FOU uniquement : il ne masque rien,
    il arrête l'exécution. Un faux positif y coûte un arrêt bruyant, pas une donnée —
    mais un faux positif SYSTÉMATIQUE (URL d'advisories) rend le moteur inutilisable :
    l'heuristique 40 caractères ignore donc les contextes infrastructure (URL, chemins),
    les motifs stricts restent évalués sur le texte intégral.
    """
    if not texte:
        return 0
    if not large:
        return sum(len(m.findall(texte)) for m in _COMPILES)
    n = sum(len(m.findall(texte)) for m in _COMPILES)
    n += len(_HEUR_40.findall(_CONTEXTE_INFRA.sub(" ", texte)))
    return n


def digeste(texte: str) -> str:
    return hashlib.sha256((texte or "").encode("utf-8", "replace")).hexdigest()[:16]


def examiner(texte: str, valeurs=()) -> Verdict:
    """Applique la politique de conservation à une sortie.

    Sûre  → conservée telle quelle.
    Sinon → empreinte + métadonnées + version masquée. Jamais la valeur en clair.

    La DÉTECTION utilise le jeu LARGE et le MASQUAGE aussi. C'est délibéré : pour une
    sortie brute, mieux vaut masquer un chemin ou un PURL de 40 caractères que laisser
    passer une clé. Constaté pour de vrai — avec le jeu précis, la clé AWS de Bandit
    était jugée « sûre » et `raw_bandit.json` partait dans le bundle en clair.

    Les findings, eux, restent masqués au jeu précis, champ par champ, via
    `masquer_large` déclaré dans le manifest : là un faux positif détruirait une donnée
    utile de façon systématique.

    `valeurs` : littéraux déjà connus (champs déclarés `champs_secrets` par le manifest),
    masqués EN PLUS des motifs. Deux voies complémentaires, et il les faut les deux :
    les motifs attrapent un secret que personne n'a déclaré, les valeurs attrapent un
    secret que les motifs ne peuvent pas reconnaître.

    Le RÉSULTAT est ré-examiné. Un masquage non vérifié n'est pas un masquage : c'est
    une intention. Si un motif subsiste après masquage, `assaini=False` et l'appelant
    doit s'abstenir de publier — jamais la valeur en clair, sous aucun nom.
    """
    texte = texte or ""
    n = contient_secret(texte, large=True)
    valeurs = set(valeurs or ())
    if n == 0 and not valeurs:
        return Verdict(sur=True, occurrences=0, digest=digeste(texte),
                       taille=len(texte), texte_masque=texte)
    masque, _ = masquer_large(texte)
    masque, nv = masquer_valeurs(masque, valeurs)
    restants = contient_secret(masque, large=True)
    return Verdict(sur=False, occurrences=n + nv, digest=digeste(texte),
                   taille=len(texte), texte_masque=masque, assaini=(restants == 0))


def examiner_fichier(chemin, valeurs=()) -> Verdict:
    from pathlib import Path
    p = Path(chemin)
    if not p.exists():
        return Verdict(sur=True, occurrences=0, digest="absent", taille=0)
    try:
        return examiner(p.read_text(encoding="utf-8", errors="replace"), valeurs=valeurs)
    except OSError as e:
        # Illisible n'est PAS « sûr » : un fichier qu'on ne peut pas lire est un fichier
        # dont on ne peut rien affirmer. `assaini=False` pour qu'il ne soit pas publié
        # sous un nom qui prétend le contraire.
        return Verdict(sur=False, occurrences=0, digest="illisible", taille=0,
                       texte_masque=f"<illisible : {e}>", assaini=False)


def assainir_recursivement(obj):
    """Masque les secrets dans une structure JSON entière, récursivement."""
    if isinstance(obj, str):
        return masquer(obj)[0]
    if isinstance(obj, list):
        return [assainir_recursivement(v) for v in obj]
    if isinstance(obj, dict):
        return {k: assainir_recursivement(v) for k, v in obj.items()}
    return obj


# extraction.py importe ce nom, qui était le sien avant la centralisation.
# Une seule implémentation, deux noms.
masquer_secrets = assainir_recursivement

