"""Cible — descripteur canonique de ce qu'AGNT analyse.

Le défaut que ce module ferme : le pipeline traitait la cible comme un `Path`
filesystem, alors que les manifests disposent déjà d'un vocabulaire `target_types`
(`repository`, `filesystem`) qui n'était pas câblé au moteur. Résultat, une URL ou
toute cible non matérialisée aurait été convertie silencieusement en chemin, puis
éventuellement montée dans bwrap comme un pseudo-chemin local.

La frontière de domaine :

    une cible est une DONNÉE MÉTIER STRUCTURÉE ;
    un chemin local est UNE des formes possibles de cible ;
    le sandbox ne reçoit JAMAIS une cible non matérialisée comme si c'était un Path.

Ce que ce module EST :

    · le descripteur canonique (`Cible`), immuable, sérialisable, fail-closed ;
    · LE vocabulaire local partagé (`TYPES_LOCAUX`) — le même langage que
      `target_types` des manifests, pas une seconde liste ;
    · LA règle unique d'applicabilité entre un descripteur et les target_types
      d'un provider (`applicable`) ;
    · la normalisation unique de frontière (`normaliser`) : un `Path` historique,
      une chaîne, ou un descripteur déjà construit deviennent une `Cible` — une
      seule fois, à l'entrée du pipeline.

Ce que ce module N'EST PAS : un transport distant, un téléchargeur d'URL, un
support d'exécution à distance. Une cible non locale est REPRÉSENTÉE, validée,
et comparée aux target_types des providers — jamais exécutée localement. Tant
qu'aucun transport compatible n'existe, elle est écartée ou refusée lisiblement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Les seuls types de cible que le cœur sait MATÉRIALISER comme chemin local.
# C'est le vocabulaire effectivement chargé aujourd'hui : `repository` (défaut des
# manifests) et `filesystem` (checkov). Les types non locaux (url, hote, image…)
# sont déclarables par les manifests/plugins (`target_types`), mais le cœur ne
# peut pas les transformer en chemin.
TYPES_LOCAUX = ("repository", "filesystem")

# Défaut d'un provider qui ne déclare pas `target_types` — aligné sur le défaut
# historique du chargeur de manifest.
TYPE_DEFAUT = "repository"

# Type attribué à une référence détectée comme URI (`scheme://…`). Représentation
# d'une cible distante, jamais un chemin.
TYPE_URL = "url"

# Les seuls schémas qu'une cible « url » peut porter : le vocabulaire des scanners
# web eux-mêmes. Un autre schéma n'est pas « toléré faute de liste » — voir la garde
# dans `__post_init__`.
_SCHEMES_URL_ADMIS = ("http", "https")

# Détection d'un schéma d'URI : ce qui distingue une URL d'un chemin local sans
# deviner — un chemin qui commence par « https:// » n'existe pas, un URI si.
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


class CibleError(Exception):
    """La cible est vide, incohérente ou non reconnue. Refus avant toute exécution."""


@dataclass(frozen=True)
class Cible:
    """Le descripteur canonique d'une cible.

    `type`       : un type du vocabulaire `target_types`. Local (`repository`,
                   `filesystem`) ou non local (url, hote, image…) — ces derniers
                   n'ont pas de chemin et ne sont jamais montés.
    `reference`  : la référence canonique DÉCLARÉE (le chemin tel que donné, ou
                   l'URL/référence distante).
    `chemin_local`: un chemin résolu, SEULEMENT quand le type est réellement local.
                   `None` sinon — c'est le champ qui garantit qu'une cible non
                   locale ne finit jamais en `Path`.
    """

    type: str
    reference: str
    chemin_local: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.type, str) or not self.type.strip():
            raise CibleError("type de cible vide — attendu un jeton `target_types`")
        object.__setattr__(self, "type", self.type.strip())
        if self.reference is None or not str(self.reference).strip():
            raise CibleError("référence de cible vide")
        object.__setattr__(self, "reference", str(self.reference))
        if self.type in TYPES_LOCAUX:
            if self.chemin_local is None:
                raise CibleError(
                    f"cible locale {self.type!r} sans chemin local — une cible locale "
                    f"doit être matérialisée sur le filesystem")
        elif self.chemin_local is not None:
            raise CibleError(
                f"cible non locale {self.type!r} avec un chemin local "
                f"({self.chemin_local}) — une cible distante n'est pas un Path, elle ne "
                f"doit jamais être montée dans le sandbox")
        # 02/09/2026 (revue adverse) — le vocabulaire « url » est celui d'un SCANNER
        # WEB, et un schéma est un pouvoir, pas une décoration : `file:///etc/passwd`
        # passé par la porte « cible distante » deviendrait une lecture de filesystem
        # déguisée en sortie réseau (et le provider zap, lui, la suivrait — ZAP sait
        # ouvrir file://). Les schémas admis sont exactement le vocabulaire des
        # outils ; tout le reste est refusé ICI, au descripteur, avant argv, avant
        # policy, avant tout montage. Un schéma non admis n'est pas « inconnu donc
        # toléré » : c'est refusé nommément.
        if self.type == TYPE_URL:
            tete = self.reference.split("://", 1)[0].strip().lower()
            if "://" in self.reference and tete not in _SCHEMES_URL_ADMIS:
                raise CibleError(
                    f"schéma {tete!r} refusé pour une cible « url » : seuls "
                    f"{list(_SCHEMES_URL_ADMIS)} sont le vocabulaire d'un scanner web — "
                    "un `file://` (ou tout autre schéma à pouvoir local) ne devient pas "
                    "une cible distante en changeant de porte d'entrée")

    # ---------------------------------------------------------------- propriétés
    @property
    def est_local(self) -> bool:
        return self.type in TYPES_LOCAUX

    def to_dict(self) -> dict:
        """Représentation SÉRIALISABLE et STABLE, consommable par le futur Web.

        La `reference` est rendue sous sa forme SÛRE (`reference_sure`) : une URL
        portant un `userinfo` (credentials) est rendue sans lui — la donnée
        sérialisée n'expose pas de secret. Le chemin local, lui, est rendu tel quel
        (c'est une donnée de la machine d'analyse, pas un secret distant).
        """
        return {
            "type": self.type,
            "reference": self.reference_sure(),
            "local": self.est_local,
            "chemin": str(self.chemin_local) if self.chemin_local is not None else None,
        }

    def reference_sure(self) -> str:
        """La référence sans secret : retire le `userinfo` d'une URI.

        Un chemin local est rendu à l'identique. C'est la seule distinction
        « référence technique / représentation sûre » nécessaire aujourd'hui, et
        elle ne s'applique qu'aux références d'URI — le chemin n'a rien à cacher.
        """
        if not _URI.match(self.reference):
            return self.reference
        try:
            from urllib.parse import urlsplit, urlunsplit
            parts = urlsplit(self.reference)
            if parts.username is None and parts.password is None:
                return self.reference
            hote = parts.hostname or ""
            if parts.port:
                hote = f"{hote}:{parts.port}"
            return urlunsplit((parts.scheme, hote, parts.path,
                               parts.query, parts.fragment))
        except ValueError:
            return self.reference


# ------------------------------------------------------------------- vocabulaire
def est_local(type_cible: str) -> bool:
    """Le cœur sait-il matérialiser ce type en chemin local ?"""
    return type_cible in TYPES_LOCAUX


def applicable(type_cible: str, types_declares) -> bool:
    """LA règle unique entre un descripteur de cible et les `target_types` d'un
    provider : un provider est applicable au type de cible T ssi T est déclaré.

    Volontairement un test d'appartenance exact, pas une hiérarchie : un provider
    qui déclare `repository` n'est pas applicable à `filesystem`, et aucun provider
    local n'est applicable à `url`. C'est ce qui empêche un outil local d'être
    sélectionné pour une cible distante.
    """
    return type_cible in tuple(types_declares or ())


def types_applicables(prov) -> tuple[str, ...]:
    """Les types de cible qu'un provider sait analyser.

    Deux origines, et c'est voulu (même doctrine que `conditions.declarees`) :
      · provider DÉCLARATIF  → `target_types` de son manifest (validés au chargement) ;
      · adaptateur HISTORIQUE (sans manifest) → les types LOCAUX : un sous-processus
        sandboxé ne peut analyser qu'un chemin local, jamais une URL.
    """
    m = getattr(prov, "manifest", None)
    if m is not None and getattr(m, "cibles", ()):
        return tuple(m.cibles)
    return TYPES_LOCAUX


# ---------------------------------------------------------------- normalisation
def normaliser(entree) -> Cible:
    """Normalisation UNIQUE de frontière : Path, str, ou Cible → une Cible.

    · `Cible`      → rendue telle quelle (déjà validée) ;
    · `Path`/PathLike → cible LOCALE : type `repository` (répertoire) ou `filesystem`
                        (fichier) ; le chemin est conservé tel quel, les gardes
                        (chemin, symlinks, sandbox) restent en aval ;
    · `str`        → URI (`scheme://`) → cible NON LOCALE de type `url`, sans chemin ;
                    sinon → chemin local, même traitement que `Path` ;
    · tout le reste → refus explicite (`CibleError`).

    C'est LA SEULE porte d'entrée : le cœur ne convertit jamais une cible en Path
    ailleurs. Un appel historique (`executer(requete, Path(...))`) passe par ici et
    obtient exactement le comportement d'avant.
    """
    if isinstance(entree, Cible):
        return entree
    if isinstance(entree, (str, Path)):
        texte = str(entree).strip()
        if not texte:
            raise CibleError("référence de cible vide")
        if _URI.match(texte):
            return Cible(type=TYPE_URL, reference=texte)
        chemin = Path(entree)
        typ = "repository" if chemin.is_dir() else "filesystem"
        return Cible(type=typ, reference=texte, chemin_local=chemin)
    raise CibleError(
        f"valeur de cible non reconnue ({type(entree).__name__}) — attendu un "
        f"Path, une chaîne (chemin ou URL) ou une Cible")
