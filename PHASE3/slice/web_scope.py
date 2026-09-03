"""Périmètre web : canonicalisation, scope et budgets (H1 — Stream B).

Une URL n'est pas une chaîne : deux écritures différentes du même endpoint
(`HTTPS://HOTE:443/a/` vs `https://hote/a`) doivent donner LA MÊME décision de
scope, sinon un contournement par casse ou port par défaut passe la garde.
Ce module est la source unique de cette décision — l'endpoint
`/api/engagements/web`, le futur worker et l'évidence s'y réfèrent.

Règles :
  · schémas admis : http, https uniquement (doctrine `cible.py` : un schéma
    est un pouvoir — `file://` = lecture filesystem déguisée) ;
  · la forme canonique RETIRE userinfo et fragment (jamais persistés) ;
  · hôte en minuscules + IDNA, ports par défaut (80/443) supprimés ;
  · scope strict : égalité d'hôte exacte ; non strict : sous-domaines admis ;
  · `a@b` : l'hôte est ce qui suit le DERNIER `@` (urlsplit) — testé ;
  · budgets : plafond d'URLs distinctes + débit max par provider (spec,
    DOCUMENTED ONLY) ; exclusions : préfixes de chemin refusés.

Aucune exécution réseau ici : que des décisions pures et testables.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cible import CibleError

SCHEMES_ADMIS = ("http", "https")
PORTS_DEFAUT = {"http": 80, "https": 443}
DEBITS_SPEC = {"httpx": 50, "katana": 20, "ffuf": 30, "nuclei": 30}  # spec, non mesuré


def canonicaliser_url(url: str) -> str:
    """Forme canonique d'une URL cible. Lève `CibleError` (refus nommé)."""
    if not isinstance(url, str) or not url.strip():
        raise CibleError("url vide")
    url = url.strip()
    if any(ord(c) < 32 for c in url):
        raise CibleError("url contenant des caractères de contrôle")
    if "://" not in url:
        raise CibleError(f"schéma absent : {url[:60]!r} — attendu http:// ou https://")
    scheme, _, reste = url.partition("://")
    scheme = scheme.strip().lower()
    if scheme not in SCHEMES_ADMIS:
        raise CibleError(f"schéma {scheme!r} refusé : seuls {list(SCHEMES_ADMIS)}")
    try:
        parts = urlsplit(f"{scheme}://{reste}")
    except ValueError as e:
        raise CibleError(f"url illisible : {e}")
    hote = (parts.hostname or "").strip().lower()
    if not hote:
        raise CibleError("hôte manquant dans l'url")
    try:
        hote = hote.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise CibleError(f"hôte non encodable : {hote[:60]!r}")
    port = ""
    try:
        if parts.port and parts.port != PORTS_DEFAUT[scheme]:
            port = f":{parts.port}"
    except ValueError:
        raise CibleError(f"port invalide dans {url[:60]!r}")
    chemin = parts.path or "/"
    if len(chemin) > 1:
        chemin = chemin.rstrip("/")
    canonique = f"{scheme}://{hote}{port}{chemin}"
    if parts.query:
        canonique += f"?{parts.query}"
    return canonique


def hote_de(url_canonique: str) -> str:
    """Hôte d'une URL déjà canonicalisée (jamais d'exception : split simple)."""
    return url_canonique.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].rsplit(":", 1)[0] \
        if "://" in url_canonique else ""


def normaliser_autorises(autorises) -> list[str]:
    """Nettoie la liste des hôtes autorisés (minuscules, sans port ni schéma)."""
    propres = []
    for a in autorises or []:
        a = str(a).strip().lower().split("://")[-1].split("/")[0].split("@")[-1]
        a = a.rsplit(":", 1)[0] if ":" in a and a.count(":") == 1 and a.rsplit(":", 1)[1].isdigit() else a
        if a and a not in propres:
            propres.append(a)
    return propres


def dans_perimetre(url_canonique: str, autorises, strict: bool = True) -> bool:
    """L'hôte canonique est-il dans le périmètre ? Strict = égalité exacte."""
    hote = hote_de(url_canonique)
    for a in normaliser_autorises(autorises):
        if hote == a:
            return True
        if not strict and hote.endswith("." + a):
            return True
    return False


@dataclass
class ScopeEnforcer:
    """Garde de périmètre + budgets d'un engagement web.

    `autoriser` ne consomme rien (décision pure) ; `enregistrer` consomme le
    budget d'URLs distinctes. Les deux rendent un motif nommé — un refus
    silencieux serait une panne déguisée.
    """
    autorises: list = field(default_factory=list)
    strict: bool = True
    max_urls: int = 1000
    exclusions: tuple = ("/.git", "/.env")
    _vus: set = field(default_factory=set, repr=False)

    def autoriser(self, url: str) -> tuple[bool, str]:
        try:
            canonique = canonicaliser_url(url)
        except CibleError as e:
            return False, f"url_refusee : {e}"
        if not dans_perimetre(canonique, self.autorises, self.strict):
            return False, f"hors_perimetre : {hote_de(canonique)}"
        chemin = "/" + canonique.split("://", 1)[-1].split("/", 1)[-1].split("?", 1)[0] \
            if "/" in canonique.split("://", 1)[-1] else "/"
        for ex in self.exclusions:
            if chemin == ex or chemin.startswith(ex.rstrip("/") + "/"):
                return False, f"exclu : {ex}"
        return True, "autorise"

    def enregistrer(self, url: str) -> tuple[bool, str]:
        ok, motif = self.autoriser(url)
        if not ok:
            return False, motif
        try:
            canonique = canonicaliser_url(url)
        except CibleError as e:                                 # déjà validée ci-dessus
            return False, f"url_refusee : {e}"
        if canonique not in self._vus and len(self._vus) >= self.max_urls:
            return False, f"budget_epuise : {self.max_urls} urls distinctes"
        self._vus.add(canonique)
        return True, "enregistre"

    @property
    def urls_distinctes(self) -> int:
        return len(self._vus)
