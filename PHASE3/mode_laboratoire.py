#!/usr/bin/env python3
"""Mode Laboratoire Propriétaire — contrôle d'admission SECURITY (P2).

Ce module n'est PAS un exécuteur. Il est un **point de garde** : il détermine
si une session de laboratoire demandée localement par l'opérateur propriétaire
peut utiliser les capacités **déjà autorisées** par AGNT (`capabilities.yaml`),
sans ouvrir le moindre chemin nouveau. La décision est pure, déterministe et
testable sans OPA, bwrap ni aucun outil.

Invariants (tous mis en œuvre ici, aucun contournable par l'entrée) :

1. Désactivé par défaut — aucune bascule de mode n'existe ; l'absence de
   double opt-in est un refus.
2. Double opt-in local opérateur : un jeton de connaissance (CLI locale) +
   un bloc de possession (fichier local `0600` sous la racine de conf), tous
   deux fournis par des canaux LOCAUX opérateur.
3. Canal d'activation verrouillé : `cli-local` uniquement. HTTP (corps ou
   en-tête), LLM, navigateur/UI, données de cible/fixture/journal/artefact,
   réponse MCP ou provider tiers = `canal-interdit`. Le module ne lit JAMAIS
   la cible, une fixture, un journal ou un artefact pour activer quoi que ce
   soit ; le fichier d'opt-in est interdit sous toute racine de cible.
4. Cible locale obligatoire : refus URL/hôte distant, `..`, chemin absolu
   hors racine admise, symlink sortant — containment vérifié par la garde
   existante `slice/garde_chemin.verifier_cible` (couche filesystem, jamais
   contournée) et par des vérifications explicites pour des codes précis.
5. Egress fermé : toute demande d'ouverture réseau (même implicite) = refus ;
   ce module n'ouvre rien et ne donne aucun accès global.
6. Sandbox, policy fail-closed, intégrité/empreintes, registre, autorisation
   explicite de cible (`cible_autorisee is True`) et liste opérateur restent
   requis : le module les vérifie, il ne les remplace pas.
7. Aucun binaire, provider, commande libre, argument libre ou capacité
   active supplémentaire : seules les capacités **déjà listées** dans le
   registre demandé et autorisée sont admises.
8. Refus en profil public/production/contexte incertain : `controlled_dev`
   est l'unique profil honnête (`profils.actif()`), tout autre nom = refus.
9. Audit **redacted** : horodatage, décision, codes, empreintes (sha256
   tronquées) — jamais de secret, jeton, argv, chemin absolu, payload ou
   sortie brute. Les messages de refus sont génériques ; les exceptions de
   la garde de chemin ne sont jamais propagées telles quelles.

Usage (bibliothèque, import depuis PHASE3) :

    from mode_laboratoire import ContexteLabo, analyser
    decision = analyser(contexte)      # décision pure
    if not decision.ok: ...

Le runner local opérateur (hors de ce module, hors périmètre CORE) est
responsable de fournir le `ContexteLabo` depuis la configuration locale et de
ne jamais logguer les jetons ; ce module ne lit ni argv réel ni aucune donnée
de cible.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ══════════════════════════════════════════════════════════════════════════
# Garde de chemin existante — importée par chemin, jamais modifiée.
# ══════════════════════════════════════════════════════════════════════════

_RACINE = Path(__file__).resolve().parent
_GARDE_PATH = _RACINE / "slice" / "garde_chemin.py"

_spec = importlib.util.spec_from_file_location("garde_chemin", str(_GARDE_PATH))
_garde = importlib.util.module_from_spec(_spec)
sys.modules["garde_chemin"] = _garde
assert _spec and _spec.loader
_spec.loader.exec_module(_garde)

# ══════════════════════════════════════════════════════════════════════════
# Constantes de contrôle
# ══════════════════════════════════════════════════════════════════════════

DESACTIVE_PAR_DEFAUT = True
"""Le mode est désactivé tant que la double opt-in locale n'est pas prouvée."""

CANAUX_AUTORISES = ("cli-local",)
"""Canaux d'activation admis. Tout le reste (http, corps/en-tête HTTP,
llm, ui, cible, fixture, journal, artefact, mcp, provider) est interdit."""

PROFILS_AUTORISES = ("controlled_dev",)
"""Seul `controlled_dev` est honnête (profils.py : mémoire non bornée ⇒
refus des dépôts non fiables et outils actifs). `limites_a_prouver`,
`public`, `production` et tout profil inconnu sont refusés ici."""

PREFIXE_JETON = "agnt-labo-optin-"
"""Préfixe du contenu du fichier-bloc local (possession démontrée)."""

SEUIL_JETON = 32
"""Longueur minimale de la partie aléatoire (hex/base64) d'un jeton."""

_JETON_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_DSL_RE = re.compile(r"^//[^/]")
_PORT_RE = re.compile(r"^[A-Za-z0-9.-]+:[0-9]{1,5}(/|$)")
_SCP_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:")
_PWDU_RE = re.compile(r"^~($|[/\\])")


# ══════════════════════════════════════════════════════════════════════════
# Types
# ══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class CibleAutorisee:
    """Entrée du registre local des cibles explicitement autorisées.

    `autorisee` est consommée telle quelle : le module exige
    `autorisee is True` (P0.1) et n'écrit JAMAIS dedans.
    """

    chemin: str
    autorisee: bool


@dataclass(frozen=True)
class ContexteLabo:
    """Demande de session laboratoire, telle que portée par le canal local."""

    operateur: str = ""
    canal_activation: str = "inconnu"
    profil: str = "inconnu"
    # Opt-in 1 (connaissance) : jeton fourni en CLI locale opérateur.
    jeton_cli: str | None = None
    jeton_cli_attendu: str = ""
    # Opt-in 2 (possession) : chemin d'un fichier-bloc local 0600.
    optin_fichier: str | None = None
    jeton_fichier_attendu: str = ""
    racine_conf: Path | None = None
    # Cible locale
    cible_proposee: str = ""
    racines_autorisees: tuple[Path, ...] = ()
    registre_cibles: tuple[CibleAutorisee, ...] = ()
    operateurs_autorises: tuple[str, ...] = ()
    # Egress : le mode n'ouvre rien ; toute demande d'ouverture est un refus.
    egress_ouverture_demandee: tuple[str, ...] = ()
    egress_global_implicite: bool = False
    # Capacités : uniquement celles déjà autorisées par AGNT.
    capacites_demandees: tuple[str, ...] = ()
    capacites_autorisees: tuple[str, ...] = ()
    providers_demandes: tuple[str, ...] = ()
    providers_autorises: tuple[str, ...] = ()
    commandes_liberes: tuple[str, ...] = ()
    # Gardes existantes : le mode les exige, il ne les remplace pas.
    policy_disponible: bool = False
    policy_allow: bool = False
    regles_presentes: bool = False
    empreintes_conformes: bool = False
    sandbox_conforme: bool = False


@dataclass(frozen=True)
class RefusLabo:
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


@dataclass(frozen=True)
class DecisionLabo:
    ok: bool
    raisons: tuple[RefusLabo, ...] = ()
    audit: tuple[dict[str, Any], ...] = ()
    actif: bool = False
    chemin_cible_resolu: str = ""

    @property
    def codes(self) -> frozenset[str]:
        return frozenset(r.code for r in self.raisons)

    def __str__(self) -> str:
        if self.ok:
            return "AUTORISE (double opt-in local prouvé, toutes gardes vertes)"
        corps = " ; ".join(str(r) for r in self.raisons[:6])
        if len(self.raisons) > 6:
            corps += f" ; … (+{len(self.raisons) - 6} autres)"
        return f"REFUSE — {corps}"


# ══════════════════════════════════════════════════════════════════════════
# Primitives : opt-in fichier (possession locale)
# ══════════════════════════════════════════════════════════════════════════


def _dans(racine: Path, chemin: Path) -> bool:
    """Containment par commonpath (pas de startswith)."""
    try:
        return os.path.commonpath([str(racine), str(chemin)]) == str(racine)
    except ValueError:
        return False


def lire_optin_fichier(chemin: str | None, racine_conf: Path | None,
                       racines_cible: tuple[Path, ...] = ()) \
        -> tuple[bool, str | None, tuple[str, ...]]:
    """Lit le fichier-bloc local du deuxième opt-in.

    Retourne `(ok, jeton, codes)` : le jeton n'est renvoyé QUE si le fichier
    est un fichier régulier détenu par l'utilisateur courant, en mode `0600`,
    sous `racine_conf`, HORS de toute racine de cible, sans symlink, avec un
    contenu au format `agnt-labo-optin-<aléatoire>`.
    """
    if chemin is None or racine_conf is None:
        return False, None, ("optin-fichier-absent",)
    bloc = Path(chemin)
    conf = Path(racine_conf).resolve()
    if not bloc.is_absolute():
        return False, None, ("optin-fichier-non-absolu",)
    reel = bloc.resolve()
    # Le bloc ne doit JAMAIS être porté par la cible ou ses racines.
    for r in racines_cible:
        if _dans(Path(r).resolve(), reel):
            return False, None, ("optin-fichier-dans-cible",)
    # Le chemin doit être local et rester sous la racine de conf.
    if not _dans(conf, reel):
        return False, None, ("optin-fichier-non-local",)
    if bloc.is_symlink() or reel.is_symlink():
        return False, None, ("optin-fichier-symlink",)
    if not reel.exists() or not reel.is_file():
        return False, None, ("optin-fichier-introuvable",)
    st = reel.stat()
    if st.st_uid != os.getuid():
        return False, None, ("optin-fichier-etranger",)
    if stat.S_IMODE(st.st_mode) & 0o077:
        return False, None, ("optin-fichier-permissif",)
    try:
        contenu = reel.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return False, None, ("optin-fichier-illisible",)
    if not contenu.startswith(PREFIXE_JETON):
        return False, None, ("optin-fichier-invalide",)
    jeton = contenu[len(PREFIXE_JETON):]
    if not _JETON_RE.match(jeton):
        return False, None, ("optin-fichier-invalide",)
    return True, jeton, ()


# ══════════════════════════════════════════════════════════════════════════
# Primitives : cible locale
# ══════════════════════════════════════════════════════════════════════════


def _composants_traversal(chemin: str) -> bool:
    p = chemin.replace("\\", "/")
    return any(seg == ".." for seg in p.split("/")) or p.startswith("../") \
        or "/../" in p or p.endswith("/..") or p == ".."


def resoudre_cible(cible_proposee: str,
                   racines_autorisees: tuple[Path, ...]) \
        -> tuple[bool, str, tuple[tuple[str, str], ...]]:
    """Vérifie qu'une cible est strictement locale et sous une racine admise.

    Retourne `(ok, chemin_résolu_ou_vide, problèmes)` où `problèmes` est une
    liste de `(code, message)` — messages GÉNÉRIQUES, jamais le chemin.
    La garde filesystem existante (`garde_chemin.verifier_cible`) reste la
    garantie finale de containment et de symlinks ; son exception est
    transformée en refus sans diffuser son message.
    """
    probleme = lambda code, msg: (code, msg)  # noqa: E731
    if not cible_proposee:
        return False, "", (probleme("cible-absente",
                                    "aucune cible proposée"),)
    c = cible_proposee.strip()
    # URL / hôte distant / protocole / userinfo / scp-like
    if _URL_RE.match(c) or _DSL_RE.match(c) or _PORT_RE.match(c) or \
            _SCP_RE.match(c):
        return False, "", (probleme("cible-non-locale",
                                    "cible distante (URL/hôte) interdite : "
                                    "le laboratoire est strictement local"),)
    # Chemin d'accueil comme cible : hors racine explicitement contrôlée.
    if _PWDU_RE.match(c):
        return False, "", (probleme("cible-hors-racine",
                                    "chemin d'accueil interdit : une racine "
                                    "explicitement contrôlée est requise"),)
    if _composants_traversal(c):
        return False, "", (probleme("cible-traversal",
                                    "traversée de répertoire interdite"),)
    cible = Path(c)
    if not cible.is_absolute():
        return False, "", (probleme("cible-non-absolue",
                                    "chemin non absolu : une racine "
                                    "explicitement contrôlée est requise"),)
    if not racines_autorisees:
        return False, "", (probleme("aucune-racine",
                                    "aucune racine autorisée déclarée"),)
    reel = cible.resolve()
    if not any(_dans(Path(r).resolve(), reel) for r in racines_autorisees):
        return False, "", (probleme("cible-hors-racine",
                                    "cible hors des racines explicitement "
                                    "contrôlées"),)
    if not reel.exists():
        return False, "", (probleme("cible-absente",
                                    "cible inexistante : le laboratoire "
                                    "exige une cible identifiée et présente"),)
    # Symlinks sortants : scan avant la garde pour un code précis.
    if reel.is_dir():
        for p in reel.rglob("*"):
            if not p.is_symlink():
                continue
            dest = Path(os.path.realpath(p))
            if not _dans(reel, dest):
                return False, "", (probleme(
                    "cible-symlink-sortant",
                    "lien symbolique sortant de la cible détecté : refus "
                    "(la garde filesystem ne résout pas, elle refuse)"),)
    try:
        _garde.verifier_cible(reel, [r for r in racines_autorisees])
    except _garde.CheminInterdit:
        # Toujours générique : le message d'origine contient le chemin.
        return False, "", (probleme(
            "cible-hors-racine",
            "la cible résolue sort de la garde filesystem existante"),)
    return True, str(reel), ()


# ══════════════════════════════════════════════════════════════════════════
# Décision
# ══════════════════════════════════════════════════════════════════════════


def _empreinte(texte: str) -> str:
    """Empreinte courte d'audit — jamais le texte source."""
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()[:16]


def analyser(contexte: ContexteLabo,
             horloge: datetime | None = None) -> DecisionLabo:
    """Décision d'admission d'une session laboratoire.

    Toutes les violations sont rapportées (pas d'arrêt à la première) : le
    verdict est exploitable et vérifiable par le harnais. Aucune valeur du
    contexte n'apparaît dans les raisons ; l'audit ne porte que des
    empreintes.
    """
    maintenant = horloge or datetime.now(timezone.utc)
    raisons: list[RefusLabo] = []

    def refus(code: str, message: str) -> None:
        raisons.append(RefusLabo(code, message))

    # ── 1. Défaut : désactivé tant que le double opt-in n'est pas prouvé ────
    optin_cli_valide = False
    optin_fichier_valide = False
    a_cli = bool(contexte.jeton_cli)
    a_bloc = bool(contexte.optin_fichier)
    if not a_cli and not a_bloc:
        refus("optin-absent",
              "mode désactivé par défaut : le double opt-in local est requis")
    else:
        if not a_cli:
            refus("optin-incomplet",
                  "double opt-in incomplet : facteur de connaissance CLI "
                  "absent")
        elif not contexte.jeton_cli_attendu:
            refus("optin-cli-sans-config",
                  "configuration locale du jeton de connaissance absente")
        elif not hmac.compare_digest(contexte.jeton_cli,
                                     contexte.jeton_cli_attendu):
            refus("optin-invalide", "jeton de connaissance invalide")
        else:
            optin_cli_valide = True

        ok_bloc, jeton_bloc, codes_bloc = lire_optin_fichier(
            contexte.optin_fichier, contexte.racine_conf,
            tuple(Path(r) for r in contexte.racines_autorisees))
        for code in codes_bloc:
            refus(code, "bloc de possession local invalide ou illisible")
        if ok_bloc:
            if not contexte.jeton_fichier_attendu or \
                    not hmac.compare_digest(jeton_bloc,
                                            contexte.jeton_fichier_attendu):
                refus("optin-fichier-invalide",
                      "jeton de possession invalide : les deux secrets "
                      "locaux doivent correspondre à la configuration "
                      "opérateur")
            else:
                optin_fichier_valide = True
        if not a_bloc:
            refus("optin-incomplet",
                  "double opt-in incomplet : facteur de possession fichier "
                  "local absent")
        elif optin_cli_valide and not optin_fichier_valide and not codes_bloc:
            refus("optin-incomplet",
                  "double opt-in incomplet : les deux facteurs locaux sont "
                  "requis")

    # ── 2. Canal d'activation : local opérateur uniquement ─────────────────
    if contexte.canal_activation not in CANAUX_AUTORISES:
        refus("canal-interdit",
              "activation par un canal non local (HTTP, LLM, UI, données "
              "cible/fixture/journal/artefact, MCP ou provider) interdite")

    # ── 3. Profil : controlled_dev uniquement ──────────────────────────────
    if contexte.profil not in PROFILS_AUTORISES:
        refus("profil-interdit",
              "profil public, production ou incertain interdit : "
              "`controlled_dev` est le seul profil honnête")

    # ── 4. Egress fermé ────────────────────────────────────────────────────
    if contexte.egress_ouverture_demandee:
        refus("egress-non-ferme",
              "ouverture réseau demandée : le laboratoire garde l'egress "
              "fermé")
    if contexte.egress_global_implicite:
        refus("egress-global-interdit",
              "accès réseau global implicite refusé")

    # ── 5. Capacités : existantes et autorisées uniquement ─────────────────
    autorisees = set(contexte.capacites_autorisees)
    hors_registre = [c for c in contexte.capacites_demandees
                     if c not in autorisees]
    if hors_registre:
        refus("capacite-non-autorisee",
              "capacité hors registre AGNT demandée (aucune capacité active "
              "supplémentaire n'est admise)")
    providers_hors = [p for p in contexte.providers_demandes
                      if p not in set(contexte.providers_autorises)]
    if providers_hors:
        refus("provider-non-autorise",
              "provider hors registre AGNT demandé")
    if contexte.commandes_liberes:
        refus("commande-libre-interdite",
              "commande ou argument libre interdit : seules les commandes "
              "du registre sont exécutables")
    if not autorisees:
        refus("capacites-aucune",
              "aucune capacité autorisée déclarée : liste vide refusée")

    # ── 6. Gardes existantes : toutes requises ─────────────────────────────
    if not contexte.policy_disponible:
        refus("policy-indisponible",
              "moteur de politique indisponible : l'absence de décision "
              "n'est pas une autorisation")
    elif not contexte.policy_allow:
        refus("policy-refusee", "la politique a refusé la demande")
    if not contexte.regles_presentes:
        refus("regles-absentes",
              "grille de règles absente : refus fail-closed")
    if not contexte.empreintes_conformes:
        refus("integrite-divergente",
              "empreintes de binaires ou de règles divergentes : refus")
    if not contexte.sandbox_conforme:
        refus("sandbox-non-conforme",
              "sandbox non conforme : refus")

    # ── 7. Cible locale, identifiée, autorisée par le propriétaire ─────────
    ok_cible, reel, problemes = resoudre_cible(contexte.cible_proposee,
                                               contexte.racines_autorisees)
    for code, message in problemes:
        refus(code, message)
    entree_registre = None
    if not contexte.operateur:
        refus("operateur-inconnu", "opérateur non identifié")
    elif contexte.operateur not in contexte.operateurs_autorises:
        refus("operateur-inconnu",
              "opérateur hors liste des propriétaires autorisés")
    if ok_cible:
        for entree in contexte.registre_cibles:
            if Path(entree.chemin).resolve() == Path(reel):
                entree_registre = entree
                break
    if entree_registre is None:
        refus("cible-non-autorisee",
              "cible absente du registre des cibles explicitement autorisées")
    elif entree_registre.autorisee is not True:
        refus("cible-non-autorisee",
              "cible non autorisée (cible_autorisee n'est pas True)")

    # ── 8. Décision + audit redacted ───────────────────────────────────────
    ok = not raisons
    codes = tuple(sorted(r.code for r in raisons))
    audit = [{
        "evenement": "laboratoire.activation",
        "horodatage": maintenant.isoformat(),
        "decision": "autorise" if ok else "refuse",
        "motifs": list(codes),
        "operateur_empreinte": _empreinte(contexte.operateur),
        "cible_empreinte": _empreinte(reel) if reel else _empreinte(
            contexte.cible_proposee),
        "profil": contexte.profil if ok else "REDACTED",
        "reseau": "ferme",
    }]
    return DecisionLabo(ok=ok, raisons=tuple(raisons), audit=tuple(audit),
                        actif=ok, chemin_cible_resolu=reel if ok else "")


# ══════════════════════════════════════════════════════════════════════════
def synthese_audit(decision: DecisionLabo) -> str:
    """Rendu texte de l'audit — ne contient jamais de valeur sensible."""
    lignes = []
    for entree in decision.audit:
        lignes.append(
            f"{entree['horodatage']} labo.{entree['decision']} "
            f"op={entree['operateur_empreinte']} cible={entree['cible_empreinte']} "
            f"motifs={','.join(entree['motifs']) or 'aucun'} "
            f"reseau={entree['reseau']}")
    return "\n".join(lignes)
