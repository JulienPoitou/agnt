"""Adaptateurs de providers + couverture.

Deux responsabilités inséparables :

  1. exécuter un outil et récupérer sa sortie brute ;
  2. déclarer ce qui a été analysé et ce qui ne l'a PAS été.

Le second point n'est pas décoratif (décision D2) : Trivy ignore silencieusement
package-lock.json manquant pour npm. Sans couverture, « aucun problème » est
indiscernable de « rien n'a été analysé ».

Règle de construction : le registre ne connaît AUCUN chemin. Il déclare des jetons —
{BIN}, {SCAN}, {REGLES}, {DB}, {OUT} — que l'adaptateur résout au moment de l'exécution.
Chaque adaptateur déclare AUSSI le drapeau de sortie de son outil : laisser le pipeline
injecter un `--output` générique produirait des échecs silencieux sur les outils qui
n'ont pas ce drapeau (gitleaks utilise --report-path).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import extraction as EX
import provider_manifest as PM
from sandbox import CACHE_BIN, CACHE_DB, CACHE_REGLES, Sandbox

IN_SCAN = "/home/user/PHASE3/mt-scan"
IN_OUT = "/home/user/PHASE3/mt-out"

# Où se trouvent réellement les binaires. Résolu à l'exécution, jamais écrit dans le
# registre — et hors du workspace, pour ne pas exploser son budget.
BIN_DIR = CACHE_BIN


@dataclass
class Cible:
    """Élément examiné, ou non, avec son état (décision D2)."""
    chemin: str
    etat: str
    raison: str = ""


@dataclass
class Couverture:
    """Les six états imposés : scanned_successfully, not_found, not_applicable,
    not_scanned, excluded_by_policy, unsupported."""
    provider: str
    cibles: list[Cible] = field(default_factory=list)
    scanners_actives: list[str] = field(default_factory=list)
    scanners_non_applicables: list[str] = field(default_factory=list)
    limites_connues: list[str] = field(default_factory=list)

    def a_analyse_quelque_chose(self) -> bool:
        return any(c.etat == "scanned_successfully" for c in self.cibles)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "cibles": [{"chemin": c.chemin, "etat": c.etat, "raison": c.raison}
                       for c in self.cibles],
            "scanners_actives": self.scanners_actives,
            "scanners_non_applicables": self.scanners_non_applicables,
            "limites_connues": self.limites_connues,
        }


@dataclass
class ResultatBrut:
    provider: str
    capability: str
    code_retour: int
    timeout: bool
    fichier: str
    donnees: object
    couverture: Couverture
    stderr: str = ""
    argv: list[str] = field(default_factory=list)


def _exe(prov) -> str:
    """Résout l'exécutable du provider.

    Ordre : chemin déclaré (jeton {BIN} résolu), puis PATH. Un outil absent doit
    échouer ICI, pas produire un scan vide plus loin — c'est exactement le mode
    d'échec silencieux que la décision D1 vise à empêcher.
    """
    from shutil import which
    brut = prov.commande[0]
    exe = brut.replace("{BIN}", str(BIN_DIR))
    if Path(exe).exists():
        return exe
    trouve = which(brut) or which(Path(brut).name)
    if not trouve:
        raise FileNotFoundError(f"outil introuvable : {brut} (ni {exe}, ni au PATH)")
    return trouve


def _resoud(args: list[str], sbx: Sandbox, sortie: str) -> list[str]:
    """Substitue les jetons du registre par les vrais chemins.

    C'est la SEULE traduction entre la déclaration (portable) et l'exécution (locale).
    """
    return [a.format(BIN=str(BIN_DIR), SCAN=sbx.M_SCAN, REGLES=sbx.M_REGLES,
                     DB=sbx.M_DB, OUT=sbx.M_OUT, sortie=sortie)
            for a in args]


def _lit_json(chemin: Path):
    if not chemin.exists() or chemin.stat().st_size == 0:
        return None
    try:
        return json.loads(chemin.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _lance(prov, sbx: Sandbox, nom_sortie: str) -> tuple:
    """Facteur commun : résolution des jetons, exécution, lecture de la sortie."""
    sortie_hote = sbx.sortie / nom_sortie
    sortie_int = f"{sbx.M_OUT}/{nom_sortie}"
    # La cible est ajoutée en dernier. Elle n'est PAS dans le registre : c'est une donnée
    # d'exécution, pas une déclaration d'outil. L'oublier fait scanner le répertoire
    # courant sans erreur — échec silencieux, vérifié pour de vrai avec Semgrep.
    argv = _resoud(list(prov.commande) + list(prov.args_obligatoires), sbx, sortie_int)
    argv[0] = _exe(prov)
    argv.append(sbx.M_SCAN)
    r = sbx.exec(argv)
    return r, _lit_json(sortie_hote), argv, sortie_int


# ------------------------------------------------------------------ Semgrep
def semgrep(prov, sbx: Sandbox) -> ResultatBrut:
    r, donnees, argv, _ = _lance(prov, sbx, "semgrep.json")
    couv = Couverture(provider=prov.id)
    fichiers = sorted({x["path"] for x in (donnees or {}).get("results", [])})
    erreurs = (donnees or {}).get("errors") or []

    for f in fichiers:
        couv.cibles.append(Cible(f, "scanned_successfully"))
    if not fichiers:
        couv.cibles.append(Cible(sbx.M_SCAN, "not_scanned",
                                 "aucune règle n'a porté sur ce dépôt"))
    if erreurs:
        # Un jeu de règles introuvable ne doit JAMAIS passer pour un dépôt sain.
        couv.limites_connues.append(
            f"{len(erreurs)} erreur(s) Semgrep : " +
            "; ".join(str(e.get("message", ""))[:120] for e in erreurs[:3]))
    couv.scanners_actives = ["semgrep:python", "semgrep:security-audit"]
    couv.limites_connues.append(
        "le jeu de règles est épinglé sur python/security-audit : un dépôt d'un autre "
        "langage ressortirait vide sans erreur")
    return ResultatBrut(prov.id, prov.capability, r.code, r.timeout,
                        "semgrep.json", donnees, couv, (r.stderr or "")[-2000:], argv)


# ------------------------------------------------------------------ Trivy
MANIFESTES = {
    "requirements.txt": "python/pip",
    "Pipfile.lock": "python/pip",
    "poetry.lock": "python/poetry",
    "package.json": "nodejs/npm",
    "package-lock.json": "nodejs/npm",
    "yarn.lock": "nodejs/yarn",
    "go.mod": "go",     # mesuré le 2026-08-29 : Trivy analyse go.mod seul (4 CVE sur
                        # testrepo_go) — sans cette ligne, la couverture déclarait
                        # « not_scanned » tout en produisant des findings.
    "go.sum": "go",
    "Gemfile.lock": "ruby",
    "pom.xml": "java/maven",
    "Cargo.lock": "rust",
}
# Vérifié par exécution : sans package-lock.json, Trivy ignore SILENCIEUSEMENT npm
# (1 fichier analysé au lieu de 2). En revanche requirements.txt est analysé seul.
LOCKFILE_OBLIGATOIRE = {"nodejs/npm": "package-lock.json", "nodejs/yarn": "yarn.lock"}


def trivy(prov, sbx: Sandbox) -> ResultatBrut:
    r, donnees, argv, _ = _lance(prov, sbx, "trivy.json")
    couv = Couverture(provider=prov.id)
    analysés = {res.get("Target", "") for res in (donnees or {}).get("Results", [])}

    présents = {nom: eco for nom, eco in MANIFESTES.items()
                if (sbx.racine_scan / nom).exists()}
    # package.json seul ne suffit pas : c'est le lockfile qui porte les versions résolues.
    if "package.json" in présents and "package-lock.json" not in présents:
        del présents["package.json"]
        couv.cibles.append(Cible(
            "package.json", "not_scanned",
            "manifeste npm présent mais AUCUN package-lock.json : Trivy ignore "
            "silencieusement ce fichier, les versions résolues sont inconnues"))
        couv.limites_connues.append(
            "dépendances npm NON couvertes : ajouter package-lock.json")

    for nom, eco in présents.items():
        if nom in analysés:
            couv.cibles.append(Cible(nom, "scanned_successfully"))
        else:
            couv.cibles.append(Cible(nom, "not_scanned",
                                     f"manifeste présent mais ignoré par l'outil ({eco})"))
            couv.limites_connues.append(
                f"{nom} présent mais non analysé : dépendances {eco} non couvertes")

    if not couv.a_analyse_quelque_chose():
        couv.cibles.append(Cible(sbx.M_SCAN, "not_scanned",
                                 "aucun manifeste de dépendances exploitable"))
    couv.scanners_actives = ["trivy:vuln"]
    couv.scanners_non_applicables = ["trivy:misconfig", "trivy:secret"]
    couv.limites_connues.append(
        "base de vulnérabilités figée au pré-chauffage : les CVE publiées depuis "
        "ne sont pas détectées")
    return ResultatBrut(prov.id, prov.capability, r.code, r.timeout,
                        "trivy.json", donnees, couv, (r.stderr or "")[-2000:], argv)


# ------------------------------------------------------------------ Gitleaks
def gitleaks(prov, sbx: Sandbox) -> ResultatBrut:
    r, donnees, argv, _ = _lance(prov, sbx, "gitleaks.json")
    couv = Couverture(provider=prov.id)

    if not (sbx.racine_scan / ".git").exists():
        couv.cibles.append(Cible(".git", "not_found",
                                 "dépôt sans historique git : `gitleaks git` n'a rien à scanner"))
    else:
        couv.cibles.append(Cible("historique git", "scanned_successfully"))
        for f in sorted({x.get("File", "") for x in (donnees or []) if x.get("File")}):
            couv.cibles.append(Cible(f, "scanned_successfully"))
    couv.scanners_actives = ["gitleaks:rules"]
    couv.limites_connues.append(
        "valeur des secrets masquée à la source (--redact) : jamais stockée")
    couv.limites_connues.append(
        "détection dépendante des règles : une clé AWS réaliste peut être classée "
        "generic-api-key, et les exemples de documentation sont sur liste blanche")

    # Gitleaks renvoie 1 quand il trouve des fuites : ce n'est pas une erreur d'exécution.
    echec = r.code not in (0, 1)
    return ResultatBrut(prov.id, prov.capability, 1 if echec else 0, r.timeout,
                        "gitleaks.json", donnees, couv,
                        (r.stderr or "")[-2000:] if echec else "", argv)


# ------------------------------------------------------------------ adaptateur générique
def generique_cli(prov, sbx: Sandbox) -> ResultatBrut:
    """Exécute un provider déclaré par MANIFEST, sans code spécifique à l'outil.

    C'est la preuve recherchée en Phase 5A : un outil ajouté dans un fichier YAML
    passe par ici, et par nulle part ailleurs.

    Le trusted core contrôle : binaire autorisé, placeholders, cible, arguments,
    risque, format de sortie, montages, timeouts. Le manifest ne décide de rien.
    """
    m = prov.manifest
    nom_sortie = f"{m.id}.{'txt' if m.sortie_format == 'custom' else 'json'}"
    sortie_int = f"{sbx.M_OUT}/{nom_sortie}"

    _chemins = {
        "BIN": str(CACHE_BIN / m.binaire) if (CACHE_BIN / m.binaire).exists() else m.binaire,
        "TARGET": sbx.M_SCAN,
        "OUT": sortie_int,
        "OUT_DIR": sbx.M_OUT,
        "REGLES": sbx.M_REGLES,
        "DB": sbx.M_DB,
    }
    argv = PM.resoudre_argv(m, _chemins)
    # Env déclaratif (étape 4) : grype configure son cache de DB par variable
    # d'environnement. Résolu par le cœur, exactement comme argv.
    env_resolu = PM.resoudre_env(m, _chemins)
    # Certains outils écrivent sur stdout plutôt que dans un fichier : on capture aussi.
    r = sbx.exec(argv, env=env_resolu or None)
    donnees = _lit_json(sbx.sortie / nom_sortie)
    if donnees is None and r.stdout:
        try:
            import json as _json
            donnees = _json.loads(r.stdout)
        except Exception:
            donnees = None

    # Format custom : un parser spécifique, référencé par son NOM dans le manifest.
    # Le cœur ne sait pas quel outil c'est, ni ce qu'est le format.
    if m.sortie_format == "custom":
        import parsers
        fn = parsers.obtenir(m.extraction.parser)
        if fn is None:
            raise KeyError(f"parser {m.extraction.parser!r} introuvable")
        texte = (sbx.sortie / nom_sortie).read_text(encoding="utf-8", errors="replace") \
            if (sbx.sortie / nom_sortie).exists() else (r.stdout or "")
        items = fn(texte)
        if donnees is None:
            donnees = {"parser": m.extraction.parser, "items": items}
    else:
        items = EX.extraire(donnees, m.extraction) if donnees is not None else []
    couv = Couverture(provider=m.id)
    fichiers = []
    for it in items:
        c = EX.champs(it, m.extraction)
        f = c.get("fichier")
        if f and f not in fichiers:
            fichiers.append(f)
    if m.declare_fichiers and fichiers:
        for f in fichiers:
            couv.cibles.append(Cible(f, "scanned_successfully"))
    elif fichiers:
        couv.cibles.append(Cible(sbx.M_SCAN, "scanned_successfully"))
    else:
        couv.cibles.append(Cible(sbx.M_SCAN, "not_scanned",
                                 "aucun résultat produit par l'outil"))
    # Un outil absent ou en échec ne doit JAMAIS ressembler à « rien trouvé ».
    # C'est le mode d'échec le plus dangereux d'un scanner : le silence rassurant.
    if donnees is None and not items:
        couv.cibles = [Cible(sbx.M_SCAN, "not_scanned",
                             f"outil {m.binaire!r} absent ou en échec "
                             f"(code {r.code}) — aucun résultat produit")]
        couv.limites_connues.append(
            f"ÉCHEC D'EXÉCUTION de {m.binaire!r} : ce scan n'a rien couvert. "
            f"Ce n'est pas une absence de problème.")
    couv.scanners_actives = [f"{m.id}:{m.sortie_format}"]
    if m.limite:
        couv.limites_connues.append(m.limite)
    couv.limites_connues.append(
        "provider déclaratif : les résultats sont extraits selon la spécification du "
        "manifest, sans connaissance de l'outil par le cœur")

    # Le code de succès est DÉCLARÉ : bandit et gitleaks renvoient 1 quand ils trouvent
    # quelque chose. Traiter ça comme une erreur masquerait tous leurs résultats.
    echec = r.code not in m.code_succes
    return ResultatBrut(m.id, m.capability, r.code if echec else 0, r.timeout,
                        nom_sortie, donnees, couv,
                        (r.stderr or "")[-2000:] if echec else "", argv)


ADAPTATEURS = {
    "semgrep": semgrep,
    "trivy": trivy,
    "gitleaks": gitleaks,
}


def executer(prov, sbx: Sandbox) -> ResultatBrut:
    """Point d'entrée unique.

    Priorité : un provider déclaré par MANIFEST passe par l'adaptateur générique, sans
    code spécifique. Les adaptateurs historiques (semgrep, trivy, gitleaks) restent
    utilisés pour leurs particularités — couverture npm, base pré-peuplée, historique git.
    """
    if getattr(prov, "manifest", None) is not None:
        return generique_cli(prov, sbx)
    fn = ADAPTATEURS.get(prov.id)
    if fn is None:
        raise KeyError(
            f"aucun adaptateur pour {prov.id!r} et aucun manifest déclaré. "
            f"Adaptateurs existants : {sorted(ADAPTATEURS)}.")
    return fn(prov, sbx)
