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
import conditions as COND
import provider_manifest as PM
import transports
from sandbox import CACHE_BIN, CACHE_DB, CACHE_REGLES, RACINE_MONTEURS, Sandbox

# Ces deux constantes sont LE préfixe de montage, pas un chemin d'hôte : un littéral séparé
# de `Sandbox.M_*` décide silencieusement si les chemins des outils seront normalisés ou
# garderont le préfixe du conteneur. Elles sont donc dérivées de la même racine (test_fanout
# 3a contrôle l'égalité des deux côtés — c'est la raison d'être de ce couple).
IN_SCAN = str(RACINE_MONTEURS / "mt-scan")
IN_OUT = str(RACINE_MONTEURS / "mt-out")

# Où se trouvent réellement les binaires. Résolu à l'exécution, jamais écrit dans le
# registre — et hors du workspace, pour ne pas exploser son budget.
BIN_DIR = CACHE_BIN


class ConditionRefusee(Exception):
    """Les conditions déclarées par l'outil ne sont pas remplies dans cette cage.

    Ce n'est PAS une ligne de couverture, encore moins un résultat vide : l'outil n'a pas
    tourné, et le dire est la seule manière honnête de le rapporter. Sans cette exception,
    un outil sans réseau (ou sans base) rendait un scan vide en code 0 — un faux « rien
    trouvé » qui, dans un rapport, se lit comme une bonne nouvelle.
    """


@dataclass
class Cible:
    """Élément examiné, ou non, avec son état (décision D2)."""
    chemin: str
    etat: str
    raison: str = ""


# Ce que trivy sait faire dans le mode `fs` qu'on emploie. Sert uniquement à calculer ce qui
# n'a PAS été activé à partir de ce qui l'a été — jamais l'inverse.
_TRIVY_SCANNERS = ("vuln", "misconfig", "secret")


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
    # Le texte tel que l'outil l'a rendu sur stdout. Conservé à part, et NON injecté dans
    # `donnees` : ajouter une clé au document parsé de l'outil fausserait les findings (et un
    # outil pourrait légitimement avoir une clé de ce nom). C'est ce texte qui permet de
    # conserver le brut d'un outil qui écrit sur stdout plutôt que dans un fichier (`json`).
    texte_brut: str = ""


def resoudre_exe(binaire: str) -> str | None:
    """Chemin réel de l'exécutable, ou None. UNE SEULE règle, partagée.

    Ordre : chemin déclaré (jeton {BIN} résolu), puis PATH. Le ledger de `statuts.py`
    appelle la même fonction : si la disponibilité était jugée deux fois avec deux
    règles, un écran pourrait écrire « outil absent » à côté d'un outil qui vient de
    tourner (et l'inverse — plus grave : promettre un outil qui échouera).
    """
    from shutil import which
    chaine = str(binaire)
    exe = chaine.replace("{BIN}", str(BIN_DIR))
    if Path(exe).exists():
        return exe
    trouve = which(chaine) or which(Path(chaine).name)
    if trouve:
        return trouve
    # 30/08/2026 — dernier recours : le répertoire des outils, même sans jeton {BIN}.
    # Raison mesurée, pas de confort : les providers de binaires autonomes déclarent
    # « {BIN}/trivy » (les deux autorités sont d'accord), mais les outils pip déclarent le
    # nom nu — « bandit », « detect-secrets » — donc leur disponibilité dépendait du PATH,
    # alors que leur argv, lui, pointe sur {BIN}. Un shim posé dans BIN_DIR rendait donc
    # l'outil exécutable ET déclaré absent (refus dans `_exe`, « non_disponible » dans
    # l'écran). Un seul critère pour les deux questions.
    dans_bin = Path(BIN_DIR) / Path(chaine).name
    return str(dans_bin) if dans_bin.exists() else None


def binaire_de(prov) -> str:
    """Le nom d'exécutable DÉCLARÉ par un provider — ce qu'on affiche, pas ce qu'on lance.

    Deux origines, et c'est la source historique des divergences : un provider
    DÉCLARATIF nomme son binaire dans son manifest, un provider à adaptateur historique
    le porte dans sa `commande`. Écrire le mauvais des deux dans un message d'erreur
    envoie l'opérateur chercher un fichier qui n'a jamais été déclaré.
    """
    mani = getattr(prov, "manifest", None)
    if mani is not None and getattr(mani, "binaire", ""):
        return str(mani.binaire)
    if getattr(prov, "commande", None):
        return str(prov.commande[0])
    return str(getattr(prov, "id", "") or "")


def exe_de(prov) -> str | None:
    """Chemin réel de l'exécutable d'un provider, ou None. UNE SEULE règle.

    `resoudre_exe` savait déjà répondre pour une chaîne ; ce qui manquait, c'était une
    seule réponse à « quel nom cherche-t-on, pour CE provider ? ». Avant cette fonction,
    trois endroits décidaient séparément : `_exe` lisait `commande[0]`, `generique_cli`
    lisait `manifest.binaire` (avec son propre `if exists`), et `statuts` faisait un `or`
    entre les deux. Conséquence possible, et c'est la famille de F8 : un outil exécuté
    par l'un et déclaré absent par l'autre.

    Décision D10 (31/08/2026) : cette fonction est aussi ce qui permet à la sélection de
    ne plus réserver un slot de fan-out à un outil qui n'existe pas sur la machine.
    """
    mani = getattr(prov, "manifest", None)
    if mani is not None and getattr(mani, "binaire", ""):
        trouve = resoudre_exe(str(mani.binaire))
        if trouve:
            return trouve
    if getattr(prov, "commande", None):
        return resoudre_exe(str(prov.commande[0]))
    return None


def _exe(prov) -> str:
    """Résout l'exécutable du provider, et refuse s'il n'existe pas.

    Un outil absent doit échouer ICI, pas produire un scan vide plus loin — c'est
    exactement le mode d'échec silencieux que la décision D1 vise à empêcher.
    """
    brut = binaire_de(prov)
    trouve = exe_de(prov)
    if not trouve:
        raise FileNotFoundError(
            f"outil introuvable : {brut} (ni {str(brut).replace('{BIN}', str(BIN_DIR))}, ni au PATH)")
    return trouve


def _resoud(args: list[str], sbx: Sandbox, sortie: str) -> list[str]:
    """Substitue les jetons du registre par les vrais chemins.

    C'est la SEULE traduction entre la déclaration (portable) et l'exécution (locale).
    """
    return [a.format(BIN=str(BIN_DIR), SCAN=sbx.M_SCAN, REGLES=sbx.M_REGLES,
                     DB=sbx.M_DB, OUT=sbx.M_OUT, sortie=sortie)
            for a in args]


# Extension du fichier que l'outil écrit, par format DÉCLARÉ. Un format sans extension
# connue est un bug de déclaration, pas un `.json` par défaut : le défaut silencieul ferait
# relire un .xml comme du JSON, donc « 0 item ».
EXTENSIONS_FORMAT = {"json": "json", "sarif": "json", "jsonl": "jsonl",
                     "csv": "csv", "xml": "xml", "custom": "txt"}

FORMATS_TEXTE = ("jsonl", "csv", "xml")


def extension_de(format_sortie: str) -> str:
    try:
        return EXTENSIONS_FORMAT[format_sortie]
    except KeyError:
        raise ManifestRefus(f"format de sortie inconnu côté cœur : {format_sortie!r}") from None


class ManifestRefus(Exception):
    """Un manifest demande au cœur quelque chose qu'il ne sait pas lire."""


def _lit_texte(chemin: Path) -> str:
    if not chemin.exists():
        return ""
    try:
        return chemin.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _lit_json(chemin: Path):
    if not chemin.exists() or chemin.stat().st_size == 0:
        return None
    try:
        return json.loads(chemin.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _lance(prov, sbx: Sandbox, nom_sortie: str) -> tuple:
    """Facteur commun : conditions, résolution des jetons, exécution, lecture de la sortie."""
    sortie_hote = sbx.sortie / nom_sortie
    sortie_int = f"{sbx.M_OUT}/{nom_sortie}"
    # Seconde barrière (la première est au plan) : les conditions de l'outil sont jugées
    # sur la commande qui va VRAIMENT partir, pas sur ce que le profil a déclaré. Un
    # `--providers` forcé en ligne de commande, ou un adaptateur appelé directement,
    # tombe ici — sinon un outil sans réseau rendrait un scan vide en code 0.
    argv_pour_juger = _resoud(list(prov.commande) + list(prov.args_obligatoires), sbx, sortie_int)
    motifs = COND.manquantes(prov, egress=COND.egress_de(sbx, argv_pour_juger),
                             racine_db=sbx.racine_db)
    if motifs:
        raise ConditionRefusee(f"{prov.id} : " + " ; ".join(motifs))
    # La cible est ajoutée en dernier. Elle n'est PAS dans le registre : c'est une donnée
    # d'exécution, pas une déclaration d'outil. L'oublier fait scanner le répertoire
    # courant sans erreur — échec silencieux, vérifié pour de vrai avec Semgrep.
    argv = _resoud(list(prov.commande) + list(prov.args_obligatoires), sbx, sortie_int)
    argv[0] = _exe(prov)
    argv.append(sbx.M_SCAN)
    demande, note = COND.timeout_effectif(prov, sbx.timeout)
    r = sbx.exec(argv, timeout=sbx.delai_effectif(demande))
    return r, _lit_json(sortie_hote), argv, sortie_int, note


# ------------------------------------------------------------------ Semgrep
def _drapeau(argv: list[str], nom: str) -> list[str]:
    """Les valeurs `--nom=valeur` de la commande QUI A ÉTÉ PASSÉE, rien d'autre.

    À quoi ça sert : la couverture est ce que le lecteur croit savoir. Elle était écrite à
    côté de la commande, en dur — `capabilities.yaml` a pris trois jeux de règles pendant
    que `adapters.semgrep` en déclarait deux, et le rapport répétait le deux avec assurance
    (constat G6b de la campagne adverse). Un chiffre recopié à la main d'un YAML vers un
    attribut de dataclass finit toujours par mentir, et il ment silencieusement.

    Donc : on lit argv. Corollaire utile — quand F7 épinglera un `--config` pour gitleaks,
    la couverture le déclarera sans qu'on écrive quoi que ce soit.
    """
    prefixe = f"--{nom}="
    return [a[len(prefixe):] for a in argv if isinstance(a, str) and a.startswith(prefixe)]


def semgrep(prov, sbx: Sandbox) -> ResultatBrut:
    r, donnees, argv, _, note = _lance(prov, sbx, "semgrep.json")
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
    epingles = _drapeau(argv, "config")
    couv.scanners_actives = [f"semgrep:{Path(c).stem}" for c in epingles]
    if not epingles:
        # aucun --config = le scan ne prouve rien, et le dire est plus utile que de se taire
        couv.limites_connues.append(
            "aucun --config passé à semgrep : le scan ne s'appuie sur AUCUN jeu de règles")
    couv.limites_connues.append(
        f"jeux de règles épinglés : {', '.join(Path(c).stem for c in epingles) or 'aucun'} — "
        "un dépôt écrit dans un autre langage ressortirait vide sans erreur")
    if note:                       # délai déclaré ramené au plafond du profil — trace
        couv.limites_connues.append("note de plafond : " + note)
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
    r, donnees, argv, _, note = _lance(prov, sbx, "trivy.json")
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
    actifs = _drapeau(argv, "scanners")
    actifs = [s for v in actifs for s in v.split(",") if s]
    couv.scanners_actives = [f"trivy:{s}" for s in actifs]
    # ce qui est « non applicable » n'est pas une liste à maintenir à jour : c'est ce que
    # trivy sait faire MOINS ce qu'on a activé, sur la même ligne de commande.
    couv.scanners_non_applicables = [f"trivy:{s}" for s in _TRIVY_SCANNERS if s not in actifs]
    couv.limites_connues.append(
        "base de vulnérabilités figée au pré-chauffage : les CVE publiées depuis "
        "ne sont pas détectées")
    if note:                       # délai déclaré ramené au plafond du profil — trace
        couv.limites_connues.append("note de plafond : " + note)
    return ResultatBrut(prov.id, prov.capability, r.code, r.timeout,
                        "trivy.json", donnees, couv, (r.stderr or "")[-2000:], argv)


# ------------------------------------------------------------------ Gitleaks
def gitleaks(prov, sbx: Sandbox) -> ResultatBrut:
    r, donnees, argv, _, note = _lance(prov, sbx, "gitleaks.json")
    couv = Couverture(provider=prov.id)

    if not (sbx.racine_scan / ".git").exists():
        couv.cibles.append(Cible(".git", "not_found",
                                 "dépôt sans historique git : `gitleaks git` n'a rien à scanner"))
    else:
        couv.cibles.append(Cible("historique git", "scanned_successfully"))
        for f in sorted({x.get("File", "") for x in (donnees or []) if x.get("File")}):
            couv.cibles.append(Cible(f, "scanned_successfully"))
    regles = _drapeau(argv, "config")
    couv.scanners_actives = [f"gitleaks:{Path(c).name}" for c in regles]
    if not regles:
        # état réel de l'outil tel qu'on le lance aujourd'hui (constat G6a) : ce n'est pas
        # une limite technique, c'est le lecteur qui doit savoir qu'il lit un scan dont il
        # ne connaît pas la grille.
        couv.limites_connues.append(
            "aucun jeu de règles épinglé pour gitleaks : ce sont ses règles par défaut, et "
            "un `.gitleaks.toml` dans le dépôt scanné pourrait les modifier (comportement "
            "non mesuré ici, le binaire est absent de cette machine)")
    couv.limites_connues.append(
        "valeur des secrets masquée à la source (--redact) : jamais stockée")
    couv.limites_connues.append(
        "détection dépendante des règles : une clé AWS réaliste peut être classée "
        "generic-api-key, et les exemples de documentation sont sur liste blanche")

    # Gitleaks renvoie 1 quand il trouve des fuites : ce n'est pas une erreur d'exécution.
    echec = r.code not in (0, 1)
    if note:                       # délai déclaré ramené au plafond du profil — trace
        couv.limites_connues.append("note de plafond : " + note)
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
    nom_sortie = f"{m.id}.{extension_de(m.sortie_format)}"
    sortie_int = f"{sbx.M_OUT}/{nom_sortie}"

    # `_exe` et rien d'autre : c'est la MÊME règle que le ledger de `statuts` et que le
    # filtre de sélection (`intent`), et c'est la seule qui REFUSE.
    #
    # 31/08/2026 — ce point valait `exe_de(prov) or m.binaire`. Le repli sur le nom nu
    # est ce qui permettait à un outil ABSENT d'être tout de même lancé : `argv[0]`
    # devenait « kics », la cage tentait le exec, récupérait un code 1 et aucune sortie,
    # et le pipeline consignait `execution kics code_retour=1 findings=0` — un outil qui
    # n'existe pas, enregistré comme un scan qui n'a rien trouvé. La couverture disait
    # « not_scanned » en aval, mais l'artefact `raw_kics.json` (null) et la ligne de
    # journal, eux, racontaient une exécution. Un outil absent doit échouer ICI (D1),
    # pas produire un vide plus loin.
    _chemins = {
        "BIN": _exe(prov),
        "TARGET": sbx.M_SCAN,
        "OUT": sortie_int,
        "OUT_DIR": sbx.M_OUT,
        "REGLES": sbx.M_REGLES,
        "DB": sbx.M_DB,
    }
    argv = PM.resoudre_argv(m, _chemins)
    # Barrière de conditions (voir conditions.py) : jugée sur la commande construite,
    # pas sur la déclaration d'un profil. Un outil qui a besoin de sortir est REFUSÉ,
    # il ne rend pas un scan vide présenté comme une conclusion.
    motifs = COND.manquantes(prov, egress=COND.egress_de(sbx, argv), racine_db=sbx.racine_db)
    if motifs:
        raise ConditionRefusee(f"{m.id} : " + " ; ".join(motifs))
    # Env déclaratif (étape 4) : grype configure son cache de DB par variable
    # d'environnement. Résolu par le cœur, exactement comme argv.
    env_resolu = PM.resoudre_env(m, _chemins)
    # Certains outils écrivent sur stdout plutôt que dans un fichier : on capture aussi.
    demande, note = COND.timeout_effectif(prov, sbx.timeout)
    r = sbx.exec(argv, env=env_resolu or None, timeout=sbx.delai_effectif(demande))
    if m.sortie_format in FORMATS_TEXTE:
        # Le cœur ne parse PAS : il remet le TEXTE, et c'est `extraction` qui lit selon le
        # modèle déclaré (lignes_json / csv / xml). Le fichier de l'outil fait foi, stdout
        # sert de repli pour les outils qui n'écrivent que là.
        texte = _lit_texte(sbx.sortie / nom_sortie) or (r.stdout or "")
        donnees = {"texte": texte} if texte.strip() else None
    else:
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
        sortie_lue = bool((texte or "").strip())
        # 30/08/2026 — le parser déclaré EST l'autorité sur `items`. Avant cette ligne,
        # le conteneur n'était construit que si aucune donnée n'avait été lue : un outil
        # « custom » dont la sortie se trouve être du JSON valide (detect-secrets) laissait
        # `donnees` rempli, le normaliseur ré-extraiait donc les items avec le modèle plat
        # depuis le JSON brut — le parser était contourné et le provider rendait 0 finding
        # en silence. bandit_custom n'y échappait que par accident (son CSV n'est pas du
        # JSON). La sortie brute reste conservée à côté, pour l'artefact et l'audit.
        brut = donnees
        donnees = {"parser": m.extraction.parser, "items": items}
        if brut is not None:
            donnees["sortie_brute"] = brut
        # Le texte tel que rendu, conservé pour l'archivage brut (voir `conserver_brut`) :
        # pour un outil qui n'écrit que sur stdout, c'est la seule trace de ses octets.
        donnees["sortie_brute_texte"] = texte
    else:
        items = EX.extraire(donnees, m.extraction) if donnees is not None else []
        sortie_lue = donnees is not None       # None = rien de lisible : voir la garde plus bas
    couv = Couverture(provider=m.id)
    if note:                       # délai déclaré ramené au plafond du profil — trace
        couv.limites_connues.append("note de plafond : " + note)
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
    # 30/08/2026 — la condition portait uniquement sur `donnees is None`. Elle ne se
    # présente jamais pour un provider à parser (donnees y est le conteneur
    # {"parser","items"} construit par le cœur), ni pour un outil qui rend une sortie
    # illisible. Juger sur ce qui a été LU et sur le code de retour, sinon « 0 finding »
    # reste ambigu exactement là où il l'est le plus.
    if not items and not sortie_lue:
        couv.cibles = [Cible(sbx.M_SCAN, "not_scanned",
                             f"outil {m.binaire!r} absent ou en échec "
                             f"(code {r.code}) — aucun résultat produit")]
        couv.limites_connues.append(
            f"ÉCHEC D'EXÉCUTION de {m.binaire!r} : ce scan n'a rien couvert. "
            f"Ce n'est pas une absence de problème.")
    elif r.code not in m.code_succes:
        couv.limites_connues.append(
            f"ÉCHEC D'EXÉCUTION de {m.binaire!r} (code {r.code}) : l'outil a rendu un code "
            "inespéré, ses résultats ne sont pas nécessairement complets — ce n'est pas une "
            "absence de problème.")
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
                        (r.stderr or "")[-2000:] if echec else "", argv,
                        texte_brut=(r.stdout or ""))


def conserver_brut(sbx: Sandbox, dossier: Path, brut: "ResultatBrut", provider: str) -> str | None:
    """Copie la sortie BRUTE de l'outil à côté du JSON re-construit par le cœur.

    Déclaré ici et pas dans le pipeline : seul l'adaptateur sait où l'outil a écrit. Et
    écrit ICI, pas seulement dans le dossier de sortie du sandbox, parce que le sandbox est
    éphémère — sans copie, la « conservation de la sortie brute » serait une promesse tenue
    jusqu'au nettoyage du répertoire temporaire.

    Deux origines, dans cet ordre : le fichier que l'outil a produit (`brut.fichier`), sinon
    ce qu'il a rendu sur stdout. `None` si l'outil n'a rien laissé d'exploitable — ce qui est
    un état à dire, pas un fichier vide à faire semblant d'archiver.
    """
    nom = getattr(brut, "fichier", "") or ""
    source = (sbx.sortie / nom) if nom else None
    if source is not None and source.exists() and source.stat().st_size:
        destination = dossier / f"brut_{provider}{source.suffix}"
        try:
            destination.write_bytes(source.read_bytes())
            return destination.name
        except OSError:
            return None
    texte = ""
    donnees = getattr(brut, "donnees", None)
    if isinstance(donnees, dict):
        texte = donnees.get("sortie_brute_texte") or (
            donnees.get("texte") if isinstance(donnees.get("texte"), str) else "")
    if not str(texte).strip():
        # Le fichier de l'outil n'existe pas (stdout-only, format json) : le texte rendu par
        # l'outil reste la trace de ses octets. Sans ce repli, un provider json n'a PAS de brut
        # conservé — et le couple « ce que le cœur a compris / ce que l'outil a écrit » promis
        # au pipeline ne serait mesurable que pour les outils à fichier.
        texte = getattr(brut, "texte_brut", "") or ""
    if not str(texte).strip():
        return None
    extension = (Path(nom).suffix if nom else "") or ".txt"
    destination = dossier / f"brut_{provider}{extension}"
    try:
        destination.write_text(str(texte), encoding="utf-8")
        return destination.name
    except OSError:
        return None


ADAPTATEURS = {
    "semgrep": semgrep,
    "trivy": trivy,
    "gitleaks": gitleaks,
}


def executer(prov, sbx: Sandbox) -> ResultatBrut:
    """Point d'entrée unique — dispatché par TRANSPORT, puis par forme de provider.

    La frontière (2026-08-30) : un provider déclare SON transport au manifest ; le cœur
    fournit `sandbox_cli` (sous-processus dans la cage) et DÉLÈGUE tout autre transport à
    l'exécuteur enregistré (`transports.deleguer`). Un transport non fourni est une erreur
    nette, jamais un repli silencieux sur le sous-processus — un provider « mcp » exécuté
    en binaire local serait exactement le mélange Provider/Transport que cette séparation
    existe pour empêcher.

    Dans `sandbox_cli`, la priorité reste : un provider déclaré par MANIFEST passe par
    l'adaptateur générique, sans code spécifique ; les adaptateurs historiques (semgrep,
    trivy, gitleaks) restent utilisés pour leurs particularités — couverture npm, base
    pré-peuplée, historique git.
    """
    transport = getattr(prov, "transport", None) or transports.TRANSPORT_SANDBOX_CLI
    if transport != transports.TRANSPORT_SANDBOX_CLI:
        return transports.deleguer(transport, prov, sbx)
    if getattr(prov, "manifest", None) is not None:
        return generique_cli(prov, sbx)
    fn = ADAPTATEURS.get(prov.id)
    if fn is None:
        raise KeyError(
            f"aucun adaptateur pour {prov.id!r} et aucun manifest déclaré. "
            f"Adaptateurs existants : {sorted(ADAPTATEURS)}.")
    return fn(prov, sbx)
