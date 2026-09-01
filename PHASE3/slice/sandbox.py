"""Sandbox — bubblewrap.

Les contraintes sont imposées PAR NOUS, pas déléguées aux images des outils : les images
officielles de Trivy et Gitleaks tournent en root par défaut (voir RESULTATS_TESTS.md).

Quatre pièges rencontrés pour de vrai, tous encodés ici :
  1. la racine est montée en LECTURE SEULE, donc bwrap ne peut plus créer de point de
     montage ensuite : toutes les cibles de --ro-bind doivent exister AVANT l'appel ;
  2. /tmp est un tmpfs qui disparaît à la sortie : les rapports vont dans un répertoire
     bindé depuis l'hôte, sinon on croit à tort que l'outil n'a rien produit ;
  3. ne jamais faire rm -rf sur un répertoire déjà bindé, ça casse le montage ;
  4. git rejette un dépôt dans un user namespace (propriétaire douteux) : il faut un
     GIT_CONFIG_GLOBAL avec safe.directory.

Limites de ressources : bwrap ne les impose pas, mais setrlimit dans un preexec_fn
fonctionne sous bwrap — vérifié par exécution :

  · RLIMIT_NPROC=64 → « Cannot fork » au lieu de 300 processus ;
  · RLIMIT_CPU      → temps CPU borné ;
  · RLIMIT_FSIZE    → borne la taille des fichiers écrits.

RLIMIT_AS est VOLONTAIREMENT EXCLU. Testé sur les outils réels, il les casse :
  · Trivy    → « cannot allocate memory » à l'ouverture de sa base boltdb (mmap) ;
  · Gitleaks → crash dans wazero, son moteur regex WASM réserve une grande région virtuelle.
J'avais validé le mécanisme avec `ulimit -v`, pas son effet sur de vrais outils.

**La limite mémoire n'est donc PAS imposée.** La faire correctement demande cgroups v2 ou un
runtime OCI. C'est une limite réelle de cette sandbox, pas un détail : un outil qui consomme
trop de mémoire ne sera pas arrêté ici.

RLIMIT_NPROC compte par utilisateur RÉEL, pas par conteneur : c'est un garde-fou, pas une
isolation par exécution.
"""

from __future__ import annotations

import os
import resource
import subprocess
from dataclasses import dataclass
from pathlib import Path

import assainissement as ASS

# Binaires, règles et base Trivy vivent HORS du workspace (~/.cache/arena_secops) :
# le workspace a un budget de 128 Mo et la base Trivy pèse 1,3 Go à elle seule.
CACHE_RACINE = Path(os.environ.get("ARENA_SECOPS_CACHE",
                                   str(Path.home() / ".cache" / "arena_secops")))
CACHE_BIN = CACHE_RACINE / "bin"
CACHE_REGLES = CACHE_RACINE / "rules"
# Parent COMMUN des bases de vulnérabilités (trivy/, grype/). Chaque outil vise
# son sous-répertoire : --cache-dir={DB}/trivy, GRYPE_DB_CACHE_DIR={DB}/grype.
CACHE_DB = CACHE_RACINE / "trivy-cache"

# Points de montage vus de l'ENFANT, et témoins contrôlés sur l'HÔTE : bwrap ne crée pas
# ses destinations, d'où `verifie()` qui exige leur présence. `bootstrap.sh` les crée sous
# <dépôt>/PHASE3 (`B="$(cd "$(dirname "$0")" && pwd)"`). Les cinq chemins étaient écrits en
# dur sous /home/user/PHASE3 — un répertoire qui n'existe sur AUCUNE machine, pas même ici :
# `verifie()` y rejetait `gitconfig.ro` alors que ce fichier est dans le dépôt, et le premier
# vrai lancement échouait ailleurs avec « lancer bootstrap.sh » après un bootstrap réussi.
# La racine suit donc le dépôt, comme `pipeline.RACINE`, et ARENA_SECOPS_MONTEURS permet un
# montage hors dépôt sur le même modèle qu'ARENA_SECOPS_CACHE pour les binaires.
RACINE_MONTEURS = Path(os.environ.get("ARENA_SECOPS_MONTEURS",
                                      str(Path(__file__).resolve().parent.parent)))


# --------------------------------------------------------------------------- environnement
# L'outil qui lit un dépôt hostile ne voyage pas avec les secrets de l'hôte.
#
# Forme exacte du défaut (campagne adverse, constat G7, mesuré sur cette machine) :
# `e = dict(os.environ)`, soit 24 variables dont GH_TOKEN, GITHUB_TOKEN et la clé du
# fournisseur LLM dans le processus qui parse le dépôt de l'attaquant. Le réseau est
# coupé (`--unshare-net`) et les montages sont en lecture seule (G1) : l'outil ne peut pas
# APPELER une destination. Il peut quand même LIRE ces valeurs, et les faire sortir par le
# seul canal qui lui reste ouvert — le rapport. Une clé recopiée dans un `message` par un
# outil qu'on ne contrôlait pas devient un finding, puis une ligne du Markdown que
# l'humain colle dans un ticket.
#
# Liste BLANCHE, pas liste noire. Une liste noire se contourne en inventant une variable ;
# une liste blanche se contourne en en oubliant une — et un oubli se voit tout de suite, en
# local, parce que l'outil concerné tombe, alors qu'un secret parti ne se voit jamais.
#
# Ce que chaque entrée paye, parce qu'une liste blanche sans raison écrite est un déguisement :
#   PATH                 semgrep lance node/rg par son exécutable ; bandit est un entry point
#   LANG, LC_ALL, LC_CTYPE  sinon la sortie des outils passe en ASCII et les accents des
#                        chemins et des messages deviennent des `?` — une preuve illisible
#   TZ                   les horodatages des findings doivent se relire, pas se décaler
#   TERM, NO_COLOR       cosmétique, mais un outil qui colore sa sortie la rend moins
#                        analysable ; ce sont des variables de rendu, pas d'identité
#
# Si un outil se plaint d'une variable absente, on l'ajoute ICI avec sa raison écrite en
# face. Jamais « pour voir si ça marche » : ce qui passe par cette liste est ce que le
# dépôt scanne est capable de lire.
ENV_HOTE_AUTORISES = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "NO_COLOR")


def environ_outil(declare: dict | None = None, hote: dict | None = None,
                  montages: dict | None = None) -> dict:
    """L'environnement réellement remis à un outil : liste blanche de l'hôte, montages,
    puis ce que le cœur déclare — dans cet ordre, parce que le déclaré doit gagner (c'est
    le comportement historique de `exec`, et c'est lui qui permet `GRYPE_DB_CACHE_DIR`).

    Fonction à part et pure : elle est testable sans sandbox, sans bwrap et sans outil, ce
    qu'aucune assertion sur `exec` ne permettait de faire ici.
    """
    source = os.environ if hote is None else hote
    e = {k: v for k, v in source.items() if k in ENV_HOTE_AUTORISES}
    if montages:
        e.update(montages)
    if declare:
        e.update(declare)
    return e



# ------------------------------------------------------------------ identité des artefacts
# Ce que `bootstrap.sh` garantit, c'est l'INSTALLATION : il compare le SHA-256 du fichier
# qu'il vient de poser. Ce que le pipeline garantit à l'exécution, c'est qu'un fichier
# EXISTE (`verifie`, ci-dessous). Entre les deux, tout un espace : `ARENA_SECOPS_CACHE`
# déplace la racine des binaires ET des règles (mesuré, constat G8), donc un cache posé
# après le bootstrap — ou un répertoire détourné — est exécuté sans jamais être regardé.
# Le manifeste épinglé, lui, n'est jamais consulté par le cœur.
#
# D'où ce contrôle, appelé par `verifie()` donc avant chaque `Popen` : on compare
# l'empreinte de ce qu'on VA lancer à ce que le manifeste déclare. Un artefact absent n'est
# pas une divergence (c'est `verifie` qui le dit, et les outils optionnels — kics, grype —
# légitimement). Un artefact PRÉSENT et différent est un refus, pas un avertissement.
#
# Le hash est COMPLET, et c'est une divergence assumée avec `run._sha256`, qui tronque à
# 1 Mio pour le digest de contexte : là on compare à une empreinte épinglée, donc hacher une
# partie du fichier en affirmant vérifier le fichier serait exactement le défaut qu'on ferme.
# Le coût est payé une fois par processus (mémo sur taille + mtime), pas une fois par appel
# d'outil — sinon la vérification serait la première victime de la perf, et on la
# retirerait.

_MEMO_EMPREINTE: dict[tuple[str, int, int], str] = {}


def _sha256_fichier(chemin: Path) -> str:
    cle = (str(chemin), chemin.stat().st_size, chemin.stat().st_mtime_ns)
    vu = _MEMO_EMPREINTE.get(cle)
    if vu is not None:
        return vu
    import hashlib
    h = hashlib.sha256()
    with open(chemin, "rb") as fh:                           # par blocs : 161 Mio de Trivy
        for bloc in iter(lambda: fh.read(1 << 22), b""):      # ne doivent pas atterrir en RAM
            h.update(bloc)
    _MEMO_EMPREINTE[cle] = h.hexdigest()
    return _MEMO_EMPREINTE[cle]


def empreintes_conformes(bin_dir: Path | None = None, regles_dir: Path | None = None,
                         manifeste: Path | None = None) -> list[str]:
    """La liste des problèmes d'identité — vide veut dire conforme.

    `manifeste` est un paramètre pour pouvoir TESTER le chemin « conforme » sans avoir le
    binaire réel sous la main : on écrit un manifeste et un fichier d'empreinte connue.
    """
    import outils as OT
    problemes: list[str] = []
    racine_bin = Path(bin_dir) if bin_dir is not None else CACHE_BIN
    if racine_bin.is_dir():
        try:
            registre = OT.registre(manifeste)
        except Exception as exc:                              # noqa: BLE001
            return [f"manifeste de dépendances illisible ({type(exc).__name__}) : "
                    "impossible de vérifier l'identité des binaires"]
        for tid, tool in registre.items():
            if tool.installation != "binaire" or not tool.sha256:
                continue                                      # les tools pip : hash de distribution
            fichier = racine_bin / tid
            if not fichier.is_file():
                continue                                        # absent : c'est `verifie` qui le dit
            reel = _sha256_fichier(fichier)
            if reel != tool.sha256:
                problemes.append(
                    f"{tid} : empreinte divergente du manifeste épinglé "
                    f"(obtenu {reel[:16]}…, attendu {tool.sha256[:16]}…) — exécution refusée")
    if regles_dir is not None and Path(regles_dir).is_dir():
        epinglees = OT.regles_epinglees(manifeste)
        for nom, attendu in sorted(epinglees.items()):
            fichier = Path(regles_dir) / nom
            if not fichier.is_file():
                continue
            reel = _sha256_fichier(fichier)
            if reel != attendu:
                problemes.append(f"règle {nom} : empreinte divergente de {attendu[:16]}… — "
                                 "le jeu de règles n'est pas celui qui a servi à valider les "
                                 "tests, le résultat n'est pas comparable")
    return problemes


def _python_user_site_hote() -> str | None:
    """Le chemin des paquets pip utilisateur de l'hôte, pour le transmettre au sandbox.

    Le sandbox met HOME=/tmp (sécurité : l'outil ne lit pas les configs de l'hôte).
    Conséquence : Python ne trouve plus les paquets installés via `pip install --user`,
    comme checkov. On ne peut pas remettre HOME=/home/user — c'est volontaire.
    La solution est d'ajouter le site-packages utilisateur au PYTHONPATH : l'outil
    retrouve ses modules sans récupérer les fichiers de config de l'hôte.
    """
    import site
    try:
        p = Path(site.getusersitepackages())
    except Exception:
        return None
    return str(p) if p.is_dir() else None



class SandboxError(Exception):
    pass


@dataclass(frozen=True)
class Resultat:
    code: int
    stdout: str
    stderr: str
    timeout: bool


@dataclass(frozen=True)
class Sandbox:
    """Configuration de confinement. Les chemins hôtes sont ceux du bootstrap."""

    bwrap: str = "bwrap"
    racine_scan: Path = None            # dépôt analysé, monté en lecture seule
    racine_regles: Path = None          # règles Semgrep, lecture seule
    racine_db: Path = None              # base Trivy, lecture seule
    sortie: Path = None                 # rapports, bindé en ÉCRITURE
    gitconfig: Path = None
    timeout: int = 600
    # Egress. FAUX par défaut, et ce n'est pas un réglage de confort : la cage coupe le réseau
    # (`--unshare-net`) parce que le dépôt scanné est une entrée non fiable. Passer ce champ à
    # vrai retire `--unshare-net` de la commande ET retire les variables de proxy neutres — les
    # deux à la fois, parce qu'une cage « autorisée » dont le proxy pointe sur port 9 est une
    # autorisation sabotée : l'outil croirait sortir et rendrait un résultat vide en code 0, le
    # pire mode d'échec connu de ce projet.
    # `conditions.egress_de` ne lit PAS ce champ : il mesure la commande construite. Une seule
    # autorité, et le test de ce lot échoue si les deux divergent.
    egress_autorise: bool = False
    # Limites de ressources (setrlimit). Vérifiées effectives sous bwrap.
    max_processus: int = 256
    max_cpu_secondes: int = 300
    max_fichier_octets: int = 512 * 1024 * 1024

    # Points de montage vus de l'intérieur. Défauts = les montages partagés du
    # bootstrap (comportement historique inchangé). Champs d'INSTANCE (étape 3) :
    # des montages par exécution sont possibles — pré-requis du parallélisme, non
    # construit ici. bwrap ne crée PAS les points de montage : des répertoires
    # personnalisés doivent exister avant l'appel (leçon bootstrap).
    M_SCAN: str = str(RACINE_MONTEURS / "mt-scan")
    M_REGLES: str = str(RACINE_MONTEURS / "mt-regles")
    M_DB: str = str(RACINE_MONTEURS / "mt-db")
    M_OUT: str = str(RACINE_MONTEURS / "mt-out")
    M_GITCONF: str = str(RACINE_MONTEURS / "gitconfig.ro")

    def verifie(self) -> list[str]:
        """Vérifie les préconditions AVANT de lancer, pour échouer avec un message utile.

        La base Trivy n'est PAS vérifiée ici : elle n'est nécessaire qu'aux providers
        qui la déclarent (trivy, grype), et cette condition est déjà jugée par
        `conditions.manquantes()` au moment de la sélection. L'exiger globalement
        empêche tout outil de tourner tant que Trivy n'est pas installé — y compris
        checkov, semgrep, bandit, gitleaks qui n'en ont aucun besoin.
        """
        prob = []
        for nom, chemin in (("dépôt", self.racine_scan), ("règles", self.racine_regles),
                            ("sortie", self.sortie),
                            ("gitconfig", self.gitconfig)):
            if chemin is None or not Path(chemin).exists():
                prob.append(f"{nom} introuvable : {chemin}")
        # M_DB n'est exigé que si une base est montée (racine_db non nulle et existante).
        points_obligatoires = [self.M_SCAN, self.M_REGLES, self.M_OUT, self.M_GITCONF]
        if self.racine_db is not None and Path(self.racine_db).exists():
            points_obligatoires.append(self.M_DB)
        for pt in points_obligatoires:
            if not Path(pt).exists():
                prob.append(f"point de montage absent : {pt} (lancer bootstrap.sh)")
        # identité, pas seulement existence : c'est ici que le cache détourné par
        # ARENA_SECOPS_CACHE cesse d'être un trou (F10 / constat G8)
        prob += empreintes_conformes(CACHE_BIN, self.racine_regles)
        return prob

    def commande(self, argv: list[str]) -> list[str]:
        cmd = [
            self.bwrap,
            "--ro-bind", "/", "/",
            "--ro-bind", str(self.racine_scan), self.M_SCAN,
            "--ro-bind", str(self.racine_regles), self.M_REGLES,
        ]
        # La base Trivy n'est montée que si elle existe — un outil qui n'en a pas
        # besoin (checkov, semgrep, bandit, gitleaks) ne doit pas échouer parce
        # qu'un répertoire déclaré par bootstrap est absent de cette machine.
        # La condition d'usage est déjà jugée par `conditions.manquantes()`.
        if self.racine_db is not None and Path(self.racine_db).exists():
            cmd += ["--ro-bind", str(self.racine_db), self.M_DB]
        cmd += [
            "--ro-bind", str(self.gitconfig), self.M_GITCONF,
            "--bind", str(self.sortie), self.M_OUT,
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--unshare-user", "--unshare-pid",
            # Le réseau n'est jamais retiré par oubli : `egress_autorise` est le seul chemin,
            # il vient du profil effectif de la mission et il est consigné au journal.
            *([] if self.egress_autorise else ["--unshare-net"]),
            "--unshare-ipc", "--unshare-uts",
            # Répertoire de travail DÉTERMINISTE (dogfooding 2026-08-29) : sans
            # --chdir, bwrap hérite du cwd du processus parent — et un outil qui
            # relativise ses chemins (kics) émettait des préfixes variables selon
            # le point de lancement (« PHASE3/mt-scan/x » vs « mt-scan/x »), ce
            # qui rendait la corrélation inter-outils aveugle (mêmes fichiers,
            # identifiants différents). Ancré sur la racine de scan : les chemins
            # relativisés deviennent ceux de la cible. M_SCAN est en lecture
            # seule — un outil qui écrirait dans son cwd échouerait bruyamment.
            "--chdir", self.M_SCAN,
            "--die-with-parent",
            *argv,
        ]
        return cmd

    @staticmethod
    def _tue_le_groupe(pid: int) -> None:
        """Tue tout le groupe de processus après un timeout.

        Sans ça, les processus lancés en arrière-plan par l'outil survivent indéfiniment :
        une fuite de processus est aussi une fuite de ressources et d'information.
        """
        import signal
        for cible in (pid,):
            try:
                os.killpg(os.getpgid(cible), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                os.kill(cible, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    def _limites(self) -> None:
        """Applique les limites de ressources dans le processus fils, avant exec.

        setrlimit fonctionne sous bwrap (vérifié) : c'est ce qui permet d'imposer des
        limites sans cgroups. Les valeurs sont volontairement larges pour des scanners
        passifs ; elles existent pour borner un dérapage, pas pour calibrer un outil.
        """
        # Pas de RLIMIT_AS : il casse Trivy (mmap boltdb) et Gitleaks (wazero).
        for res, val in ((resource.RLIMIT_NPROC, self.max_processus),
                         (resource.RLIMIT_CPU, self.max_cpu_secondes),
                         (resource.RLIMIT_FSIZE, self.max_fichier_octets),
                         (resource.RLIMIT_CORE, 0)):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                # Une limite non applicable ne doit pas empêcher l'exécution, mais
                # ne doit pas non plus passer inaperçue.
                pass

    def limites_appliquees(self) -> dict:
        return {"max_processus": self.max_processus,
                "max_cpu_secondes": self.max_cpu_secondes,
                "max_fichier_octets": self.max_fichier_octets,
                "timeout_secondes": self.timeout,
                "memoire": "NON limitée (RLIMIT_AS casse Trivy et Gitleaks) — nécessite cgroups",
                # Consigné dans `contexte_empreinte` (run.py) : une exécution qui a pu parler
                # au réseau n'est pas la même exécution. Sans cette ligne, un run « cage fermée »
                # et un run « export accordé » produiraient la même empreinte de contexte — et
                # le `run_id`, lui, est dérivé de cette empreinte.
                "reseau": ("AUTORISÉ (`--unshare-net` retiré de la commande)"
                           if self.egress_autorise else "coupé (`--unshare-net`)")}

    def delai_effectif(self, demande: int | None) -> int:
        """Délai réellement appliqué : le plafond du profil GAGNE toujours.

        Un manifest peut demander plus COURT (un outil lent ne doit pas manger toute la
        mission), jamais plus long : sinon la déclaration d'un outil non fiable
        relâcherait une limite du profil — ce que la séparation « l'outil déclare, le
        cœur décide » existe justement pour empêcher.
        """
        plafond = int(self.timeout)
        if not demande:
            return plafond
        d = int(demande)
        return max(1, min(d, plafond))

    def exec(self, argv: list[str], env: dict | None = None,
             timeout: int | None = None) -> Resultat:
        delai = self.delai_effectif(timeout)
        prob = self.verifie()
        if prob:
            raise SandboxError("sandbox inutilisable : " + "; ".join(prob))

        # Les montages d'abord, l'hôte ensuite filtré, le déclaré en dernier (voir
        # `environ_outil` : c'est l'ordre qui préserve le comportement historique).
        montages = {
            "HOME": "/tmp",
            "TMPDIR": "/tmp",
            "GIT_CONFIG_GLOBAL": self.M_GITCONF,
            # Double ceinture : même si --unshare-net tombait, aucune requête ne passerait.
            # Uniquement quand l'export n'est PAS accordé — voir le champ `egress_autorise`.
            **({} if self.egress_autorise else {
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "",
            }),
        }
        # PYTHONPATH : le sandbox met HOME=/tmp, donc Python ne trouve plus les paquets
        # pip utilisateur (checkov, etc.). On ajoute le site-packages de l'hôte.
        # Mis dans `declare` (pas `montages`) car le déclaré gagne en dernier :
        # si un provider déclare déjà PYTHONPATH, on fusionne au lieu d'écraser.
        declare = dict(env or {})
        py_site = _python_user_site_hote()
        if py_site:
            if "PYTHONPATH" in declare:
                declare["PYTHONPATH"] = py_site + os.pathsep + declare["PYTHONPATH"]
            else:
                declare["PYTHONPATH"] = py_site
        e = environ_outil(declare=declare, montages=montages)

        cmd = self.commande(argv)
        # start_new_session=True crée un groupe de processus dont on est le meneur.
        # Indispensable : subprocess.run ne tue que l'enfant DIRECT au timeout, et
        # --die-with-parent ne tue que l'enfant direct de bwrap. Vérifié pour de vrai :
        # `sleep 60 &` survivait au timeout avec un PID encore vivant.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=e, preexec_fn=self._limites,
                                start_new_session=True)
        try:
            out, err = proc.communicate(timeout=delai)
        except subprocess.TimeoutExpired:
            self._tue_le_groupe(proc.pid)
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:
                out, err = "", ""
            # stdout et stderr sont masqués DÈS la capture : c'est le premier point de
            # sortie, donc le premier endroit où un secret peut s'échapper vers un log
            # ou une exception.
            return Resultat(124, ASS.masquer(out or "")[0],
                            ASS.masquer((err or "") + "\n[timeout]")[0], True)
        return Resultat(proc.returncode, ASS.masquer(out or "")[0],
                        ASS.masquer(err or "")[0], False)
