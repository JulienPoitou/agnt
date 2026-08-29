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
    # Limites de ressources (setrlimit). Vérifiées effectives sous bwrap.
    max_processus: int = 256
    max_cpu_secondes: int = 300
    max_fichier_octets: int = 512 * 1024 * 1024

    # Points de montage vus de l'intérieur. Défauts = les montages partagés du
    # bootstrap (comportement historique inchangé). Champs d'INSTANCE (étape 3) :
    # des montages par exécution sont possibles — pré-requis du parallélisme, non
    # construit ici. bwrap ne crée PAS les points de montage : des répertoires
    # personnalisés doivent exister avant l'appel (leçon bootstrap).
    M_SCAN: str = "/home/user/PHASE3/mt-scan"
    M_REGLES: str = "/home/user/PHASE3/mt-regles"
    M_DB: str = "/home/user/PHASE3/mt-db"
    M_OUT: str = "/home/user/PHASE3/mt-out"
    M_GITCONF: str = "/home/user/PHASE3/gitconfig.ro"

    def verifie(self) -> list[str]:
        """Vérifie les préconditions AVANT de lancer, pour échouer avec un message utile."""
        prob = []
        for nom, chemin in (("dépôt", self.racine_scan), ("règles", self.racine_regles),
                            ("base Trivy", self.racine_db), ("sortie", self.sortie),
                            ("gitconfig", self.gitconfig)):
            if chemin is None or not Path(chemin).exists():
                prob.append(f"{nom} introuvable : {chemin}")
        for pt in (self.M_SCAN, self.M_REGLES, self.M_DB, self.M_OUT, self.M_GITCONF):
            if not Path(pt).exists():
                prob.append(f"point de montage absent : {pt} (lancer bootstrap.sh)")
        return prob

    def commande(self, argv: list[str]) -> list[str]:
        return [
            self.bwrap,
            "--ro-bind", "/", "/",
            "--ro-bind", str(self.racine_scan), self.M_SCAN,
            "--ro-bind", str(self.racine_regles), self.M_REGLES,
            "--ro-bind", str(self.racine_db), self.M_DB,
            "--ro-bind", str(self.gitconfig), self.M_GITCONF,
            "--bind", str(self.sortie), self.M_OUT,
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--unshare-user", "--unshare-pid", "--unshare-net",
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
                "memoire": "NON limitée (RLIMIT_AS casse Trivy et Gitleaks) — nécessite cgroups"}

    def exec(self, argv: list[str], env: dict | None = None) -> Resultat:
        prob = self.verifie()
        if prob:
            raise SandboxError("sandbox inutilisable : " + "; ".join(prob))

        e = dict(os.environ)
        e["HOME"] = "/tmp"
        e["TMPDIR"] = "/tmp"
        e["GIT_CONFIG_GLOBAL"] = self.M_GITCONF
        # Double ceinture : même si --unshare-net tombait, aucune requête ne passerait.
        e["HTTP_PROXY"] = "http://127.0.0.1:9"
        e["HTTPS_PROXY"] = "http://127.0.0.1:9"
        e["NO_PROXY"] = ""
        if env:
            e.update(env)

        cmd = self.commande(argv)
        # start_new_session=True crée un groupe de processus dont on est le meneur.
        # Indispensable : subprocess.run ne tue que l'enfant DIRECT au timeout, et
        # --die-with-parent ne tue que l'enfant direct de bwrap. Vérifié pour de vrai :
        # `sleep 60 &` survivait au timeout avec un PID encore vivant.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=e, preexec_fn=self._limites,
                                start_new_session=True)
        try:
            out, err = proc.communicate(timeout=self.timeout)
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



