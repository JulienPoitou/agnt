"""Identité d'exécution — run_id et contexte, distincts du plan_id.

    plan_id  = identité stable du PLAN      (ce qui a été demandé)
    run_id   = identité d'une EXÉCUTION     (ce qui a réellement tourné)

Sans cette séparation, deux exécutions du même plan peuvent donner des résultats
différents sans que la cause soit identifiable. Le contexte capture donc ce qui peut
changer entre deux rejeux :

    versions des outils · digest des règles · digest de la base Trivy
    empreinte de la policy · configuration du sandbox

SARIF fournit des identifiants stables et des empreintes partielles, mais il ne relie
pas deux outils entre eux : l'identité canonique interne reste nécessaire.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from sandbox import CACHE_BIN, Sandbox


def _sha256(chemin: Path) -> str:
    """Empreinte d'un fichier, ou de l'arbre s'il s'agit d'un répertoire.

    Lecture PAR BLOCS : `read_bytes()[:1Mo]` chargeait le fichier ENTIER en
    mémoire avant de le tronquer. Occurrence réelle (2026-08-29, étape 4) : la
    base grype est un fichier SQLite d'environ 1,4 Go — sur une machine à 2 Go
    de RAM, le slice tuait le processus (OOM) avant la première exécution.
    """
    h = hashlib.sha256()
    try:
        if chemin.is_dir():
            for f in sorted(chemin.rglob("*")):
                if f.is_file():
                    h.update(str(f.relative_to(chemin)).encode("utf-8"))
                    with open(f, "rb") as fh:
                        h.update(fh.read(1 << 20))
        elif chemin.exists():
            with open(chemin, "rb") as fh:
                h.update(fh.read(1 << 20))
        else:
            return "absent"
    except OSError:
        return "illisible"
    return h.hexdigest()[:16]


def _version(argv: list[str]) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip().splitlines()[0][:80]
    except Exception as e:
        return f"indisponible ({type(e).__name__})"


@dataclass
class Contexte:
    """Tout ce qui peut faire diverger deux exécutions du même plan."""
    outils: dict = field(default_factory=dict)
    regles: dict = field(default_factory=dict)
    base_trivy: str = ""
    policy: str = ""
    registre: str = ""
    sandbox: dict = field(default_factory=dict)
    contexte_empreinte: str = ""
    # input_digest est séparé du contexte : le contexte décrit l'ENVIRONNEMENT
    # (outils, règles, base), la cible est une DONNÉE. Les confondre ferait passer
    # deux dépôts différents pour un même rejeu.
    input_digest: str = ""
    input_commit: str = ""
    working_tree_dirty: bool = False

    def to_dict(self) -> dict:
        d = {
            "outils": self.outils,
            "regles": self.regles,
            "base_trivy": self.base_trivy,
            "policy": self.policy,
            "registre": self.registre,
            "sandbox": self.sandbox,
            "contexte_empreinte": self.contexte_empreinte,
            "input_digest": self.input_digest,
            "input_commit": self.input_commit,
            "working_tree_dirty": self.working_tree_dirty,
        }
        return d


def capturer(sbx: Sandbox, policy: Path, registre_empreinte: str) -> Contexte:
    """Lit l'état réel de l'environnement. Ne devine rien : ce qui est illisible
    est marqué comme tel, pour qu'une divergence reste explicable."""
    c = Contexte()
    # Les binaires sont dans CACHE_BIN, pas à côté de la cible. Une version « indisponible »
    # dans un rapport de traçabilité est pire qu'une absence : elle fait croire que l'outil
    # n'a pas servi.
    for nom, argv in (("semgrep", ["semgrep", "--version"]),
                      ("trivy", [str(CACHE_BIN / "trivy"), "--version"]),
                      ("gitleaks", [str(CACHE_BIN / "gitleaks"), "version"]),
                      ("bwrap", [sbx.bwrap, "--version"]),
                      ("opa", [str(CACHE_BIN / "opa"), "version"])):
        c.outils[nom] = _version(argv)

    c.regles = {p.name: _sha256(p) for p in sorted(sbx.racine_regles.glob("*.yaml"))}
    c.base_trivy = _sha256(sbx.racine_db)
    c.policy = _sha256(policy)
    c.registre = registre_empreinte
    c.sandbox = sbx.limites_appliquees()

    blob = repr((c.outils, c.regles, c.base_trivy, c.policy, c.registre, c.sandbox))
    c.contexte_empreinte = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    return c


def digest_cible(cible: Path) -> tuple[str, str, bool]:
    """Empreinte de l'ÉTAT RÉEL analysé — et non du seul commit.

    Entre dans le digest, par fichier et dans un ordre déterministe :
        · chemin relatif
        · contenu
        · nature (fichier, dossier, symlink)
        · cible du symlink, s'il y en a un
        · permissions utiles (mode)

    `.git` est EXCLU du digest : il change à chaque commit sans que le code analysé
    change, et l'inclure rendrait tout rejeu non comparable. En revanche :
        · les fichiers NON SUIVIS par git entrent dans le digest (ce sont eux qui
          sont réellement analysés) ;
        · le commit HEAD et l'état « working tree dirty » sont capturés À PART.

    Le commit SHA ne suffit pas : un dépôt modifié sans commit produirait le même SHA
    pour deux états analysés différents.

    Les symlinks sont représentés dans le digest même s'ils sont ensuite refusés par
    la garde de chemin : le digest décrit ce qui a été vu, la garde décide ce qui est
    autorisé. Les deux restent séparés.
    """
    cible = Path(cible)
    h = hashlib.sha256()
    commit = ""
    dirty = False

    if cible.is_file():
        h.update(cible.read_bytes())
        return h.hexdigest()[:16], "", False
    if not cible.exists():
        return "absent", "", False

    for f in sorted(cible.rglob("*"), key=lambda x: str(x)):
        try:
            rel = str(f.relative_to(cible))
        except ValueError:
            continue
        if rel.split("/")[0] == ".git":
            continue
        h.update(rel.encode("utf-8"))
        if f.is_symlink():
            h.update(b"symlink")
            h.update(os.readlink(f).encode("utf-8"))
        elif f.is_dir():
            h.update(b"dir")
        else:
            h.update(b"file")
            try:
                h.update(oct(f.stat().st_mode & 0o7777).encode("utf-8"))
                h.update(f.read_bytes())
            except OSError:
                h.update(b"illisible")

    git = cible / ".git"
    if git.exists():
        try:
            r = subprocess.run(["git", "-C", str(cible), "rev-parse", "HEAD"],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0:
                commit = r.stdout.strip()
            d = subprocess.run(["git", "-C", str(cible), "status", "--porcelain"],
                               capture_output=True, text=True, timeout=20)
            dirty = bool(d.stdout.strip())
        except Exception:
            pass
    return h.hexdigest()[:16], commit, dirty


def digest_resultats(findings: list[dict]) -> str:
    """Empreinte des résultats CANONIQUES TRIÉS.

    Le tri est indispensable : l'ordre brut dépend de l'outil et peut varier d'une
    exécution à l'autre. Comparer des résultats non triés produirait des divergences
    fantômes.
    """
    canon = sorted(
        (f.get("identity", {}).get("canonical_rule_id", ""),
         f.get("identity", {}).get("fingerprint", ""),
         f.get("location", {}).get("file", ""),
         str(f.get("location", {}).get("line")),
         f.get("source", {}).get("tool", ""))
        for f in findings
    )
    return hashlib.sha256(repr(canon).encode("utf-8")).hexdigest()[:16]


def nouveau_run_id(plan_id: str, ctx: Contexte, input_digest: str) -> str:
    """run_id = contexte + cible + instant + NONCE aléatoire.

    Le nonce est indispensable : deux exécutions lancées dans la même nanoseconde avec le
    même plan et la même cible doivent malgré tout avoir des run_id distincts. Sans lui,
    l'unicité ne reposerait que sur l'horloge.

    À l'inverse, `result_digest` reste DÉTERMINISTE : il décrit ce qui a été trouvé, pas
    quand. C'est lui qui sert à comparer deux exécutions.
    """
    return hashlib.sha256(
        f"{plan_id}|{input_digest}|{ctx.contexte_empreinte}|"
        f"{time.time_ns()}|{secrets.token_hex(8)}".encode("utf-8")
    ).hexdigest()[:16]
