"""Tâches d'exécution : lifecycle, exécuteur local, run.json scellé (Stream A).

Une TÂCHE est l'unité planifiable : un provider, un argv déjà construit par
le manifest (jamais de shell), un timeout, un état. L'exécuteur LOCAL lance
de vrais sous-processus SANS shell (`shell=False` toujours) avec timeout,
annulation et nettoyage — vérifié ici avec des commandes bénignes
(`sys.executable -c …`), jamais avec un scanner.

Ce qui est prouvé ici : lifecycle, timeout, annulation, erreurs structurées,
provenance, run.json + sceau. Ce qui NE l'est PAS : l'exécution d'un scanner
réel sous sandbox Linux (`RUNTIME_VERIFIED = False` — voir oracle_web).
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field

RUNTIME_VERIFIED = False

EN_FILE = "en_file"
EN_COURS = "en_cours"
TERMINEE = "terminee"
ECHOUEE = "echouee"
REFUSEE = "refusee"
ANNULEE = "annulee"

ETATS_TACHE = (EN_FILE, EN_COURS, TERMINEE, ECHOUEE, REFUSEE, ANNULEE)


class ErreurTache(Exception):
    """Refus ou panne structurée d'une tâche (jamais un traceback brut)."""


@dataclass
class ResultatExecution:
    code: int | None
    stdout: str
    stderr: str
    duree_s: float
    timeout: bool = False
    annulee: bool = False
    erreur: str = ""

    def to_dict(self) -> dict:
        # Plafond relevé 4000 → 20000 (mesuré le 2026-09-05) : le journal sqlmap
        # dépasse 4000 caractères et la ligne « testing URL '…' » — en TÊTE de
        # journal — était tronquée, privant les findings d'URL (oracle non
        # vérifiable). 20000 × 18 tâches reste borné (~360 Ko) ; les outils
        # écrivent surtout dans {OUT}, le stdout est le complément.
        return {"code": self.code, "stdout": self.stdout[-20000:],
                "stderr": self.stderr[-20000:], "duree_s": round(self.duree_s, 3),
                "timeout": self.timeout, "annulee": self.annulee, "erreur": self.erreur}


@dataclass
class Tache:
    """Une unité planifiable. `argv[0]` est un exécutable résolu, pas un shell."""
    provider_id: str
    argv: list
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    env: dict | None = None
    timeout_s: float = 300.0
    etat: str = EN_FILE
    tentatives: int = 0
    resultat: ResultatExecution | None = None
    debut: float = 0.0
    fin: float = 0.0

    def __post_init__(self) -> None:
        if not self.provider_id or not isinstance(self.provider_id, str):
            raise ErreurTache("provider_id vide")
        if not isinstance(self.argv, list) or not self.argv or not all(
                isinstance(a, str) and a for a in self.argv):
            raise ErreurTache("argv : liste non vide de chaînes exigée (pas de shell)")
        # Pas d'inspection du CONTENU des arguments ici : `python -c "a; b"`,
        # une URL ou un template nuclei contiennent légitimement `;`, espaces,
        # `$`. La garantie anti-injection est STRUCTURELLE : `shell=False`
        # toujours (voir ExecuteurLocal) + argv construit par le manifest
        # déclaré et validé (`provider_manifest`), jamais par concaténation.
        if not (0 < self.timeout_s <= 3600):
            raise ErreurTache(f"timeout_s hors bornes : {self.timeout_s}")

    @property
    def argv_digest(self) -> str:
        return hashlib.sha256(json.dumps(self.argv, ensure_ascii=False).encode()).hexdigest()[:16]


class ExecuteurLocal:
    """Exécute des tâches en sous-processus réels, sans shell.

    `annuler()` positionne un drapeau : la tâche en file passe ANNULEE avant
    démarrage ; une tâche en cours est tuée (`process.kill`) puis marquée.
    `journal` (dossier) reçoit `journal.jsonl` (append) ; `finaliser()` écrit
    `run.json` scellé via `preuve.sceller` (sceau vérifiable).
    """

    def __init__(self, journal_dir=None) -> None:
        from pathlib import Path
        self.journal_dir = Path(journal_dir) if journal_dir else None
        self._annulation = threading.Event()
        self._verrou = threading.Lock()
        if self.journal_dir is not None:
            self.journal_dir.mkdir(parents=True, exist_ok=True)

    def annuler(self) -> None:
        self._annulation.set()

    @property
    def annule(self) -> bool:
        return self._annulation.is_set()

    def _consigner(self, evenement: dict) -> None:
        if self.journal_dir is None:
            return
        ligne = json.dumps({"t": round(time.time(), 3), **evenement}, ensure_ascii=False)
        with self._verrou:
            with open(self.journal_dir / "journal.jsonl", "a", encoding="utf-8") as fh:
                fh.write(ligne + "\n")

    def executer(self, tache: Tache) -> Tache:
        if self.annule and tache.etat == EN_FILE:
            tache.etat = ANNULEE
            tache.resultat = ResultatExecution(None, "", "", 0.0, annulee=True,
                                               erreur="annulee_avant_demarrage")
            self._consigner({"evenement": "annulee", "tache": tache.id,
                             "provider": tache.provider_id})
            return tache
        if tache.etat != EN_FILE:
            raise ErreurTache(f"tâche {tache.id} non en file : {tache.etat}")
        tache.etat = EN_COURS
        tache.tentatives += 1
        tache.debut = time.time()
        self._consigner({"evenement": "demarrage", "tache": tache.id,
                         "provider": tache.provider_id, "argv_digest": tache.argv_digest})
        try:
            proc = subprocess.Popen(tache.argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, shell=False)
        except FileNotFoundError:
            tache.fin = time.time()
            tache.etat = ECHOUEE
            tache.resultat = ResultatExecution(None, "", "", 0.0,
                                               erreur=f"executable_introuvable : {tache.argv[0]}")
            self._consigner({"evenement": "echec", "tache": tache.id,
                             "motif": "executable_introuvable"})
            return tache
        except OSError as e:
            tache.fin = time.time()
            tache.etat = ECHOUEE
            tache.resultat = ResultatExecution(None, "", "", 0.0,
                                               erreur=f"lancement_impossible : {e}")
            self._consigner({"evenement": "echec", "tache": tache.id,
                             "motif": "lancement_impossible"})
            return tache
        try:
            restant = tache.timeout_s
            while True:
                try:
                    out, err = proc.communicate(timeout=min(0.2, restant))
                    break
                except subprocess.TimeoutExpired:
                    if self.annule:
                        proc.kill()
                        out, err = proc.communicate()
                        tache.fin = time.time()
                        tache.etat = ANNULEE
                        tache.resultat = ResultatExecution(
                            proc.returncode, out or "", err or "",
                            tache.fin - tache.debut, annulee=True, erreur="annulee_pendant_execution")
                        self._consigner({"evenement": "annulee", "tache": tache.id})
                        return tache
                    restant = tache.timeout_s - (time.time() - tache.debut)
                    if restant <= 0:
                        proc.kill()
                        out, err = proc.communicate()
                        tache.fin = time.time()
                        tache.etat = ECHOUEE
                        tache.resultat = ResultatExecution(
                            proc.returncode, out or "", err or "",
                            tache.fin - tache.debut, timeout=True,
                            erreur=f"timeout_apres_{tache.timeout_s}s")
                        self._consigner({"evenement": "timeout", "tache": tache.id})
                        return tache
            tache.fin = time.time()
            tache.etat = TERMINEE
            tache.resultat = ResultatExecution(proc.returncode, out or "", err or "",
                                               tache.fin - tache.debut)
            self._consigner({"evenement": "terminee", "tache": tache.id,
                             "code": proc.returncode,
                             "duree_s": round(tache.fin - tache.debut, 3)})
            return tache
        except Exception as e:                                  # ne jamais fuir en traceback
            try:
                proc.kill()
            except Exception:
                pass
            tache.fin = time.time()
            tache.etat = ECHOUEE
            tache.resultat = ResultatExecution(None, "", "", tache.fin - tache.debut,
                                               erreur=f"panne_executeur : {type(e).__name__}")
            self._consigner({"evenement": "echec", "tache": tache.id, "motif": "panne_executeur"})
            return tache

    def finaliser(self, taches: list[Tache], meta: dict | None = None) -> dict:
        """run.json scellé : tâches + provenance + digests. Rend le bundle."""
        import preuve as PR
        objet = {"type": "run", "horodatage": round(time.time(), 3),
                 "meta": meta or {},
                 "taches": [{"id": t.id, "provider": t.provider_id, "etat": t.etat,
                             "tentatives": t.tentatives, "argv_digest": t.argv_digest,
                             "resultat": t.resultat.to_dict() if t.resultat else None}
                            for t in taches]}
        bundle = PR.sceller(objet)
        if self.journal_dir is not None:
            with open(self.journal_dir / "run.json", "w", encoding="utf-8") as fh:
                json.dump(bundle, fh, ensure_ascii=False, indent=2)
            self._consigner({"evenement": "run_finalise",
                             "empreinte": bundle["empreinte"]})
        return bundle
