#!/usr/bin/env python3
"""Tâches : validation, exécution réelle bénigne, timeout, annulation, run scellé.

Les sous-processus lancés ici sont des `sys.executable -c …` inoffensifs —
la preuve porte sur le LIFECYCLE, pas sur un scanner (RUNTIME_VERIFIED=false).

Usage : python PHASE3/test_taches.py
"""
from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import preuve as PR                                             # noqa: E402
from taches import (ANNULEE, ECHOUEE, EN_COURS, EN_FILE,       # noqa: E402
                    RUNTIME_VERIFIED, TERMINEE, ErreurTache, ExecuteurLocal, Tache)

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


PY = sys.executable


def main() -> int:
    cas("runtime scanners NON vérifié déclaré", RUNTIME_VERIFIED is False)
    # ------------------------------------------------------- validation
    for nom, kwargs in [
        ("provider vide refusé", {"provider_id": "", "argv": [PY]}),
        ("argv vide refusé", {"provider_id": "x", "argv": []}),
        ("argv non-chaîne refusé", {"provider_id": "x", "argv": [PY, 3]}),
        ("argv chaîne vide refusé", {"provider_id": "x", "argv": [PY, ""]}),
        ("timeout 0 refusé", {"provider_id": "x", "argv": [PY], "timeout_s": 0}),
        ("timeout >1h refusé", {"provider_id": "x", "argv": [PY], "timeout_s": 99999}),
    ]:
        try:
            Tache(**kwargs)
            cas(nom, False, "acceptée")
        except ErreurTache:
            cas(nom, True)
        except Exception as e:
            cas(nom, False, f"{type(e).__name__} au lieu d'ErreurTache")
    # ------------------------------------------------------- exécution réelle bénigne
    tmp = Path(tempfile.mkdtemp(prefix="agnt-taches-"))
    ex = ExecuteurLocal(tmp)
    t = ex.executer(Tache("echo_probe", [PY, "-c", "print('bonjour')"], timeout_s=30))
    cas("commande bénigne → TERMINEE code 0 + stdout",
        t.etat == TERMINEE and t.resultat and t.resultat.code == 0
        and "bonjour" in t.resultat.stdout and t.tentatives == 1,
        str(t.resultat.to_dict())[:120] if t.resultat else "sans résultat")
    cas("argv_digest stable 16 hex",
        len(t.argv_digest) == 16 and t.argv_digest == Tache("e", t.argv).argv_digest)
    t = ex.executer(Tache("sortie_1", [PY, "-c", "import sys; sys.exit(3)"], timeout_s=30))
    cas("code 3 → TERMINEE (le code est une donnée, pas une panne)",
        t.etat == TERMINEE and t.resultat and t.resultat.code == 3)
    t = ex.executer(Tache("inexistant", ["agnt-binaire-qui-nexiste-pas-xyz"], timeout_s=30))
    cas("binaire absent → ECHOUEE structurée (pas de crash)",
        t.etat == ECHOUEE and t.resultat and "executable_introuvable" in t.resultat.erreur,
        t.resultat.erreur if t.resultat else "")
    # ------------------------------------------------------- timeout réel
    t0 = time.time()
    t = ex.executer(Tache("lente", [PY, "-c", "import time; time.sleep(30)"], timeout_s=2))
    cas("sleep 30 + timeout 2 → ECHOUEE timeout nommé, ~2s",
        t.etat == ECHOUEE and t.resultat and t.resultat.timeout
        and "timeout_apres_2" in t.resultat.erreur and time.time() - t0 < 10,
        t.resultat.erreur if t.resultat else "")
    # ------------------------------------------------------- annulation
    ex2 = ExecuteurLocal(tmp / "f2")
    ex2.annuler()
    t = ex2.executer(Tache("jamais", [PY, "-c", "print(1)"], timeout_s=30))
    cas("annulée avant démarrage → ANNULEE sans exécution",
        t.etat == ANNULEE and t.tentatives == 0, t.etat)
    ex3 = ExecuteurLocal(tmp / "f3")
    cont = {}
    def lance():
        cont["t"] = ex3.executer(Tache("longue", [PY, "-c", "import time; time.sleep(30)"],
                                       timeout_s=60))
    fil = threading.Thread(target=lance, daemon=True)
    fil.start()
    time.sleep(1.0)
    ex3.annuler()
    fil.join(timeout=15)
    t = cont.get("t")
    cas("annulée pendant exécution → ANNULEE (process tué)",
        t is not None and t.etat == ANNULEE and t.resultat is not None
        and t.resultat.annulee, getattr(t, "etat", "?"))
    # ------------------------------------------------------- run scellé
    t1 = ex.executer(Tache("p1", [PY, "-c", "print('a')"], timeout_s=30))
    bundle = ex.finaliser([t1], {"contexte": "test"})
    cas("run.json scellé et vérifiable",
        PR.verifier(bundle)[0] is True and (tmp / "run.json").is_file()
        and bundle["objet"]["taches"][0]["argv_digest"] == t1.argv_digest)
    cas("journal.jsonl append-only non vide",
        (tmp / "journal.jsonl").is_file()
        and len((tmp / "journal.jsonl").read_text(encoding="utf-8").strip().splitlines()) >= 4)
    try:
        ex.executer(t1)
        cas("ré-exécution d'une tâche terminée → ErreurTache", False, "acceptée")
    except ErreurTache:
        cas("ré-exécution d'une tâche terminée → ErreurTache", True)

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
