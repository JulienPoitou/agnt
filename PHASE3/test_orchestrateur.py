#!/usr/bin/env python3
"""Orchestrateur : ordre, cycles, propagation, retry timeout, annulation, budgets.

Usage : python PHASE3/test_orchestrateur.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import taches as TA                                                 # noqa: E402
from orchestrateur import ErreurOrchestration, executer_plan, ordonner  # noqa: E402

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def noeud(i, depend=(), etat_final=TA.TERMINEE, code=0, texte="", timeout=False):
    return {"id": i, "depend_de": list(depend), "_fin": (etat_final, code, texte, timeout)}


def faux(spec):
    appels: dict[str, int] = {}

    def executer(t: TA.Tache) -> TA.Tache:
        seq = spec[t.provider_id]
        i = appels.get(t.provider_id, 0)
        appels[t.provider_id] = i + 1
        etat_final, code, texte, timeout = seq[i] if isinstance(seq, list) else seq
        t.etat = TA.EN_COURS
        t.tentatives += 1
        if timeout:
            t.etat = TA.ECHOUEE
            t.resultat = TA.ResultatExecution(code, "", "", 0.1, timeout=True,
                                              erreur="timeout_apres_30")
        else:
            t.etat = etat_final
            t.resultat = TA.ResultatExecution(code, texte, "", 0.1)
        t.fin = t.debut + 0.1
        return t
    return executer


def T(pid):
    return TA.Tache(provider_id=pid, argv=["/bin/vrai", pid], timeout_s=30)


def main() -> int:
    cas("ordre respecte les dépendances",
        [n["id"] for n in ordonner([noeud("c", ["b"]), noeud("a"), noeud("b", ["a"])])]
        == ["a", "b", "c"])
    try:
        ordonner([noeud("a", ["b"]), noeud("b", ["a"])])
        cas("cycle → refus nommé", False, "accepté")
    except ErreurOrchestration as e:
        cas("cycle → refus nommé", "cycle" in str(e), str(e)[:80])
    try:
        ordonner([noeud("a", ["fantome"])])
        cas("dépendance inconnue → refus", False, "acceptée")
    except ErreurOrchestration:
        cas("dépendance inconnue → refus", True)
    try:
        ordonner([noeud("a"), noeud("a")])
        cas("id dupliqué → refus", False, "accepté")
    except ErreurOrchestration:
        cas("id dupliqué → refus", True)
    r = executer_plan([{**noeud("a"), "tache": T("pa")}, {**noeud("b", ["a"]), "tache": T("pb")}],
                      faux({"pa": (TA.TERMINEE, 0, "ok", False),
                            "pb": (TA.TERMINEE, 0, "ok", False)}))
    cas("chaîne ok → termine, ordre d'exécution",
        r["statut"] == "termine" and [t["id"] for t in r["taches"]] == ["a", "b"],
        r["statut"])
    r = executer_plan([{**noeud("a"), "tache": T("pa")}, {**noeud("b", ["a"]), "tache": T("pb")}],
                      faux({"pa": (TA.ECHOUEE, 1, "", False)}))
    cas("échec → arrêté, b jamais démarrée",
        r["statut"] == "arrete" and len(r["taches"]) == 1 and "a" in r["motif"],
        r["motif"][:100])
    r = executer_plan([{**noeud("a"), "tache": T("pa")}],
                      faux({"pa": [(TA.ECHOUEE, 1, "", True),
                                   (TA.TERMINEE, 0, "ok", False)]}),
                      retry_timeout=1)
    cas("timeout → 1 retry puis termine",
        r["statut"] == "termine" and len(r["taches"]) == 1, r["statut"])
    r = executer_plan([{**noeud("a"), "tache": T("pa")}],
                      faux({"pa": (TA.ANNULEE, None, "", False)}))
    cas("annulation → statut annule nommé",
        r["statut"] == "annule" and "annulation" in r["motif"], r["motif"][:80])
    r = executer_plan([{**noeud(f"t{i}"), "tache": T(f"p{i}")} for i in range(5)],
                      faux({f"p{i}": (TA.TERMINEE, 0, "", False) for i in range(5)}),
                      max_taches=3)
    cas("budget dépassé → refusé avant exécution",
        r["statut"] == "refuse" and r["taches"] == [] and "budget" in r["motif"],
        r["motif"][:80])

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
