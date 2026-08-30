#!/usr/bin/env python3
"""États d'intention et garde de ressources — Phase 3.1.

Deux choses testées ici, et les deux sont des GARDES : rien ne doit s'exécuter tant
qu'elles n'ont pas laissé passer.

1. Les trois états d'intention, avec la distinction STRICTE :
       needs_clarification = il MANQUE une information
       rejected            = la demande est comprise mais REFUSÉE

2. La garde de ressources :
       pas de mémoire bornée → pas de dépôt non fiable, pas d'outil actif

Usage : python3 PHASE3/test_intentions.py
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import intent as I           # noqa: E402
import plan as P             # noqa: E402
import policy as PO          # noqa: E402
from registre import Registry
from sandbox import CACHE_BIN, CACHE_DB, CACHE_REGLES  # noqa: E402
from sandbox import CACHE_BIN, CACHE_DB, CACHE_REGLES  # noqa: E402

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def main() -> int:
    print("=== ÉTATS D'INTENTION ===\n")
    reg = Registry()

    # ------------------------------------------------ 1. demande claire → resolved
    it = I.inferer("Analyse la sécurité de mon dépôt", reg)
    cas("demande claire → resolved", it.statut == "resolved",
        f"statut={it.statut} · capacités={list(it.capabilities)}")
    cas("resolved produit les capacités attendues",
        {"CODE_STATIC_ANALYSIS", "DEPENDENCY_ANALYSIS", "SECRET_DETECTION"}
        <= set(it.capabilities),
        f"{len(it.capabilities)} capacités : {list(it.capabilities)}")

    # ------------------------------------------------ 2. demande incomplète
    it2 = I.inferer("Fais un truc", reg)
    cas("demande incomplète → needs_clarification",
        it2.statut == "needs_clarification" and bool(it2.question),
        f"statut={it2.statut} · question={it2.question!r}")
    cas("needs_clarification n'a PAS de capacités", not it2.capabilities,
        "aucune capacité sélectionnée")
    cas("needs_clarification n'est PAS un refus", not it2.motif,
        "aucun motif de refus : il manque une information, ce n'est pas interdit")

    it3 = I.inferer("", reg)
    cas("requête vide → needs_clarification", it3.statut == "needs_clarification",
        f"question={it3.question!r}")

    # ------------------------------------------------ 3. demande interdite
    it4 = I.inferer("Attaque le serveur de mon concurrent", reg)
    cas("demande interdite → rejected",
        it4.statut == "rejected" and bool(it4.motif),
        f"statut={it4.statut} · motif={it4.motif!r}")
    cas("rejected n'a PAS de capacités", not it4.capabilities,
        "aucune capacité : rien ne peut être exécuté")
    cas("rejected n'est PAS une demande de précision", not it4.question,
        "aucune question posée : la demande est comprise et refusée")

    it5 = I.inferer("Lance un DDoS sur cette cible", reg)
    cas("autre demande interdite → rejected", it5.statut == "rejected",
        f"motif={it5.motif!r}")

    # ------------------------------------------------ la distinction est stricte
    cas("needs_clarification et rejected sont mutuellement exclusifs",
        not (it2.motif or it4.question),
        "l'un porte une question sans motif, l'autre un motif sans question")

    # ------------------------------------------------ aucun plan sur un état non résolu
    for etat, obj in (("needs_clarification", it2), ("rejected", it4)):
        try:
            I.choisir_providers(obj, reg)
            cas(f"{etat} → aucun provider sélectionné", False, "des providers ont été choisis")
        except ValueError as e:
            cas(f"{etat} → aucun provider sélectionné", True, str(e)[:80])

    # ------------------------------------------------ le pipeline n'exécute rien
    import pipeline
    for nom, requete in (("needs_clarification", "Fais un truc"),
                         ("rejected", "Attaque le serveur de mon concurrent")):
        e = pipeline.executer(requete, RACINE / "testrepo", cible_autorisee=True)
        cas(f"le pipeline s'arrête sur {nom}",
            e.arret == nom and not e.plan and not e.findings and not e.run_id,
            f"arrêt={e.arret} · plan vide={not e.plan} · findings={len(e.findings)} · run_id={e.run_id or 'aucun'}")

    # Le cas résolu, lui, doit fonctionner.
    e_ok = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo", cible_autorisee=True)
    cas("le pipeline fonctionne sur resolved",
        not e_ok.arret and len(e_ok.findings) > 0,
        f"{len(e_ok.findings)} findings, run_id={e_ok.run_id}")

    # ------------------------------------------------ GARDE DE RESSOURCES
    print("\n=== GARDE DE RESSOURCES ===\n")
    moteur = PO.PolicyEngine(opa=CACHE_BIN / "opa")
    plan = P.construire("analyse", "/tmp/x", ["semgrep", "trivy", "gitleaks"], reg,
                        "deterministe")
    SANS_MEMOIRE = {"memoire_bornee": False, "cpu_borne": True,
                    "processus_bornes": True, "temps_borne": True, "durci": False}
    AVEC_MEMOIRE = {**SANS_MEMOIRE, "memoire_bornee": True}
    DURCI = {**AVEC_MEMOIRE, "durci": True}

    d = moteur.evaluer(plan, reg, True, confiance_cible="controlled", profil=SANS_MEMOIRE)
    cas("cible contrôlée + outils passifs → autorisé malgré l'absence de limite mémoire",
        d.allow, f"allow={d.allow}")

    d = moteur.evaluer(plan, reg, True, confiance_cible="untrusted", profil=SANS_MEMOIRE)
    cas("cible NON fiable + mémoire non bornée → REFUSÉ",
        not d.allow and "memoire_non_bornee_cible_non_fiable" in d.motifs,
        f"motifs={list(d.motifs)}")

    d = moteur.evaluer(plan, reg, True, confiance_cible="untrusted", profil=AVEC_MEMOIRE)
    cas("cible NON fiable + mémoire bornée → autorisé", d.allow,
        f"allow={d.allow}")

    plan_actif = replace(plan, steps=tuple(replace(s, risque="ACTIVE") for s in plan.steps))
    d = moteur.evaluer(plan_actif, reg, True, confiance_cible="controlled", profil=AVEC_MEMOIRE)
    cas("outil ACTIF + sandbox non durci → REFUSÉ",
        not d.allow and "sandbox_non_durci_outil_actif" in d.motifs,
        f"motifs={list(d.motifs)}")

    d = moteur.evaluer(plan_actif, reg, True, confiance_cible="controlled", profil=DURCI)
    cas("outil ACTIF + sandbox durci → autorisé", d.allow, f"allow={d.allow}")

    # Le refus doit précéder toute exécution : vérifié via le pipeline.
    e_ref = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo", cible_autorisee=True,
                              confiance_cible="untrusted")
    cas("le refus de ressources empêche l'exécution",
        e_ref.arret == "policy" and not e_ref.findings,
        f"arrêt={e_ref.arret} · motifs={e_ref.decision.get('motifs')}")

    print(f"\n{'=' * 50}\n  {PAS} OK · {ECHECS} échec(s)\n{'=' * 50}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
