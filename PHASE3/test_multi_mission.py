#!/usr/bin/env python3
"""Multi-mission : le choix du moteur d'intention n'est plus un état global.

Ce que la commande du 2026-08-30 demande au cœur, et ce que cette batterie mesure :

    « le moteur doit pouvoir évoluer au-delà du modèle une mission / un processus /
      un état global. Deux missions doivent pouvoir exister sans se contaminer. »

Le levier mesuré ici est précis : avant ce lot, `pipeline.executer()` lisait son moteur
d'intention dans deux globales de module (`MOTEUR_INTENT`, `FOURNISSEUR_LLM`) que
`analyser.lancer()` et `analyser.main()` MUTAIENT avec un save/restore. Une mission
concurrente lisait donc le moteur d'une autre — et le restore lui-même n'était sûr
qu'en absence de concurrence.

Ce qui est exigé, et seulement ça :

  1. `executer()` accepte `moteur_intent` / `fournisseur_llm` en paramètres, et les
     utilise — sans lire ni écrire les globales.
  2. `analyser.lancer()` transmet le moteur en paramètre et NE MUTE PLUS les globales.
  3. Deux missions entrelacées, avec des moteurs différents, gardent chacune le sien.
  4. Compatibilité ascendante : un appelant qui pose encore les globales continue de
     fonctionner (repli de dernier recours).

Pourquoi ce trajet n'exige ni `opa` ni `bwrap` : on passe par les arrêts PRÉCÉDANT la
policy — `needs_clarification`. Un fournisseur faux qui répond « clarification » sur une
phrase que le moteur déterministe RÉSOUDRAIT prouve, sans OPA, que c'est bien le
paramètre qui a tranché (le déterministe aurait continué jusqu'à OPA).

Usage : python3 PHASE3/test_multi_mission.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import threading
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import analyser                      # noqa: E402
import intent_llm as IL              # noqa: E402
import mission as MS                 # noqa: E402
import pipeline                      # noqa: E402

CIBLE = RACINE / "testrepo"

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


class FauxFournisseur:
    """Un fournisseur qui répond TOUJOURS `needs_clarification` avec une question à lui.

    La question est l'empreinte du fournisseur : si une mission en reçoit une autre,
    c'est qu'un état partagé a fuité entre deux appels.
    """

    def __init__(self, question: str):
        self.question = question
        self.appels = 0

    def complet(self, phrase, description):
        self.appels += 1
        return IL.ReponseLLM("needs_clarification", question=self.question,
                             brut=phrase, fournisseur="faux")


def isole(tmp: Path) -> None:
    """Détourne les missions vers un répertoire jetable : aucun journal ne pollue le dépôt."""
    tmp = Path(tmp)
    MS.MISSIONS = tmp / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)


def main() -> int:
    print("=== MULTI-MISSION : LE MOTEUR D'INTENTION N'EST PLUS UN ÉTAT GLOBAL ===\n")

    # ---------------------------------------------------------------- 1. paramètres honorés
    print("--- 1. executer() utilise le moteur passé en paramètre ---")
    tmp = tempfile.mkdtemp(prefix="agnt-multi-")
    isole(tmp)
    # Le déterministe RÉSOUDRAIT « Analyse la sécurité de mon dépôt » (demande générique) et
    # continuerait jusqu'à OPA. Le faux fournisseur répond « clarification » : si le paramètre
    # est honoré, l'exécution s'arrête en needs_clarification avec SA question.
    fake = FauxFournisseur("question-du-faux-fournisseur")
    e = pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE,
                          moteur_intent="llm", fournisseur_llm=fake)
    cas("1. le moteur passé en paramètre a tranché, pas le déterministe",
        e.arret == "needs_clarification" and e.intent.get("moteur") == "llm:faux",
        f"arret={e.arret} · moteur={e.intent.get('moteur')}")
    cas("1b. la question rendue est celle du fournisseur passé en paramètre",
        e.intent.get("question") == "question-du-faux-fournisseur",
        f"question={e.intent.get('question')!r}")
    cas("1c. le fournisseur a bien été appelé",
        fake.appels == 1, f"appels={fake.appels}")

    # ------------------------------------------------- 2. aucune mutation des globales
    print("\n--- 2. executer() ne touche pas aux globales de module ---")
    pipeline.MOTEUR_INTENT = "deterministe"
    pipeline.FOURNISSEUR_LLM = None
    e2 = pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE,
                           moteur_intent="llm", fournisseur_llm=FauxFournisseur("q2"))
    cas("2. les globales ne sont pas mutées par un appel paramétré",
        pipeline.MOTEUR_INTENT == "deterministe" and pipeline.FOURNISSEUR_LLM is None,
        f"MOTEUR_INTENT={pipeline.MOTEUR_INTENT!r} · FOURNISSEUR_LLM={pipeline.FOURNISSEUR_LLM!r}")
    cas("2b. l'appel a pourtant bien utilisé le moteur llm",
        e2.arret == "needs_clarification" and (e2.intent.get("moteur") or "").startswith("llm"),
        f"moteur={e2.intent.get('moteur')}")

    # --------------------------------------------- 3. analyser.lancer ne mute plus non plus
    print("\n--- 3. analyser.lancer() transmet sans muter ---")
    pipeline.MOTEUR_INTENT = "deterministe"
    pipeline.FOURNISSEUR_LLM = None
    code, resume = analyser.lancer("un truc", CIBLE, moteur="llm",
                                   fournisseur=FauxFournisseur("question-lancer"))
    cas("3. lancer() a transmis le moteur llm au pipeline",
        (resume.get("moteur") or "").startswith("llm"), f"moteur={resume.get('moteur')!r}")
    cas("3b. lancer() n'a pas posé le moteur sur les globales",
        pipeline.MOTEUR_INTENT == "deterministe" and pipeline.FOURNISSEUR_LLM is None,
        f"MOTEUR_INTENT={pipeline.MOTEUR_INTENT!r} · FOURNISSEUR_LLM={pipeline.FOURNISSEUR_LLM!r}")
    cas("3c. la clarification est un refus propre, pas une panne",
        code == 2 and resume.get("statut") == "needs_clarification",
        f"code={code} · statut={resume.get('statut')!r}")

    # --------------------------------------------- 4. entrelacement concurrent
    print("\n--- 4. deux missions concurrentes gardent chacune leur moteur ---")
    questions = {f"faux-{i}": f"question-propre-{i}" for i in range(8)}
    resultats: dict = {}
    erreurs: list = []
    verrou = threading.Lock()

    def mission(nom: str) -> None:
        try:
            # La requête EST le nom du faux : elle garantit que le déterministe ne pourrait
            # pas être confondu avec le llm (elle résoudrait génériquement).
            f = FauxFournisseur(questions[nom])
            r = pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE,
                                  moteur_intent="llm", fournisseur_llm=f)
            with verrou:
                resultats[nom] = (r.arret, r.intent.get("question"), r.intent.get("moteur"))
        except Exception as exc:                       # noqa: BLE001
            with verrou:
                erreurs.append((nom, repr(exc)))

    fils = [threading.Thread(target=mission, args=(n,)) for n in questions]
    [t.start() for t in fils]
    [t.join(timeout=120) for t in fils]
    cas("4. aucune des huit missions concurrentes n'a levé",
        not erreurs, erreurs[:2])
    cas("4b. chaque mission a reçu la question de SON fournisseur",
        all(arret == "needs_clarification" and question == questions[nom]
            and (moteur or "").startswith("llm")
            for nom, (arret, question, moteur) in resultats.items()),
        {nom: r for nom, r in sorted(resultats.items())})

    # --------------------------------------------- 5. compatibilité ascendante (repli)
    print("\n--- 5. repli historique : les globales restent lisibles ---")
    fake_legacy = FauxFournisseur("question-legacy")
    pipeline.MOTEUR_INTENT = "llm"
    pipeline.FOURNISSEUR_LLM = fake_legacy
    try:
        e5 = pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE)
    finally:
        pipeline.MOTEUR_INTENT = "deterministe"
        pipeline.FOURNISSEUR_LLM = None
    cas("5. sans paramètre, executer() retombe sur les globales (appelant historique)",
        e5.arret == "needs_clarification" and e5.intent.get("question") == "question-legacy",
        f"question={e5.intent.get('question')!r}")
    shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
    sys.exit(1 if ECHECS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
