#!/usr/bin/env python3
"""Isolation des exécutions : plus de répertoire de sortie global partagé.

Ce que la commande du 2026-08-30 demande au cœur :

    « deux missions doivent pouvoir exister sans se contaminer. […] répertoires
      partagés, ressources non isolées. »

Avant ce lot, `pipeline.executer()` écrivait ses `raw_*`/`brut_*` dans un répertoire
GLOBAL (`PHASE3/run`) VIDÉ au début de chaque exécution (`_prepare_sortie`). Deux
missions concurrentes se réécrivaient donc l'une l'autre, et une mission effaçait les
preuves brutes de la précédente. Ce que cette batterie mesure :

  1. le répertoire de travail est PAR MISSION (`<mission>/run`), créé une fois, jamais vidé ;
  2. deux missions obtiennent deux répertoires distincts ;
  3. le pipeline n'expose plus le chemin global (`pipeline.SORTIE` a disparu) ;
  4. `analyser._archiver_mission` copie les preuves depuis la sortie de la mission
     (`e.sortie`), plus depuis un chemin global ;
  5. une exécution arrêtée avant l'étape d'exécution n'alloue pas de répertoire.

Aucun `opa` ni `bwrap` n'est requis : les cas jouent la frontière d'isolation elle-même
(création de répertoires, archivage), pas la cage.

Usage : python3 PHASE3/test_isolation_mission.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import analyser                      # noqa: E402
import mission as MS                 # noqa: E402
import pipeline                      # noqa: E402

CIBLE = RACINE / "testrepo"

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def isole(tmp: Path) -> Path:
    """Détourne les missions vers un répertoire jetable, et le retourne."""
    tmp = Path(tmp)
    MS.MISSIONS = tmp / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)
    return MS.MISSIONS


def main() -> int:
    print("=== ISOLATION : LE RÉPERTOIRE DE TRAVAIL EST PAR MISSION ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="agnt-isolation-"))
    try:
        isole(tmp)
        # ------------------------------------------------------ 1. par mission, jamais vidé
        print("--- 1. un répertoire de travail par mission, créé sans vider ---")
        m1 = MS.ouvrir("mission une", "mission une", CIBLE)
        m2 = MS.ouvrir("mission deux", "mission deux", CIBLE)
        s1 = pipeline._sortie_mission(m1)
        s2 = pipeline._sortie_mission(m2)
        cas("1. le répertoire de travail est sous la mission, nommé run/",
            s1 == m1.chemin / "run" and s2 == m2.chemin / "run",
            f"{s1.name} · {s2.name}")
        cas("1b. deux missions → deux répertoires distincts",
            s1 != s2 and s1.exists() and s2.exists(),
            f"{s1} vs {s2}")
        # Un artefact posé par la mission 1 ne doit pas être effacé par un second appel sur
        # la mission 1 (plus de `_prepare_sortie` qui vidait le répertoire à chaque entrée).
        (s1 / "raw_preuve.json").write_text("{\"x\": 1}", encoding="utf-8")
        s1_bis = pipeline._sortie_mission(m1)
        cas("1c. rappeler la sortie d'une mission ne vide pas ses artefacts",
            s1_bis == s1 and (s1 / "raw_preuve.json").exists(),
            "le contenu posé avant le second appel est toujours là")

        # ------------------------------------------------------ 2. plus de chemin global
        print("\n--- 2. le chemin global a disparu du pipeline ---")
        cas("2. pipeline n'expose plus SORTIE (le répertoire partagé est supprimé)",
            not hasattr(pipeline, "SORTIE"),
            "hasattr(pipeline, 'SORTIE') = False attendu")
        cas("2b. pipeline n'expose plus _prepare_sortie (le vidage global est supprimé)",
            not hasattr(pipeline, "_prepare_sortie"),
            "hasattr(pipeline, '_prepare_sortie') = False attendu")

        # ------------------------------------------------------ 3. archivage depuis e.sortie
        print("\n--- 3. l'archive de mission se sert de la sortie de la mission ---")
        provisoire = Path(tempfile.mkdtemp(prefix="agnt-arch-"))
        (provisoire / "raw_fake.json").write_text("{\"results\": []}", encoding="utf-8")
        (provisoire / "brut_fake.json").write_text("[]", encoding="utf-8")
        e = pipeline.Execution(
            decision={"allow": False, "motifs": ["intent_needs_clarification"]},
            plan={"plan_id": "p-iso", "requete": "x", "requete_canonique": "x",
                  "cible": str(CIBLE)},
            intent={"statut": "needs_clarification", "question": "q", "moteur": "deterministe"},
            mission=m1.id,
            sortie=str(provisoire),
            arret="needs_clarification",
            contexte={"input_digest": "", "input_commit": "", "working_tree_dirty": False,
                      "contexte_empreinte": ""},
            chemin={},
        )
        sortie_archive = analyser._archiver_mission(e, CIBLE)
        cas("3. l'archive copie les raw/brut depuis e.sortie (pas depuis un chemin global)",
            sortie_archive is not None
            and (sortie_archive / "raw_fake.json").exists()
            and (sortie_archive / "brut_fake.json").exists(),
            f"contenu : {sorted(p.name for p in sortie_archive.iterdir())}")
        cas("3b. l'archive vit sous la mission, à côté du journal",
            sortie_archive.parent == m1.chemin and (m1.chemin / "journal.jsonl").exists(),
            str(sortie_archive))
        shutil.rmtree(provisoire, ignore_errors=True)

        # ------------------------------------------------------ 4. arrêt avant exécution
        print("\n--- 4. un arrêt avant exécution n'alloue pas de répertoire ---")
        e_arret = pipeline.executer("un truc", CIBLE)
        cas("4. une clarification s'arrête sans répertoire de travail",
            e_arret.arret == "needs_clarification" and e_arret.sortie == "",
            f"arret={e_arret.arret} · sortie={e_arret.sortie!r}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
    sys.exit(1 if ECHECS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
