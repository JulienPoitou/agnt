#!/usr/bin/env python3
"""Observabilité : le journal append-only répond au « pourquoi ».

Ce que la commande du 2026-08-30 demande au cœur :

    « Chaque étape importante doit pouvoir être comprise après coup. […] pourquoi
      cette capacité ? pourquoi ce provider ? pourquoi ce provider n'a pas été
      sélectionné ? […] Privilégier des événements structurés et exploitables. »

Avant ce lot, deux réponses manquaient au journal (elles n'existaient que dans
`plan.json`, un artefact qu'on n'ouvre qu'après coup) :

    · pourquoi CETTE capacité — le motif du matching d'intention (le mot-clé qui a
      matché) n'était pas consigné, même pour un arrêt ;
    · pourquoi CE provider et pas l'autre — le motif de sélection (priorité déclarée,
      fan_out, choix imposé) n'était pas consigné avec l'événement `plan`.

Ce que cette batterie mesure :

  1. l'événement `intention` est consigné pour TOUS les états (résolu, clarification,
     refus), avec le motif du matching et le moteur qui a tranché ;
  2. l'événement `plan` porte la `selection` complète : choisis, écartés, motif.

Aucun `opa` ni `bwrap` n'est requis pour les cas 1 : les arrêts d'intention
(`needs_clarification`, `rejected`) précèdent la policy. Le cas du plan résolu est joué
jusqu'au point où OPA est consulté — l'événement `plan`, lui, est déjà écrit.

Usage : python3 PHASE3/test_observabilite.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import mission as MS                 # noqa: E402
import pipeline                      # noqa: E402
import adapters as AD                # noqa: E402 — seam « disponibilité » (alignement PR #2)

CIBLE = RACINE / "testrepo"

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def lignes(typ: str) -> list[dict]:
    return [l for l in MS.journal(_mission) if l.get("type") == typ]


def main() -> int:
    global _mission
    print("=== OBSERVABILITÉ : LE JOURNAL RÉPOND AU POURQUOI ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="agnt-observ-"))
    try:
        MS.MISSIONS = tmp / "missions"
        MS.MISSIONS.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------ 1. intention, tous les états
        print("--- 1. la décision d'intention est consignée pour tous les états ---")
        e = pipeline.executer("un truc", CIBLE)               # needs_clarification
        _mission = MS.relire(e.mission)
        ev = lignes("intention")
        cas("1. une clarification consigne l'intention",
            len(ev) == 1 and ev[0]["statut"] == "needs_clarification"
            and "moteur" in ev[0] and "motifs" in ev[0],
            ev[0] if ev else "aucun événement")
        # L'événement porte le MOTEUR qui a tranché : c'est ce qui distingue un repli
        # déterministe d'un LLM, après coup, sans rouvrir le code.
        cas("1b. l'événement dit QUI a tranché (moteur)",
            ev[0].get("moteur") == "deterministe", f"moteur={ev[0].get('moteur')!r}")

        e2 = pipeline.executer("Attaque le serveur de mon concurrent", CIBLE)   # rejected
        _mission = MS.relire(e2.mission)
        ev2 = lignes("intention")
        cas("1c. un refus consigne l'intention avec son motif",
            len(ev2) == 1 and ev2[0]["statut"] == "rejected"
            and "interdite" in str(ev2[0].get("motif", "")),
            f"statut={ev2[0].get('statut')!r} · motif={ev2[0].get('motif')!r}")

        # ------------------------------------------------ 2. sélection dans le plan
        print("\n--- 2. l'événement plan porte la sélection et son motif ---")
        # Alignement d'intégration (étape 1bis « disponibilité », PR #2) : sur une machine
        # sans outils installés, la disponibilité écarte TOUS les providers avant le plan,
        # et ce que ce cas mesure (l'événement `plan` et sa sélection) ne serait jamais
        # écrit. La disponibilité est neutralisée ici comme le serait une machine après
        # bootstrap.sh — AUCUNE attente n'est modifiée, seule l'entrée de la scène change.
        _exe_de = AD.exe_de
        AD.exe_de = lambda p: "/bin/true"
        try:
            pipeline.executer("Analyse la sécurité de mon dépôt", CIBLE)
        except Exception:
            # OPA absent ici : le plan est consigné AVANT la policy, donc l'événement
            # existe quand même — c'est exactement le point mesuré.
            pass
        finally:
            AD.exe_de = _exe_de
        # Retrouver la mission de ce dernier run : c'est la plus récente de la liste.
        der = sorted(MS.MISSIONS.iterdir(), key=lambda p: p.stat().st_mtime_ns)[-1]
        _mission = MS.Mission(der.name, der)
        plan_ev = lignes("plan")
        cas("2. le plan est consigné",
            len(plan_ev) == 1 and plan_ev[0]["providers"],
            f"providers={plan_ev[0].get('providers') if plan_ev else []}")
        sel = (plan_ev[0] or {}).get("selection") or {}
        # Les entrées de SÉLECTION sont les capacités (elles portent `choisis`/`motif`) ;
        # `applicabilite` et `conditions` sont les exclusions, de forme différente.
        capacites = {k: v for k, v in sel.items()
                     if isinstance(v, dict) and "motif" in v and "choisis" in v}
        cas("2b. la sélection nomme un motif par capacité (priorité, fan_out, imposé)",
            bool(capacites) and all(str(v.get("motif") or "").strip() for v in capacites.values()),
            {k: v.get("motif") for k, v in capacites.items()})
        # Le motif doit répondre à « pourquoi pas l'autre » : pour une capacité à un seul
        # provider, il le dit ; pour plusieurs, il nomme les écartés.
        cas("2c. le motif répond à « pourquoi pas l'autre » (écartés nommés ou choix unique)",
            all(("seul provider" in str(v.get("motif", "")).lower())
                or ("écartés" in str(v.get("motif", "")).lower())
                or ("fan_out" in str(v.get("motif", "")).lower())
                or ("imposé" in str(v.get("motif", "")).lower())
                for v in capacites.values()),
            {k: v.get("motif") for k, v in capacites.items()})

        # ------------------------------------------------ 3. pas de fuite d'outil
        print("\n--- 3. le journal d'intention ne fuit aucun nom d'outil ---")
        # On relit le journal du cas 2 : les motifs d'intention ne doivent pas nommer
        # semgrep/trivy/gitleaks — le moteur d'intention ne les connaît pas.
        _mission = MS.Mission(der.name, der)
        iv = lignes("intention")
        brut = str(iv)
        cas("3. les événements d'intention ne contiennent aucun nom d'outil",
            not any(t in brut.lower() for t in ("semgrep", "trivy", "gitleaks", "bandit")),
            "aucun nom d'outil dans les événements d'intention")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
    sys.exit(1 if ECHECS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
