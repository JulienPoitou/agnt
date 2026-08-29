"""Dossier de mission minimal — étape 2 de l'architecture gelée (2026-08-29).

Ce que c'est : un journal APPEND-ONLY qui trace une mission de bout en bout
(ouverture → contexte → plan → exécutions → clôture). Rien de plus : pas
d'hypothèses, pas d'itérations, pas de boucle d'investigation (étapes ultérieures).

Invariants (architecture gelée) :
  · le journal n'est JAMAIS réécrit — chaque événement est une ligne JSON
    ajoutée {seq, ts, type, ...} ; le préfixe du fichier est immuable ;
  · l'identifiant de mission est unique par instance (le rejeu déterministe
    passe par plan_id, pas par mission_id) ;
  · la cible est une DONNÉE, l'environnement un CONTEXTE — séparés dans les
    événements (leçon Contexte de run.py) ;
  · la mission ne décide rien : elle enregistre.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
MISSIONS = RACINE / "artifacts" / "missions"


@dataclass
class Mission:
    id: str
    chemin: Path


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ouvrir(requete: str, requete_canonique: str, cible: Path) -> Mission:
    MISSIONS.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc)
    graine = f"{cible}|{requete}|{ts.isoformat()}"
    mid = f"m-{ts.strftime('%Y%m%dT%H%M%SZ')}-{hashlib.sha256(graine.encode()).hexdigest()[:8]}"
    chemin = MISSIONS / mid
    chemin.mkdir(parents=True)
    entete = {
        "mission_id": mid,
        "cree_le": ts.isoformat(timespec="seconds"),
        "requete": requete,
        "requete_canonique": requete_canonique,
        "cible": {
            "chemin": str(cible),
            "type": ("repertoire" if cible.is_dir()
                     else "fichier" if cible.is_file() else "absent"),
        },
        "format_journal": "journal.jsonl — append-only, une ligne par événement",
    }
    (chemin / "mission.json").write_text(
        json.dumps(entete, ensure_ascii=False, indent=2), encoding="utf-8")
    m = Mission(mid, chemin)
    consigner(m, "ouverture", requete=requete, cible=str(cible))
    return m


def consigner(m: Mission, type_: str, **payload) -> int:
    """Ajoute un événement. Append strict : ouverture en mode 'a', jamais 'w'."""
    j = m.chemin / "journal.jsonl"
    seq = (sum(1 for _ in j.open(encoding="utf-8")) if j.exists() else 0) + 1
    ligne = {"seq": seq, "ts": _ts(), "type": type_, **payload}
    with j.open("a", encoding="utf-8") as f:
        f.write(json.dumps(ligne, ensure_ascii=False, default=str) + "\n")
    return seq


def relire(mission_id: str) -> Mission:
    chemin = MISSIONS / mission_id
    if not (chemin / "mission.json").is_file():
        raise KeyError(f"mission introuvable : {mission_id!r}")
    return Mission(mission_id, chemin)


def journal(m: Mission) -> list[dict]:
    p = m.chemin / "journal.jsonl"
    if not p.is_file():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l]
