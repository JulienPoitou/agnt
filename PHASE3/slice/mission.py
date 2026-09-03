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


def ouvrir(requete: str, requete_canonique: str, cible, cible_descr: dict | None = None) -> Mission:
    MISSIONS.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc)
    # 02/09/2026 (revue adverse, famille C) — le masque du userinfo d'URL est posé ICI,
    # à l'écriture, et pas seulement à l'affichage : une requête collée par l'opérateur
    # (« scan https://u:p@site ») ne doit pas survivre en clair dans `mission.json`, le
    # journal d'ouverture, ni le rapport. Les chemins locaux, eux, traversent intacts
    # (`nettoie_url` ne touche que la forme `schéma://…@…`). `requete_canonique` est
    # passé par l'appelant déjà dérivé de la requête — il est masqué pareil, sinon le
    # champ canonique redeviendrait un canal de reconstitution.
    from assainissement import nettoie_url
    requete = nettoie_url(requete)
    requete_canonique = nettoie_url(requete_canonique)
    reference = nettoie_url(str(cible))
    graine = f"{reference}|{requete}|{ts.isoformat()}"
    mid = f"m-{ts.strftime('%Y%m%dT%H%M%SZ')}-{hashlib.sha256(graine.encode()).hexdigest()[:8]}"
    chemin = MISSIONS / mid
    chemin.mkdir(parents=True)
    # L'en-tête décrit la cible. Deux formes, jamais mélangées :
    #   · `descripteur` : la forme STRUCTURÉE (type, référence sûre, local, chemin) —
    #     posée quand l'appelant détient le descripteur canonique (le pipeline) ;
    #   · `type` legacy (« repertoire »/« fichier »/« absent ») : l'inférence
    #     historique, conservée quand on n'a qu'un Path (appels et tests antérieurs).
    cible_entete: dict = {"chemin": reference}
    if cible_descr:
        cible_entete["descripteur"] = dict(cible_descr)
    else:
        chemin_local = cible if isinstance(cible, Path) else None
        cible_entete["type"] = (
            "repertoire" if chemin_local is not None and chemin_local.is_dir()
            else "fichier" if chemin_local is not None and chemin_local.is_file()
            else "absent")
    entete = {
        "mission_id": mid,
        "cree_le": ts.isoformat(timespec="seconds"),
        "requete": requete,
        "requete_canonique": requete_canonique,
        "cible": cible_entete,
        "format_journal": "journal.jsonl — append-only, une ligne par événement",
    }
    (chemin / "mission.json").write_text(
        json.dumps(entete, ensure_ascii=False, indent=2), encoding="utf-8")
    m = Mission(mid, chemin)
    consigner(m, "ouverture", requete=requete, cible=reference)
    return m


# Verrou de journal. Un verrou, pas une chance. Depuis la vague parallèle (LOT 3), deux outils
# peuvent consigner en même temps ; sans lui, deux threads calculent le même `seq` sur la même
# longueur de fichier (deux événements au même rang : un rejeu ne rechiffre plus pareil) et,
# pire, deux écritures peuvent s'entrelacer au milieu d'une ligne. Un journal append-only dont
# une ligne est cassée n'est plus une preuve, c'est un fichier de debug.
_VERROU = __import__("threading").Lock()


def consigner(m: Mission, type_: str, **payload) -> int:
    """Ajoute un événement. Append strict : ouverture en mode 'a', jamais 'w'.

    `seq` et l'écriture sont dans la même section critique : un lecteur qui voit `seq: 7` a la
    garantie qu'aucun autre événement de ce journal ne portera ce rang, et qu'aucun rang ne manque.
    """
    j = m.chemin / "journal.jsonl"
    with _VERROU:
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
