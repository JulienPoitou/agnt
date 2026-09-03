"""Orchestrateur minimal : graphe de tâches → exécution séquencée (Stream F).

Pas de multi-agent, pas de parallélisme spéculatif : un graphe de
dépendances trié (cycles refusés), exécution séquentielle dans l'ordre du
plan, retry borné sur timeout uniquement, propagation d'échec avec motif,
annulation coopérative, stop conditions (max_taches, stop_on_failure).

L'exécuteur est INJECTÉ (`executer(tache) -> Tache`) : `ExecuteurLocal` en
prod, faux en tests. L'orchestrateur ne connaît aucun outil.
"""
from __future__ import annotations

from taches import ANNULEE, ECHOUEE, EN_FILE, TERMINEE, Tache


class ErreurOrchestration(Exception):
    """Plan inexécutable : cycle, dépendance manquante, budget."""


def ordonner(noeuds: list[dict]) -> list[dict]:
    """Tri topologique stable (ordre d'entrée préservé). Nœud :
    {"id": str, "depend_de": [ids]}. Cycle ou référence inconnue → refus nommé.
    """
    ids = [n.get("id") for n in noeuds]
    if len(set(ids)) != len(ids) or any(not i for i in ids):
        raise ErreurOrchestration("ids de tâches dupliqués ou vides")
    par_id = {n["id"]: n for n in noeuds}
    for n in noeuds:
        for d in n.get("depend_de") or []:
            if d not in par_id:
                raise ErreurOrchestration(f"dépendance inconnue : {d!r} (tâche {n['id']!r})")
    visites: dict[str, str] = {}
    ordre: list[dict] = []

    def visite(nid: str, pile: tuple) -> None:
        etat = visites.get(nid)
        if etat == "fini":
            return
        if etat == "cours":
            raise ErreurOrchestration(
                f"cycle détecté : {' → '.join((*pile, nid))}")
        visites[nid] = "cours"
        for d in par_id[nid].get("depend_de") or []:
            visite(d, (*pile, nid))
        visites[nid] = "fini"
        ordre.append(par_id[nid])

    for n in noeuds:
        visite(n["id"], ())
    return ordre


def executer_plan(noeuds: list[dict], executer_tache, *,
                 stop_on_failure: bool = True, max_taches: int = 64,
                 retry_timeout: int = 1) -> dict:
    """Exécute le graphe ordonné. `executer_tache(tache) -> Tache` (injecté).

    Rend {"statut": termine|arrete|annule, "taches": [...], "motif": ...}.
    Une tâche non-démarrée reste EN_FILE : l'état dit ce qui a VRAIMENT tourné.
    """
    try:
        ordre = ordonner(noeuds)
    except ErreurOrchestration as e:
        return {"statut": "refuse", "taches": [], "motif": str(e)}
    if len(ordre) > max_taches:
        return {"statut": "refuse", "taches": [],
                "motif": f"budget : {len(ordre)} tâches > max {max_taches}"}
    resultats: list[dict] = []
    for n in ordre:
        tache: Tache = n["tache"]
        essais = 0
        while True:
            tache = executer_tache(tache)
            essais += 1
            res = tache.resultat
            if (tache.etat == ECHOUEE and res is not None and res.timeout
                    and essais <= retry_timeout):
                # Nouvelle tentative = nouvel objet (chaque exécution a son
                # enregistrement) ; la traçabilité vit au niveau du nœud.
                tache = Tache(provider_id=tache.provider_id, argv=tache.argv,
                              env=tache.env, timeout_s=tache.timeout_s)
                n["tache"] = tache
                continue
            break
        resultats.append({"id": n["id"], "provider": tache.provider_id,
                          "etat": tache.etat,
                          "resultat": tache.resultat.to_dict() if tache.resultat else None})
        if tache.etat == ANNULEE:
            return {"statut": "annule", "taches": resultats,
                    "motif": f"annulation après {n['id']}"}
        if tache.etat != TERMINEE and stop_on_failure:
            return {"statut": "arrete", "taches": resultats,
                    "motif": f"échec {n['id']} ({tache.etat}) : "
                             f"{(tache.resultat.erreur if tache.resultat else '')[:120]}"}
    # EN_FILE restant = jamais démarré (ne peut arriver qu'après annulation/arrêt,
    # déjà retournés ci-dessus) — statut termine honnête seulement si tout a tourné.
    return {"statut": "termine", "taches": resultats, "motif": ""}
