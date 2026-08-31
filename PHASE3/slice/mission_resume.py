"""Mission Resume — la projection COMPACTE « console-ready » d'une mission.

Pourquoi ce module existe (2026-08-31, console V0) : pour afficher une mission,
la couche web devait jusqu'ici recoller elle-même la vérité à partir de plusieurs
artefacts partiels — `mission.json` pour la cible, le journal pour l'arrêt,
`rapport.json` pour le ledger, `findings.json` pour le compte, `plan.json` pour
les outils. Chaque écran qui recolle invente sa propre règle, et c'est là que
naissent les deux mensonges qu'on refuse : le faux zéro (« 0 finding » alors
qu'aucun outil n'a tourné) et le faux succès (« terminé » alors que l'exécution
a été refusée).

Ce module ne crée AUCUNE vérité nouvelle. Il ne fait que replier, en un seul
objet, les projections canoniques déjà livrées par `mission_history` :

    · `statut_mission`  → le statut (dérivé du journal, jamais saisi) ;
    · `_executions`     → un enregistrement `agnt.execution-status.v1` par
                          provider, ledger ou journal seul ;
    · `resumer`         → le `MissionSummary` du contrat History (dates, cible) ;
    · `_timeline`       → la projection sûre du journal.

Règles tenues, et elles sont le produit :

 1. AUCUN FAUX ZÉRO. `findings_count` ne vaut 0 que si DEUX preuves existent :
    un `findings.json` lisible et vide, ET au moins un provider dont la
    détection est prouvée (`rien_trouve` avec cibles analysées, ou
    `findings_presents`). Sans la seconde preuve, le compte est `None` et
    l'état dit pourquoi (`non_prouve`). Un artefact vide écrit par une mission
    où rien n'a tourné n'est pas un résultat : c'est un fichier vide.

 2. UNE SEULE VÉRITÉ. Aucun statut n'est recalculé ici : les états providers
    sont un REPLI du vocabulaire `execution-status.v1`, pas un second lexique.

 3. LES CAS TÔT INTERROMPUS SE LISENT. Indisponibilité, refus de politique,
    arrêt avant exécution, plan partiel, artefacts absents : chacun rend un
    objet complet, avec un motif nommé, jamais une exception ni un blanc.

 4. ADDITIF. Ce module n'écrit rien et ne modifie aucun lecteur existant.

Usage (côté CORE / futures routes) :

    import mission_resume
    resume = mission_resume.resumer_mission(mission_id)          # par id
    resume = mission_resume.resumer_dossier(chemin_de_mission)   # par dossier
"""

from __future__ import annotations

from pathlib import Path

import mission_history as MH

SUMMARY_VERSION = "agnt.mission-summary.v1"

# Vocabulaire FERMÉ du résultat lisible par le propriétaire. « Disponible » est le
# seul état qui autorise un écran à montrer des findings ; tous les autres disent
# pourquoi il n'y en a pas, et aucun ne se confond avec « zéro trouvé ».
RESULTATS = ("resultat_disponible", "resultat_partiel", "aucun_resultat",
             "refuse", "erreur", "en_cours", "indetermine")

# Vocabulaire FERMÉ de la preuve de comptage.
ETATS_FINDINGS = ("prouve", "non_prouve", "non_produit", "incomplet",
                  "artefacts_manquants")

# Repli des dimensions `execution-status.v1` en groupes lisibles. L'ordre est
# celui de la lecture humaine : ce qui a tourné d'abord, ce qui n'a pas pu ensuite.
GROUPES = ("executes", "echoues", "en_cours", "selectionnes", "refuses",
           "non_disponibles", "non_applicables", "non_selectionnes", "indetermines")

ETATS_ARTEFACT = ("present", "absent", "illisible")

# Artefacts utiles au lecteur, et leur nom de fichier. Liste fermée : jamais un
# chemin libre (la résolution passe par `mission_history._resoudre_artefact`).
ARTEFACTS = (("plan", "plan.json"), ("run", "run.json"), ("intent", "intent.json"),
             ("findings", "findings.json"), ("clusters", "clusters.json"),
             ("rapport", "rapport.json"))

# Nombre d'événements de journal repris dans le résumé : de quoi lire la fin
# d'une mission sans charger la timeline complète (qui reste servie par History).
ETAPES_MAX = 12


# --------------------------------------------------------------------------- artefacts
def _etat_artefact(chemin: Path, nom_fichier: str) -> str:
    """`present` / `absent` / `illisible` — prouvé par le disque, jamais déduit."""
    p = MH._resoudre_artefact(chemin, nom_fichier)
    if p is None:
        return "absent"
    return "present" if MH._lire_json(p) is not None else "illisible"


def _artefacts(chemin: Path, anomalies: dict) -> dict:
    etats = {nom: _etat_artefact(chemin, fichier) for nom, fichier in ARTEFACTS}
    etats["rapport_lisible"] = ("present" if MH._rapport_lisible(chemin) is not None
                                else "absent")
    if anomalies.get("absent"):
        etats["journal"] = "absent"
    elif anomalies.get("illisible"):
        etats["journal"] = "illisible"
    else:
        etats["journal"] = "present"
    return etats


# --------------------------------------------------------------------------- plan
def _plan(chemin: Path, plan, evenements: list[dict]) -> dict:
    """Le plan tel qu'il est SUR LE DISQUE : complet, partiel, illisible ou absent.

    Un plan malformé (steps absents, entrées sans provider) ne fait pas tomber la
    projection : il rend `partiel` et le compte d'entrées invalides. C'est
    exactement le cas d'une mission interrompue au milieu de l'écriture du plan.
    """
    fichier = MH._resoudre_artefact(chemin, "plan.json")
    out: dict = {"etat": "absent", "plan_id": None, "steps": None,
                 "providers": [], "steps_invalides": 0, "source": "aucune"}
    if fichier is not None and not isinstance(plan, dict):
        out["etat"] = "illisible"
        return out
    if isinstance(plan, dict) and plan:
        out["source"] = "artefact"
        out["plan_id"] = MH._id_sur(plan.get("plan_id"))
        steps = plan.get("steps")
        if isinstance(steps, list):
            valides, invalides = [], 0
            for s in steps:
                pid = MH._id_sur(s.get("provider")) if isinstance(s, dict) else None
                if pid:
                    valides.append(pid)
                else:
                    invalides += 1
            out["steps"] = len(steps)
            out["providers"] = list(dict.fromkeys(valides))
            out["steps_invalides"] = invalides
            out["etat"] = "partiel" if (invalides or not valides) else "complet"
        else:
            out["etat"] = "partiel"
        return out
    # Pas d'artefact : le journal porte parfois la liste des providers du plan.
    for ev in evenements:
        if ev.get("type") == "plan" and isinstance(ev.get("providers"), list):
            noms = [MH._id_sur(p) for p in ev["providers"]]
            out.update({"etat": "partiel", "source": "journal",
                        "plan_id": MH._id_sur(ev.get("plan_id")),
                        "providers": [n for n in noms if n]})
    return out


# --------------------------------------------------------------------------- providers
def _groupe(record: dict) -> str:
    """Repli d'un enregistrement `execution-status.v1` vers UN groupe lisible.

    Aucun état n'est inventé : chaque branche lit une valeur déjà dérivée par
    `mission_history`. La précédence suit la question du lecteur — « est-ce que
    ça a tourné ? », puis « pourquoi pas ? ».
    """
    exe = record.get("execution") or {}
    valeur = exe.get("value")
    motif = exe.get("reason_code")
    if valeur == "unavailable":
        return "non_disponibles"
    if valeur == "termine":
        return "executes"
    if valeur in ("echoue", "timed_out", "cancelled"):
        return "echoues"
    if valeur == "en_cours":
        return "en_cours"
    if valeur == "non_lance":
        if motif in ("target_not_applicable", "condition_blocked"):
            return "non_applicables"
        if motif == "not_in_plan":
            return "non_selectionnes"
        autorisation = (record.get("authorization") or {}).get("value")
        if motif in ("policy_denied", "policy_unavailable") or autorisation == "non_autorise":
            return "refuses"
        if motif == "mission_stopped_before_execution":
            return "selectionnes"
        return "indetermines"
    return "indetermines"


def _entree_provider(record: dict, groupe: str) -> dict:
    detection = record.get("detection") or {}
    exe = record.get("execution") or {}
    entree = {
        "provider": record.get("provider_id"),
        "display_name": record.get("display_name") or record.get("provider_id"),
        "etat": groupe,
        "detection": detection.get("value"),
        # Le compte par provider n'existe QUE si la détection est prouvée : un
        # provider indisponible ou échoué ne porte pas de « 0 ».
        "findings": detection.get("findings_count"),
        "motif": exe.get("reason_code") or detection.get("reason_code"),
    }
    cap = record.get("capability_id")
    if cap:
        entree["capability"] = cap
    return entree


def _providers(executions: list[dict]) -> dict:
    par_etat: dict[str, list] = {g: [] for g in GROUPES}
    for record in executions:
        if not isinstance(record, dict) or not record.get("provider_id"):
            continue
        g = _groupe(record)
        par_etat[g].append(_entree_provider(record, g))
    comptes = {g: len(par_etat[g]) for g in GROUPES}
    return {"total": sum(comptes.values()), "comptes": comptes, "par_etat": par_etat}


def _analyse_prouvee(executions: list[dict]) -> bool:
    """Au moins un provider a analysé quelque chose, et c'est CONSIGNÉ.

    C'est la seconde preuve exigée avant d'écrire « 0 finding ». `rien_trouve`
    n'est posé par le ledger qu'avec des cibles analysées ; `findings_presents`
    porte un compte non nul. Toute autre détection (`non_evalue`, `inconnu`) ne
    prouve rien — et un zéro posé dessus serait un faux zéro.
    """
    for record in executions:
        if not isinstance(record, dict):
            continue
        if (record.get("detection") or {}).get("value") in ("rien_trouve", "findings_presents"):
            return True
    return False


# --------------------------------------------------------------------------- findings
def _findings(chemin: Path, statut: str, executions: list[dict], motif: str | None) -> dict:
    """{count, etat, raison, par_severite} — le cœur de la règle « pas de faux zéro »."""
    doc = MH._lire_json(MH._resoudre_artefact(chemin, "findings.json"))
    lisible = isinstance(doc, list)

    if statut in ("en_file", "en_cours"):
        return {"count": None, "etat": "incomplet",
                "raison": "mission en cours : aucun compte n'est encore prouvé"}
    if statut == "inconnu":
        return {"count": None, "etat": "incomplet",
                "raison": "aucun événement terminal consigné : l'état du run n'est pas prouvé"}
    if statut == "refuse":
        return {"count": None, "etat": "non_produit",
                "raison": "mission refusée avant tout résultat"
                          + (f" ({MH._nettoyer(motif, borne=80)})" if motif else "")}
    if statut == "erreur":
        return {"count": None, "etat": "non_produit",
                "raison": "mission interrompue par une erreur : aucun compte n'est prouvé"
                          + (f" ({MH._nettoyer(motif, borne=80)})" if motif else "")}
    # statut == "termine"
    if not lisible:
        return {"count": None, "etat": "artefacts_manquants",
                "raison": "artefact findings absent ou illisible : le compte n'est pas prouvé"}
    if doc:
        resume = MH._findings_summary(chemin, statut) or {}
        return {"count": len(doc), "etat": "prouve",
                "raison": "compté sur l'artefact findings",
                "par_severite": resume.get("by_severity") or {}}
    if _analyse_prouvee(executions):
        return {"count": 0, "etat": "prouve",
                "raison": "artefact findings vide ET au moins une cible analysée prouvée",
                "par_severite": {}}
    return {"count": None, "etat": "non_prouve",
            "raison": "artefact findings vide mais AUCUNE cible analysée prouvée — "
                      "le zéro n'est pas un résultat"}


# --------------------------------------------------------------------------- résultat
def _resultat(statut: str, findings: dict, providers: dict, artefacts: dict,
              motif: str | None) -> dict:
    """L'indication unique de l'écran : disponible / partiel / non produit / …"""
    if statut in ("en_file", "en_cours"):
        return {"etat": "en_cours", "motif": "mission_en_cours",
                "message": "Mission en cours : aucun résultat définitif."}
    if statut == "refuse":
        return {"etat": "refuse", "motif": motif or "arret",
                "message": MH._resume_arret(str(motif or ""))}
    if statut == "erreur":
        return {"etat": "erreur", "motif": motif or "erreur",
                "message": MH._resume_arret(str(motif or ""))}
    if statut == "inconnu":
        return {"etat": "indetermine", "motif": "aucun_evenement_terminal",
                "message": "Aucun événement terminal consigné : l'issue n'est pas prouvée."}
    # termine
    comptes = providers.get("comptes") or {}
    if findings["etat"] == "prouve":
        if artefacts.get("rapport_lisible") == "present" and not comptes.get("echoues"):
            return {"etat": "resultat_disponible", "motif": "artefacts_complets",
                    "message": f"Résultat disponible : {findings['count']} finding(s)."}
        manque = "rapport absent" if artefacts.get("rapport_lisible") != "present" \
            else "au moins un outil a échoué"
        return {"etat": "resultat_partiel", "motif": "resultat_incomplet",
                "message": f"Résultat partiel ({manque}) : {findings['count']} finding(s)."}
    if comptes.get("executes"):
        return {"etat": "resultat_partiel", "motif": "findings_non_prouves",
                "message": "Des outils ont tourné mais le compte de findings n'est pas prouvé."}
    return {"etat": "aucun_resultat", "motif": findings["etat"],
            "message": "Mission close sans résultat exploitable : " + findings["raison"]}


# --------------------------------------------------------------------------- journal
def _journal(chemin: Path, mid: str, evenements: list[dict], anomalies: dict) -> dict:
    """Minimum de timeline utile : état, volume, bornes, derniers événements."""
    tl = MH._timeline(chemin, mid, evenements, anomalies, MH.TIMELINE_LIMIT_MAX, None)
    evs = tl.get("events") or []
    derniers = [{"sequence": e["source"]["sequence"],
                 "at": (e.get("time") or {}).get("timestamp"),
                 "kind": e.get("kind"),
                 "resume": e.get("safe_summary")}
                for e in evs[-ETAPES_MAX:]]
    return {
        "etat": tl.get("state"),
        "evenements": tl.get("total_events", 0),
        "limitations": tl.get("limitations") or [],
        "premier_at": (evs[0].get("time") or {}).get("timestamp") if evs else None,
        "dernier_at": (evs[-1].get("time") or {}).get("timestamp") if evs else None,
        "derniers": derniers,
    }


# --------------------------------------------------------------------------- projection
def resumer_dossier(chemin: Path, *, proprietaire=None) -> dict:
    """La projection console d'un dossier de mission déjà résolu.

    Ne lève pas sur un artefact abîmé : chaque bloc porte son propre état.
    """
    chemin = Path(chemin)
    mid = chemin.name
    entete = MH._lire_json(chemin / "mission.json")
    evenements, anomalies = MH.lire_journal(chemin)
    statut, incomplete = MH.statut_mission(
        evenements, proprietaire and (lambda: proprietaire(mid)))
    motif = MH._motif_terminal(evenements)
    terminal_ev = MH._evenement_terminal(evenements)

    plan_doc = MH._lire_json(MH._resoudre_artefact(chemin, "plan.json"))
    rapport = MH._lire_json(MH._resoudre_artefact(chemin, "rapport.json"))
    executions = MH._executions(chemin, evenements, plan_doc, rapport)

    sommaire = MH.resumer(chemin, evenements, anomalies, statut, incomplete)
    artefacts = _artefacts(chemin, anomalies)
    providers = _providers(executions)
    findings = _findings(chemin, statut, executions, motif)
    resultat = _resultat(statut, findings, providers, artefacts, motif)
    run_id = MH._run_id_de(evenements, chemin)

    terminal = None
    if terminal_ev is not None:
        est_cloture = terminal_ev.get("type") == "cloture"
        terminal = {
            "type": "cloture" if est_cloture else "arret",
            "motif": None if est_cloture else MH._nettoyer(motif, borne=80),
            "categorie": "mission" if est_cloture else MH._categorie_arret(str(motif or "")),
            "message": "Mission terminée" if est_cloture else MH._resume_arret(str(motif or "")),
            "at": MH._rfc3339(terminal_ev.get("ts")),
        }
        erreur = terminal_ev.get("erreur")
        if erreur is not None:
            terminal["erreur"] = MH._nettoyer_erreur(erreur)

    resume: dict = {
        "schema_version": SUMMARY_VERSION,
        "mission_id": mid,
        "detail_href": f"/api/missions/{mid}",
        "run_id": run_id,
        "requete": {
            "titre": MH._titre((entete or {}).get("requete")),
            "canonique": MH._nettoyer((entete or {}).get("requete_canonique"),
                                      borne=MH.BORNE_TITRE),
        },
        "cible": MH.cible_sure(entete),
        "statut": statut,
        "incomplete": bool(incomplete),
        "terminal": terminal,
        "resultat": resultat,
        # `findings_count` est en tête parce que c'est LE chiffre que l'écran
        # affiche — et `None` y est une réponse valide, jamais remplacée par 0.
        "findings_count": findings["count"],
        "findings": findings,
        "artefacts": artefacts,
        "artefacts_manquants": list(dict.fromkeys(
            MH._artefacts_manquants(chemin, statut, anomalies, run_id))),
        "plan": _plan(chemin, plan_doc, evenements),
        "providers": providers,
        "journal": _journal(chemin, mid, evenements, anomalies),
        "dates": {
            "cree_le": sommaire.get("created_at"),
            "demarre_le": sommaire.get("started_at"),
            "termine_le": sommaire.get("completed_at"),
            "maj_le": sommaire.get("updated_at"),
            "duree_ms": sommaire.get("duration_ms"),
        },
    }
    if incomplete:
        resume["incomplete_raison"] = sommaire.get("incomplete_reason")
    return resume


def resumer_mission(mission_id: str, racine=None, *, proprietaire=None) -> dict:
    """La projection console d'une mission par identifiant.

    `MissionIntrouvable` si l'identifiant ne désigne aucun dossier lisible SOUS
    la racine (validation et bornage délégués à `mission_history`, pas refaits).
    """
    racine = MH._racine(racine)
    chemin = MH._chemin_mission(mission_id, racine)
    if chemin is None or not (chemin / "mission.json").is_file():
        raise MH.MissionIntrouvable(mission_id)
    return resumer_dossier(chemin, proprietaire=proprietaire)
