"""Pipeline web : engagement → scope → plan → exécution → findings + preuve.

Assemble les pièces (web_scope, fournisseurs_web, orchestrateur, taches,
cycle_vie, preuve) SANS en dupliquer la logique. L'exécuteur est injecté :
`ExecuteurLocal` en prod, faux en tests. Aucun binaire réel requis ici —
`RUNTIME_VERIFIED = False` tant que le runtime Linux n'a pas tourné.

Un finding interprété naît OBSERVED (transition `observer` depuis DISCOVERED,
historique joint) : jamais CONFIRMED sans oracle (voir oracle_web).
"""
from __future__ import annotations

import fournisseurs_web as FW
import preuve as PR
import taches as TA
import web_scope as WS
from cycle_vie import DISCOVERED, transition
from orchestrateur import executer_plan

RUNTIME_VERIFIED = False

ORDRE_CHAINE = ["httpx", "katana", "ffuf", "nuclei"]


class ErreurPipeline(Exception):
    """Engagement inexploitable : scope, plan ou exécution nommés."""


def derouler(engagement: dict, executer_tache, registre=None,
             out_dir: str = "/tmp/agnt-web") -> dict:
    """Déroule un engagement web planifié. Rend le rapport de mission (dict)."""
    if not isinstance(engagement, dict) or engagement.get("type") != "web":
        raise ErreurPipeline("engagement web attendu")
    url = engagement.get("url_canonique") or ""
    try:
        canonique = WS.canonicaliser_url(url)
    except Exception as e:
        raise ErreurPipeline(f"url inexploitable : {e}") from None
    if canonique != engagement.get("url_canonique"):
        raise ErreurPipeline("url_canonique incohérente avec l'engagement")
    garde = WS.ScopeEnforcer(autorises=[engagement.get("hote", "")], strict=True)
    ok, motif = garde.autoriser(canonique)
    if not ok:
        raise ErreurPipeline(f"scope : {motif}")
    egress = engagement.get("egress")
    egress_accorde = egress is True
    demandes = [p for p in ORDRE_CHAINE if p in (engagement.get("providers_prevus") or [])]
    demandes += [p for p in (engagement.get("providers_prevus") or []) if p not in ORDRE_CHAINE]
    plans, ecartes = [], []
    for pid in demandes:
        try:
            plans.append({**FW.planifier(pid, canonique, out_dir,
                                         egress=egress_accorde, registre=registre),
                          "provider_id": pid})
        except FW.ErreurPlanification as e:
            ecartes.append({"provider": pid, "motif": str(e)})
    if not plans and not ecartes:
        raise ErreurPipeline("aucun provider demandé")
    noeuds, precedent = [], None
    for plan in plans:
        nid = plan["provider_id"]
        noeuds.append({"id": nid, "depend_de": [precedent] if precedent else [],
                       "tache": TA.Tache(provider_id=nid, argv=plan["argv"],
                                         timeout_s=float(plan["timeout_s"] or 300))})
        precedent = nid
    run = executer_plan(noeuds, executer_tache)
    findings, details = [], []
    for res in run["taches"]:
        if res["etat"] != TA.TERMINEE:
            details.append({"provider": res["provider"], "etat": res["etat"],
                            "motif": (res["resultat"] or {}).get("erreur", "")})
            continue
        r = res["resultat"] or {}
        try:
            interp = FW.interpreter(res["provider"], r.get("code", -1),
                                    r.get("stdout", ""), registre=registre)
        except FW.ErreurPlanification as e:
            details.append({"provider": res["provider"], "etat": "interpretation_impossible",
                            "motif": str(e)})
            continue
        for f in interp["findings"]:
            d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            d["cycle"] = {"etat": "observed",
                          "historique": [{"depuis": DISCOVERED, "evenement": "observer",
                                          "vers": transition(DISCOVERED, "observer")}]}
            findings.append(d)
        details.append({"provider": res["provider"], "etat": res["etat"],
                        "findings": len(interp["findings"]), "motif": interp["motif"]})
    rapport = {"type": "rapport_web", "url_canonique": canonique,
               "statut_run": run["statut"], "motif_run": run["motif"],
               "providers_demandes": list(engagement.get("providers_prevus") or []),
               "providers_ecartes": ecartes, "details": details,
               "findings": findings,
               "limites_connues": [
                   "exécution par exécuteur injecté ; binaires réels non vérifiés ici",
                   "absence de correspondance ≠ absence de vulnérabilité"]}
    if not plans:
        rapport["statut_run"] = "refuse"
        rapport["motif_run"] = "; ".join(e["motif"] for e in ecartes) or "aucun plan"
    try:
        rapport["preuve"] = PR.sceller({k: rapport[k] for k in
                                        ("type", "url_canonique", "statut_run",
                                         "providers_demandes", "details")})
    except TypeError as e:
        rapport["preuve"] = {"erreur": f"preuve_non_construite : {e}"}
    return rapport
