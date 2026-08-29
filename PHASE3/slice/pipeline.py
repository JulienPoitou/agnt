"""Pipeline de bout en bout — le vertical slice.

    phrase → capacités → providers → plan typé → OPA
           → sandbox → raw results → couverture
           → findings normalisés → identités canoniques
           → clustering v0 → rapport

Un seul processus Python, aucun service séparé. Le runner est déterministe : à requête
et registre identiques, il produit le même plan et la même empreinte (critère n°10).
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import adapters
import clusterer
import garde_chemin as GC
import mission as MS
import profils
import run as RUN
import findings as F
import intent
import plan as P
import policy as PO
from registre import Registry
from sandbox import CACHE_BIN, CACHE_DB, CACHE_REGLES, Sandbox

RACINE = Path(__file__).resolve().parent.parent     # PHASE3/
SORTIE = RACINE / "run"

# Moteur d'intention : "deterministe" (référence) ou "llm".
# Le LLM ne remplace QUE le matching — jamais le contrat, ni le registre, ni OPA.
MOTEUR_INTENT = "deterministe"
FOURNISSEUR_LLM = None

# Confiances de cible admises : exactement les valeurs que `policy.rego` compare à
# `input.cible.confiance`. La liste vit ici, et non dans un drapeau CLI, parce que
# c'est la bibliothèque qui applique la décision — toute entrée d'appel (CLI, test,
# appelant tiers) passe par ce contrôle.
CONFIANCES = ("controlled", "untrusted")


class PipelineError(Exception):
    pass


@dataclass
class Execution:
    plan: dict
    decision: dict
    intent: dict = field(default_factory=dict)
    arret: str = ""
    run_id: str = ""
    profil: str = ""
    contexte: dict = field(default_factory=dict)
    chemin: dict = field(default_factory=dict)
    raw: list[dict] = field(default_factory=list)
    couverture: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    clusters: dict = field(default_factory=dict)
    rapport: dict = field(default_factory=dict)
    result_digest: str = ""
    # Dossier de mission (étape 2) : identifiant du journal append-only qui a
    # tracé cette exécution. Chaîne vide = exécution antérieure à l'étape 2.
    mission: str = ""


def _prepare_sortie() -> Path:
    """Prépare le répertoire de sortie.

    Attention : ce répertoire est BINDÉ dans le sandbox. On vide son CONTENU, on ne le
    supprime jamais — supprimer un répertoire déjà bindé casse le montage.
    """
    SORTIE.mkdir(parents=True, exist_ok=True)
    for f in SORTIE.iterdir():
        if f.is_file():
            f.unlink()
    return SORTIE


def executer(requete: str, cible: Path, cible_autorisee: bool = True,
             confiance_cible: str = "controlled",
             avec_internes: bool = False) -> Execution:
    if confiance_cible not in CONFIANCES:
        # Pas de repli : une valeur non reconnue vaudrait «controlled» par accident,
        # et désarmerait silencieusement la garde mémoire de la policy.
        raise PipelineError(
            f"confiance de cible inconnue : {confiance_cible!r} · admises : "
            f"{' | '.join(CONFIANCES)}")
    registre = Registry()

    # ---------------------------------------------------------------- 0. mission
    # Le dossier append-only s'ouvre AVANT toute décision : un arrêt (intent non
    # résolu, policy) doit être tracé autant qu'une exécution complète.
    miss = MS.ouvrir(requete, P.canonicaliser(requete), Path(cible))
    # La confiance APPLIQUÉE est consignée immédiatement, avant la policy : « qu'est-ce
    # qu'on a cru de cette cible ? » doit se relire dans le dossier de mission même si
    # la policy refuse ensuite — et même si OPA est indisponible.
    MS.consigner(miss, "confiance", confiance_cible=confiance_cible,
                 cible_autorisee=cible_autorisee, profil=profils.actif().nom)

    # ---------------------------------------------------------------- 1. intention
    # Les garde-fous déterministes s'appliquent dans les DEUX modes : une demande
    # explicitement interdite n'est jamais soumise à un modèle.
    if MOTEUR_INTENT == "llm" and FOURNISSEUR_LLM is not None:
        import intent_llm
        it = intent_llm.garde_fous(requete, registre)
        if it is None:
            it = intent_llm.inferer(requete, registre, FOURNISSEUR_LLM)
    else:
        it = intent.inferer(requete, registre, avec_internes=avec_internes)

    # Un intent non résolu n'exécute RIEN. Ni plan, ni policy, ni outil.
    # C'est testé : c'est la différence entre « il manque une information » et
    # « la demande est refusée », et aucune des deux ne doit produire d'exécution.
    if not it.executable():
        MS.consigner(miss, "arret", motif=f"intent_{it.statut}")
        return Execution(plan={}, decision={"allow": False, "motifs": [f"intent_{it.statut}"]},
                         intent=it.to_dict(), arret=it.statut, mission=miss.id)

    provs = intent.choisir_providers(it, registre)

    # --------------------------------------------- 1b. applicabilité (étape 3)
    # Filtrage DÉTERMINISTE et déclaratif, AVANT le plan : un provider dont les
    # globs déclarés ne correspondent à aucun fichier de la cible est écarté avec
    # motif tracé. Sans déclaration, le provider reste éligible (pas de devinette).
    provs, exclus = P.filtrer_applicabilite(provs, registre, Path(cible))
    if exclus:
        MS.consigner(miss, "applicabilite",
                     ecartes={k: v for k, v in exclus.items()})
    if not provs:
        # Tous les providers sont inapplicables à cette cible : ce n'est pas un
        # échec, c'est une réponse honnête — rien à exécuter ici.
        MS.consigner(miss, "arret", motif="applicabilite", ecartes=exclus)
        return Execution(plan={}, decision={"allow": False,
                                            "motifs": ["aucun provider applicable à cette cible"]},
                         intent=it.to_dict(), arret="applicabilite", mission=miss.id)

    # ---------------------------------------------------------------- 2. plan typé
    plan = P.construire(requete, str(cible), provs, registre, it.moteur,
                        exclus_applicabilite=exclus)
    MS.consigner(miss, "plan", plan_id=plan.plan_id,
                 providers=[s.provider for s in plan.steps])

    # ---------------------------------------------------------------- 3. policy
    moteur = PO.PolicyEngine(opa=CACHE_BIN / "opa")
    decision = moteur.evaluer(plan, registre, cible_autorisee,
                              confiance_cible=confiance_cible)
    if not decision.allow:
        # Le plan est refusé : on s'arrête AVANT toute exécution.
        MS.consigner(miss, "arret", motif="policy", decision=list(decision.motifs))
        return Execution(plan=plan.to_dict(),
                         decision={"allow": False, "motifs": list(decision.motifs)},
                         intent=it.to_dict(), arret="policy", mission=miss.id,
                         # Un refus sans le nom du profil qui refuse ne se relit pas :
                         # « qui a décidé quoi, avec quelles limites » est la question.
                         profil=profils.actif().nom)

    # ---------------------------------------------------------------- 4. garde de chemin
    # OPA a autorisé la cible DEMANDÉE. Ici on vérifie ce qui est RÉELLEMENT accessible :
    # OPA ne peut pas savoir qu'un symlink sort du workspace.
    rapport_chemin = GC.verifier_cible(cible, [cible])
    for step in plan.steps:
        GC.verifier_args([*step.commande, *step.args])

    # ---------------------------------------------------------------- 5. exécution
    sortie = _prepare_sortie()
    GC.verifier_sortie(sortie / "rapport.json", sortie)
    sbx = Sandbox(
        bwrap=shutil.which("bwrap") or "bwrap",
        racine_scan=cible,
        racine_regles=CACHE_REGLES,
        racine_db=CACHE_DB,
        sortie=sortie,
        gitconfig=RACINE / "gitconfig",
    )

    ctx = RUN.capturer(sbx, PO.POLICY_FILE, registre.empreinte())
    ctx.input_digest, ctx.input_commit, ctx.working_tree_dirty = RUN.digest_cible(cible)
    exec_ = Execution(plan=plan.to_dict(),
                      decision={"allow": True, "motifs": list(decision.motifs)},
                      intent=it.to_dict(),
                      profil=profils.actif().nom,
                      run_id=RUN.nouveau_run_id(plan.plan_id, ctx, ctx.input_digest),
                      contexte=ctx.to_dict(),
                      chemin=rapport_chemin.to_dict())
    MS.consigner(miss, "contexte", run_id=exec_.run_id,
                 contexte_empreinte=ctx.contexte_empreinte,
                 input_digest=ctx.input_digest, input_commit=ctx.input_commit,
                 working_tree_dirty=ctx.working_tree_dirty)

    tous_findings = []
    for step in plan.steps:
        prov = registre.provider(step.provider)
        brut = adapters.executer(prov, sbx)

        # Le RAW est conservé tel quel, sans retraitement.
        (sortie / f"raw_{prov.id}.json").write_text(
            json.dumps(brut.donnees, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8")

        exec_.raw.append({
            "provider": prov.id,
            "fichier": f"raw_{prov.id}.json",
            "code_retour": brut.code_retour,
            "timeout": brut.timeout,
        })
        exec_.couverture.append(brut.couverture.to_dict())

        # Chemins relativisés aux racines CONNUES (montage isolateur + cible) avant
        # calcul des fingerprints : identité indépendante de la machine (2026-08-28).
        norm = F.normaliser(prov.id, brut.donnees, mani=prov.manifest,
                            racines=(Sandbox.M_SCAN, str(cible)))
        tous_findings.extend(norm)
        MS.consigner(miss, "execution", provider=prov.id,
                     code_retour=brut.code_retour, timeout=brut.timeout,
                     findings=len(norm))

    # ------------------------------------------------- 5. garde-fou secrets
    fuites = F.verifie_absence_secrets(tous_findings)
    if fuites:
        raise PipelineError("des secrets ont survécu à la normalisation : " + "; ".join(fuites))

    exec_.findings = [f.to_dict() for f in tous_findings]
    exec_.result_digest = RUN.digest_resultats(exec_.findings)

    # ---------------------------------------------------------------- 6. clustering v0
    exec_.clusters = clusterer.regrouper(tous_findings)

    # ---------------------------------------------------------------- 7. rapport
    exec_.rapport = _rapport(it, plan, exec_)
    exec_.mission = miss.id
    MS.consigner(miss, "cloture", findings=len(exec_.findings),
                 clusters=len(exec_.clusters.get("clusters") or []),
                 result_digest=exec_.result_digest)
    return exec_


def _rapport(it, plan, e: Execution) -> dict:
    par_outil = {}
    for c in e.couverture:
        par_outil[c["provider"]] = {
            "analysé": [t["chemin"] for t in c["cibles"]
                        if t["etat"] == "scanned_successfully"],
            "non_analysé": [{"cible": t["chemin"], "etat": t["etat"], "raison": t["raison"]}
                            for t in c["cibles"] if t["etat"] != "scanned_successfully"],
            "limites": c["limites_connues"],
        }
    return {
        "requete": it.requete,
        "capacites_demandees": list(it.capabilities),
        "motifs_intent": it.motifs,
        "plan_id": plan.plan_id,
        "plan_empreinte": plan.empreinte(),
        "autorisation": e.decision,
        "findings": len(e.findings),
        "clustering": e.clusters["stats"],
        "clusters": e.clusters["clusters"],
        "non_regroupe": e.clusters["non_regroupe"],
        "couverture": par_outil,
    }


def main() -> int:
    requete = sys.argv[1] if len(sys.argv) > 1 else "Analyse la sécurité de mon dépôt"
    cible = Path(sys.argv[2]) if len(sys.argv) > 2 else RACINE / "testrepo"

    e = executer(requete, cible)
    SORTIE.mkdir(parents=True, exist_ok=True)
    (SORTIE / "plan.json").write_text(json.dumps(e.plan, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    (SORTIE / "findings.json").write_text(json.dumps(e.findings, ensure_ascii=False, indent=2),
                                          encoding="utf-8")
    (SORTIE / "clusters.json").write_text(json.dumps(e.clusters, ensure_ascii=False, indent=2),
                                          encoding="utf-8")
    (SORTIE / "rapport.json").write_text(json.dumps(e.rapport, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    (SORTIE / "run.json").write_text(
        json.dumps({"execution_profile": e.profil,
                    "plan_id": e.plan.get("plan_id"),
                    "input_digest": e.contexte.get("input_digest"),
                    "input_commit": e.contexte.get("input_commit", ""),
                    "working_tree_dirty": e.contexte.get("working_tree_dirty", False),
                    "execution_context_digest": e.contexte.get("contexte_empreinte"),
                    "run_id": e.run_id,
                    "result_digest": e.result_digest,
                    "contexte": e.contexte, "chemin": e.chemin},
                   ensure_ascii=False, indent=2), encoding="utf-8")

    if e.arret:
        print(f"requête      : {requete}")
        print(f"ARRÊT        : {e.arret}")
        if e.intent.get("question"):
            print(f"question     : {e.intent['question']}")
        if e.intent.get("motif"):
            print(f"motif        : {e.intent['motif']}")
        print("aucune exécution, aucun plan, aucun outil lancé")
        return 0

    r = e.rapport
    print(f"requête      : {r['requete']}")
    print(f"capacités    : {', '.join(r['capacites_demandees'])}")
    print(f"plan         : {r['plan_id']}  empreinte {r['plan_empreinte'][:16]}")
    print(f"run          : {e.run_id}  profil {e.profil}")
    print(f"  input_digest   : {e.contexte.get('input_digest')}  commit {e.contexte.get('input_commit') or '—'}"
          f"{'  (working tree MODIFIÉ)' if e.contexte.get('working_tree_dirty') else ''}")
    print(f"  contexte       : {e.contexte.get('contexte_empreinte')}")
    print(f"  result_digest  : {e.result_digest}")
    print(f"autorisation : allow={r['autorisation']['allow']} {r['autorisation']['motifs'] or ''}")
    print(f"findings     : {r['findings']}")
    print(f"clustering   : {r['clustering']['reduction']} "
          f"({r['clustering']['clusters']} clusters, "
          f"{r['clustering']['findings_non_regroupes']} non regroupés)")
    print("\n--- clusters ---")
    for c in r["clusters"]:
        print(f"  {c['cluster_id']}  {len(c['members']):>3} membres  "
              f"{c['confidence']:<7} {','.join(c['reason'])}  [{c['cle']}]")
    if r["non_regroupe"]:
        print(f"  non regroupés : {len(r['non_regroupe'])} ({', '.join(r['non_regroupe'][:6])})")
    print("\n--- couverture ---")
    for prov, c in r["couverture"].items():
        print(f"  {prov}")
        print(f"     analysé     : {c['analysé'] or '—'}")
        for na in c["non_analysé"]:
            print(f"     NON analysé : {na['cible']} [{na['etat']}] {na['raison']}")
        for lim in c["limites"]:
            print(f"     limite      : {lim}")
    print(f"\nécrit dans {SORTIE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

