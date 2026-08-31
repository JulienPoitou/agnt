#!/usr/bin/env python3
"""Une commande, un workflow complet, un rapport lisible.

    python3 PHASE3/analyser.py <dépôt> ["requête en langage naturel"] [--moteur auto|deterministe|llm]
                                 [--confiance controlled|untrusted]
                                 [--egress true|false]

Sortie : un bundle d'artefacts dans PHASE3/artifacts/<input_digest>/<plan_id>/<run_id>/
    rapport.md · rapport_humain.md · manifeste.json · plan.json · findings.json
    clusters.json · run.json · raw_*.json · rapport.sarif
et, étape 6, une archive de mission sous PHASE3/artifacts/missions/<mission>/sortie/
    RAPPORT.md · intent.json + copie des JSON du bundle

L'ordre des arguments est celui de Phase 4 : LA CIBLE D'ABORD, la requête ensuite.
Elle est optionnelle — sans elle, la requête par défaut est un audit complet.
Le faire autrement casserait tout appel déjà écrit (`test_rapport.py`, `test_bundle.py`).

Étape 6 (2026-08-29) : le matching d'intention peut être confié à un LLM. Il ne pilote
QUE le catalogue : sa sortie est validée contre le registre, un échec retombe sur le
déterministe et le repli est tracé dans `intent.moteur`. Aucune logique de sécurité
n'est ajoutée ici.

Codes de sortie :
    0  workflow exécuté
    1  erreur technique
    2  demande refusée ou nécessitant une clarification — AUCUNE exécution

CONFIANCE DE CIBLE (étape 7 amont, 2026-08-30) : `--confiance untrusted` déclare que
le dépôt n'est PAS fiable. `policy.rego` refuse alors tout plan tant que la mémoire
n'est pas bornée (limite imposée par cgroups v2 ou un runtime OCI, non disponible ici) :
le scan est refusé AVANT toute exécution, et le motif est rendu. Par défaut la cible est
`controlled` — c'est le comportement historique, et il est AFFICHÉ : une valeur par défaut
muette, pour une décision de sécurité, ne se justifie pas.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import assainissement as ASS  # noqa: E402
import mission as MS  # noqa: E402
import rapport_humain as RH  # noqa: E402
import pipeline          # noqa: E402
import rapport as R      # noqa: E402
import statuts as ST     # noqa: E402
import mcp_bootstrap as MCP_BOOT  # noqa: E402
import transports as CORE_TRANSPORTS  # noqa: E402


def initialiser_extensions() -> None:
    """Bootstrap unique des transports externes avant tout chargement de registre."""
    MCP_BOOT.initialiser_mcp(CORE_TRANSPORTS)


# Index en trois niveaux :
#   artifacts/<input_digest>/<plan_id>/<run_id>/
# La cible d'abord, puis le plan canonique, puis l'exécution unique. Deux formulations
# d'une même intention tombent dans le MÊME plan_id — c'est le but de la canonicalisation.
ARTIFACTS = RACINE / "artifacts"


def sarif(findings: list[dict], run_id: str, plan_id: str) -> dict:
    """Export SARIF 2.1.0 des observations.

    SARIF porte des identifiants stables et des empreintes partielles, mais il ne relie
    pas deux outils entre eux : c'est le canonical_rule_id interne qui le fait. L'export
    est donc une vue d'échange, pas le modèle de référence.
    """
    regles = {}
    resultats = []
    for f in findings:
        canon = f["identity"]["canonical_rule_id"]
        if canon not in regles:
            regles[canon] = {
                "id": canon,
                "shortDescription": {"text": (f.get("evidence") or {}).get("message")
                                     or canon},
                "properties": {"outil": f["source"]["tool"]},
            }
        loc = f["location"]
        res = {
            "ruleId": canon,
            "level": "warning",
            "message": {"text": (f.get("evidence") or {}).get("message") or canon},
            "partialFingerprints": {"primary": f["identity"]["fingerprint"]},
            "properties": {
                "finding_id": f["id"],
                "outil_source": f["source"]["tool"],
                "provider": f["source"].get("provider"),
                "transport": f["source"].get("transport", "local"),
                "serveur": f["source"].get("server_id"),
                "outil_provider": f["source"].get("tool"),
                "protocole": f["source"].get("protocol_version"),
                "regle_source": f["source"].get("original_rule_id"),
                "paquet": loc.get("package"),
            },
        }
        if loc.get("file"):
            region = {}
            if loc.get("line"):
                region["startLine"] = loc["line"]
            res["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": loc["file"]},
                **({"region": region} if region else {}),
            }}]
        else:
            # Cibles NON fichiers (URL d'un scanner web, hôte, image, ressource cloud) :
            # sans cette branche, un finding de cible web partait à l'export SANS
            # localisation — l'information était perdue au moment même où elle devient
            # échangeable. `uri` a le droit d'être une URL absolue en SARIF 2.1.0 ; les
            # autres coordonnées passent en logicalLocations, lues par les consommateurs.
            autre = {k: loc[k] for k in ("url", "hote", "image", "ressource") if loc.get(k)}
            if autre:
                log = [{"fullyQualifiedName": f"{k}:{v}"} for k, v in sorted(autre.items())]
                res["locations"] = [{
                    **({"physicalLocation": {"artifactLocation": {"uri": autre["url"]}}}
                       if "url" in autre else {}),
                    "logicalLocations": log,
                }]
        res["properties"].update({
            # ce que le modèle interne sait et que SARIF ne porte pas nativement
            "categorie": f["source"].get("categorie"),
            "horodatage": f["source"].get("horodatage"),
            "version_outil": f["source"].get("version_outil"),
            "cwe": (f.get("evidence") or {}).get("cwe"),
            "remediation": (f.get("evidence") or {}).get("remediation"),
            "confiance": (f.get("evidence") or {}).get("confiance"),
        })
        resultats.append(res)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "plateforme-ia-cyber",
                "version": "3.1",
                "informationUri": "https://example.invalid/plateforme",
                "rules": list(regles.values()),
            }},
            "results": resultats,
            "properties": {"run_id": run_id, "plan_id": plan_id},
        }],
    }



# Drapeaux reconnus : (valeurs admises, valeur admise quand le drapeau est nu).
# `None` en deuxième position = le drapeau EXIGE une valeur — un drapeau de sécurité
# n'a pas de valeur par défaut muette.
_DRAPEAUX = {
    "--moteur": (("auto", "deterministe", "llm"), "llm"),
    "--confiance": (pipeline.CONFIANCES, None),
    # Le drapeau n'a pas de forme « `--egress` seul vaut tout autoriser » : une valeur est
    # exigée (`true`/`false`) parce qu'un opérateur doit pouvoir écrire explicitement qu'il
    # ferme ce que le profil avait ouvert. Le nu, lui, est refusé — `None` en second.
    "--egress": (("true", "false"), None),
}


def _booleen(options: dict, cle: str) -> bool | None:
    """`None` = pas demandé (donc le profil fait foi). `absent` et `false` ne sont pas le même fait."""
    if cle not in options:
        return None
    return str(options[cle]).strip().lower() == "true"


def _options_depuis_argv(argv: list[str]) -> tuple[dict, list[str]]:
    """Sépare les options `--drapeau[=]valeur` des arguments de position.

    Retourne (options, arguments_de_position). Trois règles, toutes mesurées :

    · `--drapeau valeur` et `--drapeau=valeur` sont équivalentes — la forme espacée est
      celle documentée dans README_USAGE.md, et elle était CASSÉE avant cet extracteur :
      `--moteur deterministe` laissait « deterministe » comme requête et retenait llm ;
    · une valeur hors liste lève ValueError — jamais de repli sur un défaut : ici le
      défaut est une décision de sécurité, pas une préférence de confort ;
    · `options` ne contient QUE ce qui a été demandé. « absent » doit rester distinct
      de « demandé et obtenu », pour que l'appelant affiche la valeur réellement appliquée.
    """
    options: dict[str, str] = {}
    position: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if "=" in a and a.split("=", 1)[0] in _DRAPEAUX:
            drapeau, valeur = a.split("=", 1)
            i += 1
        elif a in _DRAPEAUX:
            drapeau = a
            suite = argv[i + 1] if i + 1 < len(argv) else ""
            if suite and not suite.startswith("--"):
                valeur, i = suite, i + 2
            else:
                valeur, i = None, i + 1
        else:
            position.append(a)
            i += 1
            continue

        admises, defaut_nu = _DRAPEAUX[drapeau]
        if valeur is None:
            if defaut_nu is None:
                raise ValueError(f"{drapeau} exige une valeur "
                                 f"({' | '.join(admises)})")
            valeur = defaut_nu
        if valeur not in admises:
            raise ValueError(f"valeur {valeur!r} inconnue pour {drapeau} "
                             f"(admises : {' | '.join(admises)})")
        options[drapeau[2:]] = valeur
    return options, position


def _choisir_moteur(moteur: str) -> tuple[str, object, str]:
    """Résout `auto` et instancie le fournisseur. Retourne (moteur, fournisseur, note).

    `auto` n'est jamais une surprise : sans canal configuré on reste déterministe et on
    le DIT (la note est affichée). Silencieux, l'utilisateur croirait à un LLM.
    """
    if moteur == "llm":
        import fournisseurs_llm
        return "llm", fournisseurs_llm.Groq(), ""
    if moteur == "auto":
        if os.environ.get("GROQ_API_KEY"):
            import fournisseurs_llm
            return "llm", fournisseurs_llm.Groq(), ""
        return "deterministe", None, (
            "aucun canal LLM configuré (GROQ_API_KEY absent) — moteur déterministe")
    return "deterministe", None, ""


def _valeurs_secretes_par_provider(src_run: Path) -> dict:
    """Les valeurs que chaque outil a LUI-MÊME désignées comme secrètes.

    Lu dans `raw_<provider>.json` (la sortie déjà parsée) d'après la déclaration du
    manifest (`champs_secrets`). Deux choses sont ainsi réunies sans que le cœur ait à
    connaître un seul outil : l'outil sait où est le secret, le manifest le déclare.
    """
    try:
        from registre import Registry
        reg = Registry()
    except Exception:                                      # noqa: BLE001 - registre illisible
        return {}
    out: dict = {}
    for f in sorted(src_run.glob("raw_*.json")):
        pid = f.name[len("raw_"):-len(".json")]
        try:
            prov = reg.provider(pid)
            champs = getattr(getattr(getattr(prov, "manifest", None), "extraction", None),
                             "champs_secrets", None)
            if not champs:
                continue
            valeurs = ASS.valeurs_secretes(
                json.loads(f.read_text(encoding="utf-8")), champs)
        except Exception:                                  # noqa: BLE001 - provider sans manifest
            continue
        if valeurs:
            out[pid] = valeurs
    return out


def _publier_sorties(src_run: Path, dossier: Path) -> dict:
    """Applique la politique de conservation aux sorties d'outils, et les publie.

    UN SEUL corps, appelé par les DEUX destinations (le bundle ET l'archive de mission).
    C'est tout l'objet de la fonction : la politique n'était appliquée qu'au bundle, et
    l'archive de mission partait avec les secrets en clair — mesuré le 31/08/2026 sur
    `artifacts/missions/…/sortie/raw_trufflehog3.json`, jamais examiné.

    Trois issues, et elles ne se disent pas de la même façon :
      · sûr                        → copié tel quel ;
      · masqué ET VÉRIFIÉ propre   → publié sous `*.redacted*` ;
      · masqué mais encore sale    → NON PUBLIÉ : empreinte et motif, jamais la valeur.
    Le troisième cas est la raison d'être de la vérification (see `Verdict.assaini`) :
    un artefact qui fuit ne doit pas porter un nom qui prétend le contraire.
    """
    dossier.mkdir(parents=True, exist_ok=True)
    valeurs = _valeurs_secretes_par_provider(src_run)
    conservation: dict = {}
    # `raw_*.json` (ce que le cœur a compris) ET `brut_*` (ce que l'outil a écrit) : les
    # deux sont des sorties d'outil, donc les deux passent par le même examen. Oublier les
    # seconds ferait sortir du dépôt une valeur non masquée — c'est précisément le défaut
    # que test_bundle cherche.
    for f in sorted(list(src_run.glob("raw_*.json")) + list(src_run.glob("brut_*"))):
        # `raw_<pid>` et `brut_<pid>` parlent du même outil : les valeurs valables pour
        # l'un le sont pour l'autre, et c'est le brut — non retraité — qui a le plus de
        # chances de porter la valeur en clair.
        pid = next((p for p in valeurs
                    if f.name.startswith(f"raw_{p}.") or f.name.startswith(f"brut_{p}.")), "")
        v = ASS.examiner_fichier(f, valeurs=valeurs.get(pid, ()))
        if v.sur:
            shutil.copy2(f, dossier / f.name)
        elif v.assaini:
            nom = f.name.replace(".json", "") + ".redacted" + (
                ".json" if f.suffix == ".json" else f.suffix)
            (dossier / nom).write_text(v.texte_masque, encoding="utf-8")
        else:
            nom = f.stem + ".non_publie.json"
            (dossier / nom).write_text(json.dumps({
                "_non_publie": ("sortie NON publiée : au moins un motif de secret subsiste "
                                "après masquage. La valeur n'est pas diffusée ; l'empreinte "
                                "permet de retrouver la sortie d'origine."),
                "fichier": f.name, "digest": v.digest,
                "taille": v.taille, "occurrences": v.occurrences,
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        conservation[f.name] = ({
            "raw_output": v.to_dict(),
            **({"sanitized_output": {
                "path": (f.name.replace(".json", ".redacted.json") if v.assaini
                         else f.stem + ".non_publie.json"),
                "redactions": v.occurrences,
            }} if not v.sur else {}),
        })
    return conservation


def _archiver_mission(e, cible: Path) -> Path | None:
    """Copie les preuves de l'exécution SOUS le dossier de la mission (append-only).

    Le bundle `artifacts/<digest>/<plan>/<run>/` reste la référence technique. Cette
    archive répond à une autre question — « qu'a produit CETTE mission ? » — et évite
    qu'une mission suivante écrase les preuves de la précédente. Les objets
    d'exécution (plan, findings, clusters, rapport, run) sont réécrits depuis `e` :
    `pipeline.executer()` les retourne sans les écrire, c'est ce module qui le fait.
    """
    if not e.mission:
        return None
    sortie = MS.MISSIONS / e.mission / "sortie"
    sortie.mkdir(parents=True, exist_ok=True)
    # Réalignement : la source est le répertoire de travail DE CETTE mission (`e.sortie`,
    # posé par le pipeline), pas le chemin global `RACINE/run` — mais la politique de
    # conservation reste CELLE DU BUNDLE : une archive de mission qui échappe à
    # l'assainissement est une fuite rangée dans un autre tiroir.
    src_run = Path(e.sortie) if getattr(e, "sortie", "") else None
    if src_run and src_run.exists():
        _publier_sorties(src_run, sortie)
    for nom, objet in (("plan", e.plan), ("findings", e.findings),
                       ("clusters", e.clusters), ("rapport", e.rapport),
                       ("intent", e.intent)):
        (sortie / f"{nom}.json").write_text(
            json.dumps(objet, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8")
    (sortie / "run.json").write_text(json.dumps({
        "run_id": e.run_id, "profil": e.profil,
        "plan_id": e.plan.get("plan_id"),
        "input_digest": e.contexte.get("input_digest"),
        "input_commit": e.contexte.get("input_commit", ""),
        "working_tree_dirty": e.contexte.get("working_tree_dirty", False),
        "execution_context_digest": e.contexte.get("contexte_empreinte"),
        "result_digest": e.result_digest,
        "contexte": e.contexte, "chemin": e.chemin,
    }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if not e.arret:
        (sortie / "RAPPORT.md").write_text(RH.generer(e, cible), encoding="utf-8")
    return sortie


def lancer(mission: str, cible: Path, moteur: str = "auto",
           fournisseur=None, confiance: str = "controlled",
           egress: bool | None = None) -> tuple[int, dict]:
    """Exécute une mission de bout en bout. Retourne (code_sortie, résumé).

    API pour les tests : elle ne passe PAS par le bundle Phase 4 (pas d'écriture dans
    artifacts/<digest>/), seulement par l'archive de mission. Le bundle est testé par
    test_bundle.py via la CLI.

    `confiance` est transmis tel quel à `pipeline.executer(confiance_cible=...)` : une
    valeur hors `pipeline.CONFIANCES` est refusée par le pipeline (PipelineError), ici
    comme partout — la CLI la intercepte plus tôt, la bibliothèque la lève.
    """
    cible = Path(cible)
    if not cible.exists():
        return 1, {"statut": "erreur", "motif": f"cible introuvable : {cible}"}

    if moteur == "auto":
        moteur, fournisseur_auto, _ = _choisir_moteur(moteur)
        if fournisseur is None:
            fournisseur = fournisseur_auto

    # Le moteur est passé EN PARAMÈTRE, plus posé sur des globales de module : deux missions
    # concurrentes peuvent choisir deux moteurs différents sans se réécrire l'une l'autre
    # (multi-mission, 2026-08-30). `pipeline.executer` lit `moteur_intent`/`fournisseur_llm`
    # locaux et ne mute plus `pipeline.MOTEUR_INTENT`/`FOURNISSEUR_LLM`.
    e = pipeline.executer(mission, cible, confiance_cible=confiance, egress=egress,
                          moteur_intent=moteur,
                          fournisseur_llm=fournisseur if moteur == "llm" else None)

    sortie = _archiver_mission(e, cible)
    resume = {
        "statut": e.arret or "complet",
        "moteur": (e.intent or {}).get("moteur", ""),
        "confiance_cible": confiance,
        # L'état de la garde d'export fait partie du résumé : un run mené cage ouverte doit
        # se reconnaître depuis l'appelant (CLI, interface), pas seulement en ouvrant le journal.
        "egress": dict(e.egress or {}),
        "mission": e.mission,
        "findings": len(e.findings),
        "clusters_inter_outils": len((e.clusters or {}).get("clusters_inter_outils") or []),
        "question": (e.intent or {}).get("question", ""),
        "motif": (e.intent or {}).get("motif", "") or "; ".join(
            (e.decision or {}).get("motifs") or []),
        "rapport": str(sortie / "RAPPORT.md") if (sortie and not e.arret) else None,
        "sortie": str(sortie) if sortie else None,
    }
    return (0 if not e.arret else 2), resume


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1

    try:
        options, args = _options_depuis_argv(argv[1:])
    except ValueError as e:
        print(f"ERREUR : {e}")
        return 1

    # Point de bootstrap applicatif : une seule fois par processus CLI, avant le
    # premier Registry(). `lancer()` (API bibliothèque) est appelé par interface.main
    # qui réalise le même bootstrap, pas par chaque mission.
    initialiser_extensions()

    moteur = options.get("moteur", "auto")
    # Défaut historique conservé — mais il est AFFICHÉ plus bas : muet, ce serait faire
    # croire qu'une cible a été jugée fiable alors qu'elle n'a simplement pas été posée.
    confiance = options.get("confiance", "controlled")
    confiance_explicite = "confiance" in options
    egress = _booleen(options, "egress")
    egress_explicite = "egress" in options

    cible = Path(args[0]).resolve()
    requete = args[1] if len(args) > 1 else "Analyse la sécurité de mon dépôt"

    moteur, fournisseur, note = _choisir_moteur(moteur)

    if not cible.exists():
        print(f"ERREUR : cible introuvable : {cible}")
        return 1

    print(f"cible   : {cible}")
    print(f"requete : {requete}")
    print(f"moteur  : {moteur}" + (f" ({note})" if note else ""))
    print(f"confiance : {confiance}" + ("" if confiance_explicite else
          "  (défaut — aucune évaluation de la cible n'a été faite ; "
          "--confiance=untrusted pour un dépôt non fiable)"))
    # Ce que la cage laisse sortir est affiché avec ce qu'elle laisse lire : un run dont
    # l'outil a pu joindre PyPI n'a pas la même portée qu'un run hors réseau, et l'opérateur
    # l'apprend en lisant la sortie, pas en relisant le code du profil.
    print("egress  : " + ("NON DEMANDÉ — le profil fait foi (cage `--unshare-net`)"
                          if not egress_explicite else
                          ("ACCORDÉ pour cette mission — les outils marqués `reseau: true` "
                           "seront lancés hors du réseau coupé" if egress else
                           "REFUSÉ explicitement — même un profil qui autorise la sortie "
                           "reste coupé")))
    print()
    # Note : le moteur EFFECTIF n'est connu qu'après exécution — un LLM injoignable
    # retombe sur le déterministe. Il est affiché plus bas, dans le résumé.

    try:
        e = pipeline.executer(requete, cible, confiance_cible=confiance, egress=egress,
                              moteur_intent=moteur,
                              fournisseur_llm=fournisseur if moteur == "llm" else None)
    except Exception as exc:                       # noqa: BLE001
        # Un refus d'exécution est une INFORMATION, pas une panne : « quelle dépendance
        # manque, quels outils étaient prêts » se lit sans décoder un traceback. Une panne
        # qui n'est PAS un refus garde son traceback complet — ici on n'étouffe rien.
        etat = getattr(exc, "agnt_refus", None)
        if etat is None:
            raise
        print(f"REFUS D'EXÉCUTION · {type(exc).__name__} : {exc}")
        # La portée demandée est rappelée DANS le bloc de refus : c'est lui qu'on colle dans un
        # ticket, trois écrans plus bas. Sans cette ligne, un refus de mission menée cage ouverte
        # se relit comme une mission ordinaire.
        eg = etat.get("egress") or {}
        if eg:
            print("cage     : " + (
                f"sortie réseau ACCORDÉE à cette mission (profil {eg.get('profil') or '?'}, "
                f"demande {eg.get('demande') or '?'}"
                + (", par délégation" if eg.get("delegation") else "") + ")"
                if eg.get("autorise") else
                f"réseau coupé pour tous les outils (profil {eg.get('profil') or '?'}, "
                f"demande {eg.get('demande') or '?'})"))
        resume = etat.get("resume") or {}
        comptes = " · ".join(f"{k} {v}" for k, v in resume.items() if v)
        if comptes:
            print(f"outils : {comptes}")
        for prov, motif in (etat.get("conditions") or {}).items():
            print(f"conditions refusées : {prov} — {motif}")
        plan = etat.get("plan") or {}
        if plan.get("providers"):
            print(f"plan {plan.get('plan_id')} · providers : {', '.join(plan['providers'])}")
        for o in (etat.get("statuts") or []):
            print(f"  – {str(o.get('provider'))[:18]:18} {str(o.get('statut'))[:16]:16} "
                  f"{str(o.get('raison') or '')[:110]}")
        if etat.get("mission"):
            print(f"journal : {etat['mission']}")
        print("\nAucune exécution, aucun rapport produit. Code de sortie 2.")
        return 2

    # ---------------------------------------------------- arrêt avant exécution
    if e.arret:
        print(f"STATUT : {e.arret}")
        if e.intent.get("question"):
            print(f"\nQUESTION : {e.intent['question']}")
        if e.intent.get("motif"):
            print(f"\nMOTIF : {e.intent['motif']}")
        motifs = (e.decision or {}).get("motifs") or []
        if motifs:
            print(f"\nMOTIFS POLICY : {'; '.join(motifs)}")
            print(f"confiance appliquée : {confiance} · profil : {e.profil or '—'}")
        print("\nAucune exécution, aucun plan, aucun outil lancé.")
        return 2

    # ---------------------------------------------------- bundle
    dossier = (ARTIFACTS / e.contexte["input_digest"] / e.plan["plan_id"] / e.run_id)
    dossier.mkdir(parents=True, exist_ok=True)

    # DEUX rapports, deux publics :
    #   rapport.md         l'ingénieur qui vérifie
    #   rapport_humain.md  la personne qui décide quoi corriger
    md = R.generer(e, cible)
    (dossier / "rapport.md").write_text(md, encoding="utf-8")
    (dossier / "rapport_humain.md").write_text(RH.generer(e, cible), encoding="utf-8")
    (dossier / "plan.json").write_text(
        json.dumps(e.plan, ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "findings.json").write_text(
        json.dumps(e.findings, ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "clusters.json").write_text(
        json.dumps(e.clusters, ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "run.json").write_text(
        json.dumps({"execution_profile": e.profil, "confiance_cible": confiance,
                    "egress": e.egress,
                    "plan_id": e.plan["plan_id"],
                    "input_digest": e.contexte.get("input_digest"),
                    "input_commit": e.contexte.get("input_commit"),
                    "working_tree_dirty": e.contexte.get("working_tree_dirty"),
                    "execution_context_digest": e.contexte.get("contexte_empreinte"),
                    "run_id": e.run_id,
                    "result_digest": e.result_digest,
                    "contexte": e.contexte, "chemin": e.chemin},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (dossier / "rapport.sarif").write_text(
        json.dumps(sarif(e.findings, e.run_id, e.plan["plan_id"]),
                   ensure_ascii=False, indent=2), encoding="utf-8")

    # Étape 6 : mêmes preuves, vues depuis la mission plutôt que depuis le plan.
    sortie_mission = _archiver_mission(e, cible)

    # ---------------------------------------------------------- politique de conservation
    # Conserver la donnée brute si elle est sûre ; sinon conserver son empreinte, ses
    # métadonnées et une version masquée. Un secret en clair dans nos artefacts serait
    # une fuite que NOUS créons — constaté pour de vrai avec Bandit.
    # Réalignement : la source est le répertoire de travail DE CETTE mission (`e.sortie`),
    # pas un chemin global partagé — sinon la mission suivante, en exécutant, effacerait ce
    # que celle-ci s'apprête à examiner. La politique reste `_publier_sorties` (corps
    # unique bundle/archive, raw_* ET brut_* examinés) — l'ancienne boucle inline de la
    # ligne CORE ombrait la variable `cible` et laissait le manifeste pointer sur un
    # fichier redacted au lieu de la cible.
    src_run = Path(e.sortie)
    conservation = _publier_sorties(src_run, dossier)

    manifeste = {
        "genere_le": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "requete": requete,
        "requete_canonique": e.plan.get("requete_canonique"),
        "request_id": e.plan.get("request_id"),
        "cible": str(cible),
        "profil": e.profil,
        # Pas seulement « quel profil » : ce que la policy a vu de LA cible. Un refus
        # pour mémoire non bornée ne se comprend qu'avec la confiance appliquée.
        "confiance_cible": confiance,
        "decision_policy": e.decision,
        "moteur_intent": e.intent.get("moteur"),
        "identifiants": {
            "plan_id": e.plan["plan_id"],
            "input_digest": e.contexte.get("input_digest"),
            "input_commit": e.contexte.get("input_commit"),
            "execution_context_digest": e.contexte.get("contexte_empreinte"),
            "run_id": e.run_id,
            "result_digest": e.result_digest,
        },
        "intent": e.intent,
        "providers": e.rapport.get("providers"),
        "couverture": e.rapport.get("couverture"),
        "statuts": list(getattr(e, "statuts", []) or []),
        "statuts_resume": ST.resumer(getattr(e, "statuts", []) or []),
        "observations": len(e.findings),
        "clusters": len(e.rapport.get("clusters", [])),
        "clusters_inter_outils": len(e.clusters.get("clusters_inter_outils", [])),
        "non_regroupe": len(e.clusters.get("non_regroupe", [])),
        "conservation_des_sorties": conservation,
        "artefacts": sorted(p.name for p in dossier.iterdir()),
    }
    (dossier / "manifeste.json").write_text(
        json.dumps(manifeste, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---------------------------------------------------- résumé console
    print("=" * 62)
    print(f"  {len(e.findings)} observations · {len(e.rapport['clusters'])} clusters"
          f" · {len(e.clusters.get('clusters_inter_outils', []))} inter-outils")
    print(f"  plan {e.plan['plan_id']} · run {e.run_id} · result {e.result_digest}")
    print("=" * 62)
    print(f"\nartefacts : {dossier.relative_to(RACINE)}")
    for p in sorted(dossier.iterdir()):
        print(f"    {p.name:<20} {p.stat().st_size:>9,} o")
    reel = e.intent.get("moteur", "")
    if reel and not reel.startswith(moteur):
        print(f"moteur effectif  : {reel}  (le {moteur} demandé n'a pas abouti)")
    print(f"\npour un humain   : {dossier / 'rapport_humain.md'}")
    print(f"rapport complet  : {dossier / 'rapport.md'}")
    if sortie_mission:
        print(f"mission {e.mission} : {sortie_mission.relative_to(RACINE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

