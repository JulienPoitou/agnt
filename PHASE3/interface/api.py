#!/usr/bin/env python3
"""API HTTP de l'interface AGNT — une surcouche, pas un cœur.

Ce fichier ne décide rien. Il reçoit trois choses (cible, question, confiance), les
transmet à `analyser.lancer()` — la même fonction que les tests et que la CLI — puis
relit l'archive de mission que ce module écrit déjà. Aucune logique de sécurité n'est
dupliquée ici : si elle existait ici, elle serait contournable par la CLI.

Trois lois de ce fichier :

1. **Une exécution à la fois.** La file à un consommateur sérialise les runs : l'écriture
   des artefacts est désormais PAR MISSION (`<mission>/run`, posé par le pipeline), donc
   deux runs ne se réécrivent plus — mais cette interface garde la file parce qu'elle
   reste la borne de simplicité et de visibilité de ce service (un run en cours se lit,
   le suivant attend). Ce n'est plus un garde-fou contre un répertoire partagé, c'est un
   choix d'ordonnancement assumé.
2. **La cible est un chemin, jamais un nom.** `GET /api/cibles` renvoie une liste ;
   `POST /api/runs` ne prend qu'un chemin de cette liste (le nom → 400). Ce n'est pas une
   micro-optimisation : la cage monte `--ro-bind / /`, donc ce qui limite la lecture, c'est
   ce qu'on autorise, pas ce qu'on sandboxe.
3. **Un refus est un résultat.** `PolicyError`, `PipelineError`, outil absent, cible
   introuvable : tout remonte dans `statut` + `motif`, jamais en 500 muet et jamais en
   « 0 constat ». Une interface qui masque un refus fabrique une fausse assurance.

Démarrage :

    python3 PHASE3/interface/api.py            # 127.0.0.1:8141
    python3 PHASE3/interface/api.py --host 0.0.0.0 --port 8141

Aucune dépendance : `http.server` + `threading` + `queue`, parce qu'un service de plus à
installer est une surface de plus à justifier (§2 du projet).
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ICI = Path(__file__).resolve().parent
RACINE = ICI.parent                      # PHASE3/
DEPOT = RACINE.parent                     # racine du repo
sys.path.insert(0, str(RACINE))            # pour `import analyser`
sys.path.insert(0, str(RACINE / "slice"))  # pour `import pipeline`, `profils`, …

TAILLE_MAX_REQUETE = 4000   # garde d'entrée, pas le correctif F5 (la borne portante est
                            # la taille du corps sortant, côté fournisseur)
PLAFOND_CORPS = 262_144     # plafond de lecture du corps AVANT rfile.read : Content-Length
                            # est déclaré par le client et ne doit jamais piloter la RAM.

# Chaîne web V1 (docs/WEB_PENTEST_V1_SPEC.md) : ordre d'exécution x débit max
# déclaratif. DOCUMENTED ONLY : ces débits sont la spec, pas une mesure.
WEB_PROVIDERS_ORDRE = {"httpx": 50, "katana": 20, "ffuf": 30, "nuclei": 30}

# Règles épinglées montées à {REGLES} pour les providers web (template nuclei
# d'épreuve, wordlist ffuf) — empreintes dans manifeste_dependances.yaml, preuves
# d'exécution dans cible_web/qualif/. Absent → {REGLES} reste vide : les providers
# qui l'exigent échoueront NOMMÉMENT à l'exécution, pas au plan.
REGLES_WEB = RACINE / "regles_web"

# Cibles proposables. Règle : un dépôt DÉJÀ sur cette machine, sous le dépôt de travail ou
# listé dans AGNT_CIBLES (séparateur « : »). Pas de clonage, pas de téléchargement : cela
# ajouterait une écriture et un réseau sortant que rien ici n'a été conçu pour border.
def cibles_admises() -> list[dict]:
    hors = [Path(p) for p in os.environ.get("AGNT_CIBLES", "").split(":") if p.strip()]
    candidats = [RACINE / "testrepo", RACINE / "testrepo_vuln",
                 RACINE / "cible_independante", RACINE / "labo_securite",
                 RACINE / "dogfooding"] + hors
    out = []
    for c in candidats:
        try:
            c = c.resolve()
        except OSError:
            continue
        if not c.is_dir():
            continue
        sous_de = any(c.is_relative_to(base) for base in (RACINE, DEPOT)) or c in hors
        if not sous_de:
            continue
        try:
            entrees = sorted(p.name for p in c.iterdir())[:6]
            langages = _devine_langages(c)
        except OSError:
            # Un candidat illisible (symlink cassé, droit refusé) ne doit pas tomber
            # toute la route : la cible est comptée, ses détails restent vides.
            entrees, langages = [], []
        out.append({"nom": c.name, "chemin": str(c),
                    "fichiers_vus": entrees,
                    "langages": langages})
    return out


def _devine_langages(c: Path) -> list[str]:
    indices = {".py": "python", ".go": "go", ".js": "javascript", ".ts": "typescript",
               ".tf": "terraform", ".yaml": "iac", ".yml": "iac", ".java": "java"}
    vus: set[str] = set()
    try:
        candidats = list(c.rglob("*"))[:400]
    except OSError:
        return []                    # arbre partiellement illisible : aucun langage déclaré
    for p in candidats:
        try:
            fichier = p.is_file()
        except OSError:
            continue                             # entrée inscanable (symlink, droit) : sautée
        if fichier:
            v = indices.get(p.suffix.lower())
            if v:
                vus.add(v)
        if len(vus) >= 5:
            break
    return sorted(vus)


# --------------------------------------------------------------------------- file de travail
# dict en mémoire : un run ne survit pas au processus, ses PREUVES oui (archive de mission).
ETATS: dict[str, dict] = {}
VERROU = threading.Lock()
FILE: queue.Queue = queue.Queue()


# --------------------------------------------------------------------------- ledger vivant
# Ce que l'écran affiche PENDANT une mission. Il n'y a aucun état intermédiaire inventé ici :
# les six étapes sont écrites par le moteur dans `journal.jsonl` (un événement `statuts` à
# chaque départ d'outil) et cette fonction se borne à relire la DERNIÈRE de ces lignes.
# Conséquence assumée : ce que l'opérateur voit à l'écran et ce qui est archivé à la fin sont
# issus du même fichier, lu par le même chemin de dérivation (slice.statuts).
FENETRE_TAILLE = 256 * 1024


def _derniere_ligne(chemin: Path, type_recherche: str) -> dict | None:
    """La dernière ligne `type_recherche` d'un JSON Lines, lue par la fin du fichier."""
    try:
        with chemin.open("rb") as f:
            f.seek(0, 2)
            n = f.tell()
            f.seek(max(0, n - FENETRE_TAILLE))
            bloc = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    for ligne in reversed(bloc.splitlines()):
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            o = json.loads(ligne)
        except ValueError:
            # L'architecture de journalisation interdit le demi-événement (write+flush
            # atomique sous verrou). Une ligne illisible est donc un fichier abîmé : on la
            # passe sans la faire passer pour un état, et la suivante est essayée.
            continue
        if o.get("type") == type_recherche:
            return o
    return None


def _vivante(question: str, cible: str, depuis: float) -> dict | None:
    """L'état en cours de la mission correspondant à ce run, ou `None` s'il n'existe pas encore.

    `depuis` est l'horodatage de la mise en file. Sans ce filtre, un run dont la mission
    n'est pas encore créée relirait le journal d'une MISSION PRÉCÉDENTE à la même question et
    afficherait son avancement comme s'il s'agissait du sien : c'est le seul mensonge
    possible de ce chemin, donc c'est la première chose qui est gardée (testée).
    """
    try:
        # `import mission`, et pas `from slice import mission` : `RACINE` et `RACINE/slice`
        # sont tous les deux sur sys.path, donc les deux orthographes chargent DEUX objets
        # module distincts. Pour une lecture de chemin c'est invisible ; pour un patch de test
        # (ou un verrou de journal partagé) c'est un silo. Le pipeline, lui, importe `mission`.
        import mission as _ms
    except Exception:                                   # noqa: BLE001
        return None                                     # pas de slice importable : pas de ledger
    dossier = getattr(_ms, "MISSIONS", None)
    if dossier is None or not dossier.is_dir():
        return None
    retenue = None
    for d in sorted(dossier.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        tete = d / "mission.json"
        if not tete.is_file():
            continue
        try:
            if tete.stat().st_mtime < depuis - 0.5:
                continue                                # mission antérieure à ce run
            ent = json.loads(tete.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if ent.get("requete") != question:
            continue
        if str((ent.get("cible") or {}).get("chemin") or "") not in (cible, str(Path(cible))):
            continue
        retenue = d
        break
    if retenue is None:
        return None
    ev = _derniere_ligne(retenue / "journal.jsonl", "statuts")
    if ev is None:
        return None
    ev = dict(ev)
    ev["mission"] = retenue.name
    ev["dossier"] = str(retenue)
    return ev


def _mission_recente(question: str, cible: str, depuis: float) -> str | None:
    """Le `mission_id` du dossier de mission correspondant à ce run, ou `None`.

    Même règle de correspondance que `_vivante` (question + cible + horodatage) —
    dernier recours quand ni le résumé ni l'objet de refus ne portent le mission_id.
    Ne rend jamais de chemin : seulement le nom du dossier."""
    try:
        import mission as _ms
    except Exception:                                   # noqa: BLE001
        return None
    dossier = getattr(_ms, "MISSIONS", None)
    if dossier is None or not dossier.is_dir():
        return None
    for d in sorted(dossier.iterdir(), reverse=True):
        if not d.is_dir() or d.is_symlink():
            continue
        tete = d / "mission.json"
        if not tete.is_file():
            continue
        try:
            if tete.stat().st_mtime < depuis - 0.5:
                continue
            ent = json.loads(tete.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if ent.get("requete") != question:
            continue
        if str((ent.get("cible") or {}).get("chemin") or "") not in (cible, str(Path(cible))):
            continue
        return d.name
    return None


def _mission_id_du_run(etat: dict) -> str | None:
    """Le `mission_id` durable associé à ce run, lu dans ce qui a été consigné.

    Le POST `/api/runs` rend un identifiant TEMPORAIRE de file ; le mission_id, lui,
    n'existe qu'une fois la mission ouverte. Il se lit dans le résumé (succès ou
    arrêt propre), sinon dans l'objet de refus (fail-closed), sinon par la règle de
    correspondance de `_mission_recente`. Champ ADDITIF : rien d'existant n'est
    modifié, aucun chemin n'est exposé."""
    resume = etat.get("resume") or {}
    if resume.get("mission"):
        return str(resume["mission"])
    donnees = etat.get("donnees") or {}
    run = donnees.get("run") or {}
    if run.get("mission"):
        return str(run["mission"])
    refus = etat.get("refus") or {}
    mp = refus.get("mission")
    if mp:
        try:
            return Path(mp).name
        except (TypeError, ValueError):
            return None
    return _mission_recente(etat.get("question") or "", etat.get("cible") or "",
                            float(etat.get("pose_le") or 0.0))


def _proprietaires_actifs() -> dict:
    """mission_id → statut de file prouvé (`en_file`/`en_cours`) pour les runs
    actuellement dans la file/ETATS. C'est la SEULE preuve de propriété en
    mémoire : sans elle, une mission sans événement terminal est `inconnu`."""
    actifs: dict = {}
    with VERROU:
        etats = [dict(e) for e in ETATS.values()]
    for etat in etats:
        if etat.get("statut") not in ("en_file", "en_cours"):
            continue
        mid = _mission_id_du_run(etat)
        if mid:
            actifs[mid] = etat["statut"]
    return actifs


def _marquer(rid: str, **champs) -> None:
    with VERROU:
        ETATS.setdefault(rid, {}).update(champs)


def _engagement_precedent(url_canonique: str, exclure: str):
    """Le rapport de l'engagement précédent sur la MÊME cible (le plus récent,
    hors le courant). Rend (id, {empreinte: {regle, url, etat}}) ou (None, None).

    La lecture est DISQUE seule : les archives survivent au processus (loi 1) et
    c'est elles qui portent l'historique — ETATS ne se souvient de rien. Une
    archive illisible est sautée, pas une panne."""
    racine = RACINE / "artifacts" / "engagements"
    if not racine.is_dir():
        return None, None
    candidats = []
    for d in racine.iterdir():
        if not d.is_dir() or d.is_symlink() or d.name == exclure:
            continue
        f = d / "rapport_web.json"
        if not f.is_file():
            continue
        try:
            ent = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if ent.get("url_canonique") != url_canonique:
            continue
        try:
            candidats.append((f.stat().st_mtime, d.name, ent))
        except OSError:
            continue
    if not candidats:
        return None, None
    candidats.sort()
    _, mid, ent = candidats[-1]
    precedents: dict = {}
    for f in ent.get("findings") or []:
        fp = ((f.get("identity") or {}).get("fingerprint")) or ""
        if fp:
            precedents[fp] = {"regle": (f.get("source") or {}).get("original_rule_id"),
                              "url": (f.get("location") or {}).get("url"),
                              "etat": (f.get("cycle") or {}).get("etat")}
    return mid, precedents


def _travail_web(rid: str, engagement: dict) -> None:
    """Exécute un engagement web mis en file (câblage ①-b, 2026-09-05).

    Toute la logique vit dans `pipeline_web.derouler` (scope → plans par manifest
    → orchestration séquencée → interprétation → cycle de vie → preuve scellée) :
    ce bloc ne fournit que le dossier d'archive, l'exécuteur local, et la
    retranscription HONNÊTE du résultat dans l'état de file — mêmes statuts que
    les runs dépôt, jamais un 200 muet. Les sorties brutes des outils et le
    rapport restent sur disque (artifacts/engagements/<id>/) : l'engagement ne
    survit pas au processus, ses PREUVES oui (loi 1).
    """
    _marquer(rid, statut="en_cours")
    dossier = RACINE / "artifacts" / "engagements" / rid
    try:
        import pipeline_web as PW
        from taches import ExecuteurLocal
    except Exception as e:                              # noqa: BLE001
        _marquer(rid, statut="erreur",
                 erreur={"type": type(e).__name__, "message": str(e)[:600],
                         "trace": traceback.format_exc(limit=6)},
                 resume={"motif": f"{type(e).__name__} : {str(e)[:280]}"})
        return
    try:
        exe = ExecuteurLocal(dossier)
        precedent_id, precedents = _engagement_precedent(
            str(engagement.get("url_canonique") or ""), rid)
        rapport = PW.derouler(engagement, exe.executer,
                              regles=str(REGLES_WEB) if REGLES_WEB.is_dir() else "",
                              out_dir=str(dossier),
                              precedent_id=precedent_id, precedents=precedents)
        (dossier / "rapport_web.json").write_text(
            json.dumps(rapport, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8")
        # `statut_run` est porté PAR le rapport (termine/arrete/refuse/…) : l'état
        # de file dit « le run d'engagement s'est terminé », le rapport dit ce qui
        # a vraiment tourné. Les confondre recacherait un échec d'outil derrière
        # un vert de file.
        _marquer(rid, statut="termine", rapport=rapport, sortie=str(dossier),
                 statut_run=rapport.get("statut_run"),
                 findings=rapport.get("findings"))
    except PW.ErreurPipeline as e:
        _marquer(rid, statut="refuse",
                 resume={"motif": f"ErreurPipeline : {str(e)[:280]}"})
    except Exception as e:                              # noqa: BLE001
        _marquer(rid, statut="erreur",
                 erreur={"type": type(e).__name__, "message": str(e)[:600],
                         "trace": traceback.format_exc(limit=6)},
                 resume={"motif": f"{type(e).__name__} : {str(e)[:280]}"})


def _travail() -> None:
    """Un seul consommateur : c'est ce qui sérialise les runs (voir loi 1)."""
    while True:
        rid, question, cible, options = FILE.get()
        if options.get("genre") == "web":
            try:
                _travail_web(rid, options.get("engagement") or {})
            finally:
                FILE.task_done()
            continue
        _marquer(rid, statut="en_cours")
        try:
            import analyser
            fournisseur = None
            moteur = options.get("moteur", "auto")
            modele = (options.get("modele") or "").strip()
            if moteur == "llm" and modele:
                import fournisseurs_llm
                # `Groq.modele` est un champ du fournisseur : le choix du modèle descend
                # ici et nulle part ailleurs. Aucun modèle n'est inventé — la liste est
                # lue dans `capacites()` pour que l'interface ne propose que l'existant.
                fournisseur = fournisseurs_llm.Groq(modele=modele)
            code, resume = analyser.lancer(question, Path(cible), moteur=moteur,
                                           fournisseur=fournisseur,
                                           confiance=options.get("confiance", "controlled"),
                                           egress=options.get("egress"),
                                           cible_autorisee=options.get("cible_autorisee", False))
            sortie = resume.get("sortie")
            donnees = _charger(sortie) if sortie else None
            if donnees is not None:      # le résumé du moteur complète l'archive, sans la contredire
                for k in ("mission", "statut", "moteur", "confiance_cible", "egress",
                          "findings", "clusters_inter_outils", "question", "motif", "rapport"):
                    if resume.get(k) is not None:
                        donnees["run"][k] = resume[k]
            _marquer(rid, statut=("termine" if code == 0 else "refuse"),
                     code=code, resume=resume, sortie=sortie, donnees=donnees)
        except Exception as e:                    # noqa: BLE001 — un échec doit être LISIBLE
            # Deux choses différentes, à ne pas confondre à l'écran : la politique a REFUSÉ
            # (le garde-fou a fonctionné, y compris quand il n'a pas pu rendre de décision),
            # ou l'exécution a PLANTÉ ailleurs. Un refus affiché comme une panne ferait passer
            # la frontière pour le problème.
            nom = type(e).__name__
            refus = nom == "PolicyError"
            detail = {"type": nom, "message": str(e)[:600],
                      "trace": traceback.format_exc(limit=6),
                      "lecteur": ("refus fail-closed : la politique n'a pas pu autoriser "
                                  "cette exécution" if refus else
                                  "la mission n'est pas allée jusqu'à la décision de politique")}
            # L'état des outils est porté par l'exception de refus (voir pipeline.py) :
            # sans lui, l'écran affichait « binaire OPA introuvable » et se taisait sur les
            # outils absents ou refusés par leurs conditions — mesuré le 2026-08-30 sur un run
            # HTTP réel. Le journal le savait, la page ne le savait pas.
            etat = getattr(e, "agnt_refus", None)
            _marquer(rid, statut="refuse" if refus else "erreur", erreur=detail,
                     resume={"motif": f"{nom} : {str(e)[:280]}"},
                     **({"refus": etat} if etat else {}))
        finally:
            FILE.task_done()


# ----------------------------------------------------------------------- lecture de l'archive
def _charger(sortie: str) -> dict:
    """Reconstruit l'objet que l'interface affiche, À PARTIR des fichiers écrits par le
    moteur. Un champ absent du fichier est absent de la réponse : rien n'est déduit,
    complété ou mis à zéro pour faire plaisir au composant d'affichage."""
    d = Path(sortie)

    def lire(nom):
        f = d / nom
        if not f.exists():
            return None
        try:
            return json.loads(f.read_text(encoding="utf-8")) if f.suffix == ".json" \
                else f.read_text(encoding="utf-8")
        except (json.JSONDecodeError, OSError):
            return None

    rapport = lire("rapport.json") or {}
    plan = lire("plan.json") or {}
    run = lire("run.json") or {}
    intent = lire("intent.json") or {}
    # Un fichier absent n'est PAS un résultat vide : `None` veut dire « on ne sait pas »,
    # [] voudrait dire « les outils n'ont rien trouvé ». Confondre les deux est exactement
    # le défaut C/« 0 constat » que la campagne adverse a reprocué au projet.
    findings = lire("findings.json")
    clusters_fichiers = lire("clusters.json")
    return {
        # ce que le moteur a retenu et ce qu'il a écarté, mot pour mot
        "chaine": {
            "requete": rapport.get("requete"),
            # La forme canonique est portée par le PLAN, pas par le rapport. Mesuré le
            # 2026-08-30 : `plan.json` la contenait, l'écran la lisait (`app.js`, ligne
            # « forme canonique »), et le chargeur ne la recopiait jamais — la ligne était
            # morte, sans erreur, parce qu'entourée d'un garde. Un champ que l'archive porte
            # et que la page ne montre jamais est une perte d'information, pas un détail.
            "requete_canonique": plan.get("requete_canonique"),
            "capacites_demandees": rapport.get("capacites_demandees", []),
            "motifs_intent": rapport.get("motifs_intent", {}),
            "plan_id": rapport.get("plan_id"),
            "plan_empreinte": rapport.get("plan_empreinte"),
            "moteur_intent": plan.get("moteur_intent"),
            "cible": plan.get("cible"),
            "steps": plan.get("steps", []),
            "selection": plan.get("selection", {}),
            "providers": rapport.get("providers"),
            "autorisation": rapport.get("autorisation", {}),
            "couverture": rapport.get("couverture", {}),
            # Ledger des six étapes par outil (slice/statuts.py) : l'écran doit pouvoir
            # dire « non autorisé » séparément de « non demarré ». Absent = mission
            # antérieure au registre, pas un défaut d'affichage.
            "statuts": rapport.get("statuts"),
            # Escalade bornée (vague 2) : ce qui a été tenté en plus, et si la politique
            # l'a refusé. Une tentative invisible serait une tentative cachée.
            "escalades": rapport.get("escalades"),
        },
        "findings": findings,
        "findings_absents": findings is None,
        # clusters.json est la source complète (stats + inter-outils) ; rapport.json ne
        # porte que clusters/non_regroupe sous le nom `clustering` pour ses stats.
        "clusters": clusters_fichiers or {
            "clusters": rapport.get("clusters", []),
            "non_regroupe": rapport.get("non_regroupe", []),
            "stats": rapport.get("clustering", {}),
        },
        "contexte": run.get("contexte", {}),
        "run": {
            # L'archive s'appelle `missions/<id>/sortie` ; ailleurs (dossier de dogfooding,
            # réemploi manuel) le nom du père n'est PAS un identifiant de mission → on
            # l'affiche comme dossier, pas comme mission. Un nom de répertoire décoré en id
            # est une affirmation gratuite.
            "mission": d.parent.name if d.parent.name.startswith("m-") else None,
            "dossier": str(d),
            "run_id": run.get("run_id"),
            "plan_id": run.get("plan_id"),
            "input_digest": run.get("input_digest"), "input_commit": run.get("input_commit"),
            "working_tree_dirty": run.get("working_tree_dirty"),
            "moteur": intent.get("moteur"), "sortie": str(d),
            # Les deux faits de LOT 3 qui changent la portée d'un run : est-ce que la cage
            # laissait sortir, et combien d'outils ont été menés de front. Lus dans le rapport,
            # avec repli sur run.json (les deux l'écrivent), et jamais recomposés par déduction :
            # absent d'une archive = absent de l'écran.
            "egress": rapport.get("egress", run.get("egress")),
            "outils_par_vague": rapport.get("outils_par_vague", run.get("outils_par_vague")),
            # Défaut trouvé en branchant le cas 15 de `test_qualite_plateforme.py` :
            # `run.json` écrit la clé `execution_profile`, cet endroit lisait `profil` — le
            # profil d'exécution n'a donc jamais été affiché par la console, alors qu'il est la
            # source du `egress`. Les deux orthographes sont lues, celle de l'archive d'abord.
            "profil": run.get("execution_profile") or run.get("profil"),
        },
        "rapport_markdown": lire("RAPPORT.md") or "",
    }


# ------------------------------------------------------------------------------------ HTTP
class Gestionnaire(BaseHTTPRequestHandler):
    server_version = "agnt-interface/0"

    # ---- utilitaires
    def _json(self, objet, code=200):
        corps = json.dumps(objet, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corps)

    TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
             ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8"}

    def _fichier(self, nom: str, type_mime: str | None = None):
        # Le chemin est résolu PUIS contrôlé sous ICI : `..` et liens symboliques dehors
        # sont refusés, sinon cette page deviendrait un lecteur de fichiers du serveur.
        f = (ICI / (nom or "index.html")).resolve()
        type_mime = type_mime or self.TYPES.get(f.suffix.lower(), "")
        # is_relative_to, pas startswith : un voisin dont le nom partage le préfixe
        # (ex. interfaceX/) passait autrement.
        if not f.is_relative_to(ICI) or not type_mime or not f.is_file():
            self.send_error(404)
            return
        corps = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", type_mime)
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corps)

    # ---- lecture
    def do_GET(self):  # noqa: N802 (nom imposé par BaseHTTPRequestHandler)
        partie = urlparse(self.path)
        chemin = partie.path
        if chemin.startswith("/api/"):
            pass
        elif chemin in ("/", "/index.html"):
            return self._fichier("index.html")
        else:
            # un seul sens de lecture : les fichiers de CE dossier, et rien d'autre.
            return self._fichier(chemin.lstrip("/"))
        if chemin == "/api/cibles":
            return self._json({"cibles": cibles_admises()})
        if chemin == "/api/capacites":
            return self._json(_capacites())
        if chemin == "/api/engagements":
            return self._json({"engagements": _engagements()})
        if chemin == "/api/providers":
            return self._json(_fournisseurs())
        if chemin == "/api/missions":
            return self._missions(partie)
        if chemin.startswith("/api/missions/"):
            return self._mission_detail(partie)
        if chemin.startswith("/api/runs/"):
            rid = chemin.rsplit("/", 1)[-1]
            with VERROU:
                etat = dict(ETATS.get(rid) or {})
            if not etat:
                return self._json({"erreur": f"run inconnu : {rid}"}, 404)
            if etat.get("statut") in ("en_file", "en_cours"):
                etat = dict(etat)
                # `vivante` est absent (et non `null`) tant qu'il n'y a rien à lire : un écran
                # qui afficherait « aucun outil » avant même l'intention ferait croire à un
                # résultat. L'absence est le fait exact.
                v = _vivante(etat.get("question") or "", etat.get("cible") or "",
                             float(etat.get("pose_le") or 0.0))
                if v is not None:
                    etat["vivante"] = v
            # Deux champs ADDITIFS du lecteur d'historique : le mission_id durable (le `id`
            # du POST est un identifiant de file TEMPORAIRE) et le lien vers son détail.
            # Absents = mission pas encore ouverte (ou pas d'archive) : `null`, pas d'invention.
            mission_id = _mission_id_du_run(etat)
            reponse = {"id": rid, **etat,
                       "mission_id": mission_id,
                       "detail_href": f"/api/missions/{mission_id}" if mission_id else None}
            if etat.get("type") == "web":
                # Preuve portable scellée (slice/preuve.py) : additive, ne change
                # rien aux runs classiques. En échec : erreur nommée, pas d'omission.
                try:
                    import preuve as PR
                    reponse["preuve"] = PR.engagement_bundle(etat)
                except Exception as e:
                    reponse["preuve"] = {"erreur": f"preuve_non_construite : {type(e).__name__}"}
            return self._json(reponse)
        return self.send_error(404)

    # ---- lecture de l'historique (délégation au lecteur canonique, rien n'est projeté ici)
    def _missions(self, partie):
        """GET /api/missions — listing paginé. Toujours HTTP 200 ; `items` toujours
        présent ; vide = `{"items": []}`. Le tri, la pagination, les filtres et la
        projection vivent dans `slice/mission_history.py`."""
        import mission_history as MH
        qs = parse_qs(partie.query)
        inconnus = [k for k in qs if k not in ("limit", "cursor", *MH.FILTRES_V1)]
        if inconnus:
            return self._erreur("INVALID_FILTER",
                                "filtre inconnu : " + ", ".join(sorted(inconnus))
                                + " — admis : limit, cursor, " + ", ".join(MH.FILTRES_V1),
                                400)
        try:
            reponse = MH.lister(limit=(qs.get("limit") or [None])[0],
                                cursor=(qs.get("cursor") or [None])[0],
                                status=(qs.get("status") or [None])[0],
                                target_type=(qs.get("target_type") or [None])[0],
                                proprietaire=_proprietaires_actifs().get)
        except MH.RequeteInvalide as e:
            return self._erreur("INVALID_ARGUMENT", str(e), 400)
        return self._json(reponse)

    def _mission_detail(self, partie):
        """GET /api/missions/{mission_id} — le détail projeté, ou 404 SANS chemin."""
        import mission_history as MH
        mid = partie.path[len("/api/missions/"):]
        qs = parse_qs(partie.query)
        inconnus = [k for k in qs if k not in ("timeline_limit", "timeline_cursor")]
        if inconnus:
            return self._erreur("INVALID_FILTER",
                                "paramètre inconnu : " + ", ".join(sorted(inconnus))
                                + " — admis : timeline_limit, timeline_cursor", 400)
        try:
            reponse = MH.projeter(mid,
                                  timeline_limit=(qs.get("timeline_limit") or [None])[0],
                                  timeline_cursor=(qs.get("timeline_cursor") or [None])[0],
                                  proprietaire=_proprietaires_actifs().get)
        except MH.MissionIntrouvable:
            return self._erreur("MISSION_NOT_FOUND", "Mission introuvable", 404)
        except MH.RequeteInvalide as e:
            return self._erreur("INVALID_ARGUMENT", str(e), 400)
        return self._json(reponse)

    def _erreur(self, code, message, statut_http):
        """Enveloppe d'erreur du contrat History §10. Message redacté, jamais de
        chemin, jamais de trace."""
        return self._json({"error": {"code": code, "message": message}}, statut_http)

    # ---- écriture
    def do_POST(self):  # noqa: N802
        chemin = self.path.split("?", 1)[0]
        if chemin == "/api/engagements/web":
            return self._post_engagement_web()
        if chemin == "/api/verification":
            return self._post_verification()
        if chemin != "/api/runs":
            return self.send_error(404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > PLAFOND_CORPS:
                return self._json({"erreur": f"corps trop volumineux "
                                             f"({n} > {PLAFOND_CORPS} octets)"}, 413)
            corps = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return self._json({"erreur": "corps de requête : JSON attendu"}, 400)

        question = str(corps.get("question") or "").strip()
        cible = str(corps.get("cible") or "").strip()
        admises = {c["chemin"]: c for c in cibles_admises()}
        if cible not in admises:
            # Le message nomme l'alternative : un refus sans porte de sortie, en interface,
            # ça ressemble à une panne.
            return self._json({"erreur": "cible hors de la liste admise",
                               "admises": sorted(admises)}, 400)
        if not question:
            return self._json({"erreur": "question vide"}, 400)
        if len(question) > TAILLE_MAX_REQUETE:
            return self._json({"erreur": f"question trop longue ({len(question)} > "
                                         f"{TAILLE_MAX_REQUETE})"}, 400)
        confiance = str(corps.get("confiance") or "controlled")
        if confiance not in ("controlled", "untrusted"):
            return self._json({"erreur": f"confiance inconnue : {confiance}"}, 400)
        moteur = str(corps.get("moteur") or "auto")
        if moteur not in ("auto", "llm", "deterministe"):
            return self._json({"erreur": f"moteur inconnu : {moteur}"}, 400)
        # Un booléen, pas une chaîne : accepter `"false"` comme vrai serait le pire défaut
        # imaginable ici. Absent = le profil fait foi ; c'est `None`, pas `False`, parce que
        # « refusé » et « non demandé » ne sont pas le même fait et ne doivent pas se rendre
        # pareil dans le rapport.
        egress = corps.get("egress")
        if egress is not None and not isinstance(egress, bool):
            return self._json({"erreur": "egress : attendu true, false, ou absent"}, 400)
        cible_autorisee = corps.get("cible_autorisee")
        if cible_autorisee is not None and not isinstance(cible_autorisee, bool):
            return self._json({"erreur": "cible_autorisee : attendu true, false, ou absent"}, 400)

        rid = uuid.uuid4().hex[:12]
        with VERROU:
            # `pose_le` n'est pas un confort : c'est la borne qui empêche `_vivante` de
            # rattraper une mission antérieure portant la même question (voir sa docstring).
            ETATS[rid] = {"statut": "en_file", "question": question, "cible": cible,
                          "pose_le": time.time()}
        options = {"moteur": moteur, "confiance": confiance, "modele": corps.get("modele")}
        if egress is not None:
            options["egress"] = egress
        if cible_autorisee is not None:
            options["cible_autorisee"] = cible_autorisee
        FILE.put((rid, question, cible, options))
        # `position` est la TAILLE DE LA FILE au moment de l'insertion, pas le rang dans une
        # attente : avec un travailleur qui débite aussitôt, deux RUNs consécutifs indiquent
        # tous deux « 1 » (mesuré le 2026-08-30 par test_interface.py). Ce n'est pas un
        # mensonge — le second est bien premier de file, le premier étant EN COURS — mais le
        # nom invite à corriger le chiffre. Le nombre est juste, la file est à un occupant.
        return self._json({"id": rid, "statut": "en_file",
                           "position": FILE.qsize()}, 202)

    # ---- engagements web (H1 : planification ; exécution câblée sur demande explicite)
    def _post_engagement_web(self):
        """POST /api/engagements/web — déclare un engagement web app black-box.

        Valide et PLANIFIE toujours. `executer: true` (câblage 2026-09-05) met
        l'engagement EN FILE : le worker exécute la chaîne prévue via
        `pipeline_web.derouler` — même file à un consommateur que les missions
        dépôt (loi 1). Sans `executer`, le plan seul est rendu
        (`execution: "non_demandee"`) et rien ne part. Conventions reprises de
        /api/runs : refus nommés, 400 chiffrés, 202 + id.
        """
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > PLAFOND_CORPS:
                return self._json({"erreur": f"corps trop volumineux "
                                             f"({n} > {PLAFOND_CORPS} octets)"}, 413)
            corps = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return self._json({"erreur": "corps de requête : JSON attendu"}, 400)
        if not isinstance(corps, dict):
            return self._json({"erreur": "corps de requête : objet JSON attendu"}, 400)

        url = corps.get("url")
        if not isinstance(url, str) or not url.strip():
            return self._json({"erreur": "url vide",
                               "attendu": "https://cible.tld (schémas admis : http, https)"}, 400)
        url = url.strip()
        if len(url) > 2048:
            return self._json({"erreur": f"url trop longue ({len(url)} > 2048)"}, 400)
        try:
            from cible import Cible, CibleError, TYPE_URL
            cible = Cible(type=TYPE_URL, reference=url)
        except CibleError as e:
            return self._json({"erreur": f"cible refusée : {e}",
                               "attendu": "https://cible.tld (schémas admis : http, https)"}, 400)
        except Exception as e:                              # descripteur illisible = refus
            return self._json({"erreur": f"cible illisible : {type(e).__name__}"}, 400)
        from urllib.parse import urlsplit
        try:
            hote = urlsplit(url).hostname or ""
        except ValueError:
            hote = ""
        if not hote:
            return self._json({"erreur": "hôte manquant dans l'url",
                               "attendu": "https://cible.tld (avec un nom d'hôte)"}, 400)
        # Forme canonique (web_scope) : deux écritures du même endpoint donnent
        # le même engagement — persistance et dédup s'y réfèrent, jamais au brut.
        try:
            from web_scope import canonicaliser_url, hote_de
            url_canonique = canonicaliser_url(url)
            hote = hote_de(url_canonique)
        except Exception as e:
            return self._json({"erreur": f"url non canonicalisable : {e}"}, 400)

        # Autorisation EXPLICITE : sans `cible_autorisee: true`, pas d'engagement.
        # `false` ou absent = 403 nommé (doctrine F2), jamais un plan silencieux.
        if corps.get("cible_autorisee") is not True:
            return self._json({"erreur": "cible_non_autorisee",
                               "detail": "un engagement web exige cible_autorisee: true explicite",
                               "url_sure": cible.reference_sure()}, 403)
        egress = corps.get("egress")
        if egress is not None and not isinstance(egress, bool):
            return self._json({"erreur": "egress : attendu true, false, ou absent"}, 400)
        executer = corps.get("executer")
        if executer is not None and not isinstance(executer, bool):
            return self._json({"erreur": "executer : attendu true, false, ou absent"}, 400)
        intensity = str(corps.get("intensity") or "normal")
        if intensity not in ("normal", "aggressive"):
            return self._json({"erreur": f"intensity inconnue : {intensity}",
                               "admises": ["normal", "aggressive"]}, 400)
        demandes = corps.get("providers")
        if demandes is None:
            demandes = list(WEB_PROVIDERS_ORDRE)
        if (not isinstance(demandes, list) or not demandes
                or any(not isinstance(p, str) for p in demandes)):
            return self._json({"erreur": "providers : liste non vide attendue",
                               "admis": list(WEB_PROVIDERS_ORDRE)}, 400)
        inconnus = [p for p in demandes if p not in WEB_PROVIDERS_ORDRE]
        if inconnus:
            return self._json({"erreur": "providers inconnus : " + ", ".join(inconnus),
                               "admis": list(WEB_PROVIDERS_ORDRE)}, 400)
        try:
            from registre import Registry
            declares = {p.id for p in Registry().providers()}
            registre_ok = True
        except Exception:
            declares, registre_ok = set(), False
        plan_providers = [{"id": p,
                           "declare": (p in declares) if registre_ok else None,
                           "debit_max_rps": WEB_PROVIDERS_ORDRE[p]}
                          for p in WEB_PROVIDERS_ORDRE if p in demandes]

        eid = uuid.uuid4().hex[:12]
        engagement = {"statut": "en_file" if executer else "planifie", "type": "web",
                      "url_sure": cible.reference_sure(), "url_canonique": url_canonique,
                      "hote": hote,
                      "intensity": intensity,
                      "egress": egress, "cible_autorisee": True,
                      "executer": executer is True,
                      "providers_prevus": [p["id"] for p in plan_providers],
                      "verification": {
                          "oracle": "http_response",
                          "replay": 5 if intensity == "aggressive" else 3,
                          "temoin_controle": True},
                      "pose_le": time.time()}
        with VERROU:
            # Dédup PLAN SEUL uniquement : deux déclarations du même endpoint sans
            # exécution rendent le même plan. Une exécution, elle, est toujours un
            # NOUVEAU run — dédupliquer un engagement en cours masquerait une
            # exécution réelle derrière l'id d'un plan antérieur.
            deduplique = False
            if not executer:
                for pid, existant in ETATS.items():
                    if (existant.get("type") == "web"
                            and existant.get("url_canonique") == url_canonique
                            and existant.get("statut") == "planifie"):
                        reponse = dict(existant)
                        reponse["id"] = pid
                        reponse["deduplique"] = True
                        deduplique = True
                        break
            if not deduplique:
                ETATS[eid] = engagement
                reponse = {"id": eid, **engagement}
                if executer:
                    # Même file que les missions dépôt (loi 1 : une exécution à la
                    # fois) — c'est un choix d'ordonnancement, pas un garde-fou.
                    FILE.put((eid, None, None,
                              {"genre": "web", "engagement": engagement}))
        limites = (["exécution réelle demandée : binaires résolus dans le PATH du "
                    "service, hors cage bwrap à ce stade (limite du runtime web, "
                    "qualifications sous cage : cible_web/qualif/)",
                    "absence de correspondance ≠ absence de vulnérabilité"]
                   if executer else
                   ["plan seul : demander executer: true pour lancer la chaîne "
                    "httpx→katana→ffuf→nuclei (cible_autorisee reste exigée)",
                    "absence de correspondance ≠ absence de vulnérabilité"])
        return self._json({**reponse,
                           "verification": reponse.get("verification") or {
                               "oracle": "http_response",
                               "replay": 5 if intensity == "aggressive" else 3,
                               "temoin_controle": True},
                           "execution": "file" if executer else "non_demandee",
                           "limites_connues": limites,
                           "detail_href": f"/api/runs/{reponse['id']}"},
                          200 if reponse.get("deduplique") else 202)

    # ---- vérification oracle (jugement sur observations, sans exécution)
    def _post_verification(self):
        """POST /api/verification — juge des observations de rejeu (oracle_web).

        Pur jugement, aucune exécution : le client apporte les observations
        (digests, jamais de corps bruts). Rend verdict + événement cycle.
        """
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > PLAFOND_CORPS:
                return self._json({"erreur": f"corps trop volumineux "
                                             f"({n} > {PLAFOND_CORPS} octets)"}, 413)
            corps = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return self._json({"erreur": "corps de requête : JSON attendu"}, 400)
        if not isinstance(corps, dict):
            return self._json({"erreur": "corps de requête : objet JSON attendu"}, 400)
        try:
            import oracle_web as OW
            url = str(corps.get("url") or "").strip()
            if not url:
                return self._json({"erreur": "url vide"}, 400)
            intensity = str(corps.get("intensity") or "normal")
            if intensity not in ("normal", "aggressive"):
                return self._json({"erreur": f"intensity inconnue : {intensity}"}, 400)
            demandes = OW.DemandeVerification(
                url=url, expect_status=int(corps.get("expect_status", 200)),
                expect_body_contains=str(corps.get("expect_body_contains") or ""),
                control_url=str(corps.get("control_url") or ""), intensity=intensity)
            brutes = corps.get("observations")
            if not isinstance(brutes, list) or not brutes:
                return self._json({"erreur": "observations : liste non vide attendue"}, 400)
            observations = []
            for i, o in enumerate(brutes):
                if not isinstance(o, dict):
                    return self._json({"erreur": f"observations[{i}] : objet attendu"}, 400)
                try:
                    observations.append(OW.ObservationRejeu(
                        status=o.get("status"), body_digest=str(o.get("body_digest") or ""),
                        body_taille=int(o.get("body_taille", 0)),
                        contient_extrait=bool(o.get("contient_extrait", False)),
                        erreur=str(o.get("erreur") or "")))
                except (TypeError, ValueError):
                    return self._json({"erreur": f"observations[{i}] : forme invalide"}, 400)
            temoin = None
            if isinstance(corps.get("temoin"), dict):
                t = corps["temoin"]
                try:
                    temoin = OW.ObservationRejeu(
                        status=t.get("status"), body_digest=str(t.get("body_digest") or ""),
                        body_taille=int(t.get("body_taille", 0)),
                        contient_extrait=bool(t.get("contient_extrait", False)),
                        erreur=str(t.get("erreur") or ""))
                except (TypeError, ValueError):
                    return self._json({"erreur": "temoin : forme invalide"}, 400)
            jugement = OW.juger(demandes, observations, temoin)
            return self._json({"runtime_verified": OW.RUNTIME_VERIFIED, **jugement.to_dict()})
        except (TypeError, ValueError) as e:
            return self._json({"erreur": f"demande invalide : {e}"}, 400)

    def log_message(self, format, *args):        # journal court, sans données d'utilisateur
        sys.stderr.write("[interface] %s\n" % (args[0] if args else ""))


def _engagements() -> list[dict]:
    """Engagements web planifiés (ETATS en mémoire). Champs sûrs uniquement :
    `url_sure`/`url_canonique` (jamais de userinfo — voir web_scope)."""
    with VERROU:
        items = [(rid, dict(e)) for rid, e in ETATS.items() if e.get("type") == "web"]
    out = []
    for rid, e in items:
        out.append({"id": rid, "statut": e.get("statut"), "type": "web",
                    "url_sure": e.get("url_sure"), "url_canonique": e.get("url_canonique"),
                    "hote": e.get("hote"), "intensity": e.get("intensity"),
                    "providers_prevus": e.get("providers_prevus"),
                    "deduplique": bool(e.get("deduplique", False)),
                    "pose_le": e.get("pose_le")})
    return out


def _fournisseurs() -> dict:
    """Providers déclarés du registre (public uniquement : id, binaire, risque,
    cibles, timeout — ni argv ni chemins internes). Registre illisible =
    `registre_erreur` (même contrat que /api/capacites)."""
    try:
        from registre import Registry
        reg = Registry()
        return {"providers": [{"id": p.id, "binaire": p.manifest.binaire,
                               "risque": p.manifest.risque,
                               "cibles": list(p.manifest.cibles),
                               "timeout_s": int(p.manifest.timeout_s or 0)}
                              for p in reg.providers() if p.manifest is not None],
                "compte": sum(1 for p in reg.providers() if p.manifest is not None)}
    except Exception as e:
        return {"providers": [], "compte": 0,
                "registre_erreur": f"{type(e).__name__}: {str(e)[:200]}"}


def _capacites() -> dict:
    """Ce que l'interface a le DROIT de proposer. Lu dans le code, pas recopié : si le
    registre change, le menu change avec lui. Les capacités publiées seulement — le
    catalogue interne n'a rien à faire dans un `<select>` (candidat F1 du relevé)."""
    out = {"confiances": ["controlled", "untrusted"], "moteurs": ["auto", "llm", "deterministe"]}
    try:
        from registre import Registry
        reg = Registry()
        publiees = list(reg.publiques())
        out["capacites"] = [{"id": c.id, "description": getattr(c, "description", "").strip()}
                            for c in publiees]
        # Filtré sur les capacités publiées : `reg.providers()` est le catalogue COMPLET,
        # et l'énumérer ici reviendrait à donner à un client la liste des providers
        # internes — précisément ce que F1 reproche à `intent_llm.valider()`.
        out["providers"] = sorted({pr.id for c in publiees for pr in c.providers})
        out["note_filtre"] = ("providers = ceux des capacités publiées ; le registre complet "
                              "n'est pas exposé par cette interface")
        # État d'extension de la plateforme de la plateforme : quels fichiers de plugin sont chargés et
        # l'empreinte contre laquelle les plans sont autorisés. Un opérateur qui voit huit
        # capacités doit pouvoir savoir que deux viennent de fichiers hors du cœur — sinon
        # « ce que la plateforme sait faire » et « ce qui est installé sur cette machine »
        # redeviennent la même ligne floue.
        try:
            out["plugins"] = dict(reg.plugins)
        except AttributeError:
            out["plugins"] = {"fichiers": [], "empreinte": "",
                              "note": "registre sans lecture de plugins"}
    except Exception as e:                                    # registre illisible = menu vide
        out["registre_erreur"] = f"{type(e).__name__}: {str(e)[:200]}"
    try:
        import fournisseurs_llm as FL
        g = FL.Groq()
        out["llm"] = {"fournisseur": "groq", "modele_defaut": g.modele_defaut,
                      "modele_env": g.modele_env,
                      "cle_lue": getattr(g, "cle_env", "GROQ_API_KEY"),
                      "cle_presente": bool(os.environ.get(getattr(g, "cle_env", "GROQ_API_KEY")))}
        if hasattr(FL, "OpenAICompatible"):
            out["llm_non_exerce"] = ["OpenAICompatible (aucune clé, aucun endpoint ici — "
                                      "le proposer serait le déclarer sans l'avoir vu)"]
    except Exception as e:
        out["llm_erreur"] = f"{type(e).__name__}: {str(e)[:200]}"
    try:
        import profils as PF
        p = PF.actif()
        out["profil"] = {"nom": p.nom, "memoire_bornee": getattr(p, "memoire_bornee", None),
                         # L'état de la cage réseau, lu à la source. Cette ligne est la seule
                         # façon pour l'écran de dire autre chose que « la case est décochée » :
                         # sans elle, l'opérateur ne sait pas si cocher élargit un périmètre ou
                         # ouvre ce que rien n'autorise.
                         "reseau_autorise": bool(getattr(p, "reseau_autorise", False)),
                         "profils_ouvrant_la_sortie": sorted(
                             n for n, x in getattr(PF, "PROFILS", {}).items()
                             if getattr(x, "reseau_autorise", False)),
                         "note": "choisi par le code, pas par l'interface (mesuré G2)"}
    except Exception as e:
        out["profil_erreur"] = f"{type(e).__name__}: {e}"
    return out


def main(argv=None) -> int:
    # Bootstrap applicatif unique : l'API démarre le transport MCP avant les
    # lectures de Registry(), jamais dans le worker ni dans une requête.
    import mcp_bootstrap as MCP_BOOT
    import transports as CORE_TRANSPORTS
    MCP_BOOT.initialiser_mcp(CORE_TRANSPORTS)
    ap = argparse.ArgumentParser(description="API de l'interface AGNT (surcouche)")
    # 127.0.0.1 par défaut : ce serveur n'a ni auth ni TLS — l'exposer au réseau est un
    # accident, pas un déploiement. 0.0.0.0 reste possible explicitement (--host), en le
    # sachant.
    ap.add_argument("--host", default="127.0.0.1",
                    help="interface d'écoute (défaut: 127.0.0.1, local uniquement ; "
                         "passer --host 0.0.0.0 pour exposer explicitement)")
    ap.add_argument("--port", type=int, default=8141)
    ap.add_argument("--ouvert", action="store_true",
                    help="afficher les cibles admises et quitter (pour vérifier la liste)")
    a = ap.parse_args(argv)
    if a.ouvert:
        print(json.dumps(cibles_admises(), ensure_ascii=False, indent=2))
        return 0
    threading.Thread(target=_travail, daemon=True, name="agnt-run").start()
    srv = ThreadingHTTPServer((a.host, a.port), Gestionnaire)
    print(f"interface AGNT · http://{a.host}:{a.port} · un run à la fois · "
          f"{len(cibles_admises())} cible(s) admise(s)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
