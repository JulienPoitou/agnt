#!/usr/bin/env python3
"""API HTTP de l'interface AGNT — une surcouche, pas un cœur.

Ce fichier ne décide rien. Il reçoit trois choses (cible, question, confiance), les
transmet à `analyser.lancer()` — la même fonction que les tests et que la CLI — puis
relit l'archive de mission que ce module écrit déjà. Aucune logique de sécurité n'est
dupliquée ici : si elle existait ici, elle serait contournable par la CLI.

Trois lois de ce fichier :

1. **Une exécution à la fois.** `pipeline` écrit ses objets dans `PHASE3/run/` avant que
   `_archiver_mission` ne les copie sous la mission : ce répertoire est partagé, donc deux
   runs simultanés se réécriraient l'un l'autre. La file à un consommateur est ce qui
   rend le partage sûr, pas une politesse. (Rendre `run/` par-exécution = travail sur le
   pipeline, hors périmètre ici.)
2. **La cible est un choix, jamais un chemin.** `GET /api/cibles` renvoie une liste
   construite ici ; `POST /api/runs` ne prend qu'un nom de cette liste. Ce n'est pas une
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
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ICI = Path(__file__).resolve().parent
RACINE = ICI.parent                      # PHASE3/
DEPOT = RACINE.parent                     # racine du repo
sys.path.insert(0, str(RACINE))            # pour `import analyser`
sys.path.insert(0, str(RACINE / "slice"))  # pour `import pipeline`, `profils`, …

TAILLE_MAX_REQUETE = 4000   # garde d'entrée, pas le correctif F5 (la borne portante est
                            # la taille du corps sortant, côté fournisseur)

# Cibles proposables. Règle : un dépôt DÉJÀ sur cette machine, sous le dépôt de travail ou
# listé dans AGNT_CIBLES (séparateur « : »). Pas de clonage, pas de téléchargement : cela
# ajouterait une écriture et un réseau sortant que rien ici n'a été conçu pour border.
def cibles_admises() -> list[dict]:
    from registre import Registry          # import tardif : après sys.path
    hors = [Path(p) for p in os.environ.get("AGNT_CIBLES", "").split(":") if p.strip()]
    candidats = [RACINE / "testrepo", RACINE / "cible_independante", RACINE / "labo_securite",
                 RACINE / "dogfooding"] + hors
    out = []
    for c in candidats:
        try:
            c = c.resolve()
        except OSError:
            continue
        if not c.is_dir():
            continue
        sous_de = any(str(c).startswith(str(base)) for base in (RACINE, DEPOT)) or c in hors
        if not sous_de:
            continue
        entrees = sorted(p.name for p in c.iterdir())[:6]
        out.append({"nom": c.name, "chemin": str(c),
                    "fichiers_vus": entrees,
                    "langages": _devine_langages(c)})
    return out


def _devine_langages(c: Path) -> list[str]:
    indices = {".py": "python", ".go": "go", ".js": "javascript", ".ts": "typescript",
               ".tf": "terraform", ".yaml": "iac", ".yml": "iac", ".java": "java"}
    vus: set[str] = set()
    for p in list(c.rglob("*"))[:400]:
        if p.is_file():
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


def _marquer(rid: str, **champs) -> None:
    with VERROU:
        ETATS.setdefault(rid, {}).update(champs)


def _travail() -> None:
    """Un seul consommateur : c'est ce qui sérialise les runs (voir loi 1)."""
    while True:
        rid, question, cible, options = FILE.get()
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
                                           confiance=options.get("confiance", "controlled"))
            sortie = resume.get("sortie")
            donnees = _charger(sortie) if sortie else None
            if donnees is not None:      # le résumé du moteur complète l'archive, sans la contredire
                for k in ("mission", "statut", "moteur", "confiance_cible", "findings",
                          "clusters_inter_outils", "question", "motif", "rapport"):
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
            _marquer(rid, statut="refuse" if refus else "erreur", erreur=detail,
                     resume={"motif": f"{nom} : {str(e)[:280]}"})
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
            "capacites_demandees": rapport.get("capacites_demandees", []),
            "motifs_intent": rapport.get("motifs_intent", {}),
            "plan_id": rapport.get("plan_id"),
            "plan_empreinte": rapport.get("plan_empreinte"),
            "moteur_intent": plan.get("moteur_intent"),
            "cible": plan.get("cible"),
            "steps": plan.get("steps", []),
            "selection": plan.get("selection", {}),
            "autorisation": rapport.get("autorisation", {}),
            "couverture": rapport.get("couverture", {}),
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
            "profil": run.get("profil"),
            "plan_id": run.get("plan_id"),
            "input_digest": run.get("input_digest"), "input_commit": run.get("input_commit"),
            "working_tree_dirty": run.get("working_tree_dirty"),
            "moteur": intent.get("moteur"), "sortie": str(d),
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
        if not str(f).startswith(str(ICI)) or not type_mime or not f.is_file():
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
        chemin = self.path.split("?", 1)[0]
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
        if chemin.startswith("/api/runs/"):
            rid = chemin.rsplit("/", 1)[-1]
            with VERROU:
                etat = dict(ETATS.get(rid) or {})
            if not etat:
                return self._json({"erreur": f"run inconnu : {rid}"}, 404)
            return self._json({"id": rid, **etat})
        return self.send_error(404)

    # ---- écriture
    def do_POST(self):  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/runs":
            return self.send_error(404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
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

        rid = uuid.uuid4().hex[:12]
        with VERROU:
            ETATS[rid] = {"statut": "en_file", "question": question, "cible": cible}
        FILE.put((rid, question, cible, {"moteur": moteur, "confiance": confiance,
                                         "modele": corps.get("modele")}))
        return self._json({"id": rid, "statut": "en_file",
                           "position": FILE.qsize()}, 202)

    def log_message(self, format, *args):        # journal court, sans données d'utilisateur
        sys.stderr.write("[interface] %s\n" % (args[0] if args else ""))


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
                         "note": "choisi par le code, pas par l'interface (mesuré G2)"}
    except Exception as e:
        out["profil_erreur"] = f"{type(e).__name__}: {e}"
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="API de l'interface AGNT (surcouche)")
    ap.add_argument("--host", default="0.0.0.0")
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
