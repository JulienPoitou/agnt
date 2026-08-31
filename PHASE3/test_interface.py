#!/usr/bin/env python3
"""Contrat de l'API d'interface : ce que `app.js` est EN DROIT de lire, vérifié par HTTP.

Pourquoi ce fichier existe : la page ne juge pas des fonctions, elle juge des réponses.
Un champ renvoyé sous un autre nom, une liste renvoyée en dictionnaire, un refus réduit à
un code — rien de tout cela ne fait planter le moteur, ça fait simplement afficher une page
vide ou « undefined ». Les suites du cœur (`test_adversaire.py`, `test_chemins.py`, …) ne
voient jamais cette frontière, et `interface/_domtest.mjs` la contourne en appelant
`api._charger()` directement. Ce fichier est le seul qui traverse `Gestionnaire`.

Ce qui est vérifié, dans les deux sens quand c'est possible :

    ADMIS       les routes que l'appel de `app.js` attend existent, avec les NOMS de champs
                que `app.js` lit — pas ceux qu'on imagine
    REFUSÉ      cible hors liste, question trop longue, run inconnu, chemin hors dossier :
                chaque refus nomme sa cause ET l'alternative
    AUCUNE      un RUN qui n'aboutit pas ne doit rien inventer : ni findings à zéro, ni
                « erreur » générique à la place d'un refus de politique
    FABRIQUÉE   la maquette reste identifiée comme telle
    HISTOIRE    un run réel abouti reparaît dans GET /api/missions et son détail rend
                une timeline : c'est le maillon « revoir l'historique » du parcours

Ce qui N'EST PAS vérifié ici : le rendu DOM (c'est `_domtest.mjs`), le moteur lui-même
(c'est le reste des suites), et l'exécution réelle d'un outil — sur cette machine, `opa`
est absent, donc tout RUN légitime s'arrête en `refuse`/`erreur`. C'est précisément l'état
qu'on juge ici, et il est atteint pour de vrai, pas simulé.

Usage : python3 PHASE3/test_interface.py       (aucun réseau extérieur, aucun paquet requis)
"""
from __future__ import annotations

import json
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))
sys.path.insert(0, str(RACINE / "interface"))

import api                                                    # noqa: E402
import pipeline as P                                          # noqa: E402
import adapters as AD                                         # noqa: E402 — seam « disponibilité » (alignement PR #2)

BUNDLE = RACINE / "dogfooding" / "rapports" / "mocha"
MISSIONS = RACINE / "artifacts" / "missions"
RESULTATS: list[tuple[str, bool, str]] = []


def verifie(nom: str, cond, detail: str = "") -> None:
    """`cond=None` = NON ÉVALUÉ : la propriété est réelle mais injouable ici. Ni un succès,
    ni un échec — la confondre avec l'un des deux est le défaut qu'on ferme partout ailleurs."""
    RESULTATS.append((nom, None if cond is None else bool(cond), detail))


def http(base: str, chemin: str, corps: dict | None = None, methode: str | None = None):
    """(code, objet) — une réponse invalide est un échec, pas une exception non capturée."""
    donnees = json.dumps(corps).encode() if corps is not None else None
    req = urllib.request.Request(base + chemin, data=donnees, method=methode or ("POST" if donnees else "GET"))
    if donnees:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            texte = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(texte) if "json" in (r.headers.get("Content-Type") or "") else texte)
    except urllib.error.HTTPError as e:
        texte = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(texte)
        except json.JSONDecodeError:
            return e.code, texte
    except Exception as exc:                                 # la panne de transport est un résultat
        return 0, f"{type(exc).__name__}: {exc}"


class Silencieux(api.Gestionnaire):
    def log_message(self, *a):                                # pas de journal de serveur dans la sortie
        pass


def main() -> int:
    avant = set(MISSIONS.glob("m-*")) if MISSIONS.is_dir() else set()
    # Le consommateur de la file est démarré par `main()`, pas par l'import du module : un
    # serveur monté à la main sans lui laisse chaque RUN en « en_file » pour l'éternité. C'est
    # une observation sur le contrat d'api.py (elle compte pour l'étape 7), reproduite ici à
    # l'identique plutôt que contournée.
    threading.Thread(target=api._travail, daemon=True, name="agnt-run-test").start()
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), Silencieux)
    base = f"http://127.0.0.1:{serveur.server_address[1]}"
    fil = threading.Thread(target=serveur.serve_forever, daemon=True)
    fil.start()
    # Alignement d'intégration (étape 1bis « disponibilité », PR #2) : sans outils
    # installés, la disponibilité refuse chaque RUN AVANT la policy, et le chemin
    # d'erreur que cette batterie mesure (PolicyError → motif + objet erreur préservés
    # jusqu'à la face) ne serait plus exercé. Le serveur tourne DANS ce processus : la
    # neutralisation est donc visible par le pipeline de l'API. AUCUNE attente n'est
    # modifiée — la scène redevient celle d'une machine après bootstrap.sh.
    _exe_de = AD.exe_de
    AD.exe_de = lambda p: "/bin/true"
    try:
        # ---------------------------------------------------------------- les fichiers statiques
        code, page = http(base, "/")
        verifie("GET / sert la page", code == 200 and "app.js" in str(page), f"code={code}")
        code, app = http(base, "/app.js")
        verifie("GET /app.js sert le script, pas du HTML", code == 200 and "function rendu" in str(app),
                f"code={code}")
        lignesinnerHTML = [l for l in str(app).splitlines() if "innerHTML" in l]
        verifie("innerHTML n'apparait que comme règle énoncée, jamais comme affectation",
                all(l.strip().startswith(("*", "//", "/*")) and ".innerHTML" not in l
                    for l in lignesinnerHTML),
                f"{len(lignesinnerHTML)} ligne(s) : " + "; ".join(l.strip()[:60] for l in lignesinnerHTML))
        for attaque in ("/../../etc/passwd", "/..%2f..%2fetc%2fpasswd", "/api/../../../etc/hostname"):
            c, _ = http(base, attaque)
            verifie(f"chemins hors dossier refusés ({attaque[-22:]})", c in (403, 404), f"code={c}")

        # ---------------------------------------------------------------- les capacités publiées
        code, caps = http(base, "/api/capacites")
        verifie("GET /api/capacites répond", code == 200 and isinstance(caps, dict), f"code={code}")
        if isinstance(caps, dict):
            # Les noms ci-dessous sont CEUX QUE app.js LIT (`l.cle_presente`, `l.modele_defaut`,
            # `caps.capacites.length`, `caps.confiances`, `caps.profil`). Une route complète mais
            # renommée est exactement le défaut que ce test doit attraper.
            verifie("les cinq clés lues par la page sont là",
                    all(k in caps for k in ("capacites", "llm", "confiances", "profil", "providers")),
                    "manquants : " + ",".join(k for k in ("capacites", "llm", "confiances", "profil",
                                                           "providers") if k not in caps))
            verifie("les capacités sont des objets avec un id",
                    all(isinstance(c, dict) and c.get("id") for c in caps.get("capacites", []))
                    and caps.get("capacites"),
                    str(caps.get("capacites"))[:80])
            llm = caps.get("llm") or {}
            verifie("llm expose cle_presente et modele_defaut (lis par la page)",
                    "cle_presente" in llm and "modele_defaut" in llm, json.dumps(llm)[:120])
            verifie("les niveaux de confiance servis sont ceux du pipeline",
                    list(caps.get("confiances") or []) == list(P.CONFIANCES),
                    f"{caps.get('confiances')} vs {P.CONFIANCES}")

        # ---------------------------------------------------------------- les cibles admises
        code, cibles = http(base, "/api/cibles")
        liste = (cibles or {}).get("cibles") if isinstance(cibles, dict) else None
        verifie("GET /api/cibles renvoie une liste non vide", isinstance(liste, list) and bool(liste),
                f"code={code} type={type(liste).__name__}")
        # `c.langages.join("/")` est appelé par app.js : une liste attendue, pas un dictionnaire
        verifie("chaque cible porte nom, chemin, langages (liste)",
                all(isinstance(c, dict) and c.get("nom") and c.get("chemin")
                    and isinstance(c.get("langages"), list) for c in (liste or [])),
                json.dumps((liste or [{}])[0], ensure_ascii=False)[:140])
        verifie("les chemins admis existent vraiment",
                all(Path(c["chemin"]).is_dir() for c in (liste or [])),
                ",".join(c["chemin"] for c in (liste or []) if not Path(c["chemin"]).is_dir()))

        # ---------------------------------------------------------------- les refus d'entrée
        c, refus = http(base, "/api/runs", {"cible": "/etc", "question": "scan"})
        verifie("cible hors liste → 400 qui nomme l'alternative",
                c == 400 and isinstance(refus, dict) and "erreur" in refus and isinstance(
                    refus.get("admises"), list) and refus["admises"],
                f"code={c} corps={json.dumps(refus, ensure_ascii=False)[:120]}")
        trop = "a" * (api.TAILLE_MAX_REQUETE + 1)
        c, refus = http(base, "/api/runs", {"cible": (liste or [{}])[0].get("chemin", ""), "question": trop})
        verifie("question démesurée → 400 chiffré (pas un troncage silencieux)",
                c == 400 and isinstance(refus, dict) and str(api.TAILLE_MAX_REQUETE) in json.dumps(refus),
                f"code={c} corps={json.dumps(refus, ensure_ascii=False)[:120]}")
        c, refus = http(base, "/api/runs", {"cible": (liste or [{}])[0].get("chemin", ""), "question": "   "})
        verifie("question vide refusée", c == 400, f"code={c}")
        c, objet = http(base, "/api/runs/pas-un-run")
        verifie("run inconnu → 404 qui redit l'identifiant",
                c == 404 and isinstance(objet, dict) and "pas-un-run" in json.dumps(objet), f"code={c}")

        # ---------------------------------------------------------------- un RUN, jusqu'au bout
        if liste:
            c, lance = http(base, "/api/runs", {"cible": liste[0]["chemin"],
                                                "question": "Analyse la sécurité de ce dépôt",
                                                "confiance": "controlled", "moteur": "auto"})
            verifie("POST /api/runs accepte une cible admise et rend un identifiant (202 = en file)",
                    c in (200, 202) and isinstance(lance, dict) and lance.get("id")
                    and lance.get("statut") == "en_file",
                    f"code={c} corps={json.dumps(lance, ensure_ascii=False)[:120]}")
            identifiant = (lance or {}).get("id", "")
            etat: dict = {}
            for _ in range(120):
                time.sleep(0.5)                              # le rythme réel du client (0,9-1,3 s)
                c, etat = http(base, f"/api/runs/{identifiant}")
                if isinstance(etat, dict) and etat.get("statut") in ("termine", "refuse", "erreur"):
                    break
            statut = etat.get("statut")
            verifie("le run aboutit à un état terminal connu",
                    statut in ("termine", "refuse", "erreur"), f"statut={statut} code={c}")
            if statut in ("refuse", "erreur"):
                motif = str(((etat.get("resume") or {}).get("motif")) or "")
                verifie("un refus/erreur porte une MOTIVATION nommant la cause",
                        bool(motif) and any(n in motif for n in
                                            ("PolicyError", "SandboxError", "PipelineError", "PermissionError")),
                        f"motif={motif[:110]!r}")
                verifie("le refus n'est pas maquillé en erreur générique",
                        "erreur interne" not in motif.lower() and "inconnue" not in motif.lower(),
                        motif[:110])
                donnees = etat.get("donnees") or {}
                verifie("une exécution interrompue ne rend PAS « 0 finding » comme si elle avait analysé",
                        not donnees.get("findings"), json.dumps(donnees)[:100])
                er = etat.get("erreur") or {}
                verifie("la réponse garde le type et le message d'origine (face non fiable)",
                        bool(er.get("type")) and bool(er.get("message")),
                        json.dumps({k: str(v)[:60] for k, v in er.items()}, ensure_ascii=False)[:160])
            # la trace sur disque doit dire pourquoi elle s'arrête (corrélé à E6 de la campagne)
            nouveaux = sorted(set(MISSIONS.glob("m-*")) - avant) if MISSIONS.is_dir() else []
            trace = "\n".join((d / "journal.jsonl").read_text(encoding="utf-8", errors="replace")
                              for d in nouveaux)
            verifie("le journal de mission consigne la cause de l'arrêt",
                    statut in ("termine", "refuse", "erreur") and ("arret" in trace or "confiance" in trace),
                    f"{len(nouveaux)} dossier(s) ; types : " +
                    ",".join(sorted({json.loads(l).get('type', '?') for l in trace.splitlines() if l.strip()})))
            # ---------------------------------------------------- revoir l'historique
            # Dernier maillon du parcours propriétaire. La page ne le consomme pas
            # encore (mesuré : aucun `/api/missions` dans app.js/index.html — WEB-001/002,
            # voir docs/coordination/WEB_DOGFOOD_V0.md), mais l'API HISTORY est en main
            # et doit pouvoir être relue depuis ce run réel : c'est ce que l'écran
            # affichera un jour. Jugé ici sur la mission RÉELLE, pas sur une fabriquée.
            mid = etat.get("mission_id") or ((etat.get("donnees") or {}).get("run") or {}).get("mission")
            verifie("le run terminal expose un mission_id durable (distinct de l'id de file)",
                    bool(mid) and mid != identifiant, f"mission_id={mid!r} id={identifiant}")
            if mid:
                c, hist = http(base, "/api/missions?limit=100")
                items = (hist or {}).get("items") if isinstance(hist, dict) else None
                verifie("GET /api/missions répond avec l'enveloppe du contrat History",
                        c == 200 and isinstance(items, list)
                        and (hist or {}).get("schema_version") == "agnt.history.v1",
                        f"code={c} schema={(hist or {}).get('schema_version')!r}")
                trouve = next((i for i in (items or []) if i.get("mission_id") == mid), None)
                verifie("la mission du run apparaît dans l'historique, statut terminal conservé",
                        bool(trouve) and trouve.get("status") == statut
                        and isinstance(trouve.get("artifacts"), dict),
                        json.dumps(trouve, ensure_ascii=False)[:220] if trouve
                        else f"absente de {len(items or [])} item(s)")
                c, det = http(base, f"/api/missions/{mid}")
                timeline = ((det or {}).get("data") or {}).get("timeline") or {}
                verifie("GET /api/missions/<id> rend la timeline de la même mission",
                        c == 200 and isinstance(det, dict)
                        and isinstance(timeline.get("events"), list)
                        and bool(timeline.get("events")),
                        f"code={c} events={len(timeline.get('events') or [])}")
            for d in nouveaux:                               # rien ne reste de la campagne locale
                shutil.rmtree(d, ignore_errors=True)

        # ---------------------------------------------------------------- la file d'attente
        # L'API garde un consommateur unique. La raison a changé en 2026-08-30 : les sorties
        # brutes vivent désormais PAR MISSION (`<mission>/run`, posé par le pipeline), donc
        # deux missions ne se réécrivent plus. La file reste un choix d'ordonnancement et de
        # visibilité — un run en cours se lit, le suivant attend — pas un garde-fou contre un
        # répertoire partagé.
        deux = []
        for question in ("Analyse la sécurité de ce dépôt", "Cherche les secrets de ce dépôt"):
            c, lance = http(base, "/api/runs", {"cible": liste[0]["chemin"], "question": question,
                                                "confiance": "controlled", "moteur": "deterministe"})
            deux.append(lance if isinstance(lance, dict) else {})
        positions = [d.get("position") for d in deux if d.get("id")]
        ids_attendus = [d.get("id") for d in deux if d.get("id")]
        # D'abord écrit « positions[0] < positions[1] », tombé en ÉCHEC avec positions=[1, 1].
        # La mesure dit que `position` est la taille de la file à l'insertion, pas un rang : le
        # second RUN est bien premier de file puisque le premier est déjà EN COURS. L'attendu
        # jugé ici est donc ce que le contrat garantit — deux identifiants distincts, deux
        # acceptations — et le [1, 1] est consigné à côté du champ, dans api.py.
        verifie("deux RUNs demandés sont acceptés avec des identifiants distincts",
                len(ids_attendus) == 2 and len(set(ids_attendus)) == 2,
                f"ids={ids_attendus} positions={positions}")
        ids = [d["id"] for d in deux if d.get("id")]
        terminaux = {}
        for identifiant in ids:
            for _ in range(160):
                time.sleep(0.4)
                c, e = http(base, f"/api/runs/{identifiant}")
                if isinstance(e, dict) and e.get("statut") in ("termine", "refuse", "erreur"):
                    terminaux[identifiant] = e
                    break
        verifie("les deux RUNs atteignent chacun un état terminal, sans se mélanger",
                len(terminaux) == len(ids) and all(
                    t.get("id") == i or t.get("statut") for i, t in terminaux.items()),
                json.dumps({k: v.get("statut") for k, v in terminaux.items()}))
        motifs = {str(((t.get("resume") or {}).get("motif")) or "") for t in terminaux.values()}
        verifie("un RUN en file derrière un autre ne reçoit pas la décision du premier",
                len(motifs) <= 2, " · ".join(sorted(m[:60] for m in motifs if m)))
        verifie("l'écriture concurrente dans le répertoire de mission est mesurée",
                None, "aucune exécution d'outil n'est possible ici (opa et bwrap absents) : la file "
                      "est jugée sur ses compteurs, pas sur ses octets. À rejouer après bootstrap.sh.")
        for d in sorted(set(MISSIONS.glob("m-*")) - avant) if MISSIONS.is_dir() else []:
            shutil.rmtree(d, ignore_errors=True)                # rien ne reste de la campagne locale

        # ------------------------------------------------------------- le chargeur d'archive
        if BUNDLE.is_dir():
            donnees = api._charger(str(BUNDLE))
            chaine = donnees.get("chaine") or {}
            verifie("_charger expose les clés lues par la page",
                    all(k in chaine for k in ("requete", "requete_canonique", "capacites_demandees",
                                              "plan_id", "steps", "selection", "autorisation", "couverture")),
                    "manquants : " + ",".join(k for k in ("requete", "requete_canonique", "steps",
                                                           "selection", "autorisation", "couverture") if k not in chaine))
            verifie("la couverture est indexée par fournisseur, pas comptée à la louche",
                    isinstance(chaine.get("couverture"), dict) and chaine["couverture"],
                    json.dumps(list((chaine.get("couverture") or {}).keys()))[:120])
            verifie("findings_absents est un booléen cohérent avec findings",
                    isinstance(donnees.get("findings_absents"), bool)
                    and (donnees["findings_absents"] == (donnees.get("findings") is None)),
                    f"absents={donnees.get('findings_absents')} findings={type(donnees.get('findings')).__name__}")
            verifie("le rapport humain arrive en texte brut",
                    isinstance(donnees.get("rapport_markdown"), str) and len(donnees["rapport_markdown"]) > 40,
                    f"{len(str(donnees.get('rapport_markdown')))} caractères")
        else:
            verifie("bundle réel de dogfooding présent (sans lui, le chargeur n'est pas mesurable)",
                    False, f"{BUNDLE} introuvable")

        # ---------------------------------------------------------------- la maquette, identifiée
        exemple = json.loads((RACINE / "interface" / "donnees_exemple.json").read_text(encoding="utf-8"))
        verifie("la maquette se déclare comme inventée", bool(exemple.get("maquette")) and
                "inventées" in str(exemple.get("note")), json.dumps(exemple.get("note"))[:90])
        code, ruban = http(base, "/index.html")
        verifie("la page porte le bandeau qui sépare la maquette du chemin réel",
                code == 200 and "MAQUETTE" in str(ruban), "index.html sans marqueur MAQUETTE")
    finally:
        AD.exe_de = _exe_de
        serveur.shutdown()
        serveur.server_close()

    echecs = non_evalues = 0
    for nom, ok, detail in RESULTATS:
        if ok is None:
            non_evalues += 1
            print(f"NON ÉVAL {nom}\n         {detail}")
            continue
        if not ok:
            echecs += 1
        print(("OK    " if ok else "ÉCHEC ") + nom + ("" if ok or not detail else f"\n         {detail}"))
    ok = len(RESULTATS) - echecs - non_evalues
    print(f"\n{ok}/{len(RESULTATS)} vérifications passées · {echecs} en échec · {non_evalues} non évaluées")
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
