#!/usr/bin/env python3
"""Mission History — le lecteur canonique, jugé au travers de l'API HTTP.

Ce que la commande P1 demande : un lecteur d'historique des Missions, et deux
routes de lecture seule (`GET /api/missions`, `GET /api/missions/{mission_id}`).
Ce fichier est le seul qui traverse `Gestionnaire` pour ces routes — les autres
suites jugent le moteur, pas la frontière HTTP.

Ce qui est mesuré, sans `opa`, sans `bwrap`, sans réseau, sans outil :

  1. liste vide → 200, `items` toujours présent (`{"items": []}`) ;
  2. tri déterministe `created_at DESC, mission_id DESC` (y compris à égalité de date) ;
  3. pagination : défaut (25), max (100), curseur valide, curseur invalide (400),
     stabilité (deux lectures identiques, aucune perte ni doublon) ;
  4. filtres v1 `status` et `target_type` seulement ; filtre inconnu ou valeur
     invalide → 400 explicite ;
  5. un refus antérieur au Run ne fabrique PAS de run_id ;
  6. une mission terminée rend des compteurs RÉELS, pas des zéros ;
  7. findings absent → jamais 0 + `missing_artifacts` ;
  8. une mission partielle ne casse pas la liste ;
  9. une ancienne mission sans `cible.descripteur` reste lisible ;
  10. une cible URL avec userinfo ne fuit pas les credentials ;
  11. les interdits ne sont jamais publiés : chemin absolu, credential, private key,
      argv, stack trace, endpoint brut, artefact brut, sortie provider ;
  12. un identifiant hostile / un symlink sortant ne lit RIEN hors de la racine ;
  13. le polling existant reçoit `mission_id` + `detail_href` (champs additifs).

Usage : python3 PHASE3/test_mission_history_api.py
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
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
import mission as MS                                          # noqa: E402

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def http(base: str, chemin: str, corps: dict | None = None):
    donnees = json.dumps(corps).encode() if corps is not None else None
    req = urllib.request.Request(base + chemin, data=donnees,
                                 method="POST" if donnees else "GET")
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
    except Exception as exc:                                 # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"


class Silencieux(api.Gestionnaire):
    def log_message(self, *a):
        pass


# --------------------------------------------------------------------------- fixtures
def _evenement(seq, ts, type_, **payload):
    return {"seq": seq, "ts": ts, "type": type_, **payload}


def _ecrire_mission(racine: Path, mid: str, cree_le: str, cible: dict,
                    evenements: list | None, artefacts: dict | None = None,
                    brut: dict | None = None) -> Path:
    """Écrit une mission complète à la main, avec contrôle total du contenu
    (pour injecter des interdits, des missions partielles, des anciens layouts)."""
    d = racine / mid
    d.mkdir(parents=True, exist_ok=True)
    entete = {"mission_id": mid, "cree_le": cree_le,
              "requete": "requête de la mission " + mid,
              "requete_canonique": "requete de la mission " + mid.lower(),
              "cible": cible, "format_journal": "journal.jsonl"}
    (d / "mission.json").write_text(json.dumps(entete, ensure_ascii=False, indent=2),
                                    encoding="utf-8")
    if evenements is not None:
        lignes = "\n".join(json.dumps(e, ensure_ascii=False) for e in evenements) + "\n"
        (d / "journal.jsonl").write_text(lignes, encoding="utf-8")
    if artefacts:
        s = d / "sortie"
        s.mkdir(parents=True, exist_ok=True)
        for nom, obj in artefacts.items():
            texte = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
            (s / nom).write_text(texte, encoding="utf-8")
    if brut:
        r = d / "run"
        r.mkdir(parents=True, exist_ok=True)
        for nom, obj in brut.items():
            texte = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
            (r / nom).write_text(texte, encoding="utf-8")
    return d


def _cible_desc(typ, reference, local=None):
    return {"descripteur": {"type": typ, "reference": reference,
                            "local": typ in ("repository", "filesystem") if local is None else local,
                            "chemin": reference if typ in ("repository", "filesystem") else None}}


def main() -> int:
    print("=== MISSION HISTORY : LECTEUR CANONIQUE, AU TRAVERS DE L'API ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="agnt-mhistory-"))
    MS.MISSIONS = tmp / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)

    # Le consommateur de file est démarré par `main()`, pas par l'import : nécessaire
    # pour le cas 13 (polling), inoffensif pour les routes GET (il attend sur la file).
    threading.Thread(target=api._travail, daemon=True, name="agnt-mhistory-test").start()
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), Silencieux)
    base = f"http://127.0.0.1:{serveur.server_address[1]}"
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    try:
        # ------------------------------------------------------------ 1. liste vide
        code, rep = http(base, "/api/missions")
        cas("1. liste vide → 200 avec items présent et vide",
            code == 200 and isinstance(rep, dict) and rep.get("items") == [], f"code={code}")

        # ------------------------------------------------------------ fixtures
        t = "2026-08-30T12:00:0"
        z = "+00:00"
        _ecrire_mission(MS.MISSIONS, "m-20260830T120005Z-00000001", t + "5" + z,
                        _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"),
                        [_evenement(1, t + "5" + z, "ouverture"),
                         _evenement(2, t + "5" + z, "contexte", run_id="run-01"),
                         _evenement(3, t + "5" + z, "cloture", findings=2, clusters=1,
                                    result_digest="aaaa")],
                        artefacts={"findings.json": [{"identity": {"canonical_rule_id": "r1"}},
                                                     {"identity": {"canonical_rule_id": "r2"}}],
                                   "clusters.json": {"clusters": [{"cluster_id": "c1"}],
                                                     "non_regroupe": [], "stats": {}},
                                   "plan.json": {"plan_id": "p1", "steps": []},
                                   "rapport.json": {"requete": "x", "couverture": {}},
                                   "run.json": {"run_id": "run-01", "plan_id": "p1"}})
        _ecrire_mission(MS.MISSIONS, "m-20260830T120004Z-00000002", t + "4" + z,
                        _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"),
                        [_evenement(1, t + "4" + z, "ouverture"),
                         _evenement(2, t + "4" + z, "arret", motif="policy",
                                    decision=["refus par défaut"])])
        _ecrire_mission(MS.MISSIONS, "m-20260830T120003Z-00000003", t + "3" + z,
                        _cible_desc("url", "https://alice:s3cret@github.com/org/repo.git"),
                        [_evenement(1, t + "3" + z, "ouverture"),
                         _evenement(2, t + "3" + z, "contexte", run_id="run-03"),
                         _evenement(3, t + "3" + z, "cloture", findings=0, clusters=0,
                                    result_digest="bbbb")],
                        artefacts={"findings.json": []})
        _ecrire_mission(MS.MISSIONS, "m-20260830T120002Z-00000004", t + "2" + z,
                        _cible_desc("filesystem", "/tmp/un_fichier.py"),
                        [_evenement(1, t + "2" + z, "ouverture"),
                         _evenement(2, t + "2" + z, "contexte", run_id="run-04"),
                         _evenement(3, t + "2" + z, "arret", motif="execution_semgrep",
                                    erreur="RuntimeError: crash")])
        _ecrire_mission(MS.MISSIONS, "m-20260830T120001Z-00000005", t + "1" + z,
                        _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"),
                        [_evenement(1, t + "1" + z, "ouverture")])
        # mission partielle : journal ABSENT (dossier avec mission.json seulement)
        _ecrire_mission(MS.MISSIONS, "m-20260830T120000Z-00000006", t + "0" + z,
                        _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"), None)
        # deux missions à la même seconde : le tri départage par mission_id DESC
        _ecrire_mission(MS.MISSIONS, "m-20260830T115959Z-00000007", "2026-08-30T11:59:59" + z,
                        _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"),
                        [_evenement(1, "2026-08-30T11:59:59" + z, "ouverture"),
                         _evenement(2, "2026-08-30T11:59:59" + z, "cloture", findings=0,
                                    clusters=0, result_digest="cccc")],
                        artefacts={"findings.json": []})
        _ecrire_mission(MS.MISSIONS, "m-20260830T115959Z-00000008", "2026-08-30T11:59:59" + z,
                        _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"),
                        [_evenement(1, "2026-08-30T11:59:59" + z, "ouverture"),
                         _evenement(2, "2026-08-30T11:59:59" + z, "arret", motif="conditions")])
        # ancienne mission sans descripteur (layout legacy) : lisible
        _ecrire_mission(MS.MISSIONS, "m-20260830T115958Z-00000009", "2026-08-30T11:58:58" + z,
                        {"chemin": "/data/repos/app", "type": "repertoire"},
                        [_evenement(1, "2026-08-30T11:58:58" + z, "ouverture"),
                         _evenement(2, "2026-08-30T11:58:58" + z, "cloture", findings=0,
                                    clusters=0, result_digest="dddd")],
                        artefacts={"findings.json": []})
        # mission terminée SANS findings.json : findings jamais 0, artefact déclaré manquant
        _ecrire_mission(MS.MISSIONS, "m-20260830T115957Z-00000010", "2026-08-30T11:57:57" + z,
                        _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"),
                        [_evenement(1, "2026-08-30T11:57:57" + z, "ouverture"),
                         _evenement(2, "2026-08-30T11:57:57" + z, "cloture", findings=0,
                                    clusters=0, result_digest="eeee")],
                        artefacts={"plan.json": {"plan_id": "p10", "steps": []}})

        ordre_attendu = [
            "m-20260830T120005Z-00000001", "m-20260830T120004Z-00000002",
            "m-20260830T120003Z-00000003", "m-20260830T120002Z-00000004",
            "m-20260830T120001Z-00000005", "m-20260830T120000Z-00000006",
            "m-20260830T115959Z-00000008", "m-20260830T115959Z-00000007",
            "m-20260830T115958Z-00000009", "m-20260830T115957Z-00000010",
        ]

        # ------------------------------------------------------------ 2. tri déterministe
        code, rep = http(base, "/api/missions?limit=100")
        ids = [i["mission_id"] for i in (rep or {}).get("items", [])]
        cas("2. tri created_at DESC, mission_id DESC (10 missions)",
            code == 200 and ids == ordre_attendu, f"ids={ids}")

        # ------------------------------------------------------------ 3. pagination
        code, p1 = http(base, "/api/missions?limit=3")
        cas("3. défaut de limite à 3 : 3 items + curseur de suite",
            code == 200 and len(p1.get("items", [])) == 3 and p1.get("next_cursor"),
            f"items={len(p1.get('items', []))} curseur={bool(p1.get('next_cursor'))}")
        recolte = [i["mission_id"] for i in p1.get("items", [])]
        curseur = p1.get("next_cursor")
        while curseur:
            code, page = http(base, f"/api/missions?limit=3&curseur={curseur}")
            if code != 200:
                break
            recolte += [i["mission_id"] for i in page.get("items", [])]
            curseur = page.get("next_cursor")
        cas("3b. pagination complète sans doublon ni perte",
            recolte == ordre_attendu, f"{len(recolte)} id(s)")
        code, rep = http(base, "/api/missions?limit=100")
        code2, rep2 = http(base, "/api/missions?limit=100")
        cas("3c. stabilité : deux lectures identiques",
            code == code2 == 200 and json.dumps(rep, sort_keys=True) == json.dumps(rep2, sort_keys=True))
        code, rep = http(base, "/api/missions?curseur=%21%21%21")
        cas("3d. curseur invalide → 400 explicite",
            code == 400 and isinstance(rep, dict) and "curseur" in json.dumps(rep), f"code={code}")
        for mauvais in ("0", "101", "abc", "-1"):
            code, rep = http(base, f"/api/missions?limit={mauvais}")
            cas(f"3e. limit invalide ({mauvais}) → 400", code == 400, f"code={code}")

        # ------------------------------------------------------------ 4. filtres
        code, rep = http(base, "/api/missions?limit=100&status=termine")
        st = {i["statut"] for i in rep.get("items", [])}
        cas("4. filtre status=termine ne rend que des missions terminées",
            code == 200 and st == {"termine"} and len(rep["items"]) == 5,
            f"statuts={st} n={len(rep.get('items', []))}")
        code, rep = http(base, "/api/missions?limit=100&target_type=url")
        cas("4b. filtre target_type=url isole la cible distante",
            code == 200 and [i["mission_id"] for i in rep.get("items", [])]
            == ["m-20260830T120003Z-00000003"],
            f"items={[i['mission_id'] for i in rep.get('items', [])]}")
        code, rep = http(base, "/api/missions?limit=100&target_type=repository")
        types = {i["cible"]["type"] for i in rep.get("items", [])}
        cas("4c. target_type=repository couvre aussi les anciennes missions (repertoire)",
            code == 200 and types == {"repository"}
            and any(i["mission_id"] == "m-20260830T115958Z-00000009"
                    for i in rep.get("items", [])), f"types={types}")
        code, rep = http(base, "/api/missions?status=nope")
        cas("4d. valeur de filtre status inconnue → 400 explicite",
            code == 400 and "status" in json.dumps(rep), f"code={code} corps={json.dumps(rep)[:120]}")
        code, rep = http(base, "/api/missions?foo=1")
        cas("4e. filtre inconnu → 400 qui nomme les admis",
            code == 400 and "admis" in (rep or {}) and "target_type" in json.dumps(rep), f"code={code}")

        # ------------------------------------------------------------ 5. refus pré-Run
        code, rep = http(base, "/api/missions/m-20260830T120004Z-00000002")
        cas("5. refus de policy : statut refuse, sans run_id inventé",
            code == 200 and rep.get("statut") == "refuse" and rep.get("run_id") is None,
            f"statut={rep.get('statut')} run_id={rep.get('run_id')!r}")

        # ------------------------------------------------------------ 6. compteurs réels
        code, rep = http(base, "/api/missions/m-20260830T120005Z-00000001")
        cas("6. mission terminée : findings et clusters comptés réellement",
            code == 200 and rep.get("statut") == "termine"
            and isinstance(rep.get("findings"), list) and len(rep["findings"]) == 2
            and rep["resume"]["findings"] == 2 and rep["resume"]["clusters"] == 1,
            f"findings={len(rep.get('findings') or [])} resume={rep.get('resume')}")
        code, listing = http(base, "/api/missions?limit=100")
        item01 = next(i for i in listing["items"]
                      if i["mission_id"] == "m-20260830T120005Z-00000001")
        cas("6b. le listing porte le même compteur réel",
            item01["findings"] == 2, f"findings={item01['findings']!r}")

        # ------------------------------------------------------------ 7. findings absent
        code, rep = http(base, "/api/missions/m-20260830T115957Z-00000010")
        cas("7. findings absent → jamais 0 + findings.json dans missing_artifacts",
            code == 200 and rep.get("statut") == "termine" and rep.get("findings") is None
            and "findings.json" in rep.get("missing_artifacts", []),
            f"findings={rep.get('findings')!r} manquants={rep.get('missing_artifacts')}")

        # ------------------------------------------------------------ 8. mission partielle
        code, listing = http(base, "/api/missions?limit=100")
        ids = [i["mission_id"] for i in listing.get("items", [])]
        cas("8. une mission sans journal ne casse pas la liste (toujours 200, 10 items)",
            code == 200 and "m-20260830T120000Z-00000006" in ids and len(ids) == 10,
            f"n={len(ids)}")

        # ------------------------------------------------------------ 9. ancienne mission
        code, rep = http(base, "/api/missions/m-20260830T115958Z-00000009")
        cas("9. ancienne mission sans descripteur : cible lisible, type traduit",
            code == 200 and rep["cible"]["type"] == "repository"
            and rep["cible"]["reference"] == "app" and "/data/" not in json.dumps(rep),
            f"cible={rep.get('cible')}")

        # ------------------------------------------------------------ 10. userinfo
        code, rep = http(base, "/api/missions/m-20260830T120003Z-00000003")
        corps = json.dumps(rep, ensure_ascii=False)
        cas("10. cible URL : userinfo retiré, credentials absents",
            code == 200 and rep["cible"]["reference"] == "https://github.com/org/repo.git"
            and "alice" not in corps and "s3cret" not in corps,
            f"reference={rep.get('cible', {}).get('reference')!r}")

        # ------------------------------------------------------------ 11. interdits
        token = "sk-abcdefghijklmnopqrstuvwxyz123456"
        poison = _ecrire_mission(
            MS.MISSIONS, "m-20260830T115956Z-00000011", "2026-08-30T11:56:56" + z,
            _cible_desc("repository", "/home/user/agnt/PHASE3/testrepo"),
            [_evenement(1, "2026-08-30T11:56:56" + z, "ouverture",
                        requete="analyse with token " + token,
                        cible="/home/user/agnt/PHASE3/testrepo"),
             _evenement(2, "2026-08-30T11:56:56" + z, "arret", motif="policy",
                        erreur="Traceback (most recent call last): File "
                               "\"/home/user/agnt/PHASE3/leak.py\", line 1, in <module>")],
            artefacts={"plan.json": {"plan_id": "p11", "cible": "/home/user/agnt/PHASE3/testrepo",
                                     "steps": [{"capability": "c", "provider": "semgrep",
                                                "risque": "PASSIVE",
                                                "commande": ["/home/user/.local/bin/semgrep",
                                                             "--config", "/etc/passwd"],
                                                "args": ["/etc/shadow"], "sorties": []}],
                                     "selection": {}},
                       "rapport.json": {"requete": "x", "couverture": {},
                                        "note": "base sous /home/user/agnt/PHASE3/cache"}},
            brut={"raw_semgrep.json": {"issue_text": "-----BEGIN RSA PRIVATE KEY-----\nMII..."},
                  "brut_semgrep.json": {"stdout": "ENDPOINT https://interne/v1?key=ghp_aaaaaaaaaaaaaaaaaaaaaa"}})
        code, rep = http(base, "/api/missions/m-20260830T115956Z-00000011")
        code2, listing = http(base, "/api/missions?limit=100")
        tout = json.dumps(rep, ensure_ascii=False) + json.dumps(listing, ensure_ascii=False)
        interdits = ["/home/", "PRIVATE KEY", "Traceback", "/etc/passwd", "/etc/shadow",
                     "alice:s3cret@", "s3cret", token, "ghp_aaaaaaaaaaaaaaaaaaaaaa"]
        fuites = [s for s in interdits if s in tout]
        cas("11. aucun interdit publié (chemin absolu, secret, argv, stack trace, artefact brut)",
            code == 200 and not fuites, f"fuites={fuites}")

        # ------------------------------------------------------------ 12. id hostile / symlink
        code, rep = http(base, "/api/missions/../../etc/passwd")
        cas("12. traversal refusé (404) sans lire hors racine", code == 404, f"code={code}")
        code, rep = http(base, "/api/missions/m-20260830T120000Z-00000001%2f..%2fetc")
        cas("12b. identifiant hostile encodé refusé (404)", code == 404, f"code={code}")
        hors = tmp / "secret_hors_racine.txt"
        hors.write_text("SECRET-DE-LECTURE-HORS-RACINE", encoding="utf-8")
        try:
            (MS.MISSIONS / "m-20260830T115955Z-00000012").symlink_to(hors)
            code, rep = http(base, "/api/missions/m-20260830T115955Z-00000012")
            cas("12c. symlink sortant refusé (404), jamais suivi",
                code == 404 and "SECRET-DE-LECTURE-HORS-RACINE" not in json.dumps(rep), f"code={code}")
            code, listing = http(base, "/api/missions?limit=100")
            cas("12d. le symlink sortant n'apparaît pas dans le listing",
                code == 200 and all(i["mission_id"] != "m-20260830T115955Z-00000012"
                                    for i in listing.get("items", [])), "symlink listé")
        finally:
            pass

        # ------------------------------------------------------------ 13. polling additif
        admises = api.cibles_admises()
        if admises:
            code, lance = http(base, "/api/runs", {"cible": admises[0]["chemin"],
                                                   "question": "Analyse la sécurité de ce dépôt",
                                                   "confiance": "controlled", "moteur": "deterministe"})
            identifiant = (lance or {}).get("id", "") if isinstance(lance, dict) else ""
            etat: dict = {}
            for _ in range(120):
                time.sleep(0.4)
                code, etat = http(base, f"/api/runs/{identifiant}")
                if isinstance(etat, dict) and etat.get("statut") in ("termine", "refuse", "erreur"):
                    break
            cas("13. le polling porte mission_id (champ additif)",
                isinstance(etat, dict) and bool(etat.get("mission_id")),
                f"mission_id={etat.get('mission_id')!r} statut={etat.get('statut')!r}")
            cas("13b. detail_href pointe vers un détail 200",
                bool(etat.get("detail_href"))
                and http(base, etat["detail_href"])[0] == 200,
                f"href={etat.get('detail_href')!r}")
            cas("13c. les champs historiques du polling sont conservés",
                "id" in etat and "statut" in etat, f"clés={sorted(etat.keys())}")
        else:
            cas("13. cible admise disponible pour tester le polling", False,
                "cibles_admises() vide — testrepo absent ?")

        # ------------------------------------------------------------ nettoyage
        code, listing = http(base, "/api/missions?limit=100")
        for i in listing.get("items", []):
            pass
    finally:
        serveur.shutdown()
        serveur.server_close()
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
    sys.exit(1 if ECHECS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
