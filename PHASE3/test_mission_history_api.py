#!/usr/bin/env python3
"""Mission History — lecteur canonique aligné sur les contrats Product, jugé au travers de l'API.

Ce que cette batterie mesure, sans `opa`, sans `bwrap`, sans réseau, sans outil :

  Contrat History v1 :
    1. liste vide → 200, `items: []`, `schema_version: agnt.history.v1`, `page` ;
    2. `MissionSummary` : champs obligatoires (mission_id, detail_href, request.title,
       target.type/display_name, status, created_at/updated_at, artifacts) ;
    3. tri stable `created_at DESC, mission_id DESC` ; pagination `cursor` opaque ;
    4. filtres v1 `status` et `target_type` ; filtre/valeur invalide → 400 enveloppe `error` ;
    5. détail : enveloppe `{schema_version, mission, data, missing_artifacts}` ;
    6. refus pré-Run : pas de run_id, pas de findings_summary ;
    7. mission terminée : compteurs réels ; zéro SEULEMENT sur artefact lisible ;
    8. findings absent → jamais 0, `findings` dans missing_artifacts ;
    9. ancienne mission sans descripteur : cible lisible, type traduit ;
   10. cible URL : userinfo retiré, credentials absents.

  Contrat Timeline v1 :
   11. `data.timeline` : enveloppe, ordre par seq, event_id déterministe,
       position stable, événement inconnu → `unknown_event_recorded`,
       journal absent → `unavailable` + `events` manquant.

  Contrat Execution Status v1 :
   12. `data.executions[]` : dimensions applicabilité/sélection/condition/
       autorisation/disponibilité/exécution/détection/complétude ;
   13. zéro findings uniquement avec `rien_trouve` + cibles analysées prouvées ;
   14. indisponibilité/refus/échec ne deviennent jamais « zéro finding ».

  Sécurité (invariants livrés) :
   15. aucun interdit publié : chemin absolu, argv, credential, private key,
       Bearer, stack trace, endpoint brut, artefact raw ;
   16. identifiant hostile / symlink sortant : aucune lecture hors racine ;
   17. polling `GET /api/runs/{id}` : `mission_id` + `detail_href` additifs.

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
def _ev(seq, ts, type_, **payload):
    return {"seq": seq, "ts": ts, "type": type_, **payload}


def _ecrire(racine: Path, mid: str, cree_le: str, cible: dict, evenements,
            sortie: dict | None = None, rapport_md: str | None = None,
            requete: str = "Analyse la sécurité de ce dépôt") -> Path:
    d = racine / mid
    d.mkdir(parents=True, exist_ok=True)
    entete = {"mission_id": mid, "cree_le": cree_le, "requete": requete,
              "requete_canonique": requete.lower(), "cible": cible,
              "format_journal": "journal.jsonl"}
    (d / "mission.json").write_text(json.dumps(entete, ensure_ascii=False, indent=2),
                                    encoding="utf-8")
    if evenements is not None:
        (d / "journal.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in evenements) + "\n",
            encoding="utf-8")
    if sortie is not None:
        s = d / "sortie"
        s.mkdir(parents=True, exist_ok=True)
        for nom, obj in sortie.items():
            texte = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
            (s / nom).write_text(texte, encoding="utf-8")
    if rapport_md is not None:
        s = d / "sortie"
        s.mkdir(parents=True, exist_ok=True)
        (s / "RAPPORT.md").write_text(rapport_md, encoding="utf-8")
    return d


def _cible(typ, reference):
    return {"descripteur": {"type": typ, "reference": reference,
                            "local": typ in ("repository", "filesystem"),
                            "chemin": reference if typ in ("repository", "filesystem") else None}}


def _finding(i, sev, fichier, tool):
    return {"identity": {"canonical_rule_id": f"rule-{i}", "fingerprint": f"fp-{i}"},
            "location": {"asset": "repository", "file": fichier, "line": i},
            "severity": {"value": sev, "origine": tool},
            "source": {"tool": tool},
            "evidence": {"title": f"titre {i}", "description": f"desc {i}"}}


def _ledger_execute(pid, findings, cibles):
    return {"provider": pid, "capability": "static-analysis", "outil": pid,
            "binaire": pid, "disponible": True, "statut": "execute",
            "raison": "ok", "findings": findings, "code_retour": 0, "timeout": False,
            "cibles_analysees": cibles,
            "rien_trouve": bool(findings == 0 and cibles > 0), "en_cours": False}


def main() -> int:
    print("=== MISSION HISTORY : CONTRATS PRODUCT, AU TRAVERS DE L'API ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="agnt-mhistory-"))
    MS.MISSIONS = tmp / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)

    serveur = ThreadingHTTPServer(("127.0.0.1", 0), Silencieux)
    base = f"http://127.0.0.1:{serveur.server_address[1]}"
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    try:
        # ------------------------------------------------------------ 1. liste vide
        code, rep = http(base, "/api/missions")
        cas("1. liste vide → 200, items [] + schema_version + page",
            code == 200 and rep.get("schema_version") == "agnt.history.v1"
            and rep.get("items") == [] and isinstance(rep.get("page"), dict),
            f"code={code}")

        # ------------------------------------------------------------ fixtures
        Z = "+00:00"
        t = "2026-08-30T12:00:0"
        # A — terminée, zéro findings PROUVÉ (rien_trouve)
        _ecrire(MS.MISSIONS, "m-20260830T120005Z-00000001", t + "5" + Z,
                _cible("repository", "/home/user/agnt/PHASE3/testrepo"),
                [_ev(1, t + "5" + Z, "ouverture", requete="Analyse", cible="/home/user/agnt/PHASE3/testrepo"),
                 _ev(2, t + "5" + Z, "intention", statut="resolved", capabilities=["static-analysis"]),
                 _ev(3, t + "5" + Z, "plan", plan_id="plan000000000001", providers=["semgrep"]),
                 _ev(4, t + "6" + Z, "contexte", run_id="run0000000000001"),
                 _ev(5, t + "7" + Z, "execution", provider="semgrep", code_retour=0, timeout=False, findings=0),
                 _ev(6, t + "8" + Z, "statuts", resume={"execute": 1},
                     outils=[_ledger_execute("semgrep", 0, 3)]),
                 _ev(7, t + "8" + Z, "cloture", findings=0, clusters=0, result_digest="aaaa")],
                sortie={"plan.json": {"plan_id": "plan000000000001", "steps": [
                            {"capability": "static-analysis", "provider": "semgrep",
                             "risque": "PASSIVE", "commande": ["semgrep"], "args": [], "sorties": []}],
                            "selection": {}},
                        "findings.json": [],
                        "clusters.json": {"clusters": [], "non_regroupe": [], "stats": {}},
                        "run.json": {"run_id": "run0000000000001", "plan_id": "plan000000000001"},
                        "rapport.json": {"requete": "Analyse", "couverture": {},
                                         "autorisation": {"allow": True, "motifs": []},
                                         "statuts": [_ledger_execute("semgrep", 0, 3)]}},
                rapport_md="# Résumé\nAucun finding.\n")
        # B — terminée, findings réels
        _ecrire(MS.MISSIONS, "m-20260830T120004Z-00000002", t + "4" + Z,
                _cible("repository", "/home/user/agnt/PHASE3/testrepo"),
                [_ev(1, t + "4" + Z, "ouverture", requete="x", cible="/home/user/agnt/PHASE3/testrepo"),
                 _ev(2, t + "4" + Z, "plan", plan_id="plan000000000002", providers=["trivy"]),
                 _ev(3, t + "5" + Z, "contexte", run_id="run0000000000002"),
                 _ev(4, t + "6" + Z, "execution", provider="trivy", code_retour=0, timeout=False, findings=2),
                 _ev(5, t + "6" + Z, "cloture", findings=2, clusters=1, result_digest="bbbb")],
                sortie={"findings.json": [_finding(1, "HIGH", "src/a.py", "trivy"),
                                          _finding(2, "MEDIUM", "src/b.py", "trivy")],
                        "clusters.json": {"clusters": [{"cluster_id": "c1", "members": []}],
                                          "non_regroupe": [], "stats": {}}})
        # C — refus de politique (pré-Run)
        _ecrire(MS.MISSIONS, "m-20260830T120003Z-00000003", t + "3" + Z,
                _cible("repository", "/home/user/agnt/PHASE3/testrepo"),
                [_ev(1, t + "3" + Z, "ouverture", requete="x", cible="/home/user/agnt/PHASE3/testrepo"),
                 _ev(2, t + "3" + Z, "plan", plan_id="plan000000000003", providers=["semgrep"]),
                 _ev(3, t + "3" + Z, "arret", motif="policy", decision=["refus par défaut"])])
        # D — indisponibilité provider (binaire absent) → indisponible, jamais zéro
        _ecrire(MS.MISSIONS, "m-20260830T120002Z-00000004", t + "2" + Z,
                _cible("repository", "/home/user/agnt/PHASE3/testrepo"),
                [_ev(1, t + "2" + Z, "ouverture", requete="x", cible="/home/user/agnt/PHASE3/testrepo"),
                 _ev(2, t + "2" + Z, "plan", plan_id="plan000000000004", providers=["semgrep"]),
                 _ev(3, t + "2" + Z, "statuts", resume={}, outils=[{
                     "provider": "semgrep", "capability": "static-analysis", "outil": "semgrep",
                     "binaire": "semgrep", "disponible": False, "statut": "non_disponible",
                     "raison": "exécutable introuvable", "findings": 0, "code_retour": None,
                     "timeout": False, "cibles_analysees": 0, "rien_trouve": False, "en_cours": False}]),
                 _ev(4, t + "2" + Z, "cloture", findings=0, clusters=0, result_digest="cccc")],
                sortie={"findings.json": []})
        # E — erreur d'exécution
        _ecrire(MS.MISSIONS, "m-20260830T120001Z-00000005", t + "1" + Z,
                _cible("filesystem", "/tmp/un_fichier.py"),
                [_ev(1, t + "1" + Z, "ouverture", requete="x", cible="/tmp/un_fichier.py"),
                 _ev(2, t + "1" + Z, "plan", plan_id="plan000000000005", providers=["bandit"]),
                 _ev(3, t + "2" + Z, "contexte", run_id="run0000000000005"),
                 _ev(4, t + "3" + Z, "execution", provider="bandit", code_retour=1, timeout=False, findings=0),
                 _ev(5, t + "3" + Z, "arret", motif="execution_bandit", erreur="RuntimeError: crash")])
        # F — ancienne mission (cible legacy, pas de descripteur)
        _ecrire(MS.MISSIONS, "m-20260830T120000Z-00000006", t + "0" + Z,
                {"chemin": "/data/repos/app", "type": "repertoire"},
                [_ev(1, t + "0" + Z, "ouverture", requete="x", cible="/data/repos/app"),
                 _ev(2, t + "0" + Z, "reprise"),
                 _ev(3, t + "0" + Z, "cloture", findings=0, clusters=0, result_digest="dddd")])
        # G — cible URL avec userinfo
        _ecrire(MS.MISSIONS, "m-20260830T115959Z-00000007", "2026-08-30T11:59:59" + Z,
                _cible("url", "https://alice:s3cret@github.com/org/repo.git"),
                [_ev(1, "2026-08-30T11:59:59" + Z, "ouverture",
                     requete="x", cible="https://alice:s3cret@github.com/org/repo.git"),
                 _ev(2, "2026-08-30T11:59:59" + Z, "arret", motif="applicabilite")])
        # H — mission sans journal (partielle)
        _ecrire(MS.MISSIONS, "m-20260830T115958Z-00000008", "2026-08-30T11:58:58" + Z,
                _cible("repository", "/home/user/agnt/PHASE3/testrepo"), None)
        # I — poison : secrets, argv, stack trace
        token = "sk-abcdefghijklmnopqrstuvwxyz123456"
        poison = _ecrire(MS.MISSIONS, "m-20260830T115957Z-00000009", "2026-08-30T11:57:57" + Z,
                         _cible("repository", "/home/user/agnt/PHASE3/testrepo"),
                         [_ev(1, "2026-08-30T11:57:57" + Z, "ouverture",
                              requete="analyse with " + token, cible="/home/user/agnt/PHASE3/testrepo"),
                          _ev(2, "2026-08-30T11:57:57" + Z, "arret", motif="policy",
                              erreur="Traceback (most recent call last): File \"/home/user/agnt/x.py\"")],
                         sortie={"plan.json": {"plan_id": "plan000000000009",
                                               "steps": [{"capability": "c", "provider": "semgrep",
                                                          "risque": "PASSIVE",
                                                          "commande": ["/home/user/.local/bin/semgrep", "--config", "/etc/passwd"],
                                                          "args": ["/etc/shadow"], "sorties": []}],
                                               "selection": {}}},
                         requete="analyse with " + token)
        # J — événement inconnu dans le journal
        _ecrire(MS.MISSIONS, "m-20260830T115956Z-00000010", "2026-08-30T11:56:56" + Z,
                _cible("repository", "/home/user/agnt/PHASE3/testrepo"),
                [_ev(1, "2026-08-30T11:56:56" + Z, "ouverture", requete="x", cible="/home/user/agnt/PHASE3/testrepo"),
                 _ev(2, "2026-08-30T11:56:56" + Z, "futur_evenement", payload={"secret": token}),
                 _ev(3, "2026-08-30T11:56:56" + Z, "cloture", findings=0, clusters=0, result_digest="eeee")])

        # ------------------------------------------------------------ 2. enveloppe + tri
        code, rep = http(base, "/api/missions?limit=100")
        ids = [i["mission_id"] for i in (rep or {}).get("items", [])]
        cas("2. schema_version + page.limit reflété + tri DESC stable",
            code == 200 and rep["schema_version"] == "agnt.history.v1"
            and rep["page"]["limit"] == 100 and rep["page"]["next_cursor"] is None
            and ids == ["m-20260830T120005Z-00000001", "m-20260830T120004Z-00000002",
                        "m-20260830T120003Z-00000003", "m-20260830T120002Z-00000004",
                        "m-20260830T120001Z-00000005", "m-20260830T120000Z-00000006",
                        "m-20260830T115959Z-00000007", "m-20260830T115958Z-00000008",
                        "m-20260830T115957Z-00000009", "m-20260830T115956Z-00000010"],
            f"ids={ids}")

        # ------------------------------------------------------------ 3. summary obligatoire
        code, rep = http(base, "/api/missions/m-20260830T120005Z-00000001")
        item = rep["mission"]
        cas("3. MissionSummary : champs obligatoires présents et corrects",
            code == 200 and all(k in item for k in
                ("mission_id", "detail_href", "request", "target", "status",
                 "created_at", "updated_at", "artifacts"))
            and item["detail_href"] == "/api/missions/m-20260830T120005Z-00000001"
            and item["status"] == "termine"
            and item["request"]["title"] and item["target"]["type"] == "repository"
            and item["target"]["display_name"] == "testrepo"
            and item["artifacts"]["findings"] is True,
            json.dumps(item, ensure_ascii=False)[:200])

        # ------------------------------------------------------------ 4. pagination curseur
        code, p1 = http(base, "/api/missions?limit=3")
        cas("4. pagination : 3 items + next_cursor opaque",
            code == 200 and len(p1["items"]) == 3 and p1["page"]["next_cursor"]
            and p1["page"]["limit"] == 3, f"items={len(p1.get('items', []))}")
        recolte = [i["mission_id"] for i in p1["items"]]
        curseur = p1["page"]["next_cursor"]
        while curseur:
            code, page = http(base, f"/api/missions?limit=3&cursor={curseur}")
            if code != 200:
                break
            recolte += [i["mission_id"] for i in page["items"]]
            curseur = page["page"]["next_cursor"]
        cas("4b. pagination complète sans doublon ni perte",
            recolte == ids, f"{len(recolte)} id(s)")
        code, rep = http(base, "/api/missions?cursor=%21%21%21")
        cas("4c. curseur invalide → 400 enveloppe error",
            code == 400 and rep.get("error", {}).get("code") == "INVALID_ARGUMENT", f"code={code}")

        # ------------------------------------------------------------ 5. filtres
        code, rep = http(base, "/api/missions?limit=100&status=termine")
        # Cinq missions « termine » : A, B (cloture), D (cloture malgré provider
        # indisponible — le cycle de vie est clos, l'indisponibilité reste un statut
        # d'exécution interne, contrat History §7), F (legacy), J (cloture).
        cas("5. filtre status=termine isolé",
            code == 200 and all(i["status"] == "termine" for i in rep["items"])
            and len(rep["items"]) == 5, f"n={len(rep.get('items', []))}")
        code, rep = http(base, "/api/missions?limit=100&target_type=url")
        cas("5b. filtre target_type=url isole la cible distante",
            code == 200 and [i["mission_id"] for i in rep["items"]] == ["m-20260830T115959Z-00000007"],
            f"{[i['mission_id'] for i in rep.get('items', [])]}")
        code, rep = http(base, "/api/missions?limit=100&target_type=repository")
        cas("5c. target_type=repository couvre aussi les anciennes missions (repertoire)",
            code == 200 and "m-20260830T120000Z-00000006" in [i["mission_id"] for i in rep["items"]])
        code, rep = http(base, "/api/missions?status=__agnt_invalid_status__")
        cas("5d. status inconnu → 400 enveloppe error",
            code == 400 and rep.get("error", {}).get("code") == "INVALID_ARGUMENT", f"code={code}")
        code, rep = http(base, "/api/missions?foo=1")
        cas("5e. filtre inconnu → 400 enveloppe error",
            code == 400 and rep.get("error", {}).get("code") == "INVALID_FILTER", f"code={code}")

        # ------------------------------------------------------------ 6. refus pré-Run
        code, rep = http(base, "/api/missions/m-20260830T120003Z-00000003")
        cas("6. refus de policy : refuse, sans run_id, sans findings_summary",
            code == 200 and rep["mission"]["status"] == "refuse"
            and "run_id" not in rep["mission"] and "findings_summary" not in rep["mission"],
            f"status={rep.get('mission', {}).get('status')}")

        # ------------------------------------------------------------ 7. zéro prouvé
        code, rep = http(base, "/api/missions/m-20260830T120005Z-00000001")
        m = rep["mission"]
        cas("7. zéro findings réel : findings_summary.total=0 (artefact lisible)",
            m["status"] == "termine" and m["findings_summary"] == {"total": 0, "by_severity": {}}
            and m["artifacts"]["findings"] is True,
            f"summary={m.get('findings_summary')}")
        execs = {e["provider_id"]: e for e in rep["data"]["executions"]}
        exe = execs["semgrep"]
        cas("7b. zéro findings → detection rien_trouve avec cibles analysées prouvées",
            exe["execution"]["value"] == "termine"
            and exe["detection"]["value"] == "rien_trouve"
            and exe["detection"]["findings_count"] == 0
            and exe["detection"]["analyzed_targets"] == 3,
            json.dumps(exe["detection"]))

        # ------------------------------------------------------------ 8. findings réels
        code, rep = http(base, "/api/missions/m-20260830T120004Z-00000002")
        m = rep["mission"]
        cas("8. findings réels : total 2, by_severity cohérent, findings dans data",
            m["findings_summary"]["total"] == 2
            and m["findings_summary"]["by_severity"] == {"HIGH": 1, "MEDIUM": 1}
            and len(rep["data"]["findings"]) == 2
            and rep["data"]["findings"][0]["location"]["file"] == "src/a.py",
            json.dumps(m.get("findings_summary")))

        # ------------------------------------------------------------ 9. findings absent
        code, rep = http(base, "/api/missions/m-20260830T120000Z-00000006")
        m = rep["mission"]
        cas("9. ancienne mission terminée sans artefact : findings jamais 0, artefact manquant",
            m["status"] == "termine" and "findings_summary" not in m
            and "findings" not in rep["data"] and "findings" in rep["missing_artifacts"],
            f"missing={rep.get('missing_artifacts')}")

        # ------------------------------------------------------------ 10. ancienne cible
        cas("10. ancienne cible legacy : type repository, display_name app, pas de /data/",
            m["target"]["type"] == "repository" and m["target"]["display_name"] == "app"
            and "/data/" not in json.dumps(rep), f"target={m['target']}")

        # ------------------------------------------------------------ 11. userinfo
        code, rep = http(base, "/api/missions/m-20260830T115959Z-00000007")
        corps = json.dumps(rep, ensure_ascii=False)
        cas("11. cible URL : userinfo retiré, credentials absents",
            rep["mission"]["target"]["display_name"] == "github.com"
            and "alice" not in corps and "s3cret" not in corps,
            f"target={rep['mission']['target']}")

        # ------------------------------------------------------------ 12. timeline
        code, rep = http(base, "/api/missions/m-20260830T120005Z-00000001")
        tl = rep["data"]["timeline"]
        cas("12. timeline : enveloppe conforme, ordre par seq, event_id déterministe",
            tl["schema_version"] == "agnt.timeline.v1"
            and tl["ordering"] == "journal_sequence_ascending"
            and tl["state"] == "complete" and tl["returned_events"] == 7
            and tl["events"][0]["event_id"] == "m-20260830T120005Z-00000001:1"
            and [e["position"] for e in tl["events"]] == list(range(1, 8)),
            f"state={tl['state']} n={tl['returned_events']}")
        code, rep = http(base, "/api/missions/m-20260830T115958Z-00000008")
        tl = rep["data"]["timeline"]
        cas("12b. journal absent → timeline unavailable + events dans missing",
            tl["state"] == "unavailable" and tl["events"] == []
            and "journal_missing" in tl["limitations"]
            and "events" in rep["missing_artifacts"],
            f"state={tl['state']} limitations={tl['limitations']}")
        code, rep = http(base, "/api/missions/m-20260830T115956Z-00000010")
        tl = rep["data"]["timeline"]
        inconnu = [e for e in tl["events"] if e["category"] == "unknown"]
        cas("12c. événement inconnu → unknown_event_recorded, payload jamais copié",
            len(inconnu) == 1 and inconnu[0]["kind"] == "unknown_event_recorded"
            and inconnu[0]["data_state"] == "unavailable"
            and token not in json.dumps(rep, ensure_ascii=False),
            f"kind={[e['kind'] for e in tl['events']]}")
        # pagination timeline
        code, rep = http(base, "/api/missions/m-20260830T120005Z-00000001?timeline_limit=3")
        tl = rep["data"]["timeline"]
        cas("12d. timeline_limit : 3 events, truncated + next_cursor",
            tl["returned_events"] == 3 and tl["truncated"] is True and tl["next_cursor"],
            f"n={tl['returned_events']} tronqué={tl['truncated']}")

        # ------------------------------------------------------------ 13. executions
        code, rep = http(base, "/api/missions/m-20260830T120002Z-00000004")
        exe = next(e for e in rep["data"]["executions"] if e["provider_id"] == "semgrep")
        cas("13. provider indisponible → unavailable, jamais zéro finding",
            exe["schema_version"] == "agnt.execution-status.v1"
            and exe["availability"]["value"] == "indisponible"
            and exe["execution"]["value"] == "unavailable"
            and exe["execution"]["invocation"] == "non"
            and exe["detection"]["value"] == "non_evalue"
            and "findings_count" not in exe["detection"],
            json.dumps(exe["execution"]) + " " + json.dumps(exe["detection"]))
        code, rep = http(base, "/api/missions/m-20260830T120001Z-00000005")
        bandit = next(e for e in rep["data"]["executions"] if e["provider_id"] == "bandit")
        cas("13b. échec d'exécution → echoue, détection non_evalue (jamais zéro)",
            bandit["execution"]["value"] == "echoue"
            and bandit["detection"]["value"] == "non_evalue"
            and "findings_count" not in bandit["detection"],
            json.dumps(bandit["execution"]))
        code, rep = http(base, "/api/missions/m-20260830T120003Z-00000003")
        cas("13c. refus de policy : le provider est non_autorise (jamais zéro)",
            any(e["provider_id"] == "semgrep"
                and e["authorization"]["value"] == "non_autorise"
                and e["detection"]["value"] == "non_evalue"
                for e in rep["data"]["executions"]),
            json.dumps(rep["data"]["executions"])[:300])

        # ------------------------------------------------------------ 14. interdits
        code, rep = http(base, "/api/missions/m-20260830T115957Z-00000009")
        code2, listing = http(base, "/api/missions?limit=100")
        tout = json.dumps(rep, ensure_ascii=False) + json.dumps(listing, ensure_ascii=False)
        interdits = ["/home/", "PRIVATE KEY", "Traceback", "/etc/passwd", "/etc/shadow",
                     "alice:s3cret@", "s3cret", token]
        fuites = [s for s in interdits if s in tout]
        cas("14. aucun interdit publié (chemin, secret, argv, stack trace)",
            code == 200 and not fuites, f"fuites={fuites}")

        # ------------------------------------------------------------ 15. traversal / symlink
        code, rep = http(base, "/api/missions/../../etc/passwd")
        cas("15. traversal refusé (404) sans lire hors racine",
            code == 404 and rep.get("error", {}).get("code") == "MISSION_NOT_FOUND", f"code={code}")
        code, rep = http(base, "/api/missions/m-20260830T120000Z-00000001%2f..%2fetc")
        cas("15b. identifiant hostile encodé refusé (404)", code == 404, f"code={code}")
        hors = tmp / "secret_hors_racine.txt"
        hors.write_text("SECRET-DE-LECTURE-HORS-RACINE", encoding="utf-8")
        try:
            (MS.MISSIONS / "m-20260830T115955Z-00000011").symlink_to(hors)
        except OSError:
            pass
        code, rep = http(base, "/api/missions/m-20260830T115955Z-00000011")
        cas("15c. symlink sortant refusé (404), jamais suivi",
            code == 404 and "SECRET-DE-LECTURE-HORS-RACINE" not in json.dumps(rep), f"code={code}")
        code, listing = http(base, "/api/missions?limit=100")
        cas("15d. le symlink sortant n'apparaît pas dans le listing",
            code == 200 and all(i["mission_id"] != "m-20260830T115955Z-00000011"
                                for i in listing["items"]), "symlink listé")

        # ------------------------------------------------------------ 16. polling additif
        # Un état de run injecté dans la file (le POST réel exige OPA/outils ; ici on
        # juge la frontière de lecture, pas l'exécution).
        with api.VERROU:
            api.ETATS["poll-test-1"] = {"statut": "refuse", "question": "Analyse la sécurité de ce dépôt",
                                        "cible": "/home/user/agnt/PHASE3/testrepo",
                                        "pose_le": time.time(),
                                        "resume": {"mission": "m-20260830T120005Z-00000001",
                                                   "motif": "PolicyError"}}
        code, etat = http(base, "/api/runs/poll-test-1")
        cas("16. polling : mission_id + detail_href additifs, champs conservés",
            code == 200 and etat["id"] == "poll-test-1" and etat["statut"] == "refuse"
            and etat["mission_id"] == "m-20260830T120005Z-00000001"
            and etat["detail_href"] == "/api/missions/m-20260830T120005Z-00000001",
            f"code={code} clés={sorted(etat.keys())}")
        code, rep = http(base, etat["detail_href"])
        cas("16b. detail_href pointe vers un détail 200 conforme",
            code == 200 and rep["schema_version"] == "agnt.history.v1", f"code={code}")

        # ------------------------------------------------------------ 17. partiel / inconnu
        code, rep = http(base, "/api/missions/m-20260830T115958Z-00000008")
        cas("17. mission sans journal : inconnu + incomplete, jamais termine",
            rep["mission"]["status"] == "inconnu" and rep["mission"]["incomplete"] is True,
            f"status={rep['mission']['status']}")

    finally:
        serveur.shutdown()
        serveur.server_close()
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
    sys.exit(1 if ECHECS else 0)


if __name__ == "__main__":
    raise SystemExit(main())
