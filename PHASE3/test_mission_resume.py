#!/usr/bin/env python3
"""Mission Resume — la projection console jugée sur les cas qui font mentir un écran.

Ce que cette batterie mesure, sans réseau, sans outil, sans `opa`, sans HTTP :

  1. mission refusée faute d'outils      → refus lisible, jamais « 0 finding » ;
  2. mission bloquée par la politique    → provider `refuses`, résultat `refuse` ;
  3. plan partiel / interrompu           → `plan.etat == partiel`, projection entière ;
  4. artefact findings absent            → `count is None` + `artefacts_manquants` ;
  5. exécution échouée                   → `echoues`, erreur redactée, aucun compte ;
  6. mission terminée exploitable        → compte prouvé, sévérités, résultat dispo ;
  7. PAS DE FAUX ZÉRO                    → `findings.json` vide sans cible analysée
                                            = `None` ; avec cible analysée = 0 prouvé ;
  8. robustesse                          → plan illisible, ledger malformé, provider
                                            absent, journal absent : aucun crash.

Usage : python3 PHASE3/test_mission_resume.py
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import mission as MS                                          # noqa: E402
import mission_resume as MR                                   # noqa: E402
import mission_history as MH                                  # noqa: E402

PAS = 0
ECHECS = 0
Z = "+00:00"


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def _ev(seq, ts, type_, **payload):
    return {"seq": seq, "ts": ts, "type": type_, **payload}


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


def _ledger(pid, statut, **kw):
    base = {"provider": pid, "capability": "static-analysis", "outil": pid,
            "binaire": pid, "disponible": statut != "non_disponible", "statut": statut,
            "raison": statut, "findings": 0, "code_retour": 0, "timeout": False,
            "cibles_analysees": 0, "rien_trouve": False, "en_cours": False}
    base.update(kw)
    return base


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


def main() -> int:
    print("=== MISSION RESUME : PROJECTION CONSOLE, CAS HONNÊTES ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="agnt-mresume-"))
    MS.MISSIONS = tmp / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)
    R = MS.MISSIONS
    t = "2026-08-31T10:00:0"
    try:
        # ---------------------------------------------------------------- 1. faute d'outils
        mid = "m-20260831T100001Z-00000001"
        _ecrire(R, mid, t + "1" + Z, _cible("repository", "/home/user/agnt/PHASE3/testrepo"),
                [_ev(1, t + "1" + Z, "ouverture", requete="x", cible="/home/user/agnt/PHASE3/testrepo"),
                 _ev(2, t + "1" + Z, "plan", plan_id="plan000000000001", providers=["semgrep"]),
                 _ev(3, t + "1" + Z, "statuts", resume={},
                     outils=[_ledger("semgrep", "non_disponible", raison="exécutable introuvable")]),
                 _ev(4, t + "2" + Z, "arret", motif="disponibilite", ecartes=["semgrep"])])
        r = MR.resumer_mission(mid)
        cas("1. refus faute d'outils : statut refuse, aucun compte, provider indisponible",
            r["schema_version"] == MR.SUMMARY_VERSION
            and r["statut"] == "refuse"
            and r["findings_count"] is None
            and r["findings"]["etat"] == "non_produit"
            and r["resultat"]["etat"] == "refuse"
            and r["providers"]["comptes"]["non_disponibles"] == 1
            and r["providers"]["comptes"]["executes"] == 0
            and "outil disponible" in r["resultat"]["message"],
            json.dumps(r["resultat"], ensure_ascii=False))
        cas("1b. cible et requête lisibles, sans chemin absolu",
            r["cible"]["type"] == "repository" and r["cible"]["display_name"] == "testrepo"
            and r["requete"]["titre"].startswith("Analyse")
            and "/home/user" not in json.dumps(r, ensure_ascii=False),
            json.dumps(r["cible"], ensure_ascii=False))

        # ---------------------------------------------------------------- 2. policy
        mid = "m-20260831T100002Z-00000002"
        _ecrire(R, mid, t + "2" + Z, _cible("repository", "/srv/app"),
                [_ev(1, t + "2" + Z, "ouverture", requete="x", cible="/srv/app"),
                 _ev(2, t + "2" + Z, "plan", plan_id="plan000000000002", providers=["semgrep"]),
                 _ev(3, t + "2" + Z, "arret", motif="policy", decision=["refus par défaut"])])
        r = MR.resumer_mission(mid)
        cas("2. bloquée par la politique avant exécution : refus nommé, provider refusé",
            r["statut"] == "refuse"
            and r["resultat"]["etat"] == "refuse"
            and r["terminal"]["categorie"] == "policy"
            and r["terminal"]["motif"] == "policy"
            and r["providers"]["comptes"]["refuses"] == 1
            and r["findings_count"] is None
            and r["findings"]["etat"] == "non_produit",
            json.dumps(r["providers"]["comptes"]))

        # ---------------------------------------------------------------- 3. plan partiel
        mid = "m-20260831T100003Z-00000003"
        _ecrire(R, mid, t + "3" + Z, _cible("repository", "/srv/app"),
                [_ev(1, t + "3" + Z, "ouverture", requete="x", cible="/srv/app"),
                 _ev(2, t + "3" + Z, "plan", plan_id="plan000000000003", providers=["semgrep"])],
                sortie={"plan.json": {"plan_id": "plan000000000003",
                                      "steps": [{"capability": "static-analysis",
                                                 "provider": "semgrep", "risque": "PASSIVE"},
                                                {"capability": "static-analysis"},
                                                "morceau-tronque"],
                                      "selection": {}}})
        r = MR.resumer_mission(mid)
        cas("3. plan partiel : projection entière, steps invalides comptés, aucun compte inventé",
            r["plan"]["etat"] == "partiel" and r["plan"]["steps"] == 3
            and r["plan"]["steps_invalides"] == 2 and r["plan"]["providers"] == ["semgrep"]
            and r["statut"] == "inconnu" and r["incomplete"] is True
            and r["resultat"]["etat"] == "indetermine"
            and r["findings"]["etat"] == "incomplet" and r["findings_count"] is None,
            json.dumps(r["plan"], ensure_ascii=False))

        # ---------------------------------------------------------------- 4. findings absents
        mid = "m-20260831T100004Z-00000004"
        _ecrire(R, mid, t + "4" + Z, _cible("repository", "/srv/app"),
                [_ev(1, t + "4" + Z, "ouverture", requete="x", cible="/srv/app"),
                 _ev(2, t + "4" + Z, "plan", plan_id="plan000000000004", providers=["semgrep"]),
                 _ev(3, t + "5" + Z, "execution", provider="semgrep", code_retour=0,
                     timeout=False, findings=3),
                 _ev(4, t + "6" + Z, "cloture", findings=3, clusters=1, result_digest="aaaa")])
        r = MR.resumer_mission(mid)
        cas("4. mission close SANS artefact findings : compte absent, manquants nommés",
            r["statut"] == "termine" and r["findings_count"] is None
            and r["findings"]["etat"] == "artefacts_manquants"
            and "findings" in r["artefacts_manquants"]
            and r["artefacts"]["findings"] == "absent"
            and r["resultat"]["etat"] == "resultat_partiel"
            and r["providers"]["comptes"]["executes"] == 1,
            json.dumps(r["findings"], ensure_ascii=False))

        # ---------------------------------------------------------------- 5. exécution échouée
        mid = "m-20260831T100005Z-00000005"
        _ecrire(R, mid, t + "5" + Z, _cible("filesystem", "/tmp/un_fichier.py"),
                [_ev(1, t + "5" + Z, "ouverture", requete="x", cible="/tmp/un_fichier.py"),
                 _ev(2, t + "5" + Z, "plan", plan_id="plan000000000005", providers=["bandit"]),
                 _ev(3, t + "6" + Z, "contexte", run_id="run0000000000005"),
                 _ev(4, t + "7" + Z, "execution", provider="bandit", code_retour=1,
                     timeout=False, findings=0),
                 _ev(5, t + "7" + Z, "arret", motif="execution_bandit",
                     erreur="Traceback (most recent call last): RuntimeError: crash /etc/passwd")])
        r = MR.resumer_mission(mid)
        cas("5. exécution échouée : erreur, provider echoue, aucun 0 déduit",
            r["statut"] == "erreur" and r["resultat"]["etat"] == "erreur"
            and r["providers"]["comptes"]["echoues"] == 1
            and r["providers"]["par_etat"]["echoues"][0]["findings"] is None
            and r["findings_count"] is None and r["findings"]["etat"] == "non_produit"
            and r["run_id"] == "run0000000000005"
            and "Traceback" not in r["terminal"]["erreur"],
            json.dumps(r["terminal"], ensure_ascii=False))

        # ---------------------------------------------------------------- 6. résultat exploitable
        mid = "m-20260831T100006Z-00000006"
        ledger_ok = _ledger("semgrep", "execute", findings=2, cibles_analysees=7)
        _ecrire(R, mid, t + "6" + Z, _cible("repository", "/srv/app"),
                [_ev(1, t + "6" + Z, "ouverture", requete="x", cible="/srv/app"),
                 _ev(2, t + "6" + Z, "plan", plan_id="plan000000000006", providers=["semgrep"]),
                 _ev(3, t + "7" + Z, "contexte", run_id="run0000000000006"),
                 _ev(4, t + "8" + Z, "execution", provider="semgrep", code_retour=0,
                     timeout=False, findings=2),
                 _ev(5, t + "9" + Z, "statuts", resume={"execute": 1}, outils=[ledger_ok]),
                 _ev(6, t + "9" + Z, "cloture", findings=2, clusters=1, result_digest="bbbb")],
                sortie={"plan.json": {"plan_id": "plan000000000006",
                                      "steps": [{"capability": "static-analysis",
                                                 "provider": "semgrep", "risque": "PASSIVE"}],
                                      "selection": {}},
                        "findings.json": [_finding(1, "HIGH", "src/a.py", "semgrep"),
                                          _finding(2, "MEDIUM", "src/b.py", "semgrep")],
                        "clusters.json": {"clusters": [{"cluster_id": "c1", "members": []}],
                                          "non_regroupe": [], "stats": {}},
                        "run.json": {"run_id": "run0000000000006", "plan_id": "plan000000000006"},
                        "rapport.json": {"requete": "x", "couverture": {},
                                         "autorisation": {"allow": True, "motifs": []},
                                         "statuts": [ledger_ok]}},
                rapport_md="# Résumé\n2 findings.\n")
        r = MR.resumer_mission(mid)
        cas("6. mission terminée exploitable : compte prouvé, sévérités, résultat disponible",
            r["statut"] == "termine" and r["findings_count"] == 2
            and r["findings"]["etat"] == "prouve"
            and r["findings"]["par_severite"] == {"HIGH": 1, "MEDIUM": 1}
            and r["resultat"]["etat"] == "resultat_disponible"
            and r["providers"]["comptes"]["executes"] == 1
            and r["providers"]["par_etat"]["executes"][0]["findings"] == 2
            and r["plan"]["etat"] == "complet"
            and r["artefacts"]["rapport_lisible"] == "present"
            and r["artefacts_manquants"] == []
            and r["dates"]["duree_ms"] == 2000,
            json.dumps(r["resultat"], ensure_ascii=False))
        cas("6b. journal projeté : volume, bornes et derniers événements sûrs",
            r["journal"]["etat"] == "complete" and r["journal"]["evenements"] == 6
            and r["journal"]["derniers"][-1]["kind"] == "mission_completed"
            and r["journal"]["derniers"][0]["sequence"] == 1,
            json.dumps(r["journal"]["derniers"][-1], ensure_ascii=False))

        # ---------------------------------------------------------------- 7. pas de faux zéro
        mid_faux = "m-20260831T100007Z-00000007"
        _ecrire(R, mid_faux, t + "7" + Z, _cible("repository", "/srv/app"),
                [_ev(1, t + "7" + Z, "ouverture", requete="x", cible="/srv/app"),
                 _ev(2, t + "7" + Z, "plan", plan_id="plan000000000007", providers=["semgrep"]),
                 _ev(3, t + "7" + Z, "statuts", resume={},
                     outils=[_ledger("semgrep", "non_disponible", raison="introuvable")]),
                 _ev(4, t + "8" + Z, "cloture", findings=0, clusters=0, result_digest="cccc")],
                sortie={"findings.json": []})
        rf = MR.resumer_mission(mid_faux)
        cas("7. findings vide SANS cible analysée : jamais 0 — état non_prouve",
            rf["statut"] == "termine" and rf["findings_count"] is None
            and rf["findings"]["etat"] == "non_prouve"
            and rf["resultat"]["etat"] == "aucun_resultat"
            and rf["providers"]["comptes"]["non_disponibles"] == 1,
            json.dumps(rf["findings"], ensure_ascii=False))

        mid_vrai = "m-20260831T100008Z-00000008"
        ledger_zero = _ledger("semgrep", "execute", findings=0, cibles_analysees=4,
                              rien_trouve=True)
        _ecrire(R, mid_vrai, t + "8" + Z, _cible("repository", "/srv/app"),
                [_ev(1, t + "8" + Z, "ouverture", requete="x", cible="/srv/app"),
                 _ev(2, t + "8" + Z, "plan", plan_id="plan000000000008", providers=["semgrep"]),
                 _ev(3, t + "8" + Z, "statuts", resume={"execute": 1}, outils=[ledger_zero]),
                 _ev(4, t + "9" + Z, "cloture", findings=0, clusters=0, result_digest="dddd")],
                sortie={"findings.json": [], "clusters.json": {"clusters": []},
                        "rapport.json": {"autorisation": {"allow": True, "motifs": []},
                                         "statuts": [ledger_zero]}},
                rapport_md="# Résumé\nAucun finding.\n")
        rz = MR.resumer_mission(mid_vrai)
        cas("7b. findings vide AVEC cibles analysées prouvées : 0 est un résultat",
            rz["findings_count"] == 0 and rz["findings"]["etat"] == "prouve"
            and rz["resultat"]["etat"] == "resultat_disponible"
            and rz["providers"]["par_etat"]["executes"][0]["detection"] == "rien_trouve",
            json.dumps(rz["findings"], ensure_ascii=False))

        # ---------------------------------------------------------------- 8. robustesse
        mid = "m-20260831T100009Z-00000009"
        _ecrire(R, mid, t + "9" + Z, {"chemin": "/data/repos/app", "type": "repertoire"},
                [_ev(1, t + "9" + Z, "ouverture", requete="x", cible="/data/repos/app"),
                 _ev(2, t + "9" + Z, "statuts", resume={},
                     outils=[{"provider": None, "statut": "execute"},
                             "ligne-cassee",
                             {"provider": "outil_x", "statut": "vocabulaire_inconnu"}]),
                 _ev(3, t + "9" + Z, "cloture", findings=0, clusters=0, result_digest="eeee")],
                sortie={"plan.json": "{ceci n'est pas du json"})
        r = MR.resumer_mission(mid)
        cas("8. plan illisible + ledger malformé + provider absent : aucun crash, tout nommé",
            r["plan"]["etat"] == "illisible" and r["plan"]["providers"] == []
            and r["providers"]["total"] == 1
            and r["providers"]["comptes"]["indetermines"] == 1
            and r["findings_count"] is None
            and r["findings"]["etat"] == "artefacts_manquants"
            and r["cible"]["type"] == "repository",
            json.dumps(r["plan"], ensure_ascii=False))

        mid = "m-20260831T100010Z-00000010"
        _ecrire(R, mid, "2026-08-31T10:00:10" + Z,
                _cible("url", "https://alice:s3cret@github.com/org/repo.git"), None)
        r = MR.resumer_mission(mid)
        cas("8b. mission sans journal ni artefact : incomplète, lisible, sans credential",
            r["statut"] == "inconnu" and r["incomplete"] is True
            and r["journal"]["etat"] == "unavailable"
            and r["artefacts"]["journal"] == "absent"
            and "events" in r["artefacts_manquants"]
            and r["resultat"]["etat"] == "indetermine"
            and r["providers"]["total"] == 0
            and r["cible"]["display_name"] == "github.com"
            and "s3cret" not in json.dumps(r, ensure_ascii=False),
            json.dumps(r["journal"], ensure_ascii=False))

        introuvable = False
        try:
            MR.resumer_mission("m-20260831T100010Z-00000010/../../etc")
        except MH.MissionIntrouvable:
            introuvable = True
        cas("8c. identifiant hostile : MissionIntrouvable, aucune lecture hors racine",
            introuvable)

        # cohérence : le vocabulaire du résumé reste fermé sur tous les cas produits
        etats = set()
        groupes = set()
        for d in sorted(R.iterdir()):
            rr = MR.resumer_dossier(d)
            etats.add(rr["resultat"]["etat"])
            etats.add(rr["findings"]["etat"])
            groupes |= {g for g, v in rr["providers"]["comptes"].items() if v}
        cas("9. vocabulaire fermé : aucun état hors contrat sur l'ensemble des cas",
            etats <= set(MR.RESULTATS) | set(MR.ETATS_FINDINGS)
            and groupes <= set(MR.GROUPES),
            f"etats={sorted(etats)} groupes={sorted(groupes)}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n=== {PAS} OK, {ECHECS} ECHEC(S) ===")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
