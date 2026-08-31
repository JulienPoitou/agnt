#!/usr/bin/env python3
"""GATE-002 — producteur des captures contrôlées du gate Product/API.

Le gate Product (`docs/coordination/api-conformance-gate/product_api_gate.py`) valide
les trois contrats (`agnt.history.v1`, `agnt.timeline.v1`, `agnt.execution-status.v1`)
soit contre une API vivante, soit contre un manifeste de captures. Son mode
`--require-full-coverage` exige que le jeu de données exerce TOUTE la matrice
sémantique — ce qu'un seul environnement réel ne contient jamais naturellement
(son README le dit explicitement).

Ce script produit ce jeu de données : il construit des missions CONTRÔLÉES, sert
l'API CORE RÉELLE en process, et capture ses réponses HTTP réelles. Aucune réponse
n'est écrite à la main : chaque octet publié ici est sorti de `interface/api.py`
+ `slice/mission_history.py`.

La construction des missions réutilise les helpers de `test_mission_history_api.py`
(import du module de test) : la capture et la batterie de 36 cas partagent donc la
MÊME définition de ce qu'est une mission contrôlée. Pas de deuxième vérité.

Usage :
    python3 PHASE3/produire_captures_product.py [--out docs/coordination/captures/gate-002-product-api]

Sortie : `<out>/capture-manifest.json` + un fichier JSON par réponse.
Le script n'écrit jamais dans le dépôt analysé et ne contacte aucun réseau.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import threading
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))
sys.path.insert(0, str(RACINE / "interface"))
sys.path.insert(0, str(RACINE))

import api                                                    # noqa: E402
import mission as MS                                          # noqa: E402
import test_mission_history_api as T                          # noqa: E402

Z = "+00:00"
BASE_TS = "2026-08-30T12:00:0"


def _construire(racine: Path) -> list[str]:
    """Les missions contrôlées, une par cas sémantique de la matrice du gate.

    Rend les identifiants dans l'ordre du listing attendu (created_at DESC).
    """
    ecrire, cible, finding, ledger = T._ecrire, T._cible, T._finding, T._ledger_execute
    ids: list[str] = []

    # A — terminée, ZÉRO finding PROUVÉ (`rien_trouve` + cibles analysées)  → zero
    ids.append("m-20260830T120005Z-00000001")
    ecrire(racine, ids[-1], BASE_TS + "5" + Z, cible("repository", "PHASE3/testrepo"),
           [T._ev(1, BASE_TS + "5" + Z, "ouverture", requete="Analyse", cible="PHASE3/testrepo"),
            T._ev(2, BASE_TS + "5" + Z, "intention", statut="resolved",
                  capabilities=["CODE_STATIC_ANALYSIS"]),
            T._ev(3, BASE_TS + "5" + Z, "plan", plan_id="plan000000000001",
                  providers=["semgrep"]),
            T._ev(4, BASE_TS + "6" + Z, "contexte", run_id="run0000000000001"),
            T._ev(5, BASE_TS + "7" + Z, "execution", provider="semgrep", code_retour=0,
                  timeout=False, findings=0),
            T._ev(6, BASE_TS + "8" + Z, "statuts", resume={"execute": 1},
                  outils=[ledger("semgrep", 0, 3)]),
            T._ev(7, BASE_TS + "8" + Z, "cloture", findings=0, clusters=0,
                  result_digest="aaaa")],
           sortie={"plan.json": {"plan_id": "plan000000000001", "steps": [
                       {"capability": "CODE_STATIC_ANALYSIS", "provider": "semgrep",
                        "risque": "PASSIVE", "sorties": []}], "selection": {}},
                   "findings.json": [],
                   "clusters.json": {"clusters": [], "non_regroupe": [], "stats": {}},
                   "run.json": {"run_id": "run0000000000001",
                                "plan_id": "plan000000000001"},
                   "rapport.json": {"requete": "Analyse", "couverture": {},
                                    "autorisation": {"allow": True, "motifs": []},
                                    "statuts": [ledger("semgrep", 0, 3)]}},
           rapport_md="# Résumé\nAucun finding.\n")

    # B — terminée, FINDINGS réels                                          → findings
    ids.append("m-20260830T120004Z-00000002")
    ecrire(racine, ids[-1], BASE_TS + "4" + Z, cible("repository", "PHASE3/testrepo"),
           [T._ev(1, BASE_TS + "4" + Z, "ouverture", requete="x", cible="PHASE3/testrepo"),
            T._ev(2, BASE_TS + "4" + Z, "plan", plan_id="plan000000000002",
                  providers=["trivy"]),
            T._ev(3, BASE_TS + "5" + Z, "contexte", run_id="run0000000000002"),
            T._ev(4, BASE_TS + "6" + Z, "execution", provider="trivy", code_retour=0,
                  timeout=False, findings=2),
            T._ev(5, BASE_TS + "6" + Z, "cloture", findings=2, clusters=1,
                  result_digest="bbbb")],
           sortie={"findings.json": [finding(1, "HIGH", "src/a.py", "trivy"),
                                     finding(2, "MEDIUM", "src/b.py", "trivy")],
                   "clusters.json": {"clusters": [{"cluster_id": "c1", "members": []}],
                                     "non_regroupe": [], "stats": {}}})

    # C — refus de politique (pré-Run)                                      → refused
    ids.append("m-20260830T120003Z-00000003")
    ecrire(racine, ids[-1], BASE_TS + "3" + Z, cible("repository", "PHASE3/testrepo"),
           [T._ev(1, BASE_TS + "3" + Z, "ouverture", requete="x", cible="PHASE3/testrepo"),
            T._ev(2, BASE_TS + "3" + Z, "plan", plan_id="plan000000000003",
                  providers=["semgrep"]),
            T._ev(3, BASE_TS + "3" + Z, "arret", motif="policy",
                  decision=["refus par défaut"])])

    # D — provider indisponible (binaire absent) : jamais zéro             → unavailable
    ids.append("m-20260830T120002Z-00000004")
    ecrire(racine, ids[-1], BASE_TS + "2" + Z, cible("repository", "PHASE3/testrepo"),
           [T._ev(1, BASE_TS + "2" + Z, "ouverture", requete="x", cible="PHASE3/testrepo"),
            T._ev(2, BASE_TS + "2" + Z, "plan", plan_id="plan000000000004",
                  providers=["semgrep"]),
            T._ev(3, BASE_TS + "2" + Z, "statuts", resume={}, outils=[{
                "provider": "semgrep", "capability": "CODE_STATIC_ANALYSIS",
                "outil": "semgrep", "binaire": "semgrep", "disponible": False,
                "statut": "non_disponible", "raison": "exécutable introuvable",
                "findings": 0, "code_retour": None, "timeout": False,
                "cibles_analysees": 0, "rien_trouve": False, "en_cours": False}]),
            T._ev(4, BASE_TS + "2" + Z, "cloture", findings=0, clusters=0,
                  result_digest="cccc")],
           sortie={"findings.json": []})

    # E — échec d'exécution                                                 → failed
    ids.append("m-20260830T120001Z-00000005")
    ecrire(racine, ids[-1], BASE_TS + "1" + Z, cible("filesystem", "un_fichier.py"),
           [T._ev(1, BASE_TS + "1" + Z, "ouverture", requete="x", cible="un_fichier.py"),
            T._ev(2, BASE_TS + "1" + Z, "plan", plan_id="plan000000000005",
                  providers=["bandit"]),
            T._ev(3, BASE_TS + "2" + Z, "contexte", run_id="run0000000000005"),
            T._ev(4, BASE_TS + "3" + Z, "execution", provider="bandit", code_retour=1,
                  timeout=False, findings=0),
            T._ev(5, BASE_TS + "3" + Z, "arret", motif="execution_bandit",
                  erreur="exécution interrompue")])

    # F — timeout d'exécution                                              → timeout
    ids.append("m-20260830T120000Z-00000006")
    ecrire(racine, ids[-1], BASE_TS + "0" + Z, cible("repository", "PHASE3/testrepo"),
           [T._ev(1, BASE_TS + "0" + Z, "ouverture", requete="x", cible="PHASE3/testrepo"),
            T._ev(2, BASE_TS + "0" + Z, "plan", plan_id="plan000000000006",
                  providers=["checkov"]),
            T._ev(3, "2026-08-30T12:00:01" + Z, "contexte", run_id="run0000000000006"),
            T._ev(4, "2026-08-30T12:00:02" + Z, "execution", provider="checkov",
                  code_retour=None, timeout=True, findings=0),
            T._ev(5, "2026-08-30T12:00:02" + Z, "statuts", resume={"echoue": 1},
                  outils=[{"provider": "checkov", "capability": "IAC_SCAN",
                           "outil": "checkov", "binaire": "checkov", "disponible": True,
                           "statut": "echoue", "raison": "timeout", "findings": 0,
                           "code_retour": None, "timeout": True, "cibles_analysees": 0,
                           "rien_trouve": False, "en_cours": False}]),
            T._ev(6, "2026-08-30T12:00:03" + Z, "cloture", findings=0, clusters=0,
                  result_digest="fff0")])

    # G — mission close pendant l'exécution : interrompue                 → cancelled
    ids.append("m-20260830T115959Z-00000007")
    ecrire(racine, ids[-1], "2026-08-30T11:59:59" + Z,
           cible("repository", "PHASE3/testrepo"),
           [T._ev(1, "2026-08-30T11:59:59" + Z, "ouverture", requete="x",
                  cible="PHASE3/testrepo"),
            T._ev(2, "2026-08-30T11:59:59" + Z, "plan", plan_id="plan000000000007",
                  providers=["gitleaks"]),
            T._ev(3, "2026-08-30T11:59:59" + Z, "statuts", resume={"selectionne": 1},
                  outils=[{"provider": "gitleaks", "capability": "SECRET_DETECTION",
                           "outil": "gitleaks", "binaire": "gitleaks", "disponible": True,
                           "statut": "selectionne", "raison": "exécution en cours",
                           "findings": 0, "code_retour": None, "timeout": False,
                           "cibles_analysees": 0, "rien_trouve": False,
                           "en_cours": True}]),
            T._ev(4, "2026-08-30T11:59:59" + Z, "cloture", findings=0, clusters=0,
                  result_digest="fff1")])

    # H — provider écarté à l'applicabilité (cible URL)              → non_applicable
    ids.append("m-20260830T115958Z-00000008")
    ecrire(racine, ids[-1], "2026-08-30T11:59:58" + Z,
           cible("url", "https://github.com/org/repo.git"),
           [T._ev(1, "2026-08-30T11:59:58" + Z, "ouverture", requete="x",
                  cible="https://github.com/org/repo.git"),
            T._ev(2, "2026-08-30T11:59:58" + Z, "plan", plan_id="plan000000000008",
                  providers=["semgrep"]),
            T._ev(3, "2026-08-30T11:59:58" + Z, "applicabilite",
                  ecartes={"kics": "non applicable à cette cible"}),
            T._ev(4, "2026-08-30T11:59:58" + Z, "arret", motif="applicabilite")])

    # I — artefacts manquants : aucune donnée fabriquée                 → incomplete
    ids.append("m-20260830T115957Z-00000009")
    ecrire(racine, ids[-1], "2026-08-30T11:59:57" + Z,
           cible("repository", "PHASE3/testrepo"),
           [T._ev(1, "2026-08-30T11:59:57" + Z, "ouverture", requete="x",
                  cible="PHASE3/testrepo"),
            T._ev(2, "2026-08-30T11:59:57" + Z, "plan", plan_id="plan000000000009",
                  providers=["detect_secrets"]),
            T._ev(3, "2026-08-30T11:59:57" + Z, "contexte", run_id="run0000000000009"),
            T._ev(4, "2026-08-30T11:59:57" + Z, "execution", provider="detect_secrets",
                  code_retour=0, timeout=False, findings=0),
            T._ev(5, "2026-08-30T11:59:57" + Z, "cloture", findings=0, clusters=0,
                  result_digest="fff2")])

    # J — type d'événement inconnu du lecteur : consigné, jamais deviné      → unknown
    ids.append("m-20260830T115956Z-0000000a")
    ecrire(racine, ids[-1], "2026-08-30T11:59:56" + Z,
           cible("repository", "PHASE3/testrepo"),
           [T._ev(1, "2026-08-30T11:59:56" + Z, "ouverture", requete="x",
                  cible="PHASE3/testrepo"),
            T._ev(2, "2026-08-30T11:59:56" + Z, "evenement_version_suivante",
                  detail="payload non publié"),
            T._ev(3, "2026-08-30T11:59:56" + Z, "arret", motif="conditions")])

    # K — provenance MCP CONSIGNÉE (faits du producteur, projetés en allowlist)  → mcp
    ids.append("m-20260830T115955Z-0000000b")
    ecrire(racine, ids[-1], "2026-08-30T11:59:55" + Z,
           cible("repository", "PHASE3/testrepo"),
           [T._ev(1, "2026-08-30T11:59:55" + Z, "ouverture", requete="x",
                  cible="PHASE3/testrepo"),
            T._ev(2, "2026-08-30T11:59:55" + Z, "plan", plan_id="plan00000000000a",
                  providers=["mcp_dep"]),
            T._ev(3, "2026-08-30T11:59:55" + Z, "statuts", resume={"execute": 1},
                  outils=[{"provider": "mcp_dep", "capability": "DEPENDENCY_ANALYSIS",
                           "outil": "mcp_dep", "binaire": "mcp_dep", "disponible": True,
                           "statut": "execute", "raison": "ok", "findings": 1,
                           "code_retour": 0, "timeout": False, "cibles_analysees": 4,
                           "rien_trouve": False, "en_cours": False,
                           "provenance": {
                               "provider_id": "mcp_dep", "provider_kind": "mcp",
                               "transport": "stdio", "server_id": "security-tools",
                               "tool_id": "scan_repository",
                               "protocol": {"name": "mcp", "version": "2025-11-25"},
                               "confidence": {"level": "medium",
                                              "basis": "provider_declared"},
                               "availability": "available",
                               # hors contrat / hostiles : le lecteur doit les jeter
                               "endpoint": "https://10.0.0.7:9000/mcp",
                               "token": "Bearer abc.def.ghi",
                               "argv": ["--secret", "x"],
                               "server_id_brut": "PHASE3/.mcp/sock"}}]),
            T._ev(4, "2026-08-30T11:59:55" + Z, "cloture", findings=1, clusters=1,
                  result_digest="fff3")],
           # Une mission qui a VRAIMENT exécuté porte son plan, ses findings et sa
           # décision de politique. Sans plan, le provider serait « hors plan » donc
           # « autorisé ? non évalué » tout en publiant un compte de findings —
           # incohérence que le gate Product refuse à juste titre.
           # `statuts` reste dans le JOURNAL : c'est ce ledger qui porte la provenance
           # (rapport.json.statuts repasserait par la projection du rapport).
           sortie={"plan.json": {"plan_id": "plan00000000000a", "steps": [
                       {"capability": "DEPENDENCY_ANALYSIS", "provider": "mcp_dep",
                        "risque": "PASSIVE", "sorties": []}], "selection": {}},
                   "findings.json": [finding(1, "HIGH", "go.mod", "mcp_dep")],
                   "clusters.json": {"clusters": [], "non_regroupe": [], "stats": {}},
                   "rapport.json": {"requete": "x",
                                    "autorisation": {"allow": True, "motifs": []}}})

    return ids


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="docs/coordination/captures/gate-002-product-api")
    args = ap.parse_args()
    out = Path(args.out).resolve()

    tmp = Path(tempfile.mkdtemp(prefix="agnt-capture-"))
    MS.MISSIONS = tmp / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)
    ids = _construire(MS.MISSIONS)

    serveur = ThreadingHTTPServer(("127.0.0.1", 0), T.Silencieux)
    base = f"http://127.0.0.1:{serveur.server_address[1]}"
    threading.Thread(target=serveur.serve_forever, daemon=True).start()

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    responses: list[dict] = []
    ecrit = 0

    def capturer(chemin: str, role: str, nom: str) -> None:
        nonlocal ecrit
        code, corps = T.http(base, chemin)
        if not isinstance(corps, (dict, list)):
            raise SystemExit(f"réponse non JSON pour {chemin} : {corps!r}")
        fichier = f"{nom}.json"
        (out / fichier).write_text(
            json.dumps(corps, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        ecrit += 1
        responses.append({"role": role, "path": chemin, "status": code,
                          "body_file": fichier})

    try:
        # Le listing complet, puis les sondes de pagination/filtres du gate.
        capturer("/api/missions?limit=25", "list", "list")
        capturer("/api/missions?limit=1", "pagination_probe", "pagination-probe")
        capturer("/api/missions?limit=25&status=termine", "status_filter", "status-filter")
        capturer("/api/missions?limit=25&target_type=repository", "target_filter",
                 "target-filter")
        # Liste réellement vide : HTTP 200 + items [] (contrat History).
        capturer("/api/missions?limit=25&status=en_file", "empty_list", "empty-list")
        capturer("/api/missions?status=__agnt_invalid_status__", "invalid_filter",
                 "invalid-filter")

        code, listing = T.http(base, "/api/missions?limit=25")
        curseur = ((listing or {}).get("page") or {}).get("next_cursor")
        if curseur:
            from urllib.parse import urlencode
            capturer("/api/missions?" + urlencode({"limit": 25, "cursor": curseur}),
                     "pagination_next", "pagination-next")

        for i, mid in enumerate(ids):
            capturer(f"/api/missions/{mid}", "detail", f"detail-{i + 1:02d}-{mid}")
    finally:
        serveur.shutdown()
        serveur.server_close()
        shutil.rmtree(tmp, ignore_errors=True)

    # Identifiant TRANSITOIRE de file (format réel de `POST /api/runs` :
    # `uuid4().hex[:12]`) — il prouve que l'id de soumission n'est PAS un mission_id.
    manifeste = {
        "capture": "AGNT GATE-002 — réponses réelles de l'API CORE sur missions contrôlées",
        "submission_id": uuid.uuid4().hex[:12],
        "responses": responses,
    }
    (out / "capture-manifest.json").write_text(
        json.dumps(manifeste, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{ecrit} réponses capturées + manifeste → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
