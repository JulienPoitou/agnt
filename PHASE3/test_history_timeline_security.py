#!/usr/bin/env python3
"""Harnais du gate SECURITY History / Timeline / Execution Status — re-bind
aux contrats Product réels (2026-08-30).

Product (`origin/arena/01a05425-agnt`) possède le contrat de transport HTTP ;
ce harnais vérifie :
  1. modèle (Verdict/Raison, pas de fuite de contenu dans les messages) ;
  2. compatibilité : captures/fixtures Product SÛRES acceptées telles quelles,
     sans seconde enveloppe publique ni dialecte concurrent (9/9) ;
  3. parité vivante : vocabulaires et clés STRICTES du gate == ceux des
     schémas Product versionnés (lus par `git show`, jamais copiés) ;
  4. contenu : secrets, chemins locaux, artefacts bruts, commandes, traces,
     HTML actif — refus fail-closed sans assainissement ;
  5. profondeur : faux zéros, contradictions, provenance non fiable,
     états inconnus non masqués, séquences/curseurs incohérents ;
  6. runner : --fixture-mode / --response-file / --base-url, codes 0/2/1,
     aucune traceback, aucun contenu sensible dans les sorties.

Corpus : `docs/coordination/fixtures/security-history-timeline-*.json`
(88 fixtures, enveloppes de test uniquement ; chaque `response` est une
réponse JSON BRUTE au format Product).
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone

RACINE = pathlib.Path(__file__).resolve().parent.parent
GATE = RACINE / "PHASE3" / "history_timeline_gate.py"
FIXTURES = RACINE / "docs" / "coordination" / "fixtures"
PRODUCT_REF = "origin/arena/01a05425-agnt"
SCHÉMAS = {
    "history": "docs/coordination/mission-history-v1.schema.json",
    "timeline": "docs/coordination/mission-timeline-v1.schema.json",
    "execution": "docs/coordination/execution-status-v1.schema.json",
}
CAPTURES_PRODUIT = [
    "docs/coordination/api-conformance-gate/examples/anonymized-capture/list.json",
    "docs/coordination/api-conformance-gate/examples/anonymized-capture/empty-list.json",
    "docs/coordination/api-conformance-gate/examples/anonymized-capture/status-filter.json",
    "docs/coordination/api-conformance-gate/examples/anonymized-capture/target-filter.json",
    "docs/coordination/api-conformance-gate/examples/anonymized-capture/detail.json",
    "docs/coordination/fixtures/mission-history-list.fixture.json",
    "docs/coordination/fixtures/mission-history-detail.fixture.json",
    "docs/coordination/fixtures/mission-timeline-complete.fixture.json",
    "docs/coordination/fixtures/mission-timeline-refused-partial.fixture.json",
]
CAS_EXECUTION = "docs/coordination/fixtures/execution-status-cases.fixture.json"

spec = importlib.util.spec_from_file_location("gate", str(GATE))
gate = importlib.util.module_from_spec(spec)
sys.modules["gate"] = gate
spec.loader.exec_module(gate)

CHECKS: list[tuple[str, str, object]] = []
_nom_section = ""


def section(titre: str) -> None:
    global _nom_section
    _nom_section = titre


def verifie(nom: str):
    def deco(fn):
        CHECKS.append((_nom_section, nom, fn))
        return fn
    return deco


def git_show(chemin: str) -> str:
    p = subprocess.run(["git", "-C", str(RACINE), "show",
                        f"{PRODUCT_REF}:{chemin}"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(
            f"branche Product absente de cet environnement ({PRODUCT_REF}) : "
            "le gate ne peut pas être re-lié sans ses contrats")
    return p.stdout


def produit_json(chemin: str):
    return json.loads(git_show(chemin))


def schema(ref: str) -> dict:
    return produit_json(SCHÉMAS[ref])


def props_schema(s: dict, defs: str | None = None) -> set[str]:
    cible = s if defs is None else s.get("$defs", {}).get(defs, {})
    return set(cible.get("properties", {}).keys())


# ══════════════════════════════════════════════════════════════════════════
# 1. Modèle
# ══════════════════════════════════════════════════════════════════════════
section("modèle")


@verifie("verdict-ok-sans-raison")
def _():
    v = gate.Verdict(True)
    assert v.ok and v.codes == frozenset() and str(v) == "PASS"
    return []


@verifie("verdict-echec-porte-codes")
def _():
    v = gate._refuse(gate.Raison("a.b", "code-x", "motif"))
    assert not v.ok and "code-x" in v.codes
    return []


@verifie("aucune-fuite-de-contenu-dans-les-decisions")
def _():
    secret = "ghp_zV2x9Q7T4K6M8N0P3R5S7"
    rep = {"$fixture": "TEST ONLY — NEVER SERVE AS PRODUCT DATA",
           "schema_version": gate.HISTORY,
           "items": [{"mission_id": "m-aaaa", "detail_href": "/api/missions/m-aaaa",
                      "request": {"title": "Audit"},
                      "target": {"type": "repository", "display_name": "x"},
                      "status": "termine",
                      "created_at": "2026-08-30T09:00:00Z",
                      "updated_at": "2026-08-30T09:01:00Z",
                      "run_id": "run-1",
                      "artifacts": {"detail": True, "findings": True,
                                    "clusters": True, "report": True},
                      "findings_summary": {"total": 0, "by_severity": {}},
                      "source_verbose": secret}],
           "page": {"limit": 25, "next_cursor": None}}
    v = gate.valider_projection(rep, autoriser_marqueur_fixture=True)
    assert secret not in str(v)
    for r in v.raisons:
        assert secret not in str(r)
        assert "\n" not in r.chemin
    return []


@verifie("le-gate-ne-mute-pas-la-projection")
def _():
    rep = {"schema_version": gate.HISTORY, "items": [], "page": {"limit": 25,
                                                                 "next_cursor": None}}
    clone = json.loads(json.dumps(rep))
    gate.valider_projection(rep)
    assert rep == clone
    return []


# ══════════════════════════════════════════════════════════════════════════
# 2. Format Product — compatible sans seconde enveloppe
# ══════════════════════════════════════════════════════════════════════════
section("format-product")


def _liste_saine(*items):
    return {"schema_version": gate.HISTORY, "items": list(items),
            "page": {"limit": 25, "next_cursor": None}}


def _summary(**kw):
    d = {"mission_id": "m-20260830T090000Z-aa11bb22",
         "detail_href": "/api/missions/m-20260830T090000Z-aa11bb22",
         "request": {"title": "Audit du dépôt"},
         "target": {"type": "repository", "display_name": "acme/service"},
         "status": kw.pop("status", "termine"),
         "created_at": kw.pop("created_at", "2026-08-30T09:00:00Z"),
         "updated_at": "2026-08-30T09:01:00Z",
         "artifacts": {"detail": True, "findings": True, "clusters": True,
                       "report": True}}
    d.update(kw)
    return d


@verifie("liste-product-avec-extension-summary-acceptee")
def _():
    rep = _liste_saine(_summary(extension_metier="v1", run_id="run-1"))
    v = gate.valider_projection(rep)
    assert v.ok, v
    return []


@verifie("extension-dans-data-acceptee")
def _():
    rep = {"schema_version": gate.HISTORY,
           "mission": _summary(run_id="run-1"),
           "data": {"executions": [], "extension_produit": {"a": 1}},
           "missing_artifacts": []}
    v = gate.valider_projection(rep)
    assert v.ok, v
    return []


@verifie("cle-inconnue-refusee-dans-page-stricte")
def _():
    rep = _liste_saine(_summary())
    rep["page"]["mode_alerte"] = True
    v = gate.valider_projection(rep)
    assert not v.ok and "cle-inconnue" in v.codes
    return []


@verifie("cle-inconnue-refusee-dans-request-stricte")
def _():
    rep = _liste_saine(_summary())
    rep["items"][0]["request"]["raw_title"] = "x"
    v = gate.valider_projection(rep)
    assert not v.ok and "cle-inconnue" in v.codes
    return []


@verifie("cle-inconnue-refusee-dans-artifacts-stricts")
def _():
    rep = _liste_saine(_summary())
    rep["items"][0]["artifacts"]["raw_findings"] = True
    v = gate.valider_projection(rep)
    assert not v.ok and "cle-inconnue" in v.codes
    return []


@verifie("detail-sans-data-refuse")
def _():
    rep = {"schema_version": gate.HISTORY, "mission": _summary(),
           "missing_artifacts": []}
    v = gate.valider_projection(rep)
    assert not v.ok and v.codes & {"champ-obligatoire", "forme-inconnue"}
    return []


@verifie("detail-id-incoherent-avec-chemin-refuse")
def _():
    rep = {"schema_version": gate.HISTORY,
           "mission": _summary(mission_id="m-0001"),
           "data": {}, "missing_artifacts": []}
    rep["mission"]["mission_id"] = "m-0002"
    v = gate.valider_projection(rep)
    assert not v.ok and "detail-href-incoherent" in v.codes
    return []


@verifie("liste-vide-200-acceptee")
def _():
    rep = {"schema_version": gate.HISTORY, "items": [], "page": {"limit": 25,
                                                                 "next_cursor": None}}
    v = gate.valider_projection(rep)
    assert v.ok, v
    return []


@verifie("statut-inconnu-avec-incomplete-accepte")
def _():
    rep = _liste_saine(_summary(status="inconnu", incomplete=True,
                                incomplete_reason="Aucun événement terminal"))
    v = gate.valider_projection(rep)
    assert v.ok, v
    return []


@verifie("ordre-liste-instable-refuse")
def _():
    rep = _liste_saine(
        _summary(created_at="2026-08-30T09:00:00Z", run_id="r1",
                 mission_id="m-20260830T090000Z-zz"),
        _summary(created_at="2026-08-30T09:01:00Z", run_id="r1",
                 mission_id="m-20260830T090000Z-aa"))
    v = gate.valider_projection(rep)
    assert not v.ok and "ordre-instable" in v.codes
    return []


# ══════════════════════════════════════════════════════════════════════════
# 3. Parité vivante avec les schémas Product
# ══════════════════════════════════════════════════════════════════════════
section("parite-schemas-product")


@verifie("clés-liste-egales-au-schema")
def _():
    assert props_schema(schema("history"), "listResponse") == gate.CLES_LISTE
    assert props_schema(schema("history"), "listResponse") \
        .issuperset({"schema_version", "items", "page"})
    return []


@verifie("clés-detail-egales-au-schema")
def _():
    assert props_schema(schema("history"), "detailResponse") == gate.CLES_DETAIL
    assert props_schema(schema("history"), "detailResponse") \
        .issuperset({"schema_version", "mission", "data", "missing_artifacts"})
    return []


@verifie("clés-page-artefacts-resume-contributeurs")
def _():
    assert props_schema(schema("history"), "listResponse") \
        .issuperset(set())
    assert props_schema(schema("history"), "listResponse") == gate.CLES_LISTE
    page = schema("history")["$defs"]["listResponse"]["properties"]["page"]
    assert set(page["properties"]) == gate.CLES_PAGE
    art = schema("history")["$defs"]["artifacts"]
    assert set(art["properties"]) == gate.CLES_ARTEFACTS
    fs = schema("history")["$defs"]["findingsSummary"]
    assert set(fs["properties"]) == gate.CLES_RESUME_FIN
    con = schema("history")["$defs"]["summary"]["properties"]["contributors"]
    assert set(con["properties"]) == gate.CLES_CONTRIBUTEURS
    return []


@verifie("clés-evenement-legacy-egales-au-schema")
def _():
    assert props_schema(schema("history"), "event") == gate.CLES_EVENEMENT_LEGACY
    return []


@verifie("timeline-racine-et-evenement-stricts")
def _():
    s = schema("timeline")
    assert set(s["properties"]) == gate.CLES_TIMELINE
    assert props_schema(s, "event") == gate.CLES_EVENEMENT
    assert props_schema(s, "source") == gate.CLES_SOURCE
    assert props_schema(s, "references") == gate.CLES_REFERENCES
    return []


@verifie("provenance-protocole-confiance-stricts")
def _():
    s = schema("timeline")
    assert props_schema(s, "provenance") == gate.CLES_PROVENANCE
    assert props_schema(s, "provenance") == gate.CLES_PROVENANCE
    prot = schema("timeline")["$defs"]["provenance"]["properties"]["protocol"]
    assert set(prot["properties"]) == gate.CLES_PROTOCOL
    conf = schema("timeline")["$defs"]["provenance"]["properties"]["confidence"]
    assert set(conf["properties"]) == gate.CLES_CONFIDENCE
    return []


@verifie("execution-status-racine-et-dimensions-stricts")
def _():
    s = schema("execution")
    assert set(s["properties"]) == gate.CLES_EXECUTION_V1
    assert props_schema(s, "baseDimension") == gate.CLES_DIMENSION
    av = schema("execution")["$defs"]["availability"]
    assert set(av["properties"]) == gate.CLES_DIMENSION
    exe = schema("execution")["$defs"]["execution"]
    assert set(exe["properties"]) == gate.CLES_EXECUTION_DIM
    det = schema("execution")["$defs"]["detection"]
    assert set(det["properties"]) == gate.CLES_DETECTION_DIM
    comp = schema("execution")["$defs"]["completeness"]
    assert set(comp["properties"]) == gate.CLES_COMPLETUDE
    return []


@verifie("vocabulaires-et-enums-harmonises")
def _():
    h, t, e = schema("history"), schema("timeline"), schema("execution")
    t_props = t["properties"]
    assert t_props["state"]["enum"] == list(gate.ETATS_TIMELINE)
    assert t_props["ordering"]["const"] == "journal_sequence_ascending"
    ev = t["$defs"]["event"]
    assert ev["properties"]["category"]["enum"] == list(gate.CATEGORIES_EVENEMENT)
    assert ev["properties"]["consequence"]["enum"] == list(gate.CONSEQUENCES)
    assert ev["properties"]["visibility"]["enum"] == list(gate.VISIBILITES)
    assert ev["properties"]["data_state"]["enum"] == list(gate.ETATS_DONNEES)
    e_dim = e["$defs"]["applicability"]["allOf"][1]["properties"]["value"]
    assert e_dim["enum"] == list(gate.APPLICABILITE)
    e_exe = e["$defs"]["execution"]
    assert e_exe["properties"]["value"]["enum"] == list(gate.EXECUTION_RESULTAT)
    assert e_exe["properties"]["invocation"]["enum"] == list(gate.INVOCATION)
    assert e_exe["properties"]["output"]["enum"] == list(gate.SORTIE)
    e_det = e["$defs"]["detection"]
    assert e_det["properties"]["value"]["enum"] == list(gate.DETECTION)
    e_comp = e["$defs"]["completeness"]
    assert e_comp["properties"]["state"]["enum"] == list(gate.COMPLETUDE)
    e_prov = t["$defs"]["provenance"]
    assert e_prov["properties"]["provider_kind"]["enum"] == list(gate.PROVIDER_KINDS)
    assert e_prov["properties"]["availability"]["enum"] == \
        list(gate.DISPONIBILITE_PROVENANCE)
    conf_props = e_prov["properties"]["confidence"]
    assert conf_props["properties"]["level"]["enum"] == list(gate.CONFIDENCES_LEVELS)
    assert conf_props["properties"]["basis"]["enum"] == list(gate.CONFIDENCES_BASIS)
    return []


@verifie("statuts-mission-identiques-au-contrat")
def _():
    assert set(gate.STATUTS_MISSION) == {"en_file", "en_cours", "termine",
                                         "refuse", "erreur", "inconnu"}
    return []


@verifie("versions-de-schema-identiques")
def _():
    h = schema("history")
    assert h["$defs"]["listResponse"]["properties"]["schema_version"]["const"] \
        == gate.HISTORY
    assert h["$defs"]["detailResponse"]["properties"]["schema_version"]["const"] \
        == gate.HISTORY
    assert schema("timeline")["properties"]["schema_version"]["const"] \
        == gate.TIMELINE
    assert schema("execution")["properties"]["schema_version"]["const"] \
        == gate.EXECUTION
    return []


# ══════════════════════════════════════════════════════════════════════════
# 4. Contenu — refus fail-closed, jamais d'assainissement
# ══════════════════════════════════════════════════════════════════════════
section("contenu-interdit")


def _response_avec_detail(data):
    return {"schema_version": gate.HISTORY,
            "mission": {"mission_id": "m-20260830T090000Z-aa11bb22",
                        "detail_href": "/api/missions/m-20260830T090000Z-aa11bb22",
                        "request": {"title": "Audit"},
                        "target": {"type": "repository", "display_name": "x"},
                        "status": "termine",
                        "created_at": "2026-08-30T09:00:00Z",
                        "updated_at": "2026-08-30T09:01:00Z",
                        "run_id": "run-1",
                        "artifacts": {"detail": True, "findings": True,
                                      "clusters": True, "report": True}},
            "data": dict(data), "missing_artifacts": []}


def _tl_un(evenement):
    return {"schema_version": gate.TIMELINE, "state": "complete",
            "ordering": "journal_sequence_ascending",
            "events": [evenement], "returned_events": 1, "total_events": 1,
            "truncated": False, "next_cursor": None, "limitations": []}


def _ev_un(summary_text="Événement consigné", **kw):
    ev = {"event_id": "m-20260830T090000Z-aa11bb22:1", "position": 1,
          "source": {"kind": "journal", "sequence": 1,
                     "source_kind": "journal"},
          "time": {"state": "recorded", "timestamp": "2026-08-30T09:00:05Z"},
          "category": "mission", "kind": "ouverture",
          "consequence": "recorded", "visibility": "summary",
          "safe_summary": summary_text,
          "references": {"mission_id": "m-20260830T090000Z-aa11bb22"},
          "data_state": "complete", "limitations": []}
    ev.update(kw)
    return ev


_CONTENUS = [
    ("secret-bearer", "Authorisation Bearer ghp_zV2x9Q7T4K6M8N0P3R5S7"),
    ("secret-jwt", "Jeton eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("secret-cle-github", "Jeton GitHub ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
    ("secret-cle-aws", "AKIAIOSFODNN7EXAMPLE"),
    ("secret-api-key", "sk_live_1234567890abcdefghij"),
    ("secret-gitlab", "glpat-ABCDEF12345678901234567890"),
    ("secret-google", "AIzaSyD1234567890abcdefghijklmnop"),
    ("secret-slack", "xoxb-123456789012-123456789012-abcdefghij"),
    ("secret-cle-privee", "-----BEGIN PRIVATE KEY-----"),
    ("secret-url-userinfo", "https://user:pass@example.com/acme.git"),
    ("secret-url-token", "https://example.com/v1?access_token=abc123456789"),
    ("secret-header-auth", "Authorization: Bearer abcdefghijklmnop123456"),
    ("secret-cookie", "Cookie: JSESSIONID=abcdef0123456789"),
    ("secret-variable-env", "GITLEAKS_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
    ("secret-affectation", "password=supersecret12345"),
    ("chemin-home", "/home/user/secrets/credentials.txt"),
    ("chemin-absolu", "/var/lib/docker/overlay2/abc/merged"),
    ("chemin-windows", "C:\\Users\\dev\\AppData\\Local\\gitleaks.toml"),
    ("chemin-traversal", "../../etc/passwd"),
    ("chemin-sandbox", "PHASE3/artifacts/missions/m-20260830/run.log"),
    ("reference-artefact", "Archive raw_output-2026-08.zip"),
    ("reference-commandes", "gitleaks git --config=rules.toml"),
    ("html-executable", "<script>alert(1)</script>"),
    ("endpoint-url", "https://api.example.com/v1"),
    ("stack-trace", "Traceback (most recent call last): File \"x.py\", line 12"),
]


@verifie("chaque-motif-de-contenu-refuse")
def _():
    echecs = []
    for code, texte in _CONTENUS:
        rep = _response_avec_detail({"timeline": _tl_un(_ev_un(texte))})
        v = gate.valider_projection(rep)
        if v.ok or code not in v.codes:
            echecs.append(f"{code}: {'PASS' if v.ok else sorted(v.codes)}")
    assert not echecs, "; ".join(echecs)
    return []


@verifie("mots-innocents-non-refuses")
def _():
    innocents = ["Le dépôt a été analysé", "Bearer", "AKIA", "token absent",
                 "aucun secret détecté", "sk_", "--config", "évaluation"]
    for t in innocents:
        v = gate.valider_projection(
            _response_avec_detail({"timeline": _tl_un(_ev_un(t))}))
        if not v.ok:
            return [f"faux positif pour {t!r}: {sorted(v.codes)}"]
    return []


@verifie("cle-interdite-refusee-nimporte-ou")
def _():
    rep = _response_avec_detail({"findings": [{"file": "a.js",
                                               "raw_output": "x"}]})
    v = gate.valider_projection(rep)
    assert not v.ok and "cle-interdite" in v.codes
    return []


@verifie("file-location-relatives-autorisees")
def _():
    rep = _response_avec_detail({"executions": [],
                                 "findings": [{"file": "src/a.js",
                                               "location": 42}]})
    v = gate.valider_projection(rep)
    assert v.ok, v
    return []


# ══════════════════════════════════════════════════════════════════════════
# 5. Profondeur — faux zéros, contradictions, provenance
# ══════════════════════════════════════════════════════════════════════════
section("profondeur-fail-closed")


@verifie("mission-terminee-sans-run-refusee")
def _():
    rep = _response_avec_detail({"executions": []})
    del rep["mission"]["run_id"]
    v = gate.valider_projection(rep)
    assert not v.ok and "mission-sans-run" in v.codes
    return []


@verifie("zero-sans-artefact-refuse")
def _():
    rep = _response_avec_detail({"executions": []})
    rep["mission"]["findings_summary"] = {"total": 0, "by_severity": {}}
    rep["mission"]["artifacts"]["findings"] = False
    v = gate.valider_projection(rep)
    assert not v.ok and "compteur-sans-artefact" in v.codes
    assert "zero-sans-artefact" in v.codes
    return []


@verifie("rien-trouve-incomplet-refuse")
def _():
    rep = _response_avec_detail({"executions": [{
        "schema_version": gate.EXECUTION, "provider_id": "p1",
        "capability_id": "gitleaks", "display_name": "Gitleaks",
        "applicability": {"value": "applicable", "proof": "recorded"},
        "selection": {"value": "selectionne", "proof": "recorded"},
        "condition": {"value": "remplie", "proof": "recorded"},
        "authorization": {"value": "autorise", "proof": "recorded"},
        "availability": {"value": "disponible", "proof": "recorded"},
        "execution": {"value": "termine", "invocation": "oui",
                      "output": "partiel", "proof": "recorded"},
        "detection": {"value": "rien_trouve", "findings_count": 0,
                      "analyzed_targets": 3, "proof": "recorded"},
        "completeness": {"state": "complete", "missing": [],
                         "limitations": []}}]})
    v = gate.valider_projection(rep)
    assert not v.ok and "rien-trouve-incomplet" in v.codes
    return []


@verifie("conflit-resolu-sous-mission-terminee-refuse")
def _():
    from copy import deepcopy
    rep = deepcopy(_response_avec_detail({"executions": [{
        "schema_version": gate.EXECUTION, "provider_id": "p1",
        "capability_id": "gitleaks", "display_name": "Gitleaks",
        "applicability": {"value": "applicable", "proof": "recorded"},
        "selection": {"value": "selectionne", "proof": "recorded"},
        "condition": {"value": "remplie", "proof": "recorded"},
        "authorization": {"value": "autorise", "proof": "recorded"},
        "availability": {"value": "disponible", "proof": "recorded"},
        "execution": {"value": "inconnu", "invocation": "inconnu",
                      "output": "inconnu", "proof": "recorded"},
        "detection": {"value": "non_evalue", "proof": "recorded"},
        "completeness": {"state": "conflict", "missing": [],
                         "limitations": ["preuve contradictoire"]}}]}))
    v = gate.valider_projection(rep)
    assert not v.ok and "conflict-resolu" in v.codes
    return []


@verifie("provenance-inconnue-refusee")
def _():
    from copy import deepcopy
    rep = deepcopy(_response_avec_detail({"executions": [{
        "schema_version": gate.EXECUTION, "provider_id": "p1",
        "capability_id": "gitleaks", "display_name": "Gitleaks",
        "applicability": {"value": "applicable", "proof": "recorded"},
        "selection": {"value": "selectionne", "proof": "recorded"},
        "condition": {"value": "remplie", "proof": "recorded"},
        "authorization": {"value": "autorise", "proof": "recorded"},
        "availability": {"value": "disponible", "proof": "recorded"},
        "execution": {"value": "termine", "invocation": "oui",
                      "output": "exploitable", "proof": "recorded"},
        "detection": {"value": "findings_presents", "findings_count": 2,
                      "proof": "recorded"},
        "completeness": {"state": "complete", "missing": [],
                         "limitations": []},
        "provenance": {"provider_id": "x", "provider_kind": "mcp",
                       "transport": "stdio",
                       "confidence": {"level": "high",
                                      "basis": "provider_declared"}}}]}))
    v = gate.valider_projection(rep)
    assert not v.ok and "confiance-non-corroboree" in v.codes
    return []


@verifie("event-inconnu-non-generique-refuse")
def _():
    ev = _ev_un(category="unknown", kind="unknown_event_recorded",
                data_state="complete", limitations=["projection_version_unsupported"])
    v = gate.valider_projection(_response_avec_detail(
        {"timeline": _tl_un(ev)}))
    assert not v.ok and "evenement-inconnu-non-generique" in v.codes
    return []


@verifie("timeline-tronquee-sans-curseur-refusee")
def _():
    tl = _tl_un(_ev_un())
    tl["truncated"] = True
    tl["next_cursor"] = None
    v = gate.valider_projection(_response_avec_detail({"timeline": tl}))
    assert not v.ok and "curseur-manquant" in v.codes
    return []


# ══════════════════════════════════════════════════════════════════════════
# 6. Captures Product réelles — preuve d'acceptation
# ══════════════════════════════════════════════════════════════════════════
section("captures-product-reelles")


@verifie("captures-product-sures-acceptees")
def _():
    # horloge postérieure aux horodatages maximaux des captures (10:16:42Z)
    echecs = []
    for p in CAPTURES_PRODUIT:
        try:
            v = gate.valider_projection(produit_json(p),
                                        autoriser_marqueur_fixture=True,
                                        horloge=datetime(2026, 8, 30, 11, 0,
                                                         tzinfo=timezone.utc))
        except Exception as e:
            echecs.append(f"{p}: exception {e!r}")
            continue
        if not v.ok:
            echecs.append(f"{p}: {sorted(v.codes)}")
    assert not echecs, "; ".join(echecs)
    return []


@verifie("cas-execution-status-product-acceptes")
def _():
    v = gate.valider_projection(produit_json(CAS_EXECUTION),
                                autoriser_marqueur_fixture=True,
                                horloge=datetime(2026, 8, 30, 11, 0,
                                                 tzinfo=timezone.utc))
    assert v.ok, sorted(v.codes)
    return []


# ══════════════════════════════════════════════════════════════════════════
# 7. Corpus fixtures
# ══════════════════════════════════════════════════════════════════════════
section("corpus-fixtures")


@verifie("tous-les-fichiers-sont-marques-et-attendus")
def _():
    echecs = []
    fichiers = sorted(FIXTURES.glob("security-history-timeline-*.json"))
    assert len(fichiers) >= 81, f"corpus réduit : {len(fichiers)}"
    for f in fichiers:
        d = json.loads(f.read_text(encoding="utf-8"))
        if not str(d.get("_marker", "")).startswith("TEST ONLY"):
            echecs.append(f"{f.name}: marqueur absent")
        if "expect" not in d or "verdict" not in d.get("expect", {}):
            echecs.append(f"{f.name}: expect absent")
        if "response" not in d:
            echecs.append(f"{f.name}: response absente")
    assert not echecs, "; ".join(echecs)
    return []


@verifie("corpus-conforme-au-verdict-attendu")
def _():
    echecs = []
    nb_ok = 0
    fichiers = sorted(FIXTURES.glob("security-history-timeline-*.json"))
    for f in fichiers:
        d = json.loads(f.read_text(encoding="utf-8"))
        attendu = d.get("expect", {})
        v = gate.valider_projection(d["response"],
                                    autoriser_marqueur_fixture=True,
                                    horloge=datetime(2026, 8, 30, 9, 10,
                                                     tzinfo=timezone.utc))
        if attendu["verdict"] == "PASS":
            if v.ok:
                nb_ok += 1
            else:
                echecs.append(f"{f.name}: PASS attendu, {sorted(v.codes)}")
        else:
            manques = set(attendu.get("codes", [])) - v.codes
            if v.ok or manques:
                echecs.append(f"{f.name}: attendu {attendu.get('codes')}, "
                              f"{'PASS' if v.ok else sorted(v.codes)} "
                              f"(manques={sorted(manques)})")
            else:
                nb_ok += 1
    assert not echecs, "; ".join(echecs)
    return []


# ══════════════════════════════════════════════════════════════════════════
# 8. Runner — codes propres, zéro fuite
# ══════════════════════════════════════════════════════════════════════════
section("runner")


def _run(*args: str, stdin=None):
    return subprocess.run([sys.executable, str(GATE), *args],
                          capture_output=True, text=True, input=stdin,
                          cwd=str(RACINE))


@verifie("fixture-mode-retourne-0")
def _():
    p = _run("--fixture-mode", str(FIXTURES))
    assert p.returncode == 0, p.stdout + p.stderr
    assert "Traceback" not in p.stdout + p.stderr
    assert "88/88" in p.stdout or "conformes" in p.stdout
    return []


@verifie("response-file-capture-product-retourne-0")
def _():
    with tempfile.TemporaryDirectory() as td:
        rep = produit_json(
            "docs/coordination/api-conformance-gate/examples/anonymized-capture/detail.json")
        del rep["$fixture"]
        f = pathlib.Path(td) / "detail.json"
        f.write_text(json.dumps(rep), encoding="utf-8")
        p = _run("--response-file", str(f))
    assert p.returncode == 0, p.stdout + p.stderr
    return []


@verifie("response-file-hostile-retourne-2-sans-fuite")
def _():
    with tempfile.TemporaryDirectory() as td:
        rep = {"schema_version": gate.HISTORY, "items": [],
               "page": {"limit": 25, "next_cursor": None},
               "note_verbose": "Bearer ghp_zV2x9Q7T4K6M8N0P3R5S7"}
        f = pathlib.Path(td) / "hostile.json"
        f.write_text(json.dumps(rep), encoding="utf-8")
        p = _run("--response-file", str(f))
    assert p.returncode == 2, p.stdout + p.stderr
    assert "ghp_zV2x9Q7T4K6M8N0P3R5S7" not in p.stdout
    assert "ghp_zV2x9Q7T4K6M8N0P3R5S7" not in p.stderr
    assert "Traceback" not in p.stderr
    return []


@verifie("modes-multiples-refuses-code-1")
def _():
    with tempfile.TemporaryDirectory() as td:
        f = pathlib.Path(td) / "x.json"
        f.write_text("{}", encoding="utf-8")
        p = _run("--fixture-mode", str(FIXTURES), "--response-file", str(f))
    assert p.returncode == 1
    assert "Traceback" not in p.stderr
    return []


@verifie("fichier-introuvable-code-1-sans-traceback")
def _():
    p = _run("--response-file", "/aucun/fichier/tel.json")
    assert p.returncode == 1
    assert "Traceback" not in p.stderr
    return []


@verifie("base-url-avec-serveur-local-retourne-0")
def _():
    rep_liste = produit_json(
        "docs/coordination/api-conformance-gate/examples/anonymized-capture/status-filter.json")
    del rep_liste["$fixture"]
    rep_detail = produit_json(
        "docs/coordination/api-conformance-gate/examples/anonymized-capture/detail.json")
    del rep_detail["$fixture"]

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/api/missions?") or self.path == "/api/missions":
                corps = json.dumps(rep_liste).encode()
            elif self.path.startswith("/api/missions/"):
                corps = json.dumps(rep_detail).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def log_message(self, *a):
            pass

    serveur = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = serveur.server_address[1]
    t = threading.Thread(target=serveur.serve_forever, daemon=True)
    t.start()
    try:
        p = _run("--base-url", f"http://127.0.0.1:{port}")
    finally:
        serveur.shutdown()
        t.join(timeout=5)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "GET /api/missions" in p.stdout
    assert "Traceback" not in p.stderr
    return []


@verifie("base-url-injoignable-code-1-sans-traceback")
def _():
    p = _run("--base-url", "http://127.0.0.1:1")
    assert p.returncode == 1
    assert "Traceback" not in p.stderr
    assert "API" in p.stderr or "API" in p.stdout
    return []


# ══════════════════════════════════════════════════════════════════════════
def main() -> int:
    print(f"GATE: {GATE.name}")
    total, echecs = 0, []
    courant = ""
    for sec, nom, fn in CHECKS:
        if sec != courant:
            courant = sec
            print(f"\n[{courant}]")
        total += 1
        try:
            resultat = fn()
            if resultat:
                echecs.append((sec, nom, "; ".join(resultat)))
                print(f"  ÉCHEC  {nom} — {'; '.join(resultat)}")
            else:
                print(f"  OK     {nom}")
        except AssertionError as e:
            echecs.append((sec, nom, str(e)))
            print(f"  ÉCHEC  {nom} — {e}")
        except Exception as e:
            echecs.append((sec, nom, f"exception {e!r}"))
            print(f"  ÉCHEC  {nom} — exception {e!r}")
    print(f"\n{total - len(echecs)}/{total} vérifications · "
          f"{len(echecs)} échec(s)")
    if echecs:
        print("Résumé des échecs :")
        for sec, nom, msg in echecs:
            print(f"  [{sec}] {nom} — {msg}")
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main())
