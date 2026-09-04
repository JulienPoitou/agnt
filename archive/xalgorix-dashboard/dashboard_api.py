#!/usr/bin/env python3
"""API HTTP du tableau de bord (`dashboard/`) — une PROJECTION de plus, pas un cœur.

Ce fichier ne décide rien de plus qu'`api.py` : il sous-classe son `Gestionnaire`,
réutilise SA file, SES états et SON worker (`analyser.lancer()`), et traduit
l'archive de mission vers le contrat que la SPA du tableau de bord lit
(`dashboard/webui/src/types/api.ts`). Le backend Go livré avec le dashboard
(`dashboard/internal/web/`) n'est PAS exécuté — c'est la référence du contrat, ce
fichier en est l'implémentation côté moteur AGNT.

Ce qui est réel : cibles, capacités, missions (l'historique), findings, journal,
rapport, lancement d'un run.
Ce qui est refusé NOMMÉMENT (501, jamais un faux ok) : arrêt d'un run, suppression
d'archive, planifications, chat, réglages en écriture — le moteur ne les a pas, et
une interface qui mentirait « stopped » fabriquerait une fausse assurance.
Ce qui est neutre (0, []) : les mesures que le moteur ne produit pas (tokens,
itérations, charge RAM) — la SPA exige des nombres, le moteur ne les mesure pas.

Démarrage :

    python3 PHASE3/interface/dashboard_api.py             # 127.0.0.1:8142, SPA servie
    python3 PHASE3/interface/dashboard_api.py --port 8142 --host 0.0.0.0

La SPA est servie depuis `dashboard/internal/web/static` (sortie de
`cd dashboard/webui && npm run build`). En dev avec rechargement :

    cd dashboard/webui && VITE_API_TARGET=http://127.0.0.1:8142 npm run dev

Mêmes trois lois qu'`api.py` (une exécution à la fois, la cible est un chemin,
un refus est un résultat) — ce fichier n'en ajoute aucune.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ICI = Path(__file__).resolve().parent
RACINE = ICI.parent                      # PHASE3/
DEPOT = RACINE.parent
sys.path.insert(0, str(ICI))             # pour `import api` (le module canonique)
sys.path.insert(0, str(RACINE))
sys.path.insert(0, str(RACINE / "slice"))

import api as API                        # noqa: E402 — la surcouche canonique, sous-classée

# La SPA buildée. Ce dossier est versionné : l'empreinte du nom d'asset change avec
# le build, donc un binaire/vieux cache navigateur ne peut pas rejouer un vieux bundle.
SPA_DIR = DEPOT / "dashboard" / "internal" / "web" / "static"

TAILLE_PAGE_DEFAUT = 25
PLAFOND_CORPS = 262_144   # lecture bornée : Content-Length est déclaré par le client.

# Le contrat SPA connaît huit statuts de pill ; le moteur en connaît six. La table
# est Totale : un statut moteur sans traduction serait rendu « undefined » par la
# SPA, pas « inconnu » — donc chaque statut AGNT est traduit explicitement.
STATUTS_SPA = {
    "en_file": "pending",     # en file, pas encore démarré
    "en_cours": "running",
    "termine": "finished",
    "refuse": "stopped",      # la politique a refusé : c'est un arrêt, pas un plantage
    "erreur": "failed",
    "inconnu": "stopped",     # archive sans événement terminal : on ne sait pas → arrêt ?
    # traduit « stopped » plutôt que « failed » : l'absence de preuve n'est pas une panne
}

# Traduction inverse pour le filtre `status` de la liste paginée SPA → statuts AGNT.
STATUTS_AGNT = {}
for _a, _s in STATUTS_SPA.items():
    STATUTS_AGNT.setdefault(_s, []).append(_a)

TYPES_SPA = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8", ".png": "image/png",
    ".svg": "image/svg+xml", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8",
    ".md": "text/markdown; charset=utf-8", ".woff": "font/woff",
    ".woff2": "font/woff2", ".map": "application/json; charset=utf-8",
}


# --------------------------------------------------------------------------- projections
def _statut_spa(statut_agnt: str) -> str:
    return STATUTS_SPA.get(statut_agnt, "stopped")


def _severite_spa(finding: dict) -> str:
    """`HIGH`/`MEDIUM`/`UNKNOWN` → minuscule. `UNKNOWN` reste `unknown` : la SPA le
    classe dans le bucket le plus bas d'elle-même ; inventer « info » ou « low »
    attribuerait au moteur un jugement qu'il n'a pas porté."""
    sev = (finding.get("severity") or {}).get("value") \
        if isinstance(finding.get("severity"), dict) else None
    return str(sev or "unknown").lower()


def _vuln_spa(finding: dict, mission_id: str) -> dict:
    """Finding AGNT (blocs source/location/severity/evidence) → VulnSummary SPA.

    Règle de traduction : les champs que le moteur ne produit pas (cvss, endpoint
    HTTP, méthode, PoC) sont laissés à la valeur neutre que la SPA exige, jamais
    décorés. `title` reprend le message de l'outil — c'est ce que l'opérateur lit
    dans le RAPPORT.md — et retombe sur la règle, jamais sur un libellé inventé."""
    src = finding.get("source") or {}
    loc = finding.get("location") or {}
    ev = finding.get("evidence") or {}
    titre = ev.get("message") or src.get("nom_regle") or src.get("canonical_rule_id") \
        or src.get("original_rule_id") or str(finding.get("id") or "finding")
    return {
        "id": str(finding.get("id") or ""),
        "source_scan_id": mission_id,
        "title": str(titre)[:300],
        "severity": _severite_spa(finding),
        "endpoint": str(loc.get("file") or loc.get("url") or ""),
        "cvss": 0,                      # le moteur ne mesure pas de CVSS ; 0 = absent
        "description": ev.get("message"),
        "remediation": ev.get("remediation"),
        "cwe_id": str(ev.get("cwe")) if ev.get("cwe") else None,
        "verified": False,
        "tags": ["needs-manual-verification"],
    }


def _scan_item_spa(item: dict) -> dict:
    """MissionSummary (contrat History) → ScanListItem SPA. `targets` est la
    forme « chaîne séparée par des virgules » que le contrat SPA exige sur les
    instances (Overview la re-splitte) : une seule cible par mission, donc la
    même valeur que `target`."""
    fs = item.get("findings_summary") or {}
    cible = (item.get("target") or {}).get("display_name") or "cible"
    return {
        "id": item["mission_id"],
        "target": cible,
        "targets": cible,
        "started_at": item.get("started_at") or item.get("created_at") or "",
        "finished_at": item.get("completed_at"),
        "status": _statut_spa(item.get("status") or "inconnu"),
        "scan_mode": "agnt",
        "vuln_count": int(fs.get("total") or 0) if isinstance(fs, dict) else 0,
        "iterations": 0,        # pas d'itérations dans le moteur AGNT (plan en vagues)
        "tool_calls": 0,
        "total_tokens": 0,      # le moteur ne mesure pas de tokens
    }


def _evenements_spa(donnees: dict) -> list[dict]:
    """La timeline legacy du contrat History (sequence/timestamp/kind/safe_message)
    → WSEvent[] SPA. Le champ `content` porte le message sûr, `type` le kind —
    le flux temps réel (WebSocket /ws) n'est pas implémenté ici : le live feed
    affiche « déconnecté » plutôt que des événements fabriqués."""
    return [{"type": str(e.get("kind") or "unknown_event"),
             "content": e.get("safe_message"),
             "timestamp": e.get("timestamp")}
            for e in (donnees.get("events") or []) if isinstance(e, dict)]


def _scan_record_spa(mission_id: str, projection: dict) -> dict:
    """MissionHistory.projeter() → ScanRecord SPA. `tool_calls` compte les
    exécutions de providers consignées ; absent = 0 (mission avant le registre)."""
    resume, donnees = projection.get("mission") or {}, projection.get("data") or {}
    fs = resume.get("findings_summary") or {}
    vulns = [_vuln_spa(f, mission_id) for f in (donnees.get("findings") or [])
             if isinstance(f, dict)]
    statut_agnt = resume.get("status") or "inconnu"
    rec = _scan_item_spa(resume)
    rec.update({
        "name": ((resume.get("request") or {}).get("title") or "")[:120],
        "instruction": (donnees.get("request") or {}).get("original"),
        "events": _evenements_spa(donnees),
        "events_total": len(donnees.get("events") or []),
        "events_truncated": False,
        "vulns": vulns,
        "vuln_count": int(fs.get("total") or 0) if isinstance(fs, dict) else len(vulns),
        "tool_calls": len(donnees.get("executions") or []),
        "phases": [1],
        "current_phase": 1 if statut_agnt == "en_cours" else 0,
    })
    if resume.get("incomplete"):
        rec["stop_reason"] = str(resume.get("incomplete_reason") or "mission incomplète")
    return rec


def _runs_actifs() -> list[dict]:
    """Les états de file vivants EN MÉMOIRE (le run ne survit pas au processus,
    ses preuves oui — cf. api.py). La clé de `ETATS` EST l'id de run : elle est
    copiée dans le dict, api.py ne l'ajoute qu'à la sérialisation de sa propre
    route. Un run dont l'archive existe déjà est filtré par les appelants :
    l'archive est la source, pas le doublon."""
    with API.VERROU:
        return [dict(v, run_id=rid) for rid, v in API.ETATS.items()]


def _run_stop_reason(etat: dict) -> str | None:
    """Le motif lisible d'un run refuse/erreur — affiché à la place d'un statut
    muet. Jamais de trace : le message borné, comme api.py."""
    erreur = etat.get("erreur") or {}
    if erreur.get("type"):
        return f"{erreur['type']} : {str(erreur.get('message') or '')[:280]}"
    return str((etat.get("resume") or {}).get("motif") or "") or None


def _run_vers_item_spa(etat: dict) -> dict:
    """Un run de file (pas encore d'archive ou en cours) → ScanListItem SPA.
    Le target est le NOM du chemin admis (jamais le chemin absolu : la cible_sure
    de l'historique fait la même redaction)."""
    cible = str(etat.get("cible") or "")
    nom = Path(cible).name or cible or "cible"
    return {
        "id": str(etat.get("run_id") or ""),
        "target": nom,
        "targets": nom,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(
            float(etat.get("pose_le") or 0.0))),
        "status": _statut_spa(str(etat.get("statut") or "en_file")),
        "scan_mode": "agnt",
        "vuln_count": 0,
        "iterations": 0,
        "tool_calls": 0,
        "total_tokens": 0,
    }


# ------------------------------------------------------------------------------------ HTTP
class GestionnaireDashboard(API.Gestionnaire):
    server_version = "agnt-dashboard/0"

    # ---- utilitaires propre au contrat SPA
    def _spa_json(self, objet, code=200):
        # Même discipline qu'api.py : JSON, no-store, taille maîtrisée.
        return self._json(objet, code)

    def _spa_refus(self, message, code=501):
        """Refus NOMMÉ : la fonctionnalité n'existe pas côté moteur. 501 (pas 500 :
        ce n'est pas une panne ; pas 200 : ce n'est pas un succès)."""
        return self._spa_json({"error": message}, code)

    def _spa_fichier(self, chemin_url: str):
        """Service statique de la SPA, avec repli index.html (router BrowserRouter).
        Résolu PUIS contrôlé sous SPA_DIR — même garde qu'api.py contre `..`."""
        if not SPA_DIR.is_dir():
            return self._spa_json({"error": "SPA non buildée — lancer "
                                            "`cd dashboard/webui && npm run build`"}, 404)
        rel = (chemin_url or "/").lstrip("/") or "index.html"
        f = (SPA_DIR / rel).resolve()
        # is_relative_to, pas startswith : un voisin partageant le préfixe passait autrement.
        if not f.is_relative_to(SPA_DIR):
            return self.send_error(404)
        if not f.is_file():
            # Route client (ex. /scans/m-…, /findings) → index.html, la SPA route.
            f = (SPA_DIR / "index.html").resolve()
            if not f.is_file():
                return self.send_error(404)
        type_mime = TYPES_SPA.get(f.suffix.lower())
        if not type_mime:
            return self.send_error(404)
        corps = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", type_mime)
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corps)

    # ---- GET
    def do_GET(self):  # noqa: N802
        partie = urlparse(self.path)
        chemin, qs = partie.path, parse_qs(partie.query)
        if not chemin.startswith("/api/"):
            return self._spa_fichier(chemin)
        # Les routes canoniques AGNT restent servies par api.py (la console `src/`
        # et app.js les consomment) — aucune réécriture, un seul moteur.
        if chemin.startswith(("/api/cibles", "/api/capacites", "/api/missions",
                              "/api/runs")):
            return super().do_GET()
        if chemin == "/api/auth/status":
            return self._spa_json({"auth_enabled": False, "authenticated": True})
        if chemin == "/api/version":
            return self._spa_json(self._version())
        if chemin == "/api/status":
            return self._spa_json(self._statut_moteur())
        if chemin == "/api/scans":
            return self._scans(qs)
        if chemin.startswith("/api/scans/"):
            reste = chemin[len("/api/scans/"):]
            if reste.endswith("/events"):
                return self._scan_events(reste[: -len("/events")], qs)
            return self._scan_detail(reste)
        if chemin == "/api/findings":
            return self._spa_json(self._findings_plats())
        if chemin == "/api/findings/summary":
            return self._spa_json(self._findings_resume())
        if chemin == "/api/instances":
            return self._instances(qs)
        if chemin == "/api/queue/status":
            return self._spa_json(self._file_statut())
        if chemin == "/api/schedules":
            return self._spa_json([])          # pas de planification dans le moteur
        if chemin == "/api/providers":
            return self._spa_json(self._providers())
        if chemin == "/api/auth/profiles":
            return self._spa_json([])
        if chemin == "/api/legacy-import/status":
            return self._spa_json({"count": 0, "dismissed": True})
        if chemin.startswith("/api/report/"):
            return self._rapport(chemin[len("/api/report/"):])
        if chemin == "/api/settings/llm":
            return self._spa_json(self._reglages_llm())
        if chemin == "/api/settings/environment":
            return self._spa_json({"envFile": "", "variables": [],
                                   "restartRequired": False})
        if chemin == "/api/settings/rate-limit":
            return self._spa_json({"requests": 0, "window": 0})
        if chemin == "/api/settings/agentmail":
            return self._spa_json({"pod": "", "apiKey": "", "hasApiKey": False})
        return self._spa_json({"error": f"route non prise en charge : {chemin}"}, 404)

    # ---- POST
    def do_POST(self):  # noqa: N802
        chemin = self.path.split("?", 1)[0]
        if chemin == "/api/runs":
            return super().do_POST()
        if chemin == "/api/scan":
            return self._lancer_scan()
        if chemin == "/api/auth/login":
            return self._spa_json({"status": "ok"})      # auth désactivée côté moteur
        if chemin == "/api/auth/logout":
            return self._spa_json({"status": "logged_out"})
        return self._spa_refus(
            f"écriture non prise en charge par le moteur AGNT : {chemin}")

    # ---- DELETE / PUT : l'archive de mission est la traçabilité du projet (append-only,
    # cf. .gitignore qui préserve journal des missions) — la suppression par l'interface
    # est refusée, jamais simulée.
    def do_DELETE(self):  # noqa: N802
        return self._spa_refus(
            "suppression non prise en charge : l'archive de mission est la "
            "traçabilité du projet et l'interface ne l'efface pas")

    def do_PUT(self):  # noqa: N802
        return self._spa_refus("écriture non prise en charge par le moteur AGNT")

    # ---- projections -------------------------------------------------------
    def _version(self) -> dict:
        cap = API._capacites()
        llm = cap.get("llm") or {}
        # La SPA préfixe un « v » : « v1.0.0 » s'affiche proprement.
        return {"version": "1.0.0",
                "ai": {"configured": bool(llm.get("cle_presente")),
                       "provider": "groq",
                       "model": llm.get("modele_defaut")}}

    def _statut_moteur(self) -> dict:
        actifs = _runs_actifs()
        en_cours = [e for e in actifs if e.get("statut") == "en_cours"]
        run = en_cours[0] if en_cours else None
        return {"running": bool(run),
                "scan_id": (API._mission_id_du_run(run) or "") if run else "",
                "instance_id": "",
                "current_phase": 1 if run else 0,
                "vulns": 0,          # pendant le run, le moteur ne publie pas ce compte
                "running_instances": len(en_cours)}

    def _lister_resumes(self) -> list[dict]:
        import mission_history as MH
        return MH.lister(proprietaire=API._proprietaires_actifs().get).get("items") or []

    def _scans(self, qs: dict):
        archives = [_scan_item_spa(i) for i in self._lister_resumes()]
        ids = {a["id"] for a in archives}
        # Les runs de file (en cours, en file, ou terminés sans archive — ex. un
        # refus avant ouverture de mission) sont préfixés ; ceux qui ont déjà une
        # archive ne sont PAS répétés : l'archive est la source, l'état de file
        # n'ajoute rien.
        vivants = [_run_vers_item_spa(e) for e in _runs_actifs()
                   if not (API._mission_id_du_run(e) or "") in ids]
        items = vivants + archives
        if qs.get("status") and qs["status"][0] not in ("all", ""):
            admis = STATUTS_AGNT.get(qs["status"][0], [])
            items = [i for i in items if i["status"] in
                     [qs["status"][0]] + [_statut_spa(a) for a in admis]]
        if qs.get("q") and qs["q"][0].strip():
            filtre = qs["q"][0].strip().lower()
            items = [i for i in items if filtre in (i.get("target") or "").lower()
                     or filtre in (i.get("name") or "").lower()]
        if "page" not in qs and "size" not in qs:
            return self._spa_json(items)
        try:
            page = max(1, int((qs.get("page") or ["1"])[0]))
            taille = min(200, max(1, int((qs.get("size") or [TAILLE_PAGE_DEFAUT])[0])))
        except ValueError:
            return self._spa_json({"error": "page/size : entiers attendus"}, 400)
        tranche = items[(page - 1) * taille: page * taille]
        return self._spa_json({"items": tranche, "total": len(items),
                               "page": page, "size": taille})

    def _scan_detail(self, mid: str):
        import mission_history as MH
        # Un run de file (id temporaire du POST /api/scan) répond avec son état —
        # EN COURS (la page poll et verra l'archive arriver) comme TERMINÉ SANS
        # archive (un refus avant ouverture de mission reste un résultat lisible,
        # jamais un 404 qui ressemblerait à une panne).
        with API.VERROU:
            run = dict(API.ETATS.get(mid) or {})
        if run:
            item = _run_vers_item_spa(run)
            item.update({"events": [], "events_truncated": False, "vulns": [],
                         "events_total": 0, "tool_calls": 0})
            motif = _run_stop_reason(run)
            if motif:
                item["stop_reason"] = motif
            return self._spa_json(item)
        try:
            projection = MH.projeter(mid, proprietaire=API._proprietaires_actifs().get)
        except MH.MissionIntrouvable:
            return self._spa_json({"error": "scan inconnu"}, 404)
        except MH.RequeteInvalide as e:
            return self._spa_json({"error": str(e)}, 400)
        return self._spa_json(_scan_record_spa(mid, projection))

    def _scan_events(self, mid: str, qs: dict):
        import mission_history as MH
        try:
            projection = MH.projeter(mid, proprietaire=API._proprietaires_actifs().get)
        except MH.MissionIntrouvable:
            return self._spa_json({"error": "scan inconnu"}, 404)
        except MH.RequeteInvalide as e:
            return self._spa_json({"error": str(e)}, 400)
        evenements = _evenements_spa(projection.get("data") or {})
        try:
            offset = max(0, int((qs.get("offset") or ["0"])[0]))
            limite = min(1000, max(1, int((qs.get("limit") or ["200"])[0])))
        except ValueError:
            return self._spa_json({"error": "offset/limit : entiers attendus"}, 400)
        return self._spa_json({"events": evenements[offset:offset + limite],
                               "total": len(evenements),
                               "offset": offset, "limit": limite})

    def _findings_plats(self) -> list[dict]:
        """Findings aplatis sur TOUTES les missions terminées (contrat FlatFinding).
        La déduplication et le tri sévérité restent côté SPA (lib/findings.ts)."""
        import mission_history as MH
        out: list[dict] = []
        for item in self._lister_resumes():
            if item.get("status") != "termine":
                continue
            mid = item["mission_id"]
            chemin = MH._chemin_mission(mid, MH._racine(None))
            if chemin is None:
                continue
            artefact = MH._resoudre_artefact(chemin, "findings.json")
            doc = MH._lire_json(artefact) if artefact is not None else None
            if not isinstance(doc, list):
                continue
            for f in doc:
                if isinstance(f, dict):
                    v = _vuln_spa(f, mid)
                    v["scan_id"] = mid
                    v["scan_target"] = (item.get("target") or {}).get("display_name") or "cible"
                    v["scan_started_at"] = item.get("started_at") or item.get("created_at") or ""
                    out.append(v)
        return out

    def _findings_resume(self) -> dict:
        totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings_plats():
            sev = str(f.get("severity") or "").lower()
            if sev in totals:
                totals[sev] += 1
            elif sev == "unknown":
                totals["info"] += 1     # bucket le plus bas, pas un jugement inventé
        return {"totals": totals,
                "as_of": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "etag": f"agnt-{sum(totals.values())}"}

    def _instances(self, qs: dict):
        archives = [_scan_item_spa(i) for i in self._lister_resumes()]
        ids = {a["id"] for a in archives}
        vivants = [_run_vers_item_spa(e) for e in _runs_actifs()
                   if not (API._mission_id_du_run(e) or "") in ids]
        instances = vivants + archives
        if "page" in qs or "size" in qs:
            try:
                page = max(1, int((qs.get("page") or ["1"])[0]))
                taille = min(200, max(1, int((qs.get("size") or [TAILLE_PAGE_DEFAUT])[0])))
            except ValueError:
                return self._spa_json({"error": "page/size : entiers attendus"}, 400)
            instances = instances[(page - 1) * taille: page * taille]
        return self._spa_json({
            "instances": instances,
            "total": len(instances), "page": 1,
            "size": TAILLE_PAGE_DEFAUT,
            "modes": ["agnt"],
            "resources": self._ressources()})

    def _ressources(self) -> dict:
        # Ce qui est mesurable sans dépendance : cœurs CPU, disque libre. La RAM et
        # la charge ne le sont pas proprement en stdlib → 0 explicite, avec `level`
        # « n/a » et la raison : la SPA exige des nombres, le moteur ne les mesure pas.
        try:
            libre_mo = shutil.disk_usage(DEPOT).free // (1024 * 1024)
        except OSError:
            libre_mo = 0
        return {"cpu_cores": os.cpu_count() or 1, "cpu_load_1m": 0,
                "ram_total_mb": 0, "ram_available_mb": 0, "disk_free_mb": libre_mo,
                "level": "n/a",
                "reason": "mesures RAM/charge non produites par le moteur AGNT",
                "max_instances": 1, "manual_max_instances": 1,
                "effective_max_instances": 1}   # loi 1 : une exécution à la fois

    def _file_statut(self) -> dict:
        actifs = _runs_actifs()
        en_cours = [e for e in actifs if e.get("statut") == "en_cours"]
        en_file = [e for e in actifs if e.get("statut") == "en_file"]
        run = en_cours[0] if en_cours else (en_file[0] if en_file else None)
        if run is None:
            return {"available": False}
        return {"available": True,
                "queue_count": len(en_file),
                "total_remaining": len(en_file),
                "active_scan_id": API._mission_id_du_run(run) or "",
                "active_target": str(run.get("cible") or ""),
                "instruction": str(run.get("question") or ""),
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(
                    float(run.get("pose_le") or 0.0)))}

    def _providers(self) -> list[dict]:
        # Le catalogue LLM réel du moteur : Groq, lu dans _capacites() — pas les
        # providers OpenAI/Gemini du backend Go d'origine, qui n'existent pas ici.
        # `modele_env` est le NOM de la variable d'environnement de surcharge, pas
        # un modèle : il ne va pas dans la liste des modèles proposés.
        llm = (API._capacites().get("llm") or {})
        modeles = [m for m in (llm.get("modele_defaut"),) if m]
        return [{"id": "groq", "displayName": "Groq",
                 "baseURL": "https://api.groq.com/openai/v1",
                 "headerStyle": "openai", "authMethods": ["api_key"],
                 "models": sorted(set(modeles)),
                 "notes": "clé lue dans la variable d'environnement "
                          f"{llm.get('cle_lue') or 'GROQ_API_KEY'} — non modifiable "
                          "par l'interface"}]

    def _reglages_llm(self) -> dict:
        llm = (API._capacites().get("llm") or {})
        return {"model": llm.get("modele_defaut") or "", "apiBase": "",
                "apiKey": "", "hasApiKey": bool(llm.get("cle_presente")),
                "reasoningEffort": "", "ollamaCompatible": False,
                "llmMaxRetries": 0, "memoryCompressorTimeout": 0,
                "maxIterations": 0, "geminiApiKey": "", "hasGeminiApiKey": False,
                "envFile": "", "provider": "groq", "authMethod": "api_key",
                "profiles": []}

    def _rapport(self, mid: str):
        """Le RAPPORT.md de l'archive, tel quel (text/markdown). 404 sans chemin."""
        import mission_history as MH
        chemin = MH._chemin_mission(mid, MH._racine(None))
        if chemin is None:
            return self._spa_json({"error": "scan inconnu"}, 404)
        artefact = MH._resoudre_artefact(chemin, "RAPPORT.md")
        if artefact is None or not artefact.is_file():
            return self._spa_json({"error": "aucun rapport pour ce scan"}, 404)
        corps = artefact.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corps)

    # ---- lancement d'un scan depuis la SPA ----------------------------------
    def _lancer_scan(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > PLAFOND_CORPS:
                return self._spa_json({"error": f"corps trop volumineux "
                                                f"({n} > {PLAFOND_CORPS} octets)"}, 413)
            corps = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return self._spa_json({"error": "corps de requête : JSON attendu"}, 400)
        if corps.get("save_only") is True:
            return self._spa_refus("save_only : le moteur n'a pas de scan « enregistré "
                                   "sans exécution » — lancer une mission ou ne rien poser")
        cibles = corps.get("targets")
        if not isinstance(cibles, list) or not cibles or not isinstance(cibles[0], str) \
                or not cibles[0].strip():
            return self._spa_json({"error": "targets : au moins un chemin de cible "
                                            "admis est requis"}, 400)
        if len(cibles) > 1:
            # Loi 1 : une exécution à la fois. Prendre la première et taire les autres
            # ferait croire à un scan multi-cibles ; nommer le refus laisse la SPA
            # (et l'opérateur) décider.
            return self._spa_json({"error": "une seule cible par mission (le moteur "
                                            "exécute une mission à la fois)"}, 400)
        question = str(corps.get("instruction") or "").strip()
        if not question:
            return self._spa_json({"error": "instruction : la question en langage "
                                            "naturel est requise"}, 400)
        if len(question) > API.TAILLE_MAX_REQUETE:
            return self._spa_json({"error": f"instruction trop longue "
                                            f"({len(question)} > {API.TAILLE_MAX_REQUETE})"}, 400)
        cible = cibles[0].strip()
        admises = {c["chemin"]: c for c in API.cibles_admises()}
        if cible not in admises:
            return self._spa_json({"error": "cible hors de la liste admise",
                                   "admises": sorted(admises)}, 400)
        modele = str(corps.get("model") or "").strip()
        moteur = "llm" if modele else "auto"
        confiance = "untrusted" if corps.get("scan_intensity") == "passive" else "controlled"
        rid = uuid.uuid4().hex[:12]
        with API.VERROU:
            API.ETATS[rid] = {"statut": "en_file", "question": question,
                              "cible": cible, "pose_le": time.time()}
        options = {"moteur": moteur, "confiance": confiance, "modele": modele}
        API.FILE.put((rid, question, cible, options))
        return self._spa_json({"status": "started", "instance_id": rid, "id": rid})


def main(argv=None) -> int:
    import argparse
    import mcp_bootstrap as MCP_BOOT
    import transports as CORE_TRANSPORTS
    MCP_BOOT.initialiser_mcp(CORE_TRANSPORTS)
    ap = argparse.ArgumentParser(
        description="API du tableau de bord AGNT (projection du contrat SPA)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8142)
    a = ap.parse_args(argv)
    threading.Thread(target=API._travail, daemon=True, name="agnt-run").start()
    srv = ThreadingHTTPServer((a.host, a.port), GestionnaireDashboard)
    print(f"tableau de bord AGNT · http://{a.host}:{a.port} · SPA : {SPA_DIR} · "
          f"un run à la fois · {len(API.cibles_admises())} cible(s) admise(s)",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
