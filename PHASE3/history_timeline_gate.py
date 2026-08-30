#!/usr/bin/env python3
"""Gate de sécurité des projections API History / Timeline / Status (P1).

Rôle — Security teste de façon hostile ce que CORE produit ; WEB ne consomme
jamais une projection qui n'est pas PASS. Ce module est le GATE : il valide une
projection JSON et rend un verdict, il ne produit jamais lui-même une projection.

Trois lois de construction (à ne pas casser) :

1. **Aucun lecteur de Mission.** Le gate ne lit ni archives, ni journaux, ni
   fichiers du workspace : il reçoit la projection en argument et la juge. Il ne
   peut rien vérifier « ailleurs » ; il vérifie ce que la projection DÉCLARE.
2. **Aucun assainissement.** Le gate ne modifie pas les données, ne redige rien,
   ne remplace aucune valeur : il refuse. C'est CORE qui doit produire une
   projection sûre ; un sanitizer côté Security serait un second chemin de
   sécurité, contournable, et cacherrait la fuite au serveur.
3. **Aucune fuite dans ses propres messages.** Un verdict ne contient JAMAIS la
   valeur fautive (secret, chemin, payload) : uniquement le chemin JSON, un code
   et une explication générique. Le gate ne doit pas devenir le canal de sortie
   de la donnée qu'il refuse.

Vocabulaire — Les schémas `agnt.history.v1`, `agnt.timeline.v1` et
`agnt.execution-status.v1` annoncés par Product ne sont PAS dans ce workspace
(vérifié : aucune branche, aucun commit). Les règles ci-dessous sont donc les
EXIGENCES DE SÉCURITÉ sur la forme attendue, en vocabulaire natif du dépôt
(`statut` : en_file / en_cours / termine / refuse / erreur …). Quand les
contrats Product arriveront, il faudra re-lier ce gate à leurs noms de clés —
le rejet d'une clé inconnue est voulu : il signale ce re-bind, il ne le simule
pas.

Usage :

    python3 PHASE3/history_timeline_gate.py --fixture-mode docs/coordination/fixtures
    python3 PHASE3/history_timeline_gate.py --response-file reponse.json
    python3 PHASE3/history_timeline_gate.py --base-url http://127.0.0.1:8141 [--mission-id m-…]

Code de sortie : 0 = tout PASS · 2 = au moins un FAIL · 1 = erreur d'usage /
réseau (cause affichée sans refléter la donnée reçue). Déterministe : même
entrée + même horloge => même verdict.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ══════════════════════════════════════════════════════════════════════════
# Vocabulaires TEMPORAIRES — à confirmer avec Product / MCP avant mise en prod.
# Une valeur inconnue n'est JAMAIS transformée en valeur valide : elle est
# refusée, et sa confirmation est un point de revue du gate.
# ══════════════════════════════════════════════════════════════════════════

API_CONNUES = ("agnt.history.v1", "agnt.timeline.v1", "agnt.execution-status.v1")

ENDPOINTS_CONNUS = ("/api/missions", "/api/missions/{mission_id}")

# Statuts de mission (vocabulaire natif du dépôt — api.py : en_file / en_cours /
# termine / refuse / erreur). `rien_trouve` est attendu comme statut de
# DÉTECTION (Product) ; `conflict` est l'état qui rend une contradiction visible.
MISSION_STATUTS = ("en_file", "en_cours", "termine", "refuse", "erreur",
                   "annulee", "conflict", "rien_trouve")

# Statuts "rassurants" : ils affirment que le travail est fini et propre.
# Aucune anomalie ne peut coexister avec eux (règles de compteurs).
MISSION_RASSURE = ("termine", "rien_trouve")

# Statuts d'EXÉCUTION (résultat du lancement d'un outil), distincts du statut de
# mission ET de la disponibilité du provider (séparation des vocabulaires).
STATUTS_EXECUTION = ("termine", "echoue", "timeout", "annulee", "refuse",
                     "en_cours", "non_lancee", "indisponible")

# Disponibilité d'un provider — UNIQUEMENT ce vocabulaire. Une valeur de statut
# de mission ici est une confusion de couches (vocabulaire-confondu).
DISPONIBILITES = ("disponible", "non_disponible", "degradee", "inconnue")

# Codes d'anomalie admis pour expliquer un résultat non exploitable.
ANOMALIES = ("opa_indisponible", "egress_bloque", "binaire_absent",
             "grille_regles_absente", "artefact_absent", "sortie_non_normalisee",
             "timeout", "annulation", "refus_politique", "provenance_inconnue",
             "mcp_indisponible", "erreur_parse")

# Provenance MCP. `source` ne peut PAS valoir « local » ni « default » :
# l'absence de provenance ne devient jamais une confiance locale.
SOURCES_PROVENANCE = ("mcp", "agnt", "mesuree")
CONFIDENCES = ("inconnue", "faible", "moyenne", "elevee")

# Vocabulaires MCP non stabilisés : allowlists TEMPORAIRES, extensibles par
# revue — jamais une valeur inconnue ramenée à une valeur valide.
TRANSPORTS = ("stdio", "sse", "websocket", "http", "grpc", "inconnu")
PROTOCOLES = ("mcp", "jsonrpc", "http", "https", "grpc", "inconnu")

# Types d'événements de timeline connus du dépôt (journal.jsonl : les six étapes
# + les événements de pré-vol). Un type inconnu est autorisé UNIQUEMENT sous
# forme générique sûre (aucun payload) — jamais inventé, jamais assaini.
TYPES_EVENEMENTS = ("ouverture", "test", "reprise", "plan", "contexte",
                    "execution", "cloture", "arret", "statuts")

# ══════════════════════════════════════════════════════════════════════════
# Schéma attendu — clés autorisées par emplacement (STRICT : clé inconnue =
# refus, car WEB pourrait la rendre).
# ══════════════════════════════════════════════════════════════════════════

CLES_RACINE = {"api", "endpoint", "data"}
CLES_DETAIL = {"mission_id", "statut", "created_at", "run_id", "providers",
               "executions", "findings_count", "findings_artifact", "timeline",
               "contradictions", "provenance", "complet", "partiel", "policy"}
CLES_LISTE = {"mission_id", "statut", "created_at", "run_id", "findings_count"}
CLES_PROVIDER = {"provider_id", "provider_kind", "availability", "reason_code",
                 "provenance"}
CLES_EXECUTION = {"provider_id", "statut", "started_at", "finished_at",
                  "findings_count", "sortie_non_normalisee", "anomalie",
                  "provenance"}
CLES_EVENEMENT = {"seq", "ts", "type", "label", "conflict"}
CLES_CONTRADICTION = {"code", "message"}
CLES_PROVENANCE = {"provider_id", "provider_kind", "transport", "server_id",
                   "tool_id", "protocol", "confidence", "source",
                   "provider_declared", "availability", "request_id",
                   "correlation_id"}
CLES_POLICY = {"moteur", "decision", "disponible", "motif"}

# Clés INTERDITES où qu'elles apparaissent : ce sont les canaux de fuite.
# Leur seule présence (même valeur vide) est un refus — WEB ne doit jamais
# avoir à décider si leur contenu est dangereux.
CLES_INTERDITES = {
    "argv", "command", "cmd", "commands", "env", "environ", "environment",
    "executable", "exe", "cwd", "chdir", "mount", "mounts",
    "wall", "shell", "stdout", "stderr", "traceback", "stack", "stack_trace",
    "backtrace", "exception_detail", "headers", "header", "authorization",
    "cookie", "cookies", "session", "token", "access_token", "refresh_token",
    "api_key", "apikey", "secret", "secrets", "password", "passwd", "pwd",
    "private_key", "credential", "credentials", "payload", "body", "raw",
    "raw_output", "raw_response", "raw_payload", "brut", "brut_output",
    "brut_response", "url", "uri", "download_url", "artifact_url",
    "path", "paths", "file_path", "local_path", "absolute_path",
    "sandbox_path", "sandbox", "filesystem", "inode", "mtime", "size",
    "mode", "file", "filename", "worktree", "home_dir", "tmp_dir",
    "cache_dir", "cache_path", "git_dir", "repo_path", "reponse_brute",
    "erreur_brute", "erreur_distante", "detail_technique", "dumps",
}

# ══════════════════════════════════════════════════════════════════════════
# Détection de CONTENU (valeurs). Chaque règle rend (code, libellé générique).
# Aucune valeur fautive n'est stockée ni rendue par le verdict.
# ══════════════════════════════════════════════════════════════════════════

_CONTENUS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("secret-bearer",
     re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
     "en-tête d'autorisation Bearer détecté"),
    ("secret-jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\b"),
     "jeton JWT détecté"),
    ("secret-cle-github",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
     "clé GitHub détectée"),
    ("secret-cle-aws",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "clé AWS détectée"),
    ("secret-api-key",
     re.compile(r"\b(?:sk|pk|rk|ak)[-_][A-Za-z0-9]{16,}\b"),
     "clé d'API détectée"),
    ("secret-gitlab",
     re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
     "jeton GitLab détecté"),
    ("secret-google",
     re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
     "clé Google détectée"),
    ("secret-slack",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
     "jeton Slack détecté"),
    ("secret-cle-privee",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
     "clé privée détectée"),
    ("secret-url-userinfo",
     re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s@]+:[^@\s/]+@", re.I),
     "URL avec identifiants (userinfo) détectée"),
    ("secret-url-token",
     re.compile(r"(?i)[?#&](?:access_token|token|api[_-]?key|auth|signature|sig)=[^&\s\"']+"),
     "jeton dans une URL détecté"),
    ("secret-header-auth",
     re.compile(r"(?i)(?:authorization|proxy-authorization)\s*[:=]\s*[^\s\"']+"),
     "en-tête d'autorisation détecté"),
    ("secret-cookie",
     re.compile(r"(?i)(?:cookie|set-cookie)\s*[:=]\s*[^;=\s\"']+="),
     "cookie / session détecté"),
    ("secret-variable-env",
     re.compile(r"(?i)\b[A-Z][A-Z0-9_]*(?:_(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL|COOKIE|SESSION|API[_-]?KEY))\s*=\s*\S+"),
     "variable d'environnement sensible détectée"),
    ("secret-affectation",
     re.compile(r"(?i)\b(?:token|access_token|api[_-]?key|secret|password|passwd|client[_-]?secret|session[_-]?id)\s*[:=]\s*[\"']?[^\s\"',}\]]{8,}"),
     "affectation de credential détectée"),
    # ── Chemins / environnements locaux ──────────────────────────────────
    ("chemin-home",
     re.compile(r"(?:^|[/\\])(?:home|Users|root)[/\\][^\s\"'\\]+"),
     "chemin d'accueil utilisateur détecté"),
    ("chemin-absolu",
     re.compile(r"/?(?:tmp|var|etc|opt|usr|bin|srv|mnt|proc|sys|run|dev)/[A-Za-z0-9._+~-]+(?:/[A-Za-z0-9._+~-]+)*"),
     "chemin absolu Linux détecté"),
    ("chemin-windows",
     re.compile(r"\b[A-Za-z]:[\\/][^\s\"']*"),
     "chemin Windows détecté"),
    ("chemin-traversal",
     re.compile(r"(?:\.\./|\.\.\\)"),
     "traversée de répertoire détectée"),
    ("chemin-sandbox",
     re.compile(r"(?:mt-scan|mt-regles|mt-out|mt-db|arena_secops|PHASE3[/\\]|docs/coordination)"),
     "chemin d'environnement AGNT détecté"),
    ("reference-artefact",
     re.compile(r"(?i)\b(?:raw|brut)_[a-z0-9_.-]+"),
     "référence à un artefact interne détectée"),
    ("reference-commandes",
     re.compile(r"(?i)\b(?:--config=|--report-path=|--format|--no-banner|gitleaks git|semgrep )"),
     "extrait de ligne de commande détecté"),
    ("fichier-cache",
     re.compile(r"(?:\.cache[/\\]|\.venv[/\\]|node_modules[/\\])(?:[^\s\"']*)"),
     "chemin de cache local détecté"),
    # ── Contenu non normalisé ─────────────────────────────────────────────
    ("stack-trace",
     re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+"),
     "trace de pile détectée"),
    ("html-executable",
     re.compile(r"(?i)<\s*(?:script|iframe|object|embed|form|svg|link|img|meta)\b|javascript:|on\w+\s*=|data:text/html"),
     "contenu HTML/script exécutable détecté"),
    ("endpoint-url",
     re.compile(r"\bhttps?://\S+"),
     "URL brute détectée"),
)

# Identifiants techniques : motif strict, sinon refus.
ID_GENERIQUE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
ID_PROVIDER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
ID_HIERARCHIQUE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
ID_MISSION = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
NOM_COURT = re.compile(r"^[^\s\"'`]{1,64}$")

_MARQUEUR_FIXTURE = "TEST ONLY — NEVER SERVE AS PRODUCT DATA"


# ══════════════════════════════════════════════════════════════════════════
# Verdict — ne contient que du texte générique + le chemin JSON de la faille.
# ══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Raison:
    chemin: str       # ex. data.timeline[2].payload — position, pas valeur
    code: str         # code de règle, stable et testable
    message: str      # explication générique, SANS la valeur fautive

    def __str__(self) -> str:
        return f"[{self.code}] {self.chemin} : {self.message}"


@dataclass(frozen=True)
class Verdict:
    ok: bool
    raisons: tuple[Raison, ...] = ()

    def __str__(self) -> str:
        if self.ok:
            return "PASS"
        corps = " ; ".join(str(r) for r in self.raisons[:6])
        if len(self.raisons) > 6:
            corps += f" ; … (+{len(self.raisons) - 6} autres)"
        return f"FAIL — {corps}"

    @property
    def codes(self) -> frozenset[str]:
        return frozenset(r.code for r in self.raisons)


def _refuse(*raisons: Raison) -> Verdict:
    return Verdict(False, tuple(raisons))


class _Juge:
    """Marche arborescente de la projection. N'écrit rien, ne lit rien d'autre."""

    def __init__(self, horloge: datetime | None) -> None:
        self.raisons: list[Raison] = []
        self._contradictions_declarees = False
        self.horloge = horloge or datetime.now(timezone.utc)

    # ── primitives ────────────────────────────────────────────────────────
    def refus(self, chemin: str, code: str, message: str) -> None:
        self.raisons.append(Raison(chemin, code, message))

    def _clés(self, obj: dict, chemin: str, autorisées: set[str],
              interdites: set[str]) -> None:
        for k in obj:
            # `endpoint` n'est admis qu'à la racine (nom public de la route
            # interrogée) ; ailleurs, une adresse de service est une fuite.
            if k == "endpoint" and chemin != "projection":
                self.refus(f"{chemin}.{k}", "cle-interdite",
                           "adresse d'endpoint présente hors racine : elle ne "
                           "doit jamais atteindre le navigateur")
            elif k in interdites:
                self.refus(f"{chemin}.{k}", "cle-interdite",
                           "clé interdite présente : son contenu ne doit jamais "
                           "atteindre le navigateur")
            elif k not in autorisées:
                self.refus(f"{chemin}.{k}", "cle-inconnue",
                           "clé hors schéma de sécurité : à valider avant toute "
                           "consommation WEB")

    def _valeurs(self, valeur: Any, chemin: str) -> None:
        """Balayage de CONTENU : valeurs interdites, à tous les niveaux."""
        if isinstance(valeur, str):
            for code, motif, libelle in _CONTENUS:
                if motif.search(valeur):
                    self.refus(chemin, code, libelle)
        elif isinstance(valeur, list):
            for i, v in enumerate(valeur):
                self._valeurs(v, f"{chemin}[{i}]")
        elif isinstance(valeur, dict):
            for k, v in valeur.items():
                # Les clés interdites sont signalées à leur emplacement exact
                # (une trace de clé suffit, sans sa valeur).
                self._valeurs(v, f"{chemin}.{k}")

    # ── utilitaires de type ───────────────────────────────────────────────
    def _est_dict(self, obj: Any, chemin: str) -> bool:
        if not isinstance(obj, dict):
            self.refus(chemin, "type-invalide",
                       "objet JSON attendu à cet emplacement")
            return False
        return True

    def _est_liste(self, obj: Any, chemin: str) -> bool:
        if not isinstance(obj, list):
            self.refus(chemin, "type-invalide",
                       "liste JSON attendue à cet emplacement")
            return False
        return True

    def _str(self, obj: Any, chemin: str, motif: re.Pattern[str],
             si_absent: str | None) -> str | None:
        if obj is None:
            self.refus(chemin, "champ-obligatoire",
                       si_absent or "champ obligatoire absent")
            return None
        if not isinstance(obj, str):
            self.refus(chemin, "type-invalide", "chaîne attendue")
            return None
        if not motif.match(obj):
            self.refus(chemin, "valeur-invalide",
                       "format incompatible avec le vocabulaire de sécurité")
            return None
        return obj

    # ── soumission ────────────────────────────────────────────────────────
    def analyser(self, projection: dict[str, Any]) -> Verdict:
        racine = "projection"
        if not self._est_dict(projection, racine):
            return _refuse(Raison(racine, "forme-invalide",
                                  "la projection doit être un objet JSON"))
        self._clés(projection, racine, CLES_RACINE, CLES_INTERDITES)
        api = projection.get("api")
        if api is None:
            self.refus(f"{racine}.api", "champ-obligatoire",
                       "le nom du contrat API est obligatoire")
        elif not isinstance(api, str) or api not in API_CONNUES:
            self.refus(f"{racine}.api", "api-inconnue",
                       "contrat non reconnu par le gate de sécurité")
        endpoint = projection.get("endpoint")
        if endpoint is not None and (
                not isinstance(endpoint, str) or endpoint not in ENDPOINTS_CONNUS):
            self.refus(f"{racine}.endpoint", "endpoint-inconnu",
                       "endpoint hors vocabulaire public admis")
        # Un SEUL point d'entrée pour le balayage de contenu : chaque chaîne est
        # jugée exactement une fois, tous niveaux confondus (pas de double
        # signalement qui brouillerait la lecture du verdict).
        self._valeurs(projection, racine)
        data = projection.get("data")
        if data is None:
            self.refus(f"{racine}.data", "champ-obligatoire",
                       "données de projection absentes")
            return _refuse(*self.raisons)
        if isinstance(data, list):
            self._liste(data, f"{racine}.data")
        elif isinstance(data, dict):
            self._detail(data, f"{racine}.data", endpoint)
        else:
            self.refus(f"{racine}.data", "type-invalide",
                       "objet ou liste attendu sous data")
        return Verdict(not self.raisons, tuple(self.raisons))

    # ── liste : GET /api/missions ─────────────────────────────────────────
    def _liste(self, data: list[Any], chemin: str) -> None:
        ids: set[str] = set()
        for i, item in enumerate(data):
            p = f"{chemin}[{i}]"
            if not self._est_dict(item, p):
                continue
            self._clés(item, p, CLES_LISTE, CLES_INTERDITES)
            mid = self._str(item.get("mission_id"), f"{p}.mission_id", ID_MISSION,
                            "identifiant de mission absent")
            if mid is not None:
                if mid in ids:
                    self.refus(f"{p}.mission_id", "mission-dupliquee",
                               "identifiant de mission répété dans la liste")
                ids.add(mid)
            self._statut_mission(item.get("statut"), f"{p}.statut")
            self._ts_iso(item.get("created_at"), f"{p}.created_at",
                         obligatoire=False)
            self._compteur(item.get("findings_count"), f"{p}.findings_count",
                           # Une liste est un résumé : pas de règles de
                           # couverture ici (elles exigent les exécutions).
                           comptes=False)

    # ── détail : GET /api/missions/{id} ───────────────────────────────────
    def _detail(self, data: dict[str, Any], chemin: str,
                endpoint: str | None) -> None:
        self._clés(data, chemin, CLES_DETAIL, CLES_INTERDITES)

        mid = self._str(data.get("mission_id"), f"{chemin}.mission_id",
                        ID_MISSION, "identifiant de mission absent")
        statut = self._statut_mission(data.get("statut"), f"{chemin}.statut")
        debut = self._ts_iso(data.get("created_at"), f"{chemin}.created_at",
                             obligatoire=False)
        run_id = data.get("run_id")
        if run_id is not None and (not isinstance(run_id, str) or
                                   not ID_MISSION.match(run_id)):
            self.refus(f"{chemin}.run_id", "valeur-invalide",
                       "identifiant de run hors format de sécurité")

        self._compteur(data.get("findings_count"), f"{chemin}.findings_count",
                       comptes=True)
        self._artefact(data.get("findings_artifact"), f"{chemin}.findings_artifact")

        # Provenance de la mission (niveau racine de data).
        if "provenance" in data:
            self._provenance(data["provenance"], f"{chemin}.provenance",
                             exigible=False)

        # Policy : un moteur indisponible ou une décision de refus doivent se
        # refléter dans le statut — jamais dans un statut rassurant.
        if "policy" in data:
            self._policy(data["policy"], f"{chemin}.policy", statut)

        # couverture providers / executions / compteurs
        self._providers_executions(data, chemin, statut)

        # contradictions D'ABORD : la timeline s'y réfère pour décider si un
        # signal `conflict` est explicite (contradiction-sans-preuve).
        self._contradictions(data.get("contradictions"), f"{chemin}.contradictions",
                             statut)
        # timeline (created_at déjà validé ci-dessus : transmis, pas re-jugé)
        if "timeline" in data:
            self._timeline(data["timeline"], f"{chemin}.timeline", debut)
        if "events" in data:
            self.refus(f"{chemin}.events", "duplication-events-timeline",
                       "deux chemins pour la même histoire : events est interdit, "
                       "timeline est la source d'ordre")

        # mission partielle / incomplète
        for clé in ("complet", "partiel"):
            if clé in data and not isinstance(data[clé], bool):
                self.refus(f"{chemin}.{clé}", "type-invalide",
                           "booléen attendu")
        incomplet = data.get("complet") is False or data.get("partiel") is True
        if incomplet and statut in MISSION_RASSURE:
            self.refus(f"{chemin}.statut", "mission-partielle-resolue",
                       "mission incomplète présentée avec un statut rassurant")

        # Mission sans run : un résultat terminal doit être rattaché à un run.
        if statut in MISSION_RASSURE and not data.get("run_id"):
            self.refus(f"{chemin}.run_id", "mission-sans-run",
                       "statut rassurant sans identifiant de run : résultat "
                       "invérifiable")
        if mid is None and data.get("mission_id") is not None and endpoint and \
                endpoint == "/api/missions/{mission_id}":
            self.refus(f"{chemin}.mission_id", "mission-inconnue",
                       "identifiant de mission illisible")

    def _statut_mission(self, valeur: Any, chemin: str) -> str | None:
        if valeur is None:
            self.refus(chemin, "champ-obligatoire",
                       "statut de mission absent")
            return None
        if not isinstance(valeur, str):
            self.refus(chemin, "type-invalide", "statut non textuel")
            return None
        # Séparation des couches : le statut de mission ne prend pas de valeur
        # de disponibilité ni un résultat d'exécution qui n'est pas un mot du
        # cycle de vie partagé (termine / en_cours / refuse / annulee).
        if valeur in DISPONIBILITES or (valeur in STATUTS_EXECUTION and
                                        valeur not in MISSION_STATUTS):
            self.refus(chemin, "vocabulaire-confondu",
                       "statut de mission et état d'une autre couche partagent "
                       "le même vocabulaire")
            return None
        if valeur not in MISSION_STATUTS:
            self.refus(chemin, "statut-inconnu",
                       "statut hors vocabulaire canonique : ne jamais convertir "
                       "une valeur inconnue en valeur valide")
            return None
        return valeur

    def _ts_iso(self, valeur: Any, chemin: str, obligatoire: bool) -> datetime | None:
        if valeur is None:
            if obligatoire:
                self.refus(chemin, "ts-absent",
                           "horodatage obligatoire absent")
            return None
        if not isinstance(valeur, str):
            self.refus(chemin, "ts-invalide", "horodatage non textuel")
            return None
        try:
            ts = datetime.fromisoformat(valeur.replace("Z", "+00:00"))
        except ValueError:
            self.refus(chemin, "ts-invalide",
                       "horodatage non conforme ISO 8601")
            return None
        if ts.tzinfo is None:
            self.refus(chemin, "ts-invalide",
                       "horodatage sans fuseau : ambigu et invérifiable")
            return None
        if ts > self.horloge + timedelta(seconds=5):
            self.refus(chemin, "ts-futur",
                       "horodatage dans le futur : impossible ou trompeur")
        return ts.astimezone(timezone.utc)

    def _compteur(self, valeur: Any, chemin: str, comptes: bool) -> int | None:
        if isinstance(valeur, bool) or not isinstance(valeur, int):
            if comptes or valeur is not None:
                self.refus(chemin, "compteur-invalide",
                           "compteur non entier ou booléen déguisé")
            return None
        if valeur < 0:
            self.refus(chemin, "compteur-negatif",
                       "compteur négatif : un compte ne peut pas prétendre "
                       "une absence de résultat")
        return valeur

    def _artefact(self, valeur: Any, chemin: str) -> None:
        if valeur is None:
            self.refus(chemin, "champ-obligatoire",
                       "état de l'artefact de findings absent")
            return
        if valeur not in ("present", "absent", "indetermine"):
            self.refus(chemin, "valeur-invalide",
                       "état d'artefact hors vocabulaire")
        # La règle de compteur (zero-artefact-absent) est appliquée dans
        # _providers_executions, où le compteur est disponible.

    # ── policy ────────────────────────────────────────────────────────────
    def _policy(self, policy: Any, chemin: str, statut: str | None) -> None:
        if not self._est_dict(policy, chemin):
            return
        self._clés(policy, chemin, CLES_POLICY, CLES_INTERDITES)
        if policy.get("disponible") is False:
            if statut in MISSION_RASSURE:
                self.refus(f"{chemin}.disponible", "zero-opa-indisponible",
                           "moteur de politique indisponible avec statut rassurant : "
                           "l'absence de décision n'est pas une autorisation")
        decision = policy.get("decision")
        if decision in ("refuse", "refusee") and statut in MISSION_RASSURE:
            self.refus(f"{chemin}.decision", "zero-refus-politique",
                       "décision de refus avec statut rassurant : un refus ne "
                       "produit pas de conclusion propre")
        if decision is not None and decision not in ("autorisee", "refuse",
                                                     "refusee", "non_evaluee"):
            self.refus(f"{chemin}.decision", "valeur-inconnue",
                       "décision hors vocabulaire")

    # ── providers / executions / compteurs ────────────────────────────────
    def _providers_executions(self, data: dict[str, Any], chemin: str,
                              statut: str | None) -> None:
        fournis = data.get("providers")
        executions = data.get("executions")
        if fournis is not None and not self._est_liste(fournis, f"{chemin}.providers"):
            fournis = None
        if executions is not None and not self._est_liste(executions, f"{chemin}.executions"):
            executions = None

        ids_fournis: set[str] = set()
        ids_executes: set[str] = set()
        indisponibles_justifies: set[str] = set()
        anomalies_0: list[str] = []

        for i, p in enumerate(fournis or []):
            pp = f"{chemin}.providers[{i}]"
            if not self._est_dict(p, pp):
                continue
            self._clés(p, pp, CLES_PROVIDER, CLES_INTERDITES)
            pid = self._str(p.get("provider_id"), f"{pp}.provider_id",
                            ID_PROVIDER, "provider sans identifiant")
            if pid:
                ids_fournis.add(pid)
            kind = p.get("provider_kind")
            if kind is not None and (not isinstance(kind, str) or
                                     not NOM_COURT.match(kind)):
                self.refus(f"{pp}.provider_kind", "valeur-invalide",
                           "type de provider hors vocabulaire")
            dispo = p.get("availability")
            if dispo is not None:
                if isinstance(dispo, str) and (dispo in MISSION_STATUTS or
                                               dispo in STATUTS_EXECUTION or
                                               dispo in CONFIDENCES):
                    # Une valeur d'une AUTRE couche n'est pas une disponibilité :
                    # c'est la confusion de vocabulaire à refuser en premier.
                    self.refus(f"{pp}.availability", "vocabulaire-confondu",
                               "disponibilité de provider et statut de mission "
                               "ne partagent pas le même vocabulaire")
                elif not isinstance(dispo, str) or dispo not in DISPONIBILITES:
                    self.refus(f"{pp}.availability", "disponibilite-inconnue",
                               "disponibilité hors vocabulaire")
            rc = p.get("reason_code")
            if rc is not None:
                if not isinstance(rc, str) or rc not in ANOMALIES:
                    self.refus(f"{pp}.reason_code", "anomalie-inconnue",
                               "code d'anomalie hors vocabulaire")
                elif dispo == "non_disponible":
                    indisponibles_justifies.add(pid or f"#{i}")
            if "provenance" in p:
                self._provenance(p["provenance"], f"{pp}.provenance",
                                 exigible=False)

        resultats_non_termineaux = []
        sorties_anormales = []
        for i, ex in enumerate(executions or []):
            ep = f"{chemin}.executions[{i}]"
            if not self._est_dict(ex, ep):
                continue
            self._clés(ex, ep, CLES_EXECUTION, CLES_INTERDITES)
            pid = self._str(ex.get("provider_id"), f"{ep}.provider_id",
                            ID_PROVIDER, "exécution sans provider")
            if pid:
                ids_executes.add(pid)
            st = ex.get("statut")
            if st is not None:
                if not isinstance(st, str) or st not in STATUTS_EXECUTION:
                    self.refus(f"{ep}.statut", "statut-execution-inconnu",
                               "statut d'exécution hors vocabulaire")
                elif st in DISPONIBILITES:
                    self.refus(f"{ep}.statut", "vocabulaire-confondu",
                               "statut d'exécution et disponibilité de provider "
                               "ne partagent pas le même vocabulaire")
                elif st in ("timeout", "annulee", "refuse", "echoue",
                            "en_cours", "non_lancee", "indisponible"):
                    resultats_non_termineaux.append((pid or f"#{i}", st))
            self._ts_iso(ex.get("started_at"), f"{ep}.started_at",
                         obligatoire=False)
            self._ts_iso(ex.get("finished_at"), f"{ep}.finished_at",
                         obligatoire=False)
            if ex.get("sortie_non_normalisee") is True:
                sorties_anormales.append(pid or f"#{i}")
            anom = ex.get("anomalie")
            if anom is not None and anom not in ANOMALIES:
                self.refus(f"{ep}.anomalie", "anomalie-inconnue",
                           "anomalie hors vocabulaire")
            if anom == "sortie_non_normalisee":
                sorties_anormales.append(pid or f"#{i}")
            if "provenance" in ex:
                self._provenance(ex["provenance"], f"{ep}.provenance",
                                 exigible=False)

        # ── règles de compteurs (détail seulement, via statut + compteur) ──
        compte = data.get("findings_count")
        rassurant = statut in MISSION_RASSURE
        if rassurant and compte == 0:
            if not executions:
                self.refus(f"{chemin}.findings_count", "zero-sans-execution",
                           "aucun résultat sans aucune exécution : zéro ne peut "
                           "pas être une conclusion de détection")
            for pid in sorted(ids_fournis - ids_executes):
                if pid not in indisponibles_justifies:
                    self.refus(f"{chemin}.providers", "zero-provider-sans-execution",
                               f"provider sans exécution ni anomalie déclarée "
                               f"conclut à zéro : couverture non démontrée")
            for pid, st in resultats_non_termineaux:
                self.refus(f"{chemin}.findings_count",
                           "zero-statut-non-terminal",
                           f"{pid} ne s'est pas terminé normalement : zéro est "
                           "une absence de résultat, pas une conclusion")
            for pid in sorties_anormales:
                self.refus(f"{chemin}.findings_count", "zero-sortie-anormale",
                           f"sortie non normalisée ({pid}) : zéro non démontré")
            if data.get("findings_artifact") == "absent":
                self.refus(f"{chemin}.findings_artifact",
                           "zero-artefact-absent",
                           "artefact de findings absent : le compteur est "
                           "inconnu, pas zéro")
            for p in (fournis or []):
                if p.get("reason_code") in ("opa_indisponible", "egress_bloque"):
                    self.refus(f"{chemin}.findings_count",
                               "zero-opa-indisponible" if p.get("reason_code")
                               == "opa_indisponible" else "zero-egress-bloque",
                               "anomalie de politique ou de sortie avec statut "
                               "rassurant : la couverture de détection est "
                               "indémontrable")
            # egress : un provider refusé à cause du réseau et compté zéro.
            for i, p in enumerate(fournis or []):
                if p.get("reason_code") in ("egress_bloque", "timeout",
                                            "annulation") and \
                        p.get("availability") == "non_disponible":
                    self.refus(f"{chemin}.providers[{i}]", "zero-egress-bloque",
                               "provider non exécuté (sortie refusée) avec statut "
                               "rassurant")
        elif rassurant and compte is None:
            self.refus(f"{chemin}.findings_count", "compteur-invalide",
                       "compteur absent sur un statut rassurant")

    # ── timeline ──────────────────────────────────────────────────────────
    def _timeline(self, timeline: Any, chemin: str,
                  debut: datetime | None) -> None:
        if not self._est_liste(timeline, chemin):
            return
        seqs: set[int] = set()
        precedente: int | None = None
        ts_precedent: datetime | None = None
        conflits_masques = False
        for i, ev in enumerate(timeline):
            p = f"{chemin}[{i}]"
            if not self._est_dict(ev, p):
                continue
            self._clés(ev, p, CLES_EVENEMENT, CLES_INTERDITES)
            # seq : source d'ordre, obligatoire, entier, unique, croissant.
            seq = ev.get("seq")
            if seq is None:
                self.refus(f"{p}.seq", "seq-manquant",
                           "séquence absente : l'ordre ne peut pas être établi")
                seq = None
            elif isinstance(seq, bool) or not isinstance(seq, int):
                self.refus(f"{p}.seq", "seq-non-numerique",
                           "séquence non entière : l'ordre ne peut pas être "
                           "établi")
                seq = None
            elif seq < 0:
                self.refus(f"{p}.seq", "seq-non-numerique",
                           "séquence négative")
                seq = None
            if seq is not None:
                if seq in seqs:
                    self.refus(f"{p}.seq", "seq-duplique",
                               "séquence dupliquée : ordre ambigu")
                elif precedente is not None and seq <= precedente:
                    self.refus(f"{p}.seq", "seq-non-croissant",
                               "séquence non croissante : ordre contradictoire")
                elif precedente is not None and seq != precedente + 1:
                    self.refus(f"{p}.seq", "seq-trou",
                               "trou dans la séquence : une étape manque")
                seqs.add(seq)
                precedente = seq
            # ts : obligatoire dans la timeline (axiome : une histoire sans
            # temps n'est pas vérifiable), validé, ordonné, non trompeur.
            ts = self._ts_iso(ev.get("ts"), f"{p}.ts", obligatoire=True)
            if ts is not None:
                if debut is not None and ts < debut:
                    self.refus(f"{p}.ts", "ts-anterieur",
                               "événement antérieur à la création de la mission")
                if ts_precedent is not None and ts < ts_precedent:
                    self.refus(f"{p}.ts", "ts-en-desordre",
                               "horodatages contraires à l'ordre des séquences")
                ts_precedent = ts
            # type : connu ou générique (sans payload). Un type inconnu avec un
            # contenu au-delà des champs génériques est un refus.
            typ = ev.get("type")
            if typ is None or not isinstance(typ, str) or not typ.strip():
                self.refus(f"{p}.type", "champ-obligatoire",
                           "type d'événement absent")
            elif typ not in TYPES_EVENEMENTS:
                extras = sorted(set(ev) - CLES_EVENEMENT)
                if extras:
                    self.refus(f"{p}.type", "evenement-inconnu-non-generique",
                               "événement inconnu porteur de champs hors forme "
                               "générique : refusé, jamais normalisé")
                # la valeur de payload a déjà été bloquée par CLES_INTERDITES
            if ev.get("conflict") is True:
                conflits_masques = True
        if conflits_masques and not self._a_contradictions_explicites:
            self.refus(f"{chemin}", "contradiction-sans-preuve",
                       "contradiction signalée sans objet explicite : une "
                       "contradiction se rend visible, elle ne se devine pas")

    def _contradictions(self, valeur: Any, chemin: str,
                        statut: str | None) -> None:
        if valeur is None:
            if statut == "conflict":
                self.refus(chemin, "contradiction-sans-preuve",
                           "état conflict déclaré sans objet de contradiction : "
                           "une contradiction se rend visible, elle ne se devine pas")
            return
        if not self._est_liste(valeur, chemin):
            return
        self._contradictions_declarees = True
        for i, c in enumerate(valeur):
            p = f"{chemin}[{i}]"
            if not self._est_dict(c, p):
                continue
            self._clés(c, p, CLES_CONTRADICTION, CLES_INTERDITES)
            if "code" not in c or not isinstance(c["code"], str) or \
                    not c["code"].strip():
                self.refus(f"{p}.code", "champ-obligatoire",
                           "code de contradiction absent")
        if valeur and statut in MISSION_RASSURE:
            self.refus(f"{chemin}", "contradiction-resolue",
                       "contradiction déclarée sous un statut rassurant : "
                       "l'état doit être conflict, jamais le plus rassurant")

    # ── provenance MCP ────────────────────────────────────────────────────
    def _provenance(self, provenance: Any, chemin: str, exigible: bool) -> None:
        if not self._est_dict(provenance, chemin):
            return
        self._clés(provenance, chemin, CLES_PROVENANCE, CLES_INTERDITES)
        source = provenance.get("source")
        if source is not None:
            if not isinstance(source, str) or source not in SOURCES_PROVENANCE:
                self.refus(f"{chemin}.source", "provenance-source-invalide",
                           "source hors vocabulaire : l'absence de provenance "
                           "ne devient jamais locale ni fiable")
        declared = provenance.get("provider_declared")
        if declared is not None and not isinstance(declared, bool):
            self.refus(f"{chemin}.provider_declared", "type-invalide",
                       "booléen attendu")
        confiance = provenance.get("confidence")
        if confiance is not None:
            if not isinstance(confiance, str) or confiance not in CONFIDENCES:
                self.refus(f"{chemin}.confidence", "confiance-inconnue",
                           "niveau de confiance hors vocabulaire")
            elif confiance != "inconnue" and \
                    (source is None or declared is True):
                self.refus(f"{chemin}.confidence", "confiance-sans-source",
                           "confiance élevée sans provenance mesurée : une "
                           "déclaration de provider n'est pas une confiance AGNT")
        availability = provenance.get("availability")
        if availability is not None and (
                not isinstance(availability, str) or
                availability not in DISPONIBILITES):
            self.refus(f"{chemin}.availability", "disponibilite-inconnue",
                       "disponibilité hors vocabulaire")
        for clé in ("transport", "protocol"):
            v = provenance.get(clé)
            if v is None:
                continue
            vocab = TRANSPORTS if clé == "transport" else PROTOCOLES
            if not isinstance(v, str) or v not in vocab:
                self.refus(f"{chemin}.{clé}", f"{clé}-inconnu",
                           "vocabulaire non stabilisé : valeur inconnue refusée "
                           "jusqu'à confirmation MCP")
        for clé in ("server_id", "tool_id"):
            v = provenance.get(clé)
            if v is None:
                continue
            if not isinstance(v, str) or not ID_HIERARCHIQUE.match(v):
                self.refus(f"{chemin}.{clé}", "provenance-id-invalide",
                           "identifiant technique hors format de sécurité")
        for clé in ("request_id", "correlation_id"):
            v = provenance.get(clé)
            if v is None:
                continue
            if not isinstance(v, str) or not ID_GENERIQUE.match(v):
                self.refus(f"{chemin}.{clé}", "provenance-id-invalide",
                           "identifiant de corrélation hors format de sécurité")
        pid = provenance.get("provider_id")
        if pid is not None:
            self._str(pid, f"{chemin}.provider_id", ID_PROVIDER,
                      "provider de provenance invalide")
        kind = provenance.get("provider_kind")
        if kind is not None and (not isinstance(kind, str) or
                                 not NOM_COURT.match(kind)):
            self.refus(f"{chemin}.provider_kind", "valeur-invalide",
                       "type de provider hors vocabulaire")


def valider_projection(projection: dict[str, Any],
                       *, horloge: datetime | None = None) -> Verdict:
    """Valide une projection History / Timeline / Status. Déterministe."""
    return _Juge(horloge).analyser(projection)


# ══════════════════════════════════════════════════════════════════════════
# Runner — fixtures, réponse capturée, ou API réelle. La projection est
# toujours jugée telle quelle ; jamais réécrite, jamais affichée.
# ══════════════════════════════════════════════════════════════════════════

def _horloge(texte: str | None) -> datetime | None:
    if not texte:
        return None
    try:
        ts = datetime.fromisoformat(texte.replace("Z", "+00:00"))
    except ValueError as e:
        raise SystemExit(f"usage : --now attend un ISO 8601 ({e.__class__.__name__})")
    if ts.tzinfo is None:
        raise SystemExit("usage : --now doit porter un fuseau (ex. +00:00)")
    return ts


def _charge_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SystemExit("fichier non JSON (contenu non affiché)")


def _verdict_str(v: Verdict) -> str:
    return str(v)


def mode_fixtures(dossier: Path, now: datetime | None) -> int:
    """Joue chaque fixture : le verdiit attendu est écrit dans le fichier."""
    total = ok = 0
    echecs: list[str] = []
    paths = sorted(dossier.glob("security-history-timeline-*.json"))
    if not paths:
        print(f"NON ÉVALUÉ — aucune fixture dans {dossier}")
        return 77
    for path in paths:
        total += 1
        enveloppe = _charge_json(path)
        if not isinstance(enveloppe, dict) or \
                not str(enveloppe.get("_marker", "")).startswith("TEST ONLY"):
            print(f"  ÉCHEC  fixture non marquée TEST ONLY : {path.name}")
            echecs.append(path.name)
            continue
        attendu = enveloppe.get("expect") or {}
        verdict_attendu = attendu.get("verdict")
        codes_attendus = set(attendu.get("codes") or [])
        horloge = _horloge(str(enveloppe.get("now") or "")) or now
        v = valider_projection(enveloppe.get("response"),
                               horloge=horloge)
        if verdict_attendu == "PASS" and v.ok:
            ok += 1
            print(f"  OK    {path.name} — PASS")
        elif verdict_attendu == "FAIL" and not v.ok:
            manques = codes_attendus - v.codes
            if not manques:
                ok += 1
                print(f"  OK    {path.name} — FAIL attendu "
                      f"({', '.join(sorted(v.codes))})")
            else:
                echecs.append(path.name)
                print(f"  ÉCHEC {path.name} — attendu {sorted(codes_attendus)}, "
                      f"obtenu {sorted(v.codes)}")
        else:
            echecs.append(path.name)
            print(f"  ÉCHEC {path.name} — verdict attendu {verdict_attendu}, "
                  f"obtenu {'PASS' if v.ok else 'FAIL'}")
    print(f"\n{ok}/{total} fixtures conformes au verdict attendu")
    return 0 if not echecs else 2


def mode_reponse(path: Path, now: datetime | None) -> int:
    data = _charge_json(path)
    if isinstance(data, dict) and "_marker" in data:
        print("usage : ce fichier est une enveloppe de fixture (--fixture-mode)")
        return 1
    v = valider_projection(data, horloge=now)
    print(_verdict_str(v))
    return 0 if v.ok else 2


def _get(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as rep:
            corps = rep.read()
            return json.loads(corps.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise SystemExit(f"API HTTP {e.code} (corps non affiché)")
    except urllib.error.URLError:
        raise SystemExit("API injoignable (détail réseau non affiché)")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SystemExit("API : corps non JSON (contenu non affiché)")


def mode_api(base: str, mission_id: str | None, now: datetime | None) -> int:
    base = base.rstrip("/")
    pire = 0
    liste = _get(f"{base}/api/missions")
    if mission_id:
        cibles = [mission_id]
    else:
        if isinstance(liste, dict) and isinstance(liste.get("data"), list):
            cibles = [it.get("mission_id") for it in liste["data"]
                      if isinstance(it, dict) and it.get("mission_id")]
        else:
            raise SystemExit("GET /api/missions : forme inattendue (corps non "
                             "affiché)")
    v = valider_projection(liste, horloge=now)
    print("GET /api/missions →", _verdict_str(v))
    pire = max(pire, 0 if v.ok else 2)
    for cible in cibles:
        detail = _get(f"{base}/api/missions/{cible}")
        v = valider_projection(detail, horloge=now)
        print(f"GET /api/missions/{cible} →", _verdict_str(v))
        pire = max(pire, 0 if v.ok else 2)
    return pire


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Gate de sécurité des projections History/Timeline/Status")
    ap.add_argument("--fixture-mode", metavar="REP", type=Path,
                    help="joue les fixtures marquées TEST ONLY de ce répertoire")
    ap.add_argument("--response-file", metavar="F", type=Path,
                    help="valide une réponse JSON capturée (sans enveloppe)")
    ap.add_argument("--base-url", metavar="URL",
                    help="valide GET /api/missions puis chaque détail")
    ap.add_argument("--mission-id", help="restreint l'appel au détail de cette mission")
    ap.add_argument("--now", help="horloge de référence (ISO 8601 + fuseau), "
                                  "pour un verdict rejouable")
    args = ap.parse_args(argv)
    now = _horloge(args.now)
    modes = [bool(args.fixture_mode), bool(args.response_file), bool(args.base_url)]
    if sum(modes) != 1:
        ap.print_usage()
        print("usage : exactement un mode parmi --fixture-mode, --response-file, "
              "--base-url")
        return 1
    if args.fixture_mode:
        if not args.fixture_mode.is_dir():
            print(f"usage : {args.fixture_mode} n'est pas un répertoire")
            return 1
        return mode_fixtures(args.fixture_mode, now)
    if args.response_file:
        if not args.response_file.is_file():
            print("usage : fichier de réponse introuvable")
            return 1
        return mode_reponse(args.response_file, now)
    return mode_api(args.base_url or "", args.mission_id, now)


if __name__ == "__main__":
    sys.exit(main())
