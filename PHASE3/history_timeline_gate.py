#!/usr/bin/env python3
"""Gate SECURITY des projections History / Timeline / Execution Status (P1,
re-lié aux contrats Product réels le 2026-08-30).

Rôle
----
`docs/coordination/api-conformance-gate/product_api_gate.py` (Product) juge la
CONFORMITÉ : schéma, types, enums, ordre, preuves. Ce module juge
l'EXPOSITION : il ne réécrit ni ne remplace le contrôle Product — il ajoute ce
que le contrôle Product ne couvre pas ou ne couvre qu'en déclaration :

1. **Contenu** — secrets (Bearer, clés API/GitHub/AWS/GitLab/Google/Slack,
   JWT, clé privée, URL userinfo/token, Authorization, cookie/session, variable
   d'environnement, affectation de credential), chemins locaux (accueil,
   absolus, Windows, traversée, montages sandbox, caches, `PHASE3/`,
   `raw_*`/`brut_*`), extraits de commande, traces de pile, HTML actif, URL
   brute. Le Product gate couvre une partie (Bearer/JWT/clé privée/chemins
   absolus/markup simple) ; Security balaie TOUT le document avec un
   vocabulaire plus large.
2. **Fail-closed** — faux zéros, artefacts manquants transformés en comptes,
   contradictions résolues vers l'état le plus rassurant, état inconnu sans
   marqueur, timeline partielle non déclarée, événement inconnu non générique.
3. **Extensions** — dans les emplacements où le contrat Product est STRICT
   (`additionalProperties: false`), une clé non approuvée est un REFUS
   (`cle-inconnue`) ; dans les emplacements EXTENSIBLES (`summary`, `data`),
   les clés inconnues sont tolérées mais balayées, et les clés INTERDITES
   restent refusées partout (`cle-interdite`).
4. **Vocabulaires MCP** — allowlist TEMPORAIRE (transport / protocol.name) :
   une valeur inconnue est refusée jusqu'à confirmation MCP, jamais convertie.

Lois de construction (vérifiées par le harnais) :
* aucun lecteur de Mission (stdlib seule, aucune lecture du workspace) ;
* aucun assainissement (l'entrée n'est pas modifiée ; verdict = ok + raisons) ;
* aucun contenu fautif dans les messages (chemin JSON + code + explication).

Contrat Product — propriété de Product/UX. Ce module ne les copie pas : il
reflète en constantes les vocabulaires documentés par les schémas versionnés
(`agnt.history.v1`, `agnt.timeline.v1`, `agnt.execution-status.v1`). Toute
divergence entre ces constantes et les schémas Product est signalée par le
harnais comme un point de re-bind, pas contournée.

Usage :
    python3 PHASE3/history_timeline_gate.py --fixture-mode docs/coordination/fixtures
    python3 PHASE3/history_timeline_gate.py --response-file reponse.json
    python3 PHASE3/history_timeline_gate.py --base-url http://127.0.0.1:8141
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
# Vocabulaires Product (miroir des schémas versionnés — ne pas redéfinir seul)
# ══════════════════════════════════════════════════════════════════════════

HISTORY = "agnt.history.v1"
TIMELINE = "agnt.timeline.v1"
EXECUTION = "agnt.execution-status.v1"

STATUTS_MISSION = ("en_file", "en_cours", "termine", "refuse", "erreur",
                   "inconnu")
# Statuts mission : vocabulaire Product ; `termine`, `en_cours` et `inconnu`
# sont PARTAGÉS avec execution.value par le contrat lui-même. Une valeur issue
# d'une autre couche SANS partage légitime (ex. `disponible`, `echoue`,
# `findings_presents`) reste refusée.
MISSION_AVEC_RUN = ("termine",)

APPLICABILITE = ("applicable", "non_applicable", "inconnu")
SELECTION = ("selectionne", "non_selectionne", "inconnu")
CONDITION = ("remplie", "bloquee", "inconnu")
AUTORISATION = ("autorise", "non_autorise", "non_evalue", "inconnu")
DISPONIBILITE_OUTIL = ("disponible", "indisponible", "inconnu")
EXECUTION_RESULTAT = ("non_lance", "en_cours", "termine", "echoue",
                      "timed_out", "cancelled", "unavailable", "inconnu")
DETECTION = ("findings_presents", "rien_trouve", "non_evalue", "inconnu")
PREUVES = ("recorded", "derived", "provider_reported", "unknown")
COMPLETUDE = ("complete", "partial", "unavailable", "conflict")
INVOCATION = ("oui", "non", "inconnu")
SORTIE = ("exploitable", "partiel", "non_exploitable", "inconnu")

ETATS_TIMELINE = ("complete", "partial", "unavailable")
CATEGORIES_EVENEMENT = ("mission", "intent", "plan", "policy", "execution",
                        "coverage", "correlation", "report", "security",
                        "system", "unknown")
CONSEQUENCES = ("recorded", "started", "progress", "completed", "succeeded",
                "refused", "failed", "skipped", "unavailable", "unknown")
VISIBILITES = ("summary", "mission", "technical")
ETATS_DONNEES = ("complete", "partial", "redacted", "unavailable")
LIMITATIONS_TIMELINE = ("journal_missing", "journal_unreadable",
                        "history_prefix_missing", "history_gap_detected",
                        "timestamp_missing", "payload_redacted",
                        "provenance_partial", "projection_version_unsupported")
ARTEFACTS_MANQUANTS = ("run", "plan", "intent", "findings", "clusters",
                       "report", "coverage", "events")

PROVIDER_KINDS = ("local", "mcp", "external")
CONFIDENCES_LEVELS = ("low", "medium", "high", "unknown")
CONFIDENCES_BASIS = ("provider_declared", "agnt_assessed", "corroborated",
                     "unknown")
DISPONIBILITE_PROVENANCE = ("available", "degraded", "unavailable", "unknown")
CONTRIBUTEURS = ("local", "mcp", "external")

STATUTS_ETRANGERS = (set(DISPONIBILITE_OUTIL) | set(DETECTION) |
                     set(CONFIDENCES_LEVELS) | set(EXECUTION_RESULTAT)) - \
                    set(STATUTS_MISSION)

# Vocabulaires MCP NON stabilisés — allowlist TEMPORAIRE, confirmée par MCP
# avant exposition. Une valeur inconnue = refus (`transport-inconnu`,
# `protocol-inconnu`) ; jamais une conversion vers une valeur valide.
TRANSPORTS = ("stdio", "sse", "websocket", "http", "grpc", "inconnu")
PROTOCOLES = ("mcp", "jsonrpc", "http", "https", "grpc", "inconnu")

# ══════════════════════════════════════════════════════════════════════════
# Schéma des clés. STRICT = miroir des `additionalProperties: false` Product ;
# EXTENSIBLE = miroir des objets à `additionalProperties: true` (summary,
# data, target, provider legacy, findings) : clés inconnues UNIQUEMENT si leur
# contenu passe le balayage et qu'elles ne sont pas interdites.
# ══════════════════════════════════════════════════════════════════════════

CLES_LISTE = {"schema_version", "items", "page", "$fixture"}
CLES_DETAIL = {"schema_version", "mission", "data", "missing_artifacts",
               "$fixture"}
CLES_PAGE = {"limit", "next_cursor"}
CLES_ARTEFACTS = {"detail", "findings", "clusters", "report"}
CLES_RESUME_FIN = {"total", "by_severity"}
CLES_CONTRIBUTEURS = {"count", "kinds"}
CLES_REQUETE = {"title"}
CLES_EVENEMENT_LEGACY = {"sequence", "timestamp", "kind", "status",
                         "capability", "provider", "safe_message"}
CLES_TIMELINE = {"schema_version", "state", "ordering", "events",
                 "returned_events", "total_events", "truncated", "next_cursor",
                 "limitations", "$fixture"}
CLES_EVENEMENT = {"event_id", "position", "source", "time", "category",
                  "kind", "consequence", "visibility", "safe_summary",
                  "references", "provenance", "data_state", "limitations"}
CLES_SOURCE = {"kind", "sequence", "source_kind"}
CLES_TEMPS = {"state", "timestamp"}
CLES_REFERENCES = {"mission_id", "run_id", "plan_id", "provider_id",
                   "finding_ids", "cluster_ids"}
CLES_PROVENANCE = {"provider_id", "provider_kind", "transport", "server_id",
                   "tool_id", "protocol", "confidence", "availability",
                   "request_id", "correlation_id"}
CLES_PROTOCOL = {"name", "version"}
CLES_CONFIDENCE = {"level", "basis"}
CLES_EXECUTION_V1 = {"schema_version", "provider_id", "capability_id",
                     "display_name", "applicability", "selection",
                     "condition", "authorization", "availability",
                     "execution", "detection", "completeness", "provenance"}
CLES_DIMENSION = {"value", "proof", "reason_code"}
CLES_EXECUTION_DIM = {"value", "invocation", "output", "proof", "reason_code"}
CLES_DETECTION_DIM = {"value", "findings_count", "analyzed_targets", "proof",
                      "reason_code"}
CLES_COMPLETUDE = {"state", "missing", "limitations"}
CLES_EXEC_LEGACY = {"provider_id", "capability_id", "display_name",
                    "capability", "status", "findings_count", "provenance",
                    "execution_status_schema", "schema_version"}
CLES_MISSING_ARTIFACTS = {"run", "plan", "intent", "findings", "clusters",
                          "report", "coverage", "events"}

# Clés INTERDITES — union Security (plus large que le product gate) : leur
# présence, même vide, est un refus, dans TOUS les emplacements (y compris
# les objets extensibles). `file`/`location` restent autorisés : les locations
# RELATIVES de findings font partie du contrat Product. Les clés ambigües
# (`path`, `url`…) ne sont pas interdites en tant que clés : leurs VALEURS
# sont balayées par la passe de contenu.
CLES_INTERDITES = {
    "argv", "command", "cmd", "commands", "env", "environ", "environment",
    "executable", "exe", "cwd", "chdir", "mount", "mounts",
    "shell", "stdout", "stderr", "traceback", "stack", "stack_trace",
    "backtrace", "exception_detail", "headers", "header",
    "authorization_header", "cookie", "cookies", "session", "set_cookie",
    "token", "access_token", "refresh_token", "api_key", "apikey",
    "secret", "secrets", "password", "passwd", "pwd", "private_key",
    "credential", "credentials", "payload", "body", "raw",
    "raw_output", "raw_response", "raw_payload", "raw_request", "brut",
    "brut_output", "brut_response", "download_url", "artifact_url",
    "endpoint", "server_url", "socket", "file_path",
    "local_path", "absolute_path", "storage_path", "sandbox_path", "sandbox",
    "filesystem", "inode", "mtime", "mode", "worktree", "home_dir",
    "tmp_dir", "cache_dir", "cache_path", "git_dir", "repo_path",
    "reponse_brute", "erreur_brute", "erreur_distante", "detail_technique",
    "dumps",
}

# ══════════════════════════════════════════════════════════════════════════
# Contenu : une passe unique sur TOUTES les chaînes de la projection.
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
     re.compile(r"\b(?:sk|pk|rk|ak)[-_][A-Za-z0-9_-]{16,}\b"),
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
     re.compile(r"(?i)(?:cookie|set-cookie|session)\s*[:=]\s*[^;=\s\"']+="),
     "cookie / session détecté"),
    ("secret-variable-env",
     re.compile(r"(?i)\b[A-Z][A-Z0-9_]*(?:_(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL|COOKIE|SESSION|API[_-]?KEY))\s*=\s*\S+"),
     "variable d'environnement sensible détectée"),
    ("secret-affectation",
     re.compile(r"(?i)\b(?:token|access_token|api[_-]?key|secret|password|passwd|client[_-]?secret|session[_-]?id)\s*[:=]\s*[\"']?[^\s\"',}\]]{8,}"),
     "affectation de credential détectée"),
    ("chemin-home",
     re.compile(r"(?:^|[/\\])(?:home|Users|root)[/\\][^\s\"'\\]+"),
     "chemin d'accueil utilisateur détecté"),
    ("chemin-absolu",
     re.compile(r"/(?:tmp|var|etc|opt|usr|bin|srv|mnt|proc|sys|run|dev)/[A-Za-z0-9._+~-]+(?:/[A-Za-z0-9._+~-]+)*"),
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
     re.compile(r"(?i)(?:--config=|--report-path=|--no-banner|gitleaks git|semgrep |--format(?:\s*=|$|\s))"),
     "extrait de ligne de commande détecté"),
    ("fichier-cache",
     re.compile(r"(?:\.cache[/\\]|\.venv[/\\]|node_modules[/\\])(?:[^\s\"']*)"),
     "chemin de cache local détecté"),
    ("stack-trace",
     re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+"),
     "trace de pile détectée"),
    ("html-executable",
     re.compile(r"(?i)<\s*(?:script|iframe|object|embed|form|svg|link|img|meta|a)\b|javascript:|(?<![\w-])on\w+\s*=|data:text/html"),
     "contenu HTML/script exécutable détecté"),
    ("endpoint-url",
     re.compile(r"\bhttps?://\S+"),
     "URL brute détectée"),
)

_ID_MISSION = re.compile(r"^m-[A-Za-z0-9-]+$")
_ID_DETAIL_HREF = re.compile(r"^/api/missions/m-[A-Za-z0-9-]+$")
_ID_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ID_RAISON = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_ID_EVENT = re.compile(r"^m-[A-Za-z0-9-]+:[1-9][0-9]*$")
_ID_SOURCE_KIND = re.compile(r"^[a-z0-9_.-]{1,64}$")
_ID_VASTE = re.compile(r"^[^\s\"'`]{1,160}$")
_MARQUEUR_FIXTURE = "TEST ONLY — NEVER SERVE AS PRODUCT DATA"
_MARQUEUR_PRODUIT = "NEVER SERVE AS PRODUCT DATA"


# ══════════════════════════════════════════════════════════════════════════
# Verdict — générique par construction
# ══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Raison:
    chemin: str
    code: str
    message: str

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


# ══════════════════════════════════════════════════════════════════════════
# Validateur
# ══════════════════════════════════════════════════════════════════════════

class _Juge:
    def __init__(self, horloge: datetime | None,
                 autoriser_marqueur_fixture: bool = False) -> None:
        self.raisons: list[Raison] = []
        self.horloge = horloge or datetime.now(timezone.utc)
        self.autoriser_marqueur_fixture = autoriser_marqueur_fixture
        # Vue interne (PRIVÉE) : ne sort jamais ; sert uniquement aux règles.
        self.mission_status: str | None = None
        self.mission_id: str | None = None
        self.created_at: datetime | None = None
        self.artefacts_findings: bool | None = None
        self.total_findings: int | None = None
        self.run_id: str | None = None
        self.incomplete: bool | None = None
        self.executions: list[dict[str, Any]] = []
        self.timeline: dict[str, Any] | None = None
        self.events_legacy: list[dict[str, Any]] = []

    # ── primitives ────────────────────────────────────────────────────────
    def refus(self, chemin: str, code: str, message: str) -> None:
        self.raisons.append(Raison(chemin, code, message))

    def _clés(self, obj: dict, chemin: str, autorisées: set[str]) -> None:
        # Clés interdites : balayées une fois pour toute la projection
        # (`_interdits`) ; ici on ne juge que les clés inconnues des objets
        # STRICTS du contrat.
        for k in obj:
            if k not in autorisées and k not in CLES_INTERDITES:
                self.refus(f"{chemin}.{k}", "cle-inconnue",
                           "clé hors contrat Product validé : extension non "
                           "approuvée par Security")

    def _interdits(self, valeur: Any, chemin: str) -> None:
        if isinstance(valeur, dict):
            for k, v in valeur.items():
                if k in CLES_INTERDITES:
                    self.refus(f"{chemin}.{k}", "cle-interdite",
                               "clé interdite présente : son contenu ne doit "
                               "jamais atteindre le navigateur")
                self._interdits(v, f"{chemin}.{k}")
        elif isinstance(valeur, list):
            for i, v in enumerate(valeur):
                self._interdits(v, f"{chemin}[{i}]")

    def _valeurs(self, valeur: Any, chemin: str) -> None:
        if isinstance(valeur, str):
            for code, motif, libelle in _CONTENUS:
                if motif.search(valeur):
                    self.refus(chemin, code, libelle)
        elif isinstance(valeur, list):
            for i, v in enumerate(valeur):
                self._valeurs(v, f"{chemin}[{i}]")
        elif isinstance(valeur, dict):
            for k, v in valeur.items():
                self._valeurs(v, f"{chemin}.{k}")

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

    def _chaîne(self, obj: Any, chemin: str, motif: re.Pattern[str],
                code_invalide: str = "valeur-invalide") -> str | None:
        if obj is None:
            self.refus(chemin, "champ-obligatoire",
                       "champ obligatoire absent")
            return None
        if not isinstance(obj, str):
            self.refus(chemin, "type-invalide", "chaîne attendue")
            return None
        if not motif.match(obj):
            self.refus(chemin, code_invalide,
                       "format incompatible avec le contrat Product")
            return None
        return obj

    def _bool(self, obj: Any, chemin: str) -> bool | None:
        if not isinstance(obj, bool):
            self.refus(chemin, "type-invalide", "booléen attendu")
            return None
        return obj

    def _iso(self, valeur: Any, chemin: str, obligatoire: bool) -> datetime | None:
        if valeur is None:
            if obligatoire:
                self.refus(chemin, "ts-absent", "horodatage obligatoire absent")
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

    def _entier(self, valeur: Any, chemin: str, minimum: int | None = None,
                obligatoire: bool = True) -> int | None:
        if valeur is None:
            if obligatoire:
                self.refus(chemin, "compteur-invalide",
                           "compteur obligatoire absent (null n'est pas un "
                           "compteur)")
            return None
        if isinstance(valeur, bool) or not isinstance(valeur, int):
            self.refus(chemin, "compteur-invalide",
                       "entier attendu (booléen déguisé refusé)")
            return None
        if minimum is not None and valeur < minimum:
            self.refus(chemin, "compteur-negatif",
                       "valeur sous le minimum autorisé")
            return None
        return valeur

    # ── entrée ────────────────────────────────────────────────────────────
    def analyser(self, projection: dict[str, Any]) -> Verdict:
        racine = "projection"
        if not self._est_dict(projection, racine):
            return _refuse(Raison(racine, "forme-invalide",
                                  "la projection doit être un objet JSON"))
        # Marqueur de fixture dans une réponse censée être une API ?
        if "$fixture" in projection and not self.autoriser_marqueur_fixture:
            self.refus(f"{racine}.$fixture", "marqueur-fixture",
                       "marqueur de données de test exposé par une API")
        # UNE passe de contenu + UNE passe de clés interdites sur tout le doc.
        self._valeurs(projection, racine)
        self._interdits(projection, racine)

        version = projection.get("schema_version")
        if version is None:
            self.refus(f"{racine}.schema_version", "champ-obligatoire",
                       "le contrat versionné est obligatoire")
            return Verdict(not self.raisons, tuple(self.raisons))
        if not isinstance(version, str) or version not in (HISTORY, TIMELINE,
                                                           EXECUTION):
            self.refus(f"{racine}.schema_version", "schema-inconnu",
                       "contrat hors des versions validées par Security")
            return Verdict(not self.raisons, tuple(self.raisons))

        if version == HISTORY:
            if "items" in projection and "mission" not in projection:
                self._liste(projection, racine)
            elif "mission" in projection and "data" in projection:
                self._detail(projection, racine)
            else:
                self.refus(racine, "forme-inconnue",
                           "forme history ni liste ni détail : impossible de "
                           "situer les données")
        elif version == TIMELINE:
            self._timeline_seule(projection, racine)
        else:
            self._execution_cases(projection, racine)
        return Verdict(not self.raisons, tuple(self.raisons))

    # ── MissionSummary (liste ET détail) ──────────────────────────────────
    def _summary(self, item: dict[str, Any], chemin: str,
                 exigences: set[str]) -> None:
        # `summary` est EXTENSIBLE dans le contrat Product : on vérifie les
        # champs obligatoires, sans rejeter les extensions (les clés
        # interdites sont balayées globalement par `_interdits`).
        for k in exigences:
            if k not in item:
                self.refus(f"{chemin}.{k}", "champ-obligatoire",
                           "champ de résumé obligatoire absent")

        mid = self._chaîne(item.get("mission_id"), f"{chemin}.mission_id",
                           _ID_MISSION)
        href = self._chaîne(item.get("detail_href"), f"{chemin}.detail_href",
                            _ID_DETAIL_HREF)
        if mid is not None and href is not None and \
                href != f"/api/missions/{mid}":
            self.refus(f"{chemin}.detail_href", "detail-href-incoherent",
                       "le lien de détail ne correspond pas à l'identifiant "
                       "de mission")

        # identité : aucun id de soumission ne se fait passer pour une mission
        if item.get("id") == mid or "submission_id" in item:
            self.refus(f"{chemin}.id", "identite-confondue",
                       "identifiant de soumission présenté comme identifiant "
                       "persistant")

        requete = item.get("request")
        if self._est_dict(requete, f"{chemin}.request"):
            self._clés(requete, f"{chemin}.request", CLES_REQUETE)
            titre = requete.get("title")
            if titre is not None:
                if not isinstance(titre, str) or not 0 < len(titre) <= 240:
                    self.refus(f"{chemin}.request.title", "valeur-invalide",
                               "titre de requête hors bornes")
                elif any(ord(c) < 0x20 for c in titre):
                    self.refus(f"{chemin}.request.title", "controle-interdit",
                               "caractère de contrôle dans un champ public")

        cible = item.get("target")
        if self._est_dict(cible, f"{chemin}.target"):
            self._chaîne(cible.get("type"), f"{chemin}.target.type",
                         _ID_VASTE, "valeur-invalide")
            self._chaîne(cible.get("display_name"),
                         f"{chemin}.target.display_name", _ID_VASTE,
                         "valeur-invalide")

        statut = self._chaîne(item.get("status"), f"{chemin}.status",
                              re.compile(r"^[a-z_]+$"))
        if statut is not None:
            if statut in STATUTS_ETRANGERS:
                self.refus(f"{chemin}.status", "vocabulaire-confondu",
                           "statut de mission porteur d'un état d'une autre "
                           "couche sans partage légitime")
            elif statut not in STATUTS_MISSION:
                self.refus(f"{chemin}.status", "statut-inconnu",
                           "statut hors vocabulaire canonique : aucune "
                           "conversion d'une valeur inconnue")

        self._iso(item.get("created_at"), f"{chemin}.created_at",
                  obligatoire="created_at" in exigences)
        self._iso(item.get("updated_at"), f"{chemin}.updated_at",
                  obligatoire="updated_at" in exigences)
        self._iso(item.get("started_at"), f"{chemin}.started_at",
                  obligatoire=False)
        self._iso(item.get("completed_at"), f"{chemin}.completed_at",
                  obligatoire=False)
        self._entier(item.get("duration_ms"), f"{chemin}.duration_ms",
                     minimum=0, obligatoire=False)

        artefacts = item.get("artifacts")
        if self._est_dict(artefacts, f"{chemin}.artifacts"):
            self._clés(artefacts, f"{chemin}.artifacts", CLES_ARTEFACTS)
            for k in CLES_ARTEFACTS:
                self._bool(artefacts.get(k), f"{chemin}.artifacts.{k}")
        fs = item.get("findings_summary")
        if fs is not None:
            if self._est_dict(fs, f"{chemin}.findings_summary"):
                self._clés(fs, f"{chemin}.findings_summary",
                           CLES_RESUME_FIN)
                total = self._entier(fs.get("total"),
                                     f"{chemin}.findings_summary.total",
                                     minimum=0)
                par = fs.get("by_severity")
                if self._est_dict(par, f"{chemin}.findings_summary.by_severity"):
                    somme = 0
                    for sev, n in par.items():
                        v = self._entier(n, f"{chemin}.findings_summary.by_severity.{sev}",
                                         minimum=0)
                        somme += v or 0
                    if total is not None and somme != total:
                        self.refus(f"{chemin}.findings_summary",
                                   "compteur-contradictoire",
                                   "la somme par sévérité contredit le total")
            if not isinstance(artefacts, dict) or \
                    artefacts.get("findings") is not True:
                self.refus(f"{chemin}.findings_summary", "compteur-sans-artefact",
                           "un compteur de findings exige un artefact lisible "
                           "déclaré — jamais un zéro par défaut")
        contrib = item.get("contributors")
        if contrib is not None:
            if self._est_dict(contrib, f"{chemin}.contributors"):
                self._clés(contrib, f"{chemin}.contributors",
                           CLES_CONTRIBUTEURS)
                self._entier(contrib.get("count"),
                             f"{chemin}.contributors.count", minimum=0)
                kinds = contrib.get("kinds")
                if self._est_liste(kinds, f"{chemin}.contributors.kinds"):
                    for i, k in enumerate(kinds):
                        if k not in CONTRIBUTEURS:
                            self.refus(f"{chemin}.contributors.kinds[{i}]",
                                       "valeur-inconnue",
                                       "catégorie de contributeur hors "
                                       "vocabulaire")

        self._entier(item.get("clusters_count"), f"{chemin}.clusters_count",
                     minimum=0, obligatoire=False)
        rid = item.get("run_id")
        if rid is not None:
            self._chaîne(rid, f"{chemin}.run_id", _ID_SAFE,
                         "valeur-invalide")
        incomplet = item.get("incomplete")
        if incomplet is not None:
            self._bool(incomplet, f"{chemin}.incomplete")
        raison = item.get("incomplete_reason")
        if raison is not None:
            if not isinstance(raison, str) or not 0 < len(raison) <= 240 or \
                    "\n" in raison or "\r" in raison:
                self.refus(f"{chemin}.incomplete_reason", "valeur-invalide",
                           "motif d'incomplétude hors bornes ou multi-ligne")

        # Vue interne
        if mid is not None and self.mission_id is None:
            self.mission_id = mid
        if statut is not None and self.mission_status is None:
            self.mission_status = statut
        if isinstance(artefacts, dict):
            self.artefacts_findings = artefacts.get("findings")
        if isinstance(fs, dict) and isinstance(fs.get("total"), int):
            self.total_findings = fs["total"]
        if isinstance(rid, str):
            self.run_id = rid
        if isinstance(incomplet, bool):
            self.incomplete = incomplet
        if isinstance(item.get("created_at"), str):
            self.created_at = self._iso(item["created_at"],
                                        f"{chemin}.created_at",
                                        obligatoire=False)

    # ── Liste ─────────────────────────────────────────────────────────────
    def _liste(self, body: dict[str, Any], chemin: str) -> None:
        self._clés(body, chemin, CLES_LISTE)
        items = body.get("items")
        if not self._est_liste(items, f"{chemin}.items"):
            return
        page = body.get("page")
        if self._est_dict(page, f"{chemin}.page"):
            self._clés(page, f"{chemin}.page", CLES_PAGE)
            self._entier(page.get("limit"), f"{chemin}.page.limit",
                         minimum=1)
            cur = page.get("next_cursor")
            if cur is not None and not isinstance(cur, str):
                self.refus(f"{chemin}.page.next_cursor", "type-invalide",
                           "curseur opaque textuel ou null attendu")
        ids: set[str] = set()
        for i, item in enumerate(items):
            p = f"{chemin}.items[{i}]"
            if self._est_dict(item, p):
                self._summary(item, p,
                              {"mission_id", "detail_href", "request",
                               "target", "status", "created_at", "updated_at",
                               "artifacts"})
                mid = item.get("mission_id")
                if isinstance(mid, str):
                    if mid in ids:
                        self.refus(f"{p}.mission_id", "mission-dupliquee",
                                   "identifiant de mission répété dans la liste")
                    ids.add(mid)
        # ordre stable : created_at DESC, mission_id DESC (Product §5)
        cle = []
        for item in items:
            if not isinstance(item, dict):
                continue
            mid = item.get("mission_id")
            if not isinstance(mid, str):
                continue
            try:
                ts = datetime.fromisoformat(
                    str(item.get("created_at", "")).replace("Z", "+00:00"))
            except ValueError:
                continue
            if ts.tzinfo is None:
                continue
            cle.append((ts.astimezone(timezone.utc), mid))
        if len({c for c in cle}) == len(cle) and cle != sorted(cle, reverse=True):
            self.refus(f"{chemin}.items", "ordre-instable",
                       "ordre de la liste non conforme (created_at DESC puis "
                       "mission_id DESC)")

    # ── Détail ────────────────────────────────────────────────────────────
    def _detail(self, body: dict[str, Any], chemin: str) -> None:
        self._clés(body, chemin, CLES_DETAIL)
        mission = body.get("mission")
        if not self._est_dict(mission, f"{chemin}.mission"):
            return
        self._summary(mission, f"{chemin}.mission",
                      {"mission_id", "detail_href", "request", "target",
                       "status", "created_at", "updated_at", "artifacts"})
        self._regles_mission(chemin)
        data = body.get("data")
        if not self._est_dict(data, f"{chemin}.data"):
            return
        # data est EXTENSIBLE (contrat Product) : validé par emplacement
        # connu, clés interdites balayées globalement par `_interdits`.
        missing = body.get("missing_artifacts")
        if missing is not None:
            self._est_liste(missing, f"{chemin}.missing_artifacts")
            if isinstance(missing, list):
                if len(missing) != len(set(missing)):
                    self.refus(f"{chemin}.missing_artifacts",
                               "artefact-duplique",
                               "nom d'artefact manquant répété")
                for i, a in enumerate(missing):
                    if a not in ARTEFACTS_MANQUANTS:
                        self.refus(f"{chemin}.missing_artifacts[{i}]",
                                   "artefact-inconnu",
                                   "nom d'artefact hors liste logique admise")
                if "findings" in missing and \
                        isinstance(mission, dict) and \
                        "findings_summary" in mission:
                    self.refus(f"{chemin}.missing_artifacts",
                               "compteur-sans-artefact",
                               "findings annoncé manquant mais compté dans le "
                               "résumé")
                if "findings" in missing and isinstance(data, dict) and \
                        "findings" in data:
                    self.refus(f"{chemin}.missing_artifacts",
                               "artefact-contredit",
                               "artefact manquant mais présent dans data")
        # report : le contenu est balayé ; la disponibilité doit être factuelle
        report = data.get("report")
        if isinstance(report, dict) and report.get("available") is True and \
                not isinstance(report.get("content"), str):
            self.refus(f"{chemin}.data.report", "type-invalide",
                       "un rapport disponible doit porter un contenu textuel "
                       "ou l'omettre")
        # événements legacy (projection minimale optionnelle)
        if "events" in data:
            if isinstance(data["events"], dict) and \
                    data["events"].get("schema_version") == TIMELINE:
                self._timeline(data["events"], f"{chemin}.data.events")
            else:
                self._events_legacy(data["events"], f"{chemin}.data.events")
        if "timeline" in data:
            self._timeline(data["timeline"], f"{chemin}.data.timeline")
        if "executions" in data:
            self._executions(data["executions"], f"{chemin}.data.executions")
        self._regles_compteurs(chemin, data)
        self._regles_preuves(chemin, data)

    def _regles_mission(self, chemin: str) -> None:
        st = self.mission_status
        if st == "inconnu" and self.incomplete is not True:
            self.refus(f"{chemin}.mission.incomplete", "inconnu-sans-incomplete",
                       "état inconnu sans marqueur d'incomplétude : une "
                       "absence de preuve ne devient pas un état neutre")
        if st is not None and st != "inconnu" and self.incomplete is True:
            self.refus(f"{chemin}.mission.incomplete",
                       "incomplet-sous-statut",
                       "mission marquée incomplète sous un statut prouvé : "
                       "les deux états se contredisent")
        if st in MISSION_AVEC_RUN and not self.run_id:
            self.refus(f"{chemin}.mission.run_id", "mission-sans-run",
                       "exécution terminée sans identifiant de run : résultat "
                       "invérifiable")
        if self.total_findings == 0 and self.artefacts_findings is not True:
            self.refus(f"{chemin}.mission.findings_summary",
                       "zero-sans-artefact",
                       "compteur zéro sans artefact de findings lisible déclaré")

    def _regles_preuves(self, chemin: str, data: dict[str, Any]) -> None:
        # Une mission prouvée terminée doit porter au moins une des deux
        # preuves du contrat trois-contrats : timeline ou exécutions.
        if self.mission_status == "termine" and \
                "timeline" not in data and "executions" not in data:
            self.refus(f"{chemin}.data", "preuves-absentes",
                       "mission terminée sans timeline ni exécutions : aucun "
                       "élément de preuve exposé")

    def _regles_compteurs(self, chemin: str, data: dict[str, Any]) -> None:
        if self.total_findings != 0:
            return
        for ex in self.executions:
            det = ex.get("detection_value")
            count = ex.get("findings_count")
            if det == "findings_presents" and isinstance(count, int) and count > 0:
                self.refus(f"{chemin}.data.executions", "compteur-contradictoire",
                           "des providers déclarent des findings alors que la "
                           "mission compte zéro")

    def _events_legacy(self, events: Any, chemin: str) -> None:
        if not self._est_liste(events, chemin):
            return
        seqs: set[int] = set()
        for i, ev in enumerate(events):
            p = f"{chemin}[{i}]"
            if not self._est_dict(ev, p):
                continue
            self._clés(ev, p, CLES_EVENEMENT_LEGACY)
            seq = ev.get("sequence")
            if seq is None:
                self.refus(f"{p}.sequence", "seq-manquant",
                           "séquence absente : l'ordre ne peut pas être établi")
            elif isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
                self.refus(f"{p}.sequence", "seq-non-numerique",
                           "séquence non entière positive : ordre impossible")
            else:
                if seq in seqs:
                    self.refus(f"{p}.sequence", "seq-duplique",
                               "séquence dupliquée : ordre ambigu")
                seqs.add(seq)
            self._iso(ev.get("timestamp"), f"{p}.timestamp",
                      obligatoire=False)
            kind = ev.get("kind")
            if not isinstance(kind, str) or not 0 < len(kind) <= 80:
                self.refus(f"{p}.kind", "valeur-invalide",
                           "type d'événement hors bornes")
            st = ev.get("status")
            if st is not None and (not isinstance(st, str) or
                                   len(st) > 80):
                self.refus(f"{p}.status", "valeur-invalide",
                           "statut d'événement hors bornes")
            cap = ev.get("capability")
            if cap is not None and (not isinstance(cap, str) or
                                    len(cap) > 160):
                self.refus(f"{p}.capability", "valeur-invalide",
                           "libellé de capacité hors bornes")
            prov = ev.get("provider")
            if prov is not None:
                if not self._est_dict(prov, f"{p}.provider"):
                    continue
            msg = ev.get("safe_message")
            if msg is not None:
                if not isinstance(msg, str) or len(msg) > 400 or "\n" in msg:
                    self.refus(f"{p}.safe_message", "controle-interdit",
                               "message sûr hors bornes ou multi-ligne")
            self.events_legacy.append({"sequence": seq})

    # ── Timeline v1 ───────────────────────────────────────────────────────
    def _timeline(self, tl: Any, chemin: str) -> None:
        if not self._est_dict(tl, chemin):
            return
        self._clés(tl, chemin, CLES_TIMELINE)
        etat = tl.get("state")
        if etat is not None and etat not in ETATS_TIMELINE:
            self.refus(f"{chemin}.state", "valeur-inconnue",
                       "état de timeline hors vocabulaire")
        if tl.get("ordering") != "journal_sequence_ascending":
            self.refus(f"{chemin}.ordering", "valeur-invalide",
                       "l'ordre de la timeline doit être la séquence du journal")
        events = tl.get("events")
        if not self._est_liste(events, f"{chemin}.events"):
            return
        retournes = tl.get("returned_events")
        if retournes != len(events):
            self.refus(f"{chemin}.returned_events", "compteur-invalide",
                       "le nombre d'événements retournés doit être factuel")
        total = tl.get("total_events")
        if total is not None and not (isinstance(total, int) and total >= 0):
            self.refus(f"{chemin}.total_events", "compteur-invalide",
                       "total d'événements hors bornes")
        tronque = tl.get("truncated")
        cur = tl.get("next_cursor")
        if not isinstance(tronque, bool):
            self.refus(f"{chemin}.truncated", "type-invalide",
                       "booléen attendu")
        elif tronque and cur is None:
            self.refus(f"{chemin}.next_cursor", "curseur-manquant",
                       "timeline tronquée sans curseur de continuation")
        elif not tronque and cur is not None:
            self.refus(f"{chemin}.next_cursor", "curseur-incoherent",
                       "curseur présent pour une timeline non tronquée")
        limites = tl.get("limitations")
        if not self._est_liste(limites, f"{chemin}.limitations"):
            limites = None
        elif limites:
            for i, code in enumerate(limites):
                if code not in LIMITATIONS_TIMELINE:
                    self.refus(f"{chemin}.limitations[{i}]",
                               "limitation-inconnue",
                               "code de limitation hors vocabulaire")
        limitations = set(limites or [])
        if etat == "unavailable" and events:
            self.refus(f"{chemin}.events", "timeline-incoherente",
                       "timeline indisponible avec des événements inventés")
        if etat == "unavailable" and not limitations:
            self.refus(f"{chemin}.limitations", "timeline-incoherente",
                       "timeline indisponible sans limitation déclarée")
        degradantes = {"journal_missing", "journal_unreadable",
                       "history_prefix_missing", "history_gap_detected"}
        if etat == "complete" and (limitations & degradantes):
            self.refus(f"{chemin}.limitations", "timeline-incoherente",
                       "timeline déclarée complète avec une limitation de "
                       "dégradation")
        if etat == "unavailable" and not (limitations & {"journal_missing",
                                                         "journal_unreadable"}):
            self.refus(f"{chemin}.limitations", "timeline-incoherente",
                       "timeline indisponible sans cause de journal déclarée")

        sequences: list[int] = []
        positions: list[int] = []
        ids: set[str] = set()
        mission_ref: str | None = None
        dernier_ts: datetime | None = None
        for i, ev in enumerate(events):
            p = f"{chemin}.events[{i}]"
            if not self._est_dict(ev, p):
                continue
            self._clés(ev, p, CLES_EVENEMENT)
            source = ev.get("source")
            seq: int | None = None
            if self._est_dict(source, f"{p}.source"):
                self._clés(source, f"{p}.source", CLES_SOURCE)
                if source.get("kind") != "journal":
                    self.refus(f"{p}.source.kind", "valeur-invalide",
                               "source d'événement non journal")
                s = source.get("sequence")
                if s is None:
                    self.refus(f"{p}.source.sequence", "seq-manquant",
                               "séquence journal absente")
                elif isinstance(s, bool) or not isinstance(s, int) or s < 1:
                    self.refus(f"{p}.source.sequence", "seq-non-numerique",
                               "séquence journal non entière positive")
                else:
                    seq = s
                    sequences.append(s)
                sk = source.get("source_kind")
                if sk is not None:
                    if not isinstance(sk, str) or not _ID_SOURCE_KIND.match(sk):
                        self.refus(f"{p}.source.source_kind",
                                   "source-inconnue",
                                   "type de source journal hors format approuvé")
            pos = ev.get("position")
            if pos is None:
                self.refus(f"{p}.position", "champ-obligatoire",
                           "position d'événement absente")
            elif isinstance(pos, bool) or not isinstance(pos, int) or pos < 1:
                self.refus(f"{p}.position", "position-invalide",
                           "position non entière positive")
            else:
                positions.append(pos)
                if pos != i + 1:
                    self.refus(f"{p}.position", "position-incoherente",
                               "position non alignée sur l'ordre de réponse")
            eid = ev.get("event_id")
            if eid is None:
                self.refus(f"{p}.event_id", "champ-obligatoire",
                           "identifiant d'événement absent")
            elif not isinstance(eid, str) or not _ID_EVENT.match(eid):
                self.refus(f"{p}.event_id", "identifiant-invalide",
                           "identifiant d'événement hors format")
            else:
                if eid in ids:
                    self.refus(f"{p}.event_id", "evenement-duplique",
                               "identifiant d'événement répété")
                ids.add(eid)
                mission_ev = eid.rsplit(":", 1)[0]
                if mission_ref is None:
                    mission_ref = mission_ev
                elif mission_ev != mission_ref:
                    self.refus(f"{p}.event_id", "mission-melangee",
                               "deux identifiants de mission dans une même "
                               "timeline")
            if seq is not None and isinstance(eid, str) and \
                    mission_ref is not None and \
                    eid != mission_ref + ":" + str(seq):
                self.refus(f"{p}.event_id", "evenement-id-incoherent",
                           "l'identifiant d'événement contredit sa séquence")
            if seq is not None and self.mission_id is not None and \
                    mission_ref is not None and mission_ref != self.mission_id:
                self.refus(f"{p}.references", "mission-melangee",
                           "la timeline appartient à une autre mission")
            # temps : display only ; jamais source d'ordre
            tps = ev.get("time")
            if self._est_dict(tps, f"{p}.time"):
                self._clés(tps, f"{p}.time", CLES_TEMPS)
                et = tps.get("state")
                ts = tps.get("timestamp")
                if et == "recorded":
                    dt = self._iso(ts, f"{p}.time.timestamp", obligatoire=True)
                    if dt is not None and self.created_at is not None and \
                            dt < self.created_at:
                        self.refus(f"{p}.time.timestamp", "ts-anterieur",
                                   "événement antérieur à la création de la "
                                   "mission")
                elif et in ("unavailable", "redacted"):
                    if "timestamp" in tps:
                        self.refus(f"{p}.time.timestamp", "ts-incoherent",
                                   "horodatage présent pour un état sans temps")
                else:
                    self.refus(f"{p}.time.state", "valeur-inconnue",
                               "état d'horodatage hors vocabulaire")
            cat = ev.get("category")
            if cat is not None and cat not in CATEGORIES_EVENEMENT:
                self.refus(f"{p}.category", "categorie-inconnue",
                           "catégorie hors vocabulaire")
            con = ev.get("consequence")
            if con is not None and con not in CONSEQUENCES:
                self.refus(f"{p}.consequence", "consequence-inconnue",
                           "conséquence hors vocabulaire")
            vis = ev.get("visibility")
            if vis is not None and vis not in VISIBILITES:
                self.refus(f"{p}.visibility", "visibilite-inconnue",
                           "tier de visibilité hors vocabulaire")
            ds = ev.get("data_state")
            if ds is not None and ds not in ETATS_DONNEES:
                self.refus(f"{p}.data_state", "valeur-inconnue",
                           "état de données hors vocabulaire")
            sm = ev.get("safe_summary")
            if sm is not None:
                if not isinstance(sm, str) or not 0 < len(sm) <= 240 or \
                        "\n" in sm or "\r" in sm:
                    self.refus(f"{p}.safe_summary", "controle-interdit",
                               "résumé sûr hors bornes ou multi-ligne")
            refs = ev.get("references")
            if self._est_dict(refs, f"{p}.references"):
                self._clés(refs, f"{p}.references", CLES_REFERENCES)
                rmid = self._chaîne(refs.get("mission_id"),
                                    f"{p}.references.mission_id", _ID_MISSION)
                if rmid is not None and mission_ref is not None and \
                        rmid != mission_ref:
                    self.refus(f"{p}.references.mission_id",
                               "mission-melangee",
                               "référence de mission contradictoire")
                for k in ("run_id", "plan_id", "provider_id"):
                    v = refs.get(k)
                    if v is not None:
                        self._chaîne(v, f"{p}.references.{k}", _ID_SAFE,
                                     "valeur-invalide")
                for k in ("finding_ids", "cluster_ids"):
                    lst = refs.get(k)
                    if lst is not None and self._est_liste(
                            lst, f"{p}.references.{k}"):
                        for j, v in enumerate(lst):
                            if not isinstance(v, str) or \
                                    not _ID_SAFE.match(v) or \
                                    lst.count(v) > 1:
                                self.refus(
                                    f"{p}.references.{k}[{j}]",
                                    "valeur-invalide",
                                    "identifiant de référence dupliqué ou "
                                    "hors format")
            prov = ev.get("provenance")
            if prov is not None:
                self._provenance(prov, f"{p}.provenance")
            lim = ev.get("limitations")
            if lim is not None:
                if not self._est_liste(lim, f"{p}.limitations"):
                    continue
                for j, code in enumerate(lim):
                    if code not in LIMITATIONS_TIMELINE:
                        self.refus(f"{p}.limitations[{j}]",
                                   "limitation-inconnue",
                                   "code de limitation hors vocabulaire")
            # événement inconnu : forme générique EXACTE ou refus
            if cat == "unknown":
                if con != "recorded" or vis != "technical" or \
                        ds != "unavailable" or \
                        "projection_version_unsupported" not in (lim or []) or \
                        ev.get("kind") != "unknown_event_recorded":
                    self.refus(f"{p}", "evenement-inconnu-non-generique",
                               "événement inconnu exposé hors forme générique "
                               "sûre : refusé, jamais normalisé")
        if sequences and len(sequences) != len(set(sequences)):
            self.refus(f"{chemin}.events", "seq-duplique",
                       "séquences journal dupliquées : ordre ambigu")
        if sequences and sequences != sorted(sequences):
            self.refus(f"{chemin}.events", "seq-non-croissant",
                       "séquences journal non croissantes")
        if sequences and len(set(sequences)) == len(sequences) and \
                sequences != list(range(sequences[0], sequences[0] + len(sequences))) \
                and "history_gap_detected" not in limitations:
            self.refus(f"{chemin}.events", "seq-trou",
                       "trou dans les séquences du journal sans limitation "
                       "history_gap_detected déclarée")
        if positions and len(positions) != len(set(positions)):
            self.refus(f"{chemin}.events", "position-dupliquee",
                       "positions d'événement dupliquées")
        self.timeline = {"etat": etat, "limitations": limitations,
                         "sequences": sequences}

    def _timeline_seule(self, body: dict[str, Any], chemin: str) -> None:
        # capture timeline seule (--response-file) : validation sans mission,
        # l'identité de mission est vérifiée à travers les événements.
        self._timeline(body, chemin)

    # ── Provenance ────────────────────────────────────────────────────────
    def _provenance(self, prov: Any, chemin: str) -> None:
        if not self._est_dict(prov, chemin):
            return
        if not prov:
            self.refus(chemin, "provenance-vide",
                       "provenance vide explicite : l'absence se déclare par "
                       "omission, jamais par un objet vide")
        self._clés(prov, chemin, CLES_PROVENANCE)
        for k in ("provider_id", "server_id", "tool_id", "request_id",
                  "correlation_id"):
            v = prov.get(k)
            if v is not None:
                self._chaîne(v, f"{chemin}.{k}", _ID_SAFE,
                             "provenance-id-invalide")
        kind = prov.get("provider_kind")
        if kind is not None and kind not in PROVIDER_KINDS:
            self.refus(f"{chemin}.provider_kind", "valeur-inconnue",
                       "type de provider hors vocabulaire")
        transport = prov.get("transport")
        if transport is not None and transport not in TRANSPORTS:
            self.refus(f"{chemin}.transport", "transport-inconnu",
                       "transport hors allowlist temporaire (à confirmer MCP)")
        proto = prov.get("protocol")
        if proto is not None:
            if self._est_dict(proto, f"{chemin}.protocol"):
                self._clés(proto, f"{chemin}.protocol", CLES_PROTOCOL)
                nom = proto.get("name")
                if nom is not None and nom not in PROTOCOLES:
                    self.refus(f"{chemin}.protocol.name", "protocol-inconnu",
                               "protocole hors allowlist temporaire (à "
                               "confirmer MCP)")
                ver = proto.get("version")
                if ver is not None and (not isinstance(ver, str) or
                                        not re.match(
                                            r"^[A-Za-z0-9_.-]{1,40}$", ver)):
                    self.refus(f"{chemin}.protocol.version", "valeur-invalide",
                               "version de protocole hors format")
        conf = prov.get("confidence")
        if conf is not None:
            if isinstance(conf, str):
                # forme observée dans l'historique legacy des findings
                if conf not in CONFIDENCES_LEVELS:
                    self.refus(f"{chemin}.confidence", "confiance-inconnue",
                               "niveau de confiance hors vocabulaire")
            elif self._est_dict(conf, f"{chemin}.confidence"):
                self._clés(conf, f"{chemin}.confidence", CLES_CONFIDENCE)
                lvl = conf.get("level")
                if lvl not in CONFIDENCES_LEVELS:
                    self.refus(f"{chemin}.confidence.level",
                               "confiance-inconnue",
                               "niveau de confiance hors vocabulaire")
                bas = conf.get("basis")
                if bas not in CONFIDENCES_BASIS:
                    self.refus(f"{chemin}.confidence.basis",
                               "confiance-sans-basis",
                               "confiance sans base déclarée : une déclaration "
                               "de provider n'est pas une vérification AGNT")
                if lvl == "high" and bas == "provider_declared":
                    self.refus(f"{chemin}.confidence",
                               "confiance-non-corroboree",
                               "confiance élevée uniquement déclarée par le "
                               "provider : aucune corroboration AGNT")
            else:
                self.refus(f"{chemin}.confidence", "type-invalide",
                           "confiance en objet {level,basis} ou libellé "
                           "canonique attendu")
        av = prov.get("availability")
        if av is not None and av not in DISPONIBILITE_PROVENANCE:
            self.refus(f"{chemin}.availability", "disponibilite-inconnue",
                       "disponibilité de provenance hors vocabulaire")

    # ── Exécutions ────────────────────────────────────────────────────────
    def _executions(self, executions: Any, chemin: str) -> None:
        if not self._est_liste(executions, chemin):
            return
        for i, ex in enumerate(executions):
            p = f"{chemin}[{i}]"
            if not self._est_dict(ex, p):
                continue
            if ex.get("schema_version") == EXECUTION:
                self._execution_v1(ex, p)
            else:
                self._execution_legacy(ex, p)

    def _execution_legacy(self, ex: dict[str, Any], chemin: str) -> None:
        self._clés(ex, chemin, CLES_EXEC_LEGACY)
        pid = self._chaîne(ex.get("provider_id"), f"{chemin}.provider_id",
                           _ID_SAFE, "provenance-id-invalide")
        st = ex.get("status")
        prov = ex.get("provenance")
        if prov is not None:
            self._provenance(prov, f"{chemin}.provenance")
        count = ex.get("findings_count")
        if count is not None:
            count = self._entier(count, f"{chemin}.findings_count", minimum=0)
        if st is not None and st not in ("selectionne", "execute", "echoue",
                                         "non_disponible", "non_autorise",
                                         "non_applicable", "non_selectionne"):
            self.refus(f"{chemin}.status", "statut-execution-inconnu",
                       "statut de provider hors vocabulaire du moteur")
        if st in ("echoue", "non_disponible", "non_autorise",
                  "non_applicable", "non_selectionne", "selectionne"):
            if count is not None:
                self.refus(f"{chemin}.findings_count",
                           "compteur-statut-non-execute",
                           "compteur de findings pour un provider non exécuté : "
                           "un statut hors exécution ne produit pas de zéro")
        elif st == "execute" and count == 0 and \
                self.artefacts_findings is not True:
            self.refus(f"{chemin}.findings_count", "zero-sans-artefact",
                       "zéro pour un provider exécuté sans artefact de "
                       "findings lisible déclaré")
        self.executions.append({
            "provider_id": pid, "form": "legacy",
            "detection_value": ("rien_trouve" if count == 0
                                and st == "execute" else
                                ("findings_presents" if count and count > 0
                                 else None)),
            "findings_count": count, "execution_value": st,
            "invocation": "oui" if st == "execute" else "non",
            "availability_value": None, "completeness_state": None,
        })

    def _execution_v1(self, ex: dict[str, Any], chemin: str) -> None:
        self._clés(ex, chemin, CLES_EXECUTION_V1)
        pid = self._chaîne(ex.get("provider_id"), f"{chemin}.provider_id",
                           _ID_SAFE, "provenance-id-invalide")
        enu = {
            "applicability": APPLICABILITE, "selection": SELECTION,
            "condition": CONDITION, "authorization": AUTORISATION,
        }
        for nom, vocab in enu.items():
            dim = ex.get(nom)
            if self._est_dict(dim, f"{chemin}.{nom}"):
                self._dimension(dim, f"{chemin}.{nom}", vocab)
        av = ex.get("availability")
        if self._est_dict(av, f"{chemin}.availability"):
            self._dimension(av, f"{chemin}.availability", DISPONIBILITE_OUTIL)
        exe = ex.get("execution")
        if self._est_dict(exe, f"{chemin}.execution"):
            self._clés(exe, f"{chemin}.execution", CLES_EXECUTION_DIM)
            self._enum(exe.get("value"), f"{chemin}.execution.value",
                       EXECUTION_RESULTAT, "statut-execution-inconnu")
            self._enum(exe.get("invocation"), f"{chemin}.execution.invocation",
                       INVOCATION, "valeur-inconnue")
            self._enum(exe.get("output"), f"{chemin}.execution.output",
                       SORTIE, "valeur-inconnue")
            self._proof(exe, f"{chemin}.execution")
            # cohérence (miroir du schéma Product ; fail-closed indépendant)
            v = exe.get("value")
            if v == "termine" and (exe.get("invocation") != "oui" or
                                   exe.get("output") not in
                                   ("exploitable", "partiel")):
                self.refus(f"{chemin}.execution", "execution-incoherente",
                           "exécution terminée sans preuve d'invocation et de "
                           "sortie exploitable")
            if v in ("non_lance", "unavailable") and \
                    (exe.get("invocation") != "non" or
                     exe.get("output") != "non_exploitable"):
                self.refus(f"{chemin}.execution", "execution-incoherente",
                           "exécution non lancée avec une sortie déclarée")
        det = ex.get("detection")
        if self._est_dict(det, f"{chemin}.detection"):
            self._clés(det, f"{chemin}.detection", CLES_DETECTION_DIM)
            self._enum(det.get("value"), f"{chemin}.detection.value",
                       DETECTION, "detection-inconnue")
            self._proof(det, f"{chemin}.detection")
            count = det.get("findings_count")
            analysed = det.get("analyzed_targets")
            if count is not None:
                count = self._entier(count, f"{chemin}.detection.findings_count",
                                     minimum=0)
            if analysed is not None:
                self._entier(analysed, f"{chemin}.detection.analyzed_targets",
                             minimum=0)
            dv = det.get("value")
            ev = exe.get("value") if isinstance(exe, dict) else None
            inv = exe.get("invocation") if isinstance(exe, dict) else None
            out = exe.get("output") if isinstance(exe, dict) else None
            comp = ex.get("completeness") or {}
            comp_state = comp.get("state") if isinstance(comp, dict) else None
            if dv == "rien_trouve":
                if ev != "termine" or inv != "oui" or out != "exploitable" \
                        or count != 0 or not isinstance(analysed, int) \
                        or analysed < 1 or comp_state != "complete":
                    self.refus(f"{chemin}.detection", "rien-trouve-incomplet",
                               "zéro sans les neuf conditions du contrat "
                               "execution-status (terminée, invoquée, "
                               "exploitable, cibles analysées, artefact "
                               "lisible, sans conflit)")
            elif dv == "findings_presents":
                if not isinstance(count, int) or count < 1 or ev != "termine":
                    self.refus(f"{chemin}.detection",
                               "findings-non-prouves",
                               "des findings déclarés sans exécution terminée "
                               "et compteur positif prouvé")
            else:
                if "findings_count" in det:
                    self.refus(f"{chemin}.detection.findings_count",
                               "compteur-non-evalue",
                               "compteur présent pour une détection non "
                               "évaluée : absence de résultat ≠ zéro")
            # Partial + résultats valides est un cas Product légitime
            # (partial_mcp_provenance_with_valid_findings) : seul un état
            # `conflict` explicite reste fail-closed, et uniquement lorsque
            # la mission est déclarée terminée (contradiction d'évidence).
            if comp_state == "conflict":
                self.executions.append({
                    "provider_id": pid, "form": "v1",
                    "detection_value": dv, "findings_count": count,
                    "execution_value": ev, "invocation": inv,
                    "availability_value": (av or {}).get("value"),
                    "completeness_state": "conflict",
                })
                if self.mission_status == "termine":
                    self.refus(f"{chemin}", "conflict-resolu",
                               "conflit d'évidence sous une mission terminée : "
                               "l'état doit être inconnu, jamais le plus "
                               "rassurant")
        comp = ex.get("completeness")
        if self._est_dict(comp, f"{chemin}.completeness"):
            self._clés(comp, f"{chemin}.completeness", CLES_COMPLETUDE)
            self._enum(comp.get("state"), f"{chemin}.completeness.state",
                       COMPLETUDE, "valeur-inconnue")
            for k in ("missing", "limitations"):
                lst = comp.get(k)
                if self._est_liste(lst, f"{chemin}.completeness.{k}"):
                    for j, code in enumerate(lst):
                        if not isinstance(code, str) or \
                                not _ID_RAISON.match(code):
                            self.refus(f"{chemin}.completeness.{k}[{j}]",
                                       "valeur-invalide",
                                       "code de complétude hors format")
            state = comp.get("state")
            if state == "conflict" and self.mission_status == "termine":
                self.refus(f"{chemin}.completeness", "conflict-resolu",
                           "conflit d'évidence sous une mission terminée")
        prov = ex.get("provenance")
        if prov is not None:
            self._provenance(prov, f"{chemin}.provenance")
        self.executions.append({
            "provider_id": pid, "form": "v1",
            "detection_value": (det or {}).get("value"),
            "findings_count": (det or {}).get("findings_count"),
            "execution_value": (exe or {}).get("value"),
            "invocation": (exe or {}).get("invocation"),
            "availability_value": (av or {}).get("value"),
            "completeness_state": (comp or {}).get("state"),
        })

    def _dimension(self, dim: dict[str, Any], chemin: str,
                   vocab: tuple[str, ...]) -> None:
        self._clés(dim, chemin, CLES_DIMENSION)
        self._enum(dim.get("value"), f"{chemin}.value", vocab,
                   "valeur-inconnue")
        self._proof(dim, chemin)
        rc = dim.get("reason_code")
        if rc is not None and (not isinstance(rc, str) or
                               not _ID_RAISON.match(rc)):
            self.refus(f"{chemin}.reason_code", "valeur-invalide",
                       "code de raison hors format")

    def _proof(self, obj: dict[str, Any], chemin: str) -> None:
        pr = obj.get("proof")
        if pr is None:
            self.refus(f"{chemin}.proof", "champ-obligatoire",
                       "preuve d'origine absente")
        elif pr not in PREUVES:
            self.refus(f"{chemin}.proof", "valeur-inconnue",
                       "origine de preuve hors vocabulaire")

    def _enum(self, valeur: Any, chemin: str, vocab: tuple[str, ...],
              code: str) -> None:
        if valeur is None:
            self.refus(chemin, "champ-obligatoire",
                       "valeur de dimension absente")
        elif valeur not in vocab:
            self.refus(chemin, code,
                       "valeur hors vocabulaire canonique : aucune conversion")

    def _execution_cases(self, body: dict[str, Any], chemin: str) -> None:
        # Capture du contrat execution-status (cas de test) : records validés
        # + cohérence avec le mission_status annoncé de chaque cas.
        cases = body.get("cases")
        if not self._est_liste(cases, f"{chemin}.cases"):
            return
        for i, c in enumerate(cases):
            p = f"{chemin}.cases[{i}]"
            if not self._est_dict(c, p):
                continue
            records = c.get("records")
            if self._est_liste(records, f"{p}.records"):
                for j, r in enumerate(records):
                    self._execution_v1(r, f"{p}.records[{j}]")


def valider_projection(projection: dict[str, Any],
                       *, horloge: datetime | None = None,
                       autoriser_marqueur_fixture: bool = False) -> Verdict:
    return _Juge(horloge, autoriser_marqueur_fixture).analyser(projection)


# ══════════════════════════════════════════════════════════════════════════
# Runner — fixtures, réponse capturée, API réelle. La projection est toujours
# jugée telle quelle ; jamais réécrite, jamais affichée.
# ══════════════════════════════════════════════════════════════════════════

def _horloge(texte: str | None) -> datetime | None:
    if not texte:
        return None
    try:
        ts = datetime.fromisoformat(texte.replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit("usage : --now attend un ISO 8601 avec fuseau")
    if ts.tzinfo is None:
        raise SystemExit("usage : --now doit porter un fuseau (ex. +00:00)")
    return ts


def _charge_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SystemExit("fichier non JSON (contenu non affiché)")


def mode_fixtures(dossier: Path, now: datetime | None) -> int:
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
        # Les enveloppes de test Security utilisent _marker ; une fixture
        # Product peut porter $fixture : autorisé en mode fixture.
        v = valider_projection(enveloppe.get("response"),
                               horloge=horloge,
                               autoriser_marqueur_fixture=True)
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
    print(str(v))
    return 0 if v.ok else 2


def _get(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as rep:
            return json.loads(rep.read().decode("utf-8"))
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
    v = valider_projection(liste, horloge=now)
    print("GET /api/missions →", str(v))
    pire = max(pire, 0 if v.ok else 2)
    cibles = []
    if mission_id:
        cibles.append(mission_id)
    elif isinstance(liste, dict) and isinstance(liste.get("items"), list):
        for item in liste["items"]:
            if not isinstance(item, dict):
                continue
            mid = item.get("mission_id")
            href = item.get("detail_href")
            cibles.append(href if isinstance(href, str) else
                          (f"/api/missions/{mid}" if isinstance(mid, str)
                           else None))
    for cible in cibles:
        if cible is None:
            continue
        detail = _get(base + cible)
        v = valider_projection(detail, horloge=now)
        print(f"GET {cible} →", str(v))
        pire = max(pire, 0 if v.ok else 2)
    return pire


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Gate SECURITY des projections History/Timeline/Status")
    ap.add_argument("--fixture-mode", metavar="REP", type=Path,
                    help="joue les fixtures marquées TEST ONLY de ce répertoire")
    ap.add_argument("--response-file", metavar="F", type=Path,
                    help="valide une réponse JSON capturée (sans enveloppe)")
    ap.add_argument("--base-url", metavar="URL",
                    help="valide GET /api/missions puis chaque détail")
    ap.add_argument("--mission-id", help="restreint au détail de cette mission")
    ap.add_argument("--now", help="horloge de référence (ISO 8601 + fuseau)")
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
