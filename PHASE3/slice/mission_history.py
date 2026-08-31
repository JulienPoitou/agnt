"""Mission History — lecteur canonique, aligné sur les contrats Product.

Ce module est la SOURCE UNIQUE de projection de l'historique des Missions. Les
routes HTTP (`PHASE3/interface/api.py`) ne projettent rien elles-mêmes : elles
délèguent ici. Les réponses publiques suivent les contrats Product versionnés :

    · agnt.history.v1         (listing + détail, enveloppe et champs)
    · agnt.timeline.v1        (data.timeline, projection du journal)
    · agnt.execution-status.v1(data.executions[], dimensions par provider)

Ce que ce module N'EST PAS :

    · il n'écrit rien (aucun index, aucune base, aucun cache, aucun artefact) ;
      il RELIT l'archive append-only (`mission.json`, `journal.jsonl`,
      `<mission>/sortie`, `<mission>/run`) ;
    · il ne décide rien : le statut est DÉRIVÉ des événements du journal, jamais
      saisi, jamais inventé ;
    · il ne publie jamais de donnée brute : chemin absolu, argv, commande,
      endpoint, credential, stack trace, sortie provider, artefact raw — tout
      passe par une projection sûre (cf. `assainissement.py`).

Cardinalité : une Mission → zéro ou un Run. L'identifiant du POST `/api/runs`
est TEMPORAIRE (file) ; l'identifiant durable est le `mission_id`. Relancer une
analyse = une NOUVELLE Mission. `GET /api/runs/<id>` n'est PAS un historique.

Règles de statut (précédence, contrat History §7) :

    événement terminal explicite  >  propriétaire courant prouvé en mémoire
                                  >  inconnu/incomplet

Sans preuve de propriété en mémoire (lecture fichiersystem seule), une mission
sans événement terminal est `inconnu` + `incomplete`, jamais `en_cours`.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import assainissement as ASS
import cible as CIB
import mission as MS

# --------------------------------------------------------------------------- versions
HISTORY_VERSION = "agnt.history.v1"
TIMELINE_VERSION = "agnt.timeline.v1"
EXECUTION_VERSION = "agnt.execution-status.v1"

# --------------------------------------------------------------------------- vocabulaire
STATUTS = ("en_file", "en_cours", "termine", "refuse", "erreur", "inconnu")

LIMIT_DEFAUT = 25
LIMIT_MAX = 100

TIMELINE_LIMIT_DEFAUT = 200
TIMELINE_LIMIT_MAX = 500

# Filtres v1 : SEULEMENT ces deux-là. Tout autre paramètre est refusé par l'API.
FILTRES_V1 = ("status", "target_type")

# Noms LOGIQUES admis pour `missing_artifacts` (contrat History, schéma). Jamais
# un chemin, jamais un nom de fichier fourni par un outil.
ARTEFACTS_LOGIQUES = ("run", "plan", "intent", "findings", "clusters", "report",
                      "coverage", "events")

# Motifs d'arrêt fail-closed → `refuse` (contrat History §7). Tout autre `arret`
# portant un champ `erreur` est un échec technique → `erreur`.
ARRETS_REFUS = ("conditions", "applicabilite", "policy", "policy_injoignable")

# Arrêts NON terminaux : consignés sans interrompre la mission.
ARRETS_NON_TERMINAUX = ("escalade_policy_injoignable",)

# Le type « inféré » historique de mission.py (`repertoire`/`fichier`) rejoint le
# vocabulaire `target_types`. Ancienne mission sans descripteur → toujours lisible.
LEGACY_TYPES = {"repertoire": "repository", "fichier": "filesystem"}

_ID_MISSION = re.compile(r"^m-\d{8}T\d{6}Z-[0-9a-f]{8}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_RAISON = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_SOURCE_KIND = re.compile(r"^[a-z0-9_.-]{1,64}$")

# Bornes de projection sûre.
BORNE_TEXTE = 1000
BORNE_TITRE = 240
BORNE_RESUME = 240          # safe_summary (contrat Timeline : ≤ 240)
BORNE_RAPPORT = 20000

_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_URI_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
# Chemin ABSOLU uniquement : la barre oblique ne doit pas être précédée d'un
# caractère de mot (sinon `src/a.py`, un chemin relatif de finding, serait
# redacté à tort en `src<chemin>`).
_ABSOLU = re.compile(r"(?<![A-Za-z0-9_])(?:/[A-Za-z0-9._@~+-]+){1,}/?")
_TRACEBACK = re.compile(r"Traceback \(most recent call last\):\s*")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+", re.I)
_CONTROLE = re.compile(r"[\x00-\x1f\x7f]")

_QUERY_SENSIBLE = {"token", "key", "api_key", "password", "secret", "auth"}

# --- provenance (contrat Timeline §9) -----------------------------------------
# Les SEULS champs projetables, et la grammaire qui borne chacun. Tout le reste du
# fait consigné est jeté : la projection ne relaie jamais un champ ajouté par un
# serveur externe. `provider_kind` n'est JAMAIS deviné — une provenance absente ne
# vaut pas « local / de confiance » (décision d'architecture : MCP détient les faits,
# CORE projette).
PROVENANCE_IDS = ("provider_id", "server_id", "tool_id", "request_id", "correlation_id")
PROVENANCE_KINDS = ("local", "mcp", "external")
PROVENANCE_DISPONIBILITES = ("available", "degraded", "unavailable", "unknown")
CONFIANCE_NIVEAUX = ("low", "medium", "high", "unknown")
CONFIANCE_BASES = ("provider_declared", "agnt_assessed", "corroborated", "unknown")
_TRANSPORT = re.compile(r"^[a-z0-9_.-]{1,40}$")
_PROTO_NOM = re.compile(r"^[a-z0-9_.-]{1,40}$")
_PROTO_VERSION = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")


# --------------------------------------------------------------------------- erreurs
class MissionIntrouvable(Exception):
    """mission_id valide mais aucun dossier lisible. → 404, sans chemin."""


class RequeteInvalide(Exception):
    """Paramètre de lecture invalide (limit, cursor, filtre). → 400, explicite."""


# --------------------------------------------------------------------------- racine
def racine_par_defaut() -> Path:
    """Racine des missions, lue VIVANTE au moment de l'appel (les tests patchent
    `mission.MISSIONS`)."""
    return MS.MISSIONS


def _racine(racine) -> Path:
    return Path(racine) if racine is not None else racine_par_defaut()


# --------------------------------------------------------------------------- lecture
def _lire_json(chemin: Path | None):
    if chemin is None or not chemin.is_file():
        return None
    try:
        return json.loads(chemin.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError, ValueError):
        return None


def _resoudre_artefact(chemin: Path, *noms: str) -> Path | None:
    """Résolution CONTRÔLÉE des deux layouts connus, et rien d'autre.

    `<mission>/sortie/` est l'archive posée par `analyser._archiver_mission` ;
    `<mission>/run/` est le répertoire de travail du pipeline. Noms dans une
    liste fermée ; jamais de chemin libre, jamais de `..`."""
    for sous in ("sortie", "run"):
        base = chemin / sous
        for nom in noms:
            p = base / nom
            if p.is_file():
                return p
    return None


def lire_journal(chemin: Path):
    """(événements triés par seq, anomalies). Lecture tolérante : une ligne
    abîmée est ignorée, un doublon de seq ne garde que la première occurrence
    physique, un trou de séquence est signalé. Jamais fatal."""
    p = chemin / "journal.jsonl"
    anomalies = {"absent": False, "illisible": False, "prefixe": False,
                 "trous": False, "malforme": False}
    if not p.is_file():
        anomalies["absent"] = True
        return [], anomalies
    try:
        brut = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        anomalies["illisible"] = True
        return [], anomalies
    evenements: list[dict] = []
    vus: set[int] = set()
    for ligne in brut.splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            ev = json.loads(ligne)
        except ValueError:
            anomalies["malforme"] = True
            continue
        seq = ev.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            anomalies["malforme"] = True
            continue
        if seq in vus:
            anomalies["trous"] = True
            continue
        vus.add(seq)
        evenements.append(ev)
    evenements.sort(key=lambda e: e["seq"])
    if evenements:
        seqs = [e["seq"] for e in evenements]
        if seqs[0] != 1:
            anomalies["prefixe"] = True
        if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
            anomalies["trous"] = True
    return evenements, anomalies


def _dirs_missions(racine: Path):
    """Dossiers de mission lisibles, recent d'abord. Aucun symlink (un lien
    sortant lirait hors racine), uniquement les dossiers portant mission.json."""
    base = racine.resolve()
    try:
        entrees = sorted(racine.iterdir(), key=lambda p: p.name, reverse=True)
    except OSError:
        return
    for p in entrees:
        if p.is_symlink():
            continue
        try:
            r = p.resolve()
        except OSError:
            continue
        if not r.is_dir():
            continue
        if r != base and not r.is_relative_to(base):
            continue
        if not (r / "mission.json").is_file():
            continue
        yield r


def _chemin_mission(mission_id: str, racine: Path) -> Path | None:
    """Valide l'identifiant AVANT le filesystem, puis borne la résolution à la
    racine. `None` = introuvable, sans jamais lever."""
    if not isinstance(mission_id, str) or not _ID_MISSION.match(mission_id):
        return None
    base = racine.resolve()
    p = racine / mission_id
    if p.is_symlink():
        return None
    try:
        r = p.resolve()
    except OSError:
        return None
    if not r.is_dir():
        return None
    if r != base and not r.is_relative_to(base):
        return None
    return r


# --------------------------------------------------------------------------- dates
def _rfc3339(ts) -> str:
    """Normalise un horodatage en RFC 3339 UTC (`Z`). Rend "" si illisible."""
    if not isinstance(ts, str) or not ts.strip():
        return ""
    try:
        dt = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
    except ValueError:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ts_du_mission_id(mid: str) -> str:
    """Horodatage de création porté par l'identifiant (`m-YYYYMMDDTHHMMSSZ-…`)."""
    m = re.match(r"^m-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z-", mid or "")
    if not m:
        return ""
    a, mo, j, h, mi, s = m.groups()
    return f"{a}-{mo}-{j}T{h}:{mi}:{s}Z"


def _dernier_ts(evenements: list[dict]) -> str:
    for ev in reversed(evenements):
        ts = _rfc3339(ev.get("ts"))
        if ts:
            return ts
    return ""


# --------------------------------------------------------------------------- statut
def _arret_terminal(motif) -> bool:
    return str(motif or "").strip() not in ARRETS_NON_TERMINAUX


def _evenement_terminal(evenements: list[dict]) -> dict | None:
    """Le DERNIER événement terminal du journal, dans l'ordre d'écriture."""
    terminal = None
    for ev in evenements:
        t = ev.get("type")
        if t == "cloture":
            terminal = ev
        elif t == "arret" and _arret_terminal(ev.get("motif")):
            terminal = ev
    return terminal


def statut_mission(evenements: list[dict], proprietaire=None) -> tuple[str, bool]:
    """Projection de statut UNIQUE. Rend (statut, incomplete).

    Précédence (contrat History §7) : terminal explicite > propriétaire courant
    prouvé > inconnu/incomplet. Un `contexte` seul ne prouve PAS `en_cours` :
    sans preuve de propriété en mémoire, l'état est `inconnu` + incomplete."""
    ev = _evenement_terminal(evenements)
    if ev is not None:
        if ev.get("type") == "cloture":
            return "termine", False
        motif = str(ev.get("motif") or "")
        if motif.startswith("intent_") or motif in ARRETS_REFUS:
            return "refuse", False
        if ev.get("erreur") is not None:
            return "erreur", False
        return "refuse", False
    # Pas de terminal.
    if proprietaire is not None:
        etat = proprietaire()
        if etat in ("en_file", "en_cours"):
            return etat, False
    if not evenements:
        return "inconnu", True
    return "inconnu", True


def _motif_terminal(evenements: list[dict]) -> str | None:
    ev = _evenement_terminal(evenements)
    if ev is None:
        return None
    return "cloture" if ev.get("type") == "cloture" else str(ev.get("motif") or "")


# --------------------------------------------------------------------------- projection sûre
def _id_sur(valeur) -> str | None:
    """Un identifiant borné par la grammaire sûre, ou None (jamais exposé brut)."""
    s = str(valeur or "")
    return s if _SAFE_ID.match(s) else None


def _provenance(fait) -> dict | None:
    """Un fait de provenance CONSIGNÉ → l'objet du contrat, ou `None`.

    Additif, allowlisté, borné : un champ hors liste est jeté, une valeur hors
    grammaire est jetée, et `provider_kind` n'est jamais deviné. Sans fait consigné
    il n'y a AUCUNE provenance — pas de « local » par défaut, qui serait une
    affirmation de confiance non prouvée.
    """
    if not isinstance(fait, dict):
        return None
    out: dict = {}
    for cle in PROVENANCE_IDS:
        val = _id_sur(fait.get(cle))
        if val:
            out[cle] = val
    kind = fait.get("provider_kind")
    if kind in PROVENANCE_KINDS:
        out["provider_kind"] = kind
    transport = fait.get("transport")
    if isinstance(transport, str) and _TRANSPORT.fullmatch(transport):
        out["transport"] = transport
    protocole = fait.get("protocol")
    if isinstance(protocole, dict):
        nom = protocole.get("name")
        if isinstance(nom, str) and _PROTO_NOM.fullmatch(nom):
            projete: dict = {"name": nom}
            version = protocole.get("version")
            if isinstance(version, str) and _PROTO_VERSION.fullmatch(version):
                projete["version"] = version
            out["protocol"] = projete
    confiance = fait.get("confidence")
    if (isinstance(confiance, dict) and confiance.get("level") in CONFIANCE_NIVEAUX
            and confiance.get("basis") in CONFIANCE_BASES):
        out["confidence"] = {"level": confiance["level"], "basis": confiance["basis"]}
    disponibilite = fait.get("availability")
    if disponibilite in PROVENANCE_DISPONIBILITES:
        out["availability"] = disponibilite
    return out or None


def _uri_sure(uri: str) -> str:
    """URI sans userinfo et sans paramètre de requête sensible."""
    try:
        parts = urlsplit(uri)
    except ValueError:
        return uri
    if parts.scheme == "" and parts.netloc == "":
        return uri
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k.lower() not in _QUERY_SENSIBLE]
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query),
                       parts.fragment))


def _rediger_chemins(texte: str) -> str:
    """Chemins absolus → `<chemin>`, en épargnant les URI (dont on assainit le
    userinfo et la query sensible)."""
    if not texte:
        return texte
    out, pos = [], 0
    for m in _URI_TOKEN.finditer(texte):
        out.append(_ABSOLU.sub("<chemin>", texte[pos:m.start()]))
        out.append(_uri_sure(m.group(0)))
        pos = m.end()
    out.append(_ABSOLU.sub("<chemin>", texte[pos:]))
    return "".join(out)


def _nettoyer(texte, borne: int = BORNE_TEXTE) -> str:
    """Projection sûre d'une chaîne : secrets masqués, markup neutralisé,
    `Bearer` masqué, chemins absolus redactés, longueur bornée."""
    if not isinstance(texte, str):
        return texte
    texte, _ = ASS.masquer(texte)
    texte = texte.replace("<", "&lt;").replace(">", "&gt;")
    texte = _BEARER.sub("Bearer &lt;masqué&gt;", texte)
    texte = _rediger_chemins(texte)
    if len(texte) > borne:
        texte = texte[:borne] + "…"
    return texte


def _nettoyer_erreur(texte) -> str:
    texte = str(texte or "").replace("\r", " ").replace("\n", " ")
    texte = _TRACEBACK.sub("", texte)
    return _nettoyer(texte, borne=300)


def _assainir(obj):
    """Projection sûre récursive."""
    if isinstance(obj, str):
        return _nettoyer(obj)
    if isinstance(obj, list):
        return [_assainir(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _assainir(v) for k, v in obj.items()}
    return obj


def _titre(requete) -> str:
    """Titre de requête : borné, sans caractère de contrôle, redacté."""
    t = str(requete or "").strip()
    t = _nettoyer(t, borne=BORNE_TITRE)
    t = _CONTROLE.sub(" ", t)
    t = " ".join(t.split())
    return t or "Mission"


# --------------------------------------------------------------------------- cible
def _type_cible(entete) -> str:
    if not isinstance(entete, dict):
        return "inconnu"
    cib = entete.get("cible")
    if not isinstance(cib, dict):
        return "inconnu"
    descr = cib.get("descripteur")
    if isinstance(descr, dict) and descr.get("type"):
        return str(descr["type"]).strip() or "inconnu"
    typ = str(cib.get("type") or "").strip()
    return LEGACY_TYPES.get(typ, typ or "inconnu")


def _reference_brute(entete) -> str:
    cib = (entete or {}).get("cible") if isinstance(entete, dict) else None
    if not isinstance(cib, dict):
        return ""
    descr = cib.get("descripteur")
    if isinstance(descr, dict) and descr.get("reference"):
        return str(descr["reference"])
    return str(cib.get("chemin") or "")


def cible_sure(entete) -> dict:
    """Projection `target` : `type` + `display_name`, jamais un chemin absolu,
    jamais une URL avec userinfo. Le type est toujours fourni (contrat History)."""
    typ = _type_cible(entete)
    reference = _reference_brute(entete)
    if _URI.match(reference):
        sure = _uri_sure(reference)
        parts = urlsplit(sure)
        nom = (parts.hostname or "").strip() or "cible-distante"
        return {"type": typ[:40] or "inconnu", "display_name": nom[:160] or "cible"}
    if reference:
        nom = Path(reference).name or reference
    else:
        nom = "cible"
    nom = _nettoyer(nom, borne=160) or "cible"
    return {"type": typ[:40] or "inconnu", "display_name": nom}


# --------------------------------------------------------------------------- artefacts
def _artefact_findings(chemin: Path, statut: str):
    """Le nombre de findings PROUVÉ par un artefact lisible, ou None.

    Seule une mission `termine` dont `findings.json` est une liste lisible rend
    un nombre (y compris 0 : `[]` est une preuve). Interruption, absence,
    illisible → None : jamais un « 0 » fabriqué."""
    if statut != "termine":
        return None
    doc = _lire_json(_resoudre_artefact(chemin, "findings.json"))
    return len(doc) if isinstance(doc, list) else None


def _artefact_clusters(chemin: Path, statut: str):
    if statut != "termine":
        return None
    doc = _lire_json(_resoudre_artefact(chemin, "clusters.json"))
    if not isinstance(doc, dict):
        return None
    cls = doc.get("clusters")
    return len(cls) if isinstance(cls, list) else None


def _rapport_lisible(chemin: Path) -> Path | None:
    p = _resoudre_artefact(chemin, "RAPPORT.md")
    return p if p is not None else None


def _run_id_de(evenements: list[dict], chemin: Path) -> str | None:
    for ev in evenements:
        if ev.get("type") == "contexte" and ev.get("run_id"):
            return _id_sur(ev["run_id"])
    run = _lire_json(_resoudre_artefact(chemin, "run.json"))
    return _id_sur((run or {}).get("run_id"))


def _findings_summary(chemin: Path, statut: str) -> dict | None:
    """{total, by_severity} SEULEMENT après lecture d'un artefact findings."""
    if statut != "termine":
        return None
    doc = _lire_json(_resoudre_artefact(chemin, "findings.json"))
    if not isinstance(doc, list):
        return None
    by_sev: dict[str, int] = {}
    for f in doc:
        if not isinstance(f, dict):
            continue
        sev = (f.get("severity") or {}).get("value") if isinstance(f.get("severity"), dict) else None
        v = str(sev or "UNKNOWN").upper()
        by_sev[v] = by_sev.get(v, 0) + 1
    return {"total": len(doc), "by_severity": by_sev}


def _artefacts_manquants(chemin: Path, statut: str, anomalies: dict,
                         run_id: str | None) -> list[str]:
    """Noms LOGIQUES des artefacts attendus et absents. Jamais un chemin."""
    manquants: list[str] = []
    if anomalies.get("absent") or anomalies.get("illisible"):
        manquants.append("events")
    if statut == "termine":
        if _lire_json(_resoudre_artefact(chemin, "plan.json")) is None:
            manquants.append("plan")
        if run_id is not None and _lire_json(_resoudre_artefact(chemin, "run.json")) is None:
            manquants.append("run")
        if _artefact_findings(chemin, statut) is None:
            manquants.append("findings")
        if _artefact_clusters(chemin, statut) is None:
            manquants.append("clusters")
        if _rapport_lisible(chemin) is None:
            manquants.append("report")
            manquants.append("coverage")
    return manquants


# --------------------------------------------------------------------------- résumé
def resumer(chemin: Path, evenements: list[dict], anomalies: dict,
            statut: str, incomplete: bool) -> dict:
    """La projection COMPACTE d'une mission (`MissionSummary`, contrat History)."""
    entete = _lire_json(chemin / "mission.json")
    mid = chemin.name
    cree_le = _rfc3339((entete or {}).get("cree_le")) or _ts_du_mission_id(mid)
    updated = _dernier_ts(evenements) or cree_le

    started = ""
    completed = ""
    for ev in evenements:
        if ev.get("type") == "contexte" and not started:
            started = _rfc3339(ev.get("ts"))
    evt = _evenement_terminal(evenements)
    if evt is not None:
        completed = _rfc3339(evt.get("ts"))

    run_id = _run_id_de(evenements, chemin)
    findings_n = _artefact_findings(chemin, statut)
    clusters_n = _artefact_clusters(chemin, statut)

    item: dict = {
        "mission_id": mid,
        "detail_href": f"/api/missions/{mid}",
        "request": {"title": _titre((entete or {}).get("requete"))},
        "target": cible_sure(entete),
        "status": statut,
        "created_at": cree_le,
        "updated_at": updated,
    }
    if started:
        item["started_at"] = started
    if completed:
        item["completed_at"] = completed
    if started and completed:
        try:
            d = (datetime.fromisoformat(completed.replace("Z", "+00:00"))
                 - datetime.fromisoformat(started.replace("Z", "+00:00")))
            if d.total_seconds() >= 0:
                item["duration_ms"] = int(d.total_seconds() * 1000)
        except ValueError:
            pass
    if run_id is not None:
        item["run_id"] = run_id
    if findings_n is not None:
        item["findings_summary"] = _findings_summary(chemin, statut)
    if clusters_n is not None:
        item["clusters_count"] = clusters_n
    item["artifacts"] = {
        "detail": True,
        "findings": findings_n is not None,
        "clusters": clusters_n is not None,
        "report": _rapport_lisible(chemin) is not None,
    }
    if incomplete:
        item["incomplete"] = True
        item["incomplete_reason"] = "Aucun événement terminal n'a été consigné"
    return item


# --------------------------------------------------------------------------- curseurs
def _encoder(token: object) -> str:
    brut = json.dumps(token, ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(brut).decode("ascii").rstrip("=")


def _decoder(token: str, nom: str) -> object:
    try:
        pad = token + "=" * (-len(token) % 4)
        return json.loads(base64.urlsafe_b64decode(pad.encode("ascii")).decode("utf-8"))
    except Exception:
        raise RequeteInvalide(f"{nom} invalide : {token!r}")


def _decoder_curseur_liste(token: str) -> tuple:
    donnees = _decoder(token, "cursor")
    if (not isinstance(donnees, list) or len(donnees) != 2
            or not all(isinstance(x, str) for x in donnees)):
        raise RequeteInvalide(f"cursor invalide : {token!r}")
    return tuple(donnees)


def _decoder_curseur_timeline(token: str) -> int:
    donnees = _decoder(token, "timeline_cursor")
    if (not isinstance(donnees, list) or len(donnees) != 1
            or not isinstance(donnees[0], int) or donnees[0] < 0):
        raise RequeteInvalide(f"timeline_cursor invalide : {token!r}")
    return donnees[0]


# --------------------------------------------------------------------------- listing
def lister(racine=None, *, limit=None, cursor: str | None = None,
           status: str | None = None, target_type: str | None = None,
           proprietaire=None) -> dict:
    """Listing paginé `created_at DESC, mission_id DESC` (contrat History §5).

    Réponse : `{"schema_version": "agnt.history.v1", "items": [...],
    "page": {"limit": N, "next_cursor": "…"|null}}`. Toujours HTTP 200 ; liste
    vide = `items: []`."""
    racine = _racine(racine)
    if limit is None or limit == "":
        limit = LIMIT_DEFAUT
    elif isinstance(limit, str):
        try:
            limit = int(limit)
        except ValueError:
            raise RequeteInvalide(
                f"limit invalide : {limit!r} — entier entre 1 et {LIMIT_MAX}")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= LIMIT_MAX:
        raise RequeteInvalide(
            f"limit invalide : {limit!r} — entier entre 1 et {LIMIT_MAX} (défaut {LIMIT_DEFAUT})")
    if status is not None and status not in STATUTS:
        raise RequeteInvalide(f"status inconnu : {status!r} — admis : {list(STATUTS)}")

    items = []
    for d in _dirs_missions(racine):
        evenements, anomalies = lire_journal(d)
        st, incomplete = statut_mission(evenements, proprietaire and (
            lambda mid=d.name: proprietaire(mid)))
        items.append(resumer(d, evenements, anomalies, st, incomplete))
    items.sort(key=lambda i: (i.get("created_at") or "", i["mission_id"]), reverse=True)

    if status is not None:
        items = [i for i in items if i["status"] == status]
    if target_type is not None:
        items = [i for i in items if i["target"]["type"] == target_type]

    if cursor is not None:
        cle = _decoder_curseur_liste(cursor)
        items = [i for i in items if (i.get("created_at") or "", i["mission_id"]) < cle]

    page = items[:limit]
    prochain = None
    if len(items) > limit:
        prochain = _encoder([page[-1].get("created_at") or "", page[-1]["mission_id"]])
    return {"schema_version": HISTORY_VERSION,
            "items": page,
            "page": {"limit": limit, "next_cursor": prochain}}


# --------------------------------------------------------------------------- timeline
# Registre de projection (contrat Timeline §6) : type de journal → (kind, category,
# consequence par défaut, visibility, résumé sûr). La conséquence dépend parfois du
# contenu (échec d'exécution, refus de politique) : traitée après.
_CAT = {
    "mission": "mission", "intent": "intent", "plan": "plan", "policy": "policy",
    "execution": "execution", "coverage": "coverage", "correlation": "correlation",
    "report": "report", "security": "security", "system": "system",
    "unknown": "unknown",
}
_REGISTRE = {
    "ouverture": ("mission_created", "mission", "recorded", "summary"),
    "confiance": ("trust_scope_recorded", "security", "recorded", "technical"),
    "egress": ("network_scope_recorded", "security", "recorded", "technical"),
    "intention": ("intent_resolved", "intent", "completed", "summary"),
    "applicabilite": ("providers_filtered", "plan", "skipped", "mission"),
    # `disponibilite` (PR #2, écrit par pipeline.py) écarte les providers dont
    # l'exécutable/base est absent : c'est le MÊME genre de décision que
    # `applicabilite` (des providers écartés avant le plan), donc le même kind du
    # contrat. Sans cette entrée, un événement connu était projeté en
    # `unknown_event_recorded` — le lecteur affirmait « inconnu » pour un fait consigné.
    "disponibilite": ("providers_filtered", "plan", "skipped", "mission"),
    "conditions": ("provider_conditions_evaluated", "policy", "skipped", "mission"),
    "plan": ("plan_created", "plan", "completed", "summary"),
    "contexte": ("execution_context_created", "execution", "started", "technical"),
    "execution": ("provider_completed", "execution", "completed", "mission"),
    "statuts": ("coverage_updated", "coverage", "completed", "mission"),
    "escalade": ("escalation_decided", "policy", "completed", "mission"),
    "cloture": ("mission_completed", "mission", "succeeded", "summary"),
    "arret": ("mission_stopped", "mission", "refused", "summary"),
    "reprise": ("mission_resumed", "mission", "started", "mission"),
}

_RESUMES = {
    "ouverture": "Mission créée",
    "confiance": "Périmètre de confiance consigné",
    "egress_accorde": "Sortie réseau autorisée",
    "egress_refuse": "Sortie réseau refusée",
    "intention_resolue": "Intention résolue",
    "intention_refusee": "Intention refusée",
    "applicabilite": "Providers filtrés par applicabilité",
    "disponibilite": "Providers filtrés par disponibilité",
    "conditions": "Conditions d'exécution évaluées",
    "plan": "Plan de mission créé",
    "contexte": "Contexte d'exécution créé",
    "execution_ok": "Analyse terminée",
    "execution_ko": "Analyse échouée",
    "statuts": "Couverture mise à jour",
    "escalade_ok": "Escalade décidée et autorisée",
    "escalade_ko": "Escalade décidée et refusée",
    "cloture": "Mission terminée",
    "reprise": "Mission reprise",
}


def _categorie_arret(motif: str) -> str:
    if motif == "policy" or motif == "policy_injoignable":
        return "policy"
    if motif.startswith("execution_"):
        return "system"
    return "mission"


def _resume_arret(motif: str) -> str:
    labels = {
        "policy": "refus de la politique",
        "policy_injoignable": "validation de sécurité indisponible",
        "conditions": "conditions d'exécution non remplies",
        "applicabilite": "aucun provider applicable",
        "intent_needs_clarification": "demande à clarifier",
        "intent_rejected": "demande refusée",
        "garde_chemin": "chemin refusé",
    }
    if motif.startswith("execution_"):
        return "Mission arrêtée : exécution interrompue"
    if motif.startswith("intent_"):
        return "Mission arrêtée : intention non résolue"
    return "Mission arrêtée : " + labels.get(motif, "arrêt consigné")


def _projeter_evenement(ev: dict, mid: str, ctx: dict) -> dict:
    """Un événement de journal → un événement timeline (allowlist, contrat §6)."""
    type_ = str(ev.get("type") or "")
    seq = ev["seq"]
    refs = {"mission_id": mid}
    limitations: list[str] = []
    data_state = "complete"
    # Provenance : projetée UNIQUEMENT si un fait est consigné (transport/protocole
    # détenus par le producteur, MCP-004). Allowlist + grammaire, jamais devinée.
    provenance = _provenance(ev.get("provenance"))

    if type_ in _REGISTRE:
        kind, category, consequence, visibility = _REGISTRE[type_]
    else:
        kind, category, consequence, visibility = ("unknown_event_recorded", "unknown",
                                                   "recorded", "technical")
        data_state = "unavailable"
        limitations.append("projection_version_unsupported")

    # --- références et conséquence selon le contenu
    if type_ == "ouverture":
        resume = _RESUMES["ouverture"]
    elif type_ == "confiance":
        resume = _RESUMES["confiance"]
    elif type_ == "egress":
        autorise = bool(ev.get("autorise"))
        consequence = "recorded" if autorise else "refused"
        resume = _RESUMES["egress_accorde" if autorise else "egress_refuse"]
    elif type_ == "intention":
        consequence = "completed" if ev.get("statut") == "resolved" else "refused"
        resume = _RESUMES["intention_resolue" if consequence == "completed" else "intention_refusee"]
    elif type_ == "applicabilite":
        n = len(ev.get("ecartes") or {})
        resume = _RESUMES["applicabilite"] + (f" ({n} écarté(s))" if n else "")
    elif type_ == "disponibilite":
        n = len(ev.get("ecartes") or {})
        resume = _RESUMES["disponibilite"] + (f" ({n} écarté(s))" if n else "")
    elif type_ == "conditions":
        n = len(ev.get("ecartes") or {})
        resume = _RESUMES["conditions"] + (f" ({n} bloqué(s))" if n else "")
    elif type_ == "plan":
        plan_id = _id_sur(ev.get("plan_id"))
        if plan_id:
            refs["plan_id"] = plan_id
            ctx["plan_id"] = plan_id
        resume = _RESUMES["plan"]
    elif type_ == "contexte":
        run_id = _id_sur(ev.get("run_id"))
        if run_id:
            refs["run_id"] = run_id
            ctx["run_id"] = run_id
        resume = _RESUMES["contexte"]
    elif type_ == "execution":
        prov = _id_sur(ev.get("provider"))
        if prov:
            refs["provider_id"] = prov
        if ctx.get("run_id"):
            refs["run_id"] = ctx["run_id"]
        code = ev.get("code_retour")
        timeout = ev.get("timeout")
        consequence = "failed" if (timeout or code not in (0, None)) else "completed"
        resume = _RESUMES["execution_ok" if consequence == "completed" else "execution_ko"]
    elif type_ == "statuts":
        if ev.get("en_cours"):
            consequence = "progress"
        resume = _RESUMES["statuts"]
    elif type_ == "escalade":
        allow = bool(ev.get("allow"))
        consequence = "completed" if allow else "refused"
        plan_id = _id_sur(ev.get("plan_id"))
        if plan_id:
            refs["plan_id"] = plan_id
        resume = _RESUMES["escalade_ok" if allow else "escalade_ko"]
    elif type_ == "cloture":
        if ctx.get("run_id"):
            refs["run_id"] = ctx["run_id"]
        resume = _RESUMES["cloture"]
    elif type_ == "arret":
        motif = str(ev.get("motif") or "")
        category = _categorie_arret(motif)
        consequence = "failed" if motif.startswith("execution_") else "refused"
        resume = _resume_arret(motif)
    elif type_ == "reprise":
        resume = _RESUMES["reprise"]
    else:
        resume = "Un événement non reconnu a été consigné"

    # --- horodatage : jamais fabriqué
    ts = _rfc3339(ev.get("ts"))
    if ts:
        temps = {"state": "recorded", "timestamp": ts}
    else:
        temps = {"state": "unavailable"}
        limitations.append("timestamp_missing")

    evenement = {
        "event_id": f"{mid}:{seq}",
        "position": seq,
        "source": {"kind": "journal", "sequence": seq},
        "time": temps,
        "category": category,
        "kind": kind,
        "consequence": consequence,
        "visibility": visibility,
        "safe_summary": _nettoyer(resume, borne=BORNE_RESUME),
        "references": refs,
        "data_state": data_state,
        "limitations": limitations,
    }
    if type_ not in _REGISTRE and _SOURCE_KIND.match(type_):
        evenement["source"]["source_kind"] = type_
    if provenance is not None:
        evenement["provenance"] = provenance
    return evenement


def _timeline(chemin: Path, mid: str, evenements: list[dict], anomalies: dict,
              timeline_limit: int, timeline_cursor: str | None) -> dict:
    """`data.timeline` conforme au contrat Timeline."""
    if anomalies.get("absent"):
        return {"schema_version": TIMELINE_VERSION, "state": "unavailable",
                "ordering": "journal_sequence_ascending", "events": [],
                "returned_events": 0, "total_events": 0, "truncated": False,
                "next_cursor": None, "limitations": ["journal_missing"]}
    if anomalies.get("illisible"):
        return {"schema_version": TIMELINE_VERSION, "state": "unavailable",
                "ordering": "journal_sequence_ascending", "events": [],
                "returned_events": 0, "total_events": 0, "truncated": False,
                "next_cursor": None, "limitations": ["journal_unreadable"]}

    ctx: dict = {}
    # Position = ordre de projection sur la timeline COMPLÈTE, pas par page.
    projetes = [_projeter_evenement(ev, mid, ctx) for ev in evenements]
    for i, ev in enumerate(projetes):
        ev["position"] = i + 1

    limitations: list[str] = []
    if anomalies.get("prefixe"):
        limitations.append("history_prefix_missing")
    if anomalies.get("trous") or anomalies.get("malforme"):
        limitations.append("history_gap_detected")
    if any(e["category"] == "unknown" for e in projetes):
        limitations.append("projection_version_unsupported")

    etat = "complete"
    if anomalies.get("prefixe") or anomalies.get("trous") or anomalies.get("malforme") \
            or any(e["category"] == "unknown" for e in projetes):
        etat = "partial"

    # pagination
    depart = 0
    if timeline_cursor is not None:
        depart = _decoder_curseur_timeline(timeline_cursor)
    page = projetes[depart:depart + timeline_limit]
    tronque = len(projetes) > depart + timeline_limit
    prochain = None
    if tronque:
        dernier = page[-1]["position"]
        prochain = _encoder([dernier])

    return {"schema_version": TIMELINE_VERSION, "state": etat,
            "ordering": "journal_sequence_ascending", "events": page,
            "returned_events": len(page), "total_events": len(projetes),
            "truncated": tronque, "next_cursor": prochain,
            "limitations": list(dict.fromkeys(limitations))}


# --------------------------------------------------------------------------- exécutions
def _dim(value: str, proof: str, reason_code: str | None = None) -> dict:
    d: dict = {"value": value, "proof": proof}
    if reason_code:
        d["reason_code"] = reason_code
    return d


def _ledger_de(chemin: Path, rapport) -> list[dict] | None:
    """Le ledger final des six étapes : rapport.json.statuts, sinon le dernier
    événement `statuts` du journal (outils)."""
    if isinstance(rapport, dict) and isinstance(rapport.get("statuts"), list):
        return rapport["statuts"]
    return None


def _ledger_journal(evenements: list[dict]) -> list[dict] | None:
    for ev in reversed(evenements):
        if ev.get("type") == "statuts" and isinstance(ev.get("outils"), list):
            return ev["outils"]
    return None


def _fournisseurs_du_plan(plan) -> list[str]:
    if not isinstance(plan, dict):
        return []
    return [str(s.get("provider")) for s in (plan.get("steps") or [])
            if isinstance(s, dict) and s.get("provider")]


def _execution_depuis_ledger(e: dict, plan_sel: dict, decision_allow, arret_motif: str,
                             in_plan: bool, n: int, cibles: int,
                             terminal: bool = False) -> dict:
    """Un enregistrement `execution-status.v1` depuis une entrée du ledger."""
    pid = _id_sur(e.get("provider")) or str(e.get("provider") or "provider")
    cap = _id_sur(e.get("capability"))
    outil = e.get("outil") or pid
    statut = e.get("statut")
    dispo = e.get("disponible")
    timeout = bool(e.get("timeout"))
    en_cours = bool(e.get("en_cours"))
    rien_trouve = bool(e.get("rien_trouve"))
    code_retour = e.get("code_retour")

    appl = plan_sel.get("applicabilite") or {}
    conds = plan_sel.get("conditions") or {}

    # Applicabilité / condition / sélection (structure du plan, pas de texte libre)
    if pid in conds and pid not in appl:
        applicability = _dim("inconnu", "unknown")
        condition = _dim("bloquee", "recorded")
    elif pid in appl:
        applicability = _dim("non_applicable", "recorded")
        condition = _dim("inconnu", "unknown")
    elif in_plan:
        applicability = _dim("applicable", "recorded")
        condition = _dim("remplie", "derived")
    else:
        applicability = _dim("inconnu", "unknown")
        condition = _dim("inconnu", "unknown")

    if pid in appl or pid in conds:
        selection = _dim("non_selectionne", "recorded")
    elif in_plan:
        selection = _dim("selectionne", "recorded")
    else:
        selection = _dim("inconnu", "unknown")

    # Autorisation
    if in_plan:
        if decision_allow is True:
            authorization = _dim("autorise", "recorded")
        elif decision_allow is False and arret_motif in ("policy_injoignable",):
            authorization = _dim("non_evalue", "recorded", "policy_unavailable")
        elif decision_allow is False:
            authorization = _dim("non_autorise", "recorded", "policy_denied")
        else:
            authorization = _dim("non_evalue", "unknown", "policy_unavailable")
    else:
        authorization = _dim("non_evalue", "derived", "not_in_plan")

    # Disponibilité
    if dispo is True:
        availability = _dim("disponible", "recorded")
    elif dispo is False:
        availability = _dim("indisponible", "recorded", "binary_missing")
    else:
        availability = _dim("inconnu", "unknown")

    # Exécution
    if statut == "non_disponible":
        execution = {"value": "unavailable", "invocation": "non",
                     "output": "non_exploitable", "proof": "recorded",
                     "reason_code": "binary_missing"}
        detection = _dim("non_evalue", "recorded")
    elif statut == "non_applicable":
        raison = "condition_blocked" if (pid in conds and pid not in appl) else "target_not_applicable"
        execution = {"value": "non_lance", "invocation": "non",
                     "output": "non_exploitable", "proof": "recorded",
                     "reason_code": raison}
        detection = _dim("non_evalue", "recorded")
    elif statut == "non_selectionne":
        execution = {"value": "non_lance", "invocation": "non",
                     "output": "non_exploitable", "proof": "recorded",
                     "reason_code": "not_in_plan"}
        detection = _dim("non_evalue", "recorded")
    elif statut == "non_autorise":
        injoignable = arret_motif == "policy_injoignable"
        execution = {"value": "non_lance", "invocation": "non",
                     "output": "non_exploitable", "proof": "recorded",
                     "reason_code": "policy_unavailable" if injoignable else "policy_denied"}
        detection = _dim("non_evalue", "recorded")
    elif statut == "selectionne":
        if en_cours and terminal:
            # La mission est CLOSE (cloture ou arret terminal) et le ledger dit encore
            # « en cours » : l'exécution a été INTERROMPUE, elle ne tourne plus. Annoncer
            # `en_cours` sur une mission close serait un mensonge observable — et
            # `cancelled` est la valeur du contrat pour ça. Aucun finding n'en est déduit.
            execution = {"value": "cancelled", "invocation": "oui",
                         "output": "non_exploitable", "proof": "recorded",
                         "reason_code": "mission_closed_while_running"}
        elif en_cours:
            execution = {"value": "en_cours", "invocation": "oui",
                         "output": "inconnu", "proof": "recorded"}
        else:
            execution = {"value": "non_lance", "invocation": "non",
                         "output": "non_exploitable", "proof": "recorded",
                         "reason_code": "mission_stopped_before_execution"}
        detection = _dim("non_evalue", "recorded")
    elif statut == "echoue":
        if timeout:
            execution = {"value": "timed_out", "invocation": "oui",
                         "output": "non_exploitable", "proof": "recorded",
                         "reason_code": "deadline_exceeded"}
        else:
            execution = {"value": "echoue", "invocation": "oui",
                         "output": "non_exploitable", "proof": "recorded",
                         "reason_code": "local_failure"}
        detection = _dim("non_evalue", "recorded")
    elif statut == "execute":
        execution = {"value": "termine", "invocation": "oui",
                     "output": "exploitable", "proof": "recorded"}
        if rien_trouve and cibles > 0:
            detection = {"value": "rien_trouve", "proof": "recorded",
                         "findings_count": 0, "analyzed_targets": cibles}
        elif n > 0:
            detection = {"value": "findings_presents", "proof": "recorded",
                         "findings_count": n}
        elif cibles == 0:
            detection = _dim("non_evalue", "recorded", "no_analyzed_target")
        else:
            detection = _dim("inconnu", "unknown", "findings_evidence_missing")
    else:
        execution = {"value": "inconnu", "invocation": "inconnu",
                     "output": "inconnu", "proof": "unknown",
                     "reason_code": "unknown_source_status"}
        detection = _dim("inconnu", "unknown", "unknown_source_status")

    # Complétude
    if statut in ("execute", "echoue", "non_disponible", "non_applicable",
                  "non_selectionne", "non_autorise", "selectionne"):
        completeness = {"state": "complete", "missing": [], "limitations": []}
    else:
        completeness = {"state": "unavailable",
                        "missing": ["execution_ledger"],
                        "limitations": ["unknown_source_status"]}

    record: dict = {
        "schema_version": EXECUTION_VERSION,
        "provider_id": pid,
        "applicability": applicability,
        "selection": selection,
        "condition": condition,
        "authorization": authorization,
        "availability": availability,
        "execution": execution,
        "detection": detection,
        "completeness": completeness,
    }
    if cap:
        record["capability_id"] = cap
    record["display_name"] = _nettoyer(str(outil), borne=160) or pid
    provenance = _provenance(e.get("provenance"))
    if provenance is not None:
        record["provenance"] = provenance
    return record


def _execution_legacy(pid: str, in_plan: bool, exclus_applicabilite: bool,
                      execution_ev: dict | None, arret_motif: str) -> dict:
    """Enregistrement `execution-status.v1` depuis le journal seul (anciennes
    missions sans ledger). Les faits non prouvés restent `inconnu`/`non_evalue`."""
    if exclus_applicabilite:
        applicability = _dim("non_applicable", "recorded")
        selection = _dim("non_selectionne", "recorded")
        authorization = _dim("non_evalue", "derived", "not_in_plan")
    elif in_plan:
        applicability = _dim("applicable", "derived")
        selection = _dim("selectionne", "recorded")
        if execution_ev is not None:
            authorization = _dim("autorise", "derived")
        elif arret_motif == "policy":
            authorization = _dim("non_autorise", "recorded", "policy_denied")
        elif arret_motif == "policy_injoignable":
            authorization = _dim("non_evalue", "recorded", "policy_unavailable")
        elif arret_motif.startswith("intent_") or arret_motif in ("conditions", "applicabilite"):
            authorization = _dim("non_evalue", "recorded", "mission_stopped_before_execution")
        else:
            authorization = _dim("inconnu", "unknown")
    else:
        applicability = _dim("inconnu", "unknown")
        selection = _dim("inconnu", "unknown")
        authorization = _dim("inconnu", "unknown")

    if execution_ev is None:
        if exclus_applicabilite:
            raison = "target_not_applicable"
        elif in_plan:
            raison = "mission_stopped_before_execution"
        else:
            raison = "not_in_plan"
        execution = {"value": "non_lance", "invocation": "non",
                     "output": "non_exploitable", "proof": "derived",
                     "reason_code": raison}
        detection = _dim("non_evalue", "derived")
        availability = _dim("inconnu", "unknown")
        completeness = {"state": "complete", "missing": [], "limitations": []}
    else:
        timeout = bool(execution_ev.get("timeout"))
        code = execution_ev.get("code_retour")
        n = execution_ev.get("findings")
        ok = (code in (0, None)) and not timeout
        execution = {"value": "termine" if ok else ("timed_out" if timeout else "echoue"),
                     "invocation": "oui",
                     "output": "exploitable" if ok else "non_exploitable",
                     "proof": "recorded"}
        if not ok:
            execution["reason_code"] = "deadline_exceeded" if timeout else "local_failure"
        availability = _dim("disponible", "derived")
        if not ok:
            detection = _dim("non_evalue", "recorded",
                             "deadline_exceeded" if timeout else "local_failure")
            completeness = {"state": "complete", "missing": [], "limitations": []}
        elif isinstance(n, int) and n > 0:
            detection = {"value": "findings_presents", "proof": "recorded",
                         "findings_count": n}
            completeness = {"state": "complete", "missing": [], "limitations": []}
        else:
            # Exécution terminée, zéro finding : sans preuve de cibles analysées,
            # rien_trouve est interdit → inconnu.
            detection = _dim("inconnu", "unknown", "findings_evidence_missing")
            completeness = {"state": "partial",
                            "missing": ["analyzed_targets"],
                            "limitations": []}

    record: dict = {
        "schema_version": EXECUTION_VERSION,
        "provider_id": pid,
        "applicability": applicability,
        "selection": selection,
        "condition": _dim("inconnu", "unknown"),
        "authorization": authorization,
        "availability": availability,
        "execution": execution,
        "detection": detection,
        "completeness": completeness,
        "display_name": pid,
    }
    provenance = _provenance((execution_ev or {}).get("provenance"))
    if provenance is not None:
        record["provenance"] = provenance
    return record


def _executions(chemin: Path, evenements: list[dict], plan, rapport) -> list[dict]:
    """`data.executions[]` conforme au contrat Execution Status."""
    decision = (rapport or {}).get("autorisation") if isinstance(rapport, dict) else None
    decision_allow = decision.get("allow") if isinstance(decision, dict) else None
    arret_motif = _motif_terminal(evenements) or ""
    # La mission est-elle CLOSE ? Un provider encore « en cours » dans le ledger d'une
    # mission close a été interrompu, il ne tourne plus (→ `cancelled`).
    terminal = _evenement_terminal(evenements) is not None

    plan_sel = (plan or {}).get("selection") if isinstance(plan, dict) else None
    plan_sel = plan_sel if isinstance(plan_sel, dict) else {}
    in_plan = _fournisseurs_du_plan(plan)

    ledger = _ledger_de(chemin, rapport) or _ledger_journal(evenements)
    if ledger is not None:
        records = []
        for e in ledger:
            if not isinstance(e, dict) or not e.get("provider"):
                continue
            pid = str(e.get("provider"))
            records.append(_execution_depuis_ledger(
                e, plan_sel, decision_allow, arret_motif,
                pid in in_plan, int(e.get("findings") or 0),
                int(e.get("cibles_analysees") or 0), terminal=terminal))
        return records

    # Fallback anciennes missions : journal seul (ouverture/plan/execution/…).
    plan_providers: list[str] = []
    for ev in evenements:
        if ev.get("type") == "plan" and isinstance(ev.get("providers"), list):
            plan_providers = [str(p) for p in ev["providers"]]
    exclus: set[str] = set()
    for ev in evenements:
        if ev.get("type") == "applicabilite" and isinstance(ev.get("ecartes"), dict):
            exclus |= {str(k) for k in ev["ecartes"]}
    executions: dict[str, dict] = {}
    for ev in evenements:
        if ev.get("type") == "execution" and ev.get("provider"):
            executions.setdefault(str(ev["provider"]), ev)

    vus: list[str] = []
    for pid in plan_providers + sorted(exclus) + sorted(executions):
        if pid not in vus:
            vus.append(pid)
    return [_execution_legacy(pid, pid in plan_providers, pid in exclus,
                              executions.get(pid), arret_motif) for pid in vus]


# --------------------------------------------------------------------------- détail
def _plan_sur(plan) -> dict | None:
    """Le plan, projeté SANS argv (commande/args = données d'exécution). Un plan
    vide (arrêt antérieur au plan) est rendu absent, pas en dict nul."""
    if not isinstance(plan, dict) or not plan:
        return None
    steps = []
    for s in plan.get("steps") or []:
        if not isinstance(s, dict):
            continue
        steps.append({k: s.get(k) for k in ("capability", "provider", "risque", "sorties")
                      if k in s})
    return {
        "plan_id": plan.get("plan_id"),
        "request_id": plan.get("request_id"),
        "requete_canonique": _nettoyer(plan.get("requete_canonique")),
        "moteur_intent": plan.get("moteur_intent"),
        "cree_le": plan.get("cree_le"),
        "steps": _assainir(steps),
        "selection": _assainir(plan.get("selection") or {}),
    }


def _rapport_sur(rapport) -> dict | None:
    if not isinstance(rapport, dict) or not rapport:
        return None
    return _assainir({
        "requete": rapport.get("requete"),
        "capacites_demandees": rapport.get("capacites_demandees"),
        "motifs_intent": rapport.get("motifs_intent"),
        "plan_id": rapport.get("plan_id"),
        "plan_empreinte": rapport.get("plan_empreinte"),
        "autorisation": rapport.get("autorisation"),
        "egress": rapport.get("egress"),
        "outils_par_vague": rapport.get("outils_par_vague"),
        "statuts": rapport.get("statuts"),
        "escalades": rapport.get("escalades"),
    })


def _intent_sur(intent_json, evenements: list[dict]):
    if isinstance(intent_json, dict) and intent_json:
        return _assainir(intent_json)
    for ev in evenements:
        if ev.get("type") == "intention":
            return _assainir(ev)
    return None


def projeter(mission_id: str, racine=None, *, timeline_limit=None,
             timeline_cursor: str | None = None, proprietaire=None) -> dict:
    """La projection COMPLÈTE d'une mission (détail, contrat History §6)."""
    racine = _racine(racine)
    chemin = _chemin_mission(mission_id, racine)
    if chemin is None or not (chemin / "mission.json").is_file():
        raise MissionIntrouvable(mission_id)

    if timeline_limit is None or timeline_limit == "":
        timeline_limit = TIMELINE_LIMIT_DEFAUT
    elif isinstance(timeline_limit, str):
        try:
            timeline_limit = int(timeline_limit)
        except ValueError:
            raise RequeteInvalide(
                f"timeline_limit invalide : {timeline_limit!r} — entier entre 1 et {TIMELINE_LIMIT_MAX}")
    if (isinstance(timeline_limit, bool) or not isinstance(timeline_limit, int)
            or not 1 <= timeline_limit <= TIMELINE_LIMIT_MAX):
        raise RequeteInvalide(
            f"timeline_limit invalide : {timeline_limit!r} — entier entre 1 et {TIMELINE_LIMIT_MAX}")

    entete = _lire_json(chemin / "mission.json")
    evenements, anomalies = lire_journal(chemin)
    statut, incomplete = statut_mission(
        evenements, proprietaire and (lambda: proprietaire(mission_id)))

    plan = _lire_json(_resoudre_artefact(chemin, "plan.json"))
    rapport = _lire_json(_resoudre_artefact(chemin, "rapport.json"))
    findings = _lire_json(_resoudre_artefact(chemin, "findings.json"))
    clusters = _lire_json(_resoudre_artefact(chemin, "clusters.json"))
    run = _lire_json(_resoudre_artefact(chemin, "run.json"))
    intent_json = _lire_json(_resoudre_artefact(chemin, "intent.json"))
    rapport_md = _rapport_lisible(chemin)
    run_id = _run_id_de(evenements, chemin)

    donnees: dict = {}
    donnees["request"] = {
        "original": _titre((entete or {}).get("requete")),
        "canonical": _nettoyer((entete or {}).get("requete_canonique"), borne=BORNE_TITRE),
    }
    intent = _intent_sur(intent_json, evenements)
    if intent is not None:
        donnees["intent"] = intent
    plan_sur = _plan_sur(plan)
    if plan_sur is not None:
        donnees["plan"] = plan_sur
    if statut == "termine" and isinstance(findings, list):
        donnees["findings"] = _assainir(findings)
    if statut == "termine" and isinstance(clusters, dict):
        donnees["clusters"] = _assainir(clusters)
    if rapport_md is not None:
        try:
            contenu = rapport_md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            contenu = ""
        donnees["report"] = {"available": True, "format": "markdown",
                             "content": _nettoyer(contenu, borne=BORNE_RAPPORT)}
    if isinstance(rapport, dict):
        couverture = rapport.get("couverture")
        if isinstance(couverture, dict):
            donnees["coverage"] = _assainir(couverture)

    donnees["executions"] = _executions(chemin, evenements, plan, rapport)
    donnees["execution_status_schema"] = EXECUTION_VERSION

    # Legacy minimal (séquence, horodatage, kind, message sûr) — jamais fusionné
    # dans les comptes de la timeline.
    events_legacy = []
    ctx: dict = {}
    for ev in evenements:
        proj = _projeter_evenement(ev, mission_id, ctx)
        events_legacy.append({
            "sequence": proj["source"]["sequence"],
            "timestamp": proj["time"].get("timestamp"),
            "kind": proj["kind"],
            "safe_message": proj["safe_summary"],
        })
    donnees["events"] = events_legacy

    donnees["timeline"] = _timeline(chemin, mission_id, evenements, anomalies,
                                    timeline_limit, timeline_cursor)

    manquants = _artefacts_manquants(chemin, statut, anomalies, run_id)

    return {
        "schema_version": HISTORY_VERSION,
        "mission": resumer(chemin, evenements, anomalies, statut, incomplete),
        "data": donnees,
        "missing_artifacts": list(dict.fromkeys(manquants)),
    }
