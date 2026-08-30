"""Mission History — le lecteur canonique de l'historique des Missions.

Ce que ce module EST : la SOURCE UNIQUE de lecture de l'historique des missions.
L'API HTTP (`PHASE3/interface/api.py`) ne projette rien elle-même — elle délègue
ici, pour que le listing et le détail racontent la MÊME histoire, avec le MÊME
vocabulaire, depuis les MÊMES artefacts. Les suites (`test_mission_history_api.py`)
jugent ce module au travers de l'API, mais le contrat vit ici.

Ce que ce module N'EST PAS :

    · il n'écrit rien (aucun index, aucune base, aucun cache persistant, aucun
      nouvel artefact) — il RELIT l'archive append-only (`mission.json`,
      `journal.jsonl`, `<mission>/sortie`, `<mission>/run`) ;
    · il ne décide rien : la projection de statut est DÉRIVÉE des événements du
      journal, jamais saisie ;
    · il ne publie jamais de donnée brute : chemin absolu, argv, sortie provider,
      stack trace, finding brut, endpoint, credential, rapport complet — tout
      passe par une projection sûre (cf. `assainissement.py`).

Cardinalité lue (contrat) : une Mission → zéro ou un Run. Un POST `/api/runs` crée
un identifiant de file TEMPORAIRE ; l'identifiant durable est le `mission_id` du
dossier de mission. Relancer une analyse = une NOUVELLE Mission.

Statuts canoniques (vocabulaire fermé) :

    en_file    mission ouverte, run non commencé (pas encore de run_id)
    en_cours   run commencé (événement `contexte` avec run_id), pas d'issue terminale
    termine    événement `cloture` présent — jamais déduit d'autre chose
    refuse     arrêt intentionnel / applicabilité / conditions / policy / fail-closed
    erreur     arrêt technique explicite (exécution interrompue)
    inconnu    journal absent ou vide : aucun état ne peut être prouvé

La projection `indisponible` (disponibilité API/provider) n'est PAS un statut de
mission : elle n'apparaît jamais ici.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import assainissement as ASS
import cible as CIB
import mission as MS

# --------------------------------------------------------------------------- vocabulaire
STATUTS = ("en_file", "en_cours", "termine", "refuse", "erreur", "inconnu")

LIMIT_DEFAUT = 25
LIMIT_MAX = 100

# Filtres v1 : SEULEMENT ces deux-là. Tout autre paramètre est refusé par l'API.
FILTRES_V1 = ("status", "target_type")

# Identifiant de mission : m-AAAAAMMJJTHHMMSSZ-xxxxxxxx (8 hex). L'identifiant est
# validé AVANT toute lecture filesystem : c'est la première barrière contre le
# traversal (`..`, `/`, `%2f`…).
_ID_MISSION = re.compile(r"^m-\d{8}T\d{6}Z-[0-9a-f]{8}$")

# Le type « inféré » historique de mission.py (`repertoire`/`fichier`) rejoint le
# vocabulaire `target_types` (`repository`/`filesystem`) pour la projection et le
# filtre. Ancienne mission sans descripteur → toujours lisible.
LEGACY_TYPES = {"repertoire": "repository", "fichier": "filesystem"}

# Artefacts attendus d'une archive, selon l'issue de la mission. Un artefact absent
# n'est PAS un « zéro » : il est déclaré dans `missing_artifacts`.
ARTEFACTS_TERMINE = ("plan.json", "findings.json", "clusters.json", "rapport.json", "run.json")
ARTEFACTS_INTERROMPU = ("intent.json", "plan.json")

# Bornes de projection sûre : un texte plus long est tronqué (l'archive complète
# reste la source de vérité pour l'opérateur ; l'API, elle, ne débite pas de blobs).
BORNE_TEXTE = 1000
BORNE_ERREUR = 300

# --------------------------------------------------------------------------- erreurs
class MissionIntrouvable(Exception):
    """mission_id valide mais aucun dossier de mission lisible. → 404, sans chemin."""


class RequeteInvalide(Exception):
    """Paramètre de lecture invalide (limit, curseur, filtre). → 400, explicite."""


# --------------------------------------------------------------------------- racine
def racine_par_defaut() -> Path:
    """La racine des missions, lue VIVANTE au moment de l'appel (les tests
    patchent `mission.MISSIONS` — une copie à l'import les raterait)."""
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
    `<mission>/run/` est le répertoire de travail du pipeline. On ne sonde JAMAIS
    ailleurs (pas de `..`, pas de chemin libre) — les noms sont dans une liste
    fermée de noms de fichiers d'archive.
    """
    for sous in ("sortie", "run"):
        base = chemin / sous
        for nom in noms:
            p = base / nom
            if p.is_file():
                return p
    return None


def lire_journal(chemin: Path) -> list[dict]:
    """Le journal append-only, lu avec tolérance : une ligne abîmée est ignorée,
    jamais fatale. Un journal absent rend `[]` (→ statut `inconnu`, pas une panne)."""
    p = chemin / "journal.jsonl"
    if not p.is_file():
        return []
    evenements: list[dict] = []
    for ligne in p.read_text(encoding="utf-8", errors="replace").splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            evenements.append(json.loads(ligne))
        except ValueError:
            continue
    return evenements


def _dirs_missions(racine: Path):
    """Les dossiers de mission lisibles, dans l'ordre inverse du temps (recent
    d'abord). Aucun symlink (un lien sortant lirait hors de la racine), aucun
    chemin hors de la racine, uniquement les dossiers portant un `mission.json`."""
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
    """Valide l'identifiant AVANT de toucher au filesystem, puis borne la
    résolution à la racine (refus des `..`, des symlinks sortants, de tout
    chemin qui s'échappe). Rend `None` = introuvable, sans jamais lever."""
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


# --------------------------------------------------------------------------- statut
# Arrêts NON terminaux : consignés au journal (`_consigner_arret`) sans interrompre
# la mission — ils ne décident d'aucun statut.
ARRETS_NON_TERMINAUX = ("escalade_policy_injoignable",)


def _arret_terminal(motif) -> bool:
    """Un événement `arret` décide-t-il de l'issue de la mission ?"""
    return str(motif or "").strip() not in ARRETS_NON_TERMINAUX


def _motif_erreur(motif) -> bool:
    """Arrêt technique explicite (exécution interrompue), par opposition au refus."""
    return str(motif or "").startswith("execution_")


def _evenement_terminal(evenements: list[dict]) -> dict | None:
    """Le DERNIER événement terminal du journal, dans l'ordre d'écriture.

    `cloture` (succès) et `arret` terminal (refus/erreur) s'excluent dans une
    mission saine ; s'ils coexistaient, le dernier en séquence l'emporte — le
    journal append-only est la source, pas une préférence de lecteur."""
    terminal = None
    for ev in evenements:
        t = ev.get("type")
        if t == "cloture":
            terminal = ev
        elif t == "arret" and _arret_terminal(ev.get("motif")):
            terminal = ev
    return terminal


def statut_mission(evenements: list[dict]) -> str:
    """Projection de statut UNIQUE, partagée par le listing et le détail.

    Règles :
      · `cloture`                        → `termine` (jamais déduit d'autre chose) ;
      · `arret` intention/applicabilité/conditions/policy/fail-closed → `refuse` ;
      · `arret` technique (`execution_*`)                           → `erreur` ;
      · activité non terminale : `contexte` présent → `en_cours`, sinon `en_file` ;
      · journal vide ou absent                                       → `inconnu`.
    """
    ev = _evenement_terminal(evenements)
    if ev is None:
        if any(e.get("type") == "contexte" for e in evenements):
            return "en_cours"
        return "en_file" if evenements else "inconnu"
    if ev.get("type") == "cloture":
        return "termine"
    return "erreur" if _motif_erreur(ev.get("motif")) else "refuse"


def _motif_terminal(evenements: list[dict]) -> str | None:
    """La cause de l'issue : le motif de l'arrêt, ou « cloture »."""
    ev = _evenement_terminal(evenements)
    if ev is None:
        return None
    return "cloture" if ev.get("type") == "cloture" else str(ev.get("motif") or "")


# --------------------------------------------------------------------------- projection sûre
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_URI_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
_ABSOLU = re.compile(r"(?:/[A-Za-z0-9._@~+-]+){1,}/?")


def _reference_sure(reference: str, local: bool = False) -> str:
    """La référence de cible sans secret, sans userinfo, sans chemin absolu.

    · URI : le `userinfo` (`user:pass@`) est retiré ;
    · chemin local absolu : réduit à son nom (la projection n'expose pas le
      filesystem de la machine d'analyse).
    """
    reference = str(reference or "").strip()
    if not reference:
        return ""
    if _URI.match(reference):
        from urllib.parse import urlsplit, urlunsplit
        try:
            parts = urlsplit(reference)
            if parts.username is None and parts.password is None:
                return reference
            hote = parts.hostname or ""
            if parts.port:
                hote = f"{hote}:{parts.port}"
            return urlunsplit((parts.scheme, hote, parts.path, parts.query, parts.fragment))
        except ValueError:
            return reference
    p = Path(reference)
    if p.is_absolute():
        return p.name
    return reference


def cible_sure(entete) -> dict:
    """Projection API dédiée de la cible : `type` + référence sûre + `local`.

    Jamais `Cible.reference` brute, jamais de chemin absolu, `target_type`
    toujours fourni. Compatible avec les anciennes missions sans
    `cible.descripteur` (le `type` legacy `repertoire`/`fichier` est traduit)."""
    if not isinstance(entete, dict):
        return {"type": "inconnu", "reference": "", "local": False}
    cib = entete.get("cible")
    if not isinstance(cib, dict):
        return {"type": "inconnu", "reference": "", "local": False}
    descr = cib.get("descripteur")
    if isinstance(descr, dict) and descr.get("type"):
        typ = str(descr["type"]).strip()
        return {"type": typ,
                "reference": _reference_sure(str(descr.get("reference") or ""),
                                             local=typ in CIB.TYPES_LOCAUX),
                "local": typ in CIB.TYPES_LOCAUX}
    # Ancienne mission : `chemin` + `type` inféré.
    typ_legacy = str(cib.get("type") or "").strip()
    typ = LEGACY_TYPES.get(typ_legacy, typ_legacy or "inconnu")
    return {"type": typ,
            "reference": _reference_sure(str(cib.get("chemin") or ""),
                                         local=typ in CIB.TYPES_LOCAUX),
            "local": typ in CIB.TYPES_LOCAUX}


def _rediger_chemins(texte: str) -> str:
    """Remplace les chemins absolus par `<chemin>`, en épargnant les URI.

    Un chemin absolu est une donnée de la machine d'analyse : le publier dans
    l'historique ferait fuir le filesystem. Les URI (`scheme://…`) sont protégées
    par le découpage — on ne redacte pas un schéma, seulement un chemin nu."""
    if not texte:
        return texte
    out, pos = [], 0
    for m in _URI_TOKEN.finditer(texte):
        out.append(_ABSOLU.sub("<chemin>", texte[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_ABSOLU.sub("<chemin>", texte[pos:]))
    return "".join(out)


def _nettoyer(texte, borne: int = BORNE_TEXTE) -> str:
    """Masque les secrets, redacte les chemins absolus, borne la longueur."""
    if not isinstance(texte, str):
        return texte
    texte, _ = ASS.masquer(texte)
    texte = _rediger_chemins(texte)
    if len(texte) > borne:
        texte = texte[:borne] + "…"
    return texte


_TRACEBACK = re.compile(r"Traceback \(most recent call last\):\s*")


def _nettoyer_erreur(texte) -> str:
    """Le champ `erreur` d'un arrêt : texte sur une ligne, borné court. C'est le
    champ le plus susceptible de porter un fragment de stack trace ou un chemin.
    L'en-tête de traceback est retiré, les chemins absolus sont redactés, les
    secrets masqués — une stack trace ne se publie jamais telle quelle."""
    texte = str(texte or "").replace("\r", " ").replace("\n", " ")
    texte = _TRACEBACK.sub("", texte)
    return _nettoyer(texte, borne=BORNE_ERREUR)


def _assainir(obj):
    """Projection sûre récursive : masque + redaction de chemins sur chaque chaîne."""
    if isinstance(obj, str):
        return _nettoyer(obj)
    if isinstance(obj, list):
        return [_assainir(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _assainir(v) for k, v in obj.items()}
    return obj


def _evenement_sur(ev: dict) -> dict:
    """Un événement du journal, assaini. `cible` (la référence brute du `ouverture`,
    un chemin absolu) est retirée — la projection sûre de la cible vit ailleurs."""
    out = {}
    for k, v in ev.items():
        if k == "cible":
            continue
        if k == "erreur" and ev.get("type") == "arret":
            out[k] = _nettoyer_erreur(v)
        else:
            out[k] = _assainir(v)
    return out


def _plan_sur(plan) -> dict | None:
    """Le plan, projeté SANS argv : `commande` et `args` sont des données
    d'exécution (commandes, chemins) que l'historique ne publie pas. Un plan vide
    (`{}`, posé par les arrêts antérieurs au plan) est rendu absent, pas en dict nul."""
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
        "requete": _nettoyer(plan.get("requete")),
        "requete_canonique": plan.get("requete_canonique"),
        "moteur_intent": plan.get("moteur_intent"),
        "cree_le": plan.get("cree_le"),
        "steps": _assainir(steps),
        "selection": _assainir(plan.get("selection") or {}),
    }


def _rapport_sur(rapport) -> dict | None:
    """Le rapport, projeté : la couverture, les statuts et les escalades, sans le
    corps complet (clusters/findings) qui vit dans ses propres champs."""
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


# --------------------------------------------------------------------------- comptage
def _compte_findings(chemin: Path, statut: str):
    """Le nombre de findings, PROUVÉ par un artefact lisible. `None` = non prouvé.

    Seule une mission `termine` dont `findings.json` est une liste lisible rend un
    nombre — y compris 0 (`[]` est une preuve). Une exécution interrompue, ou un
    fichier absent/illisible, rend `None` : jamais un « 0 » fabriqué."""
    if statut != "termine":
        return None
    doc = _lire_json(_resoudre_artefact(chemin, "findings.json"))
    return len(doc) if isinstance(doc, list) else None


def _compte_clusters(chemin: Path, statut: str):
    if statut != "termine":
        return None
    doc = _lire_json(_resoudre_artefact(chemin, "clusters.json"))
    if not isinstance(doc, dict):
        return None
    cls = doc.get("clusters")
    return len(cls) if isinstance(cls, list) else None


def _run_id_de(evenements: list[dict], chemin: Path) -> str | None:
    for ev in evenements:
        if ev.get("type") == "contexte" and ev.get("run_id"):
            return str(ev["run_id"])
    run = _lire_json(_resoudre_artefact(chemin, "run.json"))
    return (run or {}).get("run_id") or None


def _artefacts_manquants(chemin: Path, statut: str) -> list[str]:
    """Les artefacts attendus et absents. Un artefact absent est déclaré tel quel,
    jamais remplacé par un « zéro »."""
    manquants: list[str] = []
    if not (chemin / "journal.jsonl").is_file():
        manquants.append("journal.jsonl")
    if statut == "termine":
        attendus = ARTEFACTS_TERMINE
    elif statut in ("refuse", "erreur"):
        attendus = ARTEFACTS_INTERROMPU
    else:
        attendus = ()
    for nom in attendus:
        if _resoudre_artefact(chemin, nom) is None:
            manquants.append(nom)
    return manquants


# --------------------------------------------------------------------------- résumé
def resumer(chemin: Path) -> dict:
    """La projection COMPACTE d'une mission (item de listing)."""
    entete = _lire_json(chemin / "mission.json")
    evenements = lire_journal(chemin)
    statut = statut_mission(evenements)
    return {
        "mission_id": chemin.name,
        "statut": statut,
        "cree_le": (entete or {}).get("cree_le"),
        "cible": cible_sure(entete),
        "requete": _nettoyer((entete or {}).get("requete") or ""),
        "findings": _compte_findings(chemin, statut),
        "run_id": _run_id_de(evenements, chemin),
        "detail_href": f"/api/missions/{chemin.name}",
    }


# --------------------------------------------------------------------------- curseur
def _encoder_curseur(cree_le, mission_id: str) -> str:
    brut = json.dumps([cree_le, mission_id], ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(brut).decode("ascii").rstrip("=")


def _decoder_curseur(token: str) -> tuple:
    try:
        pad = token + "=" * (-len(token) % 4)
        donnees = json.loads(base64.urlsafe_b64decode(pad.encode("ascii")).decode("utf-8"))
    except Exception:
        raise RequeteInvalide(f"curseur invalide : {token!r}")
    if (not isinstance(donnees, list) or len(donnees) != 2
            or not all(isinstance(x, str) for x in donnees)):
        raise RequeteInvalide(f"curseur invalide : {token!r}")
    return tuple(donnees)


# --------------------------------------------------------------------------- listing
def lister(racine=None, *, limit=None, curseur: str | None = None,
           status: str | None = None, target_type: str | None = None) -> dict:
    """Listing paginé, trié `created_at DESC, mission_id DESC`.

    `limit` : 1..100 (défaut 25) — absent, non entier ou hors bornes = RequeteInvalide
    (→ 400). Accepte la forme brute de l'URL (chaîne) : la validation vit ICI, pas
    dans le transport.
    `curseur` : jeton opaque ; invalide = RequeteInvalide (→ 400).
    `status` : une valeur de STATUTS, sinon RequeteInvalide (→ 400).
    `target_type` : jeton du vocabulaire `target_types` ; filtre littéral (un
    jeton inconnu matche simplement rien — le vocabulaire est ouvert).
    """
    racine = _racine(racine)
    if limit is None or limit == "":
        limit = LIMIT_DEFAUT
    elif isinstance(limit, str):
        try:
            limit = int(limit)
        except ValueError:
            raise RequeteInvalide(
                f"limit invalide : {limit!r} — entier entre 1 et {LIMIT_MAX} "
                f"(défaut {LIMIT_DEFAUT})")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= LIMIT_MAX:
        raise RequeteInvalide(
            f"limit invalide : {limit!r} — entier entre 1 et {LIMIT_MAX} (défaut {LIMIT_DEFAUT})")
    if status is not None and status not in STATUTS:
        raise RequeteInvalide(f"status inconnu : {status!r} — admis : {list(STATUTS)}")

    items = [resumer(d) for d in _dirs_missions(racine)]
    items.sort(key=lambda i: (i.get("cree_le") or "", i["mission_id"]), reverse=True)

    if status is not None:
        items = [i for i in items if i["statut"] == status]
    if target_type is not None:
        items = [i for i in items if i["cible"]["type"] == target_type]

    if curseur is not None:
        cle = _decoder_curseur(curseur)
        items = [i for i in items if (i.get("cree_le") or "", i["mission_id"]) < cle]

    page = items[:limit]
    prochain = None
    if len(items) > limit:
        prochain = _encoder_curseur(page[-1].get("cree_le") or "", page[-1]["mission_id"])
    return {"items": page, "next_cursor": prochain}


# --------------------------------------------------------------------------- détail
def projeter(mission_id: str, racine=None) -> dict:
    """La projection COMPLÈTE d'une mission (détail). Lève MissionIntrouvable (404)
    sans jamais exposer de chemin."""
    racine = _racine(racine)
    chemin = _chemin_mission(mission_id, racine)
    if chemin is None or not (chemin / "mission.json").is_file():
        raise MissionIntrouvable(mission_id)

    entete = _lire_json(chemin / "mission.json")
    evenements = lire_journal(chemin)
    statut = statut_mission(evenements)
    cree_le = (entete or {}).get("cree_le")
    run_id = _run_id_de(evenements, chemin)

    plan = _lire_json(_resoudre_artefact(chemin, "plan.json"))
    findings = _lire_json(_resoudre_artefact(chemin, "findings.json"))
    clusters = _lire_json(_resoudre_artefact(chemin, "clusters.json"))
    rapport = _lire_json(_resoudre_artefact(chemin, "rapport.json"))
    run = _lire_json(_resoudre_artefact(chemin, "run.json"))
    intent_json = _lire_json(_resoudre_artefact(chemin, "intent.json"))

    # Findings : projetés seulement si l'artefact le prouve (mission termine + liste).
    if statut == "termine" and isinstance(findings, list):
        findings_proj = _assainir(findings)
        findings_count = len(findings)
    else:
        findings_proj = None
        findings_count = None

    clusters_proj = None
    if statut == "termine" and isinstance(clusters, dict):
        cls = clusters.get("clusters")
        clusters_proj = _assainir(cls) if isinstance(cls, list) else None

    # Intent : l'archive d'abord, le journal ensuite — même vocabulaire, un seul chemin.
    intent_doc = intent_json if isinstance(intent_json, dict) else next(
        (ev for ev in evenements if ev.get("type") == "intention"), None)

    provenance = _assainir({
        "run_id": run_id,
        "plan_id": (plan or {}).get("plan_id") or (run or {}).get("plan_id"),
        "request_id": (plan or {}).get("request_id"),
        "input_digest": (run or {}).get("input_digest"),
        "input_commit": (run or {}).get("input_commit"),
        "working_tree_dirty": (run or {}).get("working_tree_dirty"),
        "contexte_empreinte": (run or {}).get("execution_context_digest")
                              or (run or {}).get("contexte_empreinte"),
        "result_digest": (run or {}).get("result_digest"),
        "profil": (run or {}).get("execution_profile") or (run or {}).get("profil"),
    })

    return {
        "mission_id": mission_id,
        "statut": statut,
        "cree_le": cree_le,
        "resume": {
            "statut": statut,
            "motif": _motif_terminal(evenements),
            "findings": findings_count,
            "clusters": _compte_clusters(chemin, statut),
            "run_id": run_id,
        },
        "cible": cible_sure(entete),
        "requete": _nettoyer((entete or {}).get("requete") or ""),
        "requete_canonique": (entete or {}).get("requete_canonique"),
        "intent": _assainir(intent_doc) if isinstance(intent_doc, dict) else None,
        "run_id": run_id,
        "plan": _plan_sur(plan),
        "findings": findings_proj,
        "clusters": clusters_proj,
        "rapport": _rapport_sur(rapport),
        "couverture": _assainir((rapport or {}).get("couverture") or {}),
        "executions": [_evenement_sur(ev) for ev in evenements
                       if ev.get("type") == "execution"],
        "provenance": provenance,
        "evenements": [_evenement_sur(ev) for ev in evenements],
        "missing_artifacts": _artefacts_manquants(chemin, statut),
        "detail_href": f"/api/missions/{mission_id}",
    }
