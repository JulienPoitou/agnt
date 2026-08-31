"""Chargeur de plugins — un outil de plus sans toucher au pipeline.

Ce que ce module est, et ce qu'il n'est pas :

    IL EST      : une porte d'entrée et un CONTRÔLE. Il lit `PHASE3/plugins/*.yaml`, traduit
                  chaque fichier dans la représentation interne du registre (provider +
                  manifest), et fait refuser le fichier avant tout le reste si quelque chose
                  cloche.
    IL N'EST PAS: un second moteur. Ce qui est chargé ici devient un provider ORDINAIRE :
                  le plan, la policy, le sandbox, l'adaptateur, l'extraction, la couverture,
                  le rapport et l'écran le traitent par les mêmes fonctions que semgrep ou
                  detect-secrets. Aucun chemin spécial « plugin » n'existe en aval — c'est la
                  seule façon pour que la promesse « sans modifier le cœur » veuille dire
                  quelque chose.

Le format accepté est celui annoncé dans la commande du 2026-08-30, réduit à ce que le cœur
sait réellement lire :

    id: nmap
    capacites: [NETWORK_DISCOVERY]
    entrees: [hote, url]
    binaire: nmap
    outillage: nmap                # nom de l'entrée dans manifeste_dependances.yaml
    version_min: "7.9"
    priorite: 100
    execution:
      commande: ["{BIN}/nmap"]
      args: ["-oX", "{sortie}", "{TARGET}"]
      code_succes: [0, 1]
    sortie:
      format: xml                  # json | jsonl | sarif | csv | xml | custom
    lecture:
      modele: xml                  # plat | imbriqué | lignes_json | csv | xml
      nested_from: nmaprun/host
      nested_key: port
      contexte: {paquet_hote: "address@addr"}
      champs: {regle: "service@name", ligne: null}
    requirements:
      reseau: true
      privileges: aucun
      base_fichiers: []
      timeout_s: 900
      sandbox: true                # false est REFUSÉ, voir la règle 5 ci-dessous
    capacite:                      # UNIQUEMENT pour créer une capacité
      description: découverte de ports et de services
      domaines: [reseau]
      sortie: finding/port-ouvert
      mots_cles: [nmap, port, service]

Six règles ne sont pas négociables, et elles existent parce que chacune correspond à une
façon dont un dépôt de manifests détruirait silencieusement une garantie :

1. une clé INCONNUE est un refus, pas un ignoré (une faute de frappe sur `requirements:`
   équivaut à retirer une garde — c'est mesuré, section « Filet de sécurité » du registre) ;
2. un plugin ne peut pas redéfinir un provider ou une capacité existante (deux vérités) ;
3. le binaire doit être ÉPINGLÉ dans `manifeste_dependances.yaml` — c'est la porte : la
   liste des exécutables autorisés est une DONNÉE relue (version, source, licence, empreinte),
   pas un code à modifier, mais elle reste un fichier que le runtime ne peut pas s'écrire
   à lui-même ;
4. la licence déclarée par le plugin doit être CELLE de l'épingle (un plugin qui prétendrait
   « MIT » un outil GPL rendrait le dépôt incapable de répondre de sa redistribution) ;
5. `sandbox: false` est refusé. Un plugin ne peut pas demander à sortir de l'isolateur, ni
   implicitement ni explicitement ;
6. `reseau: true` est ADMIS à la déclaration et refusé à l'exécution tant que la mission
   n'a pas d'autorisation d'export : déclarer n'est pas pouvoir (voir conditions.py).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import provider_manifest as PM
import yaml

RACINE_SLICE = Path(__file__).resolve().parent
RACINE_PHASE3 = RACINE_SLICE.parent
DOSSIER_PLUGINS = Path(os.environ.get("AGNT_PLUGINS", RACINE_PHASE3 / "plugins"))

CLEFS_PLUGIN = ("id", "capacites", "entrees", "binaire", "outillage", "version_min",
                "priorite", "cout", "risque", "description", "execution", "sortie",
                "lecture", "requirements", "capacite", "licence", "a_verifier",
                "fichiers_requis")
CLEFS_EXECUTION = ("commande", "args", "code_succes", "env")
CLEFS_SORTIE = ("format", "fichier")
# `champs_secrets` (31/08/2026) : champs dont la VALEUR est un secret, masqués par
# structure dans les artefacts plutôt que reconnus par motif. Ajouté ici volontairement :
# une clé inconnue fait refuser le plugin, et c'est la règle — la liste est fermée pour
# qu'ajouter une garde soit un acte délibéré, pas un oubli.
CLEFS_LECTURE = ("modele", "items_from", "nested_from", "nested_key", "contexte", "champs",
                 "separateur", "parser", "masquer_large", "jetons_outil", "nettoyage_regle",
                 "champs_secrets")
CLEFS_REQUIREMENTS = ("reseau", "privileges", "base_fichiers", "timeout_s", "sandbox")
CLEFS_CAPACITE = ("description", "domaines", "entree", "sortie", "mots_cles", "interne",
                  "mode_selection", "max_providers", "generique")

_ID = re.compile(r"^[a-z][a-z0-9_]{1,40}$")


class PluginError(Exception):
    """Le plugin est refusé AU CHARGEMENT : rien de ce qu'il décrit ne sera exécutable."""


def fichiers(dossier: Path | None = None) -> list[Path]:
    """`plugins/*.yaml` uniquement. `plugins/propositions/` est un sous-répertoire de
    TRAVAIL (des brouillons classés, non chargés) : le charger serait transformer une
    recommandation en autorisation."""
    racine = Path(dossier or DOSSIER_PLUGINS)
    if not racine.exists():
        return []
    return sorted([p for p in racine.glob("*.yaml") if p.is_file()])


def _refuse(nom_fichier: str, message: str) -> None:
    raise PluginError(f"plugin {nom_fichier} : {message}")


def _verifier_cles(doc: dict, admises: tuple, ou: str, nom_fichier: str) -> None:
    inconnues = [k for k in doc if k not in admises]
    if inconnues:
        _refuse(nom_fichier,
                f"clé(s) {inconnues} inconnue(s) dans `{ou}`. Admises : {list(admises)}. "
                "Une clé ignorée équivaut à une garde retirée : le plugin est refusé, pas "
                "chargé à moitié.")


RISQUES = ("PASSIVE", "ACTIVE", "EXPLOIT")


def _risque_declare(doc: dict, nom_fichier: str) -> str:
    r = doc.get("risque")
    if r is None:
        _refuse(nom_fichier, "aucun `risque` déclaré (PASSIVE | ACTIVE | EXPLOIT) — le chargeur "
                             "n'applyque aucun niveau par défaut à un plugin : ce qui frappe la "
                             "cible et ce qui ne fait que la lire conditionne les autorisations")
    r = str(r).strip().upper()
    if r not in RISQUES:
        _refuse(nom_fichier, f"`risque: {doc.get('risque')!r} hors {list(RISQUES)}")
    return r


def capacites_et_fournisseurs_du_coeur() -> tuple[set, set, str]:
    """(ids des capacités du registre, ids des providers du registre, erreur ou '').

    Lu dans le YAML du cœur, sans fusion de plugins : c'est l'état CONTRE lequel un plugin est
    jugé (« ce provider existe-t-il déjà ? », « cette capacité existe-t-elle déjà ? »). Passer
    par `Registry()` se rappellerait les plugins et rendrait des motifs faux (mesuré le
    30/08/2026 : un registre en erreur faisait refuser chaque plugin pour « capacité inconnue »).
    """
    try:
        import registre as R
        doc = yaml.safe_load(Path(R.REGISTRY_PATH).read_text(encoding="utf-8")) or {}
        ids, fournisseurs = set(), set()
        for c in (doc.get("capabilities") or []):
            ids.add(str(c.get("id")))
            for prov in (c.get("providers") or []):
                fournisseurs.add(str(prov.get("id")))
        return ids, fournisseurs, ""
    except Exception as e:                          # noqa: BLE001
        return set(), set(), f"{type(e).__name__}: {e}"


def verdict(doc, nom_fichier: str = "<mémoire>") -> str:
    """Ce que le chargeur dirait de ce document — sans rien écrire, sans rien charger."""
    existantes, fournisseurs, erreur = capacites_et_fournisseurs_du_coeur()
    try:
        charger_doc(doc if isinstance(doc, dict) else yaml.safe_load(str(doc)) or {},
                    nom_fichier, existantes, fournisseurs)
    except PluginError as e:
        return f"refusé — {e}"
    except Exception as e:                          # noqa: BLE001
        return f"refusé — {type(e).__name__}: {e}"
    return "chargerait" + (" (capacité créée)" if (isinstance(doc, dict)
                               and set(map(str, doc.get("capacites") or [])) - existantes) else "")


def charger_un(chemin: Path, capacites_existantes,
               providers_existants) -> tuple[dict, dict | None, list[str]]:
    """(provider pour le registre, capacité à créer ou None, capacités visées)."""
    nom_fichier = chemin.name
    brut = chemin.read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(brut) or {}
    except yaml.YAMLError as e:
        _refuse(nom_fichier, f"YAML illisible : {e}")
    return charger_doc(doc, nom_fichier, capacites_existantes, providers_existants)


def charger_doc(doc, nom_fichier: str, capacites_existantes,
                providers_existants) -> tuple[dict, dict | None, list[str]]:
    """Les mêmes règles, sur un document DÉJÀ chargé.

    Ce split existe pour une raison mesurable : `inventaire_plateforme.py` doit pouvoir
    rendre le verdict du chargeur sur une proposition sans l'écrire nulle part et sans la
    charger. Un contrôle qui oblige à poser le fichier pour être exercé est un contrôle qu'on
    ne fera pas.
    """
    if not isinstance(doc, dict):
        _refuse(nom_fichier, "racine du fichier : un mapping attendu")

    _verifier_cles(doc, CLEFS_PLUGIN, "plugin", nom_fichier)
    for champ in ("id", "capacites", "binaire", "execution"):
        if champ not in doc:
            _refuse(nom_fichier, f"`{champ}` absent — un plugin sans {champ} n'est pas lisible")

    pid = str(doc["id"])
    if not _ID.match(pid):
        _refuse(nom_fichier, f"`id` {pid!r} : attendu un identifiant minuscule [a-z0-9_]")
    if pid in providers_existants:
        _refuse(nom_fichier, f"le provider {pid!r} existe déjà au registre — un plugin ne "
                            "redéfinit pas ce qui tourne déjà (deux déclarations, deux vérités)")

    capacites = [str(c) for c in (doc["capacites"] or [])]
    if not capacites:
        _refuse(nom_fichier, "`capacites` vide : sans capacité, le provider ne sera jamais choisi")
    nouvelles = [c for c in capacites if c not in capacites_existantes]
    if len(nouvelles) > 1:
        _refuse(nom_fichier, f"un plugin ne crée qu'une seule capacité à la fois (demandées : "
                            f"{nouvelles}) — sinon le fichier ne décrit plus un outil mais un morcellement")
    cap_a_creer = None
    if nouvelles:
        bloc = doc.get("capacite")
        if not isinstance(bloc, dict):
            _refuse(nom_fichier,
                    f"capacité inconnue {nouvelles[0]!r} sans bloc `capacite:` — soit elle "
                    "existe déjà, soit elle est déclarée (description, domaines, sortie, mots_cles)")
        _verifier_cles(bloc, CLEFS_CAPACITE, "capacite", nom_fichier)
        if "generique" in bloc and not isinstance(bloc["generique"], bool):
            _refuse(nom_fichier, "`capacite.generique` : un booléen (true = la capacité rejoint "
                                 "les demandes génériques type « analyse la sécurité de mon dépôt »)")
        for champ in ("description", "domaines", "sortie", "mots_cles"):
            if not bloc.get(champ):
                _refuse(nom_fichier, f"`capacite.{champ}` absent : une capacité sans "
                                     "vocabulaire ne peut pas être demandée, donc elle ne sert à rien")
        cid = nouvelles[0]
        if cid in capacites_existantes:      # garde de cohérence, après le filtre
            _refuse(nom_fichier, f"`capacite` déclaré pour {cid}, qui existe déjà")
        cap_a_creer = {"id": cid,
                       "description": str(bloc["description"]),
                       "domaines": [str(x) for x in bloc["domaines"]],
                       "entree": [str(x) for x in (doc.get("entrees") or ["cible"])],
                       "sortie": str(bloc["sortie"]),
                       "providers": [],                       # rempli par le registre
                       "mots_cles": [str(x) for x in bloc["mots_cles"]],
                       "interne": bool(bloc.get("interne", False)),
                       # Défaut inverse du cœur : une capacité de plugin n'entre dans la suite
                       # générique QUE si le fichier le dit. Sans ça, ajouter un outil change le
                       # plan de toute demande du type « analyse la sécurité de mon dépôt ».
                       "generique": bool(bloc.get("generique", False))}
        if bloc.get("mode_selection"):
            cap_a_creer["mode_selection"] = str(bloc["mode_selection"])
            cap_a_creer["max_providers"] = int(bloc.get("max_providers") or 1)

    # ── la porte : le binaire doit être épinglé, et la licence doit être la sienne
    binaire = str(doc["binaire"])
    outillage = str(doc.get("outillage") or binaire)
    import outils as OUT
    try:
        epingless = OUT.registre()
    except Exception as e:                       # un manifeste de dépendances cassé est bloquant
        _refuse(nom_fichier, f"manifeste des dépendances illisible : {e}")
    epingle = epingless.get(outillage)
    if epingle is None:
        _refuse(nom_fichier,
                f"l'outil {outillage!r} n'a pas d'entrée dans `manifeste_dependances.yaml`. "
                "Un plugin ne s'auto-autorise pas un exécutable : l'épingle (version, source, "
                "licence, empreinte ou note) est la porte, et elle se relit.")
    if epingle.role != "outil":
        _refuse(nom_fichier, f"{outillage!r} est épinglé comme {epingle.role!r}, pas comme outil")
    licence_declaree = str(doc.get("licence") or "").strip()
    if licence_declaree and licence_declaree.lower().split()[0] not in epingle.licence.lower():
        _refuse(nom_fichier,
                f"licence déclarée {licence_declaree!r} alors que l'épingle dit {epingle.licence!r} "
                "— la licence de référence est celle du dépôt amont épinglé, pas celle du plugin")

    req = dict(doc.get("requirements") or {})
    _verifier_cles(req, CLEFS_REQUIREMENTS, "requirements", nom_fichier)
    if req.get("sandbox") is False:
        _refuse(nom_fichier,
                "`requirements.sandbox: false` : aucun plugin ne peut demander à sortir de "
                "l'isolateur. Ce n'est pas une préférence d'exécution, c'est la frontière du produit.")
    if "sandbox" in req and req.get("sandbox") is not True:
        _refuse(nom_fichier, "`requirements.sandbox` doit valoir true (ou être absent)")
    for cle in req:
        if cle not in CLEFS_REQUIREMENTS:
            _refuse(nom_fichier, f"clé `requirements.{cle}` inconnue")

    exe = dict(doc.get("execution") or {})
    _verifier_cles(exe, CLEFS_EXECUTION, "execution", nom_fichier)
    # `commande` est OPTIONNEL : le programme est désigné par `binaire`, la suite par `args`.
    # Le champ reste accepté (les providers du cœur sont écrits ainsi) mais il doit dire la même
    # chose que `binaire` — deux écritures d'une même vérité, c'est deux vérités.
    commande = exe.get("commande")
    if commande is not None:
        if not isinstance(commande, list) or not all(isinstance(a, str) for a in commande):
            _refuse(nom_fichier, "`execution.commande` : une LISTE de chaînes, ou rien du tout — "
                                 "une chaîne unique serait une commande shell, et le cœur "
                                 "n'exécute pas de shell")
        if [str(c) for c in commande] != [binaire]:
            _refuse(nom_fichier, f"`execution.commande` {commande!r} alors que `binaire: {binaire}` "
                                 "— l'argv réel est `binaire` + `execution.args`, et le nom du "
                                 "programme ne se déclare qu'une fois")
    args = exe.get("args") or []
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        _refuse(nom_fichier, "`execution.args` : une liste de chaînes")
    # `commande` est redondant avec `binaire` : le nom du programme est `binaire`, ce qui suit
    # est `args`. On ne supprime pas le champ (les providers du cœur sont écrits ainsi), mais on
    # refuse qu'il dise autre chose — deux écritures d'une même vérité, c'est deux vérités.
    if commande and [str(c) for c in commande] != [binaire]:
        _refuse(nom_fichier, f"`execution.commande` {commande!r} alors que `binaire: {binaire}` — "
                            "le programme est désigné UNE fois ; l'argv réel est "
                            "`binaire` + `execution.args`")
    # Version plancher : le plugin annonce ce qu'il a été lu sur, l'épingle dit ce qui est
    # installé. Comparer les deux évite le scénario « le parseur attend `-o json` de la v2, la
    # machine a la v1 » — et le désaccord se lit ici, pas dans un finding absent.
    vmin = str(doc.get("version_min") or "").strip()
    if vmin:
        def _nomver(s):
            import re as _re
            m = _re.search(r"(\d+(?:\.\d+)*)", str(s or ""))
            return tuple(int(x) for x in m.group(1).split(".")) if m else ()
        if _nomver(epingle.version) and _nomver(vmin) and _nomver(epingle.version) < _nomver(vmin):
            _refuse(nom_fichier, f"`version_min: {vmin}` alors que l'épingle porte "
                                 f"{epingle.version!r} — bootstrap installera la version épinglée, "
                                 "le plugin serait lu avec un autre format")

    sortie = dict(doc.get("sortie") or {})
    _verifier_cles(sortie, CLEFS_SORTIE, "sortie", nom_fichier)
    lecture = dict(doc.get("lecture") or {})
    _verifier_cles(lecture, CLEFS_LECTURE, "lecture", nom_fichier)

    # ── traduction vers la représentation interne : c'est TOUT ce que fait le plugin
    manifeste = {
        "id": pid,
        "kind": "tool",
        "mode": "cli",
        "binaire": binaire,
        "tool_id": outillage,
        # `fichiers_requis` → applicabilité DÉCLARÉE du cœur (`applicable_globs`, filtrée avant
        # exécution par `plan.filtrer_applicabilite`). Ce n'est PAS `requirements.base_fichiers`
        # : ce champ-là désigne une base de données côté machine (`{racine_db}/x`, « lancer
        # bootstrap.sh »), pas un fichier de la cible. Confondre les deux fait refuser un provider
        # pour une raison qui n'existe pas — défaut trouvé le 30/08/2026 en déclarant pip-audit.
        "applicabilite": {"globs": [str(x) for x in (doc.get("fichiers_requis") or [])]},
        "argv": ["{BIN}", *[str(a) for a in args]],
        "output": {"format": str(sortie.get("format", "json")),
                   "sortie": sortie.get("fichier") or False},
        "extraction": {**{k: v for k, v in lecture.items() if v not in (None, "", {}, [])},
                       "modele": str(lecture.get("modele", "plat"))},
        # `risque` se DÉCLARE : aucun plugin n'hérite du PASSIVE par défaut. Une plateforme qui
        # classe silencieusement un fuzzer ou un scanner de ports en passif est une plateforme
        # qui a décidé à la place de l'opérateur, à l'endroit exact où l'opérateur ne regarde pas.
        "risk": _risque_declare(doc, nom_fichier),
        "target_types": [str(x) for x in (doc.get("entrees") or ["repository"])],
        "code_succes": [int(c) for c in (exe.get("code_succes") or [0])],
        "coverage": {"declares_files": bool(lecture.get("modele") != "custom")},
        "conditions": {k: v for k, v in {
            "reseau": bool(req.get("reseau", False)),
            "base_fichiers": list(req.get("base_fichiers") or []),
            "timeout_s": int(req.get("timeout_s") or 0),
            "privileges": str(req.get("privileges") or "aucun")}.items() if v},
    }
    if exe.get("env"):
        manifeste["env"] = dict(exe["env"])
    limite = (f"plugin `{nom_fichier}` — outil {binaire!r}, épinglé sous {outillage!r} "
              f"(version {epingle.version or '?'}), licence {epingle.licence}")
    a_verifier = doc.get("a_verifier")
    if a_verifier:
        limite += " · à vérifier : " + " ; ".join(str(x) for x in list(a_verifier))
    manifeste["limite"] = limite

    # La validation du manifest est REJOUÉE ici, par la fonction du cœur : un plugin passe
    # exactement les mêmes contrôles qu'un provider écrit à la main dans capabilities.yaml
    # (binaire autorisé, jetons, fragments interdits, cohérence format↔modèle, parser).
    for cap in capacites:
        try:
            PM.valider(manifeste, cap)
        except PM.ManifestError as e:
            _refuse(nom_fichier, f"manifest refusé par le cœur pour {cap} : {e}")

    provider = {
        "id": pid,
        "kind": "tool",
        "mode": "CLI",
        "risque": str(doc.get("risque", "PASSIVE")),
        "cout": str(doc.get("cout", "faible")),
        "priorite": int(doc.get("priorite", 100)),
        # `args_obligatoires` est ce que le cœur concatène réellement au programme
        # (`adapters` : `prov.commande + prov.args_obligatoires`). Oublier cette clé produirait
        # un provider dont la commande est vide : l'outil tournerait sans cible, sans option,
        # sans fichier de sortie — un échec silencieux au lieu d'un refus.
        "commande": [binaire],
        "args_obligatoires": [str(a) for a in args],
        "manifest": manifeste,
    }
    # `description` n'est PAS une clé de provider (le registre refuserait) : elle rejoint la
    # `limite` du manifest, qui est lue par le rapport. Une description que personne ne lit
    # est une documentation décorative.
    if doc.get("description"):
        provider["manifest"]["limite"] = (str(doc["description"]).strip() + " · "
                                          + provider["manifest"]["limite"])
    return provider, cap_a_creer, capacites


def fusionner(doc_registre: dict, capacites: list[dict],
              dossier: Path | None = None) -> tuple[list[dict], str, list[str]]:
    """Ajoute les plugins au document du registre AVANT la validation des capacités.

    Retourne (capacités augmentées, empreinte des plugins, noms des fichiers chargés).
    L'empreinte entre dans `Registry.empreinte()` : un plan doit pouvoir prouver contre
    QUEL jeu de plugins il a été autorisé, pas seulement contre quel YAML.
    """
    existantes = {c.get("id") for c in capacites}
    fournisseurs = {p.get("id") for c in capacites for p in (c.get("providers") or [])}
    charges: list[str] = []
    tampons: list[str] = []
    par_capacite: dict[str, list[dict]] = {}
    nouvelles: dict[str, dict] = {}
    for chemin in fichiers(dossier):
        provider, cap, capacites_visees = charger_un(chemin, existantes, fournisseurs)
        tampons.append(f"{chemin.name}\0{chemin.read_text(encoding='utf-8')}")
        charges.append(chemin.name)
        for cid in capacites_visees:
            par_capacite.setdefault(cid, []).append(provider)
        if cap:
            nouvelles[cap["id"]] = cap
            existantes.add(cap["id"])
        fournisseurs.add(provider["id"])

    if not charges:
        return capacites, "", []

    import hashlib
    empreinte = hashlib.sha256("\0".join(tampons).encode("utf-8")).hexdigest()[:12]

    # Les capacités existantes reçoivent leurs providers-plugin À LA FIN de leur liste :
    # l'ordre de déclaration arbitre les égalités de priorité (règle du registre), donc
    # placer un plugin en tête changerait la sélection des missions déjà jouées.
    sorties = []
    for c in capacites:
        ajouts = par_capacite.get(c["id"]) or []
        c2 = dict(c)
        if ajouts:
            c2["providers"] = list(c.get("providers") or []) + ajouts
        sorties.append(c2)
    for cid in sorted(nouvelles):
        cap = dict(nouvelles[cid])
        cap["providers"] = list(par_capacite.get(cid) or [])
        sorties.append(cap)
    return sorties, empreinte, charges


def resumer(dossier: Path | None = None) -> dict:
    """Vue lecture seule pour le diagnostic (`/api/capacites`, `--plugins` du CLI)."""
    out = {"dossier": str(Path(dossier or DOSSIER_PLUGINS)), "charges": [], "refuses": []}
    # Le cœur se relit dans le YAML du registre, PAS via `Registry()` : construire un registre
    # fusionne déjà les plugins, donc le diagnostic se rappellerait lui-même — et pire, une
    # exception levée là serait avalée, laissant chaque fichier refuser pour une capacité qui
    # existe. Un diagnostic qui rend un faux motif est plus coûteux qu'aucun diagnostic.
    existantes, fournisseurs, erreur = capacites_et_fournisseurs_du_coeur()
    if erreur:
        erreur = f"registre du cœur illisible ({erreur})"
    out["registre"] = {"capacites": len(existantes), "providers": len(fournisseurs)}
    if erreur:
        out["erreur_registre"] = erreur
    for chemin in fichiers(dossier):
        try:
            provider, cap, capacites_visees = charger_un(chemin, existantes, fournisseurs)
            out["charges"].append({"fichier": chemin.name, "id": provider["id"],
                                   "capacites": capacites_visees,
                                   "binaire": provider["manifest"]["binaire"],
                                   "capacite_creee": cap["id"] if cap else None})
            fournisseurs.add(provider["id"])
            if cap:
                existantes.add(cap["id"])
        except Exception as e:                       # noqa: BLE001 — le diagnostic n'est pas fatal
            out["refuses"].append({"fichier": chemin.name, "motif": str(e)})
    return out
