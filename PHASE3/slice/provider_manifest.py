"""Provider manifest — Phase 5A.

LA PROMESSE, formulée correctement :

    Ajouter SANS MODIFIER LE CŒUR les outils CLI qui utilisent un format de sortie
    supporté et un contrat d'exécution standard.

Deux niveaux, et il ne faut pas les confondre :

    outil JSON/SARIF standard   → manifest déclaratif uniquement
    outil au format propriétaire → parser spécifique, AUCUN changement du cœur

Ce qu'on ne promet PAS : « ajouter n'importe quel outil sans écrire de code ».

LE MANIFEST EST UNE LISTE D'ARGUMENTS, JAMAIS UNE CHAÎNE SHELL :

    argv: ["{BIN}", "--output", "{OUT}", "{TARGET}"]        ✔
    command: "tool --output {OUT} {TARGET}"                 ✘ interdit

Le trusted core contrôle : binaire autorisé, placeholders autorisés, répertoire cible,
arguments, risque, format de sortie, montages, timeouts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Placeholders autorisés. Tout autre jeton dans argv est une erreur : c'est la première
# ligne de défense contre l'injection d'arguments.
# {OUT_DIR} (étape 4) : certains outils écrivent dans un RÉPERTOIRE de sortie
# (kics --output-path) plutôt que dans un fichier ({OUT}). Occurrence observée,
# extension générique du vocabulaire — le cœur fournit le chemin, jamais le manifest.
PLACEHOLDERS = ("{BIN}", "{TARGET}", "{URL}", "{OUT}", "{OUT_DIR}", "{REGLES}", "{DB}")

# Fragments interdits dans un argument, indépendamment d'OPA : seconde barrière.
FRAGMENTS_INTERDITS = (";", "&&", "||", "|", "`", "$(", ">", "<", "\n", "\r", "\x00")

# Binaires du cœur. Un manifest ne peut pas introduire un binaire arbitraire.
#
# Depuis les plugins (LOT 2, 30/08/2026), cette liste n'est plus la SEULE porte : un nom absent
# d'ici est admis s'il est **épinglé** dans `manifeste_dependances.yaml` avec le rôle `outil`
# (voir `binaire_autorise`). Le déplacement est délibéré : exiger d'ajouter une ligne ici pour
# chaque nouvel outil signifiait qu'intégrer un outil public touchait encore le cœur, ce que la
# commande du 2026-08-30 interdit. Le manifeste d'approvisionnement est le meilleur endroit —
# il porte déjà la version, l'empreinte, la source et la licence, donc l'autorité y est unique,
# versionnée et relisible ; et un binaire non épinglé reste refusé, ce qui laisse le PATH vide
# d'autorité.
BINAIRES_AUTORISES = ("semgrep", "trivy", "gitleaks", "bandit", "checkov",
                      "grype", "kics",
                      # 30/08/2026 — premier outil ajouté de bout en bout SANS toucher le
                      # cœur : 1 entrée ici (la porte), 1 provider dans capabilities.yaml,
                      # 1 parser dans parsers_detect_secrets.py, 1 épingle au manifeste.
                      # detect-secrets ne sort jamais sur le réseau en mode `scan` (la
                      # vérification en ligne --verify n'est pas dans l'argv, et la limite
                      # est consignée avec).
                      "detect-secrets",
                      # 01/09/2026 — shellcheck + hadolint (et leurs wrappers de récursion,
                      # qui SONT les binaires exécutés : pas de mode répertoire, mesuré).
                      # Même promesse : 2 providers dans capabilities.yaml, 2 parsers
                      # parsers_*.py, 4 épingles au manifeste, wrappers versionnés dans
                      # bootstrap.sh. Les deux sont passifs (lecture des fichiers cibles,
                      # aucun réseau dans l'argv, limites consignées).
                      "shellcheck", "shellcheck_scan", "hadolint", "hadolint_scan",
                      # 01/09/2026 — Outils actifs Groupe B (nmap, nuclei, ffuf)
                      "nmap", "nuclei", "ffuf")

FORMATS_SORTIE = ("json", "jsonl", "sarif", "csv", "xml", "custom")

# Le modèle de lecture n'est JAMAIS déduit du contenu : il est déclaré, et la paire
# (format, modèle) doit être cohérente. Sans cette table, un `modele: plat` posé sur une
# sortie `xml` se traduirait par « 0 item lus » — le mode de défaillance le plus cher
# d'un scanner, parce qu'il ressemble à un dépôt propre.
PairesFormatModele = {
    "json": ("plat", "imbriqué"),
    "sarif": ("plat", "imbriqué"),
    "jsonl": ("lignes_json",),
    "csv": ("csv",),
    "xml": ("xml",),
    "custom": ("plat", "imbriqué"),   # admis seulement parce qu'un parser nommé lit d'abord
}
MODELES_LECTURE = ("plat", "imbriqué", "lignes_json", "csv", "xml")


import conditions as COND  # noqa: E402  (aucun cycle : conditions ne lit rien)
import cible  # noqa: E402  (module feuille : le vocabulaire target_types partagé)


class ManifestError(Exception):
    """Le manifest est refusé. On échoue avant l'exécution, jamais pendant."""


@dataclass(frozen=True)
class Extraction:
    """Spécification DÉCLARATIVE de lecture d'une sortie JSON.

    `modele` sélectionne une forme connue :
        plat    → {"results": [ {...}, {...} ]}                     (bandit, semgrep)
        imbriqué → {"Results": [{"Target": t, "Vulnerabilities":[…]}]}  (trivy)

    Un format qui ne rentre dans aucun modèle demande un parser spécifique — c'est le
    second niveau de la promesse, et il ne modifie pas le cœur.
    """
    modele: str
    items_from: str = "results"
    nested_from: str = ""
    nested_key: str = ""
    contexte: dict = field(default_factory=dict)
    champs: dict = field(default_factory=dict)
    paquet_depuis_regle: list = field(default_factory=list)
    # Nettoyage NOMMÉ de l'identifiant de règle avant canonicalisation. Même principe
    # que `parser` : référencé par son nom, versionné, validé au chargement.
    # "semgrep" = ramène l'id à sa forme canonique quel que soit le préfixe de chemin
    # (semgrep préfixe les ids de règles locales avec le chemin du fichier de règles —
    # préfixe qui varie selon le point de montage, donc non déterministe sans nettoyage).
    # Valeurs autorisées : "" (aucun) ou "semgrep".
    nettoyage_regle: str = ""
    # Champs de TEXTE LIBRE à masquer avec le jeu LARGE. Déclaré par le manifest, parce
    # que seul l'outil sait quels champs contiennent du texte libre susceptible de
    # porter un credential (Bandit met la valeur réelle dans `issue_text`).
    # Le cœur ne devine rien : il applique ce que le manifest déclare.
    # Jetons propres à l'outil, que le cœur NE résout PAS mais autorise à passer tels
    # quels (ex. `{relpath}`, `{msg}` pour `bandit -f custom`). Déclarés explicitement :
    # sans cette liste, tout jeton inconnu est refusé — et un jeton en minuscules
    # aurait sinon traversé la validation sans être vu.
    jetons_outil: list = field(default_factory=list)
    masquer_large: list = field(default_factory=list)
    # Champs dont la VALEUR est un secret, déclarés par le manifest (31/08/2026).
    #
    # `masquer_large` dit « ce champ contient du texte libre, méfie-toi » ; celui-ci dit
    # « ce champ EST le secret ». La différence n'est pas cosmétique : le masquage par
    # motif (`assainissement.masquer`) ne peut pas reconnaître une valeur que l'outil a
    # déshabillée de son préfixe — mesuré, trufflehog3 rend `"secret": "16C7e42F…"`
    # SANS le `ghp_`, donc aucun motif ne le voit. Déclarer le champ permet de masquer
    # la valeur par STRUCTURE, sans rien deviner. Le cœur ne sait toujours pas quel
    # outil c'est : il applique ce que le manifest déclare.
    champs_secrets: list = field(default_factory=list)
    # Séparateur du modèle `csv`, déclaré (pas deviné) : `;` est réellement employé par des
    # exports d'outils, et un mauvais séparateur ne lève aucune erreur — il produit UNE
    # colonne, donc tous les champs à None, donc un scan vide.
    separateur: str = ","
    # Nom d'un parser spécifique enregistré dans parsers.py. Requis pour le format
    # 'custom' : c'est le second niveau de la promesse. Le pipeline ne connaît que le
    # NOM, jamais l'outil.
    parser: str = ""

    def to_dict(self) -> dict:
        return {"modele": self.modele, "items_from": self.items_from,
                "nested_from": self.nested_from, "nested_key": self.nested_key,
                "contexte": self.contexte, "champs": self.champs,
                "paquet_depuis_regle": self.paquet_depuis_regle,
                "jetons_outil": self.jetons_outil,
                "masquer_large": self.masquer_large,
                "champs_secrets": self.champs_secrets, "parser": self.parser}


@dataclass(frozen=True)
class Manifest:
    id: str
    capability: str
    kind: str
    mode: str
    binaire: str
    argv: tuple[str, ...]
    sortie_format: str
    extraction: Extraction
    risque: str
    cibles: tuple[str, ...]
    code_succes: tuple[int, ...] = (0,)
    declare_fichiers: bool = False
    limite: str = ""
    # Référence au registre des Tools (outils.py) : le tool est l'artefact épinglé
    # (version + empreinte + licence + installation UNIQUE). Plusieurs providers
    # peuvent partager un tool (bandit/bandit_custom, semgrep/semgrep_go).
    # Champ OPTIONNEL : un manifest sans tool_id reste valide (compatibilité
    # ascendante), mais un tool_id déclaré est vérifié au chargement : connu,
    # rôle « outil », et cohérent avec le binaire.
    tool_id: str = ""
    # APPLICABILITÉ déclarative (étape 3) : globes de fichiers pour lesquels ce
    # provider a une chance de produire quelque chose. Vide = toujours éligible
    # (pas d'exclusion devinée — une fausse exclusion est pire qu'un not_scanned
    # honnête). Le filtrage est déterministe et PRÉ-exécution (plan.py).
    applicable_globs: tuple[str, ...] = ()
    # CONDITIONS D'EXÉCUTION (2026-08-30) : ce que l'outil EXIGE pour que son résultat
    # veuille dire quelque chose — réseau, base de données, durée, privilèges. Quatre
    # champs plats, parsés et bornés par `conditions.valider`, et consommés à deux
    # endroits : `plan`/`pipeline` (écarte avant même de proposer) et `adapters`
    # (refuse avant le premier Popen). Sans ces champs, un outil qui a besoin du réseau
    # tournait dans la cage sans egress, rendait un résultat VIDE en code 0, et le
    # rapport titrait « 0 vulnérabilité ». Le cœur ne devine rien : non déclaré = aucune
    # exigence (un faux refus coûterait plus cher qu'un not_scanned honnête).
    reseau: bool = False
    base_fichiers: tuple = ()
    timeout_s: int = 0
    privileges: str = "aucun"
    # Variables d'environnement DÉCLARATIVES (étape 4). Occurrence observée : grype
    # 0.118 n'a pas de flag pour son cache de DB — uniquement GRYPE_DB_CACHE_DIR.
    # Mêmes règles de sécurité qu'argv : clés au format nom de variable, valeurs
    # validées contre les mêmes placeholders/jetons (aucune chaîne libre). Le cœur
    # résout, le manifest ne décide de rien. Stocké en tuple de paires (frozen).
    env: tuple = ()
    # TRANSPORT D'EXÉCUTION (2026-08-30) : COMMENT ce provider s'exécute, distinct de CE
    # QU'IL VEUT (argv/env/sortie). Jusqu'ici ce couplage était implicite — un provider
    # était forcément un binaire local en sous-processus dans la cage. Le champ le rend
    # déclaratif : `sandbox_cli` (fourni par le cœur) ou un transport ENREGISTRÉ
    # (builder-mcp, builder-tools). Validé au chargement contre `transports.connus()` :
    # un transport inconnu est refusé, jamais deviné — sans quoi un provider « mcp »
    # serait exécuté en sous-processus local, exactement le mélange à empêcher.
    transport: str = "sandbox_cli"

    def to_dict(self) -> dict:
        return {"id": self.id, "capability": self.capability, "kind": self.kind,
                "mode": self.mode, "binaire": self.binaire, "argv": list(self.argv),
                "sortie_format": self.sortie_format, "extraction": self.extraction.to_dict(),
                "risque": self.risque, "cibles": list(self.cibles),
                "code_succes": list(self.code_succes),
                "declare_fichiers": self.declare_fichiers, "limite": self.limite,
                "tool_id": self.tool_id,
                "applicabilite": {"globs": list(self.applicable_globs)},
                "env": {k: v for k, v in self.env},
                "transport": self.transport,
                "conditions": {"reseau": self.reseau, "base_fichiers": list(self.base_fichiers),
                               "timeout_s": self.timeout_s, "privileges": self.privileges}}


def binaire_autorise(nom: str) -> bool:
    """Le nom de programme peut-il être exécuté ?

    Deux sources, dans cet ordre : la liste du cœur (outils historiquement admis, dont `opa` et
    les interpréteurs utilisés par les providers déclaratifs), puis le manifeste
    d'approvisionnement — un outil que bootstrap sait épingler et installer est un outil que la
    plateforme peut exécuter, à condition d'y figérer avec le rôle `outil`. Un nom qui ne figure
    nulle part ne peut pas être invoqué : `which` n'est pas une autorisation.
    """
    if nom in BINAIRES_AUTORISES:
        return True
    if not nom:
        return False
    try:
        import outils
        t = outils.registre().get(nom)
    except Exception:
        # Manifeste illisible : on ne peut pas s'appuyer sur une autorité cassée, donc on s'en
        # tient à la liste du cœur (refus), jamais on n'ouvre par tolérance d'exception.
        return False
    return t is not None and t.role == "outil"


def binaire_est_autorise(nom: str) -> str:
    """Vide si autorisé, sinon la raison lisible (destinée au refus, pas au journal de debug)."""
    if nom in BINAIRES_AUTORISES:
        return ""
    try:
        import outils
        epingles = outils.registre()
    except Exception as e:
        return f"manifeste des dépendances illisible ({e})"
    t = epingles.get(nom)
    if t is None:
        return (f"binaire {nom!r} ni dans la liste du cœur ni épinglé dans "
                f"{outils.MANIFESTE.name} — un outil à intégrer doit d'abord y recevoir une "
                "entrée (version, source, licence, empreinte ou note)")
    if t.role != "outil":
        return f"binaire {nom!r} épinglé sous le rôle {t.role!r}, qui ne porte pas de provider"
    return ""


def valider(doc: dict, capability: str) -> Manifest:
    """Valide un manifest et le refuse bruyamment s'il n'est pas conforme.

    Chaque contrôle correspond à une attaque ou à une erreur réelle :
      · chaîne shell au lieu d'une liste  → injection
      · binaire hors liste                → exécution arbitraire
      · placeholder inconnu               → substitution imprévue
      · fragment interdit dans un argument → contournement d'OPA
      · format de sortie non supporté     → parser inexistant
    """
    for cle in ("id", "binaire", "argv"):
        if cle not in doc:
            raise ManifestError(f"manifest invalide : {cle!r} absent")

    argv = doc["argv"]
    if isinstance(argv, str):
        raise ManifestError(
            f"{doc['id']} : 'argv' est une chaîne. Le manifest doit être une LISTE "
            f"d'arguments, jamais une chaîne shell.")
    if not isinstance(argv, list) or not argv:
        raise ManifestError(f"{doc['id']} : 'argv' doit être une liste non vide")

    binaire = doc["binaire"]
    if not binaire_autorise(binaire):
        raise ManifestError(f"{doc['id']} : binaire {binaire!r} non autorisé — {binaire_est_autorise(binaire)}")

    # tool_id (étape 2) : OPTIONNEL, mais s'il est déclaré il est vérifié ICI.
    # Le registre des tools formalise l'artefact épinglé ; le manifeste reste la
    # seule autorité d'exécution. Un tool_id inconnu, moteur, ou incohérent avec
    # le binaire est refusé au chargement — jamais à l'exécution.
    tool_id = str(doc.get("tool_id") or "")
    if tool_id:
        import outils
        try:
            t = outils.outil(tool_id)
        except outils.ToolError as e:
            raise ManifestError(f"{doc['id']} : tool_id invalide — {e}")
        if t.role != "outil":
            raise ManifestError(
                f"{doc['id']} : tool_id {tool_id!r} a le rôle {t.role!r} — seul un "
                f"tool de rôle 'outil' peut porter un provider")
        if tool_id != binaire:
            raise ManifestError(
                f"{doc['id']} : tool_id {tool_id!r} incohérent avec le binaire "
                f"déclaré {binaire!r} (convention : l'id du tool EST le nom du binaire)")

    jetons_outil = list((doc.get("extraction") or {}).get("jetons_outil") or [])
    autorises = set(PLACEHOLDERS) | set(jetons_outil)
    for a in argv:
        if not isinstance(a, str):
            raise ManifestError(f"{doc['id']} : argument non textuel {a!r}")
        for frag in FRAGMENTS_INTERDITS:
            if frag in a:
                raise ManifestError(
                    f"{doc['id']} : argument {a!r} contient {frag!r} — refusé")
        for jeton in _jetons(a):
            if jeton not in autorises:
                raise ManifestError(
                    f"{doc['id']} : placeholder {jeton!r} inconnu dans {a!r}. "
                    f"Autorisés par le cœur : {list(PLACEHOLDERS)} ; "
                    f"déclarés par l'outil : {jetons_outil or 'aucun'}")

    env_doc = doc.get("env") or {}
    if not isinstance(env_doc, dict):
        raise ManifestError(f"{doc['id']} : 'env' doit être un objet clé/valeur")
    for k, v in env_doc.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ManifestError(f"{doc['id']} : env {k!r} — clé/valeur non textuelles")
        if not _NOM_ENV.match(k):
            raise ManifestError(
                f"{doc['id']} : nom de variable d'environnement invalide {k!r} "
                f"(attendu : MAJUSCULES_CHIFFRES_)")
        for frag in FRAGMENTS_INTERDITS:
            if frag in v:
                raise ManifestError(
                    f"{doc['id']} : env {k!r} contient {frag!r} — refusé")
        for jeton in _jetons(v):
            if jeton not in autorises:
                raise ManifestError(
                    f"{doc['id']} : placeholder {jeton!r} inconnu dans env {k!r}. "
                    f"Autorisés par le cœur : {list(PLACEHOLDERS)} ; "
                    f"déclarés par l'outil : {jetons_outil or 'aucun'}")

    fmt = (doc.get("output") or {}).get("format", "json")
    if fmt not in FORMATS_SORTIE:
        raise ManifestError(
            f"{doc['id']} : format de sortie {fmt!r} non supporté. "
            f"Supportés : {list(FORMATS_SORTIE)}. Un format propriétaire demande un "
            f"parser spécifique — sans modifier le cœur.")

    ex = doc.get("extraction") or {}
    # ── cohérence format ↔ modèle, jugée AU CHARGEMENT (comme tout le reste)
    modele = str(ex.get("modele", "plat") or "plat")
    if modele not in MODELES_LECTURE:
        raise ManifestError(
            f"{doc['id']} : modèle de lecture {modele!r} inconnu. Admis : "
            f"{list(MODELES_LECTURE)}. Un modèle inconnu vaudrait « aucun item lu ».")
    attendus = PairesFormatModele.get(fmt, ())
    if fmt != "custom" and attendus and modele not in attendus:
        raise ManifestError(
            f"{doc['id']} : format {fmt!r} avec modele {modele!r} — paire non lue par le "
            f"cœur. Pour {fmt!r} le modèle attendu est {list(attendus)}, sinon il faut un "
            "parser nommé en format `custom`.")
    # Format custom : un parser spécifique est OBLIGATOIRE, et il doit exister.
    if fmt == "custom":
        nom = ex.get("parser", "")
        if not nom:
            raise ManifestError(
                f"{doc['id']} : format 'custom' sans parser déclaré. Le second niveau "
                f"de la promesse impose un parser spécifique, enregistré par son nom.")
        import parsers
        if parsers.obtenir(nom) is None:
            raise ManifestError(
                f"{doc['id']} : parser {nom!r} introuvable. "
                f"Disponibles : {parsers.disponibles()}")
    elif fmt == "json" and not ex:
        raise ManifestError(
            f"{doc['id']} : format json sans spécification d'extraction")

    risque = doc.get("risk", "PASSIVE")
    if risque not in ("PASSIVE", "ACTIVE", "INTRUSIVE", "DESTRUCTIVE"):
        raise ManifestError(f"{doc['id']} : risque {risque!r} inconnu")

    ex = doc.get("extraction") or {}
    if fmt == "json" and not ex:
        raise ManifestError(
            f"{doc['id']} : format json sans spécification d'extraction")

    return Manifest(
        id=doc["id"],
        capability=capability,
        kind=doc.get("kind", "tool"),
        mode=doc.get("mode", "cli"),
        binaire=binaire,
        argv=tuple(argv),
        sortie_format=fmt,
        extraction=Extraction(
            modele=modele,
            separateur=str(ex.get("separateur", ",") or ","),
            items_from=ex.get("items_from", "results"),
            nested_from=ex.get("nested_from", ""),
            nested_key=ex.get("nested_key", ""),
            contexte=dict(ex.get("contexte") or {}),
            champs=dict(ex.get("champs") or {}),
            paquet_depuis_regle=list(ex.get("paquet_depuis_regle") or []),
            jetons_outil=list(ex.get("jetons_outil") or []),
            masquer_large=list(ex.get("masquer_large") or []),
            champs_secrets=list(ex.get("champs_secrets") or []),
            parser=ex.get("parser", ""),
            nettoyage_regle=_nettoyage_regle_valide(doc, ex),
        ),
        risque=risque,
        cibles=_target_types_valides(doc),
        code_succes=tuple(doc.get("code_succes", [0])),
        declare_fichiers=bool((doc.get("coverage") or {}).get("declares_files", False)),
        limite=doc.get("limite", ""),
        tool_id=str(doc.get("tool_id") or ""),
        applicable_globs=tuple((doc.get("applicabilite") or {}).get("globs") or []),
        env=tuple(sorted(env_doc.items())),
        transport=_transport_valide(doc),
        **_conditions(doc),
    )


def _transport_valide(doc: dict) -> str:
    """Refuse un transport d'exécution que rien ne fournit.

    La validation est fail-closed, comme tout le reste du manifest : un `transport` que le
    cœur ne connaît pas ET qu'aucun agent n'a enregistré est refusé au chargement — jamais
    deviné, jamais silencieusement rabattu sur `sandbox_cli`. Un provider « mcp » exécuté
    en sous-processus local serait exactement le mélange Provider/Transport que la
    séparation existe pour empêcher (2026-08-30).
    """
    import transports as TR
    brut = doc.get("transport")
    if brut is None:
        return TR.TRANSPORT_SANDBOX_CLI
    nom = str(brut).strip()
    if not nom:
        raise ManifestError(f"{doc['id']} : transport vide — déclarez un transport ou "
                            f"omettez le champ (défaut {TR.TRANSPORT_SANDBOX_CLI!r})")
    if not TR.fournit(nom):
        raise ManifestError(
            f"{doc['id']} : transport {nom!r} non fourni — transports connus : "
            f"{list(TR.connus())}. Enregistrez-le avec transports.enregistrer({nom!r}, "
            f"exécuteur) avant de déclarer un provider qui l'exige.")
    return nom


def _target_types_valides(doc: dict) -> tuple[str, ...]:
    """Les types de cible qu'un provider sait analyser, validés au chargement.

    Le manifest et le pipeline parlent exactement le même langage : le défaut vient de
    `cible.TYPE_DEFAUT` (pas d'un littéral dupliqué ici), et la valeur est contrôlée
    comme une donnée de sécurité — un `target_types` vide, non listé, ou portant un
    jeton non textuel refuserait le provider au lieu de désarmer l'applicabilité en
    silence (un provider « applicable à rien » serait exclu partout sans le dire, ou
    pire, laissé éligible par un lecteur qui devine).
    """
    brut = doc.get("target_types", [cible.TYPE_DEFAUT])
    if isinstance(brut, str):
        brut = [brut]
    if not isinstance(brut, (list, tuple)) or not brut:
        raise ManifestError(
            f"{doc['id']} : target_types vide — un provider doit déclarer au moins "
            f"un type de cible (défaut {cible.TYPE_DEFAUT!r})")
    types: list[str] = []
    for t in brut:
        if not isinstance(t, str) or not t.strip():
            raise ManifestError(
                f"{doc['id']} : target_types porte {t!r} — types textuels non vides "
                f"requis (vocabulaire partagé : {list(cible.TYPES_LOCAUX)} locaux, "
                f"le reste est non local)")
        types.append(t.strip())
    return tuple(types)


NETTOYAGES_REGLE_AUTORISES = ("", "semgrep")


def _nettoyage_regle_valide(doc: dict, ex: dict) -> str:
    """Refuse un nom de nettoyage inconnu : un nom inventé ne nettoierait RIEN en
    silence et produirait des canonical_rule_id non déterministes (doublons)."""
    v = ex.get("nettoyage_regle", "")
    if v not in NETTOYAGES_REGLE_AUTORISES:
        raise ManifestError(
            f"{doc['id']} : nettoyage_regle {v!r} inconnu. "
            f"Autorisés : {[n for n in NETTOYAGES_REGLE_AUTORISES if n] or 'aucun'}")
    return v


import re as _re
_NOM_ENV = _re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _jetons(arg: str) -> list[str]:
    """Extrait les {jetons} d'un argument.

    La casse est VOLONTAIREMENT ignorée. Une première version n'attrapait que
    [A-Z_]+ : les jetons en minuscules d'un outil (`{relpath}`, `{msg}`) passaient donc
    la validation sans être vus. C'était une faille réelle.
    """
    import re
    return re.findall(r"\{[A-Za-z_][A-Za-z0-9_]*\}", arg)


def resoudre_env(m: Manifest, chemins: dict[str, str]) -> dict[str, str]:
    """Résout les placeholders des variables d'environnement déclarées.
    Mêmes chemins trusted que pour argv — le manifest ne fournit jamais de chemin."""
    out = {}
    for k, v in m.env:
        for jeton, valeur in chemins.items():
            v = v.replace("{" + jeton + "}", valeur)
        if "{" in v and "}" in v:
            restants = [j for j in _jetons(v) if j not in set(m.extraction.jetons_outil)]
            if restants:
                raise ManifestError(
                    f"{m.id} : placeholders non résolus {restants} dans env {k!r}")
        out[k] = v
    return out


def resoudre_argv(m: Manifest, chemins: dict[str, str]) -> list[str]:
    """Remplace les placeholders. Les chemins viennent du trusted core, jamais du manifest."""
    out = []
    for a in m.argv:
        for jeton, valeur in chemins.items():
            a = a.replace("{" + jeton + "}", valeur)
        if "{" in a and "}" in a:
            # Les jetons propres à l'outil sont autorisés à passer TELS QUELS : c'est
            # l'outil qui les interprète, pas le cœur. Ils ont été validés au chargement.
            restants = [j for j in _jetons(a) if j not in set(m.extraction.jetons_outil)]
            if restants:
                raise ManifestError(
                    f"{m.id} : placeholders non résolus {restants} dans {a!r}")
        out.append(a)
    return out



def _conditions(doc: dict) -> dict:
    """Bloc `conditions`, traduit en refus de manifest (jamais en erreur Python nue).

    `valider(doc)` connaît le vocabulaire et ses bornes ; ici on ne fait que changer la
    classe d'exception, parce que l'appelant (registre) présente `ManifestError` à
    l'opérateur comme « le manifest est refusé », et c'est exactement ce qui doit arriver.
    """
    try:
        return COND.valider(doc)
    except ValueError as e:
        raise ManifestError(str(e)) from None
