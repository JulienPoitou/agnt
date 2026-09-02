"""Extraction générique — lit une sortie JSON selon une spécification DÉCLARATIVE.

Aucun nom d'outil n'apparaît dans ce fichier. C'est la condition de la promesse :
ajouter un outil au format standard ne doit pas demander de code ici.

Modèles couverts (déclarés par le manifest, JAMAIS devinés par le cœur) :

    plat         {"results": [ {...}, {...} ]}                          bandit, semgrep
    imbriqué     {"Results": [{"Target": t, "Vulnerabilities": [...]}]} trivy, kics, radon
                 (conteneurs nommés : `nested_key: "*"` + `contexte` sur "*" — radon,
                  `raw`/`cc --json` rendent un objet clé-à-clé par fichier)
    lignes_json  un objet JSON par ligne                                nuclei, httpx
    csv          entêtes + lignes                                       nikto, ffuf
    xml          chemin de balises, attributs via `@`                   nmap

Cinq modèles, et pas un de plus « au cas où » : chacun correspond à un format réellement
rendu par un outil de la file d'intégration. Un format qui ne rentre dans aucun d'eux
demande un parser spécifique — c'est le second niveau de la promesse : parser nommé,
AUCUN changement du cœur.
"""

from __future__ import annotations

from provider_manifest import Extraction

# Les motifs de secret vivent dans assainissement.py — une seule source de vérité.
# Ce fichier ne fait que déléguer.
from assainissement import masquer_large, masquer_secrets  # noqa: F401


def _chemin(doc, chemin: str):
    """Suit un chemin pointé : 'a.b.c' ou 'a[0].b'. Renvoie None si absent.

    '$' désigne la racine elle-même : certains outils émettent une LISTE de blocs
    comme racine (un bloc par sous-analyse). Sans ce jeton, aucun chemin ne peut
    désigner la racine, et la liste est illisible en modèle déclaratif.
    """
    if chemin == "$":
        return doc
    if not chemin:
        return doc
    cur = doc
    for part in chemin.split("."):
        if cur is None:
            return None
        if "[" in part and part.endswith("]"):
            cle, idx = part[:-1].split("[")
            if cle:
                cur = cur.get(cle) if isinstance(cur, dict) else None
            if cur is None:
                return None
            try:
                cur = cur[int(idx)]
            except (ValueError, IndexError, TypeError):
                return None
        else:
            cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def _texte_de(brut) -> str:
    """Le texte brut, quand le cœur n'a pas pu parser la sortie (jsonl, csv, xml).

    `adapters` passe `{"texte": …}` dans ce cas : un seul point sait où aller le chercher,
    sinon chaque modèle réinvente l'accès au conteneur et ils divergent au premier ajout.
    """
    if isinstance(brut, str):
        return brut
    if isinstance(brut, dict) and isinstance(brut.get("texte"), str):
        return brut["texte"]
    return ""


def _items_lignes_json(brut) -> list[dict]:
    """Un objet JSON par ligne. Une ligne illisible est IGNOREE, pas fatale : un outil qui
    entrecoupe sa sortie avec un avertissement sur stderr mélangé au stdout ne doit pas
    faire tomber le scan — mais les lignes retenues sont comptées, et la couverture dit ce
    qui a été lu.
    """
    import json as _json
    out = []
    for ligne in _texte_de(brut).splitlines():
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            obj = _json.loads(ligne)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
        elif isinstance(obj, list):
            out.extend(o for o in obj if isinstance(o, dict))
    return out


def _items_csv(brut, ex: Extraction) -> list[dict]:
    import csv as _csv
    import io as _io
    texte = _texte_de(brut)
    if not texte.strip():
        return []
    separateur = getattr(ex, "separateur", "") or ","
    try:
        # `skipinitialspace` ne suffit pas : beaucoup de sorties CSV d'outils de sécu sont
        # espacées APRÈS la virgule (nikto, sqlmap). Mesuré le 30/08/2026 sur `" id "," msg "` :
        # avec DictReader, l'ENTÊTE garde ses espaces (« ' id ' ») et chaque valeur garde les
        # siens (« '42 ' ») — le mapping déclaré ne matche donc aucune clé, tous les champs
        # tombent à None, et un finding dont la règle vaut "R1 " n'a pas la même empreinte que
        # le même finding écrit "R1". Les deux sont bordés, ici, à la lecture.
        lecteur = _csv.reader(_io.StringIO(texte), delimiter=separateur, skipinitialspace=True)
        entetes = [(h or "").strip() for h in next(lecteur)]
    except Exception:
        return []
    if not any(entetes):
        return []
    items: list[dict] = []
    for ligne in lecteur:
        if not ligne or not any(str(c).strip() for c in ligne):
            continue                       # ligne vide = séparateur de sections, pas un item
        item = {}
        for index, cle in enumerate(entetes):
            if not cle or index >= len(ligne):
                continue                   # colonne absente de cette ligne : non déclaré, pas « None »
            item[cle] = str(ligne[index]).strip()
        if item:
            items.append(item)
    return items


def _xml_valeur(element, source: str):
    """Lecteur XML minimal, avec la grammaire de chemin la plus petite qui serve.

        '@addr'          attribut de la balise courante
        'port@state'     texte… non : attribut `state` de la sous-balise `port`
        'service@name'   idem — c'est la forme dont nmap, nessus et nikto -xml ont besoin
        'script/id'      texte de la sous-balise `script/id`
    Rien de plus : un XPath complet serait un second moteur de requête à faire vivre, et
    la promesse tient sans lui.
    """
    if not source:
        return None
    source = str(source)
    if source.startswith("@"):
        return element.get(source[1:])
    if "/" in source:
        tete, reste = source.split("/", 1)
        sous = element.find(tete)
        if sous is None:
            return None
        return _xml_valeur(sous, reste if "/" in reste or reste.startswith("@") else reste)
    if "@" in source:
        balise, attr = source.split("@", 1)
        sous = element.find(balise)
        return None if sous is None else sous.get(attr)
    sous = element.find(source)
    return None if sous is None or sous.text is None else sous.text.strip()


def _items_xml(brut, ex: Extraction) -> list[dict]:
    import xml.etree.ElementTree as ET
    texte = _texte_de(brut)
    if not texte.strip():
        return []
    try:
        racine = ET.fromstring(texte)
    except ET.ParseError:
        # Une sortie XML tronquée (outil tué en plein écriture) est un cas RÉEL : le scan
        # doit dire « rien d'exploitable » et non exploser la mission.
        return []
    # `nested_from` = chemin de balises menant aux CONTENEURS, RELATIF À L'ÉLÉMENT
    # RACINE renvoyé par la lecture (nmap : la racine EST <nmaprun> → 'host'),
    # `nested_key` = balise des items dans chaque conteneur (ex. 'port'). Les deux sont
    # optionnels : 'findall' direct sur `nested_from` suffit pour la plupart des outils.
    chemin = (ex.nested_from or "").strip("/")
    conteneurs = list(racine.iter()) if not chemin else []
    if chemin:
        conteneurs = [racine]
        for b in chemin.split("/"):
            suivants = []
            for c in conteneurs:
                suivants.extend(c.findall(b))
            conteneurs = suivants
    if not conteneurs:
        return []
    items = []
    for conteneur in conteneurs:
        cibles = list(conteneur.iter(ex.nested_key)) if ex.nested_key else [conteneur]
        for element in cibles:
            plat = {}
            conteneur_valeurs: dict[str, object] = {}
            for alias, src in (ex.contexte or {}).items():
                plat[alias] = conteneur_valeurs[alias] = _xml_valeur(conteneur, src)
            for alias, src in (ex.champs or {}).items():
                # Une source qui désigne un alias de `contexte` se lit sur le CONTENEUR, pas
                # comme un chemin de balise : c'est ce que la voie JSON fait déjà (le contexte
                # est fusionné dans l'item avant projection) et ce que le provider `kics` du
                # registre exploite. Sans cette règle, `contexte` et `champs` auraient deux
                # sémantiques selon le format — et le plugin xml ne pourrait pas renommer un
                # champ de contexte, ce qui est la seule raison de déclarer `contexte`.
                plat[alias] = (conteneur_valeurs[src] if src in conteneur_valeurs
                               else _xml_valeur(element, src))
            items.append(plat)
    return items


def extraire(brut, ex: Extraction) -> list[dict]:
    """Retourne une liste d'items bruts, aplatis selon le modèle déclaré."""
    if brut is None:
        return []

    # Modèles fondés sur le TEXTE (le cœur n'a rien pu parser comme JSON) : la dispatch
    # est sur le modèle DÉCLARÉ, jamais sur une inspection de la charge — deviner à partir
    # du contenu est exactement ce qui fait croire à un scan vide quand le format a bougé.
    if ex.modele == "lignes_json":
        return _items_lignes_json(brut)
    if ex.modele == "csv":
        return _items_csv(brut, ex)
    if ex.modele == "xml":
        return _items_xml(brut, ex)

    if ex.modele == "imbriqué":
        if not ex.nested_from or not ex.nested_key:
            return []
        out = []
        groupes = _chemin(brut, ex.nested_from)
        # Certains outils émettent UN seul bloc (dict) là où ils en émettent une
        # liste quand plusieurs sous-analyses tournent. Les deux formes se lisent.
        if isinstance(groupes, dict):
            groupes = [groupes]
        # `nested_key: "*"` — le conteneur EST la liste. Forme réellement rendue par
        # `radon cc --json` : un objet dont CHAQUE clé est un chemin de fichier et dont la
        # valeur est la liste des blocs de ce fichier. Aucun chemin pointé ne peut désigner
        # « la valeur de chaque clé », et exiger un parser sur mesure pour ça serait payer un
        # fichier pour un tour de boucle. La clé du conteneur devient lisible par `contexte`
        # (alias mappé sur "*", la clé elle-même).
        if ex.nested_key == "*" and isinstance(_chemin(brut, ex.nested_from), dict):
            items = []
            for cle, valeur in _chemin(brut, ex.nested_from).items():
                # 31/08/2026 — deux formes de valeur, mesurées sur des sorties réelles :
                #   · une LISTE d'items (radon : chaque clé = un fichier, valeur = ses blocs)
                #   · un DICT unique (npm audit : chaque clé = un paquet, valeur = sa fiche)
                # La seconde rendait 0 item en silence — un outil indexé par clé devenait
               #   « rien trouvé ». Traiter la valeur comme son propre item est la même règle,
               # pas un cas particulier : c'est le conteneur qui est la liste, ici à plat.
                for element in ([valeur] if isinstance(valeur, dict) else (valeur or [])):
                    if not isinstance(element, dict):
                        continue
                    plat = dict(element)
                    for alias, source in (ex.contexte or {}).items():
                        plat[alias] = cle if source == "*" else element.get(source)
                    items.append(plat)
            return items
        for groupe in groupes or []:
            if not isinstance(groupe, dict):
                continue
            # nested_key suit un chemin pointé ('results.failed_checks'), pas
            # seulement une clé simple : des blocs peuvent nicher leurs items.
            for item in _chemin(groupe, ex.nested_key) or []:
                if not isinstance(item, dict):
                    continue
                plat = dict(item)
                # Le contexte déclaré est recopié dans chaque item : c'est ce qui
                # permet de relier une CVE à son fichier cible.
                for alias, source in ex.contexte.items():
                    if source in groupe:
                        plat[alias] = groupe[source]
                out.append(plat)
        return out

    # modèle plat
    items = _chemin(brut, ex.items_from)
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict)]


def champs(item: dict, ex: Extraction) -> dict:
    """Projette un item brut sur les champs normalisés, selon le mapping déclaré.

    Les valeurs sont passées par `masquer_secrets` : un outil peut renvoyer la valeur
    réelle d'un credential dans son message.
    """
    out = {}
    for alias, src in ex.champs.items():
        val = _chemin(item, src)
        if val is None and src != alias and isinstance(item, dict) and alias in item:
            # Projection DÉJÀ appliquée : le modèle xml écrit les items SOUS LEUR ALIAS
            # (`_items_xml` applique le même mapping en amont). Sans ce repli, la seconde
            # projection repasse les chemins bruts (« state@state ») sur un dictionnaire
            # indexé par alias, ne trouve rien, et tout part en None — le bug qui vidait
            # les findings de nmap. Le repli ne devine pas : il lit l'alias quand l'item
            # le porte DÉJÀ, et laisse None quand personne ne l'a fourni.
            val = item.get(alias)
        if alias in ex.masquer_large:
            # Texte libre déclaré à risque : masquage LARGE. Un faux positif ici masque
            # un hachage dans un message — acceptable. Rater une clé ne l'est pas.
            val = masquer_large(val)[0] if isinstance(val, str) else masquer_secrets(val)
        else:
            val = masquer_secrets(val)
        out[alias] = val
    return out

