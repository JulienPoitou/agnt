#!/usr/bin/env python3
"""Extraction du mapping règle → paquet, à partir des règles Semgrep elles-mêmes.

POURQUOI CE SCRIPT EXISTE

Une première version écrivait `mapping_regles.yaml` À LA MAIN. Résultat : une seule
entrée (`avoid-pyyaml-load → pyyaml`), et le moteur de corrélation était aveugle à tout
le reste. Sur `cve-search`, le lien réel « Flask vulnérable + usage dangereux de Flask »
existait dans les données, et notre moteur ne le voyait pas.

Les règles Semgrep portent déjà l'information, dans `metadata.technology` (et non
`metadata.packages`). Donc le mapping s'EXTRAIT, il ne s'écrit pas.

(Le chiffre de « 376 règles pour nos deux jeux » qui figurait ici datait d'avant
l'ajout de `javascript.yaml` puis `golang.yaml` : le nombre exact n'a plus lieu d'être
dans un commentaire, c'est `regles_par_fichier` qui le rend, à chaque génération.)

Correction par rapport à l'idée d'origine : `metadata.packages` est vide partout dans nos
jeux de règles. C'est `metadata.technology` qui porte le paquet.

Le fichier produit est VERSIONNÉ et régénérable : c'est une donnée dérivée, pas une
source de vérité écrite à la main.

DEUX GARDES AJOUTÉS LE 2026-08-30 (chantier « mapping Go »), pour la même raison :
une couverture perdue silencieusement est pire qu'une couverture absente, parce qu'elle
se lit comme un choix.

  1. La liste des jeux de règles attendus est ÉPINGLÉE dans `manifeste_dependances.yaml`
     (`regles:`, un sha256 par fichier), ce n'est pas le fruit d'un `glob` sur le cache.
     `bootstrap.sh` a ajouté golang.yaml le 2026-08-29 : le mapping versionné ne le
     mentionne nulle part, et rien ne le disait. Un jeu épinglé manquant fait donc
     ÉCHOUER la génération ; `--partiel` l'autorise, en inscrivant le trou dans la liste
     `regles_absentes` du fichier produit.
  2. Un paquet Go se nomme par CHEMIN DE MODULE (`github.com/gin-gonic/gin`,
     `golang.org/x/text`) : c'est la chaîne que Trivy et Grype déclarent dans `PkgName`.
     La forme courte (`gin`) est ce que `metadata.technology` donne le plus souvent ;
     l'accepter produirait une entrée vivante dans le YAML et morte dans le clusterer,
     qui compare des chaînes. De telles entrées sont REFUSÉES et tracées dans `refusees`.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

RACINE = Path(__file__).resolve().parent
REGLES = Path.home() / ".cache" / "arena_secops" / "rules"
SORTIE = RACINE / "slice" / "mapping_regles_genere.yaml"
MANIFESTE = RACINE / "manifeste_dependances.yaml"

# Un chemin de module Go : domaine (avec point) puis au moins un segment. C'est la forme
# que les OUTILS DE DÉPENDANCES écrivent ; « gin » ne l'est jamais.
MODULE_GO = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(?:/[a-z0-9][a-z0-9._@+\-]*)+$")

# Jeux de règles dont les technologies sont des modules Go (à vérifier, pas à deviner).
FICHIERS_GO = {"golang.yaml", "go.yaml"}

# `technology` porte parfois un langage ou un framework qui n'est pas une dépendance
# pip. On ne garde que ce qui peut réellement apparaître dans un requirements.txt,
# sinon on inventerait des liens.
TECHNO_VERS_PAQUET = {
    "flask": "flask",
    "django": "django",
    "pyramid": "pyramid",
    "sqlalchemy": "sqlalchemy",
    "requests": "requests",
    "jwt": "pyjwt",
    "pyjwt": "pyjwt",
    "pycryptodome": "pycryptodome",
    "cryptography": "cryptography",
    "jinja2": "jinja2",
    "jinja": "jinja2",
    "werkzeug": "werkzeug",
    "pyyaml": "pyyaml",
    "yaml": "pyyaml",
    "boto3": "boto3",
    "tornado": "tornado",
    "aiohttp": "aiohttp",
    "urllib3": "urllib3",
    "celery": "celery",
    "redis": "redis",
    "psycopg2": "psycopg2",
    "pymongo": "pymongo",
    "lxml": "lxml",
    "pillow": "pillow",
    "numpy": "numpy",
    "nltk": "nltk",
    # --- JavaScript / TypeScript ---
    # Les règles Semgrep JavaScript référencent 41 technologies, dont express (33 règles).
    # Sans elles, la corrélation est aveugle sur tout dépôt JS/TS — c'est exactement ce
    # qui s'est produit sur MCPGUARD.
    "express": "express",
    "angular": "angular",
    "vue": "vue",
    "next.js": "next",
    "nextjs": "next",
    "node.js": None,          # langage, pas un paquet : voir IGNORES
    "nodejs": None,
    "node": None,
    "node-crypto": None,      # module intégré à Node, pas une dépendance
    "knex": "knex",
    "jose": "jose",
    "jsonwebtoken": "jsonwebtoken",
    "sequelize": "sequelize",
    "mongoose": "mongoose",
    "axios": "axios",
    "lodash": "lodash",
    "handlebars": "handlebars",
    "ejs": "ejs",
    "pug": "pug",
    "passport": "passport",
    "helmet": "helmet",
    "aws-cdk": "aws-cdk",
    # "react" a été RETIRÉ de cette table : la liste IGNORES plus bas contenait "react",
    # testée AVANT — l'entrée ne pouvait donc jamais se déclencher (les règles react
    # étaient lues, le lien jeté dans un `continue`). Le réintroduire suppose de sortir
    # "react" d'IGNORES, ce qui change la corrélation sur tout dépôt React : à faire sur
    # occurrence mesurée (voir `PROJET_ETAT.md`, étape 6quater).
    "typescript": None,
    "javascript": None,
    "browser": None,          # environnement, pas une dépendance
}

# Explicitement exclus : langages et technologies qui ne sont pas des paquets Python.
IGNORES = {"python", "python2", "python3", "java", "go", "ruby", "javascript",
           "typescript", "c", "cpp", "php", "nginx", "apache", "docker", "kubernetes",
           "terraform", "aws", "gcp", "azure", "generic", "node", "nodejs", "react"}


def regles_declarees(manifeste: Path | None = None) -> list[str]:
    """Les jeux de règles ÉPINGLÉS, c'est-à-dire attendus. La liste d'autorité est le
    manifeste, pas ce que le cache a bien voulu garder."""
    chemin = manifeste or MANIFESTE
    if not chemin.exists():
        return []
    doc = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}
    return sorted(str(k) for k in (doc.get("regles") or {}) if str(k).endswith(".yaml"))


def paquet_go_valide(valeur) -> bool:
    """Un paquet Go n'a pas de nom court : les outils le nomment par chemin de module."""
    return bool(MODULE_GO.match(str(valeur or "").strip().lower()))


def valider_tables(table: dict, ignores: set) -> list[str]:
    """Les incohérences internes du générateur, sous forme de messages. Non vides = ne pas
    écrire : une table dont une entrée est annulée par IGNORES perd de la couverture sans
    jamais le dire (c'est ainsi que « react » a vécu, mappé sur rien, pendant des semaines)."""
    anomalies = []
    for techno in sorted(set(table) & set(ignores)):
        if table[techno] is not None:
            anomalies.append(
                f"technologie {techno!r} présente dans TECHNO_VERS_PAQUET ET dans IGNORES : "
                f"IGNORES est testé en premier, l'entrée est morte")
    return anomalies


def extraire(chemin: Path) -> dict:
    """Retourne {identifiant_de_regle: {paquet, methode, confiance}} — usage d'appel direct."""
    return lire(chemin)[0]


def lire(chemin: Path) -> tuple[dict, dict, list]:
    """(mapping, {'lues','mappees'}, règles REFUSÉES).

    Les compteurs sont par RÈGLE et non par clé du dictionnaire : une règle mappée écrit
    deux clés (identifiant complet + forme courte), compter les clés gonflerait le
    résultat. « 376 lues, 0 mappée » est un résultat qui s'interprète, pas un vide ; une
    règle refusée est tracée avec son motif.
    """
    out: dict = {}
    mappnees = 0
    refusees: list = []
    try:
        doc = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return (out, {"lues": 0, "mappees": 0},
                [{"fichier": chemin.name, "regle": None, "technologie": None,
                  "motif": f"fichier illisible : {type(exc).__name__}"}])
    regles = doc.get("rules") or []
    go = chemin.name in FICHIERS_GO
    for r in regles:
        rid = r.get("id")
        meta = r.get("metadata") or {}
        if not rid:
            continue
        # `technology` peut être une chaîne ou une liste.
        tech = meta.get("technology") or []
        if isinstance(tech, str):
            tech = [tech]
        paquet = None
        for t in tech:
            t = str(t).strip().lower()
            if t in IGNORES:
                continue
            if go and not paquet_go_valide(t):
                # Jeu Go + forme qui n'est pas un chemin de module : le lien ne
                # rencontrera jamais la clé de l'outil de dépendances. On refuse et on
                # le dit, au lieu d'écrire une entrée qui ne servira jamais à rien.
                refusees.append({"fichier": chemin.name, "regle": rid, "technologie": t,
                                 "motif": "technologie Go en nom court : les outils "
                                         "déclarent un chemin de module (domaine/chemin), "
                                         "la corrélation ne se rencontrerait jamais"})
                continue
            if t in TECHNO_VERS_PAQUET:
                candidat = TECHNO_VERS_PAQUET[t]
                if candidat is None:
                    # Technologie connue mais qui n'est pas une dépendance (langage,
                    # environnement, module intégré). On continue de chercher.
                    continue
                paquet = candidat
                break
            if go:
                # Technologie Go absente de la table : c'est la voie par laquelle un
                # chemin de module légitime entre sans écriture manuelle.
                paquet = t
                break
        if not paquet:
            continue
        # L'identifiant complet de Semgrep est préfixé par le chemin du fichier ;
        # on conserve aussi la forme courte, qui est ce qui remonte dans les findings.
        mappnees += 1
        court = rid.split(".")[-1]
        for cle in {rid, court}:
            out[cle] = {
                "paquet": paquet,
                "methode": "metadata_semgrep",
                "confiance": "high",
            }
    return out, {"lues": len(regles), "mappees": mappnees}, refusees


def generer(dossier_regles: Path, sortie: Path, partiel: bool = False) -> int:
    """Cœur du script, appelé par main() et vérifiable par la batterie de tests."""
    anomalies = valider_tables(TECHNO_VERS_PAQUET, IGNORES)
    if anomalies:
        print("tables du générateur incohérentes — aucun fichier écrit :")
        for a in anomalies:
            print(f"  - {a}")
        return 2

    if not dossier_regles.exists():
        print(f"règles absentes : {dossier_regles} — lancer bootstrap.sh")
        return 1

    presents = {f.name for f in dossier_regles.glob("*.yaml")}
    declarees = regles_declarees()
    manquantes = [d for d in declarees if d not in presents]
    if manquantes and not partiel:
        print("jeux de règles ÉPINGLÉS absents du cache — génération refusée :")
        for d in manquantes:
            print(f"  - {d}")
        print(f"  (lancer bootstrap.sh ; ou --partiel pour générer en inscrivant "
              f"regles_absentes, ce qui rend le trou visible dans le fichier)")
        return 1

    total: dict = {}
    par_fichier: dict = {}
    refusees: list = []
    for f in sorted(dossier_regles.glob("*.yaml")):
        m, stats, refus = lire(f)
        par_fichier[f.name] = stats
        refusees.extend(refus)
        total.update(m)
    for d in manquantes:                       # présent = 0 lu, pas une ligne disparue
        par_fichier[d] = {"lues": 0, "mappees": 0}

    paquets = sorted({v["paquet"] for v in total.values()})
    doc = {
        "genere_par": "PHASE3/extraire_mapping.py",
        "source": "metadata.technology des règles Semgrep",
        "note": (
            "Fichier GÉNÉRÉ, ne pas éditer à la main. Le mapping règle → paquet est "
            "extrait des règles elles-mêmes : l'écrire à la main produisait une table "
            "d'une ligne et rendait la corrélation aveugle. "
            "metadata.packages est vide dans ces jeux de règles ; c'est "
            "metadata.technology qui porte le paquet. "
            "regles_par_fichier compte les règles LUES et les règles MAPPÉES : un jeu lu "
            "et non mappé y reste écrit, parce que « 0 mappée » est une information. "
            "En Go, seul un chemin de module est retenu (golang.org/x/text) : un nom "
            "court (gin) ne rencontrerait jamais la clé que Trivy déclare, il est porté "
            "dans refusees."
        ),
        "regles_declarees": declarees,
        "regles_absentes": manquantes,
        "regles_par_fichier": par_fichier,
        "refusees": refusees,
        "paquets_couverts": paquets,
        "regles": total,
    }
    sortie.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False),
                      encoding="utf-8")

    print(f"mapping écrit       : {len(total)} entrées")
    for k in sorted(par_fichier):
        v = par_fichier[k]
        marque = "  (épinglé, ABSENT du cache)" if k in manquantes else ""
        print(f"  {k:<24} {v['lues']:>4} lues · {v['mappees']:>4} mappées{marque}")
    if refusees:
        motifs: dict = {}
        for r in refusees:
            motifs[r["motif"]] = motifs.get(r["motif"], 0) + 1
        print(f"  {len(refusees)} règles refusées :")
        for m, n in sorted(motifs.items(), key=lambda kv: -kv[1]):
            print(f"    {n:>4} × {m}")
    print(f"\npaquets couverts    : {len(paquets)}")
    print(f"  {', '.join(paquets) if paquets else '(aucun)'}")
    print(f"\nécrit dans {sortie.relative_to(RACINE) if sortie.is_relative_to(RACINE) else sortie}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extrait le mapping règle → paquet des jeux de règles Semgrep épinglés.")
    ap.add_argument("--regles", type=Path, default=REGLES,
                    help=f"cache des règles (défaut : {REGLES})")
    ap.add_argument("--sortie", type=Path, default=SORTIE,
                    help=f"fichier de mapping à écrire (défaut : {SORTIE})")
    ap.add_argument("--partiel", action="store_true",
                    help="générer même si un jeu épinglé manque au cache, en l'inscrivant "
                         "dans regles_absentes (par défaut : échec, pour qu'une couverture "
                         "perdue ne ressemble pas à une couverture choisie)")
    a = ap.parse_args()
    return generer(a.regles, a.sortie, a.partiel)


if __name__ == "__main__":
    raise SystemExit(main())

