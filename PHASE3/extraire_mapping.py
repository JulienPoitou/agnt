#!/usr/bin/env python3
"""Extraction du mapping règle → paquet, à partir des règles Semgrep elles-mêmes.

POURQUOI CE SCRIPT EXISTE

Une première version écrivait `mapping_regles.yaml` À LA MAIN. Résultat : une seule
entrée (`avoid-pyyaml-load → pyyaml`), et le moteur de corrélation était aveugle à tout
le reste. Sur `cve-search`, le lien réel « Flask vulnérable + usage dangereux de Flask »
existait dans les données, et notre moteur ne le voyait pas.

Les règles Semgrep portent déjà l'information, dans `metadata.technology`. Les 376 règles
de nos deux jeux ont des métadonnées. Donc le mapping s'EXTRAIT, il ne s'écrit pas.

Correction par rapport à l'idée d'origine : `metadata.packages` est vide partout dans nos
jeux de règles. C'est `metadata.technology` qui porte le paquet.

Le fichier produit est VERSIONNÉ et régénérable : c'est une donnée dérivée, pas une
source de vérité écrite à la main.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

RACINE = Path(__file__).resolve().parent
REGLES = Path.home() / ".cache" / "arena_secops" / "rules"
SORTIE = RACINE / "slice" / "mapping_regles_genere.yaml"

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
    "react": "react",
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
    "typescript": None,
    "javascript": None,
    "browser": None,          # environnement, pas une dépendance
}

# Explicitement exclus : langages et technologies qui ne sont pas des paquets Python.
IGNORES = {"python", "python2", "python3", "java", "go", "ruby", "javascript",
           "typescript", "c", "cpp", "php", "nginx", "apache", "docker", "kubernetes",
           "terraform", "aws", "gcp", "azure", "generic", "node", "nodejs", "react"}


def extraire(chemin: Path) -> dict:
    """Retourne {identifiant_de_regle: {paquet, methode, confiance}}."""
    doc = yaml.safe_load(chemin.read_text(encoding="utf-8")) or {}
    out = {}
    for r in doc.get("rules") or []:
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
            if t in TECHNO_VERS_PAQUET:
                candidat = TECHNO_VERS_PAQUET[t]
                if candidat is None:
                    # Technologie connue mais qui n'est pas une dépendance (langage,
                    # environnement, module intégré). On continue de chercher.
                    continue
                paquet = candidat
                break
        if not paquet:
            continue
        # L'identifiant complet de Semgrep est préfixé par le chemin du fichier ;
        # on conserve aussi la forme courte, qui est ce qui remonte dans les findings.
        court = rid.split(".")[-1]
        for cle in {rid, court}:
            out[cle] = {
                "paquet": paquet,
                "methode": "metadata_semgrep",
                "confiance": "high",
            }
    return out


def main() -> int:
    if not REGLES.exists():
        print(f"règles absentes : {REGLES} — lancer bootstrap.sh")
        return 1

    total = {}
    par_fichier = {}
    for f in sorted(REGLES.glob("*.yaml")):
        m = extraire(f)
        par_fichier[f.name] = len(m)
        total.update(m)

    paquets = sorted({v["paquet"] for v in total.values()})
    doc = {
        "genere_par": "PHASE3/extraire_mapping.py",
        "source": "metadata.technology des règles Semgrep",
        "note": (
            "Fichier GÉNÉRÉ, ne pas éditer à la main. Le mapping règle → paquet est "
            "extrait des règles elles-mêmes : l'écrire à la main produisait une table "
            "d'une ligne et rendait la corrélation aveugle. "
            "metadata.packages est vide dans ces jeux de règles ; c'est "
            "metadata.technology qui porte le paquet."
        ),
        "regles_par_fichier": par_fichier,
        "paquets_couverts": paquets,
        "regles": total,
    }
    SORTIE.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False),
                      encoding="utf-8")

    print(f"règles parcourues   : {sum(par_fichier.values())} entrées de mapping")
    for k, v in par_fichier.items():
        print(f"  {k:<24} {v:>4} règles mappées")
    print(f"\npaquets couverts    : {len(paquets)}")
    print(f"  {', '.join(paquets)}")
    print(f"\nécrit dans {SORTIE.relative_to(RACINE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

