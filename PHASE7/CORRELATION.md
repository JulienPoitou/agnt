# CORRÉLATION — MAPPING EXTRAIT + RÈGLE same_dependency_usage

_Étape 2 de l'ordre validé : prouver la corrélation sur un dépôt réel._

---

## Le point de départ

Sur `cve-search`, le lien réel existait dans les données :

```
Trivy    : Flask 2.2.5 → CVE-2026-27205
Semgrep  : avoid_app_run_with_bad_host sur web/wsgi.py:25
           « Running flask app with host 0.0.0.0 could expose the server publicly »
```

Notre moteur ne le voyait pas. Cause : `mapping_regles.yaml` était **écrit à la main** et ne
contenait qu'une seule entrée (`avoid-pyyaml-load → pyyaml`). Sur Config-Portal, la corrélation
avait marché **par chance** : pyyaml était la seule entrée du mapping, et c'était justement le
bon paquet.

## Le mapping s'extrait, il ne s'écrit pas

Les règles Semgrep portent déjà l'information, dans `metadata.technology`. Les 376 règles de
nos deux jeux ont des métadonnées.

**Correction par rapport à l'idée d'origine :** `metadata.packages` est **vide** partout dans
ces jeux de règles. C'est `metadata.technology` qui porte le paquet.

```
python.yaml          151 règles, 151 avec métadonnées
   flask 18 · django 27 · pyramid 16 · sqlalchemy 4 · jwt 3 · requests 3 …
security-audit.yaml  225 règles, 225 avec métadonnées
   flask 20 · django 24 · jwt 5 …
```

`PHASE3/extraire_mapping.py` produit `slice/mapping_regles_genere.yaml` :

```
265 entrées · 13 paquets
boto3, cryptography, django, flask, jinja2, psycopg2, pycryptodome, pyjwt,
pymongo, pyramid, pyyaml, requests, sqlalchemy
```

Fichier **généré**, régénérable, à ne pas éditer à la main. L'extraction est **locale** :
pas besoin de télécharger `semgrep-rules`, les règles sont déjà dans le cache.

### Ce qui est correctement exclu

```
avoid_app_run_with_bad_host    → flask     (metadata_semgrep, high)
secure-set-cookie              → flask     (metadata_semgrep, high)
template-unescaped-with-safe   → flask     (metadata_semgrep, high)
var-in-script-tag              → None      (inconnu)
```

`var-in-script-tag` n'est **pas** mappé à Flask : c'est du XSS de template, pas une règle
spécifique à Flask. C'est exactement l'exigence posée — « CVE sur paquet X + n'importe quel
finding → cluster » est interdit. C'est le mapping qui décide, et une règle non mappée ne
produit aucun lien.

Les langages et technologies qui ne sont pas des paquets pip sont explicitement exclus
(`python`, `java`, `go`, `javascript`, `nginx`, …) : les mapper inventerait des liens.

## La règle `same_dependency_usage`

```
CVE sur paquet X  +  usage dangereux de CE paquet X
  → UN seul cluster, explicitement lié
```

Les deux familles sont dans le **même** cluster, pas deux clusters séparés. Les séparer
rendait le lien implicite et faisait disparaître le marqueur `cross_tool`.

La comparaison de paquets est **insensible à la casse** : Trivy renvoie « Flask » tel qu'écrit
dans `requirements.txt`, le mapping renvoie « flask ».

## Résultat sur `cve-search`

```
findings : 25          (Semgrep 19 · Trivy 6)
clustering : 25 → 12   (6 clusters · 6 non regroupés)

CL-001   6 membres   high
  reason : same_dependency_usage, related_dependency, same_package,
           cross_tool, tools:semgrep+trivy
  clé    : dependance:flask
  membres: sg-0003  semgrep  secure-set-cookie              views.py:316
           sg-0004  semgrep  secure-set-cookie              views.py:327
           sg-0005  semgrep  secure-set-cookie              views.py:342
           sg-0011  semgrep  template-unescaped-with-safe   cve.html:749
           sg-0019  semgrep  avoid_app_run_with_bad_host    wsgi.py:25
           tv-0001  trivy    CVE-2026-27205                 requirements.txt

CL-002   5 membres   high    same_package, related_dependency        [paquet:nltk]
CL-003   4 membres   medium  same_asset, same_file, ligne_proche     [search.html]
CL-004   2 membres   medium  same_asset, same_file, ligne_proche     [capec.html]
CL-005   1 membre    medium  same_asset, same_file                   [capec.html]
CL-006   1 membre    medium  same_asset, same_file                   [cve.html]
non regroupés : 6
```

**Le cluster inter-outils est apparu, sur un dépôt réel, sans que le moteur ne le devine.**

`nltk` a 5 CVE mais **aucun** cluster inter-outils — parce qu'aucun finding Semgrep n'est
mappé à nltk. C'est correct : il n'y a pas de lien à produire.

## Deux bugs trouvés en route

**1. `source.rule_id` est `None` pour Semgrep comme pour Trivy.** L'identifiant réel est dans
`original_rule_id`. Utiliser `rule_id` faisait tomber les CVE dans le mauvais sous-cluster
(libellé « usage » au lieu de « cve »), et le marqueur `cross_tool` disparaissait.

**2. Une définition de fonction en double dans `findings.py`**, résidu d'éditions
successives, qui masquait la première. En la supprimant, la classe `Finding` est partie avec —
restaurée.

## Ce que ça prouve, et ce que ça ne prouve pas

**Prouvé :**

- le mapping extrait des métadonnées produit des liens justes ;
- la règle `same_dependency_usage` relie CVE et usage du même paquet ;
- une règle non mappée ne produit **aucun** lien faux ;
- ça fonctionne sur un dépôt réel de 198 fichiers, non préparé par nous.

**Non prouvé :**

- **une seule règle de corrélation est démontrée.** `same_file`, `ligne_proche` et
  `same_rule` existent mais ne sont pas la corrélation inter-outils ;
- **un seul dépôt réel testé.** Un deuxième dépôt avec un lien d'une autre nature
  (par exemple même fichier vu par deux outils) renforcerait la preuve ;
- le mapping couvre 13 paquets Python. Rien pour JavaScript, Go, Java.

## Reproductibilité

```bash
bash PHASE3/bootstrap.sh
python3 PHASE3/extraire_mapping.py        # régénère le mapping
python3 PHASE3/slice/pipeline.py "Analyse la sécurité de ce dépôt" PHASE3/cible_cvesearch
```

Suite de tests : **11/11 vertes**, somme des codes 0.
