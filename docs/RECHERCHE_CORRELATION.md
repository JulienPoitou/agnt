# Veille technique — Déduplication, vérification, priorisation et orchestration IA des findings

*Étude réalisée le 2026-09-05 (recherche web réelle, sources citées dans le texte). Lecture seule : ce document est le seul fichier créé.*

**Contexte AGNT** : moteur de test d'intrusion web local (Python, fail-closed) qui normalise les findings de plusieurs outils (httpx, ffuf, nuclei, git-dumper…) via des manifests déclaratifs. Existe déjà : un clusterer inter-outils à règles explicites (`clusterer.py`, `agnt/PHASE3/slice/`), un oracle de vérification HTTP par rejeu ×N + témoin (`oracle_web.py`), un cycle de vie d'états nommés (`cycle_vie.py`), un pipeline web (`pipeline_web.py`, `agnt-src/`) et un registre déclaratif d'outils (`capabilities.yaml`).

Quatre axes évalués pour chaque plateforme :
1. **Déduplication / corrélation** multi-outils,
2. **Vérification / confirmation** (PoC, rejeu, confiance, réduction des faux positifs),
3. **Priorisation / présentation** (sévérité, tri, regroupement par racine de cause),
4. **Orchestration IA** (agents qui décident quoi scanner ensuite).

---

## 1. État de l'art par plateforme

### 1.1 Burp Suite Pro (PortSwigger)

**Dédup/corrélation.** Deux mécanismes distincts. (a) La **consolidation des issues passives site-wide** fonctionne en deux phases : la phase passive « compte les issues et trace leurs localisations » au lieu de les rapporter isolément, puis Burp « consolide ces issues selon leur fréquence et leur localisation » — aboutissant à une seule issue rapportée à la racine web ou dans un dossier, avec la mention « found at multiple locations under the reported path » et un échantillon de requêtes/réponses comme preuve (exemple mesuré : 310 findings de clickjacking fusionnés en 1). Fonctionnalité optionnelle, active par défaut (PortSwigger, blog *Consolidation of site-wide passive issues*). (b) Limite documentée : Burp ne consolide **que dans le cadre d'un même audit** ; les doublons à travers plusieurs audits du même domaine ne sont pas fusionnés (doc *Viewing scan results* — les URLs marquées « Consolidated » n'ont pas été auditées individuellement ; cf. aussi l'issue #28 de l'extension burp-suite-software-version-checks qui documente l'absence de consolidation inter-URLs).

**Vérification/confiance.** Chaque issue porte un niveau de confiance **Certain / Firm / Tentative**, déterminé par la fiabilité inhérente du type de check (et non par une mesure d'exécution) : « tentative » signifie que l'issue est potentiellement présente mais peut être un faux positif (doc GraphQL API *Confidence* ; doc *Analyzing scan results*). La thèse de M. Dibbets (RU Nijmegen, 2024) confirme que ces niveaux existent parce que les checks produisent des faux positifs connus. La vérification active est étendue par des **BChecks** (checks YAML personnalisés, Pro) et des **custom scan checks Montoya** (Java), appelés à l'étape pertinente de l'audit pour chaque requête de base — c'est le mécanisme utilisé pour re-émettre des requêtes (l'audit embarque une phase dédiée « test the stored input paths for second-order vulnerabilities », et un check natif « SQL injection (second order) » d'ID 0x00100210 existe).

**Priorisation/présentation.** Issues groupées par **risque et niveau de confiance**, filtres sur les deux dimensions ; les URLs consolidées sont marquées comme telles. La liste officielle des vulnérabilités détectées associe à chaque check un ID numérique hexadécimal stable (ex. 0x00100210).

**Orchestration IA.** Aucune orchestration IA native documentée dans les sources consultées ; l'extensibilité passe par BChecks/extensions, pas par un agent décideur.

### 1.2 OWASP ZAP

**Dédup/corrélation.** Le modèle historique est par alerte : chaque règle (passive ou active, indexées avec ID, statut release/beta/alpha/deprecated, risque High/Medium/Low/Informational, type Active/Passive/Tool/…, CWE/WASC) émet des alertes par URL, ce qui génère des doublons massifs en scan passif. Le blog officiel du 2025-09-30 (*Alert De-Duplication*) documente la refonte : les doublons sont définis comme « des alertes qui sont essentiellement les mêmes, même si les URLs diffèrent sur des points non pertinents » ; la cause est que le scan passif ne passe pas par le Sites Tree (qui représente la fonctionnalité de l'application et ignore les valeurs des paramètres — *Data-Driven Nodes*). Correctif : l'arbre d'alertes adopte les mêmes conventions de nommage que le Sites Tree, après quoi « toute alerte dupliquée une fois cette convention appliquée est **jetée** ». De plus, un **tag SYSTEMIC** marque les alertes souvent site-wide (ex. en-têtes de sécurité manquants) : au-delà d'un seuil **configurable (défaut ≈ 5)**, les alertes supplémentaires sont jetées et la troncature est **affichée** dans l'arbre. L'API et les rapports gagnent un champ `nodeName` à utiliser pour les comparaisons inter-scans à la place de l'URI (prévu pour ZAP 2.17.0, sans option de retour à l'ancien comportement).

**Vérification.** Pas d'oracle de rejeu comparable à AGNT ; la séparation passive (tout flux) / active (policy qui détermine quelles règles s'exécutent, cf. intégration Dradis) est le principal levier anti-bruit. La gestion des faux positifs passe par la désactivation d'IDs d'alerte ou des hooks de scan.

**Priorisation.** Risque (Info→High) + statut de règle (release/beta/alpha) ; le nouveau `nodeName` permet le regroupement par fonctionnalité d'application.

**Orchestration IA.** Rien de natif documenté.

### 1.3 DefectDojo

**Dédup/corrélation — mécanisme exact du hash.** C'est la référence documentée la plus précise (doc *About Deduplication*). À chaque import, les nouveaux findings sont comparés aux existants ; le finding le plus ancien d'une chaîne de doublons devient l'original canonique (dans un même rapport, l'original est choisi par un ordre « stable, dérivé du contenu », pas par l'ordre du scanner). Par défaut la dédup s'applique entre Tests du **même Asset** (réductible à un Engagement). Deux identités coexistent :
- `unique_id_from_tool` (ou `vuln_id_from_tool`) : ID fourni par le scanner ; les endpoints sont alors **ignorés** pour le matching.
- `hash_code` : calculé à partir des champs listés par **`HASHCODE_FIELDS_PER_SCANNER`** (par parser : title, cwe, severity, description, line, file_path… selon le scanner) **plus** le champ toujours inclus **`HASH_CODE_FIELDS_ALWAYS = ["service"]`**. Endpoints : s'ils sont dans les champs du hash, ils doivent matcher ; sinon le réglage OS **`DEDUPE_ALGO_ENDPOINT_FIELDS`** décide — liste vide `[]` = endpoints ignorés, ou `["host", "port"]` = dédup si **au moins un** couple d'endpoints matche sur tous les attributs listés.
- Quatre algorithmes (OS) par parser : **Unique ID From Tool**, **Hash Code**, **Unique ID From Tool or Hash Code** (dupliqué si même ID outil **ou** même hash), **Legacy** (multi-conditions : statique = le nouveau finding doit contenir tous les endpoints de l'original ; dynamique = endpoints strictement égaux ; pas de dédup si endpoints + file_path + line tous vides). Le Pro ajoute **Global Component** (nom+version, tous Assets confondus) et **Global Vulnerability ID** (CVE/GHSA), avec matching de sets exact/`_partial`/`_subset` sur les IDs et CWE.

**Reimport.** Algorithme **distinct** du Same-Tool : l'exemple documenté hash sur Title, CWE, Severity, Description, **Line Number** — un décalage de ligne survit donc au reimport (nouveau finding créé) puis est re-marqué doublon par la dédup Same-Tool (qui omet la ligne) ensuite. Le reimport peut **jeter** les matches (« will never be created as Findings »), d'où l'avertissement de prudence de la doc. Exécution asynchrone via Celery, flag `deduplication_complete`, timeout `DD_DEDUPLICATION_ASYNC_WAIT_TIMEOUT` (60 s).

**Statuts de doublons.** Doublons **inactifs** par défaut ; quand l'original est Mitigated, les doublons le deviennent aussi ; l'original n'est jamais rétrogradé.

**Corrélation multi-scanners — limites mesurées.** Les mainteneurs reconnaissent qu'une dédup inter-scanners « ne sera probablement jamais exacte à 100 % » (issue #1037) ; le parsing d'endpoints différent entre Nessus et Nuclei casse le matching (issue #10215) ; `UNIQUE_ID_FROM_TOOL_OR_HASH_CODE` a des effets de bord connus — reimport ne matchant que le **premier** finding existant de même hash (#12924) ou fermant inopinément des findings SARIF (#14205). L'intégration Burp Enterprise permet de fixer un seuil de confiance (Certain/Firm/Tentative) pour le triage.

**Vérification.** Aucune : DefectDojo est un triage/management, pas un moteur d'exécution.

**Priorisation.** Sévérité scanner + flux de triage (métadonnées, statuts), pas de scoring propre.

### 1.4 Faraday

**Dédup/corrélation.** Plateforme de vuln management recevant 120+ outils, avec normalisation et dédup **par niveau** (doc *Deduplicated Assets*) :
- **Assets** : fusion « quand ils partagent le même champ d'adresse IP **normalisé** » — la normalisation convertit toutes les IPs en minuscules avant comparaison. Règles de fusion : asset canonique = IP en minuscules, hostnames de tous les doublons agrégés, OS/MAC et autres attributs pris sur l'**asset le plus ancien**, description fusionnée avec mention « Merged from N Assets », flag Owned si un seul doublon l'était.
- **Services** : agrégés ; deux doublons partageant **même port + même protocole** s'effondrent en un service (attributs du plus ancien, bannières/descriptions combinées avec mention « Merged from N services »).
- **Vulnérabilités** : toutes migrent sur l'asset canonique ; dédup sur « même nom, même type, même description, même service associé » — **le plus ancien gagne** ; repli si le nom de service a disparu : service de même port/protocole. Pas de `vuln_id` : le matching est nom/type/description/service.

**Vérification.** Aucune (management/reporting). **Priorisation** : sévérité importée. **Orchestration IA** : rien de documenté dans les sources consultées.

### 1.5 GitLab Vulnerability Management (référence complémentaire, très documentée)

Règle générale : « une vulnérabilité est un doublon d'une autre quand **scan type, location et identifiers** sont identiques » ; CWE/WASC sont exclus de la comparaison d'identifiants (ce sont des classifiants de type) ; « deux findings sont uniques seulement si **aucun** de leurs identifiants ne matche ». Algorithmes par type :
- **DAST** : location = **chemin d'URL + méthode HTTP + paramètres HTTP** ;
- **Container scanning** : nom d'image uniquement, sauf tag semver non-ressemblant à un hash de commit ;
- **Dependency scanning** : nom de paquet + version ;
- **SAST** : signature « **scope-offset** » `Fichier|Classe[0]|Fonction[0]:ligne` — la portée (fonction/classe) retenue est celle dont la somme des distances au début et à la fin est minimale ; survit à un déplacement de code, cassée par un renommage ; les uploads SARIF tiers retombent sur une empreinte fichier+ligne ;
- **Secret detection** : par valeur et par fichier.

Deux principes notables pour AGNT : GitLab **ne déduplique jamais entre types de scan différents**, et traite les rapports en ordre alphabétique de chemin en gardant la **première occurrence**. Le suivi inter-pipelines repose sur l'**identifiant primaire = première entrée des identifiers** (recommandation : une clé de règle stable, ex. clé de règle SonarQube) ; si elle change, l'ancien finding est marqué no-longer-detected et le nouveau enregistré séparément.

### 1.6 Nuclei (ProjectDiscovery)

**Orchestration de vérification par workflows.** Clé YAML `workflows` avec `template` (fichier/dossier), `tags`, `subtemplates` et `matchers` **nommés** : un template de détection (ex. `http/technologies/jira-detect.yaml`) conditionne l'exécution de sous-templates d'exploit (ex. `tags: jira`) ; les conditions peuvent porter sur chaque matcher nommé du template de base ; les `subtemplates` s'imbriquent (détection techno → version → CVE précis). Bénéfice documenté : ne pas asperger tous les templates sur toutes les cibles — moins de bruit et de temps de scan. **Contexte partagé** : « transparent workflow cookiejar and key-value sharing across templates » — tout extracteur nommé d'un template est accessible dans un autre via `{{extracted}}`. La réutilisation des réponses d'une requête à l'autre dans un même template vient de l'issue #156 (ex. mesuré : récupération d'un token CSRF puis substitution dans la requête suivante). Les issues #2415 (exécution conditionnelle par annotations `if`) et #3582 (`negative: true` : exécuter des sous-templates quand la base ne matche **pas**) étendent la logique. Côté qualité : les **global matchers** centralisent la logique de détection pour réduire les erreurs, et la proposition #16348 sur les templates demande des contrôles CI (rejet des templates incomplets, checks de similarité).

**Dédup.** Pas de mécanisme de dédup inter-outils documenté — Nuclei est un émetteur de findings ; la dédup se joue en aval (cf. DefectDojo issues #10215/#14205).

### 1.7 Semgrep

**Confiance et portée.** Chaque finding est groupé par règle, filtrable par **sévérité et confidence** ; la `confidence` reflète « la confiance du rédacteur de règle que ses patterns capturent la vulnérabilité sans générer trop de faux positifs » (doc *understand-severities*). Semgrep génère une **empreinte par finding** (la composition exacte de l'empreinte n'est pas publiée sur la page consultée) ; via l'API, un flag **`dedup`** déduplique les findings **à travers refs/branches**, et la doc indique que la logique de dédup s'améliore en continu (*Remove duplicate findings*). GitLab a d'ailleurs dû créer des fingerprints personnalisés pour Semgrep (MR 184050, issue 299589) — preuve que l'empreinte d'un scanner n'est pas portable telle quelle chez les agrégateurs.

**Reachability (SCA).** Semgrep Supply Chain utilise une analyse de **dataflow** pour distinguer « reachable-but-safe » de « reachable-and-exploitable » — une dépendance vulnérable n'est remontée comme exploitable que si un flux de données atteint la fonction dangereuse (blog *Dependency Reachability in SCA* ; doc Supply Chain ; couverture étendue à 12 langages).

**Dédup inter-règles.** Deux règles différentes qui matchent le même code produisent deux findings distincts groupés par règle ; la fusion inter-règles n'est pas documentée comme automatique.

### 1.8 Outils IA de pentest

**PentestGPT (USENIX Security '24, arXiv 2308.06782).** Architecture tripartite : **Reasoning** (planification stratégique, décomposition de tâches, décision du prochain pas), **Generation** (production des commandes concrètes), **Parsing** (analyse des sorties d'outils et des entrées utilisateur). Le module Reasoning maintient une vue macro via une structure de données dédiée, la **Pentesting Task Tree (PTT)**. Ablations mesurées dans le papier (ex. retrait du module Generation → génération de tâches repliée dans le Reasoning) et résultat rapporté : **+228,6 % de tâches complétées** vs GPT-3.5 brut sur les cibles de référence. La vérification des résultats reste du ressort de l'opérateur ; le papier documente surtout la **gestion d'état**, pas un oracle.

**PentAGI (vxcontrol, open source).** Hiérarchie stricte **Flow → Task → SubTask → Action**, chaque Action produit des **Artifacts** et alimente la **Memory** ; statuts explicites (SubTask : queued/running/completed/failed ; Action : success/failure). Un **Orchestrator** enchaîne trois phases déléguées à des spécialistes : **Researcher** (recherche de cas similaires, CVE connues) → **Developer** (requêtes d'exploits et de capacités d'outils, production d'un plan d'attaque) → **Executor** (guides d'outils, stockage des résultats, remontée de statut). Deux paliers d'agents avec **caps de tool-calls** : agents généraux (Assistant, Primary Agent, Pentester, Coder, Installer — plafond `MAX_GENERAL_AGENT_TOOL_CALLS` = 100) et agents limités (Searcher, Enricher, Memorist, Generator, Reporter, Adviser, Reflector, Planner — plafond 20). Mémoire : PostgreSQL + **pgvector** (long-term / working / **episodic** avec types d'entrées `observation`/`conclusion`), Graphiti + Neo4j optionnels pour les relations sémantiques. Garde-fous de vérification/supervision : l'**Adviser** intervient sur détection de boucles (5 appels d'outil identiques / 10 au total) et analyse la progression vers l'objectif du SubTask ; le **Reflector** est invoqué automatiquement « quand le LLM échoue à générer des appels d'outil après 3 tentatives » ; un **Planner** « génère 3 à 7 étapes spécifiques et actionnables ».

**XBOW.** Agent de pentest web autonome devenu en juin 2025 premier « bug hunter » non-humain du classement US HackerOne (>1 000 rapports). Deux mécanismes documentés, tous deux **hors-LLM dans leur critère** : (a) des **« validators — automated peer reviewers that confirm each vulnerability XBOW uncovers »** avant soumission, décrits comme validant l'exploitabilité « en éliminant les faux positifs pouvant résulter des hallucinations de l'IA » ; (b) un benchmark public de **104 challenges web containerisés** dont le principe de conception est que **l'exploitation est requise, pas seulement la détection** (récupération d'un flag frais à chaque run) — repo `xbow-engineering/validation-benchmarks`, réutilisé par des tiers (arXiv 2508.20816 : MAPTA 76,9 %, perf. parfaite sur SSRF et misconfig). Les writeups (SQLi Z-Push, XSS stocké 2FAuth CVE-2024-52597) traitent la **confirmation** (exfiltration out-of-band, preuve d'exécution) comme un problème à part entière.

**MITRE Caldera.** L'orchestration est portée par les **planners** : « Caldera uses planners to decide **if, when, and how** an ability of a given adversary profile should be executed during an operation » (plugin Bounty Hunter). Le planner par défaut (**Atomic**) file une ability à la fois dans l'ordre du profil ATT&CK ; des planners plus autonomes existent, dont le **Naive Bayes planner** (ML sur l'historique d'opération pour choisir la prochaine ability) et le Hunter (déclenchement sur état). Décision bornée par le catalogue d'**abilities** (tactic/technique ATT&CK) et par le profil choisi — pas d'improvisation libre.

**HackerGPT.** Assistant de connaissances (techniques, docs d'outils, writeups) pour l'opérateur ; **n'orchestre ni n'exécute pas de scans** — un contrepoint utile : plusieurs sources soulignent que la valeur est dans le conseil, pas dans la chaîne d'exécution.

### 1.9 Priorisation fondée sur la menace : SSVC, EPSS, KEV

- **SSVC (Stakeholder-Specific Vulnerability Categorization, CMU SEI / CISA)** : arbre de décision produisant **Track / Track\* / Attend / Act** (des décisions, pas un score), sur cinq points de décision : **Exploitation** (état de l'exploitation observée), **Automatable** (exploitation automatisable), **Technical Impact** (total/partiel), **Mission Prevalence** et **Human Impact** (arbre CISA Tier-1, calculateur public).
- **EPSS (FIRST)** : modèle **machine-learning** estimant « la probabilité qu'une CVE publiée soit exploitée » dans les ~30 jours, score 0–1 recalculé quotidiennement ; features incluant la disponibilité d'exploits (Exploit-DB, PoC), le score CVSS, l'âge de la CVE. Le papier fondateur (Jacobs, Romanosky et al., *Digital Threats: Research and Practice*, dl.acm.org/doi/10.1145/3436242) le présente comme le premier cadre ouvert de mesure de la **menace** (vs CVSS = sévérité/impact) ; la pratique recommandée (ex. CISA, Splunk, Orca) combine **KEV** (exploitation confirmée) + **EPSS** (menace imminente) + CVSS (impact), car CVSS classe une fraction trop large des CVEs en High/Critical pour trier.
- Lien avec la vérification : pour des findings **internes** à un pentest web (pas de CVE), l'équivalent SSVC du « Exploitation » est exactement ce que mesure un oracle de rejeu — un finding CONFIRMED est un « exploitation: PoC observed ».

---

## 2. Patterns transposables à AGNT

Chaque pattern : **ce que fait le concurrent** → **module AGNT hôte** → **travail**.

1. **Empreinte de dédup explicite façon `hash_code` (DefectDojo) / location fingerprint (GitLab)**
   → **`clusterer.py`** (le regroupement actuel repose sur des clés implicites `paquet:`, `fichier:`, `regle:`, `asset:`).
   Travail : une fonction `empreinte(finding, champs)` calculée sur des champs **déclarés par provider** dans **`capabilities.yaml`** (nouveaux blocs `champs_empreinte: [...]`, style `HASHCODE_FIELDS_PER_SCANNER`), avec un champ toujours inclus à la DefectDojo (`HASH_CODE_FIELDS_ALWAYS=["service"]` → chez AGNT : l'hôte/scope de l'engagement). L'empreinte est stockée sur le finding et stable d'un run à l'autre.

2. **Diff de re-scan par empreinte (reimport DefectDojo, primary identifier GitLab)**
   → **`cycle_vie.py`** (les transitions nécessaires existent déjà : `(REJECTED, "rouvrir") → CANDIDATE`, `(FIXED, "regresser") → REGRESSED`, `(FIXED, "rouvrir") → CANDIDATE`).
   Travail : au run suivant, match des findings par empreinte : ré-observé → `rouvrir`/`observer` avec l'historique joint ; empreinte disparue → événement nommé `no_longer_detected` (à ajouter à `TRANSITIONS`) plutôt qu'une disparition silencieuse. Éviter le bug DefectDojo #12924 : matcher contre **tous** les findings de même empreinte, pas le premier.

3. **Confiance à deux étages (Burp Certain/Firm/Tentative + verdict mesuré)**
   → **`capabilities.yaml`** (déclarer par provider/règle une confiance *a priori* = fiabilité du check, à la Burp) **croisée avec `oracle_web.py`** (verdict mesuré : CONFIRMED/POTENTIAL/REFUTED/INCONCLUSIVE) et **`clusterer.py`** (qui a déjà des niveaux high/medium/low/none).
   Travail : séparer la confiance **déclarée** (le manifeste répond de son check) de la confiance **mesurée** (l'oracle répond du rejeu) et n'afficher qu'un statut composé dont les deux composantes restent nommées — cohérent avec la console honnête.

4. **Normalisation de coordonnée avant matching (Faraday : IP minuscule ; ZAP : conventions du Sites Tree)**
   → **`clusterer.py`** (règle `asset`, qui groupe sur `(asset, valeur)` brute) **réutilisant `web_scope.py`** (`canonicaliser_url` existe dans `pipeline_web.py`).
   Travail : passer la coordonnée par la canonicalisation d'URL (casse du host, query triée ou valeurs ignorées façon DDN de ZAP, slash final) avant la clé de regroupement, pour que `http://Host/a?x=1` et `http://host/a?x=2` convergent quand c'est le même fait.

5. **Plafond SYSTEMIC + troncature affichée (ZAP 2025)**
   → **`clusterer.py`** (règle `asset` / clusters multi-URL) + console.
   Travail : quand un même motif (même règle canonique, même digest) sature N URLs (seuil configurable, défaut ≈ 5 à la ZAP), produire **un** finding systémique porteur du compteur, avec mention explicite de troncature (« N instances agrégées ») — jamais une liste de 40 doublons, jamais un 0 inventé.

6. **Seconde recette indépendante pour VERIFIED (validators XBOW : exploitation requise, pas détection)**
   → **`pipeline_web.py`** (`_verifier_par_oracle`) + **`oracle_web.py`**.
   Travail : exiger pour `VERIFIED` une **deuxième preuve indépendante** de la première (aujourd'hui : statut + digest concordants + témoin discordant). Par exemple : extrait attendu présent dans le corps (le champ `contient_extrait` d'`ObservationRejeu` existe mais n'est pas encore piloté par recette) OU variation de la requête (méthode/param) qui doit produire le même effet ; sinon l'état plafonne à CANDIDATE. Le témoin anti-soft-404 est déjà la première « recette générique » réfutée — le pattern XBOW généralise : une détection sans preuve d'exploitation reste candidate.

7. **Seconde vague conditionnelle façon workflows Nuclei (détection → vérification ciblée)**
   → **`pipeline_web.py`** (la chaîne `ORDRE_CHAINE` est linéaire : chaque nœud `depend_de` le précédent).
   Travail : autoriser `executer_plan` à **enrichir le plan après coup** : après l'oracle, ne planifier des providers de vérification (ex. nuclei avec tags précis) que sur les URLs des findings CANDIDATE, avec contexte partagé (`{{extracted}}` Nuclei ≈ passer l'URL + param du finding au provider suivant). Reste fail-closed : chaque nœud dynamique passe par les mêmes plans déclarés de `capabilities.yaml`.

8. **Priorisation à la SSVC/EPSS sur les clusters**
   → **`clusterer.py`** (les clusters ont déjà `remediation` et les IDs CVE/GHSA via `original_rule_id`) + module d'enrichissement optionnel.
   Travail : pour les clusters porteurs de CVE/GHSA, enrichir avec EPSS (probabilité d'exploitation, API FIRST) et rendre un **tri décisionnel** type Track/Attend/Act avec les facteurs nommés ; pour les findings sans CVE, arbre SSVC-lite interne : Exploitation = verdict oracle (CONFIRMED ≈ « PoC observed »), Automatable = check déclarable automatisable dans le manifeste, prévalence = taille du cluster. Un finding REJECTED est explicitement hors triage.

9. **Identifiant primaire stable inter-runs (GitLab : première entrée des identifiers)**
   → **`clusterer.py`** (clé de cluster) + cycle de vie.
   Travail : définir l'identifiant primaire d'un cluster par priorité : CVE/GHSA d'abord (mesuré : grype émet du GHSA-* — le clusterer gère déjà `PREFIXES_VULN`), sinon règle canonique (`canonical_rule_id`), sinon empreinte. C'est cette clé — pas l'URL — qui porte le suivi d'état entre runs.

10. **Orchestrateur IA borné (PentAGI/PentestGPT/Caldera, gardefous inclus)**
    → **`pipeline_web.py`** (boucle plan→exécution) + **`capabilities.yaml`** (le registre reste la seule source de vérité d'outils).
    Travail (préparation, pas urgent) : si un décideur arrive un jour, reproduire les garde-fous mesurés chez les autres : caps de tool-calls par type d'agent (PentAGI 100/20), détection de boucles (5 appels identiques/10 totaux), Reflector après échecs répétés, mémoire `observation`/`conclusion`, planner qui **propose** mais ne dispose pas (Caldera : décision bornée au catalogue d'abilities = chez AGNT, les capacités déclarées). Doctrine : la vérification reste déterministe (oracle), l'IA ne valide jamais ses propres résultats (leçon XBOW validators).

---

## 3. Recommandations concrètes priorisées pour AGNT

| # | Recommandation | Impact | Effort | Modules |
|---|---|---|---|---|
| R1 | **Empreinte de dédup par provider** déclarée dans `capabilities.yaml` (`champs_empreinte` par bloc provider, champAlways = hôte engagé), calculée et stockée sur chaque finding | Haut (conditionne tout le reste : diff, suivi, corrélation) | Moyen | `clusterer.py`, `capabilities.yaml` |
| R2 | **Diff de re-scan** : ré-observation par empreinte → `rouvrir`/`observer` ; empreinte disparue → événement nommé `no_longer_detected` ; matcher tous les homonymes d'empreinte | Haut (c'est le cœur d'un cycle discovered→fixed→regressed utile) | Moyen | `cycle_vie.py`, `pipeline_web.py` |
| R3 | **Confiance deux étages** : fiabilité du check déclarée dans le manifeste × verdict oracle, les deux affichées | Haut (réduit le triage manuel sans mentir) | Faible | `capabilities.yaml`, `oracle_web.py`, console |
| R4 | **Seconde preuve indépendante obligatoire pour VERIFIED** (extrait attendu piloté par recette, ou requête variée produisant le même effet) ; sinon plafond CANDIDATE | Haut (faux positifs restants : le seul vrai sujet) | Moyen | `oracle_web.py`, `pipeline_web.py` |
| R5 | **Plafond SYSTEMIC** : motifs génériques multi-URL agrégés en un finding systémique avec compteur et troncature affichée (seuil défaut 5) | Moyen (bruit de scan, à la ZAP) | Faible | `clusterer.py`, console |
| R6 | **Normalisation d'URL** dans la règle `asset` du clusterer via `canonicaliser_url` (casse host, query, slash final) | Moyen (convergence inter-outils sur la même cible) | Faible | `clusterer.py`, `web_scope.py` |
| R7 | **Identifiant primaire de suivi** : CVE/GHSA > règle canonique > empreinte ; stocké sur le cluster et repris inter-runs | Moyen (stabilité du suivi, leçon GitLab) | Faible | `clusterer.py`, `cycle_vie.py` |
| R8 | **Enrichissement EPSS + tri SSVC-lite** sur les clusters à CVE (facteurs nommés : exploitation observée = verdict oracle, automatisable = déclaré, prévalence = taille de cluster) ; hors-ligne si pas de réseau, raison nommée | Moyen (priorisation défendable, pas un score magique) | Faible–moyen | `clusterer.py`, console |
| R9 | **Seconde vague conditionnelle** : après l'oracle, planification dynamique de providers de vérification ciblés sur les CANDIDATE uniquement (workflows Nuclei généralisés), via plans déclarés existants | Moyen–haut (temps de scan et bruit réduits) | Moyen | `pipeline_web.py`, `capabilities.yaml` |
| R10 | **Si orchestration IA un jour** : caps de tool-calls, détection de boucles (5 identiques/10 totaux), Reflector après 3 échecs, mémoire observation/conclusion, planner propose / le registre dispose — la validation reste à l'oracle, jamais au LLM | Moyen (préparation) | Élevé | `pipeline_web.py`, `capabilities.yaml` |

**Ordre suggéré** : R1 → R2 → R7 (fondations de l'identité des findings), puis R3+R4 (vérité des verdicts), puis R5+R6 (bruit), puis R8 (priorisation), R9 (efficacité), R10 (seulement si besoin d'IA).

---

## 4. Sources

**Burp Suite Pro**
- https://portswigger.net/blog/consolidation-of-site-wide-passive-issues
- https://portswigger.net/burp/documentation/dast/user-guide/work-with-scan-results/viewing-scan-results
- https://portswigger.net/burp/documentation/dast/setup/trial-deployment/analyze-your-scan-results
- https://portswigger.net/burp/extensibility/dast/graphql-api/confidence.html
- https://portswigger.net/burp/documentation/desktop/extend-burp/custom-scan-checks/creating
- https://portswigger.net/burp/pro/features/bchecks
- https://portswigger.net/burp/documentation/desktop/running-scans/results/audit-items
- https://portswigger.net/burp/documentation/scanner/vulnerabilities-list
- https://github.com/PortSwigger/BChecks
- https://github.com/augustd/burp-suite-software-version-checks/issues/28
- https://defectdojo.com/integrations/burp-enterprise-scan
- https://www.cs.ru.nl/masters-theses/2024/M_Dibbets___Improving_Burp_Scanner_using_benchmarks_and_BChecks.pdf

**OWASP ZAP**
- https://www.zaproxy.org/blog/2025-09-30-alert-de-duplication/
- https://www.zaproxy.org/docs/alerts/
- https://dradis.com/integrations/zap.html

**DefectDojo**
- https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/
- https://docs.defectdojo.com/triage_findings/finding_deduplication/os__deduplication_tuning/
- https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__deduplication_tuning/
- https://github.com/DefectDojo/django-DefectDojo/issues/1037
- https://github.com/DefectDojo/django-DefectDojo/issues/10215
- https://github.com/DefectDojo/django-DefectDojo/issues/12924
- https://github.com/DefectDojo/django-DefectDojo/issues/14205

**Faraday**
- https://docs.faradaysec.com/Deduplicated-Assets/
- https://docs.faradaysec.com/
- https://github.com/infobyte/faraday

**GitLab**
- https://docs.gitlab.com/user/application_security/detect/vulnerability_deduplication/
- https://gitlab.com/gitlab-org/gitlab/-/issues/299589
- https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184050

**Nuclei**
- https://docs.projectdiscovery.io/templates/workflows/overview
- https://docs.projectdiscovery.io/opensource/nuclei/running
- https://projectdiscovery.io/blog/ultimate-nuclei-guide
- https://projectdiscovery.io/blog/introducing-global-matchers-in-nuclei
- https://github.com/projectdiscovery/nuclei/issues/156
- https://github.com/projectdiscovery/nuclei/issues/2415
- https://github.com/projectdiscovery/nuclei/issues/3582
- https://github.com/projectdiscovery/nuclei-templates/issues/16348

**Semgrep**
- https://docs.semgrep.dev/semgrep-code/remove-duplicates
- https://docs.semgrep.dev/kb/rules/understand-severities
- https://docs.semgrep.dev/semgrep-code/findings
- https://semgrep.dev/blog/2025/what-you-should-know-about-dependency-reachability-in-sca
- https://docs.semgrep.dev/semgrep-supply-chain/overview

**Outils IA de pentest**
- https://arxiv.org/html/2308.06782v2 (PentestGPT, USENIX Security '24)
- https://pentestgpt.com/
- https://www.alphaxiv.org/abs/2308.06782
- https://github.com/vxcontrol/pentagi (README : architecture Flow→Task→SubTask→Action, spécialistes, garde-fous)
- https://www.helpnetsecurity.com/2026/04/22/pentagi-autonomous-ai-penetration-testing/
- https://xbow.com/
- https://xbow.com/platform
- https://github.com/xbow-engineering/validation-benchmarks
- https://arxiv.org/html/2508.20816v1 (MAPTA évalué sur le benchmark XBOW)
- https://hackerone.com/xbow
- https://hackergpt.org/
- https://www.godefend.co.uk/resources/articles/hackergpt---simplifying-hacking-with-generative-ai
- https://caldera.readthedocs.io/en/latest/How-to-Build-Planners.html
- https://caldera.readthedocs.io/en/3.0.0/Learning-the-terminology.html
- https://medium.com/@mitrecaldera/mitre-caldera-naive-bayes-planner-1a581c2140c3
- https://medium.com/@mitrecaldera/emulating-complete-realistic-cyber-attack-chains-with-the-new-caldera-bounty-hunter-plugin-196e6fa44663

**Priorisation**
- https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc
- https://www.cisa.gov/ssvc-calculator
- https://riskbasedprioritization.github.io/ssvc/SSVC/
- https://www.first.org/epss/
- https://dl.acm.org/doi/10.1145/3436242 (papier fondateur EPSS)
- https://www.splunk.com/en_us/blog/learn/epss-exploit-prediction-scoring-system.html
- https://orca.security/resources/blog/epss-scoring-system-explained/
