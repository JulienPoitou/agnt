# PHASE 3 — VALIDATION DE GÉNÉRALISATION DE L'ARCHITECTURE

_Analyse demandée : l'architecture conçue pour 3 outils tient-elle pour les 38 ?_
_Sources : `01_GRILLE_TRI.csv`, `NOTES.csv`, profils README/arborescence._

---

## ⚠️ Le cadre de la question est en partie faux — et c'est la découverte principale

**Les 38 ne sont pas 38 providers.** Ce sont 38 repos stratégiques, dont la majorité n'a pas
vocation à être intégrée comme fournisseur de capacité. Répartition réelle :

| Rôle dans notre plateforme | Nombre | Exemples |
|---|---|---|
| **Provider** de capacité | **10** | trivy, nuclei, semgrep, prowler, Cortex, Velociraptor |
| **Composant** de la plateforme | 10 | OPA, ToolHive, gVisor, Temporal, LangGraph, gateways |
| **Lib** | 1 | FastMCP |
| **Pair** — moteur concurrent ou source d'inspiration | 10 | Strix, PentAGI, Decepticon, Shannon, SOAR |
| **Référence** de modèle de données | 7 | DefectDojo, secureCodeBox, Dependency-Track |

**Donc « valider que l'architecture s'applique aux 38 » ne veut pas dire « intégrer les 38 ».**
Dix seulement sont des providers. Les dix « pairs » sont des moteurs complets — concurrents ou
modèles, pas composants.

**Mais ton instinct est juste, pour une autre raison.** Ces 10 providers ne représentent pas la
diversité réelle de l'écosystème. Et ils révèlent trois trous dans le modèle.

---

## Q1 — Le modèle `provider → capability` peut-il représenter chacun des 38 ?

**Pour les 10 providers : oui pour 6, non pour 4.**

| Repo | Représentable ? | Pourquoi |
|---|---|---|
| trivy, semgrep, nuclei, prowler | ✅ | CLI une seule passe, sortie fichier — forme déjà supportée |
| mcp-scanner, mcp-scan | ✅ | idem |
| **Cortex** | ⚠️ partiel | service long avec API, analyseurs configurables, état |
| **Velociraptor** | ❌ | **agents déployés sur des endpoints** — l'exécution n'est pas chez nous |
| **IntelOwl** | ⚠️ partiel | dépend de **clés API tierces** (VirusTotal…) |
| **MCPJungle** | ⚠️ partiel | agrégateur : expose d'autres providers, résolution récursive |

**Pour les 28 autres : la question ne se pose pas.** Ils ne sont pas des providers. OPA n'est
pas un fournisseur de capacité, c'est notre policy engine. DefectDojo n'est pas un outil qu'on
invoque, c'est le modèle de notre store. Strix n'est pas intégrable, c'est un moteur complet.

### Le trou que ça révèle

**Notre modèle n'a pas de concept pour les 10 « composants ».** OPA, ToolHive, gVisor, Temporal,
LangGraph, les gateways — ce sont des morceaux de *notre* plateforme, pas des capacités.

Il manque donc **un second registre** :

```
CAPABILITY REGISTRY   ce que la plateforme SAIT FAIRE   → providers
COMPONENT REGISTRY    ce dont la plateforme EST FAITE   → composants
```

Les confondre serait une erreur de conception : on ne « sélectionne » pas un policy engine comme
on sélectionne un scanner.

---

## Q2 — Quels kinds ?

Les quatre kinds prévus (`tool`, `mcp_server`, `aggregator`, `gateway`) **ne suffisent pas**.
Sur les 10 providers réels :

| Kind prévu | Cas réels | Suffisant ? |
|---|---|---|
| `tool` | trivy, semgrep, nuclei, prowler, mcp-scanner, mcp-scan | ✅ |
| `mcp_server` | **aucun dans les 38** | non testé |
| `aggregator` | MCPJungle | ⚠️ récursivité non implémentée |
| `gateway` | **aucun comme provider** — ContextForge et agentgateway sont des composants | mal classé |
| — | Cortex, Velociraptor, IntelOwl | ❌ **kind manquant** |

**Kinds à ajouter :**

| Kind | Ce que c'est | Cas |
|---|---|---|
| `service` | API longue durée, authentifiée, avec état | Cortex, Velociraptor, IntelOwl |
| `async_job` | soumission → attente → récupération | Cuckoo |
| `stream` | démon qui produit des événements en continu | Falco |

Et une précision : `kind` décrit **la forme d'exécution**, pas le rôle. Un même outil peut être
exposé en CLI ou en API.

---

## Q3 — Lesquels demandent une abstraction différente ?

**Quatre formes d'exécution, une seule implémentée et testée.**

| Forme | Comment ça marche | État |
|---|---|---|
| **CLI une passe** | on lance, on lit un fichier | ✅ **implémenté et testé** — 11/11 |
| **Service API** | session, auth, santé, état | ❌ non implémenté |
| **Job asynchrone** | soumettre, sonder, récupérer | ❌ non implémenté |
| **Flux d'événements** | s'abonner, consommer en continu | ❌ non implémenté |

**C'est le point le plus important de cette analyse.** Notre confiance actuelle repose
entièrement sur la première forme. Prétendre que le modèle fonctionne pour les trois autres
serait infondé — nous n'avons rien testé.

### Incompatibilités concrètes

**Velociraptor est le cas le plus dur.** Son modèle : un serveur central + **des agents installés
sur les endpoints**. L'exécution a lieu sur des machines qui ne sont pas les nôtres. Notre
sandbox est donc **sans objet** pour lui — on ne peut pas confiner ce qui tourne chez le client.
Ça ne veut pas dire qu'il faut l'écarter, mais qu'il relève d'un autre régime : celui des
outils `ACTIFS` avec validation humaine, pas du sandbox.

**Cuckoo** est un workflow asynchrone long (soumission d'un échantillon, détonation, rapport).
Notre executor est synchrone. De plus il est **archivé et non maintenu**.

**Falco** est un démon de détection runtime. Il ne produit pas un rapport, il produit un flux.
Notre modèle `résultat → finding` ne s'applique pas.

**IntelOwl** dépend de clés API tierces. Ça introduit un secret externe, un quota, une latence
réseau — et un tiers qui voit nos requêtes.

---

## Q4 — Capacités que notre registry ne sait pas représenter

**Oui, et c'est structurel.** Notre schéma suppose :

```
une cible → un outil → des findings
```

Plusieurs capacités importantes des 38 ne suivent pas cette forme :

| Capacité | Cas | Pourquoi ça ne rentre pas |
|---|---|---|
| **Surveillance continue** | Falco | pas de cible, pas de fin, produit des événements |
| **Enrichissement** | IntelOwl | **l'entrée est un finding**, pas une cible |
| **Remédiation + vérification** | redamon | produit un correctif, puis un re-scan — c'est une boucle |
| **Gestion de cas** | TheHive | produit un état de workflow, pas un finding |
| **Détonation** | Cuckoo | asynchrone long, artefact binaire en entrée |
| **Collecte endpoint** | Velociraptor | l'exécution est distribuée chez le client |

**Conclusion honnête : notre registry est conçu pour l'analyse ponctuelle, pas pour le SOC, le
DFIR ou la surveillance.** Ce n'est pas un défaut pour la Phase 3-4 — c'est exactement notre
périmètre. Mais il ne faut pas prétendre que le registre actuel couvre les 13 domaines du
master prompt.

**Ce qu'il faudrait pour couvrir l'enrichissement et la remédiation** — les deux seuls qui
comptent vraiment, parce que la remédiation est notre Phase 11 :

```yaml
id: FINDING_ENRICHMENT
entree: [finding]          # et non [cible]
sortie: finding/enrichi

id: CODE_REMEDIATION
entree: [finding]
sortie: correctif
verification: re-scan de la même capacité
```

C'est un changement de schéma, pas un ajout de champ.

---

## Q5 — Contraintes incompatibles avec notre architecture

| Contrainte | Repos concernés | Impact |
|---|---|---|
| **Serveur long + auth** | Cortex, Velociraptor, TheHive, IntelOwl, Temporal | l'executor doit gérer sessions et santé |
| **État persistant** | Cortex, TheHive, Temporal, Velociraptor | notre cœur est sans état par exécution |
| **Clés API tierces** | IntelOwl | secret externe, quota, **un tiers voit nos requêtes** |
| **Exécution hors de chez nous** | Velociraptor | **le sandbox est inopérant** |
| **Réseau obligatoire** | nuclei (cibles), Velociraptor (agents), IntelOwl (API) | régime `ACTIF`, pas `PASSIVE` |
| **Sortie non SARIF** | Cortex, Velociraptor, Gitleaks, IntelOwl | normaliseurs spécifiques obligatoires |
| **Licence inconnue** | Velociraptor, MCP registry | bloque toute réutilisation de code |
| **AGPL** | Cortex, TheHive, IntelOwl, Shannon, Tracecat | sans effet si on les **exécute**, bloquant si on les importe |
| **Projet mort** | Cuckoo (archivé), TheHive 3/4 (fin de distribution) | à écarter comme base |

**Le point le plus sérieux est Velociraptor** : c'est le seul où une hypothèse centrale de
l'architecture — « on confine l'exécution » — ne s'applique pas du tout.

---

## Q6 — « Ajouter un provider = ajouter une déclaration » tient-il ?

**Réponse honnête : non, pas dans l'absolu.**

La formulation exacte devrait être :

> Ajouter un provider dont **la forme d'exécution est déjà supportée** = ajouter une déclaration.
> Ajouter une **nouvelle forme d'exécution** = modifier le moteur.

| Cas | Déclaration seule ? |
|---|---|
| nouveau scanner CLI (trivy → grype, bandit, checkov) | ✅ **oui**, purement déclaratif |
| provider en API (Cortex) | ❌ le moteur doit savoir parler API |
| provider asynchrone (Cuckoo) | ❌ le moteur doit savoir sonder un job |
| provider en flux (Falco) | ❌ le moteur doit savoir s'abonner |
| agrégateur (MCPJungle) | ❌ le moteur doit résoudre récursivement |

**Et aujourd'hui, une seule forme est implémentée et testée : le CLI.**

### La correction que je propose

Ce n'est pas un échec du modèle, c'est une formulation trop ambitieuse. La bonne règle :

1. **Définir un ensemble clos de formes d'exécution** — `cli`, `api`, `async_job`, `stream`,
   `recursive`. Quatre ou cinq, pas davantage.
2. **Chaque forme est implémentée une fois dans le moteur**, et testée.
3. **Ensuite**, la promesse tient : tout outil qui rentre dans une de ces formes est une
   déclaration de données.
4. **Une nouvelle forme est un changement de moteur assumé**, pas un ajout de provider.

C'est la seule façon dont la promesse soit vraie — et vérifiable.

---

## Q7 — Les 5 cas les plus difficiles

Si l'architecture fonctionne pour ceux-là, elle fonctionnera pour le reste.

| # | Repo | Pourquoi c'est dur | Ce qu'il faut pour le résoudre |
|---|---|---|---|
| **1** | **`velocidex/velociraptor`** | Agents sur les endpoints clients → **le sandbox ne s'applique pas**. Serveur + état + auth. Licence inconnue | Un régime d'exécution « hors plateforme », avec validation humaine et scope explicite. C'est un concept qui n'existe pas encore chez nous |
| **2** | **`cuckoosandbox/cuckoo`** | Workflow asynchrone long. Archié et non maintenu | Forme `async_job` : soumettre, sonder, timeout, récupérer. Projet à ne prendre que comme référence |
| **3** | **`intelowlproject/IntelOwl`** | Clés API tierces → secret externe, quota, latence, **fuite de nos requêtes vers un tiers** | Gestion des secrets par provider + déclaration explicite de ce qui quitte la plateforme |
| **4** | **`falcosecurity/falco`** | Démon en flux continu, pas de rapport | Forme `stream`, et un modèle de finding qui accepte l'arrivée continue |
| **5** | **`TheHive-Project/Cortex`** | Serveur, analyseurs configurables, files d'attente, auth, AGPL | Forme `api` complète. Le plus proche d'un cas réaliste — **c'est par lui qu'il faut commencer** |

**Mon avis :** il ne faut pas viser les cinq. **Cortex suffit comme deuxième forme.** C'est un
service API réaliste, maintenu, et son modèle analyzer/job/flavor est le plus proche de notre
capability → provider. Si notre moteur sait parler à Cortex, la forme `api` est prouvée.

Velociraptor et Falco relèvent de régimes qu'on n'ouvrira pas avant les Phases 7 et 10.

---

## Corrections proposées — aucune n'est appliquée

| # | Correction | Pourquoi |
|---|---|---|
| **G1** | **Séparer `CAPABILITY REGISTRY` et `COMPONENT REGISTRY`** | 10 des 38 sont des composants de la plateforme, pas des capacités. Les confondre est une erreur de conception |
| **G2** | **Définir un ensemble clos de formes d'exécution** (`cli`, `api`, `async_job`, `stream`, `recursive`), chacune implémentée et testée une fois | Sans ça, la promesse « ajouter un provider = ajouter une déclaration » est fausse |
| **G3** | **Écrire explicitement que le registry couvre l'analyse ponctuelle**, et pas la surveillance, le SOC ou le DFIR | Éviter de promettre les 13 domaines du master prompt avec un schéma qui n'en couvre qu'un |
| **G4** | **Prévoir `entree: [finding]`** pour l'enrichissement et la remédiation | La remédiation est notre Phase 11 et notre différenciant ; le schéma actuel ne peut pas la représenter |
| **G5** | **Ajouter un régime « exécution hors plateforme »** | Velociraptor : le sandbox est inopérant, il faut un autre mode de confiance |

**Ce que je ne propose PAS :** forcer Strix, PentAGI, Decepticon ou Shannon dans notre modèle.
Ce sont des moteurs complets, concurrents du nôtre. Ils sont utiles comme références
d'architecture — c'est déjà leur verdict (`ADAPT (archi)`) — et rien de plus.

---

## Réponse directe à ta question

> L'architecture du minimal core est-elle réellement conçue pour les 38 ?

**Non, et elle n'a pas à l'être.** Elle est conçue pour **des providers de capacité**, et 10 des
38 seulement en sont.

**Mais ta question a trouvé trois vrais trous :**

1. nous n'avons pas de concept pour les **composants** de la plateforme (10 des 38) ;
2. nous n'avons implémenté qu'**une forme d'exécution sur quatre** ;
3. notre registre ne sait pas représenter **l'enrichissement ni la remédiation** — dont la
   seconde est notre Phase 11.

**Le minimal core n'est pas mal conçu pour autant.** Il est correctement dimensionné pour la
Phase 3. Ce qui serait une erreur, c'est de croire qu'il généralise déjà. Il ne généralise pas :
il couvre une forme d'exécution et un type de capacité.

**La vraie validation de généralisation ne se fera pas sur les 38.** Elle se fera sur le
deuxième provider de forme différente — et **Cortex est le bon candidat**.
