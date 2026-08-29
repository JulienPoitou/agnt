# PHASE 1 — ARCHITECTURE DE RÉFÉRENCE

_Réponses aux cinq questions de sortie de Phase 1 (`CRITERES.md` §5), chacune appuyée sur_
_les repos qui l'ont tranchée. Ce document est la porte d'entrée de la Phase 2 : tant qu'une_
_réponse n'est pas validée, on ne construit pas._

---

## Q1 — Comment représenter une capacité et ses providers ?

**Réponse : la capacité est une donnée déclarative, jamais du code.**

Trois implémentations indépendantes convergent :

| Repo | Comment il le fait |
|---|---|
| `TheHive-Project/Cortex` | **analyzer / job / flavor** : un analyzer déclare ce qu'il sait traiter, ses flavors sont des variantes paramétrées. C'est `CAPABILITY → PROVIDERS` écrit noir sur blanc |
| `velocidex/velociraptor` | `artifacts/` : un artefact est une capacité déclarée, exécutée via VQL, avec `acls/` au même niveau |
| `projectdiscovery/nuclei` | le template YAML *est* la déclaration ; le moteur ne connaît aucun outil en dur |
| `StackStorm/st2` | le « pack » regroupe capteurs + règles + actions ; 10 ans de preuve que le modèle tient |
| `aquasecurity/trivy` | matrice **scanners × cibles** : « ce qu'on cherche » séparé de « où on le cherche » |

**Ce que ça impose chez nous.** Un enregistrement de capacité doit porter : identifiant,
description sémantique (pour le routage par l'IA), domaines, liste de providers, et pour chaque
provider ses préconditions et son coût. Aucun `if tool == "nuclei"` dans le moteur.

**Piège identifié.** `0x4m4/hexstrike-ai` fait l'inverse — 11 393 étoiles, deux fichiers Python,
tout en dur. La popularité ne valide pas une architecture : c'est précisément le cas que le
critère C1 à 50 % était censé attraper.

---

## Q2 — Où se situe la frontière déterministe, et que couvre-t-elle ?

**Réponse : elle ne s'écrit pas, elle s'intègre. OPA existe déjà.**

| Repo | Ce qu'il apporte |
|---|---|
| `open-policy-agent/opa` | policy-as-code, CNCF **graduated**, `sdk/` + `server/` + `topdown/` + `bundle`. Écrire notre propre moteur de règles serait recréer ça |
| `microsoft/agent-governance-toolkit` | `policy-engine/` + `schemas/` + `benchmarks/prompt-injection`, porté sur 7 langages. C'est la formalisation de « le modèle propose, le runtime autorise » |
| `stacklok/toolhive` | applique la politique **par requête**, pas au démarrage |
| `agentgateway/agentgateway` | un point de contrôle unique entre l'IA et les outils, sous charter Linux Foundation |
| `velocidex/velociraptor` | `acls/` intégré au modèle d'artefacts : la permission accompagne la capacité |

**Ce que ça impose chez nous.** La chaîne reste `AI PLANNER → POLICY ENGINE → EXECUTION`.
Le policy engine est un composant **distinct, déterministe, testable sans LLM**, qui évalue au
minimum : cible dans le scope, outil autorisé, classification de risque, ressources, réseau,
durée, nécessité d'une validation humaine.

**Point de vigilance.** `agentgateway` et `toolhive` placent le contrôle dans une gateway.
C'est tentant, mais une gateway n'est pas une politique : si la règle vit dans la gateway,
elle devient contournable dès qu'un chemin n'y passe pas. **La règle vit dans le policy engine ;
la gateway n'est qu'un point d'application parmi d'autres.**

---

## Q3 — Quel niveau d'isolement, et qui l'impose ?

**Réponse : conteneur par exécution + proxy d'egress + limites, imposés par l'orchestrateur, pas par l'outil.**

| Repo | Ce qu'il apporte |
|---|---|
| `stacklok/toolhive` | **chaque serveur MCP dans un conteneur isolé**, `containers/egress-proxy/`, identité et politique par requête. C'est la réponse la plus directement réutilisable |
| `TracecatHQ/tracecat` | sandboxé **par défaut** avec nsjail, exécution sur Temporal. Le « par défaut » est le point important |
| `vxcontrol/pentagi` | sandbox Docker avec accès Docker contrôlé (« giving agents Docker without giving away the host »), multi-tenant |
| `google/gvisor` | isolation userspace forte, runtime OCI `runsc`. Pour plus tard : complexe à opérer |
| `secureCodeBox/secureCodeBox` | le scanner tourne dans son propre conteneur, orchestré par un opérateur Kubernetes |

**Ce que ça impose chez nous.** L'outil ne décide jamais de son propre isolement. Classification
`PASSIVE / ACTIVE / INTRUSIVE / DESTRUCTIVE` évaluée **avant** l'exécution, egress sur liste
blanche, timeout et quotas imposés par l'orchestrateur, journal d'audit écrit hors de portée
de l'outil exécuté.

**Note de réalisme.** `cuckoosandbox/cuckoo` est archivé et se déclare non maintenu ;
`nsacyber/WALKOFF` est archivé depuis 2020. Les deux références historiques du domaine sont
mortes. Ne pas les prendre pour base — mais leurs modèles `analyzer/` et `app_sdk/` restent
lisibles et instructifs.

---

## Q4 — Quel modèle de findings unifié, et comment préserver la donnée brute ?

**Réponse : s'aligner sur DefectDojo et les standards, ne pas inventer de modèle.**

| Repo | Ce qu'il apporte |
|---|---|
| `DefectDojo/django-DefectDojo` | des dizaines de parsers d'import, modèle produit / engagement / test / finding, BSD-3-Clause. **La référence à suivre** |
| `aquasecurity/trivy` | SARIF et CycloneDX en sortie native |
| `secureCodeBox/secureCodeBox` | `parser-sdk/` : un SDK pour écrire un parseur, et `hook-sdk/` pour post-traiter |
| `DependencyTrack/dependency-track` | `vuln-data-source/` et `vuln-analysis/` séparés : la source de vérité n'est pas le moteur d'analyse |
| `infobyte/faraday` | `architecture.md`, corrélation et collaboration sur findings |

**Ce que ça impose chez nous.** `RAW RESULT` conservé intégralement et immuable,
`NORMALIZED FINDING` dérivé et rejouable depuis le brut. Champs minimum : source (outil +
version + paramètres), asset, règle/CVE/CWE, sévérité avec **provenance du score**, preuve,
horodatage. Un parseur se branche via un SDK, jamais par un `if` dans le moteur.

**Décision à prendre en Phase 2.** SARIF comme pivot interne, ou modèle maison aligné sur
DefectDojo ? SARIF a l'avantage d'être un standard outillé ; le modèle DefectDojo a l'avantage
de couvrir le cycle de vie du finding (statut, faux positif, réouverture), ce que SARIF ne fait
pas. Piste : SARIF pour l'échange, modèle interne pour le cycle de vie.

---

## Q5 — Workflow déclaré à l'avance, ou composé dynamiquement par l'IA ?

**Réponse : les deux, mais pas au même endroit. Déclaré pour l'exécution, dynamique pour la planification.**

| Repo | Ce qu'il apporte |
|---|---|
| `temporalio/temporal` | exécution durable et rejeu déterministe. Un workflow **déclaré** qui survit aux pannes |
| `StackStorm/st2` | capteurs → règles → actions : composition déclarative éprouvée |
| `TracecatHQ/tracecat` | « prompt-to-automations » : l'IA **produit** l'automation, qui devient ensuite déclarative |
| `langchain-ai/langgraph` | graphe d'états pour la partie planification |
| `samugit83/redamon` | enchaîne recon → exploitation → post-exploitation, puis triage → fix → PR |
| `PurpleAILAB/Decepticon` | orchestrateur qui démarre des spécialistes à la demande (`ops_start("ad")`) |
| `Ed1s0nZ/CyberStrikeAI` | « intent becomes governed execution » : l'intention produit une exécution **gouvernée** |

**Ce que ça impose chez nous.** L'IA compose un plan ; le plan est **matérialisé en objet
déclaratif** avant exécution ; le policy engine évalue cet objet, pas une intention flottante ;
l'exécution est durable et rejouable. C'est exactement ce qui permet d'auditer après coup.

---

## 6. Synthèse BUILD / INTEGRATE / ADAPT / IGNORE par brique

| Brique de notre architecture | Décision | Appui |
|---|---|---|
| Intent engine | **BUILD** | aucun repo ne fait intention → capacités de façon réutilisable |
| Capability registry | **BUILD** (modèle) + **ADAPT** (schéma) | Cortex, Velociraptor, StackStorm, Nuclei, Trivy |
| Planner / router | **BUILD** sur **INTEGRATE** LangGraph | Decepticon, CyberStrikeAI, redamon |
| **Policy engine** | **INTEGRATE** | OPA + agent-governance-toolkit |
| Execution engine | **BUILD** + **INTEGRATE** ToolHive, Temporal | ToolHive, Tracecat, PentAGI |
| Sandbox | **INTEGRATE** | ToolHive (conteneur + egress), gVisor plus tard |
| Tool adapters | **BUILD** sur **INTEGRATE** FastMCP | FastMCP, MCP registry |
| Result normalization | **ADAPT** | DefectDojo, secureCodeBox `parser-sdk/` |
| Findings store | **ADAPT** | DefectDojo |
| Correlation | **BUILD** | **lacune réelle** : aucun repo ne corrèle des findings multi-outils |
| Reporting | **BUILD** | lacune, mais faible valeur différenciante |
| Remediation loop | **ADAPT** | redamon a déjà triage → fix → PR |

**Les deux seules lacunes réelles** — ce que personne ne fait et qui justifie le projet :
**l'intent engine** (intention → capacités) et **la corrélation multi-outils**. Tout le reste
existe déjà, sous une forme ou une autre.

---

## 7. Ce que la Phase 2 doit trancher

1. SARIF comme pivot, ou modèle interne aligné DefectDojo ? (Q4)
2. La politique vit dans le policy engine ; la gateway n'est qu'un point d'application. Validé ? (Q2)
3. Quel niveau d'isolement pour la Phase 3 : conteneur simple, ou ToolHive d'emblée ? (Q3)
4. **Licence de notre plateforme.** Non décidée. Le barème a noté comme si nous étions en
   permissif (Apache-2.0/MIT). Si nous visons AGPL, 16 repos changent de verdict.
5. `IBM/mcp-context-forge` est riche mais énorme : risque de sur-ingénierie dès la Phase 3.
   Faut-il s'en inspirer ou l'ignorer au démarrage ?
