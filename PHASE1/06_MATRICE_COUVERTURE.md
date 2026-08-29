# PHASE 1 — MATRICE DE COUVERTURE

_Centrée sur les capacités et les couches, pas sur le nombre de repos._
_Chaque candidat cité a été vérifié présent dans `01_GRILLE_TRI.csv` par requête programmatique._
_Licence de travail retenue : **Apache-2.0** (provisoire)._

**Colonnes `confiance` et `preuve`** : elles existent pour qu'on puisse distinguer ce qui est
mesuré de ce qui est supposé. `haute` = vérifié dans l'inventaire ou le code ; `moyenne` = README
et arborescence seulement ; `faible` = inférence, à confirmer en Phase 2.

---

## A. Capacités

| Axe | Élément | État | Candidats | Décision | Confiance | Preuve |
|---|---|---|---|---|---|---|
| Capability | **Secret detection** | couverte par outils | `gitleaks/gitleaks` (MIT), `trufflesecurity/trufflehog` (AGPL), `GitGuardian/ggshield` (MIT), `Yelp/detect-secrets` | **outil externe** CLI | haute | 9 candidats dans l'inventaire, tous actifs |
| Capability | **Dependency / SCA** | couverte | `DependencyTrack/dependency-track`, `aquasecurity/trivy`, `anchore/grype`, `anchore/syft` | **outil externe** + **référence** DependencyTrack | haute | 28 candidats ; Trivy déjà INTEGRATE |
| Capability | **SAST** | couverte | `semgrep/semgrep` (LGPL), `PyCQA/bandit`, `Bearer/bearer`, `secureCodeBox` | **outil externe** CLI | haute | 4 candidats |
| Capability | **Container / image** | couverte | `aquasecurity/trivy`, `anchore/grype`, `falcosecurity/falco` | **outil externe** | haute | 8 candidats |
| Capability | **Cloud posture** | couverte | `prowler-cloud/prowler`, `kubescape/kubescape`, `nccgroup/ScoutSuite`, `turbot/steampipe` | **outil externe** | haute | 9 candidats |
| Capability | **IaC** | couverte | `bridgecrewio/checkov`, `Checkmarx/kics`, `aquasecurity/tfsec` | **outil externe** | haute | 3 candidats |
| Capability | **Endpoint / DFIR** | couverte | `velocidex/velociraptor`, `osquery/osquery`, `dfir-iris/iris-web` | **outil externe** + **référence** | haute | 7 candidats |
| Capability | **Threat intelligence** | couverte, dispersée | `OpenCTI-Platform/opencti`, `MISP/MISP`, `intelowlproject/IntelOwl`, `smicallef/spiderfoot` | **référence architecturale** | moyenne | 26 candidats, mais aucun modèle commun |
| Capability | **CVE lookup** | couverte | `mukul975/cve-mcp-server`, sources NVD/GHSA | **outil externe** API | moyenne | candidats présents, non notés |
| Capability | **SBOM** | couverte | `anchore/syft`, CycloneDX via Trivy | **outil externe** | haute | format standardisé, pas de build nécessaire |
| Capability | **🔴 Corrélation multi-outils** | **LACUNE MAJEURE** | — | **BUILD** | **haute** | **requête `correlat` sur 324 entrées → 0 candidat** |
| Capability | **🔴 Intent → capabilities** | **LACUNE MAJEURE** | — | **BUILD** | haute | aucun repo ne déclare de capacités consommables par une IA |
| Capability | Remediation / vérification | partielle | `samugit83/redamon` (triage → fix → PR) | **référence**, LATER | moyenne | un seul candidat, boucle déjà implémentée |
| Capability | Reporting | faible | — | **BUILD** | haute | faible valeur différenciante |

## B. Couches d'architecture

| Axe | Élément | État | Candidats | Décision | Confiance | Preuve |
|---|---|---|---|---|---|---|
| Couche | **Intent engine** | lacune | `Ed1s0nZ/CyberStrikeAI`, `PurpleAILAB/Decepticon` | **BUILD** sur **référence** | haute | aucun ne expose intention → capacités de façon réutilisable |
| Couche | **Capability registry** | **modèles existants prometteurs, intégration non résolue** | `velocidex/velociraptor`, `TheHive-Project/Cortex`, `secureCodeBox/secureCodeBox`, `modelcontextprotocol/registry`, `projectdiscovery/nuclei` | **référence architecturale** → BUILD | moyenne | 5 candidats, aucun ne couvre notre périmètre multi-domaine |
| Couche | **Planner / router** | candidats | `langchain-ai/langgraph`, `samugit83/redamon` | **code réutilisable** (LangGraph) | moyenne | graphe d'états éprouvé, aucun contenu sécurité |
| Couche | **Policy engine** | candidats solides | `open-policy-agent/opa`, `microsoft/agent-governance-toolkit` | **code réutilisable** | haute | OPA CNCF graduated, `sdk/` + `topdown/` + `bundle/` |
| Couche | **Execution / sandbox** | plusieurs options | `stacklok/toolhive`, `google/gvisor`, nsjail via `TracecatHQ/tracecat` | **composant d'infrastructure**, à décider en Phase 2 | moyenne | trois voies incompatibles entre elles |
| Couche | **Tool adapters** | à construire sur SDK | `jlowin/fastmcp`, `modelcontextprotocol/registry` | **code réutilisable** | haute | FastMCP Apache-2.0, API gelée côté registry |
| Couche | **Result normalization** | modèles mûrs | `DefectDojo/django-DefectDojo`, `secureCodeBox` (`parser-sdk/`) | **code réutilisable** / **référence** | haute | dizaines de parsers d'import existants |
| Couche | **Findings store** | candidat direct | `DefectDojo/django-DefectDojo` (BSD-3) | **code réutilisable** | haute | modèle produit/engagement/test/finding |
| Couche | **🔴 Correlation engine** | **LACUNE MAJEURE** | — | **BUILD** | **haute** | 0 candidat dans tout l'inventaire |
| Couche | **Orchestration** | forte mais dispersée | `temporalio/temporal`, `StackStorm/st2`, `TracecatHQ/tracecat` | **composant d'infrastructure**, à décider en Phase 2 | moyenne | durable vs événementiel vs sandboxé : trois philosophies |
| Couche | **Reporting** | faible | — | **BUILD** | haute | commodité, pas un différenciant |

---

## C. Les cinq catégories de lacune, appliquées

| Catégorie | Où elle s'applique |
|---|---|
| **Aucun repo pertinent** | corrélation multi-outils, intent engine, reporting |
| **Repo existant mais inutilisable** | `cuckoosandbox/cuckoo` (archivé, non maintenu), `nsacyber/WALKOFF` (archivé 2020) |
| **Repo intéressant uniquement architecturalement** | 18 repos en `ADAPT (archi)` — dont Cortex, Velociraptor, Tracecat |
| **Capacité couverte par un outil externe** | secret, SCA, SAST, container, cloud, IaC, endpoint, CVE |
| **Capacité que nous devons construire** | intent engine, capability registry, corrélation, reporting |

---

## D. Ce que la matrice prouve

**Huit capacités sur quatorze sont déjà couvertes par des outils qu'il suffit de piloter.**
Aucune ne demande de code de notre part. C'est la validation directe du principe fondateur :
on ne recrée pas Nmap, Nuclei ou Semgrep.

**Trois éléments n'existent nulle part** : l'intent engine, le capability registry unifié,
et la corrélation multi-outils. Ce sont les trois seules raisons d'être du projet.

**La corrélation est la plus solide des trois**, et c'est la plus démontrable :
une recherche sur les 324 entrées de l'inventaire renvoie zéro candidat. `DefectDojo`,
`TheHive` et `Faraday` font du regroupement et de la déduplication **au sein d'une même
plateforme** ; aucun ne corrèle des findings hétérogènes issus d'outils différents.

**Deux décisions de Phase 2 sont déjà identifiables comme coûteuses** : le choix du sandbox
(ToolHive / gVisor / nsjail sont trois voies incompatibles) et le choix de l'orchestrateur
(durable vs événementiel vs sandboxé). Ni l'un ni l'autre ne sont réversibles facilement.

## E. Confiance — ce qui reste à prouver

Toute la colonne `confiance` à `moyenne` repose sur README + arborescence. **Aucun code n'a été
lu, aucun test n'a été compté.** Avant de décider un INTEGRATE en `code réutilisable`
(OPA, DefectDojo, FastMCP, agent-governance-toolkit), il faut lire le code réel. C'est l'objet
du P1.
