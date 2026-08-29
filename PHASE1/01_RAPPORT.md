# PHASE 1 — ANALYSE DE L'EXISTANT

_Inventaire reçu le 2026-08-27 : `uploads/liste complete.txt` (5 934 lignes)._
_Toutes les métadonnées (étoiles, dernier commit, licence, archivage) sont relevées sur_
_github.com, pas estimées. Voir `05_PROVENANCE.md`._

---

## 1. Ce que contenait réellement l'inventaire

| Étape | Nombre |
|---|---|
| Fiches brutes dans le fichier | **444** |
| Doublons fusionnés (1re passe, sur URL) | 111 |
| Doublons fusionnés (2e passe, après correction d'URL) | 9 |
| **Entrées uniques** | **324** |
| — dont exploitables (repo GitHub résolu) | **295** |
| — dont URL GitHub en 404, non résolues | 14 |
| — dont organisations GitHub, pas un repo | 5 |
| — dont hors périmètre (outil propriétaire, agrégat, artefact) | 10 |

Le fichier parlait de ~125 repos. Il en contenait 444 fiches, soit 324 projets distincts.
**L'écart était trop grand pour être traité à l'œil** : d'où le pipeline `parse_liste.py →
fix_urls.py → enrich.py → scoring.py`, rejouable de bout en bout.

Répartition par section (entrées uniques) :

| Section | Total | dont importance « Haute » |
|---|---|---|
| 🟤 Threat Intelligence / OSINT | 98 | 34 |
| 🟡 Vulnerability Management | 56 | 15 |
| 🔴 Offensive / Pentesting | 45 | 13 |
| 🔵 Defensive / Blue Team | 28 | 13 |
| 🟣 MCP / Tool Aggregation | 26 | 14 |
| 🟢 AI Security Agents | 26 | 10 |
| 🟠 Security Orchestration / Automation | 20 | 5 |
| 🟠 DevSecOps / CI-CD Security | 14 | 0 |
| sections « Compléments » + sans section | 20 | 3 |

---

## 2. Hygiène de l'inventaire : ce qui ne tenait pas

Ces défauts auraient faussé tout le tri. Ils sont corrigés, et la correction est tracée.

| Défaut trouvé | Preuve | Correction |
|---|---|---|
| **14 URL GitHub en 404** | HEAD/GET 404 sur github.com | 13 résolues par recherche, 14 restantes classées hors périmètre — `04_URL_CORRIGEES.md` |
| `GreyDoff/PentestGPT` | 404 | corrigé en `GreyDGL/PentestGPT` (200) |
| `StrangeBee-Official/thehive` | 404 | corrigé en `TheHive-Project/TheHive` (200) |
| `abuse-ch/URLhaus` | 404 — l'org est **`abusech`** | corrigé via recherche GitHub |
| `spiderfoot/spiderfoot` | 404 | corrigé en `smicallef/spiderfoot` (200) |
| **9 doublons non détectés** | `wazuh/wazuh` et `GreyDGL/PentestGPT` présents 2× | 2e passe de dédup après correction d'URL |
| `mitre/caldera` **et** `apache/caldera` | mêmes 7 215 étoiles, même date | même projet donné à l'ASF : à ne compter qu'une fois |
| Étiquettes de section fausses | `langchain-ai/langchain`, `grafana`, `keycloak`, `hashicorp/vault`, `moby` classés « Vulnerability Management » | signalé, non corrigé : le reclassement des 295 entrées est un chantier distinct |

---

## 3. État de santé mesuré des 295 repos exploitables

| Signal | Nombre | Conséquence sur le barème |
|---|---|---|
| Dernier commit > 18 mois | **34** | gate **G1** → jamais INTEGRATE |
| Repo **archivé** | **14** | gate **G5** → lecture seule, jamais INTEGRATE |
| Licence inconnue | **59** | gate **G2** → pas de réutilisation de code |
| Copyleft fort (AGPL/SSPL/BUSL) | **16** | gate **G2** |
| Copyleft (GPL/LGPL/MPL) | **33** | gate **G2** |

Deux points à ne pas survoler :

- **G1 et G5 ne se recouvrent pas.** `aliasrobotics/cai` a été archivé le 22 août 2026 avec un
  commit du même jour : la date seule ne le disqualifiait pas. Inversement `smicallef/spiderfoot`
  n'est pas archivé mais n'a plus bougé depuis novembre 2023. Il fallait les deux gates.
- **Les 59 « licence inconnue » ne sont pas 59 repos sans licence.** C'est « je n'ai pas pu lire
  un identifiant SPDX fiable ». GitHub renvoie `NOASSERTION` pour `hashicorp/vault`
  (`license.name: "Other"`). Le sens de l'erreur est le bon — on refuse de réutiliser du code de
  licence inconnue — mais chaque cas doit être revérifié à la main avant de conclure.

---

## 4. La shortlist : 38 repos retenus

Barème `CRITERES.md` : C1 architecture 50 %, C2 code 30 %, C3 couverture 20 %, gates avant
pondération. **Tableaux générés depuis `01_GRILLE_TRI.csv`.**

**Révision du 2026-08-27** — trois règles, qui changent la répartition :
1. une gate de licence bloque la **réutilisation de code**, pas le pilotage d'un outil en CLI ;
2. un usage `référence architecturale` n'est **jamais** INTEGRATE : on ne l'exécute ni ne l'importe ;
3. `mode_integration` doit refléter la réalité technique — OPA est un **sidecar HTTP**, pas un SDK
   Python ; DefectDojo est un **modèle à adapter**, pas une appli Django à importer.

**INTEGRATE : 12 repos.** Point important pour la Phase 3 : seulement
**2 d'entre eux impliquent un import de code**, et aucun
n'est nécessaire au minimal core. Le cœur démarre donc sans dépendance de licence.

#### INTEGRATE — 12 repos

| Repo | Score | Gate | Usage | Mode |
|---|---|---|---|---|
| `aquasecurity/trivy` | 5.0 | — | outil externe | CLI |
| `projectdiscovery/nuclei` | 5.0 | — | outil externe | CLI |
| `stacklok/toolhive` | 4.8 | — | composant d'infrastructure | conteneur |
| `open-policy-agent/opa` | 4.6 | — | composant d'infrastructure | HTTP sidecar |
| `velocidex/velociraptor` | 4.5 | G2:licence-inconnue | outil externe | API |
| `microsoft/agent-governance-toolkit` | 4.3 | — | code réutilisable | à confirmer |
| `google/gvisor` | 4.1 | — | composant d'infrastructure | conteneur |
| `jlowin/fastmcp` | 4.1 | — | code réutilisable | SDK |
| `temporalio/temporal` | 4.1 | — | composant d'infrastructure | API |
| `TheHive-Project/Cortex` | 4.0 | G2:copyleft-fort | outil externe | API |
| `prowler-cloud/prowler` | 4.0 | — | outil externe | CLI |
| `semgrep/semgrep` | 4.0 | G2:copyleft | outil externe | CLI |

> **Lecture** : `outil externe` = piloté en CLI/API, la licence ne bloque pas. `code réutilisable`
> = importé, licence compatible requise. `composant d'infrastructure` = déployé à côté.
#### ADAPT (archi) — 19 repos

| Repo | Score | Gate | Usage | Mode |
|---|---|---|---|---|
| `DefectDojo/django-DefectDojo` | 4.7 | — | référence architecturale | lecture |
| `usestrix/strix` | 4.7 | — | référence architecturale | lecture |
| `PurpleAILAB/Decepticon` | 4.5 | — | référence architecturale | lecture |
| `TracecatHQ/tracecat` | 4.5 | G2:copyleft-fort | référence architecturale | lecture |
| `secureCodeBox/secureCodeBox` | 4.5 | — | référence architecturale | lecture |
| `Ed1s0nZ/CyberStrikeAI` | 4.4 | — | référence architecturale | lecture |
| `vxcontrol/pentagi` | 4.4 | — | référence architecturale | lecture |
| `StackStorm/st2` | 4.3 | — | référence architecturale | lecture |
| `DependencyTrack/dependency-track` | 4.0 | — | référence architecturale | lecture |
| `Tencent/AI-Infra-Guard` | 4.0 | — | référence architecturale | lecture |
| `falcosecurity/falco` | 4.0 | — | référence architecturale | lecture |
| `aliasrobotics/cai` | 3.9 | G5:archive | référence architecturale | lecture |
| `KeygraphHQ/shannon` | 3.7 | G2:copyleft-fort | référence architecturale | lecture |
| `infobyte/faraday` | 3.7 | G2:copyleft | référence architecturale | lecture |
| `intelowlproject/IntelOwl` | 3.7 | G2:copyleft-fort | référence architecturale | lecture |
| `samugit83/redamon` | 3.7 | — | référence architecturale | lecture |
| `modelcontextprotocol/registry` | 3.6 | G2:licence-inconnue | code réutilisable | API |
| `TheHive-Project/TheHive` | 3.4 | G2:copyleft-fort;G5:archive | référence architecturale | lecture |
| `cuckoosandbox/cuckoo` | 3.2 | G1:inactif;G2:licence-inconnue;G5:archive | référence architecturale | lecture |

C'est la catégorie la plus utile du lot, et celle qu'un tri par étoiles aurait jetée.
#### ADAPT — 7 repos

| Repo | Score | Gate | Usage | Mode |
|---|---|---|---|---|
| `IBM/mcp-context-forge` | 3.8 | — | composant d'infrastructure | API |
| `agentgateway/agentgateway` | 3.8 | — | composant d'infrastructure | conteneur |
| `agentic-community/mcp-gateway-registry` | 3.8 | — | composant d'infrastructure | API |
| `cisco-ai-defense/mcp-scanner` | 3.8 | — | outil externe | CLI |
| `langchain-ai/langgraph` | 3.6 | — | code réutilisable | SDK |
| `invariantlabs-ai/mcp-scan` | 3.1 | — | outil externe | CLI |
| `mcpjungle/MCPJungle` | 3.1 | G2:copyleft | composant d'infrastructure | API |
#### IGNORE — 5 repos

| Repo | Score | Gate | Usage | Mode |
|---|---|---|---|---|
| `GH05TCREW/pentestagent` | 3.0 | — | référence architecturale | lecture |
| `GreyDGL/PentestGPT` | 3.0 | — | référence architecturale | lecture |
| `metatool-ai/metamcp` | 3.0 | — | référence architecturale | lecture |
| `0x4m4/hexstrike-ai` | 2.7 | — | référence architecturale | lecture |
| `nsacyber/WALKOFF` | 2.5 | G1:inactif;G2:licence-inconnue;G5:archive | référence architecturale | lecture |

**Total notés : 43 — shortlist : 38 repos** (cible 35–40 ✓).

### 4.1 Ce qu'on déploie réellement — les INTEGRATE

| Brique | Repo | Usage | Mode | Phase |
|---|---|---|---|---|
| Scanner multi-cibles | `aquasecurity/trivy` | outil externe | CLI | 3 |
| Scanner web/infra | `projectdiscovery/nuclei` | outil externe | CLI | 5+ |
| Isolation des MCP | `stacklok/toolhive` | composant d'infrastructure | conteneur | 7 |
| Policy engine | `open-policy-agent/opa` | composant d'infrastructure | HTTP sidecar | 3 |
| Collecte endpoint | `velocidex/velociraptor` | outil externe | API | 5+ |
| — | `microsoft/agent-governance-toolkit` | code réutilisable | à confirmer | ? |
| Sandbox userspace (hors Phase 3) | `google/gvisor` | composant d'infrastructure | conteneur | 7+ |
| Adaptateurs MCP (hors Phase 3) | `jlowin/fastmcp` | code réutilisable | SDK | 6+ |
| Exécution durable (hors Phase 3) | `temporalio/temporal` | composant d'infrastructure | API | 6+ |
| Analyseurs / jobs | `TheHive-Project/Cortex` | outil externe | API | réf. |
| Conformité cloud | `prowler-cloud/prowler` | outil externe | CLI | 5+ |
| Analyse statique | `semgrep/semgrep` | outil externe | CLI | 3 |

---

## 5. Le point de méthode qui change tout

Une gate de licence ne s'applique **qu'à la réutilisation de code**. Piloter Semgrep ou Nmap
en CLI ne demande aucune licence compatible.

Conséquence : `semgrep → ADAPT (archi)` est un verdict correct pour le *code* et trompeur pour
l'*usage*. Pour chaque repo, la fiche doit dire lequel des deux on vise. C'est fait en 4.1.

Sans cette distinction, la Phase 3 partirait sur l'hypothèse fausse qu'il faut forker ou réécrire
la moitié des outils qu'on veut simplement exécuter.
