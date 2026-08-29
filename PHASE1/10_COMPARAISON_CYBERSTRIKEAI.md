# Comparaison CyberStrikeAI — pause stratégique avant l'étape 5 (2026-08-29)

**Objet.** Avant de transformer le moteur en système d'investigation (étape 5),
comparer notre socle (étapes 1-4, code réel exécuté) avec `Ed1s0nZ/CyberStrikeAI`
— le projet le plus proche de notre trajectoire, déjà identifié en Phase 1
(`02_TRIAGE.csv` : « concurrent », 6013★ à l'époque ; `03_ARCHI_REFERENCE.md` :
« intent becomes governed execution »).

**Méthode.** Pas de diagrammes : leurs faits viennent du dépôt et de leur
documentation (consultés le 2026-08-29, sources en fin de document) ; les nôtres
viennent du workspace (fichiers cités, mesures des batteries d'étapes 1-4).
Aucune des deux colonnes n'est enjolivée.

**Distinction préalable.** `Ed1s0nZ/CyberStrikeAI` (Go, celui de notre catalogue)
n'est pas `CyberStrikeus/CyberStrike` (TypeScript, harness offensif) qui circule
sous un nom voisin. Cette comparaison porte sur le premier.

---

## 1. CyberStrikeAI, état mesuré (2026-08-29)

- Go + Eino (agents LLM), ~6k★, 976 forks, 2 220 commits, 145 tags — projet
  vivant et adopté.
- Positionnement offensif assumé, « pour opérations autorisées » : 100+ outils
  YAML couvrant la kill chain (nmap, sqlmap, nuclei, metasploit, hashcat,
  mimikatz, bloodhound…), **WebShell** et **C2 intégré** (désactivé par défaut),
  workspace auditable (« evidence becomes operational memory »).
- Gouvernance : HITL (approbations), allowlists d'outils, Audit Agent, RBAC
  multi-utilisateurs, logs d'audit, persistance SQLite, replay.
- Intégration : MCP natif (HTTP/stdio/SSE), fédération MCP externe, découverte
  dynamique d'outils ; RAG ; workflows visuels.
- Exécution : shell sur l'hôte (`internal/security/executor.go`), outils
  installés par brew/apt et attendus sur le PATH ; « les outils manquants sont
  sautés ou substitués à l'exécution » (README).
- Leurs propres garde-fous documentés : « HITL Is Not Magic » (un HITL voit un
  nom d'outil et des arguments, pas l'impact réel) ; « No high-risk tools in
  global allowlist » ; modèle de menace explicite (prompt injection, MCP
  malveillant, tampering des YAML d'outils).
- Format d'outil : `name/command/args/parameters` + `additional_args` — chaîne
  libre ajoutée à la ligne de commande (« Ensure valid syntax to avoid command
  injection » — la charge de la preuve est sur l'opérateur). **Aucun épinglage
  de version, aucune empreinte, aucune spécification d'extraction de sortie.**

## 2. Notre socle, état mesuré (mêmes date et méthode)

- 8 providers intégrés (trivy, grype, semgrep, semgrep_go, bandit,
  bandit_custom, gitleaks, checkov, kics — whitelist dans
  `PHASE3/slice/provider_manifest.py`), tous PASSIF, chacun qualifié par
  exécution sandbox réelle (dossiers de qualification, ATTENDUS régénérables,
  `PHASE3/harnais.py`).
- 2 fan-out réels bornés (`trivy×grype`, `checkov×kics`), convergence
  inter-outils mesurée (6/6 paquets, clusters à raisons explicites).
- 21 batteries de tests vertes ; pool dérivé de 309 dépôts catalogués Phase 1.

## 3. Comparaison par axe

| Axe | CyberStrikeAI (leurs docs) | Nous (notre code) | Écart |
|---|---|---|---|
| Périmètre | Offensif (kill chain, C2, WebShell) | Passif/défensif (SAST, SCA, IaC, secrets) | **Produits différents aujourd'hui** |
| Décision | Agents Eino : le LLM choisit les outils ; HITL approuve | Intent → capacités → plan **déterministe** matérialisé AVANT exécution ; LLM = propositions enregistrées comme données | **CLAIR** (à défendre) |
| Policy | Config plateforme + allowlists + HITL | OPA indépendant (moteur externe, policy versionnée), scope immuable, l'agent ne peut pas élargir son périmètre | **CLAIR** (mécanisme, pas intention) |
| Exécution | Shell sur l'hôte, outils sur PATH, `additional_args` libre | bwrap `--unshare-net/user/pid/ipc/uts` + rlimits, argv validé (fragments interdits), whitelist binaire, aucun argument libre | **CLAIR** |
| Supply chain | brew/apt, pas d'épinglage documenté | versions + sha256 + tarball audités (`manifeste_dependances.yaml`), vérifiés au bootstrap | **CLAIR** |
| Qualification d'intégration | Recette YAML = intégrée | Harnais : capture réelle, stabilité, ATTENDUS, dossier — puis approbation humaine | **CLAIR** |
| Corrélation findings | Attack-chain modeling (graphe d'opérations) ; pas de corrélation/déduplication findings multi-outils visible | Clusterer à raisons explicites, cross_tool, « ne jamais forcer un regroupement », gravité jamais inventée | **CLAIR** (lacune Phase 1 confirmée) |
| Preuve/couverture | Evidence d'actions, audit logs, replay | Mission append-only, raw brut conservé, couverture scanned/not_scanned motivée, empreinte de contexte (versions, bases, policy, registre) | Complémentaires plus qu'opposés |
| Largeur d'outils | 100+ recettes, MCP fédération, découverte dynamique | 8 intégrés profonds + 309 catalogués non intégrés | **ILS GAGNENT** |
| Produit | Web UI, RBAC multi-utilisateurs, RAG, workflows visuels, communauté 6k★ | Moteur + batteries, pas d'UI | **ILS GAGNENT** |
| Traction | 2 220 commits, 145 tags | Prototype de recherche | **ILS GAGNENT** |

## 4. Verdict

**La différenciation est CLAIRE sur cinq axes vérifiables dans notre code ce
jour** — et ce sont exactement ceux que l'étape 5 va solliciter :

1. **capability-first + décision déterministe** : chez eux le LLM est dans la
   boucle de décision (leur doc le dit : le HITL « ne voit pas l'impact réel ») ;
   chez nous le plan est un objet évalué par OPA avant toute exécution.
2. **policy indépendante** : OPA externe vs configuration de plateforme.
3. **exécution contrôlée** : sandbox sans réseau + rlimits + argv validé vs
   shell hôte + `additional_args` libre.
4. **supply chain épinglée et qualification par preuve** : sha256 + harnais vs
   PATH + « skipped or substituted at runtime ».
5. **corrélation findings à raisons explicites** : leur attack-chain modélise
   des opérations, pas des findings multi-outils ; notre clusterer le fait et
   rend compte de ce qu'il ne sait pas regrouper.

**Elle est FLOUE sur deux dérives possibles** — et seulement si nous dérivons :

- **A. LLM en boucle de décision.** Si l'étape 5 laisse un modèle séquencer des
  exécutions (au lieu d'enregistrer ses propositions comme données), nous
  devenons un clone plus faible de leur agent — sans leur largeur d'outils.
- **B. Course à la largeur.** Si nous intégrons des outils sans harnais pour
  rattraper « 100+ recettes », nous perdons l'avantage preuve — le seul qu'ils
  ne peuvent pas copier en un commit.

**Ce qu'ils font mieux, sans enjolivement** : largeur (100+ outils), MCP
fédération déjà livrée, UI/RBAC/RAG, attack-chain visuel, communauté. Si la
cible produit inclut ces briques, la séquence en 9 étapes les traite plus tard
(MCP notamment) — et il faudra assumer « plus lent, mais prouvé ».

## 5. Conséquences pour l'étape 5 (garde-fous proposés)

1. **L'épine dorsale reste déterministe** : l'investigation (étape 5) compose
   des capacités via le registre et le plan ; les propositions LLM restent des
   données enregistrées dans la mission, jamais des décisions d'exécution.
2. **Aucun nouveau provider sans harnais** (règle déjà actée à l'étape 4 — elle
   devient ici un garde-fou stratégique, pas seulement technique).
3. **L'étape 5 approfondit corrélation/couverture/investigation passive** — pas
   d'outillage offensif : c'est la frontière produit qui nous distingue d'eux ;
   la franchir sans différenciation offensive propre serait entrer sur leur
   terrain avec 8 outils contre 100+.

## Sources (consultées le 2026-08-29)

- `github.com/Ed1s0nZ/CyberStrikeAI` — README (tagline, Eino, MCP, RAG,
  attack-chain, quick start, catégories d'outils, « missing tools are skipped or
  substituted at runtime »), README_CN (RBAC, Audit Agent, WebShell, C2).
- `docs/en-US/security-model.md` — frontières de confiance, modèle de menace,
  « HITL Is Not Magic », production baseline, ancres de code
  (`internal/security/executor.go`, `internal/handler/hitl_execution.go`,
  `internal/audit/service.go`).
- `tools/README_EN.md` — format YAML des outils, `additional_args`
  (« Ensure valid syntax to avoid command injection »), pas d'épinglage.
- Workspace : `PHASE1/02_TRIAGE.csv`, `03_ARCHI_REFERENCE.md`,
  `06_MATRICE_COUVERTURE.md` (« Correlation : lacune réelle ») ;
  `PHASE3/slice/{provider_manifest,sandbox,policy,clusterer,mission}.py` ;
  `PHASE3/manifeste_dependances.yaml` ; `PHASE3/harnais.py` ;
  `PROJET_ETAT.md` (étapes 1-4).
