# MARKET GAPS — où frapper (2026-09-03)

## Table 1 — Où les concurrents dominent AGNT
| Domaine | Leader | Pourquoi | Effort AGNT | Priorité |
|---|---|---|---|---|
| Pentest réseau interne/latéral | NodeZero/Pentera (4) | RAT, credential attacks, pivots cloud, centaines d'outils chaînés | Énorme (nouveau domaine) | P3 — NE PAS suivre |
| ASM externe continu event-driven | Hadrian (4) | scans horaires + retest au changement + shadow IT | Élevé (infra 24/7) | P3 — NE PAS suivre |
| Remediation-PR + retest dev | Aikido (4) | AutoFix merge-ready par diff + retest auto | Moyen (moteur existe) | P1 — suivre via capability |
| API/GraphQL logique métier | Escape (4) | scanner natif schéma, auth multi-rôles | Moyen | P1 — vertical après web |
| Cloud graph/toxic combos | Wiz (4) | agentless + runtime sensor + 500M ARR | Énorme | P3 — intégrer, pas copier |
| SAST/SCA IDE | Snyk/Semgrep (4) | 35k fixes experts, IDE, reachability | Énorme | P3 — orchestrer, pas copier |

## Table 2 — Où AGNT peut réellement les dépasser
| Domaine | Concurrent | Faiblesse | Opportunité AGNT | Moat |
|---|---|---|---|---|
| Exécution vérifiable locale | Tous (SaaS/cloud) | données qui sortent, boîte noire, coût par scan | sandbox bwrap+OPA+evidence 100% locale, 2 Go RAM | Security Execution Fabric |
| Neutralité multi-outils | Tous (stack fermée) | lock-in, 1 moteur = 1 avis | 1 capability = N providers comparables | Provider Independence |
| Preuve rejouable | XBOW/NodeZero (preuves propriétaires) | preuve non portable, pas de brut d'outil | brut_* + raw_* + ProofCapsule + run.json ouverts | Evidence Graph |
| Politique explicite | Tous (guardrails implicites) | "l'IA décide", non auditable | OPA + refus nommés + journal append-only | Deterministic Boundary |
| Sécurité des agents/MCP | Wiz/Pentera partiels | MCP = nouvelle surface sans garde standard | REGISTRY→POLICY→SANDBOX→EVIDENCE pour chaque tool | Open Security Fabric |
| Coût marginal | Aikido $10/agent, SaaS au scan | facturation à l'usage | outils OSS épinglés, coût ≈ 0 par run | — (avantage prix) |

## Table 3 — Marché mal servi (priorité max : coûteux × fréquent × dur × multi-outils × vérification × self-hosting)
1. **Preuve d'exploitation portable** : tout le monde valide, personne ne livre un bundle rejouable hors plateforme. AGNT peut en faire un standard ouvert.
2. **Pentest par diff pour équipes sans AppSec** : Aikido le fait en SaaS fermé ; version self-hosted/secret-friendly inexistante (hôpitaux, industrie, défense, régulés).
3. **Gouvernance MCP/agent** : explosion des serveurs MCP (perso + tiers) sans contrôle d'exécution standard. Wiz observe, Pentera expose ; personne n'impose policy+sandbox par défaut.
4. **Corrélation multi-outils honnête** : SAST+DAST combinés = promesse XBOW/Aikido en boîte noire ; version déclarative ouverte (même finding, N outils, 1 empreinte) inexistante.
5. **Validation continue sans cloud** : NodeZero planifié = cloud ; continu + on-prem + offline = vide.
