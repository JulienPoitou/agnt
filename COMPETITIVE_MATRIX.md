# COMPETITIVE MATRIX — AGNT vs marché (2026-09-03)
> Échelle : 0 absent · 1 rudimentaire · 2 utilisable · 3 fort · 4 leader. AGNT noté sur PREUVES locales (fichiers/tests), concurrents sur docs publiques 2026.
> Légende preuve : [V]=VERIFIED local · [P]=PARTIALLY · [D]=DOCUMENTED ONLY · [C]=CONFIRMED vendor · [I]=INFERRED · [U]=UNKNOWN.

## Discovery
| Capacité | AGNT | XBOW | NodeZero | Pentera | Hadrian | Aikido | Escape | Snyk | Wiz | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| asset discovery | 1 [P] | 3 [C] | 4 [C] | 3 [C] | 4 [C] | 2 [C] | 3 [C] | 1 [I] | 4 [C] | AGNT: httpx/katana déclarés, crawl non éprouvé en prod (`docs/WEB_PENTEST_V1_SPEC.md` [D]) |
| subdomain/endpoint discovery | 2 [P] | 3 [C] | 3 [C] | 2 [I] | 4 [C] | 2 [C] | 4 [C] | 0 | 3 [C] | AGNT: ffuf provider actif, subfinder en proposition [P] |
| cloud discovery | 0 | 2 [I] | 4 [C] | 3 [C] | 1 [I] | 2 [C] | 1 [I] | 1 [I] | 4 [C] | AGNT: aucun provider cloud [V absent] |
| identity discovery | 0 | 2 [I] | 3 [C] | 3 [C] | 1 [I] | 1 [I] | 2 [C] | 0 | 3 [C] | AGNT: rien |
| repository discovery | 2 [V] | 1 [I] | 0 | 0 | 0 | 3 [C] | 0 | 3 [C] | 1 [I] | AGNT: catalogue 309 dépôts PHASE1 [V] |

## SAST / Supply-chain
| Capacité | AGNT | XBOW | NodeZero | Pentera | Hadrian | Aikido | Escape | Snyk | Semgrep | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| static analysis | 3 [V] | 2 [C] | 1 [I] | 1 [I] | 0 | 3 [C] | 1 [I] | 4 [C] | 4 [C] | AGNT: semgrep/bandit/ruff/eslint qualifiés, 13/13 test_selection [V] |
| secrets | 3 [V] | 1 [I] | 2 [C] | 2 [I] | 1 [I] | 2 [C] | 1 [I] | 2 [C] | 1 [I] | AGNT: gitleaks/detect-secrets/trufflehog3 + masquage large [V] |
| dependency/SCA | 3 [V] | 1 [I] | 1 [I] | 1 [I] | 0 | 3 [C] | 0 | 4 [C] | 2 [C] | AGNT: trivy/grype/pip-audit/npm-audit, remediation `dependency_bump` [V] |
| IaC/container | 2 [V] | 1 [I] | 1 [I] | 1 [I] | 0 | 2 [C] | 0 | 2 [C] | 3 [C] | AGNT: checkov 38 findings fixture, kics [V] |

## DAST / Pentest
| Capacité | AGNT | XBOW | NodeZero | Pentera | Hadrian | Aikido | Escape | Evidence |
|---|---|---|---|---|---|---|---|---|
| web scanning | 2 [P] | 4 [C] | 3 [C] | 2 [C] | 3 [C] | 3 [C] | 4 [C] | AGNT: nuclei/zap/ffuf déclarés, tests 59/59 en shims [P] |
| API/auth testing | 1 [P] | 3 [C] | 3 [C] | 2 [I] | 1 [I] | 3 [C] | 4 [C] | AGNT: `cible_autorisee` + userinfo masqué, pas d'OAuth/SSO [P] |
| business logic/IDOR/BOLA | 0 | 3 [C] | 3 [C] | 2 [I] | 2 [C] | 3 [C] | 4 [C] | AGNT: rien (trou béant) |
| exploit validation | 2 [V] | 4 [C] | 4 [C] | 4 [C] | 3 [C] | 3 [C] | 3 [C] | AGNT: Oracle 12/12 backend, pas encore branché au DAST web en prod [P] |
| attack paths/lateral | 1 [P] | 4 [C] | 4 [C] | 4 [C] | 2 [C] | 2 [C] | 2 [C] | AGNT: clusterer `same_asset` medium/high, pas de mouvement latéral [P] |
| retesting | 2 [V] | 3 [C] | 4 [C] | 4 [C] | 2 [C] | 4 [C] | 3 [C] | AGNT: benchmark+remediation re-scan (Chantier 3) [V] |

## Orchestration / Evidence / Remediation / Platform
| Capacité | AGNT | XBOW | NodeZero | Pentera | Hadrian | Aikido | Wiz | Evidence |
|---|---|---|---|---|---|---|---|---|
| deterministic planning | 3 [V] | 2 [I] | 1 [I] | 3 [C] | 1 [I] | 1 [I] | 1 [I] | AGNT: intent→providers→plan.json avec motifs [V] |
| policy engine | 3 [V] | 2 [I] | 2 [I] | 3 [C] | 1 [I] | 1 [I] | 2 [I] | AGNT: OPA + verrou durci, refus nommés [V] |
| sandbox/execution | 3 [V] | 2 [I] | 2 [I] | 2 [I] | 1 [I] | 2 [I] | 0 | AGNT: bwrap --unshare-net, OCI 12/12, egress par mission [V] |
| raw evidence/replay | 3 [V] | 4 [C] | 3 [C] | 3 [C] | 2 [C] | 2 [C] | 2 [C] | AGNT: brut_* + raw_*, ProofCapsule, run.json [V] |
| auto-remediation/PR | 2 [V] | 2 [C] | 3 [C] | 4 [C] | 2 [C] | 4 [C] | 3 [C] | AGNT: remediation déterministe, pas de PR auto [V] |
| CI/CD natif | 1 [P] | 2 [I] | 2 [I] | 3 [C] | 2 [I] | 4 [C] | 2 [I] | AGNT: ci.yml minimal, pas de quality gates [P] |
| self-hosting | 4 [V] | 2 [C] | 2 [C] | 1 [I] | 0 | 2 [C] | 0 | AGNT: 100% local, 2 Go RAM, offline [V] |
| MCP governé | 2 [P] | 1 [U] | 1 [U] | 3 [C] | 1 [U] | 1 [U] | 3 [C] | AGNT: mcp_transport/provider/bootstrap + 7 batteries test_mcp* [P] |
| AI/agent security | 1 [P] | 2 [C] | 1 [I] | 1 [I] | 1 [I] | 2 [C] | 3 [C] | AGNT: tests adversariaux 46 cas, pas de suite prompt-injection [P] |

## Lecture
- AGNT mène : self-hosting (4), sandbox/policy déterministe (3), evidence/replay (3), SAST/secrets/SCA locaux (3).
- AGNT perd : cloud/identité (0), logique métier (0), ASM continu (1), CI/CD remediation-PR (1-2), mouvement latéral (1).
