# AGNT ROADMAP — H0→H17 + priorisation (2026-09-03)
> Score par feature : VALUE × DIFF × URGENCY × MOAT / EFFORT / RISK (1-5). 10X test : priorité au levier multi-providers. Moat test : copiable en 2 semaines = pas un moat.

## H0 — TRUST FOUNDATION (0-2 sem, P0)
Tests/CI verts, OPA officiel, licence tranchée, F2/F7 documentés, build Node mesuré, bootstrap rejoué, gitleaks.toml épinglé, CRLF propre. DoD : 1 mission reproductible sans LLM pour la sécurité. Score type : 5×3×5×4/2/2 = 75.

## H1 — WEB SECURITY VERTICAL (2-6 sem, P0, first advantage)
`POST /api/engagements/web` + WebScan (httpx→katana→ffuf→nuclei→Oracle http_response, replay 3/5 + témoin), scope RDN, rate limits, run.json/journal. Score : 5×4×5×4/3/3 = 44.

## H2 — VERIFICATION ENGINE (6-12 sem, wedge)
Oracle branché au DAST web en prod ; états observation→...→rejected ; FP rate publié. Score : 5×5×4×5/3/2 = 83 (top).

## H3 — AUTONOMOUS ORCHESTRATION (6-12 sem)
Retry/fallback/budget/timeout/stop conditions/escalation/approval humain ; jamais sans policy. Score : 4×4×3×4/4/3 = 16.

## H4 — MULTI-DOMAIN (3-6 mois, via providers uniquement)
Repo ✓ → Web H1 → API/auth (P1, cf. Escape) → Cloud/Identity/IA en INGEST (importer Wiz/Pentera-like outputs comme providers, kill list : pas de clones).

## H5 — SECURITY GRAPH (3-6 mois, moat)
Asset→...→Verification ; dédup, attack paths, régressions, drift. Score : 5×5×3×5/4/3 = 31.

## H6 — REMEDIATION LOOP (parallèle H2)
dependency_bump/code_patch/config_fix + PR + retest + vérification régression (moteur existe, reste PR auto + SLA). Score : 5×3×4×3/3/2 = 30.

## H7 — CONTINUOUS (6-12 mois)
Missions planifiées, change detection, scans différentiels, baselines, tendances. Après H5.

## H8 — PROVIDER ECOSYSTEM (6-12 mois)
Standard provider (contrat déjà partiel : `provider_contract.py`) + 50 providers qualifiés avant toute idée marketplace.

## H9 — MCP ECOSYSTEM (P1, après H0)
MCP passe par REGISTRY→POLICY→SANDBOX→EVIDENCE (code existe : `mcp_*.py` + 7 batteries — à durcir, modèle Pentera). Score : 4×5×5×5/3/3 = 55.

## H10 — AGENT SECURITY (12 mois)
Permissions/prompt-injection/tool abuse/exfiltration/MCP malveillants ; répondre "que peut cet agent ?". Score : 4×5×4×5/4/3 = 33.

## H11 — CONTROL PLANE (12 mois)
Centraliser identités/cibles/engagements/policies/exécutions/preuves ; web+code+cloud sous un plan.

## H12 — ENTERPRISE (12-24 mois)
RBAC, orgs, audit logs, SSO, API keys, secrets, quotas, SIEM/tickets, CI/CD gates. Seulement après H0-H2 solides.

## H13 — PERF/SCALE (continu)
Benchmarks reproductibles avant toute optimisation.

## H14 — BENCHMARK COMPETITIF (dès H1, voir BENCHMARK_STRATEGY.md)
Dashboard AGNT vs MARKET, corpus DVWA/Juice Shop épinglés.

## H15 — PRODUCT UX (dès H1)
"Analyse cette application." → Mission/Target/Authorization/Scope/Risk/Durée/Capabilities/Live/Findings/Verification/Remediation.

## H16 — OPEN SOURCE (12 mois)
Public : core orchestration+preuves (moat par l'écosystème) ; gardé : calibrations, packs qualifiés, benchmarks propriétaires ? À trancher avec la licence (H0).

## H17 — GO-TO-MARKET (après wedge H1)
ICP : équipes produit sans AppSec + régulés on-prem. Killer : pentest à chaque release, preuve rejouable, données locales. Activation : `./lancer.sh` → 1er rapport < 30 min. Pricing : hypothèses (flat self-hosted vs per-seat vs per-verified-finding — à tester, pas à fixer).

## Jalons
- 30 j : H0 vert + squelette web (httpx+nuclei) + FP rate baseline.
- 90 j : H1 complet + Oracle web + benchmark concurrent v1.
- 12 mois : H5+H6+H9 + 50 providers + ICP payant pilote.
- 24 mois : category "Security Execution & Evidence Fabric" + leadership preuves.
