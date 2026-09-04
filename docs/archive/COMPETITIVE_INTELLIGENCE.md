# COMPETITIVE INTELLIGENCE — AGNT War Room (vivant)
> Règle : aucune affirmation marketing n'est une preuve. Tags : CONFIRMED (source publique citée) / INFERRED / UNKNOWN.
> Dernière mise à jour : 2026-09-03. Méthode : docs vendor + presse 2026. Jamais d'architecture supposée présentée comme fait.

## 1. XBOW (xbow.com) — Autonomous Offensive Security, ex-HackerOne #1
- Positionnement : pentest applicatif autonome gouverné, "AI surfaces, validation decides". 150+ équipes. CONFIRMED (xbow.tech, 2026).
- ICP : AppSec/plateformes qui shippent vite, veulent du validé sans triage. Enterprise + mid-market.
- Architecture observable : flotte de milliers d'agents courts + coordinateurs persistants + logique déterministe de validation ; discovery et validation SÉPARÉES (l'IA qui trouve n'est jamais celle qui confirme). INFERRED (blog XBOW "AI Pentesting: Strengths, Gaps" 04/2026 décrivant fleet + deterministic debrief — CONFIRMED comme propos vendor, INFERRED comme implémentation réelle).
- Preuves publiques : 1060+ vulns HackerOne automatisées, #1 US leaderboard 06/2025, XSS GlobalProtect Palo Alto, bypass de mitigation re-testé, padding oracle AES-128-CBC en 17,5 min, chaîne 48 étapes SSRF→GDAL. CONFIRMED (blog XBOW "1060 autonomous attacks", 2026).
- Pricing : non public (UNKNOWN). SaaS + options déploiement (résidence/isolement — CONFIRMED).
- Remplace chez AGNT : le vertical web black-box V1 + une partie de l'Oracle (validation d'exploit réelle). Ne remplace PAS : policy OPA explicite, sandbox locale, self-hosting total, neutralité multi-outils.

## 2. Horizon3.ai NodeZero — Continuous Autonomous Pentesting (6 500+ orgs, NSA/CISA cités)
- Positionnement : "hack, fix, verify" continu, interne/externe/cloud + WebApp (07/2026). Production-safe, graduated testing. CONFIRMED.
- Architecture : SaaS + Docker host/OVA on-prem pour tests internes ; centaines d'outils offensifs orchestrés ; RAT post-exploitation ; RealTime View ; retest planifié. CONFIRMED (docs.horizon3.ai, factsheets 2026).
- WebApp 2026 : crawl headless (SPA/REST/SOAP/GraphQL), auth multi-rôles + MFA, logique métier/IDOR/BOLA, preuve rejouable (screenshots, requêtes). CONFIRMED (press release 29/07/2026, 95 clients early access dont Fortune 10).
- Remplace chez AGNT : pentest réseau interne/latéral + cloud pivots + credential attacks — domaine où AGNT est à 0 (pas de mouvement latéral, pas de RAT, pas d'infra cible). Ne remplace PAS : exécution locale sandboxée, registre de capabilities déclaratif, preuve cryptographique/replay ORACLE.
- Pricing : non public (UNKNOWN). Gartner Peer Insights 4.7 (CONFIRMED).

## 3. Pentera — Automated Security Validation / CTEM (Core/Surface/Cloud/Resolve)
- Positionnement : validation continue d'exposition, kill chains complètes, remediation automatisée + re-test. CONFIRMED (pentera.io, 02/2026).
- Architecture : moteurs déterministes + IA agentique (payloads adaptatifs), guardrails client (throttling, limites d'impact, emergency stop, audit logs), MCP Server local Docker/STDIO exposant les données de validation aux assistants IA (RBAC hérité). CONFIRMED (The Hacker News 07/2026 + docs Pentera).
- Remplace chez AGNT : boucle remediation→retest enterprise + exposition continue + MCP governé. AGNT a remediation déterministe (Chantier 3) mais sans ticketing/SLA ni MCP governé équivalent. Ne remplace PAS : neutralité outils (Pentera = stack fermée).

## 4. Hadrian (Atlas + Nova) — External exposure, 300+ entreprises
- Positionnement : ASM externe continu event-driven + pentest on-demand (Nova, 24-48h). Gartner AEV + GigaOm Leader. CONFIRMED.
- Architecture : flotte d'agents par classe d'attaque, scans passifs horaires, validation indépendante ("100% trusted"), revue humaine, rapports SOC2/ISO/NIS2. INFERRED pour l'interne (externe uniquement — CONFIRMED).
- Remplace chez AGNT : discovery externe continue (shadow IT, certificats) + event-driven testing. AGNT n'a ni ASM ni déclenchement sur changement. Ne remplace PAS : code/SCA/secrets locaux, sandbox.

## 5. Aikido Infinite — Self-securing software (100k+ équipes, licorne EU la plus rapide)
- Positionnement : chaque diff → pentest scopé → patch auto (PR merge-ready) → retest avant prod. $10/agent/30min. CONFIRMED (aikido.dev, 02/2026, Series B).
- Architecture : contexte code-to-runtime, agents parallèles par feature, validation par exploitation réelle, AutoFix + retest, Machine on-prem. CONFIRMED (vendor). "Aikido Machine" on-prem = point commun architectural avec AGNT (INFERRED comme intention, CONFIRMED comme offre).
- Remplace chez AGNT : la boucle detect→patch→retest côté dev + le "killer workflow" (pentest à chaque release). AGNT a le moteur de remediation mais pas le déclenchement par diff ni la PR auto. Ne remplace PAS : politique explicite, multi-providers.

## 6. Escape — API/GraphQL offensive security (business-logic-aware DAST)
- Positionnement : DAST natif GraphQL/REST (BOLA/IDOR, batching/aliasing), in-cluster K8s (Helm, 6 régions chez Sigma), CI/CD ciblé par schéma, MCP/CLI/API publics, CVE-2026-17059 (Keycloak PII). CONFIRMED.
- Remplace chez AGNT : test d'API authentifiées (OAuth/SSO/MFA), logique métier, fuzzing de schéma. AGNT n'a ni parser GraphQL ni auth multi-rôles. Ne remplace PAS : corrélation multi-outils, sandbox binaire.

## 7. Adjacents (résumé — dossiers complets à étendre)
- **Snyk** (AI Security Fabric 02/2026, Agent Fix agentic few-shot 35k+ fixes experts, MCP-Scan anti-tool-poisoning) : remplace SAST/SCA/IDE-fix d'AGNT ; ne remplace PAS l'orchestration multi-outils ni DAST. CONFIRMED.
- **Semgrep** (règles + MCP server, circuits LLM) : remplace une partie SAST ; AGNT l'ORCHESTRE déjà comme provider. INFERRED/CONFIRMED mixte.
- **GitHub Advanced Security** (CodeQL, secret scanning, Dependabot) : remplace la couverture baseline repo ; pas d'autonomie. INFERRED.
- **Wiz** (Security Graph agentless, runtime sensor, toxic combinations, Pen-Test Findings GA 08/2026, Red Agent API, MCP skill) : remplace cloud/graph/prioritisation ; ne remplace PAS l'exécution sandboxée ni la validation d'exploit custom. CONFIRMED (blog Wiz 2026).
- **Endor/Socket** : SCA reachability + supply-chain ; INFERRED (à documenter).
- **Palo Alto/CrowdStrike/Microsoft/Google/AWS** : plateformes ; remplacent des briques (runtime, CDR, ASM) jamais le tout. INFERRED.

## 8. War-room log (ajouter toute découverte : DATE/SOURCE/COMPETITOR/CHANGE/IMPACT/RESPONSE/PRIORITY)
- 2026-09-03 / vendor blogs / XBOW+NodeZero+Aikido+Escape+Pentera+Wiz / baseline ci-dessus / IMPACT : barre "validé ou rien" partout / RESPONSE : Oracle web + preuves rejouables en H1 / PRIORITY : P0.
