# AGNT STRATEGY — thèse stratégique (2026-09-03)

## AGNT IS NOT
- Un meilleur scanner (Snyk/Semgrep/Wiz gagnent déjà).
- Un meilleur pentester IA (XBOW/NodeZero ont 1000x plus de runs).
- Un meilleur dashboard (tout le monde en a un).
- Un ASM/cloud de plus (Hadrian/Wiz imbattables là).
- Un marketplace de tools (trop tôt, règle anti-dispersion : backlog 281 entrées).

## AGNT IS
**La couche d'exécution, de vérification et d'orchestration ouverte pour la sécurité autonome : toute capability déclarée, tout provider interchangeable, chaque finding prouvé et rejouable — 100% self-hosted.**

## ONE SENTENCE
AGNT prouve ce qui est réellement exploitable, avec des preuves rejouables, sans que tes données ne quittent ta machine.

## WHY NOW
- L'IA génère 10x plus de code → surface +10x, pentesters humains ne suivent plus (Aikido : 76% déploient hebdo, 21% testent chaque release).
- Les agents/MCP explosent → nouvelle surface (tool poisoning, exfiltration) sans garde standard (Snyk MCP-Scan, Wiz runtime MCP le confirment).
- Le marché a tranché : "validé ou rien" (XBOW zéro faux positifs, NodeZero preuves, Pentera CTEM). La validation est la table stakes ; la véritable différence devient : QUI contrôle l'exécution et possède la preuve.

## WHY AGNT
- intent→capability→provider→policy OPA→sandbox bwrap→execution→evidence→oracle : déjà codé et testé (56 batteries, Oracle 12/12, adversarial 46 cas), pas un slide.
- Coût marginal ≈ 0 (outils OSS épinglés), 2 Go RAM, offline : là où les SaaS facturent au scan.
- Neutre LLM (déterministe par défaut, Groq en option validée) : l'avantage ne dépend d'aucun modèle.

## WHY NOT COMPETITORS
- SaaS-first : refondre pour du 100% local casserait leur modèle économique (données, facturation à l'usage).
- Stack fermée : ouvrir le capability/provider reviendrait à désarmer leur lock-in.
- Preuve propriétaire : publier des bundles rejouables ouverts cannibaliserait leur plateforme.
- Politique implicite : rendre chaque refus explicite et auditable contredit le "l'IA décide".

## Scénarios (réponses en 1 ligne chacune)
- **A. XBOW domine** → AGNT survit comme couche d'exécution vérifiable sous les preuves XBOW (importer leurs findings comme providers, prouver localement).
- **B. NodeZero domine** → AGNT se différencie : réseau/interne à eux, code+web+agents autohébergés à nous + interop (corréler leurs paths avec nos findings).
- **C. Snyk absorbe l'agentic** → AGNT reste la neutralité : Snyk devient UN provider parmi N dans notre registre.
- **D. LLM surpuissants** → le moat tient : meilleurs modèles = meilleurs adapters, la boundary déterministe (policy+sandbox+oracle) reste rare et copiable difficilement.
- **E. Agents = interface principale** → AGNT devient infrastructure critique : chaque tool d'agent passe par REGISTRY→POLICY→SANDBOX→EVIDENCE.
