# Câble chat→moteur (engagement web) — check-list anti-boucle

Règle de session : **commencer à la première case NON cochée.** Rien de déjà coché
ne se re-qualifie ni ne se re-teste — les preuves vivent dans
`PHASE3/cible_web/qualif/` (`DOSSIER_web.yaml` + `ATTENDUS_SANDBOX.yaml`) et dans
les batteries de ce dépôt : on s'y réfère, on ne les refait pas.

## ① Le câble (de la console aux findings réels)

- [x] ①-a `POST /api/engagements/web` branché au cockpit : plan + statut réels à
      l'écran (section « Engagement web » de la console) — 2026-09-05
- [x] ①-b tranche **httpx** : `executer: true` → file → `pipeline_web.derouler` →
      `ExecuteurLocal` → findings OBSERVED affichés + `rapport_web.json` scellé
      (batterie machine de référence : `PHASE3/test_web_cable.py`) — 2026-09-05
- [x] ①-b tranche **ffuf** : tourne dans la chaîne au cockpit (wordlist épinglée
      `{REGLES}/dossiers-mini.txt`) — démo 2026-09-05 : `admin` et `.env` confirmés 3/3
- [x] ①-b tranche **nuclei** : tourne dans la chaîne au cockpit (template local
      épinglé `{REGLES}/nuclei-epreuve.yaml`) — démo 2026-09-05 : `epreuve-thaumas-info` confirmé
- [x] **oracle** : branché dans `pipeline_web` (`_rejouer`) — rejeu RÉEL ×N
      (3 normal / 5 aggressive) + témoin (chemin aléatoire du même hôte) ;
      recette = statut déclaré quand le tool en porte un, sinon « stabilité »
      (anti-soft-404) ; CONFIRMED → candidater + verifier_ok (VERIFIED),
      REFUTED → rejeter (REJECTED), POTENTIAL/INCONCLUSIVE → reste OBSERVED
      avec la raison ; hors scope = pas de rejeu (raison nommée) ;
      test_web_cable 12/12, démo : 4/4 vérifiés — 2026-09-05
- [x] **correspondance IA** : chat BYOK (Groq) dans la console — parle librement
      de tout, peut PROPOSER un engagement via appel d'outil, CONFIRMATION
      HUMAINE obligatoire (le clic est l'attestation cible_autorisee), explique
      les constats rendus par le moteur (jamais inventés) ; clé + consigne
      permanente éditables, localStorage navigateur — 2026-09-05
- [ ] ①-b tranche **katana** : MANIFEST À ÉCRIRE d'abord (aucun au registre aujourd'hui) ;
      qualif sandbox à produire, puis tranche cockpit
- [ ] ①-b tranche **git-dumper** : hors `WEB_PROVIDERS_ORDRE` (découverte ≠ sonde) —
      décider de son entrée dans la chaîne (provider d'appoint ? capacité à part ?)
- [x] **corrélation — étude** : `docs/RECHERCHE_CORRELATION.md` (Burp, ZAP,
      DefectDojo, Faraday, GitLab, Nuclei, Semgrep, PentestGPT/PentAGI/XBOW,
      SSVC/EPSS — mécanismes exacts + 10 patterns transposables + 10
      recommandations impact/effort) — 2026-09-05
- [ ] **corrélation — implantation v1** (dans l'ordre de la priorisation) :
      empreinte de finding (champs déclarés dans capabilities.yaml, stable
      inter-runs, modèle DefectDojo et de ses bugs documentés) → diff de
      re-scan (événement `no_longer_detected` dans cycle_vie — `rouvrir`/
      `regresser` existent déjà) → identifiant primaire CVE/GHSA > règle
      canonique > empreinte (leçon GitLab) → confiance à deux étages
      (déclarée au manifest × verdict oracle, leçon Burp) → seconde recette
      indépendante pour VERIFIED (piloter `contient_extrait`, leçon XBOW :
      validation par exploitation, jamais auto-évaluation) → plafond
      SYSTEMIC affiché (conventions ZAP 2.17) → vers `clusterer.py`
- [ ] **cage** : exécution web sous bwrap au runtime (aujourd'hui `ExecuteurLocal`
      exécute hors cage — les qualifications sous cage existent, le runtime pas encore)

## ② Qualifications sandbox — TERMINÉ ✅ (ne pas refaire)

httpx, git-dumper, nmap, nuclei, ffuf : preuves d'exécution réelle sous bwrap 0.9.0
(egress accordé), stabilité contenu normalisé, findings attendus relus —
`PHASE3/cible_web/qualif/DOSSIER_web.yaml`. Bug produit trouvé au passage :
manifeste ffuf sans `-w` (inutilisable depuis l'origine) + placeholders `0.1.0`
écrasant les épinglages — corrigé et épinglé dans `manifeste_dependances.yaml`.

## ③ Vague scanners — GELÉE

Ajout des ~14 scanners web manquants au registre : interdit tant que ① n'est pas
démo-complet (chaîne au cockpit + oracle). Après quoi, une vague = des manifests +
une tranche batterie chacun, jamais de re-test global.
