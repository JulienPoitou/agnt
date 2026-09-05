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
- [ ] ①-b tranche **ffuf** : visible au cockpit (manifest épinglé `{REGLES}/dossiers-mini.txt`,
      déjà qualifié sandbox — reste la preuve au cockpit + case batterie réelle)
- [ ] ①-b tranche **nuclei** : idem, template local épinglé `{REGLES}/nuclei-epreuve.yaml`
- [ ] ①-b tranche **katana** : MANIFEST À ÉCRIRE d'abord (aucun au registre aujourd'hui) ;
      qualif sandbox à produire, puis tranche cockpit
- [ ] ①-b tranche **git-dumper** : hors `WEB_PROVIDERS_ORDRE` (découverte ≠ sonde) —
      décider de son entrée dans la chaîne (provider d'appoint ? capacité à part ?)
- [ ] **oracle** : rejeu ×N (`verification.replay`) + jugement `oracle_web` branché
      sur les findings web → CONFIRMED seulement là où il le dit
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
