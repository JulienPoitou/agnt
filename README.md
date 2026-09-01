# Agent de sécurité polyvalent — dépôt privé (travail en cours)

Moteur : mission en langage naturel + cible → capacités → sélection dans un pool
d'outils open source qualifiés → exécution sandboxée → corrélation inter-outils →
rapport. Architecture Source → Tool → Provider → Execution ; le runtime ne lit
que `capabilities.yaml`, le pool est une vue dérivée.

**État (2026-08-29)** : étapes 0-5 closes — registre/pool (309 dépôts catalogués),
objet Tool, applicabilité + fan-out, harnais de qualification, 8 providers
passifs intégrés (trivy, grype, semgrep×2, bandit×2, gitleaks, checkov, kics),
dogfooding sur 4 dépôts réels. Journal : `PROJET_ETAT.md`.

## Structure

- `PHASE1/` — le pool : catalogue, triage, fiches providers, backlog, comparaison stratégique.
- `PHASE3/slice/` — le cœur (pipeline, registre, sandbox bwrap, policy OPA, extraction, clusterer, rapports).
- `PHASE3/` — batteries de tests (`test_*.py`), fixtures (`testrepo*`), harnais, dogfooding.
- `PHASE3/dogfooding/` — cibles réelles épinglées, observations, utilisabilité.
- `dashboard/` — **le tableau de bord** (UI web React/Vite, reprise du dashboard
  Xalgoryx, Apache 2.0 — voir `dashboard/PROVENANCE.md`). Le backend Go livré
  avec n'est pas exécuté : l'intégration visée est le branchement sur
  `PHASE3/interface/api.py`. En attendant, un backend mock (`webui/mock-backend.mjs`)
  permet de le lancer en démo :
  `cd dashboard/webui && npm install && npm run dev`.

## Lancer la belle interface (console web)

Une console React/Vite branchée sur le **vrai moteur** (le même `analyser.lancer` que la CLI) :

```bash
./lancer.sh            # installe ce qui manque, démarre l'API (8141) + la console (5173)
# → ouvrir http://localhost:5173
```

- La console détecte l'API toute seule : bandeau **MOTEUR CONNECTÉ**, sélecteur de cible,
  lancement d'un run, journal/observations/clusters/couverture réels.
- Si l'API est éteinte, elle retombe sur le **rejeu** d'une exécution passée, affichée sous
  bandeau MAQUETTE (jamais comme un résultat réel).
- **Sans outils installés**, un run renvoie un **refus nommé** (ex. « binaire OPA introuvable »,
  « aucun outil disponible ») — c'est le comportement attendu, pas un bug.
- En production : `./lancer.sh --build` (build + `vite preview`).

## Prérequis (machine de développement)

```bash
bash PHASE3/bootstrap.sh   # bwrap + OPA + outils épinglés, empreintes vérifiées (~3,7 Go hors workspace)
bash PHASE3/reconstruire_fixtures.sh   # recrée l'historique git des fixtures (gitleaks)
```

Pré-requis système : `python3-venv` et `node`/`npm`. L'interface elle-même n'a besoin que de
PyYAML côté Python (créé automatiquement dans `.venv` par `lancer.sh`). Les scanners réels
(trivy, semgrep, checkov, gitleaks…) et la sandbox **bwrap** sont installés par `bootstrap.sh` :
sans eux, la console tourne mais les runs aboutissent à un refus nommé.

Machine de référence : 2 Go de RAM suffisent (contrainte mesurée et documentée).

## Notes

- Les fixtures `testrepo*` contiennent des **faux secrets volontaires** — ne pas
  les « corriger », ne pas les réutiliser ailleurs.
- Dépôt privé, pas de licence accordée à ce stade.
