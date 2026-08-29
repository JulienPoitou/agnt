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

## Prérequis (machine de développement)

```bash
bash PHASE3/bootstrap.sh   # outils épinglés + empreintes vérifiées (~3,7 Go hors workspace)
bash PHASE3/reconstruire_fixtures.sh   # recrée l'historique git des fixtures (gitleaks)
```

Machine de référence : 2 Go de RAM suffisent (contrainte mesurée et documentée).

## Notes

- Les fixtures `testrepo*` contiennent des **faux secrets volontaires** — ne pas
  les « corriger », ne pas les réutiliser ailleurs.
- Dépôt privé, pas de licence accordée à ce stade.
