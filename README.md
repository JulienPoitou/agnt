# AGNT — agent de sécurité autonome (dépôt privé, travail en cours)

Moteur : mission en langage naturel + cible → capacités → sélection dans un pool
d'outils open source qualifiés → exécution sandboxée (bwrap, OPA fail-closed) →
corrélation inter-outils → rapport. Architecture Source → Tool → Provider →
Execution ; le runtime ne lit que `capabilities.yaml`, le pool est une vue dérivée.

## Lancer la console opérationnelle

```bash
./lancer.sh        # venv + API moteur + console sur http://127.0.0.1:8141
```

La console vit dans `PHASE3/interface/` — servie **par l'API elle-même** (même
origine, zéro build, zéro node). Le brief de mission est une page imprimée ; les
résultats s'affichent sur un CRT monochrome (trois phosphores : ambre, verde,
blanc). Le langage graphique est contractualisé dans [`DESIGN.md`](DESIGN.md).

- Sans outils installés, un run renvoie un **refus nommé** — c'est le comportement
  attendu, pas un bug. Pour de vrais constats : `bash PHASE3/bootstrap.sh` (~3,7 Go).
- Sans API démarrée, la page reste lisible sous bandeau **MAQUETTE** (rejeu de
  `donnees_exemple.json`, affiché comme tel — jamais comme un résultat réel).

## Structure

- `PHASE3/slice/` — le cœur (pipeline, registre, sandbox bwrap, policy OPA, extraction, clusterer, rapports).
- `PHASE3/interface/` — **la console** (`api.py` : routes canoniques + page ; `app.js` :
  câblage testé ; `console.js` : habillage sans données).
- `PHASE3/` — batteries de tests (`test_*.py`), fixtures (`testrepo*`), harnais, dogfooding.
- `PHASE1/` — le pool : catalogue, triage, fiches providers, backlog.
- `docs/coordination/PROJECT_STATE.md` — **la source de vérité d'état et de coordination**.
- `docs/archive/` — sédiment stratégique daté (état 30/08, concurrentiel, prompts de sessions).
- `archive/` — produits tiers ou frontends retirés du tronc (Xalgorix dashboard, design-lab,
  première console React), gardés par référence.

## Prérequis

```bash
python3-venv, node/npm (facultatifs)   # la console n'a plus besoin de node
bash PHASE3/bootstrap.sh               # bwrap + OPA + outils épinglés, empreintes vérifiées (~3,7 Go)
bash PHASE3/reconstruire_fixtures.sh   # recrée l'historique git des fixtures (gitleaks)
```

Machine de référence : 2 Go de RAM suffisent (contrainte mesurée et documentée).

## Notes

- Les fixtures `testrepo*` contiennent des **faux secrets volontaires** — ne pas
  les « corriger », ne pas les réutiliser ailleurs.
- Dépôt privé, pas de licence accordée à ce stade.
