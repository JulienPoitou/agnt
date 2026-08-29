# Utiliser le système — une page

## Prérequis (une fois)

```bash
bash PHASE3/bootstrap.sh              # outils épinglés + empreintes (~3,7 Go hors workspace)
bash PHASE3/reconstruire_fixtures.sh  # uniquement pour lancer les batteries de tests
```

## Analyser une cible

```bash
python3 PHASE3/analyser.py /chemin/du/depot ["Analyse la sécurité de mon dépôt"]
python3 PHASE3/analyser.py /chemin/du/depot "Analyse mon code Terraform" --moteur deterministe
```

- **La cible vient en premier**, la demande ensuite — et elle est optionnelle :
  sans elle, la demande par défaut est un audit complet du dépôt.
- La mission est en **langage naturel** : « Vérifie mes dépendances »,
  « Cherche des secrets exposés », « Analyse mon code Terraform »…
- Le moteur d'intention est **déterministe** par défaut. Avec une clé
  `GROQ_API_KEY` dans l'environnement (ou `--moteur llm`), un LLM comprend la
  demande — **dans le catalogue des capacités uniquement** : sa sortie est
  validée contre le registre, tout échec retombe sur le déterministe et le
  repli est tracé dans le champ `moteur`. `--moteur auto` (défaut) choisit le
  LLM si une clé est présente, sinon le déterministe — et le dit à l'écran. Le contrat a
  été exercé contre un vrai modèle (Groq) : c'est une preuve d'intégration, **pas** une
  validation en production — limites de débit, file d'attente et relances restent à
  concevoir (`PROJET_ETAT.md`, « Clarification — LLM réel testé ≠ LLM réel validé »).
- **La confiance de cible se déclare** : `--confiance untrusted` dit « ce dépôt n'est
  pas fiable ». La politique OPA refuse alors tout plan tant que la mémoire n'est pas
  bornée (il faut cgroups v2 ou un runtime OCI) — refus rendu **avant** exécution,
  avec le motif `memoire_non_bornee_cible_non_fiable`. Défaut : `controlled`, et il est
  affiché, jamais silencieux. Une valeur inconnue est une **erreur** (`1`), pas un repli.
- Codes de sortie : `0` analyse complète · `2` rien n'a été exécuté (une
  clarification est demandée, la demande est refusée, ou aucun provider ne
  s'applique) · `1` erreur technique.

## Lire le résultat

Les chemins de `findings.json` (et les clés de cluster) sont **relatifs à la cible**,
quelle que soit la forme rendue par l'outil : `/…/mt-scan/docs/x.py`, `./x.py`,
`docs\\x.py`, `/PHASE3/mon_depot/x.py` deviennent tous `docs/x.py` ou `x.py`. C'est ce qui
rend `same_file` possible entre outils — et un chemin qui remonterait hors de la cible
(`../x`) n'est jamais aplati : il reste distinct de `x`.

Deux vues des mêmes preuves :

```
PHASE3/artifacts/missions/<id>/sortie/     ← « qu'a produit CETTE mission ? »
├── RAPPORT.md      ← commencer ici : ce qu'il faut regarder, en clair
├── findings.json   · clusters.json   · rapport.json
├── plan.json       ← qui a été choisi, qui a été écarté, et POURQUOI
├── raw_*.json      ← sorties brutes des outils, telles quelles
└── run.json        ← empreintes (versions outils, bases, policy, cible)

PHASE3/artifacts/<digest>/<plan_id>/<run_id>/   ← vue technique, indexée par cible
├── rapport_humain.md  · rapport.md  · rapport.sarif   ← export SIEM/IDE
└── manifeste.json     ← identifiants, digests, couverture, conservation des sorties
```

Le dossier de mission contient aussi le **journal append-only** (décisions,
arrêts, propositions LLM enregistrées comme données).

## Ce que le système ne fait pas

- Il n'exécute que des outils **passifs** intégrés et qualifiés (8 à ce jour) —
  aucun scan offensif, aucun outil non qualifié, aucune commande libre.
- Il n'élargit jamais son périmètre : ce qui est refusé ou écarté est dit, avec
  un motif, dans `plan.json`.
- Une gravité inconnue reste « indéterminée » — jamais inventée.
