# BENCHMARK STRATEGY — mesurer ou se taire (2026-09-03)
> Ne jamais utiliser de marketing comme preuve. Tout claim vs concurrent = corpus + chiffres + reproduction.

## Corpus (légal, contrôlé, versionné)
- `PHASE3/testrepo*` + `testrepo_iac` (existe) + cibles web : Tolède ? Non — corpus web à créer : apps vulnérables OSS épinglées (DVWA, Juice Shop, WebGoat) en versions fixées + instanciées en local (Docker), JAMAIS de prod tierce.
- Ground truth : `PHASE3/benchmark/ground_truth.yaml` (étendre à chaque verticale : web, API, IaC).

## Metrics (par run, par corpus)
discovery coverage · precision · recall · verification rate · false positive rate · execution time · evidence quality (brut+replay présents ?) · reproducibility (2 runs → même verdicts ?) · remediation success · regression detection · cost/run · autonomy (% steps sans opérateur) · operator interventions.

## Protocole
1. Baseline gelée (commit + empreintes outils + policy) dans `run.json`.
2. 3 runs par cible (nondéterminisme LLM mesuré, pas nié).
3. Concurrent : UNIQUEMENT leurs claims publics + nos mesures sur corpus ouvert — jamais "on est meilleurs" sans tableau.
4. Dashboard `AGNT vs MARKET` : matrice §4 + FP rate + coût. Publication : `BENCHMARK_RESULTS.md` à chaque release (déjà initié Chantier 3).

## Definition of Done d'un benchmark
corpus versionné + ground truth + 3 runs + métriques ci-dessus + limites écrites + reproduction en 1 commande.
