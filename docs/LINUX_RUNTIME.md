# LINUX RUNTIME — passer de TESTED_WITH_FIXTURES à RUNTIME_VERIFIED
> Tout ce qui suit est DOCUMENTED ONLY tant qu'exécuté nulle part. Règle : un seul
> module passe RUNTIME_VERIFIED à la fois, avec la commande exacte et sa sortie.

## Prérequis (WSL2 Ubuntu 24.04 — pas WSL1, pas /mnt/c pour le clone)
```bash
wsl.exe -l -v                                  # VERSION = 2 ; uname -r contient WSL2
git clone <dépôt> agnt && cd agnt               # côté LINUX
python3 -c "import yaml" || sudo apt-get install -y python3-yaml
bash PHASE3/bootstrap.sh                        # ~3,7 Go : bwrap + OPA 1.20.0 + scanners épinglés
bash PHASE3/test_bwrap.sh                       # 0 exigé (77 = non mesuré, pas un succès)
bash PHASE3/test_oci.sh                         # 12/12 exigé (profil non fiable)
```
AppArmor : si `bwrap: setting up uid map: Permission denied` → profil limité à
`/usr/bin/bwrap` (préféré au sysctl global). Ne JAMAIS retirer `--unshare-net`.

## Séquence E2E (première session Linux)
1. `python3 PHASE3/test_slice.py` + batteries existantes → baseline verte documentée.
2. Nouvelles suites : `test_cycle_vie.py` (18) `test_oracle_web.py` (13)
   `test_taches.py` (17) `test_fournisseurs_web.py` (13) `test_web_scope.py` (29)
   `test_preuve.py` (14) `test_orchestrateur.py` (9) `test_pipeline_web.py` (8)
   `test_engagements_web.py` (20) `test_pilotage.py` (10) `test_graphe.py` (8)
   `test_flux_mcp.py` (17) → tout doit rester vert (176 cas).
3. Exécuteurs réels : `ExecuteurLocal` + `planifier("httpx"/"nuclei")` sur cible
   de test AUTORISÉE (DVWA/Juice Shop locale, jamais de prod tierce) →
   `interpreter` sur vraies sorties → lever `RUNTIME_VERIFIED` module par module :
   - `fournisseurs_web.RUNTIME_VERIFIED` : 1 run httpx + 1 run nuclei mesurés ;
   - `taches.RUNTIME_VERIFIED` : inchangé (déjà réel, bénin) ;
   - `oracle_web.RUNTIME_VERIFIED` : 1 rejeu N/N réel + témoin.
4. Benchmark : `BENCHMARK_RESULTS.md` (corpus épinglé, 3 runs, métriques §BENCHMARK_STRATEGY).

## Table des statuts (mettre à jour, jamais d'avance)
| Module | État | Preuve |
|---|---|---|
| cycle_vie, web_scope, preuve, graphe, remediation_flux, gouvernance_mcp, orchestrateur | TESTED_WITH_FIXTURES | suites locales vertes |
| taches.ExecuteurLocal | TESTED (réel bénin) | sous-processus vrais, pas de scanners |
| fournisseurs_web, pipeline_web, oracle_web, api engagements | TESTED_WITH_FIXTURES | fixtures + mocks |
| sandbox bwrap / OPA / OCI / scanners | NOT VERIFIED ici | voir H0 roadmap |
