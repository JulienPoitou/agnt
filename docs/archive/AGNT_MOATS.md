# AGNT MOATS — 7 avantages défendables (2026-09-03)

## 1. Capability Graph (intent→capability→provider→tool→execution→evidence→finding→verification)
- Problème : 1 outil = 1 avis, impossible de comparer ou remplacer.
- Mécanisme : `registre.py` + `capabilities.yaml` + `plan.json` (qui choisi, qui écarté, pourquoi).
- Valeur : changer d'outil sans changer de question ; 50 tools améliorés d'un coup.
- Difficile à copier : demande de refondre le produit autour du registre (les SaaS sont construits autour de LEUR moteur).
- Données : verdicts de sélection + plans refusés/acceptés. 6 mois : comparabilité inter-outils. 2 ans : graphe de couverture unique.

## 2. Provider Independence
- Problème : lock-in scanner, aveugle aux angles morts d'un seul moteur.
- Mécanisme : manifest déclaratif (`PHASE3/plugins/*.yaml` + épingle `manifeste_dependances.yaml`), validation `provider_manifest.valider()`.
- Valeur : nuclei ET zap sur la même capability, findings fusionnés même empreinte.
- Copie : moyenne (format copiable) mais sans l'écosystème d'épingles+qualif, coquille vide. 2 ans : catalogue 119 épinglés = barrière.

## 3. Security Execution Fabric (LLM→plan typé→policy→scope→sandbox→execution→evidence)
- Problème : agents qui agissent sans contrôle (exfiltration, hors-scope).
- Mécanisme : `sandbox.py` (bwrap --unshare-net) + OPA + `cible.py` + `cible_autorisee` + egress par mission + journal append-only.
- Valeur : autonomie sans confiance aveugle. 6 mois : pentests prod-safe autohébergés. 2 ans : standard d'exécution.

## 4. Verification Engine (Oracle : observation ≠ vulnérabilité)
- Problème : bruit, faux positifs, "l'IA a dit".
- Mécanisme : `oracle.py` (observation→finding→verification→evidence→verdict→proof_capsule), replay N/N + témoin contrôle, 12/12 tests.
- Valeur : divise le triage par 10. Copie : facile à clamer, dur à prouver (batteries adversariales 46 cas). 2 ans : taux de faux positifs publié et auditable.

## 5. Evidence Graph (chaque finding remonte à sa preuve)
- Problème : findings sans contexte = tickets morts.
- Mécanisme : `brut_*` (octets outil) + `raw_*` (compris) + `run.json` (empreintes) + ProofCapsule + `mission.json`/`journal.jsonl`.
- Valeur : rejouer, auditer, corréler code↔runtime. 2 ans : graphe historique (régressions, drift, tendances).

## 6. Open Security Fabric (un outil compatible = une capability, zéro touche au core)
- Problème : ajouter un outil = fork ou ticket vendor.
- Mécanisme : voie plugin (`test_plugins.py` 92 cas), 5 modèles de lecture + parsers nommés, whitelist binaires par épingle.
- Valeur : la communauté étend sans permission. 2 ans : effet réseau des providers.

## 7. Deterministic Security Boundary (l'IA propose, le système décide)
- Problème : LLM non déterministe comme garde de sécurité.
- Mécanisme : LLM confiné au catalogue (`intent_llm.py` validé contre registre, repli déterministe tracé), OPA + sandbox décident toujours.
- Valeur : utiliser n'importe quel modèle sans changer le niveau de sécurité. 2 ans : agnosticité modèle = assurance anti-obsolescence.
