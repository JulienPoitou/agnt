# PHASE 5A — PROVIDER MANIFEST DÉCLARATIF

_Le test décisif de l'architecture. Résultat : **27/27**, promesse tenue._

## La preuve

```
j'ajoute un provider CLI dans un fichier YAML,
sans modifier le cœur Python,
et il apparaît correctement dans le plan,
la policy, l'exécution, la couverture et le rapport.
```

Bandit a été ajouté dans `slice/capabilities.yaml`. **Aucun fichier du cœur ne le
connaît** — vérifié mécaniquement sur `pipeline.py`, `findings.py`, `policy.py`,
`plan.py`, `registre.py`, `clusterer.py`, `rapport.py`.

Résultat sur la fixture : **65 findings avant, 70 après**. Les 5 de Bandit sont passés
par la voie déclarative.

## La promesse, formulée correctement

Ce qu'on promet :

```
Ajouter SANS MODIFIER LE CŒUR les outils CLI qui utilisent
un format de sortie supporté et un contrat d'exécution standard.
```

Deux niveaux :

```
outil JSON/SARIF standard    → manifest déclaratif uniquement
outil au format propriétaire → parser spécifique, AUCUN changement du cœur
```

**Ce qu'on ne promet PAS :** « ajouter n'importe quel outil sans écrire de code ».

## Le manifest

```yaml
- id: bandit
  kind: tool
  mode: CLI
  risque: PASSIVE
  commande: ["bandit"]
  manifest:
    id: bandit
    binaire: bandit
    argv: ["{BIN}", "-f", "json", "-r", "{TARGET}"]   # LISTE, jamais chaîne shell
    output: { format: json }
    extraction:
      modele: plat
      items_from: results
      champs:
        regle: test_id
        fichier: filename
        ligne: line_number
        message: issue_text
        severite: issue_severity
    risk: PASSIVE
    code_succes: [0, 1]      # bandit renvoie 1 quand il trouve quelque chose
    coverage: { declares_files: true }
```

## Le trusted core refuse — 8 cas testés

Le manifest est validé **au chargement du registre**, donc avant toute exécution et
indépendamment d'OPA.

| Tentative | Refus |
|---|---|
| `argv` en chaîne shell | « doit être une LISTE d'arguments, jamais une chaîne shell » |
| binaire non autorisé (`curl`) | « binaire non autorisé. Autorisés : semgrep, trivy, gitleaks, bandit » |
| placeholder inconnu (`{CMD}`) | « placeholder inconnu » |
| `; rm -rf /` dans un argument | « contient ';' — refusé » |
| `$(id)` dans un argument | « contient '$(' — refusé » |
| format de sortie non supporté (`xml`) | « un format propriétaire demande un parser spécifique » |
| `json` sans spécification d'extraction | « format json sans spécification d'extraction » |
| risque inconnu (`DANGEREUX`) | « risque inconnu » |

Ce que le trusted core contrôle : **binaire autorisé, placeholders autorisés, répertoire
cible, arguments, risque, format de sortie, montages, timeouts.**

## Extraction déclarative

`extraction.py` ne contient **aucun nom d'outil**. Deux modèles :

```
plat       {"results": [ {...} ]}                              bandit, semgrep
imbriqué   {"Results": [{"Target": t, "Vulnerabilities": […]}]}  trivy
```

Un format hors de ces deux modèles demande un parser spécifique — c'est le second niveau
de la promesse, et il ne modifie pas le cœur.

## Un problème de sécurité trouvé en route

Bandit renvoie **la valeur réelle du credential** dans son champ `issue_text` :

```
Possible hardcoded password: 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'
```

Le garde-fou du pipeline a **bloqué l'exécution** :

```
PipelineError: des secrets ont survécu à la normalisation : ba-0002 contient un motif de secret
```

C'est le comportement voulu — un échec bruyant plutôt qu'une fuite silencieuse. Corrigé par
un masquage **à l'extraction**, avant tout stockage, avec les motifs :

```
ghp_…  github_pat_…  AKIA…  xox[baprs]-…  -----BEGIN … PRIVATE KEY-----  JWT  [A-Za-z0-9/+=]{40}
```

Vérifié : `fuite de secret après extraction : False`.

## Canonicalisation du plan — corrigée avant Phase 5A

Quatre identifiants, et non trois :

```
request_id    requête brute                    3 formulations → 3 request_id
plan_id       hash du plan CANONIQUE           3 formulations → 1 plan_id
input_digest  cible analysée
run_id        exécution unique (nonce)
```

Testé :

```
« Analyse la sécurité de mon dépôt »
« analyse la sécurité de mon depot »        → beeaab40d60d0387
«   ANALYSE   la sécurité, de mon dépôt! »

« Vérifie les dépendances »                 → f89e20c97d79cef9   (autre intention)
```

La phrase originale est conservée dans le plan ; c'est `requete_canonique` qui définit
l'identité. Normalisation : minuscules, accents retirés, ponctuation supprimée.

## Index des artefacts — corrigé

```
avant   bundles/<plan_id>/
après   artifacts/<input_digest>/<plan_id>/<run_id>/
```

```
artifacts/e8c0c0a783c8b58e/d01ff365ef88eae0/7cd85de90270978a/
    rapport.md · manifeste.json · plan.json · findings.json · clusters.json
    run.json · rapport.sarif · raw_bandit.json · raw_gitleaks.json
    raw_semgrep.json · raw_trivy.json
```

La cible d'abord, puis le plan canonique, puis l'exécution unique.

## Deux tests fragiles corrigés

L'ajout de Bandit a cassé `test_slice` (6/10) et `test_intentions`. Cause : des attentes
codées en dur — « trois outils », « 3 étapes », « version 1.0 ».

**Un test qui casse quand on ajoute un provider déclaratif est un mauvais test** : il
contredit la promesse même de la phase. Les attentes sont devenues extensibles
(`>= 3`, `attendues <= caps_plan`, `P.VERSION_PLAN`).

## Suite de tests

```
test_securite       16/16   porte bloquante
test_slice          10/10
test_tracabilite    12/12
test_intentions     22/22
test_correlation     7/7
test_independant    10/10
test_manifest       27/27   ← Phase 5A
test_rapport        21/21
somme des codes : 0
```

## Ce qui n'a PAS été construit

Conformément au périmètre : aucun registry distribué, récursif, MCP-compatible, aucune
marketplace. Un seul provider déclaratif, une seule forme d'exécution.

## Ce que ça ne prouve pas

- **Un seul provider déclaratif testé.** Bandit est au format JSON plat, le cas le plus
  simple. Le modèle `imbriqué` (Trivy) n'est pas encore exercé par la voie déclarative —
  Trivy utilise toujours son adaptateur historique.
- **Aucun outil au format propriétaire.** Le second niveau de la promesse n'est pas démontré.
- **Bandit n'est pas dans le manifeste des dépendances** avec un SHA-256 : il est installé
  par pip. À durcir s'il reste.
