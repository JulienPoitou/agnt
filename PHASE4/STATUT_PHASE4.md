# PHASE 4 — WORKFLOW UTILISABLE

_Transformer le vertical slice testé en un workflow compréhensible, rejouable et
exploitable par un humain. Aucune nouvelle capacité, aucun nouvel outil, aucun LLM._

## La commande

```bash
python3 PHASE3/analyser.py <dépôt> ["requête en langage naturel"]
```

Sans requête : « Analyse la sécurité de ce dépôt ».

```
cible   : /home/user/PHASE3/cible_independante
requete : Analyse la sécurité de ce dépôt

==============================================================
  10 observations · 3 clusters · 1 inter-outils
  plan cd5f71edb7589436 · run 4abfea5405ca3421 · result 9adc149c7531de0b
==============================================================

bundle : PHASE3/bundles/cd5f71edb7589436
```

**Codes de sortie**

```
0   workflow exécuté
1   erreur technique
2   demande refusée ou nécessitant une clarification — AUCUNE exécution
```

## Le bundle

Un répertoire par `plan_id`, donc **reproductible** : le même plan produit le même dossier.
Le `run_id`, unique, est à l'intérieur.

| Fichier | Contenu |
|---|---|
| `rapport.md` | le rapport lisible par un humain |
| `manifeste.json` | identifiants, digests, profil, couverture, inventaire des artefacts |
| `plan.json` | le plan typé autorisé par la politique |
| `findings.json` | findings normalisés, identité source et canonique |
| `clusters.json` | regroupements et raisons |
| `run.json` | contexte d'exécution complet |
| `raw_*.json` | sorties brutes des outils, **copiées sans retraitement** |
| `rapport.sarif` | export SARIF 2.1.0 des observations |

## Le rapport — six sections

```
1. Résumé                      dépôt, commit, digest, date, profil, statut, comptes
2. Périmètre et couverture     outils, analysé / non analysé, limites, règles, base
3. Observations regroupées     clusters, confiance, raison, outils, findings sources
4. Preuves                     localisation, règle source, mapping, extraits
5. Reproductibilité            les cinq identifiants + limites du profil
6. Artefacts                   inventaire du bundle
```

## La règle de sémantique

C'est la contrainte la plus importante de cette phase, et elle est **testée**.

```
observé         un outil a produit ce résultat
corrélé         plusieurs observations sont reliées
probable        une corrélation renforce la plausibilité
vérifié         un re-scan ou une preuve explicite le confirme
non déterminé   le système ne peut pas trancher
```

Le rapport commence par :

> **Ce que ce rapport est.** Une synthèse d'**observations** produites par des outils, et de
> **corrélations** entre ces observations. Ce n'est pas une confirmation de vulnérabilité.

Et il refuse d'écrire « votre dépôt contient 8 vulnérabilités » alors qu'il a établi
« 8 clusters d'observations provenant de 65 findings ». `test_rapport.py` cherche
explicitement ces sur-affirmations et **échoue** si elles apparaissent.

## Généré sans LLM — et pourquoi

Le rapport est produit par du code déterministe. Ce n'est pas un choix esthétique : si le
texte changeait à chaque exécution, on ne pourrait plus savoir si une divergence vient des
outils, des findings ou du modèle.

`test_rapport.py` le vérifie : à date et identifiants hexadécimaux normalisés, **deux
exécutions produisent exactement le même texte**.

## Critères de réussite — 21/21

| # | Critère | |
|---|---|---|
| 1 | Une seule commande lance le workflow complet | ✅ |
| 2 | Une demande ambiguë retourne une question sans exécution | ✅ exit 2 |
| 3 | Une demande interdite est refusée sans exécution | ✅ exit 2 |
| 4 | Un rapport Markdown est généré automatiquement | ✅ 10 150 car. |
| 5 | Le rapport expose le périmètre et les limites | ✅ + limite mémoire explicite |
| 6 | Les clusters sont compréhensibles | ✅ raison + confiance partout |
| 7 | Chaque cluster permet de retrouver ses findings sources | ✅ 0 orphelin |
| 8 | Les secrets restent masqués | ✅ rapport **et** sorties brutes |
| 9 | Les artefacts JSON/SARIF/raw sont disponibles | ✅ 10 fichiers, SARIF valide |
| 10 | Le rapport contient les identifiants et digests | ✅ les cinq |
| 11 | Un test golden vérifie la structure | ✅ sections, ordre, reproductibilité |
| 12 | Pas de confirmation prétendue sans preuve | ✅ aucune sur-affirmation |

## Deux bugs trouvés en écrivant le rapport

**1. Versions d'outils fausses.** Le rapport affichait :

```
| gitleaks | indisponible (FileNotFoundError) | exécuté |
| trivy    | indisponible (FileNotFoundError) | exécuté |
| opa      | indisponible (FileNotFoundError) | exécuté |
```

Les trois outils **avaient tourné** — je cherchais leurs binaires à côté de la cible au lieu
du cache. Pire : la colonne « Résultat : exécuté » était affirmée sans preuve. Colonne
supprimée, chemins corrigés.

**2. Deux bundles pour deux requêtes.** `plan_id` dépend de la requête brute, donc
« analyse la sécurité… » et « Analyse la sécurité… » produisent deux plans et deux bundles.
C'est le comportement attendu, mais il faut le savoir : le bundle est indexé par plan, pas
par cible.

## Ce qui n'a PAS été ajouté

Conformément au périmètre :

```
LLM narratif · UI riche · MCP · agrégateurs · nouveaux scanners
remédiation automatique · multi-utilisateur · scans parallèles
outils actifs · cgroups obligatoires
```

L'intent engine déterministe reste en place. Le LLM viendra derrière le même contrat :

```
IntentResult → resolved | needs_clarification | rejected
```

## Profil et limites

La Phase 4 tourne dans `controlled_dev`. La règle reste :

```
untrusted ou ACTIVE → refus tant que la mémoire n'est pas bornée
```

**La Phase 4 n'est pas une version de production.** Le rapport le dit lui-même, dans sa
section 5.

## Suite de tests

```
test_securite       16/16   porte bloquante
test_slice          10/10
test_tracabilite    12/12
test_intentions     22/22
test_correlation     7/7
test_independant    10/10
test_rapport        21/21   ← Phase 4
somme des codes : 0
```
