# Analyse de sécurité — ce qu'il faut regarder

Dépôt analysé le 29/08/2026 à 16:54.

## L'essentiel

Aucun problème à gravité haute signalé. 14 points secondaires, et 2 regroupements **sans gravité fournie** à examiner.

## À regarder ensuite

- 17 problèmes de même nature signalés dans `main.tf` (gravité moyenne).
- 5 problèmes de même nature signalés dans `main.tf` (gravité moyenne).
- 3 problèmes de même nature signalés dans `main.tf` (gravité moyenne).
- 3 problèmes de même nature signalés dans `main.tf` (gravité moyenne).
- 9 problèmes de même nature signalés dans `pre-commit.yml` (gravité faible).
- 7 problèmes de même nature signalés dans `vpc-flow-logs.tf` (gravité faible).
- 4 problèmes de même nature signalés dans `main.tf` (gravité faible).
- 2 problèmes de même nature signalés dans `lock.yml` (gravité faible).
- 2 problèmes de même nature signalés dans `pr-title.yml` (gravité faible).
- 2 problèmes de même nature signalés dans `release.yml` (gravité faible).
- 34 problèmes de même nature signalés dans `main.tf` (gravité faible).
- 6 problèmes de même nature signalés dans `main.tf` (gravité faible).
- 3 problèmes de même nature signalés dans `main.tf` (gravité faible).
- 2 problèmes de même nature signalés dans `main.tf` (gravité faible).
- 7 problèmes de même nature signalés dans `main.tf` (gravité indéterminée).
- 4 problèmes de même nature signalés dans `main.tf` (gravité indéterminée).

2 observations isolées : le regroupement n'a pas trouvé de lien. Elles restent dans le rapport détaillé.

## Gravité « indéterminée » — ce que ça veut dire

39 observations de cette analyse n'ont **aucune gravité fournie** : `checkov` n'en renvoie aucune pour ces règles. La valeur est absente de leur sortie — ce n'est pas un oubli de ce rapport.

- **Indéterminée ≠ faible.** Ces observations n'ont pas été évaluées : le risque réel peut être bénin comme sérieux. Leur attribuer une gravité serait inventer une information.
- **À faire :** prioriser selon l'impact de la ressource concernée, son exposition (Internet, réseau interne) et son contexte (production, expérimentation). Chaque observation est listée dans `rapport.md` avec son fichier, sa ligne et sa règle.

## Ce qui a été analysé

- **semgrep** : rien
- **trivy** : rien
- **gitleaks** : `historique git`
- **checkov** : `mt-scan`
- **kics** : `mt-scan`

### Ce qui n'a PAS été analysé

**C'est important** : un problème dans ces éléments n'aurait pas été détecté.

- `mt-scan` (semgrep) — aucune règle n'a porté sur ce dépôt
- `mt-scan` (trivy) — aucun manifeste de dépendances exploitable

### Limites de cette analyse

- le jeu de règles est épinglé sur python/security-audit : un dépôt d'un autre langage ressortirait vide sans erreur
- base de vulnérabilités figée au pré-chauffage : les CVE publiées depuis ne sont pas détectées
- valeur des secrets masquée à la source (--redact) : jamais stockée
- détection dépendante des règles : une clé AWS réaliste peut être classée generic-api-key, et les exemples de documentation sont sur liste blanche
- severity est null dans la sortie OSS (mesuré le 2026-08-28) : la gravité remonte « indéterminée », jamais inventée (leçon #4). file_path n'a pas la même base selon le framework (module Terraform vs dépôt) : les chemins sont conservés tels que l'outil les émet, non réécrits. Les frameworks détectés dépendent du contenu de la cible ; un framework absent n'est pas un échec.

- provider déclaratif : les résultats sont extraits selon la spécification du manifest, sans connaissance de l'outil par le cœur
- Bibliothèque de requêtes v2.1.20 pré-installée sous {REGLES}/kics ; sans elle, kics échoue (« unable to find queries »). Les formats IaC en JSON (CloudFormation, ARM) ne sont pas couverts par les globes (collision avec package.json). similarity_id et ordre d'énumération varient entre deux exécutions (mesuré) — l'ensemble des détections, non. severity est portée par la requête, pas par le fichier.

- provider déclaratif : les résultats sont extraits selon la spécification du manifest, sans connaissance de l'outil par le cœur

## Comment lire ce rapport

| Ce qu'on dit | Ce que ça veut dire |
|---|---|
| observé | un outil a produit ce résultat |
| probable | plusieurs outils convergent, ou une faille connue est concernée |
| à vérifier | personne n'a encore confirmé que c'est exploitable |
| gravité indéterminée | l'outil n'a fourni aucune gravité : non évalué — ce n'est ni faible ni moyen |

Rien dans ce rapport n'est une vulnérabilité **confirmée**. Une confirmation demande
un test réel, ou une correction suivie d'une nouvelle analyse.

---

## Détails techniques

_Pour vérifier, rejouer ou auditer cette analyse. Le rapport complet est dans_
_`rapport.md` du même dossier._

- dépôt : `/home/user/PHASE3/dogfooding/cibles/terraform-aws-vpc`
- commit : `cf0e3ca46fd51f47bf095957f2a6ac6127c89045`
- identifiants : plan `22cd89223255cf1b` · run `75d8fe1a76fb64af`
- empreintes : cible `7ab781de0c88663f` · contexte `331c2ee5fe0b55fb` · résultat `c05d1841354b3f72`
- profil : `controlled_dev`
- 112 observations, 16 regroupements
