# Analyse de sécurité — ce qu'il faut regarder

Dépôt analysé le 29/08/2026 à 16:51.

## L'essentiel

Aucun problème grave. 1 point secondaire à regarder.

## À regarder ensuite

- 2 problèmes de même nature signalés dans `security.yml` (gravité faible).

3 observations isolées : le regroupement n'a pas trouvé de lien. Elles restent dans le rapport détaillé.

## Gravité « indéterminée » — ce que ça veut dire

1 observation de cette analyse n'ont **aucune gravité fournie** : `checkov` n'en renvoie aucune pour cette règle. La valeur est absente de leur sortie — ce n'est pas un oubli de ce rapport.

- **Indéterminée ≠ faible.** Ces observations n'ont pas été évaluées : le risque réel peut être bénin comme sérieux. Leur attribuer une gravité serait inventer une information.
- **À faire :** prioriser selon l'impact de la ressource concernée, son exposition (Internet, réseau interne) et son contexte (production, expérimentation). Chaque observation est listée dans `rapport.md` avec son fichier, sa ligne et sa règle.

## Ce qui a été analysé

- **semgrep** : rien
- **semgrep_go** : rien
- **trivy** : `go.mod`
- **gitleaks** : `historique git`
- **checkov** : `mt-scan`
- **kics** : `mt-scan`

### Ce qui n'a PAS été analysé

**C'est important** : un problème dans ces éléments n'aurait pas été détecté.

- `mt-scan` (semgrep) — aucune règle n'a porté sur ce dépôt
- `mt-scan` (semgrep_go) — aucun résultat produit par l'outil

### Limites de cette analyse

- le jeu de règles est épinglé sur python/security-audit : un dépôt d'un autre langage ressortirait vide sans erreur
- provider déclaratif : les résultats sont extraits selon la spécification du manifest, sans connaissance de l'outil par le cœur
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

- dépôt : `/home/user/PHASE3/dogfooding/cibles/mux`
- commit : `db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265`
- identifiants : plan `57bee9c26081801b` · run `0a401f37fb7f6f0b`
- empreintes : cible `116f3c41da27f50b` · contexte `331c2ee5fe0b55fb` · résultat `d3c46361e61c558c`
- profil : `controlled_dev`
- 5 observations, 1 regroupements
