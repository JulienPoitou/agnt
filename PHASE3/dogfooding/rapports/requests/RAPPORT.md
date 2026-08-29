# Analyse de sécurité — ce qu'il faut regarder

Dépôt analysé le 29/08/2026 à 16:55.

## L'essentiel

Aucun problème grave. 3 points secondaires à regarder.

## À regarder ensuite

- 5 problèmes de même nature signalés dans `sidebar.html` (gravité moyenne).
- 2 problèmes de même nature signalés dans `sidebar.html` (gravité moyenne).
- 2 observations regroupées (gravité moyenne).

5 observations isolées : le regroupement n'a pas trouvé de lien. Elles restent dans le rapport détaillé.

## Gravité « indéterminée » — ce que ça veut dire

1 observation de cette analyse n'ont **aucune gravité fournie** : `checkov` n'en renvoie aucune pour cette règle. La valeur est absente de leur sortie — ce n'est pas un oubli de ce rapport.

- **Indéterminée ≠ faible.** Ces observations n'ont pas été évaluées : le risque réel peut être bénin comme sérieux. Leur attribuer une gravité serait inventer une information.
- **À faire :** prioriser selon l'impact de la ressource concernée, son exposition (Internet, réseau interne) et son contexte (production, expérimentation). Chaque observation est listée dans `rapport.md` avec son fichier, sa ligne et sa règle.

## Ce qui a été analysé

- **semgrep** : `sidebar.html`, `auth.py`
- **trivy** : rien
- **grype** : rien
- **gitleaks** : `historique git`, `ca-private.key`, `server.key`, `client.key`, `server.key`
- **checkov** : `mt-scan`
- **kics** : rien

### Ce qui n'a PAS été analysé

**C'est important** : un problème dans ces éléments n'aurait pas été détecté.

- `mt-scan` (trivy) — aucun manifeste de dépendances exploitable
- `mt-scan` (grype) — aucun résultat produit par l'outil
- `mt-scan` (kics) — aucun résultat produit par l'outil

### Limites de cette analyse

- le jeu de règles est épinglé sur python/security-audit : un dépôt d'un autre langage ressortirait vide sans erreur
- base de vulnérabilités figée au pré-chauffage : les CVE publiées depuis ne sont pas détectées
- grype identifie en GHSA-* (mesuré : 62/62 sur testrepo_sca), trivy en CVE-* : convergence inter-outils par PAQUET (6/6 paquets communs mesurés), pas par identifiant de règle. La base grype (~2 Go) est pré-téléchargée sous {DB}/grype ; sans elle, grype tenterait un téléchargement — impossible dans la sandbox (pas de réseau).

- provider déclaratif : les résultats sont extraits selon la spécification du manifest, sans connaissance de l'outil par le cœur
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

- dépôt : `/home/user/PHASE3/dogfooding/cibles/requests`
- commit : `5460f467b02e49471c0fd6cfc9ca0adab6351f98`
- identifiants : plan `3a8fd0fb5f536e54` · run `09c0f79b59aa9bf9`
- empreintes : cible `c7a5d4bf302ea7fd` · contexte `331c2ee5fe0b55fb` · résultat `99d2663d44b252ab`
- profil : `controlled_dev`
- 14 observations, 3 regroupements
