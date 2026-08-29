# Analyse de sécurité — ce qu'il faut regarder

Dépôt analysé le 29/08/2026 à 17:14.

## L'essentiel

**8 points à traiter en priorité**, sur 12 au total.

**1.** La librairie `fast-uri` présente 3 failles connues (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-13676`, `CVE-2026-16221`, `CVE-2026-18446`.
Fichiers : `docs/package-lock.json`.

→ **À faire :** vérifier, puis corriger. 6 observations dans le rapport détaillé.

**2.** La librairie `js-yaml` présente 2 failles connues (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-59869`, `CVE-2026-73643`.
Fichiers : `docs/package-lock.json`, `package-lock.json`.

→ **À faire :** vérifier, puis corriger. 6 observations dans le rapport détaillé.

**3.** La librairie `serialize-javascript` présente 1 faille connue (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-34043`.
Fichiers : `package-lock.json`.

→ **À faire :** vérifier, puis corriger. 4 observations dans le rapport détaillé.

**4.** La librairie `fast-xml-parser` présente 1 faille connue (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-73569`.
Fichiers : `docs/package-lock.json`.

→ **À faire :** vérifier, puis corriger. 2 observations dans le rapport détaillé.

**5.** La librairie `nanoid` présente 1 faille connue (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-67213`.
Fichiers : `docs/package-lock.json`.

→ **À faire :** vérifier, puis corriger. 2 observations dans le rapport détaillé.

**6.** 2 observations regroupées (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Fichiers : `docs/package-lock.json`.

→ **À faire :** vérifier, puis corriger. 2 observations dans le rapport détaillé.

**7.** La librairie `svgo` présente 1 faille connue (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-73650`.
Fichiers : `docs/package-lock.json`.

→ **À faire :** vérifier, puis corriger. 2 observations dans le rapport détaillé.

**8.** La librairie `brace-expansion` présente 1 faille connue (gravité haute).

Signalé par `trivy` et `grype`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-69152`.
Fichiers : `package-lock.json`.

→ **À faire :** vérifier, puis corriger. 2 observations dans le rapport détaillé.

## À regarder ensuite

- La librairie `@astrojs/rss` présente 1 faille connue (gravité moyenne).
- La librairie `postcss` présente 1 faille connue (gravité moyenne).
- La librairie `yaml` présente 1 faille connue (gravité moyenne).
- 2 problèmes de même nature signalés dans `release-please.yml` (gravité faible).

4 observations isolées : le regroupement n'a pas trouvé de lien. Elles restent dans le rapport détaillé.

## Gravité « indéterminée » — ce que ça veut dire

2 observations de cette analyse n'ont **aucune gravité fournie** : `checkov` n'en renvoie aucune pour ces règles. La valeur est absente de leur sortie — ce n'est pas un oubli de ce rapport.

- **Indéterminée ≠ faible.** Ces observations n'ont pas été évaluées : le risque réel peut être bénin comme sérieux. Leur attribuer une gravité serait inventer une information.
- **À faire :** prioriser selon l'impact de la ressource concernée, son exposition (Internet, réseau interne) et son contexte (production, expérimentation). Chaque observation est listée dans `rapport.md` avec son fichier, sa ligne et sa règle.

## Ce qui a été analysé

- **semgrep** : rien
- **trivy** : `package-lock.json`
- **grype** : rien
- **gitleaks** : `historique git`
- **checkov** : `mt-scan`
- **kics** : `mt-scan`

### Ce qui n'a PAS été analysé

**C'est important** : un problème dans ces éléments n'aurait pas été détecté.

- `mt-scan` (semgrep) — aucune règle n'a porté sur ce dépôt
- `package.json` (trivy) — manifeste présent mais ignoré par l'outil (nodejs/npm)
- `mt-scan` (grype) — aucun résultat produit par l'outil

### Limites de cette analyse

- le jeu de règles est épinglé sur python/security-audit : un dépôt d'un autre langage ressortirait vide sans erreur
- package.json présent mais non analysé : dépendances nodejs/npm non couvertes
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

- dépôt : `/home/user/PHASE3/dogfooding/cibles/mocha`
- commit : `e6b9ee773481fd739ae24caeb42f32ac0b010f95`
- identifiants : plan `55666b89d65fb397` · run `6c6da33e8bba224d`
- empreintes : cible `5649d47d39487d08` · contexte `331c2ee5fe0b55fb` · résultat `1fba9303cbf2655d`
- profil : `controlled_dev`
- 38 observations, 12 regroupements
