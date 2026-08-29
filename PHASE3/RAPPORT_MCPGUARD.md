# Analyse de sécurité — ce qu'il faut regarder

Dépôt analysé le 28/08/2026 à 11:54.

## À regarder

**2 problèmes signalés**, aucun regroupement possible.

- **CVE-2026-41907** — gravité moyenne — `package-lock.json` (trivy)

- **generic-api-key** — gravité haute — `config-parser.test.ts`:215 (gitleaks)

## Ce qui a été analysé

- **semgrep** : rien
- **trivy** : `package-lock.json`
- **gitleaks** : `historique git`, `config-parser.test.ts`

### Ce qui n'a PAS été analysé

**C'est important** : un problème dans ces éléments n'aurait pas été détecté.

- `mt-scan` (semgrep) — aucune règle n'a porté sur ce dépôt
- `package.json` (trivy) — manifeste présent mais ignoré par l'outil (nodejs/npm)

### Limites de cette analyse

- le jeu de règles est épinglé sur python/security-audit : un dépôt d'un autre langage ressortirait vide sans erreur
- package.json présent mais non analysé : dépendances nodejs/npm non couvertes
- base de vulnérabilités figée au pré-chauffage : les CVE publiées depuis ne sont pas détectées
- valeur des secrets masquée à la source (--redact) : jamais stockée
- détection dépendante des règles : une clé AWS réaliste peut être classée generic-api-key, et les exemples de documentation sont sur liste blanche

## Comment lire ce rapport

| Ce qu'on dit | Ce que ça veut dire |
|---|---|
| observé | un outil a produit ce résultat |
| probable | plusieurs outils convergent, ou une faille connue est concernée |
| à vérifier | personne n'a encore confirmé que c'est exploitable |

Rien dans ce rapport n'est une vulnérabilité **confirmée**. Une confirmation demande
un test réel, ou une correction suivie d'une nouvelle analyse.

---

## Détails techniques

_Pour vérifier, rejouer ou auditer cette analyse. Le rapport complet est dans_
_`rapport.md` du même dossier._

- dépôt : `/home/user/PHASE3/cible_mcpguard`
- commit : `5f6ff1e3092802a31042417d23e7477a479487aa`
- identifiants : plan `e845aaed6d2f5a27` · run `8f7d2cce0d0efd6d`
- empreintes : cible `89a89c7dcdf53c5b` · contexte `55683d0a886af57e` · résultat `9915bf3855f583ce`
- profil : `controlled_dev`
- 2 observations, 0 regroupements
