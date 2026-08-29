# Analyse de sécurité — ce qu'il faut regarder

Dépôt analysé le 28/08/2026 à 09:27.

## L'essentiel

**2 points à traiter en priorité**, sur 6 au total.

**1.** La librairie `nltk` présente 5 failles connues (gravité haute).

Signalé par `trivy`.
Failles concernées : `CVE-2026-12061`, `CVE-2026-12072`, `CVE-2026-12074`, `CVE-2026-12075`, `CVE-2026-54293`.
Fichiers : `requirements.txt`.

→ **À faire :** vérifier, puis corriger. 5 observations dans le rapport détaillé.

**2.** La librairie `flask` présente 1 faille connue (gravité moyenne), et 2 outils différents signalent un problème dans la façon dont votre code l'utilise.

Signalé par `semgrep` et `trivy`. Quand deux outils indépendants convergent, le problème est **probable** — mais il reste à vérifier.
Failles concernées : `CVE-2026-27205`.
Fichiers : `views.py`, `cve.html`, `wsgi.py`, `requirements.txt`.

→ **À faire :** vérifier, puis corriger. 6 observations dans le rapport détaillé.

## À regarder ensuite

- 4 problèmes de même nature signalés dans `search.html` (gravité moyenne).
- 2 problèmes de même nature signalés dans `capec.html` (gravité moyenne).
- 1 problème de même nature signalé dans `capec.html` (gravité moyenne).
- 1 problème de même nature signalé dans `cve.html` (gravité moyenne).

6 observations isolées : le regroupement n'a pas trouvé de lien. Elles restent dans le rapport détaillé.

## Ce qui a été analysé

- **semgrep** : `search.py`, `Config.py`, `views.py`, `admin.html`, `capec.html`
- **trivy** : `requirements.txt`
- **gitleaks** : `historique git`

### Limites de cette analyse

- le jeu de règles est épinglé sur python/security-audit : un dépôt d'un autre langage ressortirait vide sans erreur
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

- dépôt : `/home/user/PHASE3/cible_cvesearch`
- commit : `2e25b80902ae3dfe12c2671b249d69e7944d9748`
- identifiants : plan `5cc67e6b1e3e400d` · run `3ee6d78e0928ac30`
- empreintes : cible `a28a6bae8e249884` · contexte `99bafb7452acf73f` · résultat `a7327cab4e0d7d80`
- profil : `controlled_dev`
- 25 observations, 6 regroupements
