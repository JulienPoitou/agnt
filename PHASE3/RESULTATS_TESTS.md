# PHASE 3 — RÉSULTATS DES TESTS RÉELS

_Exécuté le 2026-08-27 dans cet environnement de travail._

| Outil | Version testée | Comment |
|---|---|---|
| Semgrep | 1.175.0 | installé via pip |
| Trivy | 0.74.0 | script d'installation officiel |
| Gitleaks | 8.30.1 | binaire de la release officielle |

**Dépôt de test** : `PHASE3/testrepo/` — un `app.py` contenant une injection de commande, un
hachage MD5, un token GitHub et une clé AWS ; un `requirements.txt` avec flask 1.0, requests
2.20.0, pyyaml 5.1, django 2.2.0 ; un `package.json` avec lodash 4.17.4 et minimist 0.0.8.

**Méthode de coupure réseau** : `HTTPS_PROXY` et `HTTP_PROXY` pointés vers `127.0.0.1:9`,
port qui refuse les connexions. Ce n'est pas une vraie isolation réseau, mais toute tentative
de connexion échoue — ce qui suffit pour savoir si un outil a besoin du réseau.

---

## 1. Ce qui est confirmé par exécution

### 🔴 Gitleaks renvoie le secret en clair

```
$ gitleaks git . --report-format json --report-path gl.json --no-banner
findings: 1
  RuleID = github-pat
  Secret = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'      ← LA VRAIE VALEUR
```

Ce n'était plus une hypothèse de lecture de code : c'est mesuré.

### ✅ `--redact` corrige le problème

```
$ gitleaks git . --redact ...
  Secret = 'REDACTED'      Match = 'REDACTED'
```

### ✅ Gitleaks ne fournit aucune sévérité

Les 18 champs réels du JSON :

```
Author, Commit, Date, Description, Email, EndColumn, EndLine, Entropy, File,
Fingerprint, Match, Message, RuleID, Secret, StartColumn, StartLine, SymlinkFile, Tags
```

Aucun `Severity`. La sévérité est donc bien **notre** responsabilité.

### ✅ Trivy et Semgrep produisent du SARIF 2.1.0 valide

| Outil | SARIF | Résultats | Identifiants |
|---|---|---|---|
| Trivy | 2.1.0 | 50 | `ruleId` = CVE directement (`CVE-2019-14234`) |
| Semgrep | 2.1.0 | 2 | `ruleId` = identifiant complet de la règle |

Aucun convertisseur à écrire pour l'export.

### ✅ Trivy fonctionne hors ligne — à une condition

```
$ HTTPS_PROXY=http://127.0.0.1:9 trivy fs --skip-db-update --skip-java-db-update \
    --disable-telemetry --format json .
exit=0 — 50 vulnérabilités trouvées
```

**La condition : le cache doit être pré-peuplé.** Deux preuves que ce n'est pas optionnel :

```
# --offline-scan seul, cache vide, réseau coupé :
FATAL  failed to download vulnerability DB:
       proxyconnect tcp: dial tcp 127.0.0.1:9: connect: connection refused

# --skip-db-update, cache vide :
ERROR  The first run cannot skip downloading DB
FATAL  --skip-db-update cannot be specified on the first run
```

Le piège que j'avais identifié en lisant le code est donc **réel** : `--offline-scan` ne dispense
pas de la base. Il coupe les requêtes API d'identification de dépendances, c'est tout.

**La base pèse 1,3 Go** (`du -sh ~/.cache/trivy`). C'est ce qu'il faudra monter en lecture seule
dans le sandbox, et qu'il faudra rafraîchir périodiquement.

### ✅ Semgrep fonctionne hors ligne — avec des règles locales

```
$ HTTPS_PROXY=http://127.0.0.1:9 semgrep scan --config ../rules/python.yaml \
    --config ../rules/security-audit.yaml --metrics=off --json .
exit=0 — 2 résultats
```

**Sans règles locales, il échoue.** Avec `--config p/ci` et le réseau coupé : exit 2 après 98 s.
Les règles doivent donc être pré-téléchargées (`p/python` = 488 Ko, `p/security-audit` = 474 Ko).

---

## 2. Trois découvertes qui n'étaient pas prévues

### 🔴 Le choix du jeu de règles change tout

```
p/ci                       → 160 règles chargées, 0 résultat
p/python + p/security-audit → les 2 vulnérabilités trouvées
```

Les deux vulnérabilités volontaires de notre fixture — injection de commande ligne 9, MD5 ligne
12 — **ne sont pas détectées par `p/ci`**. Un adaptateur configuré avec le mauvais jeu de règles
produit un scan vide, sans erreur, sans avertissement.

**Conséquence :** le jeu de règles doit être **épinglé dans la configuration du provider**, et
jamais laissé par défaut. C'est exactement le rôle du champ `args_obligatoires`.

### 🔴 Trivy ignore silencieusement `package.json`

```
sans package-lock.json  → fichiers analysés : ['requirements.txt']
avec package-lock.json  → fichiers analysés : ['package-lock.json', 'requirements.txt']
                          package-lock.json : 12 vulnérabilités
```

Aucun avertissement dans les deux cas. Un dépôt npm sans lockfile est analysé **sans ses
dépendances**, et le résultat a l'air normal.

**Conséquence :** une capacité `DEPENDENCY_ANALYSIS` doit déclarer ses **préconditions**
(« nécessite un lockfile pour npm »). Sinon on produit des rapports faussement rassurants —
le pire type d'échec pour un outil de sécurité.

### 🟡 L'identifiant de règle change selon l'origine

```
depuis le registre Semgrep : python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
depuis un fichier local    : rules.python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
                             ^^^^^^ préfixe ajouté
```

La **même** vulnérabilité a deux identifiants différents. Sans normalisation, la déduplication
et la corrélation — notre principal différenciant — produiraient des doublons.

### 🟡 Gitleaks classe une clé AWS en `generic-api-key`

Une clé AWS d'apparence réaliste est détectée sous la règle générique, pas sous une règle AWS.
Et `AKIAIOSFODNN7EXAMPLE` — l'exemple de la documentation AWS — n'est pas détecté du tout,
probablement sur liste blanche.

**Conséquence :** la couverture réelle de `SECRET_DETECTION` est plus étroite que son nom.

---

## 3. Ce que ça impose à l'architecture

**Aucune de ces découvertes ne remet en cause la structure** `LLM → Plan typé → OPA → Executor →
Sandbox → Tools`. Elles portent toutes sur la **configuration des providers**, ce qui confirme
le choix de mettre cette configuration dans le registre plutôt que dans le moteur.

| Découverte | Champ du registre concerné |
|---|---|
| Gitleaks en clair | `args_obligatoires: ["--redact"]` |
| Trivy télémétrie + base | `args_obligatoires: ["--skip-db-update", "--skip-java-db-update", "--disable-telemetry"]` + volume de cache |
| Semgrep metrics + règles | `args_obligatoires: ["--metrics=off", "--disable-version-check"]` + volume de règles |
| Jeu de règles critique | `config_epinglee` — **nouveau champ à ajouter** |
| npm sans lockfile | `preconditions` — à enrichir |
| Identifiants instables | normalisation côté moteur, **avant** stockage |

**Un nouveau champ apparaît : `config_epinglee`.** Je le signale sans le créer : c'est une
décision d'architecture, et tu m'as demandé d'être prévenu avant.

**Deux pré-chauffages obligatoires**, pas un :
- base Trivy (1,3 Go) ;
- règles Semgrep (~1 Mo).

Les deux hors sandbox, puis montés en lecture seule.

---

## 3bis. Blocage levé : sandbox validé avec bubblewrap

Docker reste absent, mais **ce n'était pas nécessaire**. Vérifications faites :
`max_user_namespaces=7917`, `unshare --user --pid` fonctionnel, `CapEff: 0000000000000000`,
cgroups v2 présents. bubblewrap 0.12.0 installé via apt.

**Résultat de `PHASE3/test_bwrap.sh` : 11/11, exit 0.**

| Test | Résultat |
|---|---|
| Gitleaks en rootless + read-only + sans réseau | ✅ rc=1 car 1 leak trouvé |
| Rapport de Gitleaks produit sur l'hôte | ✅ |
| 1 leak détecté | ✅ |
| Aucun secret en clair dans le rapport | ✅ `--redact` |
| Semgrep en rootless + read-only + sans réseau | ✅ exit 0 |
| Semgrep : 2 vulnérabilités trouvées | ✅ |
| Trivy en rootless + read-only + sans réseau | ✅ exit 0 |
| Trivy : 62 vulnérabilités (50 pip + 12 npm) | ✅ |
| Timeout imposé de l'extérieur | ✅ code 124 |
| Trivy échoue sans base pré-peuplée | ✅ |
| L'erreur cite bien un échec de connexion | ✅ |

**Conditions validées :** rootless (uid 1000) · filesystem lecture seule · capabilities nulles ·
réseau coupé · timeout · workspace temporaire · aucun secret.

**Non validé :** les limites CPU / mémoire / PIDs. bubblewrap ne les impose pas ; il faut
cgroups v2, `systemd-run`, ou un vrai conteneur. C'est le seul reste, et il ne change rien à
l'architecture.

### Quatre pièges rencontrés — à connaître avant d'écrire l'executor

1. **L'ordre des arguments bwrap compte.** La racine est montée en lecture seule, donc bwrap ne
   peut plus créer de point de montage ensuite. Toutes les cibles de `--ro-bind` et `--bind`
   doivent **exister avant** l'appel, et être déclarées **après** `--ro-bind / /`.
   Erreur obtenue : `bwrap: Can't create file ...: Read-only file system`.
2. **`/tmp` est un tmpfs** : il disparaît à la sortie. Les rapports doivent être écrits dans un
   répertoire bindé depuis l'hôte, sinon on conclut à tort que l'outil n'a rien produit.
3. **Ne jamais faire `rm -rf` sur un répertoire déjà bindé** : ça casse le montage.
4. **git rejette le dépôt dans un user namespace** (propriétaire douteux). Il faut un
   `GIT_CONFIG_GLOBAL` avec `safe.directory`. Erreur obtenue : `fatal: not a git repository`.

---

## 4. Ce qui n'a PAS pu être testé — Docker absent

Vérifié : aucun runtime de conteneur dans cet environnement (ni docker, ni podman, ni nerdctl,
ni singularity, ni bubblewrap), et pas de `/var/run/docker.sock`.

**Les conditions de sandbox restent donc non validées :**

| Condition | État |
|---|---|
| rootless (uid 1000) | ❌ non testé |
| filesystem en lecture seule | ❌ non testé |
| capabilities Linux supprimées | ❌ non testé |
| limites CPU / mémoire / PIDs | ❌ non testé |
| réseau désactivé | 🟡 simulé par proxy, pas par isolation réelle |
| timeout obligatoire | ❌ non testé |
| workspace temporaire | ❌ non testé |
| aucun secret par défaut | ✅ validé pour Gitleaks via `--redact` |

**Note :** le risque que je signalais sur les permissions de volume pour Semgrep en non-root
**ne s'est pas matérialisé** — Semgrep tourne en uid 1000 avec le dépôt en lecture seule.
Le piège réel était ailleurs : l'ordre des montages et `safe.directory` pour git.

### Comment lever ce blocage

`PHASE3/harnais_sandbox.sh` teste les huit conditions. Syntaxe validée (`bash -n`), mais
**jamais exécuté** faute de Docker.

```bash
# 1. pré-télécharger la base Trivy dans un volume
docker volume create trivy-cache
docker run --rm -v trivy-cache:/root/.cache/trivy aquasec/trivy image --download-db-only

# 2. télécharger les règles Semgrep
mkdir -p PHASE3/rules
curl -sL -o PHASE3/rules/python.yaml         https://semgrep.dev/c/p/python
curl -sL -o PHASE3/rules/security-audit.yaml https://semgrep.dev/c/p/security-audit

# 3. lancer
./PHASE3/harnais_sandbox.sh
```

Le script rend un code de sortie non nul si une condition échoue, avec ce principe : **on ne
passe pas au minimal core tant qu'il y a un échec.**

---

## 5. Réponse à la question posée

> Est-ce que les résultats sont compatibles avec l'architecture ?

**Oui, pour tout ce que j'ai pu tester.** Les trois outils produisent ce qu'on attend, dans un
format standard, et fonctionnent sans réseau moyennant un pré-chauffage. Rien ne demande de
revenir sur les décisions de Phase 2.

**Et la réponse est maintenant complète sur l'essentiel :** les trois outils tournent dans un
environnement confiné — rootless, lecture seule, sans capabilities, sans réseau — et produisent
leurs résultats normalement. 11 tests sur 11.

**Reste un seul point non validé :** les limites CPU / mémoire / PIDs, qui demandent cgroups ou
un vrai conteneur. Ça ne change rien à l'architecture, seulement au choix du runtime en Phase 3.
