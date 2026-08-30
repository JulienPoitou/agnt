# PHASE 3.1 — CONTRAT PUBLIC

Ce que le système garantit, ce qu'il refuse, et ce qu'il ne promet pas.
Version figée le 2026-08-27.

---

## 1. Entrée

Une intention en langage naturel. Rien d'autre : ni chemin d'outil, ni commande, ni paramètre.

## 2. Trois états d'intention

La sortie de l'intent engine est toujours l'un de ces trois états. La distinction entre les
deux derniers est **stricte** et testée.

```yaml
# L'intention est comprise, un plan peut être construit.
status: resolved
capabilities: [CODE_STATIC_ANALYSIS, DEPENDENCY_ANALYSIS, SECRET_DETECTION]

# Il MANQUE une information. Aucune exécution.
status: needs_clarification
question: "Que veux-tu vérifier : le code, les dépendances, ou les secrets exposés ?"

# La demande est comprise mais REFUSÉE. Aucune exécution.
status: rejected
motif: "demande interdite : cible externe qui n'est pas la mienne, attaque non autorisée"
```

```
needs_clarification = il manque une information  → porte une QUESTION, aucun motif
rejected            = compris mais refusé        → porte un MOTIF, aucune question
```

**Aucune exécution ne part sur un état non résolu** : plan vide, zéro finding, aucun run_id.
C'est testé, pas seulement déclaré.

En Phase 3.1 l'inférence est déterministe. Les tests de paraphrase sont un **contrat**, pas une
validation : le LLM n'est pas branché.

## 3. Les cinq identifiants

```
plan_id                   identité du plan typé            déterministe
input_digest              empreinte de l'état analysé      déterministe
execution_context_digest  outils, règles, base, policy     déterministe
run_id                    identité de l'exécution          UNIQUE (nonce aléatoire)
result_digest             empreinte des résultats          déterministe
```

```
run_id       = contexte + cible + instant + nonce    → toujours distinct
result_digest = findings canoniques TRIÉS            → toujours comparable
```

**Règle de comparaison :**

```
même plan + même cible + même contexte  → même result_digest
autre cible                             → input_digest différent, pas un rejeu comparable
```

**`input_digest` contient :** chemins, contenu, nature (fichier / dossier / symlink),
**cible des symlinks**, permissions, fichiers non suivis par git. **`.git` est exclu.**

Deux champs séparés, parce que le commit SHA ne suffit pas si le dépôt est modifié sans commit :

```
input_commit        = commit HEAD
working_tree_dirty  = true / false
```

## 4. Profils d'exécution

Le profil **actuel** est le seul honnête tant que la mémoire n'est pas bornée :

```yaml
nom_profil: controlled_dev
memoire_bornee: false
confiance_admise: [controlled]
risques_admis: [PASSIVE]
durci: false
```

Le profil cible, **non disponible** :

```yaml
nom_profil: limites_a_prouver
memoire_bornee: true
confiance_admise: [controlled, untrusted]
risques_admis: [PASSIVE, ACTIVE]
durci: true
```

Ces noms sont ceux que `policy.rego` lit : le dictionnaire rendu par
`profils.Profil.to_dict()` EST l'entrée soumise à OPA (`policy.py:72`), pas une vue de
rapport. Un nom qui diverge d'un côté rend la garde inopérante **sans erreur** — côté
OPA un champ absent ne lève rien, et `not <indéfini>` vaut vrai. Contrats vérifiés par
`test_utilisation.py` (G15) et par les cas de `test_intentions.py`.

**La mémoire n'est pas bornée. Le système refuse donc les dépôts non fiables et les outils
actifs.** Ce n'est pas un détail qui peut attendre sans condition : un dépôt volumineux ou
hostile peut provoquer un problème de disponibilité même avec un outil passif.

La confiance de cible se **déclare** à l'entrée utilisateur
(`analyser.py --confiance controlled|untrusted`, défaut `controlled` affiché) et traverse
`pipeline.executer(confiance_cible=…)` jusqu'à OPA ; une valeur hors liste est une erreur,
jamais un repli.

Le refus est **déterministe**, appliqué par OPA, et testé :

```
cible non fiable + mémoire non bornée    → memoire_non_bornee_cible_non_fiable
outil ACTIF + sandbox non durci          → sandbox_non_durci_outil_actif
```

## 5. Identité des findings

```yaml
source:
  tool: semgrep
  original_rule_id: PHASE3.mt-regles.python.lang…avoid-pyyaml-load   # toujours conservé
  canonical_rule_id: semgrep:python.lang…avoid-pyyaml-load
  package: pyyaml
  package_mapping:
    method: mapping_versionné      # rule_metadata | mapping_versionné | inconnu
    confidence: high
identity:
  canonical_rule_id: semgrep:python.lang…avoid-pyyaml-load
  fingerprint: 12dda28ffdad8beb7cb78faab05f56de
```

**Un paquet inconnu reste `null`**, avec `method: inconnu`. Le système n'invente jamais une
donnée qu'il n'a pas.

**La valeur d'un secret n'entre jamais dans la base.** Masquée à la source (`--redact`) puis
vérifiée par garde-fou automatisé.

## 6. Clustering

Un cluster est **une relation entre observations**, pas une vulnérabilité confirmée.

```yaml
cluster_id: CL-002
confidence: high
reason: [cross_tool, same_package, related_dependency, tools:semgrep+trivy]
members: [sg-0001, tv-0001, tv-0002, tv-0003]
```

**Aucune perte :** le nombre de findings en entrée est toujours égal au nombre réparti.
Le regroupement est conservateur : il ne force jamais un lien pour réduire le compte.

## 7. Couverture

Chaque exécution déclare ce qu'elle a analysé **et ce qu'elle n'a pas analysé**, avec l'un des
six états :

```
scanned_successfully · not_found · not_applicable · not_scanned · excluded_by_policy · unsupported
```

Exemple réel :

```
trivy
   analysé      : requirements.txt, package-lock.json
   NON analysé  : package.json [not_scanned] — manifeste npm présent mais ignoré
   limite       : base de vulnérabilités figée au pré-chauffage
```

## 8. Ce qui est validé

```
Vertical slice                     VALIDÉ
Sécurité passive contrôlée         VALIDÉE
Traçabilité                        VALIDÉE
Rejeu déterministe                 VALIDÉ sous contexte identique
Clustering                         VALIDÉ
Corrélation inter-outils           MÉCANISME validé
Transfert sur cible indépendante   DÉMONTRÉ (Config-Portal)
Généralité du mécanisme            encore à renforcer
États d'intention                  VALIDÉS (3 états)
```

## 9. Ce qui n'est PAS validé

```
Mémoire bornée                     NON DISPONIBLE
LLM                                NON VALIDÉ
Production                         INTERDITE dans le profil actuel
```

**Insuffisant pour :** tout dépôt non fiable, tout service exposé, tout environnement
multi-utilisateur, tout scan parallèle, tout outil actif ou intrusif.

Avant tout élargissement : cgroups v2 ou runtime OCI imposant CPU, mémoire, PIDs et I/O.

## 10. Suites de tests

```
test_securite.py       16/16   porte bloquante — à lancer en premier
test_slice.py          10/10
test_tracabilite.py    12/12
test_intentions.py     22/22
test_correlation.py     7/7    mécanisme, fixture contrôlée
test_independant.py    10/10   transfert sur cible indépendante
```

**Trois états, jamais mélangés dans une suite :**

```
succès       → OK, compté
échec        → ECHEC, et exit 1
non évalué   → signalé comme tel, ni compté comme succès ni comme échec
```

La version précédente affichait « 7 OK + 1 non satisfait » avec exit 0 : un état non évalué
noyé dans une suite verte. Corrigé — la partie généralisation vit dans `test_independant.py`.

## 11. Ce qui reste à renforcer

**Généralité du mécanisme.** Un seul dépôt indépendant est une bonne preuve de
non-circularité, pas une preuve générale. Familles à couvrir :

```
Python + PyYAML                    ✅ fait (Config-Portal)
Node.js + package-lock.json        ⬜
Go + go.sum                        ⬜
dépendance sans relation Semgrep/Trivy   ⬜
plusieurs versions d'une même dépendance ⬜
```

**Les dix limites à tester avant d'employer le mot « durci » :** mémoire maximale, swap,
CPU, PID, taille des fichiers, timeout, réseau, capabilities, `no-new-privileges`,
nettoyage après arrêt. En l'état, seuls timeout, capabilities, réseau et taille des
fichiers sont testés.

## 12. Manifeste des dépendances

`PHASE3/manifeste_dependances.yaml` : versions et SHA-256 des binaires et des jeux de règles.
Le bootstrap **vérifie** et **refuse** un binaire inattendu (testé : un octet ajouté à
gitleaks provoque un refus avec exit 1). C'est ce qui rend l'affirmation « reconstruction
depuis zéro » vraie plutôt qu'approximative.

