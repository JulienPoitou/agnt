# PHASE 3.1 — STATUT CONSOLIDÉ (version figée)

_Mise à jour après les trois corrections du 2026-08-27 : statut mémoire, digest de la cible,
robustesse du mapping de paquet._

## Suites de tests

| Suite | Résultat | Ce qu'elle couvre |
|---|---|---|
| `test_securite.py` | **16/16, exit 0** | chemins, symlinks, sorties, arguments, écriture, timeout, processus |
| `test_slice.py` | **10/10, exit 0** | les dix critères du vertical slice |
| `test_tracabilite.py` | **12/12, exit 0** | les cinq identifiants et la règle de comparaison |
| `test_correlation.py` | **7 OK, 0 échec, 1 non satisfait** | mécanisme validé, généralité non démontrée |

---

## 1. Contention d'exécution — formulation corrigée

**La formulation « containment validée » était trop large. La bonne :**

```
Execution containment :
  validée pour les chemins, fichiers, processus et temps ;
  limitation mémoire NON démontrée.
```

`RLIMIT_AS` casse les outils réels — Trivy (`cannot allocate memory`, mmap boltdb) et
Gitleaks (crash wazero). La mémoire n'est donc pas bornée. `RLIMIT_NPROC`, `RLIMIT_CPU` et
`RLIMIT_FSIZE` fonctionnent et sont appliqués.

**Suffisant pour :**

```
une fixture locale contrôlée
des scanners passifs
un environnement de développement dédié
un risque accepté et explicitement limité
```

« Un seul utilisateur » a été RETIRÉ de cette liste : il ne protège pas contre un dépassement
mémoire. Un dépôt malveillant, ou simplement très volumineux, peut provoquer une consommation
excessive même avec un outil passif.

**INSUFFISANT pour :**

```
tout dépôt non fiable
tout service exposé
tout environnement multi-utilisateur
tout scan parallèle
tout outil actif ou intrusif
```

Avant la Phase 7 ou toute exposition réelle : cgroups v2 ou runtime OCI imposant CPU, mémoire,
PIDs et I/O.

### Cette limite est maintenant IMPOSÉE, pas seulement documentée

Deux règles dans `policy/policy.rego`, testées :

```
cible non fiable  + mémoire non bornée   → REFUS (memoire_non_bornee_cible_non_fiable)
outil ACTIF/INTRUSIVE + sandbox non durci → REFUS (sandbox_non_durci_outil_actif)
```

Le moteur DÉCLARE son profil (`memoire_bornee`, `durci`, …) ; OPA DÉCIDE. Si la déclaration
ment, la garde ne vaut rien — d'où le test dédié.

---

## 2. Les cinq identifiants

```
plan_id                   = e6f24a71248449fa    hash du plan typé
input_digest              = f149171fae884fb9    hash de la cible analysée
execution_context_digest  = 22e0923d990bd8bd    outils, règles, base, policy, registre, sandbox
run_id                    = 4933c23de483bb61    identité unique de l'exécution
result_digest             = b2e30e301b38f23b    hash des findings canoniques TRIÉS
```

**Critère exact, désormais testé :**

```
même plan + même cible + même contexte  → même result_digest
même plan + autre cible                 → input_digest différent, PAS un rejeu comparable
```

Et deux champs ajoutés le 2026-08-27 :

```
input_commit        = defbe2dd27a6…     commit HEAD
working_tree_dirty  = true/false        modifications non commitées
```

Le commit SHA ne suffit pas : un dépôt modifié sans commit produirait le même SHA pour deux
états analysés différents.

**Ce qui entre dans `input_digest`** — vérifié par test, pas seulement déclaré :

| Élément | Testé |
|---|---|
| chemins relatifs | ✓ |
| contenu des fichiers | ✓ le digest change |
| nature (fichier / dossier / symlink) | ✓ |
| **cible du symlink** | ✓ changer `/etc/passwd` → `/etc/shadow` change le digest |
| permissions (mode) | ✓ le digest change |
| fichiers non suivis par git | ✓ inclus |
| `.git` | **exclu** — change sans que le code change |

Les symlinks sont représentés dans le digest **même s'ils sont ensuite refusés** par la garde
de chemin : le digest décrit ce qui a été vu, la garde décide ce qui est autorisé.

Détails de conception :

- **`.git` est exclu** du digest de l'arbre — il change à chaque commit sans que le code
  analysé change. Le commit SHA est capturé **à part** (`input_commit`).
- **`result_digest` est calculé sur des tuples triés.** Testé : permuter l'ordre des findings
  ne change pas l'empreinte. Comparer l'ordre brut produirait des divergences fantômes.
- **`run_id` inclut l'`input_digest`** : deux dépôts différents ne peuvent pas être confondus.

---

## 3. Mapping de paquet — plus heuristique

**Avant :** une table de marqueurs en dur dans le code, et un paquet déduit du nom de la règle.

**Après :** `slice/mapping_regles.yaml`, versionné, et une structure explicite :

```json
{
  "tool": "semgrep",
  "original_rule_id": "PHASE3.mt-regles.python.lang.security.deserialization.avoid-pyyaml-load…",
  "canonical_rule_id": "semgrep:python.lang.security.deserialization.avoid-pyyaml-load…",
  "package": "pyyaml",
  "package_mapping": { "method": "mapping_versionné", "confidence": "high" }
}
```

**L'identifiant original est toujours conservé.** Le canonical est défini par le mapping ou par
les métadonnées de la règle, jamais deviné.

Méthodes observées sur les 73 findings des deux fixtures :

| Méthode | Cas |
|---|---|
| `rule_metadata` | Trivy déclare lui-même le paquet — le plus fiable |
| `mapping_versionné` | règles Semgrep listées dans le YAML |
| `inconnu` | **3 findings à `package: null`** — on ne devine pas |

Un paquet inconnu ne bloque rien : il empêche seulement le regroupement par paquet.

**Limite assumée :** la normalisation par recherche de marqueurs (`python.lang.`, `django.`…)
reste une réparation immédiate. À terme, le canonical id doit venir des métadonnées de la règle
ou du registre de règles, pas d'une liste de préfixes.

---

## 4. Corrélation inter-outils — statut exact

```
Mécanisme de corrélation      : validé
Corrélation sur fixture       : validée
Généralisation                : NON démontrée
```

Démontré sur la fixture contrôlée :

```
CL-001 · 4 membres · high
  reason  = [cross_tool, same_package, related_dependency, tools:semgrep+trivy]
  membres = sg-0001 (Semgrep, avoid-pyyaml-load) + tv-0001/0002/0003 (Trivy, CVE pyyaml)
```

**Le test B ne bloque pas la validation du vertical slice.** Il bloque uniquement
l'affirmation « la corrélation inter-outils est générale ».

### Ce qu'il faut pour le test B

Une cible qui soit :

```
versionnée par commit
connue comme vulnérable
non préparée par le moteur
reproductible hors réseau
avec manifest/lockfile ET code réellement liés
```

Et trois résultats possibles, tous acceptables :

| Résultat | Interprétation |
|---|---|
| cluster inter-outils trouvé | la corrélation généralise |
| aucun cluster mais findings corrects | le mécanisme est sain, le cas ne se présente pas |
| finding attendu absent | **bug à diagnostiquer** |

Un dépôt qui ne produit aucun finding — comme `PHASE3/slice` actuellement — teste l'absence de
faux positifs, pas la corrélation.

---

## 5. Intent engine — trois états, implémentés et testés

```yaml
status: resolved | needs_clarification | rejected
```

La distinction est **stricte**, et testée comme telle :

```
needs_clarification = il MANQUE une information → porte une question, AUCUN motif
rejected            = demande comprise mais refusée → porte un motif, AUCUNE question
```

`test_intentions.py` vérifie aussi qu'**aucune exécution** ne part sur un état non résolu :
plan vide, zéro finding, aucun run_id.

Les tests de paraphrase restent à écrire **comme contrat** — ils ne comptent pas comme
validation tant que le LLM n'est pas branché.

---

## 6. Ordre restant

```
1. ✅ input_digest et result_digest
2. ✅ mapping paquet renforcé, identifiants originaux conservés
3. ✅ tests de sécurité
4. ✅ fixture inter-outils
5. ✅ états d'intention resolved / needs_clarification / rejected
6. ✅ garde de refus si mémoire non bornée  (imposée, pas seulement documentée)
7. ✅ dépôt indépendant — généralisation démontrée (Config-Portal)
8. ✅ états d'intention au contrat public
9. ⬜ cgroups v2 ou runtime OCI, avant tout élargissement
```

## 6bis. Suites de tests — Phase 3.1

| Suite | Résultat |
|---|---|
| `test_securite.py` | 16/16, exit 0 |
| `test_slice.py` | 10/10, exit 0 |
| `test_tracabilite.py` | 12/12, exit 0 |
| `test_intentions.py` | 22/22, exit 0 |
| `test_correlation.py` | 7 OK, 0 échec, 1 non satisfait |

## 6ter. Verdict figé — PHASE 3.1 FERMÉE

```
Phase 3.1                          : VALIDÉE
Vertical slice                     : VALIDÉ
Sécurité passive contrôlée         : VALIDÉE
Mémoire bornée                     : NON DISPONIBLE
Traçabilité                        : VALIDÉE
Rejeu déterministe                 : VALIDÉ sous contexte identique
Clustering                         : VALIDÉ
Corrélation inter-outils           : mécanisme validé
Transfert sur cible indépendante   : DÉMONTRÉ
Généralité du mécanisme            : encore à renforcer
LLM                                : non validé
Production                         : interdite dans le profil actuel
```

## 6quater. Test indépendant — généralisation démontrée

Cible : `anotherik/Config-Portal` au commit `0ae503e6b6b37f11ed1bed5e917e19cb631ed041`,
clone épinglé, scan passif hors réseau, **aucun exploit exécuté**.

Le moteur n'a reçu que « analyse la sécurité de ce dépôt ». Aucune mention de PyYAML,
de `yaml.load` ni de CVE. L'oracle est externe au moteur.

```
10 findings
Trivy    : CVE-2019-20477 · CVE-2020-14343 · CVE-2020-1747   (les 3 documentées)
Semgrep  : avoid-pyyaml-load sur app.py
CL-002   : 4 membres · cross_tool, same_package, related_dependency, tools:semgrep+trivy
rejeu    : même plan_id, même input_digest, même result_digest, run_id distinct
```

**10/10.** Le cluster inter-outils est apparu sur une cible que le moteur ne connaissait pas.

## 6quinquies. Profils d'exécution

```yaml
execution_profile: controlled_dev        # profil actif
memory_bounded: false
allowed_target_trust: [controlled]
allowed_risk: [PASSIVE]
```

`limites_a_prouver` est déclaré mais **ne doit pas être utilisé** tant que les limites ne
sont pas réellement appliquées : le déclarer sans les appliquer désactiverait la garde de refus.

## 6hexies. run_id

`run_id = contexte + cible + instant + nonce aléatoire`. Le nonce est indispensable : deux
exécutions lancées dans la même nanoseconde sur le même plan et la même cible doivent malgré
tout avoir des run_id distincts. Testé : 200 générations, 200 identifiants uniques.

`result_digest` reste déterministe — c'est lui qui sert à comparer.

## 7. Contrat public

`PHASE3/CONTRAT_PUBLIC.md` : les trois états d'intention, les cinq identifiants, les profils,
l'identité des findings, la couverture, et ce qui n'est PAS validé.

## 7. Comment rejouer

```bash
bash PHASE3/bootstrap.sh
python3 PHASE3/test_securite.py       # porte bloquante — en premier
python3 PHASE3/test_slice.py
python3 PHASE3/test_tracabilite.py
python3 PHASE3/test_correlation.py
```
