# PHASE 3 — SÉCURITÉ, TRAÇABILITÉ, CORRÉLATION

_Ordre validé le 2026-08-27 : sécurité → traçabilité → corrélation → validation indépendante._

## État des trois suites de tests

| Suite | Résultat | Fichier |
|---|---|---|
| **Sécurité** (porte bloquante) | **16/16, exit 0** | `test_securite.py` |
| **Slice** (dix critères) | **10/10, exit 0** | `test_slice.py` |
| **Corrélation** | **7 OK, 0 échec, 1 NON SATISFAIT** | `test_correlation.py` |

---

## 1. Porte bloquante de sécurité — 16/16

Les deux couches sont testées séparément, parce qu'elles n'offrent pas les mêmes garanties :

| Cas | Couche | Résultat |
|---|---|---|
| cible `../hors-workspace` | exécution | bloqué |
| symlink vers un fichier hors workspace | exécution | bloqué |
| symlink **interne** | exécution | autorisé (option 2) |
| chemin absolu hors racines | exécution | bloqué |
| sortie hors répertoire autorisé | exécution | bloqué |
| sortie dans le répertoire autorisé | exécution | autorisé |
| argument contenant `;` `&&` `$(...)`, retour à la ligne, octet NUL | exécution | bloqués (5 cas) |
| argument légitime | exécution | non bloqué |
| écriture dans le dépôt d'entrée | exécution | bloqué (`Read-only file system`) |
| timeout coupe l'exécution | exécution | bloqué (code 124 en 2,0 s) |
| **processus enfant ne survit pas** | exécution | bloqué |
| création excessive de processus | exécution | bloqué (`Cannot fork`) |

### Ce que la porte a révélé

**Deux découvertes qui contredisent ce que j'avais écrit auparavant.**

**a) `RLIMIT_AS` est inutilisable.** Je l'avais ajouté en croyant combler le trou mémoire.
Testé sur les outils réels, il les casse :

```
Trivy    → « cannot allocate memory » à l'ouverture de sa base boltdb (mmap)
Gitleaks → crash dans wazero, son moteur regex WASM réserve une grande région virtuelle
```

J'avais validé le **mécanisme** avec `ulimit -v`, pas son effet sur de vrais outils.
**Conséquence : la mémoire n'est PAS limitée.** Le faire correctement demande cgroups v2
ou un runtime OCI. C'est une limite réelle, pas un détail.

En revanche `RLIMIT_NPROC`, `RLIMIT_CPU` et `RLIMIT_FSIZE` fonctionnent et sont conservés —
`RLIMIT_NPROC=64` produit bien `Cannot fork` au lieu de 300 processus.

**b) `--die-with-parent` ne suffit pas.** Testé pour de vrai : `sleep 60 &` **survivait** au
timeout avec un PID encore vivant. `timeout` ne tue que l'enfant direct, et `--die-with-parent`
ne tue que l'enfant direct de bwrap. Corrigé avec `start_new_session=True` + `killpg` sur le
groupe entier. Une fuite de processus est aussi une fuite de ressources et d'information.

### Répartition OPA / filesystem

Conforme à ce que tu as formulé :

- **OPA** décide si la cible **demandée** est autorisée — il ne voit que des chaînes.
- **Le filesystem** garantit qu'aucun symlink ne sort **réellement** du workspace.

`garde_chemin.py` utilise `os.path.commonpath`, pas `startswith` : ce dernier accepterait
`/testrepo-malin` comme contenu dans `/testrepo`.

---

## 2. `plan_id` / `run_id` et contexte d'exécution

Séparation effective, vérifiée par le critère 10 réécrit :

```
plan_id  = da77ddebc02abde1     stable entre deux rejeux
run_id   = 90edfb4c4b4d9c50 → fa9c7d858430a1e5    distinct à chaque exécution
contexte = a3f7c5ef080ee570     5 outils, 2 règles, base Trivy, policy, registre, sandbox
```

Le contexte capture : versions de semgrep, trivy, gitleaks, bwrap et opa ; digest des règles ;
digest de la base Trivy ; empreinte de la policy ; empreinte du registre ; limites du sandbox.

**Critère 10 réécrit** selon ta formulation :

> même plan + même contexte → résultats identiques
> même plan + autre contexte → nouveau run_id et divergence traçable

---

## 3. Corrélation inter-outils — mécanisme démontré, généralité NON démontrée

### Test A — fixture contrôlée : démontré

```
CL-001 · 4 membres · confiance high
  reason  = [cross_tool, same_package, related_dependency, tools:semgrep+trivy]
  clé     = paquet:pyyaml
  membres = sg-0001 (Semgrep, avoid-pyyaml-load)
            tv-0001, tv-0002, tv-0003 (Trivy, CVE pyyaml)
```

Les 8 findings en entrée sont tous répartis, aucune perte. Le cluster n'est présenté
**nulle part** comme une vulnérabilité confirmée : c'est une relation entre observations.

**Limite assumée :** c'est moi qui ai construit cette fixture pour provoquer le lien.
Le test démontre donc le **mécanisme**, pas sa généralité.

### Test B — dépôt indépendant : NON SATISFAIT

Le seul test à l'aveugle disponible (`PHASE3/slice`) produit **0 finding et le déclare
correctement**. C'est un vrai négatif — pas de faux positif, couverture honnête — mais
**il ne valide rien sur la corrélation**.

**Il manque une cible réelle** : un dépôt avec une dépendance vulnérable **et** un usage
dangereux de cette dépendance, que je n'aurais pas construit pour l'occasion.
Aucun dépôt de ce type n'existe dans cet environnement.

### Un problème d'identité résolu au passage

L'identifiant de règle Semgrep **varie selon le chemin du fichier de règles** :

```
registre        → python.lang.security.audit.subprocess-shell-true…
fichier local   → rules.python.lang.security.audit.subprocess-shell-true…
autre chemin    → PHASE3.mt-regles.python.lang.security.deserialization…
```

Ma normalisation précédente retirait un préfixe fixe `rules.` : elle cassait dès que le
chemin changeait. Remplacée par une recherche de marqueurs (`python.lang.`, `django.`, …).
Sans ça, la même règle produisait plusieurs `canonical_rule_id` et la déduplication
fabriquait des doublons.

Le lien inter-outils passe par un nouveau champ `source.package`, déduit de la règle
(`deserialization.avoid-pyyaml-load` → `pyyaml`). C'est ce qui permet de relier un usage
dangereux vu par Semgrep à la vulnérabilité du paquet vue par Trivy.

---

## 4. Statut consolidé

```
Vertical slice            : fonctionnel, 10/10 critères
Policy boundary           : validée, y compris contre arguments hostiles
Execution containment     : validée sur 16 cas — SAUF la mémoire, non limitée
Traçabilité               : plan_id / run_id / contexte opérationnels
Clustering v0             : démontré, conservateur, sans perte
Corrélation inter-outils  : MÉCANISME démontré, GÉNÉRALITÉ non démontrée
Intent engine             : contrat déterministe validé, LLM non testé
Sandbox durcie            : non démontrée (mémoire, et pas d'équivalent cgroups)
```

---

## 5. Ce qu'il reste, dans l'ordre

1. **Une cible réelle pour le test B.** Sans elle, on ne peut pas affirmer que la corrélation
   généralise. C'est le seul point qui bloque une conclusion.
2. **Tests de paraphrase** comme contrat, marqués non validés tant que le LLM n'est pas branché.
   Ajouter aussi le comportement « demander une clarification », qui n'existe pas aujourd'hui :
   l'intent engine lève une exception au lieu de demander.
3. **Limites mémoire** via cgroups ou runtime OCI — nécessaire avant tout outil actif.

## 6. Comment rejouer

```bash
bash PHASE3/bootstrap.sh
python3 PHASE3/test_securite.py      # porte bloquante — doit passer en premier
python3 PHASE3/test_slice.py         # dix critères
python3 PHASE3/test_correlation.py   # mécanisme + généralité
```
