=== AGNT HANDOFF v1 ===

Agent     : ORCHESTRATEUR (intégration, session `arena/01a05783-agnt`)
Domaine   : intégration de la ligne CORE sur main — re-alignment post PR #2
Branche   : `arena/01a05783-agnt` (PR cible : main)
Base      : main `b85bc91` (PR #2 MERGED) ← merge `origin/arena/01a0575c-agnt` (tip `3aeb8bc`)
Statut    : READY_FOR_REVIEW — batterie CORE rejouée VERTE sur l'arbre intégré, campagne adversariale identique à la base

---

## 1. Ce qui a été fait

Re-alignment de la ligne CORE (11 commits `91f1775..eebefbc` + handoff `3aeb8bc`)
sur le nouveau main (`b85bc91`, qui contient PR #2 : LOT 1 E2E + LOT 3 plugins).
Conflits prévus par merge-tree : 3. Conflits réels : 3 — résolus un par un, jamais en bloc.

### Résolutions de conflit (production)

| Fichier | Conflit | Résolution |
|---|---|---|
| `PHASE3/slice/plan.py` | signature `construire()` : `exclus_disponibilite` (PR #2) vs `cible_descr` (CORE) | **Union** : les deux paramètres conservés ; le corps auto-fusionné utilise déjà les deux. |
| `PHASE3/slice/pipeline.py` | appel `P.construire()` : dimension disponibilité vs descripteur de cible | **Union** : `exclus_disponibilite=exclus_dispo` ET `cible_descr=cib.to_dict()`, référence `reference_cible` (CORE) conservée. |
| `PHASE3/analyser.py` (hunk 1, `_archiver_mission`) | source des artefacts : `RACINE/run` global (PR #2) vs `<mission>/run` via `e.sortie` (CORE) | **CORE** (invariant « état par mission ») + politique de conservation PR #2 via `_publier_sorties(src_run, sortie)`. |
| `PHASE3/analyser.py` (hunk 2, `main()`) | idem, pour le bundle | **CORE pour la source** (`e.sortie`), **PR #2 pour la politique** (`_publier_sorties`). |

### Défaut trouvé et corrigé PENDANT la résolution (ligne CORE, préexistant)

La boucle de conservation inline de la ligne CORE réutilisait la variable `cible`
(`cible = dossier / "<f>.redacted..."`) dans `main()` : le manifeste écrivait ensuite
`"cible": str(cible)` — donc **le chemin du dernier fichier redacted à la place de la
cible réelle**. Corrigé en réutilisant le corps unique `_publier_sorties` (qui ne
touche pas aux paramètres de l'appelant). Aucun comportement attendu n'était
différent : la politique (raw_* ET brut_* examinés, masquage vérifié, non-publication
si encore sale) est strictement celle de PR #2.

### Alignements de harnais (tests uniquement — AUCUNE attente modifiée)

PR #2 a introduit l'étape 1bis « disponibilité » AVANT le plan et l'applicabilité :
sur une machine sans outils installés, la mission s'arrête plus tôt, et trois suites
CORE mesuraient des étapes situées APRÈS ce nouveau stade. Même précédent que la
réparation MCP `59252df` : le harnais est aligné sur la réalité du pipeline, les
attentes restent identiques. Seam choisi : `adapters.exe_de`, neutralisé localement
(`"/bin/true"`) avec `try/finally` — c'est exactement la scène d'une machine après
`bootstrap.sh`.

| Suite | Alignement | Résultat |
|---|---|---|
| `test_observabilite.py` | `AD.exe_de` neutralisé autour du cas 2 (l'événement `plan`) | 7/7 |
| `test_cibles.py` | idem autour du cas 7 (URL s'arrête à l'applicabilité) | 33/33 |
| `test_interface.py` | idem pour toute la section HTTP (serveur en-process : la neutralisation est visible par l'API ; le chemin d'erreur PolicyError redevient exercé) | 34/35 · 0 échec · 1 NE |

## 2. Batterie rejouée sur l'arbre intégré (2026-08-31, venv pyyaml 6.0.3, Python 3.11.2)

| Suite | Résultat |
|---|---|
| `test_mission_history_api.py` | **PASS** 33/33 |
| `test_transports.py` | **PASS** 12/12 |
| `test_observabilite.py` | **PASS** 7/7 |
| `test_cibles.py` | **PASS** 33/33 |
| `test_multi_mission.py` | **PASS** 11/11 |
| `test_isolation_mission.py` | **PASS** 8/8 |
| `test_interface.py` | **PASS** 34/35 · 0 en échec · 1 non évaluée (antérieure) |
| `test_chemins.py` (régression main) | **PASS** 48/48 · 3 non évalués |
| `test_selection.py` (régression main) | **PASS** 13/13 |
| `test_adversaire.py` (campagne) | **46 cas · 40 PASS · 2 FAIL · 4 NON ÉVALUÉS — IDENTIQUE à la base `b85bc91`** (contrôle rejoué) : les 2 FAIL (D4 `cible_autorisee`, G6a règles gitleaks) sont préexistants, domaine SECURITY (`d1d562f`, `e5838003` non intégrés) ; les 4 NE sont env (D2/D3 OPA, G9 gitleaks) + E7 (choix PR #2, déjà documenté) |
| `test_qualite_plateforme.py` | rc=1 : 2 ÉCHEC (`16quater`, `16nonies`) **identiques sur la base `b85bc91`** (contrôle rejoué en worktree) — environnement OPA absent, non-régression prouvée |
| `test_slice.py` / `test_bundle.py` / `test_plugins.py` / `test_intentions.py`… | BLOCKED environnement (OPA, bwrap, binaires absents) — identiques à la base |

`compileall PHASE3` : rc 0.

## 3. Invariants vérifiés pendant l'intégration

- **Cible ≠ sandbox** : `Cible(type, reference, chemin_local=None)` conservé ; cible
  distante jamais `Path` ; `test_cibles` 6b/7/9d verts.
- **Autorisation de cible explicite** : non régressée (D4 reste un FAIL détecté, pas un
  silence — la garde mesure, le correctif est sur la ligne SECURITY).
- **État par mission** : artefacts sous `<mission>/run` (résolution de conflit), jamais
  de `PHASE3/run` global.
- **Transport fail-closed** : registre canonique `enregistrer/fournit/connus/deleguer`
  arrivé avec CORE ; aucun fallback CLI silencieux (`test_transports` 12/12).
- **Pas de dérive repository-specific** : `cible.py` type les cibles
  (`repository`/`filesystem`/`url` représentable) ; le littéral `cible_type="repository"`
  de la ligne MCP n'est PAS ici (il reste sur la ligne MCP, à corriger à MCP-004).
- **Politique de conservation** : corps unique `_publier_sorties` pour bundle ET archive
  de mission ; le défaut d'ombrage `cible` corrigé.

## 4. Blocages / limites

- OPA absent : policy réelle NON ÉVALUÉE (aucun verdict OPA sur l'arbre intégré).
- bwrap absent : exécution sandboxée NON ÉVALUÉE.
- Binaires d'outils absents : toute exécution réelle d'outil NON ÉVALUÉE (les suites
  d'exécution sont bloquées ou alignées comme documenté).
- Gates Product/Security : à rejouer sur l'API intégrée (prochaine action).

## 5. Périmètre non touché

- Aucun fichier MCP, SECURITY, WEB, PRODUCT modifié.
- Aucune attente de test modifiée ou adoucie (seules les entrées de scène sont alignées).
- Aucun manifest, aucune règle OPA, aucun sandbox modifié.

## 6. Gates exécutés sur l'API intégrée réelle (2026-08-31, serveur `api.py --port 8141` sur l'arbre intégré)

- **Product gate** (`product_api_gate.py`, contrats `agnt.history.v1`/`timeline.v1`/`execution-status.v1`, extrait de `3f96e25`, stdlib seule, GET uniquement) :
  `--require-full-coverage --submission-id db1c6c5f5383` → **3470 PASS · 0 FAIL · 1 SKIP**.
  Le SKIP restant = « full semantic case coverage » (états `cancelled`/`timeout`/`mcp`/`zero`
  non produisibles dans cet environnement sans outils ni OPA). Preuve incluse :
  `submission_id` (`db1c6c5f5383`, POST /api/runs) ≠ `mission_id`
  (`m-20260831T113617Z-4bf75f78`) — distinction vérifiée sur API réelle.
- **Security gate** (`history_timeline_gate.py` de `dae445a`, extrait de `08a8150`) :
  `--base-url` sur la même API → **26/26 GET → PASS** (liste + tous les détails de mission,
  y compris la mission refusée créée pendant le gate). Harnais de construction du gate :
  `test_history_timeline_security.py` 46/46 sur l'arbre SECURITY.
- Aucune fuite, aucun faux zéro, aucune contradiction masquée, aucune clé inconnue,
  aucun vocabulaire MCP non allowlisté détecté par le gate Security.

## 7. Prochaine action

1. PR de cette intégration vers main (feu vert gates accordé sur l'API intégrée).
2. Re-alignment MCP sur l'arbre CORE intégré (MCP-004 : transports canoniques,
   `cible_type` dérivé, batterie 104 cas rejouée).
3. Feu vert WEB uniquement après merge de CORE dans main + gates rejoués sur main.

Confiance : HAUTE sur les 9 suites vertes, la campagne et les deux gates (sorties lues,
rc capturés, contrôle de base rejoué). NULLE sur toute évaluation OPA/sandbox réelle ici.
=== END AGNT HANDOFF ===
