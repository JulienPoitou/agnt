=== AGNT HANDOFF v1 ===

**Agent :** CORE
**Domaine :** moteur — cible typée, provider/transport, isolation multi-mission, observabilité, History/Timeline/Status API
**Branche de session :** `arena/01a0575c-agnt` (tip `eebefbc` + cet enregistrement)
**Ligne d'origine :** `arena/01a05415-agnt` @ `eebefbcaf575d27efad61f95853d53274248b997` — récupérée par `git merge --ff-only eebefbc` depuis `4433af6` (fast-forward vérifié : `git merge-base --is-ancestor 4433af6 eebefbc` → vrai, 11 commits)
**Statut :** `READY_FOR_INTEGRATION` — **CONFIRMÉ par exécution** (n'était que DÉCLARÉ dans la mémoire)
**Date :** 2026-08-31

---

## 1. Commits (11, ordre chronologique)

| SHA | Sujet |
|---|---|
| `91f1775` | core: remove global intent state |
| `5f3f522` | core: isolate mission execution state |
| `0f73325` | core: introduce provider execution contract |
| `084bb73` | core: journal structured decision trail |
| `d1c236c` | core: update run-dir rationale in interface docs and test |
| `8eb4005` | core: add canonical target descriptor |
| `f1f323d` | core: wire target descriptor into plan, policy, sandbox and journal |
| `729c2c0` | core: add canonical mission history reader |
| `fed13d6` | core: expose read-only mission history endpoints |
| `e36c53a` | core: test mission history through the HTTP API |
| `eebefbc` | core: aligne l'historique Mission sur les contrats Product v1 (history/timeline/execution-status) |

## 2. Périmètre exact — **22 fichiers** (correction de la mémoire : 21 annoncé)

`git diff --stat 4433af6..eebefbc` → **22 files changed, 3465 insertions(+), 91 deletions(-)**
(la mémoire citait « 21 fichiers, +3247/−77 » : le chiffre annoncé était faux, le diff réel fait foi.)

Nouveaux (9) :
- `PHASE3/slice/cible.py` — descripteur de cible canonique : `Cible(type, reference, chemin_local=None)`, `normaliser()`, `est_local()`, `applicable()`, `types_applicables()`
- `PHASE3/slice/transports.py` — registre de transports : `enregistrer()`, `fournit()`, `connus()`, `deleguer()`, `TRANSPORT_SANDBOX_CLI`
- `PHASE3/slice/mission_history.py` — lecteur unique read-only : `lire_journal()`, `statut_mission()`, projections `agnt.history.v1` / `agnt.timeline.v1` / `agnt.execution-status.v1`, rédaction des chemins (`_rediger_chemins`, `_uri_sure`, `_nettoyer`)
- `PHASE3/test_cibles.py`, `PHASE3/test_transports.py`, `PHASE3/test_observabilite.py`, `PHASE3/test_multi_mission.py`, `PHASE3/test_isolation_mission.py`, `PHASE3/test_mission_history_api.py`

Modifiés (13) :
- `PHASE3/slice/pipeline.py`, `PHASE3/slice/plan.py`, `PHASE3/slice/policy.py`, `PHASE3/slice/adapters.py`, `PHASE3/slice/registre.py`, `PHASE3/slice/provider_manifest.py`, `PHASE3/slice/mission.py`
- `PHASE3/interface/api.py` — routes read-only `GET /api/missions` (paginé, `items` toujours présent) et `GET /api/missions/{mission_id}` ; toute la projection déléguée à `slice/mission_history.py`
- `PHASE3/analyser.py`, `PHASE3/dogfooding/lancer.py`
- `PHASE3/test_slice.py`, `PHASE3/test_interface.py`, `PHASE3/test_bundle.py`

## 3. Résultats réels — exécution du 2026-08-31

Environnement : Python 3.11.2 ; `pyyaml` 6.0.3 installé dans `/home/user/.venv-agnt` (le Python système est PEP 668 *externally-managed*, `import yaml` y échoue — sans ce venv, 2 suites ne démarrent même pas).

### Les 3 suites demandées

| Suite | Classement | Résultat | Sortie |
|---|---|---|---|
| `PHASE3/test_mission_history_api.py` | **PASS** | exit 0 | `33/33 cas vérifiés` |
| `PHASE3/test_transports.py` | **PASS** | exit 0 | `12/12 cas vérifiés` |
| `PHASE3/test_observabilite.py` | **PASS** | exit 0 | `7/7 cas vérifiés` |

Chemins de code réellement exécutés (pas une réimplémentation) :
- History : HTTP réel → `interface/api.py::_missions` / détail → `mission_history.lire_journal` / `statut_mission` ; cas 13/13b/13c prouvent `unavailable` / `echoue` / `non_autorise` **jamais ramenés à zéro finding** ; cas 14 prouve `fuites=[]` (aucun chemin, secret, argv, stack trace publié) ; cas 15/15b/15c/15d refusent traversal, identifiant hostile encodé et symlink sortant (404, et absent du listing) ; cas 16/16b `mission_id` + `detail_href` additifs avec détail 200 ; cas 17 mission sans journal → `inconnu`, jamais `termine`.
- Transport : délégation réelle `transports.deleguer()` vers un transport enregistré (`RESULTAT-MCP`) ; transport non enregistré → **refus explicite, aucun repli sous-processus** ; `enregistrer('sandbox_cli')` refusé (nom réservé au cœur).
- Observabilité : le journal nomme **qui** a tranché (`moteur='deterministe'`), un refus consigne l'intention et son motif, et la sélection porte un motif par capacité nommant les providers **écartés** (réponse à « pourquoi pas l'autre »).

### Régressions sur les autres suites touchées par ces 11 commits

| Suite | Classement | Résultat |
|---|---|---|
| `PHASE3/test_cibles.py` | **PASS** | exit 0 — `33/33 cas vérifiés` (dont déterminisme : empreinte de plan identique sur 2 exécutions) |
| `PHASE3/test_multi_mission.py` | **PASS** | exit 0 — `11/11 cas vérifiés` |
| `PHASE3/test_isolation_mission.py` | **PASS** | exit 0 — `8/8 cas vérifiés` |
| `PHASE3/test_interface.py` | **PASS** | exit 0 — `34/35 · 0 en échec · 1 non évaluées` |
| `PHASE3/test_slice.py` | **BLOCKED** | exit 1 — `policy.PolicyError: binaire OPA introuvable` (échoue à la ligne de construction du moteur, avant tout cas) |
| `PHASE3/test_bundle.py` | **BLOCKED** | exit 1 — « aucun bundle produit » → cas conservation non examiné |

**Les 2 BLOCKED ne sont pas des régressions de cette ligne.** Rejoués sur la base `4433af6` via worktree `/tmp/base4433` : mêmes échecs, mêmes messages, mêmes exit 1. `test_interface.py` donne aussi `34/35 · 1 non évaluées` sur la base → le NON ÉVALUÉ est antérieur.

### NON ÉVALUÉ

- `test_slice.py` et `test_bundle.py` dans leur ensemble : la policy OPA réelle n'est pas évaluable ici (voir Blocages). Aucun cas de ces deux suites n'a produit de verdict.
- 1 vérification de `test_interface.py` (antérieure à cette ligne).

## 4. Blocages (environnement, pas des bugs AGNT)

- **OPA absent.** Tentative réelle d'installation : `openpolicyagent.org` → `curl: (35) SSL_ERROR_SYSCALL` ; miroir GitHub `release-assets.githubusercontent.com` → même erreur ; `pip index versions opa` → `No matching distribution found`. Égress limité à `pypi.org` (200) et `github.com` (200). Aucun fichier partiel laissé (`~/.cache/arena_secops/bin/opa` supprimé).
- **`bwrap` absent** (`command -v bwrap` → vide) → exécution réellement sandboxée non évaluable. Note : la mémoire décrivait « bwrap présent mais userns refusés » ; dans ce sandbox il est absent, et `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` est `n/a`.
- Conséquence : tout ce qui exige policy réelle ou sandbox réelle reste **NON ÉVALUÉ**, pas PASS et pas FAIL.

## 5. Périmètre non touché (volontairement)

- Aucun nouveau code sur la base `4433af6` : cet enregistrement est le seul ajout, docs uniquement.
- `PHASE3/slice/transports.py` est le module CORE canonique attendu par MCP-004 ; **aucun** transport MCP concret n'a été ajouté (domaine MCP).
- Sandbox/policy/isolation durcie, mode laboratoire : non touchés (domaine SECURITY).
- `index.html` / `app.js` / `style.css` : non touchés (domaine WEB).
- Aucun contrat HTTP public modifié : `/api/missions` et `/api/missions/{id}` sont **additifs** (`mission_id`, `detail_href`), `items` toujours présent.

## 6. À traiter à l'intégration

1. **PR #2 avant tout** : cette ligne recoupe PR #2 sur `PHASE3/slice/pipeline.py`, `PHASE3/slice/adapters.py`, `PHASE3/slice/plan.py`, `PHASE3/analyser.py`, `PHASE3/slice/provider_manifest.py`. Re-alignment à faire après merge de PR #2 dans `main`.
2. Gates Product + Security à rejouer sur l'API intégrée réelle (les endpoints History sont **candidats, non certifiés** contre les fichiers Product).
3. MCP-004 : supprimer la duplication `transports.py` de la branche MCP au profit du module canonique (dispatch `enregistrer/fournit/connus/deleguer`, fail-closed).
4. CORE-005 reste ouvert : contrat Transport recevant `Cible` distante.

## 7. Confiance

- **Haute** sur les 3 suites demandées + `test_cibles` / `test_multi_mission` / `test_isolation_mission` / `test_interface` : sorties lues, exit codes capturés, chemins de code nommés.
- **Haute** sur la non-régression de `test_slice` / `test_bundle` : comparaison explicite avec la base `4433af6`.
- **Nulle** sur la policy OPA réelle et la sandbox réelle : non exécutées ici.

=== END AGNT HANDOFF ===
