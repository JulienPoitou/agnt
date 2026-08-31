# AGNT — PROJECT STATE (mémoire de coordination)

> **Mainteneur :** orchestrateur AGNT (session `arena/01a05783-agnt`, reprise 31/08).
> **But :** décisions, contrats, état des builders, dépendances, conflits, ordre d'intégration — utiles entre les handoffs. Synthèse vivante, pas un journal. Les commits et handoffs restent les preuves détaillées.
> **Historique :** reprend et met à jour `AGNT_PROJECT_STATE.md` (30/08, branche `arena/01a0543a-agnt@aafe5af`). Ce fichier est désormais l'unique source de vérité de coordination ; `AGNT_PROJECT_STATE.md` est un pointeur.

**Dernière mise à jour :** 2026-08-31 — reprise `arena/01a05783-agnt` : PR #2 fusionnée dans `main` ET vérifiée, **ligne CORE intégrée dans main (PR #6, `2010f38`)**, double gate feu vert, perte WEB déclarée.
**Base d'intégration connue :** `main` = `2010f38` = `b85bc91` (PR #2) + ligne CORE (`3aeb8bc`) + résolutions d'intégration + harnais alignés.
**Ligne la plus avancée :** `main` (`2010f38`) — voir Topologie.

---

## INCIDENT BOOTSTRAP 31/08 — RÉSOLU (à connaître avant tout diagnostic sandbox)

**Symptôme :** sessions builder (p.ex. `arena/01a0575c-agnt`, CORE) — TOUT appel d'outil échoue avant exécution (`duration_ms: 0`) : `git clone failed … error: Your local changes … would be overwritten by checkout: docs/coordination/prompts/Builder-Core.md`.
**Cause racine (CONFIRMÉE par reproduction sur clone vierge) :** le `.gitattributes` du 30/08 a posé la politique `eol=lf` **sans renormaliser les blobs** ; les 2 prompts commis en CRLF produisaient un diff fantôme dès l'extraction, et le `checkout <SHA>` du bootstrap refusait. Aucun lien avec le code AGNT ni avec la session elle-même.
**Correctif (landé via PR #3) :** blobs des 2 prompts renormalisés en LF (contenu identique hors CR, vérifié `--ignore-cr-at-eol` vide) ; `.gitattributes` d'origine (41 lignes) restauré à l'identique ; worktree propre après clone. Vérifié : clone vierge → status vide → `checkout 4433af6` SUCCESS.
**Leçon :** une politique d'attributs sans migration des blobs existants = dette immédiate. Toute évolution `.gitattributes` ⇒ `git add --renormalize .` + vérification du statut post-clone.
**Note :** un builder a déclaré `builder-web` inexistante — faux (préfixe `arena/` omis) ; les 6 branches `arena/builder-*` existent à `4433af6`.

---

## Règles de coordination

- Pas d'audit global du dépôt à chaque événement ; vérification ciblée seulement si elle peut changer une décision.
- Confiance aux rapports builders par défaut ; classer toute information en CONFIRMÉ / DÉCLARÉ / HYPOTHÈSE. `DONE` = terminé **et** vérifié au niveau de son risque.
- Les builders construisent sur leurs branches ; l'orchestrateur décide les intégrations. Jamais de merge builder↔builder, jamais de merge aveugle.
- Ne pas recréer une fonctionnalité marquée terminée ; tout nouveau contrat partagé est ajouté ici avec ses consommateurs.
- Fin de mission = bloc `=== AGNT HANDOFF v1 ===`…`=== END AGNT HANDOFF ===` (agent, domaine, branche, statut, commits, livrables, tests PASS/FAIL/BLOCKED/NON ÉVALUÉ, blocages, périmètre non touché, confiance). Mission en cours = `=== AGNT PROGRESS v1 ===`.
- Citer le SHA immuable et le domaine avant le nom de branche (un nom de branche n'est pas une preuve).
- **Ne pas confondre** bug réel / dette / limitation environnementale / test obsolète / choix volontaire / fonctionnalité manquante.

---

## TOPOLOGIE GIT (révisée 31/08 après-midi — CONFIRMÉ par git ls-remote + fetch complet)

```
(fusion PR#1, 30/08) 4433af6 ──┬─ main 2010f38 (31/08 soir) = 4433af6 + PR#2 (LOT 1 E2E + LOT 3 plugins)
                               │            + ligne CORE intégrée (PR #6, arbre identique à l'arbre testé)
                               ├─ PR #2 : a1520d2 (01a052a5-agnt)  → MERGED dans main (b85bc91)
                               ├─ CORE    arena/01a05415-agnt  (11 commits, tip eebefbc)
                               │         └─ reprise arena/01a0575c-agnt → tip 3aeb8bc (handoff v1 enregistré, pushé)
                               ├─ MCP     arena/01a05417-agnt  ( 5 commits, tip 6e04ff8)
                               │         └─ reprise arena/01a05760-agnt → tip 451de79 (handoff v1 + réparation garde, pushé)
                               ├─ WEB     arena/01a0541a-agnt  ( 2 commits docs, tip 3268641) — voir « PERTE WEB » ci-dessous
                               ├─ PRODUCT arena/01a05425-agnt  ( 5 commits, tip 3f96e25)
                               ├─ SECURITY arena/01a05426-agnt ( 5 commits, tip 08a8150) — PAS de handoff v1
                               ├─ DEVOPS  arena/01a0543a-agnt  (24 commits docs, tip aafe5af)
                               └─ arena/builder-{core,mcp,web,security,product,devops} : 6 branches à 4433af6 (sessions à venir)
```

Faits critiques (tous revérifiés 31/08 après-midi, `arena/01a05783-agnt`) :
1. **PR #2 est FUSIONNÉE dans main** (`b85bc91`, merge 11:01:17Z). Le diff de la fusion = exactement le diff de PR #2 (30 fichiers, +1113/−162) — GitHub n'a rien « arrangé ». C'était l'action 1 des « Intégrations prévues » : elle est FAITE. Preuve minimale exécutée après coup sur l'arbre fusionné (voir « VÉRIFICATION main »).
2. L'historique de `main` reste squashé ; les SHA cités dans `PROJET_ETAT.md` (`f400fe6`, `8c89916`, `53ab18b`…) ne sont pas résolubles localement — s'y référer par le récit, pas par SHA.
3. **Aucun travail builder n'est dans main** : `PHASE3/slice` de main ne contient ni `cible.py`, ni `transports.py`, ni `mission_history.py`, ni les modules MCP. Toutes les lignes builders sont basées sur `4433af6` (pré-LOT) et doivent se re-aligner sur `b85bc91`.
4. **Recouvrements mesurés par merge-tree (dry-run sur main)** : CORE → 3 conflits (`analyser.py`, `slice/pipeline.py`, `slice/plan.py`) ; MCP → 1 conflit (`slice/statuts.py`) ; SECURITY → 3 conflits (`test_manifest.py`, `test_niveau2.py`, `test_utilisation.py`) ; PRODUCT → 1 conflit (`interface/app.js`). Après l'atterrissage de CORE, MCP et SECURITY devront re-aligner une seconde fois (`pipeline.py`, `transports.py`, `interface/api.py`).

## VÉRIFICATION main (31/08 après-midi — CONFIRMÉ par exécution, session `arena/01a05783-agnt`)

Environnement : Python 3.11.2 + venv `/tmp/agnt-venv` (pyyaml 6.0.3), `PYTHONPATH=PHASE3/slice`. binaires absents (OPA, bwrap, radon, bandit, semgrep, gitleaks) — mêmes limites que dans toute la mémoire.

| Vérification | Résultat |
|---|---|
| `python -m compileall -q PHASE3` | **PASS** (rc 0, tout l'arbre fusionné compile) |
| `test_chemins.py` | **PASS** 48/48 · 3 non évalués |
| `test_selection.py` | **PASS** 13/13 |
| `test_adversaire.py` | **46 cas · 40 PASS · 2 FAIL · 4 NON ÉVALUÉS** — voir note E7 |
| `test_plugins / catalogue_outils / vague_parallele / conditions_outils / intentions` | **BLOCKED environnement** (radon, bandit, semgrep, OPA absents) — identiques aux blocages documentés, aucune non-régression mesurable par ces suites |

**Note E7 (pas une régression, un changement de comportement assumé de PR #2) :** sur `4433af6` la campagne donne 41 PASS / 2 FAIL / 3 NON ÉVALUÉS (contrôle rejoué en worktree détaché — CONFIRMÉ). Sur main, **E7** (« isolateur inutilisable : arrêt consigné ») passe de PASS à NON ÉVALUÉ : PR #2 introduit la dimension *disponibilité* jugée AVANT l'exécution — la mission avorte sur `motif: disponibilite` (semgrep absent) avant que le chemin « isolateur inutilisable » puisse être exercé. Le cas se déclare honnêtement NON ÉVALUÉ (« ne peut pas le simuler ») au lieu de voler un PASS. Classification : **choix volontaire de PR #2 qui rend E7 non exercable dans un environnement sans outils installés** — le cas redeviendrait jugeable après `bootstrap.sh` + isolateur cassé. À garder en tête aux gates, pas à corriger maintenant.
Les 2 FAIL (D4 `cible_autorisee`, G6a règles gitleaks) sont **identiques à la base** et appartiennent à SECURITY (`d1d562f`, `e5838003`) — non absorbés par main.

---

## BUILDERS

| Builder | Branche de travail réelle | Nouvelle session | Statut | Dernier commit connu | Débloque |
|---|---|---|---|---|---|
| CORE | `arena/01a05415-agnt` + reprise `arena/01a0575c-agnt` | `arena/builder-core` | **INTÉGRÉ DANS main** (PR #6 → `2010f38`, 31/08) — batterie verte, double gate feu vert, défaut d'ombrage `cible` corrigé ; handoff : `docs/coordination/handoffs/INTEGRATION-CORE-2026-08-31.md` | `3aeb8bc` | MCP-004 (raccord transport), WEB (API réelle) |
| MCP | `arena/01a05417-agnt` + reprise `arena/01a05760-agnt` | `arena/builder-mcp` | `READY_FOR_INTEGRATION` — **CONFIRMÉ par exécution** (handoff v1 reçu : `451de79` → `PHASE3/STATUT_MCP.md`) ; batterie 104/104 + garde adversariale réparée (`59252df`) | `451de79` | — (raccord Transport à l'intégration, MCP-004) |
| WEB | `arena/01a0541a-agnt` | `arena/builder-web` | **PERTE DÉCLARÉE** — carte d'adoption récupérable (`3268641`, docs) ; **20 prototypes UI : PERDUS / NOT RECOVERABLE** (0 commit, 0 push vérifié GitHub ; rien dans le sandbox de reprise) | `3268641` | — |
| SECURITY | `arena/01a05426-agnt` | `arena/builder-security` | `READY_FOR_INTEGRATION` (DÉCLARÉ) mais **PAS de handoff v1** — intégration gelée tant que le protocole n'est pas rempli | `08a8150` | STRAT-001 (labo Strix) |
| PRODUCT | `arena/01a05425-agnt` | `arena/builder-product` | `READY_FOR_INTEGRATION` — 3 contrats versionnés + gate black-box livrés (`3f96e25`) ; certification en attente de l'API CORE réelle | `3f96e25` | WEB (feu vert) |
| DEVOPS | reconnaissance sur `arena/01a0543a-agnt` (docs) | `arena/builder-devops` | implémentation `NOT_STARTED` — 40 suites réconciliées (DÉCLARÉ) ; toute implémentation (bootstrap/doctor/CI/pins) exige l'accord explicite du propriétaire | `aafe5af` | CORE-003, MCP-001, DEVOPS-002 |

Règle reprise : un builder qui reprend sur sa nouvelle branche session doit repartir de son tip précédent (SHA ci-dessus), pas de zéro.

---

## ARCHITECTURE — décisions actives (invariants à préserver)

| Décision | Conséquence |
|---|---|
| Provider ≠ Transport | Un provider décrit *quoi* ; un transport *comment*. Un provider n'est pas implicitement un binaire local. |
| Registre AGNT = autorité | Capability/provider/serveur/outil/arguments/conditions viennent du registre ; ni LLM ni serveur externe n'étendent les permissions. |
| Transport fail-closed | `sandbox_cli` fourni par le cœur ; un transport tiers doit être enregistré avant le chargement du manifest qui le déclare. Aucun fallback CLI local silencieux. |
| `LLM → Plan typé → OPA → Executor déterministe → Sandbox → Tools` | Le plan déclaratif est la frontière de sécurité ; `AI → SHELL` impossible par construction. |
| État par mission | Artefacts bruts dans `<mission>/run` ; jamais de `PHASE3/run` global. |
| Intention locale à l'appel | `moteur_intent`/`fournisseur_llm` passés à `pipeline.executer()` ; globales = repli compat seulement. |
| Journal append-only | Porte au minimum intention + sélection de providers ; ne dépend pas de `plan.json` seul. |
| Policy avant invocation | Policy absente/indisponible/refusée ⇒ jamais d'exécution (locale ou externe). |
| Cible distincte du sandbox | `Cible(type, reference, chemin_local=None)` canonique ; cible distante jamais `Path`, jamais `sandbox_cli`, filtrée à l'applicabilité. |
| Pas de faux état produit | API répond sans mission ⇒ accueil réel, jamais de démo. |
| Progressive disclosure + rendu sûr | Résultat métier d'abord ; `textContent` jamais `innerHTML` pour données non fiables. |
| Dimensions de statut séparées | Applicabilité/sélection/condition/autorisation/disponibilité/exécution/détection/complétude distinctes ; aucune absence ne devient `rien_trouve` ou zéro. |
| Product détient la forme API History | Schémas `agnt.history.v1` / `agnt.timeline.v1` / `agnt.execution-status.v1` = autorité ; le gate Security complète, jamais un dialecte concurrent. |
| Provenance MCP : faits puis projection | MCP détient les faits transport/protocole ; CORE projette en forme Product ; Security valide l'exposition. |
| Autorisation de cible explicite | `cible_autorisee` : seul `True` explicite arme ; l'API dérive exclusivement de `cibles_admises()`. |
| Règles scanners contrôlées | Jamais de config chargée depuis le dépôt analysé ; source AGNT de confiance, lecture seule, vérifiée. |
| Mode laboratoire ≠ bypass | Facilite des tests sur cibles contrôlées ; ne désactive jamais sandbox/policy/intégrité/redaction ; activable ni par LLM ni par API. |
| Agents Pentest tiers = composant borné, pas étiquette | Jamais un second orchestrateur. Strix = seul candidat pilote ultérieur, après gates. |
| DevOps : sources/périmètre immuables | Une reconnaissance ne change ni pin ni source sans instruction propriétaire. |
| **Vision produit multi-usage** | Les usages INVESTIGATE / VALIDATE / DEFEND / « ATTACK » restent **bornés par la contrainte gelée « agent passif, pas un outil offensif »** : « attack » ne peut exister que comme mode laboratoire propriétaire contrôlé (SEC-LAB), jamais comme scan d'attaque automatisé. Décision propriétaire requise si cette frontière doit bouger. |

---

## CONTRATS À RESPECTER (consommateurs entre parenthèses)

- **Transport MCP** (CORE↔MCP) : `transports.enregistrer("mcp", executeur)` avec `executeur(provider, sandbox) -> ResultatBrut` ; enregistrement avant chargement du registre ; dispatch canonique via `transports.deleguer`. La variante MCP locale `obtenir` est **provisoire** et ne doit pas survivre à l'intégration (MCP-004). `tools/list` informatif, jamais une autorité.
- **Cible** (CORE→MCP/SECURITY/PRODUCT) : `Cible(type, reference, chemin_local=None)`, `Cible.normaliser(...)`, `to_dict()` sans userinfo. Types locaux effectifs : `repository`, `filesystem` ; `url` représentable mais aucun transport ne la reçoit — évolution conjointe CORE/MCP/SECURITY requise (CORE-005).
- **History `agnt.history.v1`** (PRODUCT→CORE/WEB/SECURITY) : Mission 1→0..1 Run ; `mission_id` persistant ≠ id de soumission `POST /api/runs` ; `GET /api/missions`, `GET /api/missions/{mission_id}` ; statuts `en_file/en_cours/termine/refuse/erreur/inconnu` ; liste vide = HTTP 200 `items: []` ; zéro affichable seulement si artefact findings le prouve, sinon `missing_artifacts`.
- **Timeline `agnt.timeline.v1`** : projection read-only du journal sous `data.timeline` ; `seq` définit ordre+identité ; `data.events` reste fallback legacy ; WEB ne fusionne jamais les deux ; provenance MCP additive/allowlistée/redacted.
- **Execution status `agnt.execution-status.v1`** : enrichit `data.executions[]` sans toucher aux statuts Mission ; `rien_trouve`/`findings_count: 0` exigent preuve complète ; `timed_out/cancelled/unavailable/echoue/refus` jamais zéro ; contradiction ⇒ `conflict`.
- **Autorisation de cible** (SECURITY→CORE/MCP) : `pipeline.executer(..., cible_autorisee=None)` refus ; jamais d'influence client sur ce booléen.
- **Endpoints lecture seule CORE candidats** : livrés dans `eebefbc` (`mission_history.py` unique lecteur, pagination opaque, filtres `status`/`target_type`, projection redacted, refus traversal/symlink) — **candidats, non certifiés** contre les fichiers Product réels.

---

## DÉPENDANCES

```
CORE : Provider / Transport / Cible / artefacts par mission / lecteur History
  ├── MCP    : transport "mcp", normalisation findings, provenance   [raccord à l'intégration]
  ├── WEB    : consomme /api/missions + timeline + provenance        [BLOQUÉ par double gate]
  ├── SECURITY : autorisation cible, egress/policy/secrets, gates    [gate à rejouer sur API réelle]
  └── PRODUCT  : contrats de forme History/Timeline/Status + gate    [gate à exécuter vs CORE]

Ordre : PR#2 → main ✅ (FAIT, b85bc91)  →  re-align CORE sur main  →  gates Product+Security sur API réelle
                          →  feu vert WEB  →  raccord MCP Transport (canonique CORE)  →  lots WEB  →  (pilote Strix)
```

---

## FONCTIONNALITÉS / BACKLOG (extrait décisionnel)

| ID | Sujet | Priorité | Statut |
|---|---|---:|---|
| — | **Premier RUN réel E2E navigateur→rapport** | P0 | **DANS main** (`b85bc91`) — fusion vérifiée 31/08 (compileall + suites légères + campagne adversariale : voir « VÉRIFICATION main ») |
| CORE-001 | Cible typée | P1 | Terminé (`8eb4005`, `f1f323d`) — sur la ligne CORE, pas dans main |
| CORE-004/006 | History API + `data.timeline` + `data.executions[]` | P1 | **CONFIRMÉ par exécution** (`3aeb8bc`, handoff v1) : 3 suites demandées PASS (33/33, 12/12, 7/7) + `test_cibles` 33/33, `test_multi_mission` 11/11, `test_isolation_mission` 8/8, `test_interface` 34/35·1 NE ; `test_slice`/`test_bundle` BLOCKED OPA (non-régression prouvée vs base) — reste : re-alignment sur main + gates |
| MCP-004 | Raccord MCP au Transport CORE canonique | P1 intégration | Ouvert — intégration coordonnée |
| MCP-005 | Interop SDK indépendant | P2 | Terminé borné stdio `6e04ff8` ; HTTP/SSE/streaming non prouvés — ne pas réélargir sans besoin |
| GATE-001/002/003 | Gates sur API réelle + captures + corpus hostiles | P1 intégration | Gates livrés (`3f96e25`, `dae445a`) — attente arbre CORE intégré |
| WEB-001/002 | Adoption UI `/api/missions` | P1 | Carte livrée `93f8ead` ; code bloqué par gates |
| SEC-G6a | Config gitleaks contrôlée par AGNT | P1 | Terminé (`e5838003`) |
| SEC-HIST-001 | Gate adversarial History | P1 | Re-lié (`dae445a`) ; à rejouer sur API réelle |
| SEC-LAB-001 | Mode laboratoire propriétaire borné | P1 | **En cours** — `08a8150` P2 admission locale (DÉCLARÉ, gros diff 125 fichiers à vérifier) |
| CORE-005 | Transport recevant Cible (distante) | P1 archi | Ouvert — joint CORE/MCP/SECURITY |
| DEVOPS-001/002 | Matrice suites réconciliée / bootstrap-doctor-CI | P1 env | Réconciliation terminée (DÉCLARÉ) / non commencé, accord propriétaire requis |
| STRAT-001 | Pilote Strix en labo | P2 | Différé — après SEC-LAB + double gate |
| CORE-002 / PRODUCT-002 / SEC-B6/B7 | Graphe d'exécution, comparaison de runs, durcissements | P2/P3 | Différés |

---

## CONFLITS

1. **[RÉSOLU 31/08] PR #2 ↔ branches builders sur le cœur.** PR #2 a été fusionnée dans main **en premier** (`b85bc91`), conformément à la résolution décidée. Reste le re-alignment builder par builder sur le nouveau main — conflits mesurés par merge-tree (voir Faits critiques §4), traités un par un, jamais en bloc.
2. **[P1 — API différente] MCP réimplémente `transports.py`** avec un dispatch différent (`obtenir` vs `enregistrer/fournit/connus/deleguer`). Résolution décidée : module CORE canonique gagne ; garder `mcp_bootstrap.initialiser_mcp` + tests E2E ; rejouer la batterie MCP sur l'arbre intégré. Pas de merge builder↔builder.
3. **[P1 — NOUVEAU, mesuré] `cible_type="repository"` en dur (ligne MCP).** `pipeline.py` de la ligne MCP passe `cible_type="repository"` à `moteur.evaluer()` (l. 531, l. 662) alors que le type réel est dérivé par provider dans `_vague` (`repository` **ou** `filesystem`). Une règle OPA distinguant les deux recevrait un fait faux. La réparation `59252df` n'a aligné que les doubles de test ; le code de production garde le littéral. **Résolution décidée :** lors du re-alignment MCP sur l'arbre CORE intégré, dériver le type depuis la `Cible`/`_vague` réels (pas de littéral) — fait partie du raccord MCP-004/CORE-005. Ne pas corriger isolément maintenant (contrat CORE). C'est l'exemple concret de la vigilance « ne pas devenir repository-specific » : le registre déclare déjà des providers `filesystem`.
4. **[P1] WEB/PRODUCT sur l'interface partagée** (`index.html`, `app.js`, `style.css`). Résolu par la carte d'adoption WEB (7 lots, portes Q1–Q10, 6 conflits documentés dont id de soumission ≠ `mission_id` sur refus). Le conflit PRODUCT→main mesuré (`interface/app.js`) est le reflet attendu de ce dossier. Pas de seconde refonte UI.
5. **[RÉSOLU 31/08] Nommage de la mémoire** : `AGNT_PROJECT_STATE.md` (ancien, référencé par le guide `prompts/question`) vs `PROJECT_STATE.md` (charte orchestrateur). Une seule source de vérité : `PROJECT_STATE.md` ; l'ancien nom devient un pointeur.
6. **[OUVERT — décision propriétaire] Vision multi-modes (ATTACK…) vs contrainte « agent passif ».** Recommandation : « attack » = usage en mode laboratoire propriétaire borné (SEC-LAB-001), pas un scanner d'attaque. Ne pas relâcher la contrainte sans décision explicite du propriétaire.

---

## BLOQUANTS

- **[RÉSOLU 31/08] Bootstrap sessions builder** : voir « INCIDENT BOOTSTRAP » en tête.
- **[NOUVEAU — perte] Prototypes WEB (override propriétaire « 20 prototypes »)** : **PERDUS / NOT RECOVERABLE**. Aucune branche, aucun commit, aucune PR, aucun fichier dans le sandbox de reprise (`/home/user` ne contient que le clone `agnt/`). Ne pas reconstruire l'interface maintenant : le blocage gate reste en vigueur et la carte d'adoption (`3268641`) suffit pour préparer la suite. Reprise UI à décider avec le propriétaire après le feu vert WEB.
- **[NOUVEAU] Handoff SECURITY manquant** : la ligne SECURITY (`08a8150`, 125 fichiers) n'a aucun bloc `AGNT HANDOFF v1` — vérifié sur toute la branche. Intégration gelée jusqu'à production du handoff (voir protocole ci-dessous).
- **Environnement (NON-BUGS documentés)** : binaire OPA absent (policy réelle non évaluée) ; `bwrap` absent dans ce sandbox (userns n/a) ; binaires/caches de scan absents ; gitleaks réel absent (SEC-G9 non mesurable) ; pas de réseau pour LLM réel ; `bandit/checkov/detect-secrets/radon/semgrep` absents. Baseline DevOps réconciliée : ~20 PASS / 16 FAIL environnementaux / 1 NON ÉVALUÉ. Re-vérifié 31/08 : `test_plugins`, `catalogue_outils`, `vague_parallele`, `conditions_outils`, `intentions` restent bloqués sur ces absences, à l'identique de la base.
- **DEVOPS-002** : toute implémentation (venvs, doctor, CI, pins, armement gitleaks) attend l'accord explicite du propriétaire.
- **WEB** : code UI bloqué jusqu'au passage des gates Product + Security sur une API CORE réellement intégrée.
- **Support cible distante** (`url`) : bloqué par CORE-005 (contrat Transport recevant `Cible`).

---

## RISQUES

| Risque | Gravité | Réponse |
|---|---:|---|
| Base d'intégration divergente (builders sur 4433af6, main en avance) | **Haute** | ✅ PR #2 mergée ; re-alignment builders un par un, CORE d'abord (3 conflits mesurés), puis MCP/SECURITY/PRODUCT |
| Diff SECURITY `08a8150` anormalement large (125 fichiers, +12623) — périmètre à vérifier avant intégration | Haute | Handoff SECURITY exigé (protocole) ; vérifier qu'il ne touche pas le cœur hors de son domaine |
| Alignement CORE History non certifié contre les fichiers Product réels | Haute | Gates Product+Security sur arbre intégré avant tout feu vert WEB |
| `cible_type="repository"` en dur → fait OPA faux pour cibles `filesystem` | Haute sécurité | Correction à l'intégration MCP-004/CORE-005 (dériver le type réel) ; garde adversariale déjà réparée (`59252df`) |
| Historique main squashé — SHAs anciens introuvables | Moyenne | S'appuyer sur `PROJET_ETAT.md` (récit) + SHAs listés ici |
| Perte de l'autorisation explicite de cible lors des évolutions CORE/MCP | Haute sécurité | Tests de régression Security préservés ; invariants ci-dessus |
| Un « bypass » générique deviendrait une backdoor | Haute sécurité | Mode laboratoire borné uniquement (SEC-LAB-001), local, audité, double opt-in |
| Serveur MCP externe hors sandbox locale présenté comme sandboxé | Haute | Contrôles Security + provenance ; jamais présenter comme sandboxé |

---

## INTÉGRATIONS PRÉVUES (ordre révisé 31/08 soir)

1. ~~**PR #2 → main**~~ ✅ **FAIT** (`b85bc91`) + preuve minimale exécutée après coup.
2. ~~**Re-align CORE sur main**~~ ✅ **FAIT** (orchestrateur, session `arena/01a05783-agnt`) : 3 conflits résolus (union des dimensions disponibilité + descripteur de cible ; invariant « état par mission » + politique de conservation unique) ; défaut d'ombrage `cible` de la ligne CORE corrigé ; batterie verte (voir handoff `INTEGRATION-CORE-2026-08-31.md`). PR vers main à ouvrir après les gates.
3. **Gates sur API intégrée réelle** ✅ **EXÉCUTÉS (31/08, serveur sur l'arbre intégré)** : Product `3470 PASS · 0 FAIL · 1 SKIP` (SKIP = états sémantiques non produisibles sans outils ; preuve submission_id ≠ mission_id incluse) ; Security `26/26 PASS` (liste + détails, y compris mission refusée ; harnais du gate 46/46). → **feu vert gates sur l'arbre intégré** (rejeu à refaire sur main après merge, sans changer les verdicts attendus).
4. ~~**PR CORE → main**~~ ✅ **FAIT** (PR #6 → `2010f38` ; arbre de main identique à l'arbre testé, compile + History API 33/33 + transports 12/12 + cibles 33/33 rejoués sur main). Suit : **raccord CORE+MCP Transport** (MCP-004) : re-align MCP sur le nouveau main (attendre des re-confits sur `pipeline.py`/`transports.py`) ; supprimer `transports.py` MCP provisoire au profit du canonique ; corriger `cible_type="repository"` en dur (dériver le type réel) ; rejouer les 104 cas MCP.
5. **Lots WEB** selon la carte `3268641`, après double feu vert (prototypes perdus — reconstruction décidée avec le propriétaire, pas en l'état des 20 prototypes).
6. **SEC-LAB-001** : handoff v1 exigé d'abord (protocole), puis revue du périmètre 125 fichiers et audit ; ensuite seulement STRAT-001 (Strix) sur décision propriétaire.
7. **DEVOPS-002** dès accord propriétaire.

---

## PROCHAINES ACTIONS

| # | Qui | Action |
|---|---|---|
| 0 | ~~ORCHESTRATEUR~~ | ~~Incident bootstrap~~ **FAIT** (PR #3). ~~Merger PR #2 + vérifier~~ **FAIT**. ~~Mémoire~~ **FAIT** (PR #5). ~~Re-align CORE + batterie~~ **FAIT**. ~~Gates~~ **FAIT** (3470 PASS / 0 FAIL ; 26/26). ~~PR CORE → main~~ **FAIT** (PR #6 → `2010f38`). Reste : MCP-004, rejeu gates sur main, puis WEB. |
| 1 | MCP (reprise `arena/builder-mcp`) | Re-alignment sur `main 2010f38` : supprimer `transports.py` provisoire (canonique CORE gagne), brancher `mcp_bootstrap` sur le registre réel, corriger `cible_type` dur, rejouer les 104 cas + campagne adversariale, handoff v1. **Le brief « P0 Provider abstraction » reste SUSPENDU.** |
| 2 | PRODUCT | Vérifier les verdicts du gate sur l'arbre intégré ; certifier ou lister les écarts par contrat `agnt.history.v1`/`timeline.v1`/`execution-status.v1`. |
| 3 | SECURITY | **Produire le handoff v1 de `08a8150`** (protocole ci-dessous : périmètre 125 fichiers justifié, invariants labo, tests labo, non-bypass, périmètre non touché). Puis préparer le rejeu du gate History (`dae445a`) sur l'API intégrée. |
| 4 | MCP (reprise `arena/builder-mcp`) | **STOP jusqu'à l'atterrissage CORE.** Le brief « P0 Provider abstraction » reste SUSPENDU (contredit Provider/Transport CORE + MCP-004). Ensuite : re-align sur l'arbre CORE intégré, supprimer `transports.py` provisoire, corriger `cible_type` dur (dériver le type réel), rejouer les 104 cas. |
| 5 | WEB | Rien à construire maintenant : prototypes perdus (décision propriétaire requise pour la suite) et blocage gates en vigueur. La carte `3268641` reste le plan de reprise UI. |
| 6 | DEVOPS | Rien sans accord propriétaire. |

---

## PROTOCOLE HANDOFF v1 — exigences minimales et conformité (révisé 31/08)

Un builder n'est **jamais** considéré terminé sur le seul mot `DONE`. Minimum exigé (déjà dans les Règles) :

```text
agent · domaine · branche (nom + SHA immuable du tip) · statut ·
commits (liste SHA+sujet) · livrables (fichiers) ·
tests classés PASS / FAIL / BLOCKED / NON ÉVALUÉ (avec sorties et codes réels) ·
blocages · périmètre non touché · confiance par zone
```

Conventions de lieu et de conformité :

1. **Emplacement canonique :** `docs/coordination/handoffs/<AGENT>-<SHA>-<AAAA-MM-JJ>.md` (CORE l'a suivi : `CORE-eebefbc-2026-08-31.md`). MCP a embarqué son bloc dans `PHASE3/STATUT_MCP.md` — accepté à titre exceptionnel, enregistré ici ; les prochains handoffs vont au lieu canonique.
2. **Pas d'intégration sans handoff v1** (ou dérogation explicite pour les lignes docs-only, ex. WEB carte). Conséquence immédiate : la ligne SECURITY est gelée tant que le handoff `08a8150` n'existe pas.
3. **Un `DONE` sans preuve reproductible est un DÉCLARÉ**, pas un CONFIRMÉ — le classement CONFIRMÉ/DÉCLARÉ/HYPOTHÈSE s'applique aussi aux rapports de fin.
4. **Non-conformité connue au 31/08 :** SECURITY (aucun bloc v1 sur la branche). CORE et MCP sont conformes. WEB/PRODUCT/DEVOPS : lignes docs, tolérées.

---

## SOURCES

- `AGNT_PROJECT_STATE.md@aafe5af` (mémoire précédente, 30/08) — absorbée par ce fichier.
- `PROJET_ETAT.md`, `CONTEXTE_PROJET.md` (contraintes non négociables), `PHASE3/CONTRAT_PUBLIC.md`.
- Handoffs : `docs/coordination/handoffs/CORE-eebefbc-2026-08-31.md` (`3aeb8bc`), `PHASE3/STATUT_MCP.md` (`451de79`).
- GitHub au 31/08 après-midi : PR #1, #2, #3, #4 toutes MERGED ; aucune PR ouverte ; `git ls-remote` + fetch complet des 20 refs ; dry-runs `git merge-tree --write-tree` par ligne builder.
