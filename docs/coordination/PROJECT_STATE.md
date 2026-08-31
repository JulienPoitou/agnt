# AGNT — PROJECT STATE (mémoire de coordination)

> **Mainteneur :** orchestrateur AGNT (session `arena/01a0575d-agnt`).
> **But :** décisions, contrats, état des builders, dépendances, conflits, ordre d'intégration — utiles entre les handoffs. Synthèse vivante, pas un journal. Les commits et handoffs restent les preuves détaillées.
> **Historique :** reprend et met à jour `AGNT_PROJECT_STATE.md` (30/08, branche `arena/01a0543a-agnt@aafe5af`). Ce fichier est désormais l'unique source de vérité de coordination ; `AGNT_PROJECT_STATE.md` est un pointeur.

**Dernière mise à jour :** 2026-08-31 (incident bootstrap builder — résolu)
**Base d'intégration connue :** `main` = `563ab9d` + correctif eol (PR #3) ; contenu code = `4433af6`
**Ligne la plus avancée :** PR #2 (`a1520d2`, OUVERTE) — voir Topologie.

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

## TOPOLOGIE GIT (établie le 31/08 — CONFIRMÉ par git ls-remote)

```
(fusion PR#1, 30/08) 4433af6 ──┬─ main 563ab9d (31/08) = 4433af6 + docs/coordination/prompts  ← base actuelle, EN RETARD côté code
                               ├─ PR #2 OUVERTE : a1520d2 (01a052a5-agnt, 30/08)  ← LIGNE LA PLUS AVANCÉE (LOT 1 E2E + LOT 3 plugins, +1113/−162, 30 fichiers)
                               ├─ CORE    arena/01a05415-agnt  (11 commits, tip eebefbc)
                               ├─ MCP     arena/01a05417-agnt  ( 5 commits, tip 6e04ff8)
                               ├─ WEB     arena/01a0541a-agnt  ( 2 commits, tip 93f8ead)
                               ├─ PRODUCT arena/01a05425-agnt  ( 5 commits, tip 3f96e25)
                               ├─ SECURITY arena/01a05426-agnt ( 5 commits, tip 08a8150)
                               ├─ DEVOPS  arena/01a0543a-agnt  (24 commits docs, tip aafe5af — contient l'ancienne mémoire)
                               └─ arena/builder-{core,mcp,web,security,product,devops} : 6 branches VIDES à 4433af6 (nouvelles sessions, aucun travail)
```

Faits critiques :
1. **L'historique de `main` est squashé** (1 commit). Les SHA cités dans `PROJET_ETAT.md` (`f400fe6`, `8c89916`, `53ab18b`…) ne sont pas résolubles localement — s'y référer par le récit, pas par SHA.
2. **PR #2 n'est pas dans main** et son `PROJET_ETAT.md` est plus récent que celui de main (+43 lignes). La fusion 31/08 décrite dans `PROJET_ETAT.md` (PR #1 absorbée par la ligne LOT 1→5) est le contenu de PR #2.
3. PR #2 recoupe les branches builders sur les fichiers du cœur : ∩ CORE 5, ∩ MCP 7, ∩ SECURITY 11, ∩ PRODUCT 1 (`analyser.py`, `slice/pipeline.py`, `slice/adapters.py`, `slice/plan.py`, `app.js`…). → Conflit d'intégration garanti si l'ordre est mal choisi.
4. Les travaux builders de la ronde précédente sont tous basés sur `4433af6` (pré-LOT). Aucun n'est intégré à main.

---

## BUILDERS

| Builder | Branche de travail réelle | Nouvelle session | Statut | Dernier commit connu | Débloque |
|---|---|---|---|---|---|
| CORE | `arena/01a05415-agnt` | `arena/builder-core` | `READY_FOR_INTEGRATION` — P1 History/Timeline/Status **livré candidat** (`eebefbc`, DÉCLARÉ, handoff non reçu) | `eebefbc` | PRODUCT (gate réel), WEB (API) |
| MCP | `arena/01a05417-agnt` | `arena/builder-mcp` | `READY_FOR_INTEGRATION` — interop stdio SDK `mcp==2.1.1` terminée bornée (`6e04ff8`) | `6e04ff8` | — (raccord Transport à l'intégration) |
| WEB | `arena/01a0541a-agnt` | `arena/builder-web` | `BLOCKED` (volontaire) — carte d'adoption livrée (`93f8ead`) ; tout code UI attend la double gate Product+Security | `93f8ead` | — |
| SECURITY | `arena/01a05426-agnt` | `arena/builder-security` | `READY_FOR_INTEGRATION` + SEC-LAB-001 **en cours** — `08a8150` « P2 mode laboratoire propriétaire » (125 fichiers, +12623 — périmètre À VÉRIFIER, postérieur à l'ancienne mémoire) | `08a8150` | STRAT-001 (labo Strix) |
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

Ordre : PR#2 → main  →  CORE History aligné  →  gates Product+Security sur API réelle
                          →  feu vert WEB  →  raccord MCP Transport  →  lots WEB  →  (pilote Strix)
```

---

## FONCTIONNALITÉS / BACKLOG (extrait décisionnel)

| ID | Sujet | Priorité | Statut |
|---|---|---:|---|
| — | **Premier RUN réel E2E navigateur→rapport** | P0 | **PR #2 OUVERTE** — déclarée vérifiée par exécution (6 findings, 1 cluster, egress refusé, RAPPORT.md) ; à merger après re-vérification minimale |
| CORE-001 | Cible typée | P1 | Terminé (`8eb4005`, `f1f323d`) |
| CORE-004/006 | History API + `data.timeline` + `data.executions[]` | P1 | **Livré candidat** `eebefbc` (DÉCLARÉ, +3247/−77, 21 fichiers) — alignement à confirmer, puis gates |
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

1. **[P0 — NOUVEAU] PR #2 ↔ branches builders sur le cœur.** PR #2 modifie `pipeline.py`, `adapters.py`, `analyser.py`, `plan.py`, `provider_manifest.py`, plugins… recouvrant CORE (5 fich.), MCP (7), SECURITY (11), PRODUCT (1). **Résolution recommandée :** merger PR #2 dans main **en premier** (ligne la plus avancée, E2E, orientée produit), puis faire re-baser/re-aligner chaque builder sur le nouveau main. Tout autre ordre multiplie les conflits sur les mêmes fichiers.
2. **[P1] MCP réimplémente `transports.py`** avec un dispatch différent (`obtenir` vs `enregistrer/fournit/connus/deleguer`). Résolution décidée : module CORE canonique gagne ; garder `mcp_bootstrap.initialiser_mcp` + tests E2E ; rejouer la batterie MCP sur l'arbre intégré. Pas de merge builder↔builder.
3. **[P1] WEB/PRODUCT sur l'interface partagée** (`index.html`, `app.js`, `style.css`). Résolu par la carte d'adoption WEB (7 lots, portes Q1–Q10, 6 conflits documentés dont id de soumission ≠ `mission_id` sur refus). Pas de seconde refonte UI.
4. **[RÉSOLU 31/08] Nommage de la mémoire** : `AGNT_PROJECT_STATE.md` (ancien, référencé par le guide `prompts/question`) vs `PROJECT_STATE.md` (charte orchestrateur). Une seule source de vérité : `PROJECT_STATE.md` ; l'ancien nom devient un pointeur.
5. **[OUVERT — décision propriétaire] Vision multi-modes (ATTACK…) vs contrainte « agent passif ».** Recommandation : « attack » = usage en mode laboratoire propriétaire borné (SEC-LAB-001), pas un scanner d'attaque. Ne pas relâcher la contrainte sans décision explicite du propriétaire.

---

## BLOQUANTS

- **[RÉSOLU 31/08] Bootstrap sessions builder** : voir « INCIDENT BOOTSTRAP » en tête. Les sessions bloquées devraient repartir seules (le bootstrap relit main corrigé à chaque appel) — sinon, reset de la session côté Arena (propriétaire). Aucune action builder requise.
- **Environnement (NON-BUGS documentés)** : binaire OPA absent (policy réelle non évaluée) ; `bwrap` présent mais user namespaces refusés (`apparmor_restrict_unprivileged_userns=1`) ; binaires/caches de scan absents (~/.cache) ; gitleaks réel absent (SEC-G9 non mesurable) ; pas de réseau pour LLM réel (`test_llm_reel` exit 2) ; `bandit/checkov/detect-secrets/radon` absents. Baseline DevOps réconciliée : ~20 PASS / 16 FAIL environnementaux / 1 NON ÉVALUÉ.
- **DEVOPS-002** : toute implémentation (venvs, doctor, CI, pins, armement gitleaks) attend l'accord explicite du propriétaire.
- **WEB** : code UI bloqué jusqu'au passage des gates Product + Security sur une API CORE réellement intégrée.
- **Support cible distante** (`url`) : bloqué par CORE-005 (contrat Transport recevant `Cible`).

---

## RISQUES

| Risque | Gravité | Réponse |
|---|---:|---|
| Base d'intégration divergente (main en retard sur PR #2, builders sur 4433af6) | **Haute** | Merge PR #2 d'abord, puis re-alignment builders ; voir Conflit 1 |
| Diff SECURITY `08a8150` anormalement large (125 fichiers, +12623) — périmètre à vérifier avant intégration | Haute | Demander handoff SECURITY ; vérifier qu'il ne touche pas le cœur hors de son domaine |
| Alignement CORE History non certifié contre les fichiers Product réels (absents du checkout CORE) | Haute | Gates Product+Security sur arbre intégré avant tout feu vert WEB |
| Historique main squashé — SHAs anciens introuvables | Moyenne | S'appuyer sur `PROJET_ETAT.md` (récit) + SHAs listés ici |
| Perte de l'autorisation explicite de cible lors des évolutions CORE/MCP | Haute sécurité | Tests de régression Security préservés ; invariants ci-dessus |
| Un « bypass » générique deviendrait une backdoor | Haute sécurité | Mode laboratoire borné uniquement (SEC-LAB-001), local, audité, double opt-in |
| Serveur MCP externe hors sandbox locale présenté comme sandboxé | Haute | Contrôles Security + provenance ; jamais présenter comme sandboxé |

---

## INTÉGRATIONS PRÉVUES (ordre révisé 31/08)

1. **PR #2 → main** (orchestrateur). Pré-requis : re-vérification minimale sur worktree (`py_compile` fichiers touchés + suites légères disponibles), puis merge de la PR ouverte. Résultat : main redevient la ligne la plus avancée.
2. **Re-alignment builders** : chaque builder repart de son tip précédent re-aligné sur le nouveau main (conflits attendus sur `pipeline/adapters/analyser` — traités builder par builder, pas en bloc).
3. **Handoff + intégration CORE History** (`eebefbc`) : confirmer l'alignement `agnt.history.v1`/`timeline`/`execution-status`, préserver Cible + autorisation de cible + correctifs Security P0.1/G6a (`d1d562f`, `e5838003`).
4. **Double gate sur API réelle** : Product (`product_api_gate.py --base-url --require-full-coverage`) ET Security (`dae445a`) contre la même API intégrée, captures complètes. → feu vert WEB.
5. **Raccord CORE+MCP Transport** (MCP-004) : module canonique, suppression de la duplication, batterie MCP rejouée.
6. **Lots WEB** selon la carte `93f8ead`, après double feu vert.
7. **SEC-LAB-001** finalisé + audit ; puis (plus tard, décision propriétaire) pilote Strix strictement local.
8. **DEVOPS-002** dès accord propriétaire.

---

## PROCHAINES ACTIONS

| # | Qui | Action |
|---|---|---|
| 0 | ~~ORCHESTRATEUR~~ | ~~Corriger l'incident bootstrap~~ **FAIT 31/08** (renormalisation eol, PR #3 → main). |
| 1 | ORCHESTRATEUR | Vérifier PR #2 sur worktree (preuve minimale) puis merger dans `main` ; mettre à jour ce fichier (base d'intégration). |
| 2 | CORE | Retenter une commande (self-heal attendu) ; lire la mémoire (`git fetch origin main && git show origin/main:docs/coordination/PROJECT_STATE.md` — le checkout 4433af6 ne la contient pas) ; produire le handoff `eebefbc` ; **aucun nouveau code sur la base 4433af6** avant re-alignment post-PR#2. |
| 3 | SECURITY | Produire le handoff `08a8150` (justifier le périmètre 125 fichiers ; confirmer invariants labo : double opt-in, egress fermé, aucun bypass). |
| 4 | PRODUCT | Préparer l'exécution du gate `--base-url` contre l'arbre CORE intégré (après action 3 de la section précédente). |
| 5 | WEB | Rester en attente (gates). Aucun code UI avant feu vert double. |
| 6 | MCP | Rien d'assigné — le raccord Transport se fera en intégration coordonnée. |
| 7 | DEVOPS | Rien sans accord propriétaire. |

---

## SOURCES

- `AGNT_PROJECT_STATE.md@aafe5af` (mémoire précédente, 30/08) — absorbée par ce fichier.
- `PROJET_ETAT.md`, `CONTEXTE_PROJET.md` (contraintes non négociables), `PHASE3/CONTRAT_PUBLIC.md`.
- GitHub : PR #1 (MERGED), PR #2 (OPEN) ; `git ls-remote` au 31/08.
