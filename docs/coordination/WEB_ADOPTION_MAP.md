# Carte d'adoption WEB — AGNT

Version `1.1` · 2026-08-30 · Owner: builder-web · Statut: **préparation d'intégration** (aucun code WEB écrit)

Ce document est la préparation d'intégration du travail WEB : il dit **exactement** ce que WEB
adopte, ce qu'il attend de CORE/MCP/Security, dans quel ordre, et quelles portes doivent être
vertes avant chaque étape. Ce n'est ni un audit global ni une implémentation.

## 1. Références

| Référence | Identifiant | Statut mesuré (2026-08-30) |
|---|---|---|
| Refonte UI Product | `18c1aad` `feat(ui): redesign mission workspace experience` | Sur `arena/01a05415-agnt` ; **non fusionné** dans la base `arena/builder-web @ 4433af6` |
| Contrat History | `bb2de26` → `docs/coordination/MISSION_HISTORY_CONTRACT.md` (`agnt.history.v1`) + fixture | Idem |
| Contrat Timeline | `226029fa` → `docs/coordination/MISSION_TIMELINE_CONTRACT.md` (`agnt.timeline.v1`) + fixture | Idem |
| Contrat Status | `cebdf10f` → `docs/coordination/EXECUTION_STATUS_CONTRACT.md` (`agnt.execution-status.v1`) + `execution-status-v1.schema.json` | Idem |
| Gate Product/API | `3f96e255` → `docs/coordination/api-conformance-gate/` : `product_api_gate.py` (black-box, stdlib, lecture seule) + `test_product_api_gate.py` + captures anonymisées | Sur `arena/01a05425-agnt` ; **non fusionné** |
| Invariants WEB existants | `PHASE3/interface/{index.html,app.js,style.css,api.py,_domtest.mjs}` + `PHASE3/test_interface.py` | Base HEAD `4433af6` ; baseline mesurée : `_domtest.mjs` **103/103 PASS**, `test_interface.py` **34/35** (1 NON ÉVAL : sérialisation `PHASE3/run/` exige opa+bwrap absents de la sandbox) |
| Branche CORE | `arena/builder-core` | Toujours à `4433af6` (mesuré) : **endpoints non livrés** |

Le gate est un validateur **serveur** des trois contrats (HTTP uniquement, ne crée/modifie
aucune mission) ; les suites `_domtest.mjs`/`test_interface.py` restent les portes **rendu/
client** de WEB. Les deux se complètent, aucune ne remplace l'autre.

Règle de lecture : les contrats sont lus **tels que livrés par Product** ; aucun contrat n'est
reproduit ici, seulement les obligations WEB qu'ils imposent.

## 2. Étape A — Adoption de la refonte Product : la référence WEB

### 2.1 Fichiers Product à intégrer (`18c1aad`)

`PHASE3/interface/index.html` (+130), `app.js` (+133), `style.css` (+412), `README.md` (+8).
`api.py` n'est **pas** touché par la refonte → les 5 routes et le chargeur `_charger` restent
les seuls canaux de données de la mission courante.

### 2.2 Comportements canoniques adoptés (référence, à ne pas redéfinir)

| Comportement | Où dans `18c1aad` |
|---|---|
| État d'accueil réel quand l'API répond mais qu'aucune mission n'existe | `section#welcome` ; masqué par `rendu()` et `lancerUnRun()` |
| Données de démonstration **uniquement** si l'API est indisponible | `principal()` : `if (reel) return;` — la maquette n'est rendue que si `brancher()` échoue |
| Étiquetage explicite de toute maquette | `#ruban` « MAQUETTE / MODE DÉMONSTRATION — données d'aperçu, aucun moteur connecté » + `rendu({...exemple, maquette:true})` |
| Progressive disclosure | `rendu()` : résultats d'abord, `blocCouverture`/`blocChaine` en `technical-section` ; options avancées du formulaire dans `<details>` ; nav « Findings »/« Rapports » inactifs avant une mission terminée |
| Création de mission simplifiée | Composer minimal (cible + demande) ; moteur/modèle/confiance/cage dans « Options avancées » ; validation client dans `#form-error` (role=alert) |
| États attente / exécution / refus / erreur / offline | `#etat` + `#connection-dot`/`#connection-label` (`connected`/`offline`), `#form-error`, ledger `#vivante` (aria-live), `STATUT_LISIBLE` |
| Rendu sûr | `textContent` partout ; `existe()` = absent → absent (jamais 0/undefined/[object Object]) |
| Responsive + thèmes | layout sidebar/workspace ; `#theme` (system/dark/light) |
| Concepts principaux vs secondaires | Mission, Finding, Cluster, Capability en premier plan (vue d'ensemble, résultats, regroupement) ; provider/provenance en détail technique (`technical-section`, tiers `technical`) |

### 2.3 Identifiants DOM à préserver

**Conservés depuis HEAD** (le harnais `_domtest.mjs` construit son DOM à partir de ces ids et
les tests les jugent) : `ruban`, `form`, `cible`, `question`, `modele`, `confiance`, `egress`,
`egress-note`, `moteur`, `run`, `etat`, `vivante`, `poste`, `pied`.

**Nouveaux** : `connection-dot`, `connection-label`, `theme`, `form-error`, `welcome`,
`welcome-title`, `mission`, `composer-title`.

**Fonctions/comportements existants qui restent** : `json()` (fetch borné, `{ok:false,status:0}`
sur rejet de transport), `blocVivant()` (ledger vivant = même dérivation que l'archive),
`lancerUnRun()` (validation, attente, polling borné : 3 silences → arrêt, 404 → état nommé
« inconnu du serveur (redémarrage ?) »), `rendu()` (fidélité artefacts), `brancher()`
(remplissage du sélecteur depuis `/api/cibles` et `/api/capacites`).

**Contraintes d'accès** : éléments par id uniquement (pas de `parentElement.querySelector` —
interdit par le harnais), aucun `innerHTML` (vérifié sur le code `18c1aad` : 1 occurrence,
commentaire de règle seulement). `localStorage` : le seul usage existant est la préférence de
thème cosmétique `agnt-theme` (fournie par Product) ; **interdit** comme source de données,
cache ou fallback de mission/historique.

### 2.4 Tests qui protègent l'intégration

- `_domtest.mjs` (rendu, 11 scénarios dont hostile, refuse, api_morte, ledger vivant) — lit
  `index.html` + `app.js` au vol : il suit l'adoption, mais ses **libellés attendus** sont
  liés à l'UI HEAD (voir C2).
- `test_interface.py` (contrat HTTP des 5 routes ; ancres : `function rendu` dans `app.js`,
  `innerHTML` commentaire seulement, bandeau `MAQUETTE` dans le HTML, noms des 5 clés lues
  dans `/api/capacites`).
- `test_product_api_gate.py` (self-test du gate, stdlib) — porte de l'étape 4, côté
  `docs/coordination/api-conformance-gate/`.

### 2.5 Conflits probables identifiés (à régler à l'intégration, pas à contester)

| # | Conflit | Traitement |
|---|---|---|
| C1 | Sur `refuse`/`erreur`, `lancerUnRun()` pose `run.mission: id` = **id de soumission** : le contrat history §1 interdit de le relabeller mission id | Corrigé dès que le polling fournit `mission_id` (étapes 5–6) |
| C2 | Le harnais `_domtest.mjs` fixe des libellés HEAD (« prêt », « envoi… ») ; la refonte a changé les textes (« Moteur connecté · prêt », « Préparation de la mission… ») | Réconcilier **les libellés attendus** avec la refonte — sans affaiblir aucune assertion d'honnêteté (règle du harnais : on ne passe pas un test en trichant ; un libellé attendu est un fait de contrat) |
| C3 | Deux entrées de données convergeront vers l'écran (run live `/api/runs/<id>.donnees`, détail `/api/missions/{id}.data`) | Une **seule** chaîne de rendu : l'étape 6 consomme la projection par les blocs existants, pas un second rendeur |
| C4 | `data.events` (legacy) et `data.timeline` coexisteront | Règle du code : timeline présente → timeline ; sinon events ; **jamais fusionnées** (le gate vérifie la séparation côté API ; un test DOM dédié le vérifie côté rendu) |
| C5 | `localStorage` (thème) vs interdiction de cache local | Cosmétique autorisé (Product) ; données mission : jamais (règle de cette carte) |
| C6 | Nav « Historique » `aria-disabled` « Bientôt » | Actif seulement quand `GET /api/missions` répond (étape 5) ; sinon rester « Bientôt » |

## 3. Étape B — Contrat CORE à consommer (ce que WEB attend, mot pour mot)

### 3.1 Historique — `agnt.history.v1`

```text
GET /api/missions?limit=25&cursor=<opaque>&status=<statut>&target_type=<type>
→ { schema_version, items: [MissionSummary], page: { limit, next_cursor } }

GET /api/missions/{mission_id}
→ { schema_version, mission: MissionSummary+, data: { request, intent, plan, findings,
    clusters, report, coverage, executions, events }, missing_artifacts: [noms logiques] }
```

Rappels obligatoires WEB :

- `mission_id` = référence **persistante** (URL et affichage) ; le submission ID de
  `POST /api/runs` reste **temporaire** (lancement/polling seulement) — jamais relabellé (C1).
- `items: []` + HTTP 200 = **état vide réel** (« connecté, aucune mission persistée ») : ni
  offline, ni erreur, ni fixture.
- `missing_artifacts` (noms logiques stables : `findings`, `clusters`, `report`, `run`) →
  avertissement de complétude ; **jamais** zéro finding, jamais « aucun problème ».
- WEB ne lit **jamais** le filesystem ; ne reconstruit **jamais** une Mission depuis une
  fixture, un bundle, un cache local ou `localStorage`. L'unique source est
  `GET /api/missions`.
- Champs optionnels (`findings_summary`, `clusters_count`, `duration_ms`, `run_id`,
  `started_at`, `completed_at`, `contributors`, `incomplete`) : absents → absents ou
  « inconnu », jamais défaultés à zéro.
- Statuts canoniques mission : `en_file`, `en_cours`, `termine`, `refuse`, `erreur`,
  `inconnu`. `indisponible` **n'est pas** un statut mission (état HTTP/API côté WEB, ou statut
  provider `non_disponible` en détail). Valeur inconnue → rendue inconnue, jamais succès.
- `request.title`, `target.display_name` : texte borné, sans chemin absolu, rendu `textContent`.
- Les fixtures Product (marqueur `$fixture`) et les captures anonymisées du gate sont des
  données de test : **jamais** de fallback produit.

### 3.2 Timeline — `agnt.timeline.v1` (dans le détail, pas d'endpoint dédié)

```text
GET /api/missions/{mission_id}?timeline_limit=200&timeline_cursor=<opaque>
└── data.timeline = { schema_version, state: complete|partial|unavailable,
    ordering: journal_sequence_ascending, events[], returned_events, total_events?,
    truncated, next_cursor, limitations[] }
```

Règles WEB :

- Ordre = **ordre reçu** (`position` / séquence journal) ; **pas de tri frontend par
  timestamp seul** ; timestamp absent → « indisponible », jamais l'heure du navigateur.
- **Pas de fusion** `data.events` + `data.timeline` : timeline présente → timeline ; sinon
  `data.events` (legacy) ; jamais les deux (C4).
- Événement inconnu = **rendu générique sûr** (catégorie `unknown`, `data_state: unavailable`) ;
  payload arbitraire/HTML jamais rendu.
- Étape absente = **absence**, pas étape inventée ; jamais de remplissage de préfixe.
- `state: partial`/`truncated`/`redacted` + codes `limitations` (`journal_missing`,
  `history_gap_detected`, `provenance_partial`, …) → avertissements + poursuite via
  `next_cursor` opaque (jamais parsé).
- Hiérarchies `visibility` : `summary` d'abord, `mission` au détail, `technical` repli.

### 3.3 Statuts — `agnt.execution-status.v1` (dans `data.executions[]`, enrichi in place)

Chaque item (schema `execution-status-v1.schema.json`) porte, **indépendamment** :

```text
applicability   applicable | non_applicable | inconnu
selection       selectionne | non_selectionne | inconnu
condition       remplie | bloquee | inconnu
authorization   autorise | non_autorise | non_evalue | inconnu
availability    { value: disponible|indisponible|inconnu, reason_code?, proof }
execution       { value: non_lance|en_cours|termine|echoue|timed_out|cancelled|unavailable|inconnu,
                  invocation, output, reason_code?, proof }
detection       { value: findings_presents|rien_trouve|non_evalue|inconnu, findings_count?,
                  analyzed_targets?, proof }
completeness    { state: complete|partial|unavailable|conflict, missing[], limitations[] }
proof           (origine de la preuve : recorded | derived | provider_reported | unknown)
provenance      (additive, optionnelle, §3.4)
```

WEB garde ces dix notions **séparées** (statut mission, applicabilité, sélection, condition,
autorisation, disponibilité, résultat d'exécution, résultat de détection, complétude, preuve).

Règle absolue, à afficher comme autant d'états **distincts** :

```text
outil absent ≠ outil échoué ≠ outil refusé ≠ timeout ≠ annulation ≠ aucun finding
```

- Le zéro est affichable **uniquement** si le backend le prouve : `detection: rien_trouve`
  (9 conditions du contrat §6 : exécution `termine`, invocation oui, output exploitable,
  cibles analysées > 0, artefact findings lisible, attribution provider, compteur 0, sans
  contradiction) ou `findings_presents` avec compteur attribué ; jamais de compteur calculé
  côté WEB.
- `conflict` → avertissement ; jamais « la valeur la plus rassurante » ; jamais de parsing de
  `raison` libre, de classe CSS, de timestamp ou d'existence de fichier.
- Tons visuels (sémantique du contrat §5, tokens libres) : gris = non sélectionné/non
  applicable ; bleu = attente/en cours ; ambre = indisponible/timeout/annulé/partiel/inconnu ;
  rouge = échec/refus explicite ; vert = exécution terminée **uniquement** (jamais « sécurisé »).
  Jamais la couleur seule : texte + icône + label accessible.
- Le statut mission ne se déduit **pas** des lignes provider, et l'inverse non plus.

### 3.4 Provenance MCP — additive

Champs techniques affichables **uniquement en détail** (tiers `technical`, matrice du contrat
timeline §9) : `provider_id`, `provider_kind` (`local`|`mcp`|`external`), `transport`,
`server_id`, `tool_id`, `protocol`, `confidence` (+`basis`), `availability`, `request_id`,
`correlation_id`. En résumé métier : nom d'affichage approuvé, `confidence`/`availability`
seulement s'ils changent l'interprétation ; en liste : agrégats `contributors{count,kinds}`
seulement.

**Jamais atteints par l'UI** (interdits à tous les niveaux de détail) :

```text
endpoint brut · token · credential · Authorization · header · argv · commande ·
payload MCP brut · trace · chemin absolu · sortie brute provider
```

- Absence de provenance = « non consignée » ; **jamais** « local » ou « fiable » par défaut.
- Confiance déclarée par provider ≠ vérification AGNT (`basis` le dit ; l'affichage aussi).
- La rédaction se fait **server-side** (CORE/Security) ; le rendu texte côté WEB est la
  défense en profondeur, pas la garantie.

### 3.5 Polling existant — extension additive

`GET /api/runs/{submission_id}` conserve tous ses champs actuels (`statut`, `vivante`,
`donnees`, `refus`, `erreur`, `resume`, `sortie`) et **ajoute** `mission_id` et
`detail_href` (`"/api/missions/m-…"`) dès que connus. Aucune `GET /api/runs` de liste en v1 :
l'historique persistant passe par `/api/missions` uniquement.

## 4. Étape C — Ordre d'intégration (10 étapes)

| # | Étape | Prérequis | Fichiers futurs concernés | Test à exécuter | Risque | Critère de feu vert | Hors scope |
|---|---|---|---|---|---|---|---|
| 1 | Intégrer la refonte Product UI | Branche Product réconciliée dans la base (orchestrateur) ; aucun endpoint | `PHASE3/interface/{index.html,app.js,style.css,README.md}` (déjà écrits par Product) | — (porte à l'étape 2) | Dérive de la réconciliation (conflits de merge) | Fichiers Product présents à l'identique dans la base | Aucune modification WEB à ce stade |
| 2 | Vérifier les suites existantes | Étape 1 | `_domtest.mjs` (réconciliation des libellés C2 si nécessaire), `test_interface.py`, `test_product_api_gate.py` (self-test du gate) | `_domtest.mjs` (tous scénarios), `test_interface.py`, self-test du gate | Harnais lié à d'anciens libellés (C2) — seul risque connu | Les trois portes vertes sur la base fusionnée ; `#welcome` visible API connectée ; zéro donnée de démo API connectée ; `#ruban` uniquement API indispo | Aucun nouveau test de feature ; pas d'affaiblissement d'assertion |
| 3 | Attendre l'API CORE History/Timeline/Status | — (pas de code) | aucun | — | Attente ; ne pas brancher sur du provisoire | Endpoints livrés sur la branche CORE + tests fixtures CORE verts (contrat history §13) | AUCUNE route parallèle, AUCUN stub de mock produit |
| 4 | Lancer le gate Product/API contre l'API réelle | Étape 3 | aucun (le gate est livré par Product) | `python3 docs/coordination/api-conformance-gate/product_api_gate.py --base-url <API>` (+ `--submission-id <id réel>` pour prouver la distinction des IDs) | Environnement : sans endpoint → exit 1 (attendu avant l'étape 3 terminée) ; un live sans tous les cas sémantiques → exit 0 ou 2 selon `--require-full-coverage` | **Exit 0** sur l'API réelle ; cas manquants du live couverts par captures contrôlées CORE + `--require-full-coverage` (exit 0, jamais 2) | Ne pas utiliser `--fixture-mode` comme preuve d'API réelle ; pas de modification du gate par WEB |
| 5 | Brancher l'historique | `GET /api/missions` + polling enrichi `mission_id`/`detail_href` (C1 corrigé) | `app.js` (bloc historique + activation nav C6 ; référence mission = `mission_id`, lien `detail_href`), `style.css` | Scénarios `_domtest` nouveaux : vide réel (`items:[]`), chargé, pagination cursor, erreur API, offline ; `test_interface` (champs, 404 `MISSION_NOT_FOUND`) ; gate (filtres/cursor) | Activation nav trop tôt (C6) ; deux sources d'IDs (C1) | 6 états rendus (loading/vide/chargé/partiel/erreur/offline) ; liens via `detail_href` ; IDs affichés = `mission_id` ; compteurs optionnels non défaultés | Recherche/filtres avancés (dodés v1) ; détail |
| 6 | Brancher le détail Mission | `GET /api/missions/{mission_id}` livré (contrat §6) | `app.js` (vue détail par les **blocs existants** alimentés par `data.*` — C3), `index.html` (conteneur), `style.css` | Scénario `_domtest` sur `mission-history-detail.fixture.json` (marqueur `$fixture` visible) ; `missing_artifacts` → avertissement ; findings absents ≠ 0 ; rapport présent/absent | Divergence des deux entrées de données (C3) | Disclosure progressive résumé → résultats → exécution → provenance/événements ; `missing_artifacts` visible ; aucun chemin absolu | Sorties brutes, téléchargement d'artefacts |
| 7 | Brancher la timeline | `data.timeline` (`agnt.timeline.v1`) dans le détail | `app.js` (rendu timeline : visibilités, `truncated`/`next_cursor`, avertissements), `style.css` | Scénario `_domtest` sur `mission-timeline-complete.fixture.json` ; inconnu → générique sûr ; ordre seq (pas ts) ; **pas de fusion events+timeline** ; `state: unavailable` + `journal_missing` | Règle « pas de fusion » (C4) | Ordre = position reçue ; événements inconnus sûrs ; aucune duplication events+timeline ; pagination opaque | Animation/charts, streaming/SSE, store front |
| 8 | Brancher les statuts structurés + provenance MCP | `data.executions[]` conforme `execution-status-v1.schema.json` ; provenance MCP additive validée | `app.js` (10 notions séparées + carte `reason_code` → libellés FR ; tons du contrat §5), `style.css` | Scénarios `_domtest` par situations du contrat statuts §9 (binaire absent, OPA absent, egress bloqué, timeout, annulé, findings absents après exécution, provenance partielle) ; chaînes interdites (§3.4) absentes du rendu | Alignement `blocStatuts` (run live) et rendu structuré (détail) sur la même autorité CORE | Les 6 états distincts rendus séparément ; zéro seulement si prouvé ; provenance partielle prudente ; absence ≠ local | Filtres, scoring « sécurisé », retry/annulation |
| 9 | Validation Security | Étape 8 | aucun (validation, pas code) | Cas hostiles du contrat (timeline §12 SECURITY) : userinfo URL, caractères de contrôle, secrets, traversal, valeurs surdimensionnées, lignes de journal malformées, séquences dupliquées/lacunaires, métadonnées MCP hostiles ; gate avec `--require-full-coverage` sur captures | Découverte de trous de rédaction **server-side** (périmètre CORE/Security, à remonter, pas à corriger côté WEB) | Security : grammaires d'identifiants + allowlists transport/protocol approuvées ; rédaction server-side vérifiée ; cas hostiles verts | Aucune correction « en douce » côté client des trous serveur |
| 10 | Validation navigateur réelle | Étape 9 ; machine bootstrapée (OPA épinglé + bwrap) — hors sandbox actuelle | aucun (validation) | Parcours complet : page → API connectée → `#welcome` → mission réelle → `termine` → findings/clusters/rapport ; + `refuse` nommé ; desktop et fenêtre réduite | Limitation environnementale (mesurée) : dans la sandbox, seule la trajectoire `refuse`/`erreur` est mesurable (OPA/bwrap/outils absents) | RUN réel `termine` affiché fidèlement à ses artefacts, sur machine bootstrapée ; matrice §5 complète | Toute feature ; toute installation d'outils pour forcer un RUN |

## 5. Étape D — Porte de qualité WEB (matrice post-intégration)

| # | Scénario | Attendu | Couverture |
|---|---|---|---|
| Q1 | API connectée, aucune Mission | `#welcome` réel ; aucune donnée de démo | Nouveau (`connecte`) — verrouille `principal()` de la refonte |
| Q2 | API indisponible | État offline (`connection offline`, « Moteur hors ligne ») ; maquette **explicitement étiquetée** seulement si `donnees_exemple.json` existe ; jamais confondue avec une mission | Existant `api_morte` + extension libellés |
| Q3 | Mission refusée | Refus clair et nommé (motif, fail-closed) ; aucun faux succès ; aucun compteur zéro inventé | Existant `refuse` + `missing_artifacts` |
| Q4 | Mission incomplète | `missing_artifacts` visible (avertissement) ; aucun zéro inventé | Nouveau (fixture détail) |
| Q5 | Mission terminée, zéro réellement prouvé | Zéro affichable **uniquement** avec `detection: rien_trouve` prouvé ; sinon `non_evalue`/`inconnu` | Nouveau (contrat statuts §6) |
| Q6 | Provider absent | `unavailable` distinct d'un échec (couleur + texte + raison) | Nouveau (contrat statuts §9) |
| Q7 | Provider timeout | `timed_out` distinct d'une annulation (`cancelled`) et de l'indisponibilité | Nouveau (contrat statuts §9) |
| Q8 | Provenance MCP incomplète | Prudence : champs validés seuls, `provenance_partial` ; absence ≠ local/favorable | Nouveau (timeline §11) |
| Q9 | Timeline | Ordre `seq` ; événement inconnu sûr ; pas de duplication events+timeline | Nouveau (fixture timeline) |
| Q10 | Injection hostile | Rendu textuel (`textContent`) ; jamais `innerHTML` ; payload arbitraire jamais interprété | Existant `hostile` + extension timeline/provenance |

Complément serveur : le **gate Product/API** (`3f96e255`) couvre côté HTTP les mêmes
invariants (vide réel, distinction des IDs, zéro prouvé, états distincts, `missing_artifacts`,
provenance allowlistée, absence de données sensibles) ; il s'exécute à l'étape 4 et doit rester
vert à chaque étape 5–8. Les fixtures du gate ne valent jamais comme preuve d'API réelle
(`--fixture-mode` ≠ validation réelle — README du gate).

## 6. Risques de conflit (synthèse)

1. **Fenêtre de migration** : entre le polling enrichi et la route détail, `detail_href` peut
   pointer vers une route absente → le lien n'est rendu qu'une fois la route mesurée présente
   (un 404 sur un lien affiché serait une promesse brisée).
2. **Divergence de rendu** (étape 6) : projection `data.*` vs forme `_charger` — une seule
   chaîne de rendu (C3), sinon deux écrans contradictoires pour une même mission.
3. **Dérive des libellés** : les contrats imposent des sémantiques (ex. « Aucune finding
   remonté sur les cibles analysées » + limites — jamais « Le projet est sécurisé ») ; la carte
   `reason_code` → libellé vit dans un seul endroit côté WEB.
4. **Fixtures/captures comme fallback** : fixtures Product (`$fixture`) et captures anonymisées
   du gate sont des données de test ; un fallback produit dessus serait une régression
   d'honnêteté (contrat §10, README du gate).
5. **Concurrents de branches** : builder-core/mcp/product avancent chacun sur leur branche ;
   toute adoption WEB se fait sur la base réconciliée — ne merge ni rebase aucune branche
   builder (orchestrateur).

## 7. Critères de feu vert

1. **Étape 2** : refonte intégrée + `_domtest.mjs`, `test_interface.py` et self-test du gate
   verts sur la base fusionnée (libellés réconciliés, C2).
2. **Étape 4** : gate `product_api_gate.py` **exit 0** contre l'API réelle ; cas sémantiques
   absents du live couverts par captures contrôlées CORE + `--require-full-coverage` (exit 0).
3. **Étapes 5–8** : les endpoints correspondants livrés et conformes (gate vert à chaque
   étape) ; provenance MCP : grammaires d'identifiants + allowlists transport/protocol
   approuvées par Security.
4. **Étape 9** : validation Security des cas hostiles et de la rédaction server-side.
5. **Étape 10** : machine bootstrapée (OPA épinglé + bwrap) pour le RUN réel `termine` ; dans
   la sandbox actuelle (OPA/bwrap/outils absents, mesuré) seule la trajectoire `refuse`/`erreur`
   nommée est mesurable — limitation environnementale caractérisée, pas un blocage du chantier.

## 8. Ce que WEB ne doit PAS reconstruire (liste explicite)

- Historique depuis le filesystem (`artifacts/missions/`), les bundles dogfooding,
  `localStorage`, fixtures ou données locales : **une seule source, `GET /api/missions`**.
- Route parallèle, liste `GET /api/runs` (temporaire), endpoint de fichiers, téléchargement
  d'artefacts ou de sorties brutes (décision Security, hors v1).
- Timeline frontend (store, tri, fusion events+timeline, streaming) : projection serveur lue
  telle quelle.
- Filtres Findings, vues globales Findings/Clusters/Rapports, recherche avancée (dodés v1).
- Nouveaux statuts mission, agrégation statut-mission depuis les lignes provider, scores de
  sécurité, retry/annulation.
- Zéros, statuts ou états « probablement » : absent = absent ou inconnu ; `rien_trouve` prouvé
  seulement par le backend.
- Données de démonstration présentées comme réelles ; fallback produit sur fixtures/captures.
- `localStorage` comme source de données (le thème cosmétique de Product est le seul usage).
- Installation d'OPA/bwrap/outils pour « prouver » un RUN (limitation environnementale déjà
  caractérisée — §7.5).
- Pipeline, registre, policy, sandbox (`PHASE3/slice/`, `PHASE3/policy/`), modèles Finding,
  transports MCP, code de redaction : périmètres CORE/SECURITY/MCP, intouchés par WEB.

## 9. Points ouverts à réconcilier (non bloquants du document)

- **O1** — `arena/builder-core` à `4433af6` (mesuré) : les endpoints du §3 ne sont pas encore
  sur le remote ; les contrats et le gate sont prêts, l'implémentation attend.
- **O2** — Migration des artefacts de résultat `sortie` → `run` (signalée par CORE, contrat
  history §2) : le lecteur de détail doit passer par le lecteur canonique de mission, jamais
  de chemin durci des deux côtés.
- **O3** — Classification terminale structurée des événements de journal (contrat history §7) :
  ajout additif CORE attendu ; les lecteurs conservent le mapping legacy (cloture/arret).
- **O4** — Décision WEB déjà prise : **pas de test statique de ce document** (le livrable est
  le document seul ; les portes réelles sont `_domtest.mjs`, `test_interface.py` et le gate
  Product/API — un test de prose n'ajouterait pas de protection opérationnelle).
