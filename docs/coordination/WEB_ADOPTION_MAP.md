# Carte d'adoption WEB — AGNT

Version `1.0` · 2026-08-30 · Owner: builder-web · Statut: **préparation d'intégration** (aucun code WEB écrit)

Ce document est la préparation d'intégration du travail WEB : il dit **exactement** ce que WEB
adopte, ce qu'il attend de CORE/MCP/Security, dans quel ordre, et quelles portes doivent être
vertes avant chaque lot. Ce n'est ni un audit global ni une implémentation.

## 1. Références

| Référence | Identifiant | Statut mesuré (2026-08-30) |
|---|---|---|
| Refonte UI Product | commit `18c1aad` `feat(ui): redesign mission workspace experience` | Présent sur `arena/01a05415-agnt` ; **pas fusionné** dans la base `arena/builder-web @ 4433af6` |
| Contrat historique | commit `bb2de26` → `docs/coordination/MISSION_HISTORY_CONTRACT.md` (`agnt.history.v1`) + fixture | Idem |
| Contrat timeline | commit `226029fa` → `docs/coordination/MISSION_TIMELINE_CONTRACT.md` (`agnt.timeline.v1`) + fixture | Idem |
| Contrat statuts | commit `cebdf10f` → `docs/coordination/EXECUTION_STATUS_CONTRACT.md` (`agnt.execution-status.v1`) + `execution-status-v1.schema.json` | Idem |
| Invariants WEB existants | `PHASE3/interface/{index.html,app.js,style.css,api.py,_domtest.mjs}` + `PHASE3/test_interface.py` | Base HEAD `4433af6` ; baseline mesurée : `_domtest.mjs` **103/103 PASS**, `test_interface.py` **34/35** (1 NON ÉVAL : sérialisation `PHASE3/run/` exige opa+bwrap absents de la sandbox) |
| Branche CORE | `arena/builder-core` | Toujours à `4433af6` (mesuré) : **endpoints non livrés** |

Règle de lecture : les contrats sont lus **tels que livrés par Product** ; aucun contrat n'est
reproduit ici, seulement les obligations WEB qu'ils imposent.

## 2. Lot 1 — Adoption de la refonte Product UI

### 2.1 Fichiers modifiés par Product (`18c1aad`)

`PHASE3/interface/index.html` (+130), `app.js` (+133), `style.css` (+412), `README.md` (+8).
`api.py` n'est **pas** touché par la refonte → les 5 routes et le chargeur `_charger` restent
les seuls canaux de données.

### 2.2 Comportements canoniques adoptés (référence, à ne pas redéfinir)

| Comportement | Où dans `18c1aad` |
|---|---|
| État d'accueil réel (`#welcome`) jusqu'à la première mission | `index.html` `section#welcome` ; masqué par `rendu()` et `lancerUnRun()` |
| Aucune donnée de démo quand l'API répond | `principal()` : `if (reel) return;` — la maquette n'est rendue **que** si `brancher()` échoue |
| Maquette uniquement API indisponible, bandeau explicite | `#ruban` « MAQUETTE / MODE DÉMONSTRATION » + `rendu({...exemple, maquette:true})` |
| Progressive disclosure | `rendu()` : résultats d'abord, `blocCouverture`/`blocChaine` en classe `technical-section` ; options avancées du formulaire dans `<details>` |
| États attente / exécution / refus / erreur / offline | `#etat` + `#connection-dot`/`#connection-label` (`connected`/`offline`), `#form-error` (role=alert), ledger `#vivante` (aria-live) |
| Rendu sécurisé | `textContent` partout, `existe()` = absent → absent (jamais 0/undefined/[object Object]) |
| Responsive + thèmes | layout sidebar/workspace ; `#theme` (system/dark/light), seul usage `localStorage` = préférence cosmétique `agnt-theme` |
| Slot Historique réservé | nav `aria-disabled` « Historique · Bientôt » — activation au Lot 3, jamais avant |

### 2.3 Identifiants DOM à préserver (contrat du harnais + du futur code WEB)

**Conservés depuis HEAD** (le harnais `_domtest.mjs` construit son DOM à partir de ces ids et
les tests les jugent) : `ruban`, `form`, `cible`, `question`, `modele`, `confiance`, `egress`,
`egress-note`, `moteur`, `run`, `etat`, `vivante`, `poste`, `pied`.

**Nouveaux** : `connection-dot`, `connection-label`, `theme`, `form-error`, `welcome`,
`welcome-title`, `mission`, `composer-title`.

Règles d'accès inchangées : éléments atteints **par id uniquement** (le harnais l'interdit :
pas de `parentElement.querySelector`), aucun `innerHTML` (la mention ne subsiste que comme
commentaire de règle — vérifié sur le code `18c1aad`), polling borné (3 silences → arrêt ;
404 → état nommé).

### 2.4 Invariants de tests déjà vérifiés sur le code Product

- `innerHTML` : 1 occurrence, commentaire de règle uniquement (check `test_interface.py` OK).
- `parentElement` utilisé seul (jamais `.querySelector`) — le commentaire qui nomme la forme
  interdite est retiré par le harnais avant sa propre vérification.
- Bandeau `MAQUETTE` présent dans le HTML (check `test_interface.py` OK).
- `function rendu` présente (check `test_interface.py` OK).

### 2.5 Conflits identifiés à l'adoption (à régler, pas à contester)

| # | Conflit | Traitement |
|---|---|---|
| C1 | Sur `refuse`/`erreur`, `lancerUnRun()` pose `run.mission: id` = **id de soumission** : le contrat history §1 interdit de le relabeller mission id | Corrigé au **Lot 2** dès que le polling fournit `mission_id` |
| C2 | Le harnais `_domtest.mjs` fixe des libellés HEAD (« prêt », « envoi… ») ; la refonte a changé les textes (« Moteur connecté · prêt », « Préparation de la mission… ») | Au Lot 1, réconcilier **les libellés attendus** du harnais avec la refonte — sans affaiblir aucune assertion d'honnêteté (c'est la règle du harnais : on ne passe pas un test en trichant, mais un libellé attendu est un fait de contrat) |
| C3 | Deux entrées de données convergeront vers l'écran (run live `/api/runs/<id>.donnees`, détail `/api/missions/{id}.data`) | Une **seule** chaîne de rendu ; le Lot 4 consomme la projection par les blocs existants, pas un second rendeur |
| C4 | `data.events` (legacy) et `data.timeline` coexisteront | Règle du code : timeline présente → timeline ; sinon events ; **jamais fusionnées** (Lot 5, test dédié) |
| C5 | `localStorage` utilisé par le thème | Autorisé **uniquement** cosmétique ; jamais de données mission/historique |
| C6 | Nav « Historique » `aria-disabled` | Actif seulement quand `GET /api/missions` répond (Lot 3) ; sinon rester « Bientôt » |

## 3. Contrat CORE à consommer (ce que WEB attend, mot pour mot)

### 3.1 Historique — `agnt.history.v1`

```text
GET /api/missions?limit=25&cursor=<opaque>&status=<statut>&target_type=<type>
→ { schema_version, items: [MissionSummary], page: { limit, next_cursor } }

GET /api/missions/{mission_id}
→ { schema_version, mission: MissionSummary+, data: { request, intent, plan, findings,
    clusters, report, coverage, executions, events }, missing_artifacts: [noms logiques] }
```

Obligations WEB :

- `mission_id` = référence persistante primaire (URL et affichage) ; l'id de soumission de
  `POST /api/runs` reste **temporaire** (lancement/polling seulement) — jamais relabellé (C1).
- `items: []` + HTTP 200 = **état vide réel** (« connecté, aucune mission persistée ») : ni
  offline, ni erreur, ni fixture.
- Aucun historique local, fixture, bundle, filesystem ni localStorage : l'unique source est
  `GET /api/missions` (c'est le nav « Historique » qui s'active, pas un second store).
- Champs optionnels (`findings_summary`, `clusters_count`, `duration_ms`, `run_id`,
  `started_at`, `completed_at`, `contributors`, `incomplete`) : **absents → absents ou
  « inconnu »**, jamais défaultés à zéro.
- `missing_artifacts` (noms logiques stables : `findings`, `clusters`, `report`, `run`) →
  avertissement de complétude ; **jamais** zéro finding, jamais « aucun problème ».
- Statuts canoniques mission : `en_file`, `en_cours`, `termine`, `refuse`, `erreur`,
  `inconnu`. `indisponible` **n'est pas** un statut mission (état HTTP/API côté WEB, ou statut
  provider `non_disponible` en détail). Valeur inconnue → rendue inconnue, jamais succès.
- `request.title`, `target.display_name` : texte borné, sans chemin absolu, rendu `textContent`.
- Les fixtures `docs/coordination/fixtures/*` (marqueur `$fixture`) servent **aux tests
  seulement**, jamais de fallback produit.

### 3.2 Timeline — `agnt.timeline.v1` (dans le détail, pas d'endpoint dédié)

```text
GET /api/missions/{mission_id}?timeline_limit=200&timeline_cursor=<opaque>
└── data.timeline = { schema_version, state: complete|partial|unavailable,
    ordering: journal_sequence_ascending, events[], returned_events, total_events?,
    truncated, next_cursor, limitations[] }
```

Obligations WEB :

- Ordre = **ordre reçu** (`position` / séquence journal) ; **pas de tri frontend par timestamp** ;
  timestamp absent → « indisponible », jamais l'heure du navigateur.
- `data.events` est **legacy** : WEB préfère `data.timeline` et peut retomber sur `events`
  **sans jamais fusionner les deux** (C4).
- Événement inconnu = rendu sûr générique (catégorie `unknown`, `data_state: unavailable`) ;
  payload arbitraire/HTML jamais rendu.
- Étape absente = **absence** ; jamais d'étape inventée, jamais de remplissage de préfixe.
- `state: partial`/`truncated`/`redacted` + codes `limitations` (ex. `journal_missing`,
  `history_gap_detected`, `provenance_partial`) → avertissements + poursuite (`next_cursor`
  opaque, jamais parsé).
- Hiérarchies `visibility` : `summary` d'abord, `mission` au détail, `technical` replié.

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
provenance      (additive, optionnelle, §3.4)
```

Rappel explicite, à afficher comme autant d'états **distincts** :

```text
outil absent ≠ outil échoué ≠ outil refusé ≠ timeout ≠ annulation ≠ aucun finding
```

- `rien_trouve` n'est affichable que si le backend le **prouve** (9 conditions du contrat §6 :
  exécution `termine`, invocation oui, output exploitable, cible analysée > 0, artefact
  findings lisible, attribution provider, compteur 0, sans contradiction) ; sinon
  `non_evalue`/`inconnu`. Le compteur 0 n'existe qu'avec `rien_trouve` ou `findings_presents`
  attribué — jamais calculé côté WEB.
- `conflict` → avertissement ; jamais « choisir la valeur la plus rassurante » ; jamais de
  parsing de `raison` libre, de classe CSS, de timestamp ou d'existence de fichier.
- Tons visuels (contrat §5, sémantique — pas de tokens imposés) : gris = non sélectionné /
  non applicable ; bleu = attente/en cours ; ambre = indisponible/timeout/annulé/partiel/
  inconnu ; rouge = échec/refus explicite ; vert = exécution terminée **uniquement** (jamais
  « sécurisé »). Jamais la couleur seule : texte + icône + label accessible.
- Le statut mission ne se déduit **pas** des lignes provider, et l'inverse non plus.

### 3.4 Provenance MCP — additive

Champs optionnels sous finding `source.provenance` / exécution / événement : `provider_id`,
`provider_kind` (`local`|`mcp`|`external`), `transport`, `server_id`, `tool_id`, `protocol`,
`confidence` (avec `basis`), `availability`, `request_id`, `correlation_id`.

- Affichée **uniquement** au niveau de détail approprié (matrice du contrat timeline §9) ;
  jamais dans un résumé qui masquerait le résultat métier. Liste = agrégats
  `contributors{count,kinds}` seulement.
- Absence de provenance = « non consignée » ; **jamais** « local » ou « fiable » par défaut.
- Confiance déclarée par provider ≠ vérification AGNT (le `basis` le dit ; l'affichage aussi).
- **Jamais attendus ni affichés par le navigateur** : endpoint brut, token, credential,
  header, argv, payload MCP brut, trace, chemin absolu, sortie brute provider. (La
  rédaction se fait côté serveur ; le rendu texte côté WEB est la défense en profondeur.)

### 3.5 Polling existant — extension additive

`GET /api/runs/{submission_id}` conserve tous ses champs actuels (`statut`, `vivante`,
`donnees`, `refus`, `erreur`, `resume`, `sortie`) et **ajoute** `mission_id` et
`detail_href` (`"/api/missions/m-…"`) dès que connus. Aucune `GET /api/runs` de liste n'est
définie : l'historique persistant passe par `/api/missions` uniquement.

## 4. Plan d'intégration par petits lots

| Lot | Titre | Prérequis backend | Fichiers probables | Tests à exécuter | Risque de régression | Condition de validation | Hors scope explicite |
|---|---|---|---|---|---|---|---|
| 1 | Adoption de la refonte Product UI | Branche Product réconciliée dans la base (orchestrateur) ; aucun endpoint | `index.html`, `app.js`, `style.css`, `README.md` (déjà écrits) ; `_domtest.mjs` (libellés C2) | `_domtest.mjs` (tous scénarios), `test_interface.py`, navigateur : page, connexion, `#welcome`, offline | Harnais lié à d'anciens libellés (C2) ; rien d'autre (aucune route change) | Deux suites vertes sur la base fusionnée ; `#welcome` visible API connectée ; zéro donnée de démo API connectée ; `#ruban` visible **uniquement** API indispo | Aucune nouvelle route, vue, source de données |
| 2 | Polling Mission/Run → `mission_id`/`detail_href` | CORE ajoute `mission_id`+`detail_href` au polling (champs conservés) | `app.js` (`lancerUnRun`/`rendu` : référence mission = `mission_id`, lien `detail_href`) ; `test_interface.py` (champs) | `_domtest` (scénarios `termine`/`refuse` avec `mission_id` dans le polling), `test_interface` | Faible (additif) ; garder le chemin 404/redémarrage (C1 corrigé) | L'ID affiché après RUN est `m-…` (persistant), jamais l'id de soumission ; le lien pointe sur `detail_href` | Pas encore de vue historique |
| 3 | Consommation `GET /api/missions` | Route livrée + tests fixtures CORE (contrat §13) | `app.js` (bloc historique + activation nav), `style.css` (lignes/table) | Scénarios `_domtest` nouveaux : vide réel (`items:[]`), chargé, pagination cursor, erreur API, offline ; `test_interface` (noms de champs, 404 `MISSION_NOT_FOUND`, absence chemins/secrets) | Activation nav (C6) ; ne pas casser les ids harnais | 6 états rendus (loading/vide/chargé/partiel/erreur/offline) ; liens via `detail_href` ; compteurs optionnels non défaultés ; statut inconnu rendu inconnu | Recherche/filtres avancés (dodés v1) ; détail |
| 4 | Consommation détail Mission | `GET /api/missions/{mission_id}` livré (contrat §6) | `app.js` (vue détail par les **blocs existants** alimentés par `data.*` — C3), `index.html` (conteneur), `style.css` | Scénario `_domtest` sur `mission-history-detail.fixture.json` (marqueur `$fixture` visible) ; `missing_artifacts` → avertissement ; findings absents ≠ 0 ; rapport présent/absent | Moyen : deux entrées de données, une seule chaîne de rendu (C3) | Disclosure progressive résumé → résultats → exécution → provenance/événements ; `missing_artifacts` visible ; aucun chemin absolu | Sorties brutes, téléchargement d'artefacts |
| 5 | Affichage timeline | `data.timeline` (`agnt.timeline.v1`) dans le détail | `app.js` (rendu timeline : visibilités, `truncated`/`next_cursor`, avertissements), `style.css` | Scénario `_domtest` sur `mission-timeline-complete.fixture.json` ; inconnu → générique sûr ; ordre seq (pas ts) ; **pas de fusion events+timeline** ; `state: unavailable` + `journal_missing` | Faible (bloc neuf) ; règle « pas de fusion » à coder ET tester (C4) | Ordre = position reçue ; événements inconnus sûrs ; aucune duplication events+timeline ; poursuite de pagination opaque | Animation/charts, streaming/SSE, store front |
| 6 | Statuts structurés + provenance MCP | `data.executions[]` conforme `execution-status-v1.schema.json` ; provenance MCP additive validée ; Security : grammaires + allowlists + rédaction serveur | `app.js` (6 dimensions + carte `reason_code` → libellés FR ; tons du contrat §5), `style.css` | Scénarios `_domtest` par situations du contrat §9 : binaire absent, OPA absent, egress bloqué, timeout, annulé, findings absents après exécution, provenance partielle ; chaînes interdites (endpoint/argv/chemin/token) absentes du rendu | Moyen : aligner `blocStatuts` (run live) et le rendu structuré (détail) sur la même autorité CORE | Les 6 états distincts rendus séparément ; `rien_trouve` seulement si prouvé ; provenance partielle prudente ; absence ≠ local | Filtres, scoring « sécurisé », retry/annulation |
| 7 | Validation visuelle / DOM / sécurité | Lots 1–6 | `_domtest.mjs`, `test_interface.py` (complétés) | Matrice §5 complète ; injection hostile étendue (événements, `safe_summary`, provenance) ; navigateur desktop + fenêtre réduite ; accessibilité (pas de statut couleur-seule) | Faible (pas de feature) | Matrice 10/10 verte ; rendu texte sur données hostiles ; responsive lisible | Toute nouvelle feature métier |

## 5. Porte de qualité WEB (matrice — exécuter dès les endpoints CORE disponibles)

| # | Scénario | Attendu | Couverture |
|---|---|---|---|
| Q1 | API connectée, aucune Mission | `#welcome` réel ; aucune donnée fictive ; aucun finding de démo | Nouveau (`connecte`) — verrouille `principal()` de la refonte |
| Q2 | API indisponible | État offline (`connection offline`, « Moteur hors ligne ») ; maquette **étiquetée** seulement si `donnees_exemple.json` existe ; jamais confondue avec une mission | Existant `api_morte` + extension libellés |
| Q3 | Mission refusée | Refus lisible et nommé (motif, fail-closed) ; aucune fausse réussite ; aucun compteur zéro inventé | Existant `refuse` + `missing_artifacts` |
| Q4 | Mission incomplète | `missing_artifacts` visible (avertissement de couverture) ; pas de finding/compteur inventé | Nouveau (fixture détail) |
| Q5 | Terminée sans findings prouvés | Zéro affichable **seulement** si `detection: rien_trouve` prouvé ; sinon `non_evalue`/`inconnu` | Nouveau (contrat statuts §6) |
| Q6 | Provider absent | `unavailable` distinct de `echoue` (couleur+texte+raison) | Nouveau (contrat statuts §9) |
| Q7 | Provider timeout | `timed_out` distinct de `cancelled` et de `unavailable` | Nouveau (contrat statuts §9) |
| Q8 | Provenance MCP partielle | Affichage prudent (`provenance_partial`, champs validés seuls) ; absence ≠ local/fiable | Nouveau (timeline §11) |
| Q9 | Timeline | Ordre `seq` ; événements inconnus sûrs ; aucune duplication events+timeline | Nouveau (fixture timeline) |
| Q10 | Injection hostile | Rendu textuel (`textContent`) ; jamais `innerHTML` ; payload arbitraire jamais interprété | Existant `hostile` + extension timeline/provenance |

Porte d'intégration permanente : `_domtest.mjs` (rendu) + `test_interface.py` (contrat HTTP) —
les deux sont déjà vertes à la base (103/103, 34/35) et restent les seules portes obligatoires.

## 6. Risques de conflit (synthèse)

1. **Fenêtre de migration** : entre le Lot 2 (polling enrichi) et le Lot 4 (route détail),
   `detail_href` pointe vers une route peut-être absente → le lien n'est rendu qu'une fois la
   route mesurée présente (un 404 sur un lien affiché serait une promesse brisée).
2. **Divergence de rendu** lot 4 : projection `data.*` vs forme `_charger` — une seule chaîne
   de rendu (C3), sinon deux écrans contradictoires pour une même mission.
3. **Dérive des libellés** : les contrats imposent des sémantiques (ex. « Aucune finding
   remonté sur les cibles analysées » suivi des limites — jamais « Le projet est sécurisé ») ;
   la carte `reason_code` → libellé vit dans un seul endroit côté WEB.
4. **Fixtures comme fallback** : les fixtures Product (`$fixture`) sont des données de test ;
   un fallback produit dessus serait une régression d'honnêteté (contrat §10).
5. **Concurrents de branches** : builder-core/builder-mcp/builder-product avancent chacun sur
   leur branche ; toute adoption WEB se fait sur la base réconciliée, jamais sur merge
   spéculatif (règle : ne merge ni rebase aucune branche builder — orchestrateur).

## 7. Critères de feu vert (avant chaque lot)

1. **Lot 1** : branche Product réconciliée dans la base + `_domtest.mjs` et `test_interface.py`
   verts sur cette base (libellés réconciliés, C2).
2. **Lot 2** : `mission_id`/`detail_href` présents dans le polling (champs existants conservés).
3. **Lots 3–4** : `GET /api/missions` + `GET /api/missions/{mission_id}` livrés, tests fixtures
   CORE verts (contrat history §13 : ordre stable, curseur, 404, zéro jamais inventé, aucune
   donnée interdite).
4. **Lot 5** : `data.timeline` conforme `agnt.timeline.v1` (critères CORE du contrat timeline).
5. **Lot 6** : `data.executions[]` conforme `execution-status-v1.schema.json` ; provenance MCP
   additive ; Security : grammaires d'identifiants, allowlists transport/protocol, rédaction
   serveur vérifiées.
6. **Lot 7** : tous les lots précédents ; matrice §5 complète.
7. **Validation finale « RUN réel termine »** : machine bootstrapée (OPA épinglé + bwrap) —
   dans la sandbox actuelle (OPA/bwrap/outils absents, mesuré), seule la trajectoire
   `refuse`/`erreur` nommée est mesurable ; c'est une limitation environnementale caractérisée,
   pas un blocage du chantier.

## 8. Ce que WEB ne doit PAS reconstruire (liste explicite)

- Historique depuis le filesystem (`artifacts/missions/`), les bundles dogfooding,
  `localStorage`, fixtures ou données locales : **une seule source, `GET /api/missions`**.
- Liste `GET /api/runs` (temporaire), route parallèle, endpoint de fichiers, téléchargement
  d'artefacts ou de sorties brutes (décision Security, hors v1).
- Timeline frontend (store, tri, fusion events+timeline, streaming) : projection serveur lue
  telle quelle.
- Filtres Findings, vues globales Findings/Clusters/Rapports, recherche avancée (dodés v1).
- Nouveaux statuts mission, agrégation statut-mission depuis les lignes provider, scores de
  sécurité, retry/annulation.
- Zéros, statuts ou étabs « probablement » : absent = absent ou inconnu ; `rien_trouve` prouvé
  seulement par le backend.
- Données de démonstration présentées comme réelles ; fallback produit sur fixtures.
- Installation d'OPA/bwrap/outils pour « prouver » un RUN (limitation environnementale déjà
  caractérisée — §7.7).
- Pipeline, registre, policy, sandbox, modèles Finding, transports MCP : périmètres
  CORE/SECURITY/MCP, intouchés par WEB.

## 9. Points ouverts à réconcilier (non bloquants du document)

- **O1** — `arena/builder-core` à `4433af6` (mesuré) : les endpoints du §3 ne sont pas encore
  sur le remote ; les contrats sont prêts, l'implémentation attend.
- **O2** — Migration des artefacts de résultat `sortie` → `run` (signalée par CORE, contrat
  history §2) : le lecteur de détail doit passer par le lecteur canonique de mission, jamais
  de chemin durci des deux côtés.
- **O3** — Classification terminale structurée des événements de journal (contrat history §7) :
  ajout additif CORE attendu ; les lecteurs conservent le mapping legacy (cloture/arret).
- **O4** — Décision d'implémentation WEB déjà prise : **pas de test statique de ce document**
  (le livrable est le document seul ; les portes réelles sont `_domtest.mjs` +
  `test_interface.py` — un test de prose n'ajouterait pas de protection opérationnelle).
