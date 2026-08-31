# Vérification navigateur — matrice réelle gate-002 (design-lab)

**Date :** 2026-08-31 · **Branche :** `arena/01a05837-agnt` · **Base :** `main @ 5f5e09d6`, rebasé sur `main @ 16eeb4f` (le déplacement de main pendant la session touchait bootstrap/DevOps, sans recouvrement)

## Périmètre

Rattrapage honnête du « raccord aux captures » : la session précédente avait DÉCRIT un
raccordement aux 16 captures gate-002 qui n'existait pas. Ce document atteste le raccord
réel, commit par commit, avec les captures d'écran faites en navigateur.

| Étape | Commit | Contenu |
|---|---|---|
| 1. Nettoyage | `b16ed0d` (+ fix `12a8455`) | suppression des copies « front » du gate Python (`data/product_api_gate.py`, `data/test_product_api_gate.py`), du doublon `data/examples/` et de la copie fixture `public/data/examples/` ; PROVENANCE.md réécrit (source = `main @ 5f5e09d6`, dossier `docs/coordination/captures/gate-002-product-api/`) |
| 2. Matrice | `c608cf2` | 18 fichiers copiés **octet pour octet** (17 corps de réponses + manifeste) dans `public/data/gate-002-product-api/`, vérifiés par `diff -r` ; `src/lib/api.ts` typé en Zod sur les champs RÉELS des captures (aucun champ inventé, aucun absent rendu en zéro) ; `tsc --noEmit` : 0 erreur |
| 3. États non-heureux | `3cfb777` | chaque état branché sur SA capture, URL `?v=<body_file|mission_id>` |
| 4. Vérification | ce commit | 18 états réellement visités en Chromium headless, captures d'écran ci-dessous |

## Faits vérifiés sur la source

- Les captures canoniques venaient du checkout : `docs/coordination/captures/gate-002-product-api/`
  (17 réponses HTTP réelles de l'API CORE + `capture-manifest.json` ; 16 cas `FULL_COVERAGE`
  du gate, rejeu mesuré par CORE : 1467 PASS · 0 FAIL · 0 SKIP).
- Le gate vit côté `docs/` : vérifié le 2026-08-31, `docs/coordination/api-conformance-gate/`
  (`product_api_gate.py`, son test, son README, ses fixtures) existe sur la branche PRODUCT
  `arena/01a05425-agnt @ 3f96e25` — `git ls-tree` exécuté, pas supposé. Il n'est PAS encore
  mergé dans `main` ; c'est pourquoi des copies traînaient dans le front. Elles n'y ont rien à
  faire : supprimées, sans recopie vers `docs/` (hors périmètre du labo).

## Ce que chaque vue affiche (et depuis quelle capture)

| Vue (URL `?v=`) | Capture branchée | Écran |
|---|---|---|
| accueil (pas de param) | manifeste complet | `verification/00-accueil.png` |
| `list.json` | `GET /api/missions?limit=25` → 200, 11 items | `verification/01-liste.png` |
| `pagination-probe.json` | `?limit=1` → 200, `next_cursor` réellement publié | `verification/02-pagination-probe.png` |
| `status-filter.json` | `?status=termine` → 200, 7 items TERMINÉS | `verification/03-filtre-status.png` |
| `target-filter.json` | `?target_type=repository` → 200, 9 items | `verification/04-filtre-cible.png` |
| `empty-list.json` | `?status=en_file` → 200 + `items: []` — vide prouvé, ni erreur ni refus | `verification/05-liste-ide.png` |
| `invalid-filter.json` | `?status=__agnt_invalid_status__` → **HTTP 400**, message verbatim | `verification/06-filtre-invalide-400.png` |
| `m-…0001` | zéro finding PROUVÉ : `rien_trouve` + 3 cibles analysées + complétude | `verification/10-detail-zero.png` |
| `m-…0002` | 2 findings normalisés + 1 cluster `c1` | `verification/11-detail-findings.png` |
| `m-…0003` | refus pré-Run : `non_autorise` + `policy_denied`, jamais zéro | `verification/12-detail-refuse.png` |
| `m-…0004` | binaire absent : `indisponible` + `binary_missing`, détection `non_evalue` | `verification/13-detail-indisponible.png` |
| `m-…0005` | code retour 1 : `échouée` + `local_failure` | `verification/14-detail-echoue.png` |
| `m-…0006` | deadline : `expirée (deadline)` + `deadline_exceeded` | `verification/15-detail-expiree.png` |
| `m-…0007` | annulée : `mission_closed_while_running` | `verification/16-detail-annulee.png` |
| `m-…0008` | cible url écartée à l'applicabilité : `target_not_applicable` | `verification/17-detail-non-applicable.png` |
| `m-…0009` | incomplet : 6 `missing_artifacts` listés, rien de fabriqué | `verification/18-detail-incomplet.png` |
| `m-…000a` | `unknown_event_recorded` : « payload jamais publié » | `verification/19-detail-evenement-inconnu.png` |
| `m-…000b` | provenance MCP brute (allowlist projetée), `mcp_dep` | `verification/20-detail-mcp.png` |
| liste, mobile 420 px | comme ci-dessus en responsive | `verification/30-liste-mobile.png` |
| détail zero, mobile 420 px | idem | `verification/31-detail-zero-mobile.png` |

## Invariants d'affichage mesurés en navigateur (pas seulement en type)

- **inconnu ≠ zéro** : toute mission sans `findings_summary` affiche « inconnu — aucun compte
  publié dans cette capture » (visible sur 03/05/06/07/08/09/10 des détails). Le front ne
  remplace JAMAIS une absence par 0 ; `detection: non_evalue` affiche aussi « aucun compte publié ».
- **zéro = positif prouvé** : seule la mission 01 affiche le bandeau « Zéro finding prouvé »,
  avec `analyzed_targets: 3` et complétude.
- **refusé ≠ échoué ≠ non exécuté ≠ non applicable ≠ expiré ≠ annulé** : rendus par des tokens
  distincts (`refuse` vs `erreur` vs `non_lance` vs `non_applicable` vs `timed_out` vs
  `cancelled`) avec leur `reason_code` (`policy_denied`, `local_failure`,
  `mission_stopped_before_execution`, `target_not_applicable`, `deadline_exceeded`,
  `mission_closed_while_running`).
- **liste vide ≠ erreur ≠ refus** : `empty-list` est une vue 200 à part ; `invalid-filter` est
  une vue 400 à part, aucune des deux ne passe par une liste de missions.
- **journal vs legacy** : les compteurs `data.timeline` (renvoyés/total) et `data.events`
  (legacy) sont affichés séparés, légendés « jamais fusionnés ».
- **curseurs réels** : `next_cursor: null` s'affiche « null · page finale » ; le curseur de la
  pagination-probe s'affiche en extenso dans l'attribut title (capture visuelle tronquée,
  valeur non inventée).
- **artefacts manquants** : chips listées (plan/run/findings/clusters/report/coverage pour la
  mission 09) avec la mention « données jamais fabriquées par le front ».
- **provenance** : rendue en bloc JSON brut sur `mcp_dep` uniquement ; le front ne déduit aucun
  `provider_kind` absent.

## Méthode de vérification (rejouable)

```sh
npm run dev -- -H 0.0.0.0 -p 3000   # preview ouverte
# puis visite des 18 URLs /dashboard?v=… en Chromium headless (playwright-core),
# screenshot fullPage 1440x900 + assertions de texte dans le DOM + comptage des lignes.
```

Résultats bruts de l'automate : 18/18 états OK sur leurs assertions (le 19e enregistrement est
le comptage des lignes : liste 11, status 7, cible 9, pagination 1 — égal aux fichiers
sources). `pageerror` : aucun. Erreurs réseau console : uniquement le beacon
`va.vercel-scripts.com` (analytics hérité du template, egress du sandbox coupé) — sans lien
avec les données ; à neutraliser lors du re-habillage.

## Limites connues (déclarées, pas cachées)

- La capture ne contient pas la page 2 de la pagination (curseur publié, page suivante absente
  du jeu) : le front l'affiche comme tel, il ne simule pas la page suivante.
- Cas `mcp` = projection vérifiée seulement (aucun serveur MCP réel) — même limite que le
  README canonique des captures, rappelée dans le rail.
- Le re-habillage « Trusted Evidence » complet (directions UX du labo branchées sur la même
  matrice) est une passe ULTÉRIEURE, volontairement hors de ce raccord.
- `index.html`/`app.js` (v1 statique « 20 directions ») restent l'exploration UX d'origine ;
  ils ne touchent plus aux données et ne sont pas branchés sur le contrat.
