# WEB DOGFOOD V0 — note de preuve du gate console V0

**Agent :** QA-DOGFOOD — **Date :** 2026-08-31
**Gate :** `console-v0` (branche `arena/01a058ea-agnt`, base `origin/main` `89bd3b1`)

## Matrice (dernier rejeu — transcript machine)

| # | Maillon | Verdict | Preuve |
|---|---|---|---|
| 1 | Chargement console | **PASS** | `GET /` + `app.js` réel évalué, bandeau MAQUETTE retiré, état `run <id> · refuse` |
| 2 | Cibles remontées | **PASS** | 3 cibles (`testrepo`, `labo_securite`, `dogfooding`), formulaire activé |
| 3 | Soumission mission | **PASS** | `POST /api/runs` → HTTP 202 + id de file ; clic RUN page → id affiché |
| 4 | Évolution statut | **PASS** | polling réel → `en_file → refuse` en ~0,9–1,5 s, état terminal atteint |
| 5 | Résultat/refus lisible | **PASS** | `refusé par la politique (fail-closed)` + motif `aucun outil exécutable dans ces conditions : aucun outil disponible sur cette machine` ; jamais « 0 finding » |
| 6 | Historique API | **PASS** | `GET /api/missions` 200 (100 missions), détail 200 `agnt.history.v1`, timeline 7 événements `complete` |
| 7 | Historique UI | **BLOCKED** | aucune référence `/api/missions` dans `app.js` et aucun élément d'historique dans `index.html` (lecture directe des fichiers servis) — l'API est prête, la page ne l'affiche pas |
| 8 | Cas non heureux | **PASS** | cible `/etc` → 400 + 3 alternatives nommées ; run inconnu → 404 qui redit l'id ; machine sans outils → refus nommé, pas de faux zéro |
| 9 | Rendu `app.js` (DOM) | **PASS** | `_domtest.mjs` 103/103 (artefacts réels, refus, erreur, données hostiles, maquette) |
| 10 | Layout navigateur réel | **NON ÉVALUÉ** | aucun binaire navigateur ; téléchargements bloqués dans ce sandbox (TLS/ECONNRESET sur `storage.googleapis.com`, `download-cdn.playwright.dev`, miroir npmmirror) |

**Synthèse :** 8 PASS · 1 BLOCKED · 1 NON ÉVALUÉ · 0 FAIL.

## Ce qui est prouvé

Les maillons 1→6 + 8 + 9 sont mesurés sur l'**API et la page de production réelles**
(le serveur `api.py` est démarré par le gate ; `app.js`/`index.html` sont exécutés tels
quels). Le parcours propriétaire « charger → cibles → lancer → suivre → lire refus » est
**fonctionnel dans les limites de cette machine** (voir « non évaluable »). L'historique
côté API est complet et cohérent avec le run.

## Ce qui est bloqué

- **Maillon 7 (BLOCKED) : l'historique n'est pas câblé dans la page.** Mesure directe,
  pas une opinion : `grep -n '/api/missions' PHASE3/interface/app.js PHASE3/interface/index.html`
  → 0 résultat ; aucun élément d'historique dans `index.html`. Ce maillon ne peut pas être
  confondu avec une panne : il est classé BLOCKED (pas câblé), pas FAIL.
  → **NEEDS-COORDINATION** WEB-001/002 (déjà suivi dans `docs/coordination/PROJECT_STATE.md`,
  WEB bloqué par les gates). Non corrigé ici : hors périmètre.

## Ce qui reste non évaluable DANS CE SANDBOX

- **Maillon 10 : layout/pixel réel.** Pas de Chromium/Firefox ; les downloads de binaires
  sont bloqués (mesuré 3 fois, dont miroir alternatif). Le rendu est donc jugé en DOM
  minimal (maillon 9) — un jugement de contrat, pas un jugement visuel.
- **Un vrai scan avec findings** (statut `terminé`) : aucun outil installé ici (`opa`,
  `bwrap`, scanners) ; chaque RUN s'arrête honnêtement au stade disponibilité. Non
  évaluable avant `bootstrap.sh` sur une machine outillée — pas de vert inventé.

## Commandes exactes pour rejouer

```sh
# 1. Gate complet (maillons 1–10, matrice machine + transcript JSON)
PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_gate_console_v0.mjs
#    → sortie console + docs/coordination/captures/web-dogfood-v0/gate-console-v0.json
#    → code 0 si aucun FAIL ; code 1 si FAIL (ou avec AGNT_GATE_STRICT=1 si un seul ≠ PASS)

# 2. Marche par marche (les deux sous-suites rejouées par le gate)
PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_smoke_parcours.mjs   # page + API réelles
PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_domtest.mjs           # rendu sur artefacts réels

# 3. Contrat HTTP de la page (suite CORE, non modifiée par ce gate)
PYTHONPATH=/home/user/.pydeps python3 PHASE3/test_interface.py

# 4. Mesure du layout réel (sur une machine avec navigateur installé)
AGNT_BROWSER_BIN=$(which chromium) PYTHONPATH=/home/user/.pydeps \
  node PHASE3/interface/_gate_console_v0.mjs
```

Transcripts : `docs/coordination/captures/web-dogfood-v0/gate-console-v0.json`
(depuis `606aa70` : 8 PASS / 1 BLOCKED / 1 NON ÉVALUÉ / 0 FAIL, ~6 s) et
`…/smoke.json` (rejeu page).

## Prochain pas (hors périmètre QA, à coordonner)

Après WEB-001/002 (raccord UI `/api/missions`) puis `bootstrap.sh` : rejouer les 4
commandes ci-dessus — le gate classifiera alors 7 en PASS et devrait passer le maillon
5 du refus au résultat réel, sans réanalyse du dépôt.
