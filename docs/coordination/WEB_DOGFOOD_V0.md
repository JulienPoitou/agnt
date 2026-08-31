# WEB DOGFOOD V0 — preuve du parcours propriétaire

**Agent :** QA-DOGFOOD — **Date :** 2026-08-31
**Branche :** `arena/01a058ea-agnt` — **Base :** `origin/main` `89bd3b1`

## Classification (honnête)

| Maillon du parcours | Verdict |
|---|---|
| 1. Charger l'interface | **PASS** — `GET /` sert la page ; bandeau `MAQUETTE` retiré dès que `api.py` répond |
| 2. Voir les cibles | **PASS** — 3 cibles proposées (`testrepo`, `labo_securite`, `dogfooding`), formulaire activé |
| 3. Soumettre une mission | **PASS** — clic RUN → `POST /api/runs` → `202` + id de file |
| 4. Observer le statut | **PASS** — `run <id> · en_file → refuse` suivi en ~1,5 s (polling réel, pas de spinner éternel) |
| 5. Lire résultat ou refus | **PASS** — refus affiché ET nommé : `refusé par la politique (fail-closed)` + motif `aucun outil exécutable dans ces conditions : aucun outil disponible sur cette machine` |
| 6. Revoir l'historique | **BLOCKÉ côté UI** — l'API le sert (`GET /api/missions`, `GET /api/missions/<id>` : 200, timeline 7 événements, statut `refuse` conservé) ; **la page ne l'expose pas** : aucune référence à `/api/missions` dans `app.js`/`index.html` (grep vérifié) |
| Rendu visuel (layout/pixel) | **NON ÉVALUÉ** — aucun navigateur graphique disponible dans ce sandbox (téléchargement Chromium bloqué : `ECONNRESET` sur `storage.googleapis.com` et `download-cdn.playwright.dev`, retours TLS `35`). La preuve est faite dans un DOM minimal (même contrat que `_domtest.mjs`), pas dans un Chromium |

## Preuve reproductible (3 commandes, 0 dépendance hors PyYAML)

```sh
# 1. Contrat HTTP de la page (green : 38/39, 0 échec, 1 non évaluée)
PYTHONPATH=/home/user/.pydeps python3 PHASE3/test_interface.py

# 2. Rendu `app.js` sur les artefacts réels (green : 103/103)
PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_domtest.mjs

# 3. Parcours complet contre l'API de production (green : 11/11)
PYTHONPATH=/home/user/.pydeps node PHASE3/interface/_smoke_parcours.mjs
```

Transcript du smoke : `docs/coordination/captures/web-dogfood-v0/smoke.json`
(résultat de la dernière course : mission `m-20260831T174909Z-e622abae` → refus → history OK).

## Ce qui marche

- Le parcours 1→5 est **réellement utilisable par le propriétaire sur cette machine** :
  le formulaire se branche sur la vraie API, une mission se lance, l'état terminal
  arrive, et le refus est un résultat **nommé** (jamais « 0 finding », jamais
  « terminé » à la place d'un refus, jamais spinner infini).
- L'historique API est en place et cohérent : la mission du run reparaît dans
  `/api/missions` avec son statut terminal, et `GET /api/missions/<id>` rend une
  timeline complète (`agnt.history.v1`, 7 événements, `missing_artifacts: []`).
- Les non-régressions utiles restent verrouillées : `test_interface.py` couvre
  désormais aussi le maillon 6 au niveau du contrat (run réel → liste → détail),
  et `_domtest.mjs` couvre le rendu de `app.js` (y compris refus, erreur, données
  hostiles, maquette).

## Ce qui bloque encore

1. **[BLOCKÉ — UI] Historique invisible dans le navigateur.** L'API est prête,
   la page ne la consomme pas (aucun appel `/api/missions` dans `app.js` ni
   d'élément d'historique dans `index.html`). Le propriétaire peut relire une
   mission via `curl /api/missions`, pas via l'écran.
   → **NEEDS-COORDINATION** : raccord UI = lot WEB-001/002 (déjà suivi dans
   `docs/coordination/PROJECT_STATE.md`, WEB bloqué par les gates Product/Security).
   Non corrigé ici : hors périmètre (pas de modification large de `app.js`).
2. **[BLOCKÉ — environnement] Aucun outil installé sur cette machine.** `opa`,
   `bwrap` et les scanners sont absents : chaque RUN s'arrête honnêtement au stade
   disponibilité (`aucun outil exécutable dans ces conditions`). Un vrai scan
   (`terminé` + findings) reste à prouver après `bootstrap.sh` — NON ÉVALUÉ ici,
   pas d'invention.
3. **[NON ÉVALUÉ] Rendu graphique réel.** Rejouer `_smoke_parcours.mjs` dans un
   navigateur headless (Chromium/Playwright) sur une machine où le téléchargement
   du binaire est autorisé, pour verrouiller le visuel.

## Prochain pas

1. Raccord UI de l'historique (WEB-001/002) — puis re-prouver le maillon 6 à l'écran.
2. `bootstrap.sh` sur une machine avec outils → rejouer les 3 commandes → passer le
   maillon 5 de « refus » à « résultat réel ».
3. Rejouer le smoke sous Chromium headless pour lever le verdict NON ÉVALUÉ du layout.
