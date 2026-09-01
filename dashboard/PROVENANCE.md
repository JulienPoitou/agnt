# Provenance de `dashboard/`

Ce dossier est le **tableau de bord** du projet. Il est repris du dashboard web
de **Xalgoryx**, publié sous licence **Apache 2.0** (badge licence du README
d'origine). Il a été extrait de GitHub le 2026-09-01 (archive
`xalgorix_dashboard_web.zip`) et inséré ici tel quel.

## Contenu

- `webui/` — la partie utilisée : SPA React 19 / Vite 8 / Tailwind 4
  (pages overview, scans, findings, live feed, schedules, settings…).
  En dev, un plugin Vite lance automatiquement `mock-backend.mjs` (port 8787,
  proxy `/api`) : le tableau de bord est donc démontrable sans backend réel.
- `internal/web/` — le backend Go d'origine (serveur, sessions, orchestrateur).
  **Non exécuté** dans ce projet : conservé tel quel comme référence des
  contrats d'API (`/api/*`) attendus par la SPA.
- `Makefile`, `docker-compose.yml`, `README.md` — outillage d'origine.

## Intégration visée

Le backend réel d'agnt est `PHASE3/interface/api.py` (moteur Python). Le plan
d'intégration est d'adapter le client `webui/src/api/client.ts` et les types
`webui/src/types/api.ts` aux points d'entrée de cette API (cibles, capacités,
runs, journal), sur le modèle de ce qui a été fait pour la console `src/`
(PR #19). D'ici là, la SPA tourne sur le mock.

## Licence

Xalgoryx est sous Apache 2.0 : ce dossier reste réutilisable dans les termes de
cette licence, avec conservation des mentions d'origine (README d'origine
inclus). Le reste du dépôt agnt n'accorde pas de licence à ce stade.
