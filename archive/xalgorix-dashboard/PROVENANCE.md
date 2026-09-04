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

## Intégration (état au 2026-09-01)

**Le tableau de bord est branché sur le moteur réel** via
`PHASE3/interface/dashboard_api.py` : un serveur Python (aucune dépendance, même
style qu'`api.py`) qui sous-classe le `Gestionnaire` d'`api.py`, réutilise sa file
et son worker (`analyser.lancer()`), sert la SPA buildée et projette l'archive de
mission vers le contrat que la SPA lit.

```bash
cd dashboard/webui && npm run build          # une fois, ou après modification de la SPA
python3 PHASE3/interface/dashboard_api.py    # → http://127.0.0.1:8142
```

En dev (rechargement à chaud) : `cd dashboard/webui && VITE_API_TARGET=http://127.0.0.1:8142 npm run dev`.

Réel : cibles, capacités, historique des missions (scans), findings, journal
(onglet Events), rapport markdown (`/api/report/{id}`), lancement d'un run
(`POST /api/scan`). Refusé nommément (501) : arrêt, suppression d'archive,
planifications, chat, réglages en écriture — le moteur ne les a pas. Neutre :
WebSocket `/ws` non implémenté (le live feed affiche « déconnecté »), tokens/
itérations/RAM (mesures que le moteur ne produit pas).

## Intégration visée ensuite

Voir `docs/TACHES_RESTANTES.md` (section « Tableau de bord ») : remplacer la
grille « 22 phases » Xalgoryx par le registre des six étapes AGNT, brancher le
New Scan sur les capacités/confiances réelles, WebSocket, rebranding.

## Licence

Xalgoryx est sous Apache 2.0 : ce dossier reste réutilisable dans les termes de
cette licence, avec conservation des mentions d'origine (README d'origine
inclus). Le reste du dépôt agnt n'accorde pas de licence à ce stade.
