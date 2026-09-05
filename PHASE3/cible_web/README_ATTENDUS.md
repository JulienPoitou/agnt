# THAUMAS-WEB — cible d'épreuve : failles plantées et ATTENDUS

Cible permanente de qualification des providers web. Stdlib Python uniquement,
écoute sur `127.0.0.1` uniquement, secrets tous factices. ~20 Mo de RAM.

Lancement : `python PHASE3/cible_web/serveur.py 8807`

## Failles plantées (IDs de test)

| ID | Route | Faille | Vérification manuelle |
|---|---|---|---|
| T-ENV-001 | `/.env` | Secrets factices exposés | `curl http://127.0.0.1:8807/.env` → 200 avec `DB_PASSWORD=…` |
| T-GIT-001 | `/.git/config` | Dépôt git exposé | 200 avec `[remote "origin"]` |
| T-XSS-001 | `/search?q=<b>x</b>` | XSS réfléchie non échappée | la balise est rendue telle quelle dans la page |
| T-TRAVERSAL-001 | `/download?file=../cible_web_secret/sauvegarde.txt` | Path traversal hors racine | 200 avec `SAUVEGARDE-CONFIDENTIELLE-QUALIF` |
| T-SQLI-001 | `/users?id=1 OR 1=1` | SQLi SQLite par concaténation | les 3 utilisateurs sont renvoyés |
| T-SQLI-002 | `/users?id='` | Erreur SQL brute exposée | 500 avec `erreur SQL : …` |
| T-ADMIN-001 | `/admin` | Panneau d'admin sans authentification | 200 « Aucune authentification requise » |
| T-SRV-001 | (réponse) | Bannière serveur explicite | `Server: THAUMAS-WEB/1.0 Python/x.y` |
| T-GIT-002 | `/.git/*` | Dépôt git COMPLET servi (HEAD, objects, refs) | épreuve git-dumper : dump + checkout restaurés |

## ATTENDUS par provider

### httpx (WEB_HTTP_PROBE) — qualifié le 2026-09-05

Sonde la racine : 1 finding par URL vivante.

- sortie brute de référence : `epreuve_httpx.jsonl`
- extraction prouvée par le cœur (`extraction.py`, modèle `lignes_json`) :
  `url`, `regle` = code HTTP (200), `nom_regle` = titre de page, `message` = bannière
  serveur + version Python, `preuve` = URL sonnée
- PAS de sévérité : une sonde est de la cartographie, pas un constat de vulnérabilité
- preuve sandbox bwrap : **produite le 2026-09-05** (`qualif/` — bwrap 0.9.0, egress
  autorisé, stabilité contenu normalisé True, code 0) (WSL arrêté au moment de l'épreuve)

### git-dumper (WEB_VCS_DUMP) — qualifié le 2026-09-05

Dump du dépôt git complet servi sous `/.git/` (T-GIT-002).

- fixture : `_git_fixture/` (généré au démarrage du serveur, commit unique avec
  `secret_app.txt` contenant le marqueur `GIT-DUMP-OK-THAUMAS-2026`)
- sortie brute de référence : `_gitdump_log.txt` (22 fichiers récupérés, code 0,
  `[-] Running git checkout .` exécuté)
- vérification du dump : `secret_app.txt` restauré avec le marqueur, `git log`
  lisible — l'impact est PROUVÉ, pas supposé
- parser nommé `gitdumper` (`slice/parsers_gitdumper.py`) : 1 constat
  « dépôt .git exposé et restauré », confiance confirmée, preuve = chemins [200],
  CWE-538, PAS de sévérité (jamais inventée)
- preuve sandbox bwrap : **produite le 2026-09-05** (`qualif/DOSSIER_web.yaml` —
  2 exécutions stables, dump restauré DANS la sandbox, marqueur relisible :
  `qualif/gitdumper/dump_reference/` et `dump_stabilite/`)

### Reportés (raison documentée)

| Outil | Raison du report | Pré-requis |
|---|---|---|
| wapiti | build wheel échoue sans toolchain C Windows | WSL (VM VMware à fermer) |
| tlsx | cible HTTP pur, pas de TLS à sonder | serveur HTTPS sur la cible |
| graphql-cop | pas d'endpoint GraphQL sur la cible | route GraphQL de test |

### Providers à venir (vagues web)

nikto (T-SRV-001, T-ADMIN-001), dalfox (T-XSS-001), sqlmap (T-SQLI-001/002),
ffuf déjà qualifié (T-ADMIN-001, T-ENV-001, T-GIT-001 comme chemins découverts),
testssl (n/a — cible HTTP pur), nuclei (templates info : `/.env`, `/.git/config`).
