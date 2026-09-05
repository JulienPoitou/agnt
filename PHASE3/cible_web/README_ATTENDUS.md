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
| T-AUTH-001 | `/login` (POST) puis `/admin/secret-session` | Session factice : jeton généré UNE FOIS au boot, émis en `Set-Cookie` par `/login`, exigé par la zone protégée | `curl -si -X POST -d 'user=alice&pass=x' http://127.0.0.1:8807/login` → 200 + `Set-Cookie: SESSION=…` ; sans cookie `curl -si http://127.0.0.1:8807/admin/secret-session` → 302 `Location: /login` ; avec `-b "SESSION=<token>"` → 200 « espace admin authentifié » + `RAPPORT-INTERNE-SESSION-THAUMAS-2026` |
| T-AUTH-002 | `/admin/secret-session?user=oscar` | IDOR : fiche d'un autre utilisateur servie sans contrôle de propriétaire | avec le cookie de session : `curl -si -b "SESSION=<token>" "http://127.0.0.1:8807/admin/secret-session?user=oscar"` → 200 + `DOSSIER-AUDIT-OSCAR-FACTICE` (fiche d'oscar) ; `?user=inconnu` → 404 |
| T-SRV-001 | (réponse) | Bannière serveur explicite | `Server: THAUMAS-WEB/1.0 Python/x.y` |
| T-GIT-002 | `/.git/*` | Dépôt git COMPLET servi (HEAD, objects, refs) | épreuve git-dumper : dump + checkout restaurés |

## Failles authentifiées

T-AUTH-001 et T-AUTH-002 ne sont visibles QU'AVEC le cookie de session obtenu via
`POST /login` : le jeton `SESSION` est généré une fois au boot et exigé partout —
sans lui, `/admin/secret-session` répond 302 vers `/login` et la route s'arrête là.
Un scan NON authentifié ne peut donc ni voir le secret ni sonder l'IDOR (`?user=`) ;
c'est l'épreuve du scan authentifié à venir : seul un provider qui présente le
cookie atteint les deux constats. Batterie : `python PHASE3/test_cible_auth.py`
(serveur éphémère sur 8809, repli 8819).

## Mode HTTPS (`--tls`) — épreuve des outils TLS

`python serveur.py 8443 --tls` : les MÊMES failles, servies en TLS. Le certificat
auto-signé est GÉNÉRÉ AU BOOT (`openssl req -x509`, clé 2048, dans `certs/` —
gitignoré, une clé privée ne se versionne jamais, même factice) :

| ID | Route | Faille | Vérification manuelle |
|---|---|---|---|
| T-TLS-001 | (mode --tls) | Certificat auto-signé CN=thaumas-web-epreuve (SAN IP:127.0.0.1, DNS:localhost) | `openssl x509 -in certs/cert.pem -noout -subject` ; les outils TLS relisent ce CN |

Comportements mesurés du mode TLS : le handshake est PAR CONNEXION (une sonde HTTP pur
au port TLS tue SA connexion, pas le serveur) ; les multi-slash sont normalisés
(`//admin/...` ≡ `/admin/...` — les scanners émettent la forme `{canonique}/FUZZ`,
l'oracle rejoue la forme brute du constat : sans normalisation, il réfuterait ce que
l'outil a réellement vu).

ATTENDUS TLS mesurés le 2026-09-05 (archives `qualif/<outil>/*_https.*` +
`attendus_tls.yaml`, relus par `test_plugins_g4.py` SANS réseau) :

- **sslscan** — 18 items : TLS 1.2 + TLS 1.3 enabled=1, 16 suites accepted
  (TLS_AES_256_GCM_SHA384 en tête), renégociation supported=0 (pas d'item). Cible en
  forme hôte:port (`{HOSTPORT}` — le manifest refuse l'URL, mesuré).
- **sslyze** — manifest runtime (scans de sélection, SANS `--certinfo`) : 6 commandes
  exécutées → 6 items (tls_1_2/tls_1_3_cipher_suites, session_renegotiation,
  tls_compression, heartbleed, openssl_ccs_injection). `--certinfo` est VOLONTAIREMENT
  hors manifeste : le PEM du certificat déclenche le masquage des blobs base64 (≥ 40
  caractères, jeu LARGE) qui rend le JSON capturé illisible → 0 item (mesuré, assumé) ;
  le certificat est couvert par testssl.sh et tlsx. La capacité COMPLÈTE (18 commandes
  dont certificate_info) est prouvée hors manifeste : `sslyze_complet.json`.
- **testssl.sh** — 166 entrées, code 0, sévérités DÉCLARÉES portées telles quelles :
  CRITICAL = cert_chain_of_trust (« failed (self signed) », note T), OK =
  TLS1_2/TLS1_3/cert_commonName, WARN = engine_problem (état de scan, jamais affiché
  comme une vulnérabilité).
- **tlsx** — 1 enregistrement JSONL : tls_version tls13, cipher
  TLS_AES_256_GCM_SHA384, subject_cn == issuer_cn == thaumas-web-epreuve
  (l'auto-signature se lit en rapprochant les deux champs), self_signed=true dans
  l'artefact brut. Mapping corrigé sur structure réelle (`cipher`, PAS `cipher_suite` ;
  `probe_status` booléen).

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
| graphql-cop | pas d'endpoint GraphQL sur la cible | route GraphQL de test |

### Providers à venir (vagues web)

nikto (T-SRV-001, T-ADMIN-001), dalfox (T-XSS-001), sqlmap (T-SQLI-001/002),
ffuf déjà qualifié (T-ADMIN-001, T-ENV-001, T-GIT-001 comme chemins découverts),
testssl (n/a — cible HTTP pur), nuclei (templates info : `/.env`, `/.git/config`).
