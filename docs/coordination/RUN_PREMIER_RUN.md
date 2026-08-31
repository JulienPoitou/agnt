# RUN_PREMIER_RUN — premier run réel, re-mesuré (session coordinée)

> **Session :** `arena/01a0585a-agnt` (rattrapage coordonné, docs uniquement + 2 lignes Livrable 2)
> **Base :** `main` `dfc412d` (merge PR #13) — worktree propre au départ, HEAD = `origin/main`.
> **Date/heure des mesures :** 2026-08-31, 15:09 → 15:22 UTC.
> **Règle de la session :** chaque affirmation ci-dessous est une mesure de CETTE
> session (commande, sortie, empreinte, horodatage). Aucune carte héritée n'est
> recopiée — les chiffres d'egress, en particulier, **varient par session**.

---

## 1. Environnement mesuré au départ

| Élément | Mesure |
|---|---|
| Python | 3.11.2 (`/usr/bin/python3`) ; PyYAML **absent** du système (requis par `bootstrap.sh` → venv) |
| `bwrap` | **absent** (`command not found`) — c'est le seuil d'exécution, voir §6 |
| `unshare --user --map-root-user true` | **rc=0** (mesuré 3×) ; à l'intérieur `id` → `uid=0(root) gid=0(root)` |
| `/proc/sys/user/max_user_namespaces` | **15734** |
| `sysctl kernel.unprivileged_userns_clone` | absent (noyau 6.1.158+, contrôle Debian `kernel.apparmor_restrict_unprivileged_userns` non présent) |
| Outils de mesure de paquets | `strace`, `tcpdump`, `iftop`, `ngrep` : **absents** → egress mesuré par proxy local (§5) |
| Réseau direct | `pypi.org` 200 (0.26 s) ; `registry.npmjs.org` 200 (0.05 s) ; `github.com` 200 (0.51 s) au 15:09 |

**Userns :** la création d'un user namespace fonctionne (15734 max, bascule root
réussie), mais **`bwrap` n'est pas installé** : l'isolateur est donc non exécutable,
le seuil mesuré du run réel, §6.

---

## 2. Armement OPA — commande et vérification

Commande (exacte) :

```sh
bash PHASE3/bootstrap.sh --armement opa
```

Mesure (15:13:00 → 15:13:30 UTC, rc=0) :

```
  OK  monteurs (mt-*, gitconfig) — local, rien téléchargé
==> fixture : recréation du dépôt git dans testrepo
==> fixture : recréation du dépôt git dans testrepo_xtool
==> fixture : recréation du dépôt git dans testrepo_go
  OK  fixtures (.git) — local, rien téléchargé
==> cache : /home/user/.cache/arena_secops
==> opa 0.70.0 (source épinglée du manifeste — ré-épinglage justifié dans manifeste_dependances.yaml)
  OK  opa
==> environnement prêt (composants demandés)
    cache      : /home/user/.cache/arena_secops   (43M)
    workspace  : 22M  (hors cache)
Version: 0.70.0
```

Vérifications indépendantes (15:14 UTC) :

| Contrôle | Résultat |
|---|---|
| `opa version` | `Version: 0.70.0` ; Build Commit `2ea031ea04e6a8afbc5dd22f656131dc3cfc5a7d` ; Build Timestamp `2024-10-31T19:39:52Z` ; go1.23.1 ; linux/amd64 ; `WebAssembly: unavailable` |
| SHA-256 du binaire posé | `00d114b94fdb1606a48cccdfc73c9ccdc62c38721150131ae578d5ff3df5c084` |
| SHA-256 attendu (manifeste `binaires.opa.sha256`) | `00d114b94fdb1606a48cccdfc73c9ccdc62c38721150131ae578d5ff3df5c084` — **identique** |
| SHA-256 du tarball npm épinglé (vérifié par `bootstrap.sh` → `verifier_archive`) | `f2bb77a025ba9a16e80c107852f5c8ab424730eb1d2db3a8f94a9f531a0b886b` == manifeste `tarball_sha256` |
| Source épinglée | `https://registry.npmjs.org/agent-control-specification-opa-linux-x64/-/agent-control-specification-opa-linux-x64-0.3.1-beta.0.tgz` |

---

## 3. Venv `/tmp` — reproduction du chemin du premier run

```sh
python3 -m venv /tmp/agnt-premier-run-venv
/tmp/agnt-premier-run-venv/bin/pip install --disable-pip-version-check \
    pyyaml "mcp==2.1.1" "bandit==1.9.4"
```

Mesure : **rc=0**, 7,8 s (15:12:45 UTC). Versions réellement installées :

| Paquet | Version |
|---|---|
| PyYAML | 6.0.3 |
| mcp | 2.1.1 (avec `mcp-types` 2.1.1, starlette 1.6.0, uvicorn 0.52.4, pydantic 2.13.5…) |
| bandit | **1.9.4** = épingle du manifeste (`binaires.bandit.version`) |

`bandit 1.9.4` est le seul outil de scan armable de la session (les autres —
semgrep, trivy, gitleaks, grype, kics, checkov, detect-secrets, trufflehog3,
ruff, radon, pip-audit, eslint — sont absents et leurs sources étant en partie
injoignables, cf. §5, ils n'ont **pas** été armés : `--armement outils-pip`
installerait dans le venv courant, mais les composants bloqués le restent).

---

## 4. Fixtures et points de montage

```sh
bash PHASE3/reconstruire_fixtures.sh
```

Sortie mesurée (15:14 UTC) : `testrepo : déjà initialisé` ×3, **rc=0** — les trois
dépôts git de fixtures (`.git` recréé par le bootstrap, lui-même idempotent) :
`PHASE3/testrepo`, `PHASE3/testrepo_go`, `PHASE3/testrepo_xtool`.

Points de montage (présents, créés par `preparer_monteurs` à 15:13 UTC) :

```
PHASE3/mt-scan  PHASE3/mt-regles  PHASE3/mt-db  PHASE3/mt-out  PHASE3/run
PHASE3/gitconfig (22 o)  PHASE3/gitconfig.ro (0 o)
```

Répertoires vides (quelques octets) — « bwrap ne crée pas les points de montage :
ils doivent exister avant l'appel » (commentaire de `sandbox.py`).

---

## 5. Egress PAR HÔTE — mesuré dans CETTE session

**Méthode :** proxy CONNECT local (`127.0.0.1:8899`, script Python, aucun MITM :
relais + comptage d'octets par hôte, `req` = client→amont, `rep` = amont→client)
posé autour de **toutes** les opérations de la session (pip, bootstrap OPA,
sondes de connectivité). Compteurs figés au `__stats__` à **15:15:53 UTC**
(dernier relevé exhaustif 15:15 / 15:19). Les octets sont ceux réellement
échangés par la session (TLS incluse — le tunnel compte le flux chiffré).

| Hôte | octets `req` (vers l'amont) | octets `rep` (reçus) | Connexions | Source / observation |
|---|---:|---:|---:|---|
| `registry.npmjs.org` | 900 | **21 042 357** (20,1 Mio) | 1 | tarball OPA épinglé (bootstrap) |
| `pypi.org` | 23 832 | 3 569 012 (3,4 Mio) | 1 | index pip (venv) |
| `files.pythonhosted.org` | 23 328 | **12 194 757** (11,6 Mio) | 1 | wheels (pyyaml, mcp, bandit) |
| `codeload.github.com` | 1 604 | 6 042 983 (5,8 Mio) | 2 | probe + tarball réel `refs/heads/main` (6 019 591 o, HTTP 200) |
| `github.com` | 2 403 | 299 134 | 3 | page repo + redirections release |
| `openpolicyagent.org` | 517 | **0** | 1 | TLS reset — `SSL_ERROR_SYSCALL` |
| `semgrep.dev` | 517 | **0** | 1 | TLS reset — `SSL_ERROR_SYSCALL` |
| `raw.githubusercontent.com` | 517 | **0** | 1 | TLS reset — `SSL_ERROR_SYSCALL` |
| `deb.debian.org` | 517 | **0** | 2 | TLS reset (https **et** http) |
| `objects.githubusercontent.com` | 517 | **0** | 1 | cible réelle des assets de release GitHub (asset trivy `v0.74.0`) — TLS reset |
| `release-assets.githubusercontent.com` | 517 | **0** | 1 | probe direct — TLS reset |

**Total mesuré de la session :** ~43,1 Mio d'octets reçus (et ~34,2 kio envoyés).
**Carte de session (à ne pas recopier ailleurs) :** joignables = npm, pypi,
files.pythonhosted, github.com, codeload.github.com ; **injoignables** (TLS coupé)
= openpolicyagent.org, semgrep.dev, raw.githubusercontent.com, deb.debian.org,
objects/release-assets.githubusercontent.com. C'est ce qui explique : OPA vient
du **paquet npm** (pas d'openpolicyagent.org), `raw.githubusercontent.com` bloqué
casse `armer_trivy` (install.sh), semgrep.dev bloqué casse `armer_regles_semgrep`.

---

## 6. Run réel — pipeline en bibliothèque, cible ABSOLUE, `with_internes=True`

Commande (exacte, sans proxy, PATH = venv + cache armé) :

```sh
env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy \
  PATH=/tmp/agnt-premier-run-venv/bin:$HOME/.cache/arena_secops/bin:$PATH \
  PYTHONPATH=/home/user/agnt/PHASE3/slice \
  /tmp/agnt-premier-run-venv/bin/python3 /tmp/run_premier.py
```

(`run_premier.py` : `pipeline.executer("Analyse la sécurité de mon dépôt",
Path("/home/user/agnt/PHASE3/testrepo"), avec_internes=True)` ; `run_premier2.py`
ajoute un `PolicyEngine` enregistreur qui lit **la vraie** sortie OPA.)

### 6.1 Run n° 1 — 15:13:58 UTC (mission `m-20260831T151358Z-0d5a9665`)

- Cible consignée (`mission.json`) : `{"type":"repository","reference":"/home/user/agnt/PHASE3/testrepo","local":true,"chemin":"/home/user/agnt/PHASE3/testrepo"}` — cible **typée repository**, chemin absolu.
- `confiance_cible=controlled`, `cible_autorisee=true`, profil `controlled_dev`, `egress` : demandé par le **profil** → `autorise: false`.
- Intention : `resolved`, 7 capacités (« demande générique ») — dont les capacités **internes** `CODE_STATIC_ANALYSIS_SUITE` et `CODE_STATIC_ANALYSIS_CUSTOM` (portées par bandit).
- Disponibilité : **13 providers écartés** (semgrep, semgrep_go, trivy, grype, pip_audit, gitleaks, detect_secrets, trufflehog3, checkov, kics, ruff_lint, radon_cc, eslint_js) — « exécutable introuvable … ce n'est pas « rien trouvé » » ; **bandit et bandit_custom restent sélectionnables**.
- **Plan : `plan_id = 81ec7fc4f2ee1faf`**, providers `[bandit, bandit_custom]` (seul provider PASSIF déclaré, priorité 100).
- Contexte : `run_id=bee6e91f13a905fb`, `contexte_empreinte=6c68a2846fde1b95`, `input_digest=b01ecd1ecf3f6f45`, `input_commit=79584b9a1174818c905c8cd06dc87955c4872bd8`, working tree **propre**.
- **Décision OPA : `allow=true`** (le pipeline a franchi la policy — preuve : exécution tentée ; confirmée en 6.2 par la sortie brute).
- **Jusqu'où ça va :** `arret: execution_bandit` →
  `SandboxError: sandbox inutilisable : base Trivy introuvable : /home/user/.cache/arena_secops/trivy-cache`
  (dans `Sandbox.verifie()`, **avant** bwrap : le sandbox exige l'existence de la base Trivy pour toute exécution, y compris un plan bandit seul). Ledger final : `non_disponible=13, sélectionné=1, échoué=1, exécuté=0`.

### 6.2 Run n° 2 — 15:14:37 UTC (mission `m-20260831T151437Z-ff27060f`)

Mutation **explicite et bornée** : `/home/user/.cache/arena_secops/trivy-cache`
créé **vide** — seule condition d'existence manquante, pour mesurer le seuil
suivant (la base Trivy n'est pas armée : `--armement trivy-db` n'a pas été
demandé ; aucun contenu n'a été fabriqué).

- **Plan : `plan_id = 81ec7fc4f2ee1faf`** (identique — plan déterministe).
- **Décision OPA réelle (brut de `opa eval` 0.70.0) : `{"allow":true,"motifs":[]}`**.
- Contexte : `run_id=cea151baf3b5a8b1`, `contexte_empreinte=dc4194f48bef3939` (diffère de 6.1 : la base Triy "existe" désormais — l'empreinte de contexte reflète l'environnement, pas le code ; `input_digest` et `input_commit` **identiques**).
- **Jusqu'où ça va — SEUIL BWRAP :** `arret: execution_bandit` →
  `FileNotFoundError: [Errno 2] No such file or directory: 'bwrap'`
  (`subprocess.Popen` à `sandbox.py:377`, après `verifie()` passée). Le run a donc
  franchi : intention → disponibilité → applicabilité → conditions → plan →
  **OPA (allow)** → garde de chemin → capture de contexte → **premier Popen
  d'outil** → bwrap absent. C'est le seuil annoncé : la seule barrière restante
  de cette machine.

**En clair :** bandit est armé (venv, 1.9.4) et sélectionné ; aucune exécution
d'outil n'a eu lieu — le seuil bwrap est atteint avant tout lancement sous cage.

---

## 7. API — lancement exact et POST `/api/runs` (chemin, pas nom)

Lancement (mesuré 15:16 UTC, port 8141, `--host 0.0.0.0`) :

```sh
PATH=/tmp/agnt-premier-run-venv/bin:$HOME/.cache/arena_secops/bin:$PATH \
  /tmp/agnt-premier-run-venv/bin/python3 PHASE3/interface/api.py \
  --host 0.0.0.0 --port 8141
```

> **Note de mesure :** l'API est un processus ; pour que le PATH survive dans le
> service (le worker lit `shutil.which` avec l'environnement du processus), le
> lancement se fait dans un shell qui **exporte** PATH avant `exec` (vérifié par
> `/proc/<pid>/environ` : `bandit` et `opa` résolus). Un simple préfixe `VAR=… cmd`
> n'a pas été fiable dans le superviseur de cette session — mesuré deux fois.

Vérifications HTTP (mesurées 15:16–15:17 UTC) :

| Requête | Réponse |
|---|---|
| `GET /api/cibles` | 3 cibles : `testrepo`, `labo_securite`, `dogfooding` — chaque entrée porte `{"nom": …, "chemin": "/home/user/agnt/PHASE3/…"}` |
| `POST /api/runs` `{"cible":"testrepo", "question":"Analyse la sécurité de mon dépôt"}` | **HTTP 400** — `{"erreur":"cible hors de la liste admise","admises":[…3 chemins absolus…]}` |
| `POST /api/runs` `{"cible":"/home/user/agnt/PHASE3/testrepo","question":"Analyse la sécurité de mon dépôt"}` | **HTTP 202** — `{"id":"5c31211bf29a","statut":"en_file","position":1}` |
| `GET /api/runs/5c31211bf29a` | `statut:"refuse"`, `code:2` — `motif:"aucun outil exécutable dans ces conditions : aucun outil disponible sur cette machine"`, mission `m-20260831T151700Z-3f383f37` |

**Nuance mesurée :** via l'API, le run publié est `refuse` **avant** OPA
(arrêt `disponibilité`) : l'interface n'active pas `with_internes`, donc les
capacités internes `CODE_STATIC_ANALYSIS_SUITE/CUSTOM` (bandit) ne sont pas
sélectionnées et les 5 capacités publiques n'ont aucun outil armé sur cette
machine. La décision `refuse` est **nommée** (motif de disponibilité, pas un
500), et le run bibliothèque (§6), lui, franchit OPA — c'est la différence que
le doc doit garder : le « premier run de bout en bout » est celui de §6.

---

## 8. Ce que cette session n'a PAS pu mesurer

- Exécution réelle de bandit sous bwrap (bwrap absent) — reste `NON ÉVALUÉ`, comme la base `AUDIT_E2E.md` ligne 8.
- Compilation OPA `WebAssembly: unavailable` (binaire npm) : la policy est évaluée par `opa eval` (mesurée : `{"allow":true}`), pas en WASM.
- `deb.debian.org`, `semgrep.dev`, `raw.githubusercontent.com`, assets GitHub, `openpolicyagent.org` : **injoignables** depuis cette session (TLS coupé) — toute affirmation « X est téléchargeable » doit être re-mesurée, pas héritée.

## 9. COMMANDE EXACTE (bloc final)

```sh
# 1. Armement OPA (tarball npm épinglé, SHA-256 vérifié par le script)
bash PHASE3/bootstrap.sh --armement opa

# 2. Venv du premier run (dans /tmp)
python3 -m venv /tmp/agnt-premier-run-venv
/tmp/agnt-premier-run-venv/bin/pip install pyyaml "mcp==2.1.1" "bandit==1.9.4"

# 3. Fixtures + montures (locales, idempotentes)
bash PHASE3/reconstruire_fixtures.sh

# 4. API — PATH = bin du venv ET ~/.cache/arena_secops/bin
export PATH=/tmp/agnt-premier-run-venv/bin:$HOME/.cache/arena_secops/bin:$PATH
exec /tmp/agnt-premier-run-venv/bin/python3 PHASE3/interface/api.py \
  --host 0.0.0.0 --port 8141

# 5. POST /api/runs — cible = CHEMIN ABSOLU (jamais le nom)
curl -sS -X POST http://127.0.0.1:8141/api/runs \
  -H "Content-Type: application/json" \
  -d '{"cible":"/home/user/agnt/PHASE3/testrepo","question":"Analyse la sécurité de mon dépôt"}'
# → 202 {"id":"…","statut":"en_file","position":1}
# {"cible":"testrepo"} → 400 "cible hors de la liste admise"
```
