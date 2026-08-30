# History / Timeline / Status — Gate de sécurité (P1)

> **Règle centrale.** CORE produit une projection sûre. SECURITY la teste de
> façon hostile. WEB ne corrige jamais une fuite à la place du serveur.
>
> Ce gate est l'outil de SECURITY : il **refuse** les projections dangereuses,
> il ne les **assainit** pas. Un gate qui réécrit les données créerait un second
> chemin de sécurité, contournable, et cacherait la fuite au serveur.

---

## 1. Ce que c'est

`PHASE3/history_timeline_gate.py` — validateur déterministe qui reçoit une ou
plusieurs projections JSON (History / Timeline / Status) et rend un verdict :

```text
PASS
FAIL — [code] projection.data.timeline[2].label : explication générique
```

Le verdict est **toujours générique** : chemin JSON + code + explication. La
valeur fautive (secret, chemin, payload) n'est jamais reflétée — le gate ne
doit pas devenir le canal de sortie de la donnée qu'il refuse.

Trois lois de construction, vérifiées par
`PHASE3/test_history_timeline_security.py` :

1. **Aucun lecteur de Mission** — le validateur n'importe que la bibliothèque
   standard et ne lit aucun fichier du workspace (vérifié statiquement). Il
   juge ce que la projection **déclare**, jamais ce qui existe ailleurs.
2. **Aucun assainissement** — l'entrée n'est pas modifiée, le verdict ne porte
   aucune donnée de sortie (champs `ok` et `raisons` uniquement).
3. **Aucune fuite dans ses propres messages** — testé sur toutes les fixtures
   hostiles : aucune valeur qui déclenche une règle de contenu n'apparaît dans
   le texte du verdict.

## 2. Usage

```bash
# corpus de fixtures (mode par défaut du harnais)
python3 PHASE3/test_history_timeline_security.py

# gate en ligne de commande
python3 PHASE3/history_timeline_gate.py --fixture-mode docs/coordination/fixtures
python3 PHASE3/history_timeline_gate.py --response-file reponse.json --now 2026-08-30T12:00:00Z
python3 PHASE3/history_timeline_gate.py --base-url http://127.0.0.1:8141 [--mission-id m-…]

# import dans un futur consommateur WEB (validation avant affichage)
from history_timeline_gate import valider_projection  # sys.path += PHASE3
verdict = valider_projection(reponse, horloge=...)
```

| Mode | Entrée | Sortie |
|---|---|---|
| `--fixture-mode REP` | enveloppes `TEST ONLY` | un verdict par fixture, comparé au verdict attendu inscrit dans l'enveloppe |
| `--response-file F` | réponse JSON capturée (sans enveloppe) | `PASS` ou `FAIL` + raisons |
| `--base-url URL` | API CORE réelle : `GET /api/missions` puis chaque `GET /api/missions/{id}` | un verdict par endpoint |

Codes de sortie : `0` = tout PASS · `2` = au moins un FAIL · `1` = usage /
réseau / forme inattendue (la cause est affichée sans refléter le corps reçu).
Déterminisme : même entrée + même horloge (`--now`, paramètre `horloge`) =>
même verdict. Les corpus de test figent une horloge (`now` de l'enveloppe).

## 3. Fixtures

`docs/coordination/fixtures/security-history-timeline-*.json` — 81 scénarios.
Chaque fichier est une **enveloppe de test**, jamais une réponse API :

```json
{
  "_marker": "TEST ONLY — NEVER SERVE AS PRODUCT DATA",
  "scenario": "Bearer token dans un libellé d'événement",
  "now": "2026-08-30T12:00:00Z",
  "expect": {"verdict": "FAIL", "codes": ["secret-bearer"]},
  "response": { … projection jugée … }
}
```

Règles du corpus :

* le marqueur est obligatoire — `--fixture-mode` refuse toute enveloppe non
  marquée (une fixture ne doit jamais pouvoir être confondue avec de la donnée
  produit) ;
* `expect.verdict` : `PASS` ou `FAIL` ; `expect.codes` : codes **attendus**
  (l'ensemble doit être contenu dans le verdict réel : une fixture qui échoue
  « pour une autre raison » est un échec du harnais — on ne ferme pas une faille
  par accident) ;
* `response` est une projection **pure** (sans enveloppe) : elle peut donc être
  rejouée à l'identique via `--response-file`.

Couverture : secrets (13 emplacements), chemins et artefacts (14), journal
hostile/inconnu (16), provenance MCP (14), statuts et compteurs mensongers (18).

## 4. Règles d'allowlist (à approuver pour l'implémentation CORE)

Le gate ne crée pas de contrat Product : il formalise les **exigences Security**
sur la forme attendue. Quand `agnt.history.v1`, `agnt.timeline.v1` et
`agnt.execution-status.v1` seront livrés, ce schéma devra être **re-lié** à
leurs noms de clés ; en attendant, une clé inconnue est un refus
(`cle-inconnue`) — c'est le signal du re-bind, pas un défaut à contourner.

### Champs admis sous contrôle (clés autorisées)

| Emplacement | Clés |
|---|---|
| racine | `api` (contrat connu), `endpoint` (`/api/missions` ou `/api/missions/{mission_id}`), `data` |
| détail | `mission_id`, `statut`, `created_at`, `run_id`, `providers`, `executions`, `findings_count`, `findings_artifact`, `timeline`, `contradictions`, `provenance`, `complet`, `partiel`, `policy` |
| liste | `mission_id`, `statut`, `created_at`, `run_id`, `findings_count` |
| provider | `provider_id`, `provider_kind`, `availability`, `reason_code`, `provenance` |
| exécution | `provider_id`, `statut`, `started_at`, `finished_at`, `findings_count`, `sortie_non_normalisee`, `anomalie`, `provenance` |
| événement | `seq`, `ts`, `type`, `label`, `conflict` |
| contradiction | `code`, `message` |
| provenance MCP | `provider_id`, `provider_kind`, `transport`, `server_id`, `tool_id`, `protocol`, `confidence`, `source`, `provider_declared`, `availability`, `request_id`, `correlation_id` |
| policy | `moteur`, `decision`, `disponible`, `motif` |

### Champs interdits ou à redacter (présence = refus, valeur vide comprise)

`argv`, `command`/`cmd`, `env`/`environ`/`environment`, `executable`, `cwd`,
`chdir`, `mount`, `shell`, `stdout`, `stderr`, `traceback`/`stack_trace`,
`headers`/`authorization`, `cookie`/`session`, `token`/`access_token`/`api_key`,
`secret(s)`, `password`, `private_key`, `credential(s)`, `payload`/`body`,
`raw`/`raw_output`/`brut*`, `url`/`uri`/`download_url`, `endpoint` (hors
racine), `path`/`file_path`/`absolute_path`/`cache_path`, `sandbox`,
`filesystem`/`inode`/`mtime`/`size`/`mode`, `erreur_distante`,
`detail_technique`, `erreur_brute` …

Un refus de clé signifie : **CORE doit redacter en amont** ; WEB ne doit pas
avoir à décider si le contenu d'une telle clé est dangereux.

### Vocabulaires contrôlés (valeurs)

| Champ | Valeurs admises (TEMP — à confirmer) |
|---|---|
| `api` | `agnt.history.v1` · `agnt.timeline.v1` · `agnt.execution-status.v1` |
| `statut` (mission) | `en_file` · `en_cours` · `termine` · `refuse` · `erreur` · `annulee` · `conflict` · `rien_trouve` |
| `statut` (exécution) | `termine` · `echoue` · `timeout` · `annulee` · `refuse` · `en_cours` · `non_lancee` · `indisponible` |
| `availability` (provider) | `disponible` · `non_disponible` · `degradee` · `inconnue` |
| `reason_code` / `anomalie` | `opa_indisponible` · `egress_bloque` · `binaire_absent` · `grille_regles_absente` · `artefact_absent` · `sortie_non_normalisee` · `timeout` · `annulation` · `refus_politique` · `provenance_inconnue` · `mcp_indisponible` · `erreur_parse` |
| `source` (provenance) | `mcp` · `agnt` · `mesuree` — **jamais** `local` / `default` |
| `confidence` | `inconnue` · `faible` · `moyenne` · `elevee` |
| `transport` | `stdio` · `sse` · `websocket` · `http` · `grpc` · `inconnu` (**TEMP MCP**) |
| `protocol` | `mcp` · `jsonrpc` · `http` · `https` · `grpc` · `inconnu` (**TEMP MCP**) |
| `decision` (policy) | `autorisee` · `refuse` · `refusee` · `non_evaluee` |

**Règle anti-invention** : une valeur inconnue est un **refus** (`*-inconnu`),
jamais une valeur ramenée à une valeur valide. Les vocabulaires
transport/protocole sont explicitement temporaires : ils seront confirmés avec
MCP avant toute mise en production.

**Séparation des couches** — statut de mission, disponibilité de provider,
résultat d'exécution et résultat de détection ne partagent pas le même
vocabulaire (`vocabulaire-confondu`) : une disponibilité ne peut pas valoir
`termine`, et une exécution ne peut pas valoir `disponible`. Les mots de cycle
de vie partagés (`termine`, `en_cours`, `refuse`, `annulee`) restent admis
entre mission et exécution — ce sont des couches, pas des dialectes.

## 5. Invariants de la timeline

* `seq` : entier ≥ 0, obligatoire, **unique**, strictement croissant, sans
  trou (`seq-manquant`, `seq-non-numerique`, `seq-duplique`, `seq-non-croissant`,
  `seq-trou`). `seq` est la source d'ordre ; aucune étape n'est inventée, aucune
  n'est supposée à partir d'un trou.
* `ts` : ISO 8601 avec fuseau, **obligatoire dans la timeline** (une histoire
  sans temps n'est pas vérifiable), non antérieur à `created_at`, non postérieur
  à l'horloge de référence (± 5 s), cohérent avec l'ordre des `seq`
  (`ts-absent`, `ts-invalide`, `ts-anterieur`, `ts-futur`, `ts-en-desordre`).
  Ailleurs (`created_at`, `started_at`…), un horodatage absent est admis.
* Type d'événement **inconnu** : autorisé uniquement sous forme générique sûre
  (`type` + `seq` + `ts` + `label`), **sans payload ni champ supplémentaire**
  (`evenement-inconnu-non-generique`). Le gate ne transforme jamais cet
  événement ; il vérifie que CORE l'a déjà rendu générique.
* **Une seule histoire** : `data.events` et `data.timeline` en même temps sont
  un refus (`duplication-events-timeline`). `timeline` est l'unique source
  d'ordre.

## 6. Statuts et compteurs

`rien_trouve` / `findings_count: 0` ne sont acceptés **que si** l'exécution est
réellement terminée, invoquée, couverte, normalisée et sans contradiction :

| Règle | Refus quand |
|---|---|
| `zero-sans-execution` | zéro sans aucune exécution déclarée |
| `zero-provider-sans-execution` | un provider disponible n'a ni exécution ni anomalie déclarée |
| `zero-statut-non-terminal` | une exécution est `timeout`, `annulee`, `refuse`, `echoue`, `en_cours`… |
| `zero-sortie-anormale` | `sortie_non_normalisee` ou anomalie de parse |
| `zero-artefact-absent` | `findings_artifact: absent` (le compteur est inconnu, pas zéro) |
| `zero-opa-indisponible` | moteur de politique indisponible sous statut rassurant |
| `zero-refus-politique` | décision de refus sous statut rassurant |
| `zero-egress-bloque` | sortie refusée / provider non exécuté sous statut rassurant |
| `mission-sans-run` | statut terminal rassurant sans `run_id` |
| `mission-partielle-resolue` | `complet: false` / `partiel: true` sous statut rassurant |
| `contradiction-resolue` | `contradictions` non vide **et** statut rassurant |
| `contradiction-sans-preuve` | statut `conflict` **sans** objet de contradiction |

Une contradiction est **explicitement marquée** `conflict`, jamais résolue vers
l'état le plus rassurant. Le gate ne choisit pas l'un des deux états : il refuse
la résolution silencieuse.

## 7. Règles de contenu (valeurs balayées récursivement)

Chaque chaîne de la projection est passée une fois au crible (un seul point
d'entrée : pas de double signalement) :

secrets — Bearer, JWT, `sk_*`/`pk_*`, GitHub `ghp_*`/`gho_*`, AWS `AKIA*`,
clé privée (bloc `-----BEGIN … PRIVATE KEY-----`), GitLab `glpat-*`, Google
`AIza*`, Slack `xox*`, URL avec userinfo ou token, en-tête Authorization,
cookie/session, variable d'environnement sensible, affectation de credential,
tout URL brute (`endpoint-url`) ;

chemins — `/home/…`, `/Users/…`, `/tmp|var|etc|…`, `C:\…`, `../`, montages
sandbox (`mt-scan`, `mt-regles`, `mt-out`, `mt-db`), `arena_secops`, `PHASE3/`,
`docs/coordination`, caches locaux, `raw_*`/`brut_*`, extraits de ligne de
commande (`--config=`, `--report-path=`, `gitleaks git`…) ;

contenu non normalisé — trace de pile, HTML/script exécutable, `javascript:`.

## 8. Intégration

**CORE** — la projection doit être sûre **à la source** (redaction serveur,
pas de fallback client). Le gate valide l'existence des champs, pas la véracité
des artefacts : ce que la projection déclare (`findings_artifact: present`) est
une promesse de CORE. Le gate vérifie que CORE ne s'auto-contredit pas ; il ne
va pas lire le disque pour corroborer.

**MCP** — champs de provenance adoptés tels qu'annoncés (`provider_id`,
`provider_kind`, `transport`, `server_id`, `tool_id`, `protocol`, `confidence`,
`availability`, `request_id`, `correlation_id`). À confirmer : vocabulaire
**définitif** de `transport`/`protocol` (allowlists temporaires ci-dessus),
normalisation des `request_id`/`correlation_id` (le gate n'accepte que des
identifiants au format strict ; un identifiant contenant un secret déclenche
TOUJOURS une règle de contenu), et le sens exact de `provider_kind`.

**WEB** — après un verdict PASS uniquement. Jamais de sanitization côté
client (une fuite passée par le gate doit faire corriger CORE, pas être
masquée à l'écran) ; jamais d'affichage de clés inconnues ; une réponse FAIL
est un état bloquant, pas un « à nettoyer ».

## 9. Modes d'échec connus et limites

* Le validateur ne lit pas les artefacts : il ne peut pas détecter une
  projection qui serait vraie dans sa forme mais fausse dans son fond (un
  `findings_count: 0` conforme aux règles est encore une promesse de CORE).
* Le gate est **strict** sur les clés inconnues : c'est voulu (le re-bind aux
  contrats Product est un point de revue Security, pas un contournement).
* Contrats Product **absents de ce workspace** (vérifié sur toutes les
  branches et tous les commits) : le schéma ci-dessus est une attente
  Security, à re-lier ; `test_history_timeline_security.py` le signale
  explicitement (`NON ÉVALUÉ · re-lien …`).
