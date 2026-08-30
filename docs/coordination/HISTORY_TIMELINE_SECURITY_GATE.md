# History / Timeline / Status — Gate de sécurité (P1, re-lié aux contrats Product)

> **Règle centrale.** CORE produit une projection sûre. SECURITY la teste de
> façon hostile. WEB ne corrige jamais une fuite à la place du serveur.
>
> **Qui possède quoi.** **Product** (`docs/coordination/api-conformance-gate`
> + contrats versionnés `agnt.history.v1`, `agnt.timeline.v1`,
> `agnt.execution-status.v1`) est l'autorité du **contrat de transport HTTP** :
> noms de champs, enveloppes, types, enums, ordre, pagination, preuves
> dimensionnelles. **Security** est un **complément d'exposition** : il ne
> redéfinit aucun nom de champ, n'invente aucune seconde enveloppe publique et
> ne juge pas la conformité à la place de Product — il ajoute ce que la
> conformité ne couvre pas : fuites de contenu, profondeur des compteurs,
> contradictions masquées, provenance non fiable, extensions refusables,
> fail-closed.

---

## 1. Ce que c'est

`PHASE3/history_timeline_gate.py` — validateur déterministe qui reçoit une
réponse JSON **brute** au format Product (History list / détail / Timeline /
Execution Status) et rend un verdict :

```text
PASS
FAIL — [code] projection.data.timeline.events[2].safe_summary : explication générique
```

Le verdict est **toujours générique** : chemin JSON + code + explication. La
valeur fautive (secret, chemin, payload) n'est jamais reflétée.

Trois lois de construction, vérifiées par
`PHASE3/test_history_timeline_security.py` :

1. **Aucun lecteur de Mission** — bibliothèque standard uniquement, aucun
   fichier du workspace lu. Le gate juge ce que la projection **déclare**,
   jamais ce qui existe ailleurs.
2. **Aucun assainissement** — l'entrée n'est pas modifiée (testé par clonage
   avant/après) ; le verdict ne porte que `ok` + `raisons`.
3. **Aucune fuite dans ses propres messages** — testé sur les fixtures
   hostiles : aucune valeur déclenchant une règle de contenu n'apparaît dans
   le verdict, ni dans les sorties du runner (`--response-file` sur une
   réponse hostile : code 2, sortie sans le secret, sans traceback).

## 2. Usage

```bash
# harnais (les deux interpréteurs doivent être verts)
python3 PHASE3/test_history_timeline_security.py        # 46/46
.venv/bin/python PHASE3/test_history_timeline_security.py

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
| `--fixture-mode REP` | enveloppes `TEST ONLY` | un verdict par fixture, comparé au verdict attendu |
| `--response-file F` | réponse JSON brute Product (sans enveloppe) | `PASS` ou `FAIL` + raisons |
| `--base-url URL` | API réelle : `GET /api/missions` puis chaque `GET /api/missions/{id}` | un verdict par endpoint |

Codes de sortie : `0` = tout PASS · `2` = au moins un FAIL · `1` = usage /
réseau / forme inattendue (cause affichée sans refléter le corps reçu).
Déterminisme : même entrée + même horloge (`--now`, paramètre `horloge`) =>
même verdict ; les fixtures figent une horloge (`now` de l'enveloppe).

## 3. Fixtures

`docs/coordination/fixtures/security-history-timeline-*.json` — **88**
scénarios. Chaque fichier est une **enveloppe de test** (jamais une réponse
d'API publique) :

```json
{
  "_marker": "TEST ONLY — NEVER SERVE AS PRODUCT DATA",
  "scenario": "Bearer token dans un libellé d'événement",
  "now": "2026-08-30T09:10:00Z",
  "expect": {"verdict": "FAIL", "codes": ["secret-bearer"]},
  "response": { … réponse JSON BRUTE au format Product … }
}
```

Règles du corpus :

* marqueur obligatoire — `--fixture-mode` refuse toute enveloppe non marquée ;
* `expect.verdict` : `PASS` ou `FAIL` ; `expect.codes` : codes **attendus**
  (ensemble inclus dans le verdict réel : une fixture qui échoue « pour une
  autre raison » est un échec du harnais) ;
* `response` est une réponse **pure** Product, rejouable à l'identique via
  `--response-file` (après retrait du marqueur `$fixture`).

Couverture : captures Product sûres (9/9 acceptées), contenu (secrets,
chemins, artefacts, commandes, HTML, traces), structure stricte (clés
inconnues, compteurs, séquences, curseurs), profondeur (faux zéros,
contradictions, conflits, états inconnus), provenance MCP (identifiants,
transport/protocole temporaires, confiance). Le générateur
(`/tmp/gen_fixtures.py`, hors dépôt) régénère le corpus avec auto-vérification.

**Preuves d'acceptation Product** (harnais, lecture `git show` de
`origin/arena/01a05425-agnt` — branche jamais extraite ni modifiée) :
`list.json`, `empty-list.json`, `status-filter.json`, `target-filter.json`,
`detail.json` + `mission-history-list/detail`, `mission-timeline-complete`,
`mission-timeline-refused-partial` → **9/9 PASS** ; les 18 cas
`execution-status-cases.fixture.json` → **PASS**.

## 4. Re-liage aux contrats Product — comment ça fonctionne

Le gate ne copie pas les contrats comme seconde source de vérité : le harnais
**lit les schémas et le product gate sur la branche Product** et vérifie au
moment du test que les constantes du gate sont identiques :

* clés strictes : `listResponse`, `page`, `detailResponse`, `artifacts`,
  `findingsSummary`, `contributors`, `event` (legacy), racine timeline,
  `source`, `references`, `provenance`, `protocol`, `confidence`, `event`
  timeline, racine execution-status, `baseDimension`/`availability`/
  `execution`/`detection`/`completeness` ;
* enums : statuts mission, applicabilité, sélection, condition, autorisation,
  disponibilité, exécution, détection, preuves, complétude, états timeline,
  visibilités, conséquences, catégories, données, `provider_kind`,
  confiance, disponibilité de provenance ;
* versions `agnt.history.v1` / `agnt.timeline.v1` / `agnt.execution-status.v1`.

Le product gate (`product_api_gate.py`) juge la **conformité** (types, enums,
`if/then` de l'exécution, `oneOf` du temps, ordre de liste, cohérence
`returned_events`, `validate_submission_distinction`, `check_safe_payload` de
base). Security ne rejoue pas cette conformité : il la **complète**.

### Objets STRICTS (`additionalProperties: false`) — extension = refus

Une clé hors contrat dans un objet strict est un refus `cle-inconnue`
(ex. `page`, `request`, `artifacts`, `findingsSummary`, `contributors`,
racines list/detail/timeline/execution, `source`, `references`,
`provenance`, `protocol`, `confidence`, événements). C'est le signal de
re-bind, pas un contournement.

### Objets EXTENSIBLES (`additionalProperties: true`) — extension tolérée

`summary`, `target`, `detail.data` (et donc `data.timeline`,
`data.execution_status_schema`, extensions produit) : les clés inconnues sont
**acceptées** (mais leur contenu est balayé). Une clé **interdite** reste un
refus **partout**, y compris dans les objets extensibles et récursivement
(`cle-interdite`).

### Clés interdites (présence = refus, valeur comprise)

`argv`, `command`/`cmd`/`commands`, `env`/`environ`/`environment`,
`executable`/`exe`, `cwd`, `chdir`, `mount`/`mounts`, `shell`, `stdout`,
`stderr`, `traceback`/`stack`/`stack_trace`/`backtrace`, `exception_detail`,
`headers`/`header`, `authorization_header` (`authorization` est un **nom de
dimension** du contrat execution-status, pas un en-tête : autorisé),
`cookie`/`cookies`/`session`/`set_cookie`, `token`/`access_token`/
`refresh_token`/`api_key`, `secret(s)`, `password`/`passwd`/`pwd`,
`private_key`, `credential(s)`, `payload`/`body`, `raw`/`raw_*`/`brut*`,
`download_url`/`artifact_url`, `endpoint`, `server_url`, `socket`,
`file_path`/`local_path`/`absolute_path`/`storage_path`/`sandbox_path`/
`sandbox`/`filesystem`/`inode`/`mtime`/`mode`/`worktree`/`home_dir`/
`tmp_dir`/`cache_dir`/`cache_path`/`git_dir`/`repo_path`,
`reponse_brute`/`erreur_brute`/`erreur_distante`/`detail_technique`/`dumps`.

Les clés **ambigües** (`path`, `url`, `uri`…) ne sont pas interdites en tant
que clés : leurs **valeurs** sont balayées. `file`/`location` (relatifs) de
findings restent autorisés — ils font partie du contrat Product.
L'union des clés interdites Security ⊇ `FORBIDDEN_KEYS` du product gate
(vérifié par le harnais).

### Vocabulaires

Tous les vocabulaires de valeurs (statuts, dimensions, preuves, états,
provenance, limitations, artefacts manquants) sont **ceux des schémas
Product** (voir la table du §3 des contrats). Écart particulier, partagé par
le contrat lui-même : `termine`, `en_cours` et `inconnu` existent à la fois
dans le statut mission et `execution.value` — **admis** ; une valeur issue
d'une autre couche **sans** partage légitime (`disponible`, `echoue`,
`findings_presents`…) reste refusée (`vocabulaire-confondu`).

### Vocabulaires MCP temporaires (à confirmer par MCP)

`transport` (`stdio` · `sse` · `websocket` · `http` · `grpc` · `inconnu`) et
`protocol.name` (`mcp` · `jsonrpc` · `http` · `https` · `grpc` · `inconnu`)
sont des **allowlists temporaires** : valeur inconnue = refus
(`transport-inconnu`, `protocol-inconnu`), jamais convertie. Les données
Product actuelles exposent `stdio` + `mcp` — compatibles. Ces vocabulaires
ne sont **pas** déclarés définitifs sans confirmation directe de la branche
MCP. Règle complémentaire : `confidence.level: high` avec
`basis: provider_declared` est refusé (`confiance-non-corroboree`) — une
déclaration de provider n'est pas une vérification AGNT (les données Product
exposent `medium` + `provider_declared`, acceptées).

## 5. Invariants de la timeline

* `source.sequence` : entier ≥ 1, obligatoire, unique, strictement croissant,
  sans trou non déclaré (`seq-manquant`, `seq-non-numerique`, `seq-duplique`,
  `seq-non-croissant`, `seq-trou`) ; `ordering` doit être
  `journal_sequence_ascending`. La séquence est la source d'ordre ; un trou
  doit être déclaré `history_gap_detected` dans `limitations`.
* `position` : entier ≥ 1, aligné sur l'ordre de réponse
  (`position-invalide`, `position-incoherente`, `position-dupliquee`) ;
  `event_id` = `m-…:séquence` (`identifiant-invalide`,
  `evenement-id-incoherent`, `evenement-duplique`) ; une timeline ne mélange
  jamais deux missions (`mission-melangee`).
* `time` : enregistré ⇒ `timestamp` présent, ISO 8601 avec fuseau, non
  antérieur à `created_at`, non postérieur à l'horloge (± 5 s)
  (`ts-absent`, `ts-invalide`, `ts-anterieur`, `ts-futur`) ; état
  `unavailable`/`redacted` ⇒ **pas** d'horodatage (`ts-incoherent`).
  Le temps est **affiché**, jamais utilisé pour ordonner.
* Événement **inconnu** : uniquement sous la forme générique Product exacte
  (`kind: unknown_event_recorded`, `category: unknown`, `data_state:
  unavailable`, `limitations` incluant
  `projection_version_unsupported`, `visibility: technical`) —
  sinon `evenement-inconnu-non-generique` (le gate ne normalise jamais).
* `truncated` ↔ `next_cursor` cohérents (`curseur-manquant`,
  `curseur-incoherent`) ; `state: complete` sans limitation de dégradation ;
  `state: unavailable` exige une limitation de journal
  (`timeline-incoherente`) ; `data.events` (legacy) reste **indépendant** de
  `data.timeline` — jamais fusionné.
* `safe_summary` : 1–240 caractères, mono-ligne (`controle-interdit`).

## 6. Statuts, compteurs et profondeur

| Règle | Refus quand |
|---|---|
| `mission-sans-run` | statut `termine` sans `run_id` rattaché |
| `inconnu-sans-incomplete` | statut `inconnu` sans `incomplete: true` |
| `incomplet-sous-statut` | `incomplete: true` sous un statut prouvé |
| `zero-sans-artefact` | total de findings `0` avec artefact findings non lisible déclaré |
| `compteur-sans-artefact` | `findings_summary` présent sans `artifacts.findings: true` |
| `compteur-contradictoire` | somme par sévérité ≠ total ; ou findings déclarés par une exécution alors que la mission compte 0 |
| `compteur-non-evalue` | `findings_count` présent pour une détection `non_evalue`/`inconnu` |
| `rien-trouve-incomplet` | zéro sans exécution `termine` + `invocation: oui` + `output: exploitable` + `analyzed_targets ≥ 1` + complétude `complete` |
| `findings-non-prouves` | findings déclarés sans exécution terminée ni compteur positif |
| `execution-incoherente` | `termine` sans invocation/sortie exploitable ; `non_lance`/`unavailable` avec sortie déclarée |
| `conflict-resolu` | `completeness.state: conflict` sous mission `termine` |
| `preuves-absentes` | mission terminée sans timeline ni exécutions |
| `inconnu-sans-preuve` | état inconnu sans marqueur (via `incomplete`) |
| `compteur-non-evalue` / `compteur-invalide` / `compteur-negatif` | booléen déguisé, null obligatoire, valeur négative |

Une contradiction est **explicitement marquée** `conflict`, jamais résolue vers
l'état le plus rassurant. Les champs optionnels Product (`duration_ms`,
`clusters_count`) acceptent `null` ; un compteur **obligatoire** ne l'accepte
pas.

## 7. Règles de contenu (valeurs balayées récursivement, un seul point d'entrée)

Chaque chaîne de la projection est passée une fois au crible (pas de double
signalement) : secrets — Bearer, JWT, `sk_*`/`pk_*`, GitHub `ghp_*`, AWS
`AKIA*`, clé privée, GitLab `glpat-*`, Google `AIza*`, Slack `xox*`, URL avec
userinfo ou token, en-tête Authorization, cookie/session, variable
d'environnement sensible, affectation de credential ; chemins — `/home/…`,
`/Users/…`, `/tmp|var|etc|opt|usr|bin|srv|mnt…`, `C:\…`, `../`, montages
sandbox, `PHASE3/`, `docs/coordination`, caches locaux (`\.cache`,
`.venv`, `node_modules`), `raw_*`/`brut_*`, extraits de ligne de commande
(`--config=`, `--report-path=`, `gitleaks git`, `semgrep `) ; contenu non
normalisé — trace de pile, HTML/script exécutable, `javascript:`.

Faux positifs écartés et testés : `Bearer`, `AKIA`, `sk_`, `--config`,
`token absent` seuls ne déclenchent rien ; `on\w+=` ne matche pas
`--config=` ; `authorization` (dimension) n'est pas une clé interdite.

## 8. Intégration

**CORE (agnt-core)** — la projection doit être sûre **à la source**. Le gate
valide la forme et l'auto-cohérence, pas la véracité des artefacts : ce que la
projection déclare (`artifacts.findings`, `findings_count`) est une promesse
de CORE.

**MCP** — champs de provenance tels qu'annoncés (`provider_id`,
`provider_kind`, `transport`, `server_id`, `tool_id`, `protocol`,
`confidence`, `availability`, `request_id`, `correlation_id`) ; à confirmer :
vocabulaire définitif `transport`/`protocol` (allowlist temporaire),
normalisation des `request_id`/`correlation_id` (format strict ; un
identifiant contenant un secret déclenche toujours une règle de contenu).

**Product** — `product_api_gate.py` reste l'autorité de conformité ; le gate
Security ne doit pas être utilisé pour valider la conformité à sa place, ni
copié dans CORE/WEB comme second product gate.

**WEB** — après un verdict PASS uniquement. Jamais de sanitization côté
client ; jamais d'affichage de clés inconnues ; une réponse FAIL est un état
bloquant, pas un « à nettoyer ».

## 9. Modes d'échec connus et limites

* Le validateur ne lit pas les artefacts : il ne détecte pas une projection
  vraie dans sa forme mais fausse dans son fond (un `findings_count: 0`
  conforme est encore une promesse de CORE).
* L'absence de contrat Product n'est plus un cas « NON ÉVALUÉ » : le harnais
  **exige** la branche Product (`origin/arena/01a05425-agnt`) pour la parité
  schémas et les captures — si elle est absente, les vérifications échouent
  explicitement (le re-bind est une exigence, pas une option).
* Le gate est strict dans les objets STRICTS du contrat : une clé inconnue
  est un refus (`cle-inconnue`) — extension non approuvée par Security ;
  dans les objets EXTENSIBLES, elle est tolérée mais balayée.
