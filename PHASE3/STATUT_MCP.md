# Intégration MCP — statut de validation

Date de la vérification : **2026-08-30 UTC**.
Rejeu complet : **2026-08-31 UTC** sur `6e04ff8` (voir « Rejeu du 31/08 » ci-dessous).

## Rejeu du 31/08 (session `arena/01a05760-agnt`)

Batterie rejouée intégralement sur l'arbre `6e04ff8` après fast-forward depuis `4433af6`,
avec un venv reconstruit (`/tmp/agnt-venv` + `pyyaml`) et le SDK interop réinstallé
(`mcp==2.1.1`, hors dépôt). **104/104 cas passent**, comptes identiques au 30/08 :

```text
test_mcp.py            23/23   INTEGRATION SIMULATED (transport en mémoire)
test_mcp_contract.py   16/16
test_mcp_e2e.py        17/17   INTEGRATION SIMULATED (ThreadingHTTPServer MCP loopback)
test_mcp_policy_gate.py 3/3
test_mcp_stdio.py       8/8    processus Python réel, sans shell
test_mcp_http_cancel.py 17/17  annulation par fermeture TCP réelle
test_mcp_interop.py    20/20   REAL — SDK officiel Model Context Protocol 2.1.1, stdio
```

### Régression trouvée par le rejeu — corrigée

`be68844` a ajouté `cible_type=` à l'appel `moteur.evaluer(...)` dans `pipeline.py`
(l. 531 et l. 662) sans mettre à jour les doubles de `PolicyEngine` côté tests. Conséquence
mesurée : `test_adversaire.py` s'arrêtait sur
`TypeError: EngineJouee.evaluer() got an unexpected keyword argument 'cible_type'`
au lieu de mesurer les gardes — la campagne adversariale était silencieusement désarmée.

Contrôle de référence exécuté dans un worktree détaché sur `4433af6` : la campagne y va
jusqu'au bout (`46 cas · 41 PASS · 2 FAIL · 3 NON ÉVALUÉS`). Après alignement de la signature
des doubles sur `PO.PolicyEngine.evaluer`, la ligne MCP redonne exactement
`46 cas · 41 PASS · 2 FAIL · 3 NON ÉVALUÉS`. Les 2 FAIL restants (`D4` armement de
`cible_autorisee`, `G6a` règles de détection de secrets) sont **antérieurs à la ligne MCP**
et appartiennent à SECURITY (`e5838003`) — ils ne sont pas absorbés ici.

Aucune attente de test n'a été modifiée ou adoucie : seule la signature des doubles a été
alignée. `test_utilisation.py` a reçu le même alignement **à titre préventif** — ce chemin est
**NON EXERCÉ** dans cet environnement (binaire OPA absent), l'échec y est identique sur
`4433af6` et sur `6e04ff8`.

### Note technique transmise à CORE / SECURITY (non absorbée)

`pipeline.py` passe `cible_type="repository"` en **dur** à `moteur.evaluer(...)` (l. 531, l. 662),
alors que le type de cible réellement retenu est dérivé plus bas, par provider, dans `_vague`
(`prov.target_types` → `repository` **ou** `filesystem`, l. 266-270). Le registre déclare bien
des providers `filesystem` (`detect_secrets` : `target_types: ['repository','filesystem']`),
donc l'entrée OPA peut annoncer `cible.type = "repository"` pour une exécution `filesystem`.

Impact : une règle OPA qui distinguerait `repository` de `filesystem` recevrait un fait faux.
Non corrigé ici volontairement : le type de cible est un contrat **CORE→MCP/SECURITY/PRODUCT**
(`Cible(type, reference, chemin_local=None)`) et son évolution relève de CORE-005 / MCP-004,
explicitement suspendus. À traiter dans l'intégration coordonnée, pas dans un chantier MCP isolé.


## Verdict par fonctionnalité

| Fonctionnalité | Statut | Preuve / limite |
|---|---|---|
| Contrat `capability ↔ provider ↔ transport ↔ backend` | **IMPLEMENTED + VERIFIED** | `test_mcp_contract.py` : 16/16 |
| Binding registre ↔ capability ↔ serveur ↔ outil | **IMPLEMENTED + VERIFIED** | chargement validé sans découverte réseau ; outil absent refusé |
| Sélection, plan, policy input et cible typée | **IMPLEMENTED + PARTIALLY VERIFIED** | plan/policy input testé ; évaluation OPA bloquée sans binaire |
| Garde policy/egress avant transport | **IMPLEMENTED + VERIFIED** | `test_mcp_policy_gate.py` : 3/3 avec double ; moteur OPA réel bloqué par environnement |
| Validation locale de schéma et d'arguments | **IMPLEMENTED + VERIFIED** | `test_mcp.py` : refus avant construction du transport |
| Handshake, découverte et appel JSON-RPC | **IMPLEMENTED + VERIFIED** | faux transport + HTTP/stdio/Streamable HTTP locaux + SDK Python MCP indépendant 2.1.1 en stdio |
| Transport stdio sans shell + transport HTTP/Streamable HTTP | **IMPLEMENTED + VERIFIED** | stdio indépendant et HTTP/Streamable HTTP contrôlés ; pas de compatibilité générale revendiquée |
| Interopérabilité avec une implémentation indépendante | **IMPLEMENTED + VERIFIED** | `mcp==2.1.1` officiel, `MCPServer`, stdio local : `test_mcp_interop.py` 20/20 |
| Timeout | **IMPLEMENTED + VERIFIED** | HTTP et stdio réels + doubles : `timed_out`, couverture `not_scanned`, ledger |
| Annulation et fermeture de session | **IMPLEMENTED + VERIFIED** | annulation HTTP par fermeture TCP + annulation stdio réelles ; aucune notification MCP d'annulation revendiquée |
| Erreurs serveur / outil / réponse non conforme | **IMPLEMENTED + VERIFIED** | `unavailable`, `failed` et `invalid` testés séparément sur HTTP réel |
| Secrets et sorties distantes non fiables | **IMPLEMENTED + VERIFIED** | réponse, URL et message d'erreur masqués avant `ProviderResult`/brut |
| Sandbox / frontière de confiance serveur distant | **IMPLEMENTED + PARTIALLY VERIFIED** | MCP n'est pas présenté comme sandbox local ; serveur local contrôlé hors sandbox |
| Findings, normalisation et provenance | **IMPLEMENTED + VERIFIED** | HTTP réel et stdio passés par `findings.normaliser` |
| Ledger, couverture, corrélation et reporting UI/SARIF | **IMPLEMENTED + VERIFIED** | pipeline HTTP réel ; brut, mission, ledger et identité conservés |

## Test d'intégration simulée

```text
PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python PHASE3/test_mcp.py
23/23 cas passent
```

Le transport de ce test joue `initialize`, `tools/list` et `tools/call` en mémoire. Il ne prouve
donc ni un handshake réseau réel, ni la compatibilité avec une implémentation MCP tierce,
ni la disponibilité d'un credential.

## Intégration réelle contrôlée

```text
PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python PHASE3/test_mcp_e2e.py
17/17 cas passent

PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python PHASE3/test_mcp_policy_gate.py
3/3 cas passent

PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python PHASE3/test_mcp_stdio.py
8/8 cas passent

PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python PHASE3/test_mcp_http_cancel.py
17/17 cas passent

MCP_INTEROP_PYTHON=/tmp/agnt-mcp-interop-venv/bin/python \
  PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python PHASE3/test_mcp_interop.py
20/20 cas passent
```

`test_mcp_e2e.py` démarre un `ThreadingHTTPServer` MCP local sur loopback et port éphémère,
exerce réellement `initialize`, `notifications/initialized`, `tools/list` et `tools/call`,
puis garantit l'arrêt du serveur. Aucun appel Internet, serveur tiers ou credential n'est utilisé.
Les scénarios couvrent binding, outil absent, secret, erreur JSON-RPC, JSON malformé, réponse
trop grande, handshake incomplet, réponse lente et endpoint fermé.

`test_mcp_stdio.py` lance un processus Python local contrôlé, sans shell, via le transport stdio.
Il vérifie le même cycle, l'outil lié, la cible injectée, ainsi que l'annulation et la récolte
du processus après succès comme après timeout. Le mode stdio est donc prouvé contre un processus
réel ; aucune compatibilité avec un serveur MCP tiers n'est revendiquée.

`test_mcp_http_cancel.py` utilise un serveur HTTP local dont `tools/call` bloque après réception.
Le `cancel_event` ferme la socket HTTP active, le serveur observe EOF/reset, le résultat est
`cancelled` avec son `request_id`, aucun résultat tardif n'est normalisé, et la requête suivante
obtient une nouvelle session. Le test distingue ce chemin d'un timeout, d'une fermeture serveur,
d'une erreur JSON-RPC et d'une annulation précoce sans connexion.

`test_mcp_policy_gate.py` utilise un double de la frontière policy et prouve que le refus policy,
la policy indisponible et l'egress fermé n'atteignent pas le transport.

## Interopérabilité indépendante

La cible indépendante est le projet officiel **Model Context Protocol Python SDK** (`mcp`),
version exacte **2.1.1**, publié sous l'organisation Model Context Protocol / Linux Foundation.
Le test utilise l'API `MCPServer` du SDK v2 et son transport **stdio**. Ce choix est borné au
profil réellement commun avec AGNT : aucun HTTP, Streamable HTTP, SSE, streaming, ressource,
prompt, authentification ou annulation protocolaire n'est revendiqué ici.

L'installation est temporaire, hors dépôt :

```text
python -m venv /tmp/agnt-mcp-interop-venv
/tmp/agnt-mcp-interop-venv/bin/python -m pip install --no-cache-dir 'mcp==2.1.1'
```

`MCP_INTEROP_PYTHON` pointe vers cet interpréteur pour lancer le processus enfant. Le fixture
créé dans un répertoire temporaire ne fournit que deux fonctions déterministes (`review_code`
et `rogue_tool`) et un audit minimal des appels ; le framing JSON-RPC, le handshake, la validation,
`tools/list`, `tools/call` et le transport stdio sont exécutés par le SDK indépendant.

`test_mcp_interop.py` prouve le handshake accepté en `2025-06-18`, `request_id`,
`correlation_id`, `notifications/initialized`, la découverte informative avec un outil rogue,
le binding et le schéma locaux non élargis, un appel autorisé, la normalisation, le ledger,
la provenance, le rapport et l'absence de contamination entre appels successifs. Il distingue
également `cancelled` pré-invocation, `timed_out`, `unavailable` (outil absent, serveur absent,
fermeture) et `failed` (rejet fonctionnel du SDK). Les réponses JSON-RPC malformées et
l'incompatibilité de protocole ne sont pas fabriquées contre le SDK : ce sont des scénarios
**NOT EXERCISED** dans cette preuve indépendante. La seule cible exécutée est un
`Target("repository", ...)` synthétique ; aucune cible URL n'est exécutée ou convertie en `Path`.

## Bootstrap CORE — raccordé au module canonique (MCP-004, 31/08)

Le module CORE canonique `slice/transports.py` est désormais présent sur cette branche
(intégré dans `main` = `e7262f9`). L'implémentation MCP dupliquée a été **supprimée** :
il ne reste qu'un seul registre de transports, celui du cœur.

| API locale supprimée | API canonique du cœur |
|---|---|
| `obtenir(nom)` → exécuteur | `deleguer(nom, prov, sbx, **contexte)` |
| `enregistre(nom)` | `fournit(nom)` |
| `noms()` | `connus()` |
| `UnknownTransport` / `DuplicateTransport` / `TransportRegistryError` | `TransportError` |
| tuple `provider_contract.TRANSPORTS` codé en dur | `transports.fournit()` / `connus()` |

Le bootstrap MCP reste le seul point d'enregistrement explicite, et il n'utilise que le
couple canonique `enregistrer` / `fournit` :

```python
import transports
from mcp_bootstrap import initialiser_mcp
initialiser_mcp(transports)  # une fois, avant le premier Registry()
```

`initialiser_mcp()` n'est appelé ni par une requête Web ni par le backend. Trois issues,
toutes fail-closed : registre non conforme → erreur ; `mcp` déjà fourni par un tiers →
erreur, jamais d'écrasement ; déjà enregistré par nous → retour idempotent. Aucun fallback
vers `sandbox_cli` ni vers un exécutable local.

### Seule extension apportée au module CORE

`transports.deleguer(nom, prov, sbx, /, **contexte)` transmet le contexte **par appel** que
le cœur sait produire et qu'un transport ne peut pas deviner : cible typée, arguments
validés, fabrique de transport (tests), événement d'annulation. Le module ne l'inspecte pas
et ne le transforme pas — il ne connaît pas le vocabulaire des transports.

Rétrocompatible et borné par quatre cas dédiés (`test_mcp_contract` 0quinquies…0octies) :
un exécuteur `(prov, sbx)` fonctionne toujours sans contexte ; un contexte non accepté lève
`TypeError` (jamais de perte silencieuse d'une annulation) ; un transport inconnu lève
`TransportError` sans repli local.

### Trois couplages « provider = binaire local » supprimés

1. **Disponibilité** (`pipeline.executer`) : elle était décidée pour tous les providers sur
   `adapters.exe_de()`, donc sur la présence d'un exécutable. Un provider externe n'en a pas
   par contrat : il était écarté avant toute exécution et son absence devenait une absence
   **inexpliquée**. Désormais `sandbox_cli` → exécutable résolvable ; externe → transport
   enregistré, la disponibilité réelle du serveur restant portée par le résultat.
2. **Type de cible en policy** : `cible_type="repository"` était passé en dur à
   `moteur.evaluer()`. Le paramètre a **disparu** : OPA lit le descripteur structuré porté
   par le plan (`cible_descr` = `Cible.to_dict()`), donc le type réel. Le cas `15bis` de
   `test_mcp` le prouve (fichier → `filesystem`).
3. **Nom du transport** : cinq défauts/replis écrivaient le littéral `"local"` dans le
   chemin résultat → provenance → rapport. Ils prennent tous `TRANSPORT_SANDBOX_CLI`.

## CORE COMPATIBILITY MAP (après MCP-004)

| Contrat CORE | État | Preuve |
|---|---|---|
| `Provider` par capability, transport nommé canoniquement | **VÉRIFIÉ** | `Provider.transport`, `test_mcp_contract` 1-2 |
| `transports.enregistrer` / `fournit` / `connus` / `deleguer` | **VÉRIFIÉ sur le module CORE réel** | plus aucune API dupliquée ; `test_mcp_contract` 0bis…0octies |
| dispatch par le registre canonique | **VÉRIFIÉ** | `adapters.executer` → `transports.deleguer` ; aucune table locale |
| validation du transport au chargement du registre | **VÉRIFIÉ fail-closed** | `registre.Provider.__post_init__` → `transports.fournit` |
| enregistrement explicite avant `Registry()` | **VÉRIFIÉ** | `mcp_bootstrap`, entrées CLI/API/pipeline, cas 0 |
| `Cible` CORE distincte de `Sandbox` | **VÉRIFIÉ** | `cible.normaliser` → `plan.cible_descr` → entrée OPA ; `Target` MCP jamais converti en `Path` |
| résultat commun, normalisation, ledger, rapport | **VÉRIFIÉ** | passes HTTP contrôlée et stdio SDK indépendant |
| découverte distante informative seulement | **VÉRIFIÉ** | `tools/list` annonce `rogue_tool`, binding et schéma non élargis |
| aucun fallback local | **VÉRIFIÉ** | transport inconnu → `TransportError` ; disponibilité externe ≠ binaire |

## Blocages explicites

- OPA n'est pas installé dans l'environnement (`/home/user/.cache/arena_secops/bin/opa` absent) :
  la policy MCP reste **IMPLEMENTED + NOT EXERCISED** côté moteur OPA réel. Les garde-fous
  testés ici le sont sur un double de la frontière policy (`test_mcp_policy_gate`, 3/3).
- **PRÉ-EXISTANTS SUR `main` (`e7262f9`), non introduits par MCP** — vérifié par exécution
  dans un worktree détaché sur `e7262f9`, résultats identiques de part et d'autre :
  `test_manifest` et `test_fanout` (`KeyError: 'steps'`), `test_correlation`
  (`KeyError: 'clusters'`), `test_tracabilite` (`KeyError: 'plan_id'`), `test_utilisation`
  (double de `pipeline.executer` périmé), `test_qualite_plateforme` 32/34,
  `test_adversaire` 46 cas · 40 PASS · 2 FAIL · 4 NON ÉVALUÉS. Ces suites relèvent de CORE.
- Une interopérabilité indépendante est désormais démontrée uniquement avec le SDK Python
  officiel `mcp==2.1.1` en stdio. Aucun support général d'un serveur tiers, d'un proxy, de HTTP,
  de Streamable HTTP, de SSE ou d'une variante de framing non testée n'est revendiqué.
- MCP-003 est **IMPLEMENTED + VERIFIED** au niveau transport HTTP : l'annulation volontaire
  ferme la connexion TCP active et le serveur contrôlé observe EOF/reset. Cela ne constitue pas
  une notification protocolaire MCP d'annulation : aucun mécanisme serveur de type cancellation
  n'est inventé ni revendiqué.
- Les échecs historiques liés à des exécutables/cache locaux absents ne sont pas comptés comme
  validation MCP.

---

```
=== AGNT HANDOFF v1 ===
agent      : MCP
domaine    : providers externes / transport MCP / normalisation / provenance
branche    : arena/01a05760-agnt  (session) — PR ouverte vers main
base       : e7262f9 (main : CORE intégré, PR#2 incluse) — rebase, 12 commits
statut     : MCP-004 TERMINÉ — raccordé au Transport canonique, batterie rejouée

commits (sur e7262f9)
  3fe55dd  introduce external provider contract
  5fc130f  integrate backend with pipeline and reporting
  4dac4c0  wire explicit CORE transport bootstrap and controlled tests
  0e46217  annulation HTTP réellement interruptible
  2622ad3  interoperability with independent server (SDK mcp 2.1.1)
  20256bc  repair adversarial guard broken by cible_type
  05e095a  record AGNT handoff after full battery replay
  035dd88  decide external provider availability by transport, not local binary
  d797e92  name the sandbox transport canonically in plan steps
  23a0795  align test doubles and battery with canonical CORE contracts
  99363e9  name every transport by its canonical registry name
  d5212a9  bound the deleguer context extension with contract tests

MCP-004 — ce qui a été fait
  - transports.py dupliqué SUPPRIMÉ : un seul registre, celui du cœur
    (enregistrer / fournit / connus / deleguer / TransportError).
  - dispatch par transports.deleguer ; table locale TRANSPORT_ADAPTATEURS supprimée.
  - mcp_bootstrap n'utilise que enregistrer + fournit ; homonyme d'un tiers jamais écrasé.
  - tuple TRANSPORTS codé en dur supprimé : validation par transports.fournit().
  - cible_type="repository" SUPPRIMÉ : OPA lit plan.cible_descr (Cible.to_dict()).
  - disponibilité externe = transport enregistré, plus la présence d'un binaire local.
  - tous les littéraux de transport "local" remplacés par TRANSPORT_SANDBOX_CLI.
  - seule extension au contrat CORE : deleguer(..., **contexte), rétrocompatible,
    bornée par 4 cas de test.

tests
  PASS — batterie MCP 110 cas
    test_mcp_contract.py    21/21  contrat, binding, bootstrap, contrat deleguer
    test_mcp.py             24/24  INTEGRATION SIMULATED (transport en mémoire)
    test_mcp_e2e.py         17/17  INTEGRATION SIMULATED (serveur MCP HTTP loopback réel)
    test_mcp_policy_gate.py   3/3  refus policy / policy indisponible / egress fermé
    test_mcp_stdio.py         8/8  processus Python réel, sans shell
    test_mcp_http_cancel.py  17/17 annulation par fermeture TCP réelle
    test_mcp_interop.py     20/20  REAL — SDK officiel mcp==2.1.1, transport stdio
  PASS — régression non-MCP (identique à la base e7262f9)
    test_selection 13/13 · test_statuts_outils 31/31 · test_modele_finding 37/37
    test_empreintes 13/13 · test_garde_fous 29/29 · test_isolation_mission 8/8
    test_qualite_plateforme 32/34 (= base) · test_adversaire 40 PASS/2 FAIL/4 NE (= base)
  BLOCKED (environnement, identiques sur e7262f9 et ici — domaine CORE)
    binaire OPA absent → policy réelle non évaluée
    test_manifest, test_fanout (KeyError 'steps'), test_correlation (KeyError
    'clusters'), test_tracabilite (KeyError 'plan_id'), test_utilisation (double
    périmé) — PRÉ-EXISTANTS SUR MAIN, vérifiés en worktree détaché sur e7262f9
  NON ÉVALUÉ
    HTTP / Streamable HTTP / SSE / streaming / resources / prompts / auth /
    annulation protocolaire contre le SDK indépendant (borné à stdio)
    réponses JSON-RPC malformées et incompatibilité de protocole contre le SDK

modifications de tests (justification écrite, aucune attente adoucie)
  - doubles de PolicyEngine sans cible_type (le paramètre a disparu de la policy) ;
  - double de Plan complété de steps=() (_rapport lit plan.steps) ;
  - plus de pipeline.SORTIE (CORE : artefacts par mission dans <mission>/run) ;
  - transports.fournit() au lieu de l'aide locale enregistre() ;
  - cas 15 porte un vrai descripteur de cible + cas 15bis prouve que le type suit le
    descripteur (fichier -> filesystem) au lieu d'un littéral.

périmètre non touché
  Aucun redesign de registry/provider/adapter (brief « P0 Provider abstraction »
  toujours SUSPENDU). Aucune règle OPA, aucune UI, aucun manifest versionné, aucun
  credential. Sandbox et policy inchangés dans leur logique : seul le NOM du
  transport et l'ORIGINE de la disponibilité ont été corrigés.

confiance
  HAUTE sur les 110 cas MCP et sur la régression (baseline e7262f9 exécutée en
  worktree détaché, comparaison ligne à ligne).
  NULLE sur toute évaluation OPA réelle : le binaire est absent de l'image.
=== END AGNT HANDOFF ===
```
