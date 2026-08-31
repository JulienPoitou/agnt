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

## Bootstrap CORE

Le checkout actuel n'expose pas encore le bootstrap CORE canonique. Le patch ajoute uniquement
le point d'extension générique `transports.enregistrer` et un bootstrap MCP explicite :

```python
import transports
from mcp_bootstrap import initialiser_mcp
initialiser_mcp(transports)  # une fois, avant le premier Registry()
```

`mcp_bootstrap.initialiser_mcp()` n'est appelé ni par une requête Web ni par le backend. Il
refuse les doublons et ne fournit aucun fallback vers `sandbox_cli` ou un exécutable local.
Lors de l'arrivée du CORE canonique, `transports.py` doit être remplacé/aligné par son registre,
et le point d'appel conservé dans le bootstrap applicatif (`analyser.main`, `interface.api.main`,
`pipeline.main`).

## CORE COMPATIBILITY MAP

| Contrat CORE attendu | État dans ce checkout | Preuve / action d'intégration |
|---|---|---|
| `Provider` enregistré par capability, avec transport nommé | **COMPATIBLE + VÉRIFIÉ LOCAL** | `Provider.transport`, binding MCP et `test_mcp_contract.py` |
| extension générique `transports.enregistrer(nom, executor)` | **COMPATIBLE PROVISOIRE** | API reproduite par `slice/transports.py`; le module n'est pas le CORE canonique |
| résolution/dispatch par le registre générique | **COMPATIBLE PROVISOIRE** | `adapters.executer` appelle `transports.obtenir`; remplacer par la méthode CORE équivalente si son nom diffère |
| enregistrement explicite avant `Registry()` | **VÉRIFIÉ** | `mcp_bootstrap.initialiser_mcp`, entrées CLI/API/pipeline et test fail-closed |
| cible structurée CORE, distincte de `Sandbox` | **PARTIELLEMENT COMPATIBLE** | `provider_contract.Target` local ; URLs/hôtes ne sont pas coercés depuis `Path` |
| résultat commun, normalisation, ledger et rapport | **VÉRIFIÉ DANS LE PIPELINE EXISTANT** | passes HTTP contrôlée et stdio indépendant dans `test_mcp_e2e.py` / `test_mcp_interop.py` |
| découverte distante comme information seulement | **VÉRIFIÉ** | `tools/list` du SDK indépendant annonce `rogue_tool`, sans modifier `argument_schema` ni `approved_tool` |
| absence de fallback local | **VÉRIFIÉ** | transport non enregistré = erreur ; aucun appel CLI/`sandbox_cli` dans le chemin MCP |

**Action requise lors du merge CORE :** comparer les signatures et exceptions du registre canonique,
brancher `mcp_bootstrap` sur son instance/API réelle, supprimer le raccord local si le CORE expose
ces primitives, puis relancer les tests MCP ciblés. Aucun commit de ce checkout ne peut prétendre
avoir compilé contre le CORE absent.

## Blocages explicites

- OPA n'est pas installé dans l'environnement (`/home/user/.cache/arena_secops/bin/opa` absent) :
  `test_manifest.py` et `test_fanout.py` restent bloqués, et la policy MCP est **IMPLEMENTED +
  NOT EXERCISED** côté moteur OPA.
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
branche    : arena/01a05760-agnt  (session) — PR cible : arena/builder-mcp
base       : 4433af6 (fast-forward) -> 6e04ff8 (5 commits MCP repris) -> 59252df
statut     : READY_FOR_INTEGRATION — batterie rejouée, 104/104 cas
commits    : 458d23b external provider contract
             be68844 integrate backend with pipeline and reporting
             229601a explicit CORE transport bootstrap + controlled tests
             b6b650d annulation HTTP réellement interruptible
             6e04ff8 interoperability with independent server (SDK mcp 2.1.1)
             59252df repair adversarial guard broken by cible_type + record replay

livrables  : slice/provider_contract.py, slice/mcp_provider.py, slice/mcp_transport.py,
             slice/mcp_bootstrap.py, slice/transports.py (PROVISOIRE — voir MCP-004),
             STATUT_MCP.md, 7 suites test_mcp*.py

tests
  PASS (104 cas)
    test_mcp.py            23/23  INTEGRATION SIMULATED (transport en mémoire)
    test_mcp_contract.py   16/16  contrat + binding registre + refus schéma malformé
    test_mcp_e2e.py        17/17  INTEGRATION SIMULATED (ThreadingHTTPServer MCP loopback)
    test_mcp_policy_gate.py  3/3  refus policy / policy indisponible / egress fermé
    test_mcp_stdio.py        8/8  processus Python réel, sans shell
    test_mcp_http_cancel.py 17/17 annulation par fermeture TCP réelle
    test_mcp_interop.py    20/20  REAL — SDK officiel mcp==2.1.1, transport stdio
  PASS (régression)
    test_adversaire.py     46 cas · 41 PASS · 2 FAIL · 3 NON ÉVALUÉS
                           = relevé identique à la base 4433af6 (worktree détaché)
  FAIL (pré-existants, hors domaine MCP — non absorbés)
    D4  armement de cible_autorisee      -> SECURITY
    G6a règles de détection des secrets  -> SECURITY (e5838003)
  BLOCKED (environnement, identiques sur 4433af6 et 6e04ff8)
    binaire OPA absent : test_slice, test_correlation, test_tracabilite,
    test_manifest, test_fanout, test_utilisation
    -> policy MCP = IMPLEMENTED + NOT EXERCISED côté moteur OPA réel
  NON ÉVALUÉ
    HTTP / Streamable HTTP / SSE / streaming / resources / prompts / auth /
    annulation protocolaire contre le SDK indépendant (borné à stdio)
    réponses JSON-RPC malformées et incompatibilité de protocole contre le SDK

blocages
  - MCP-004 raccord au Transport CORE canonique : SUSPENDU par la coordination,
    à traiter en intégration coordonnée CORE+MCP. slice/transports.py reste une
    API PROVISOIRE (obtenir) à remplacer par le registre canonique
    (enregistrer/fournit/connus/deleguer). Aucun merge builder↔builder.
  - CORE-005 Cible distante (url) : aucun transport ne reçoit encore une Cible
    distante ; évolution conjointe CORE/MCP/SECURITY requise.

note transmise à CORE / SECURITY (non absorbée, non corrigée ici)
  pipeline.py passe cible_type="repository" EN DUR à moteur.evaluer() (l. 531,
  l. 662) alors que le type réel est dérivé par provider dans _vague
  (prov.target_types -> repository OU filesystem, l. 266-270). detect_secrets
  déclare target_types: ['repository','filesystem'] : l'entrée OPA peut donc
  annoncer cible.type="repository" pour une exécution filesystem. Une règle OPA
  distinguant les deux recevrait un fait faux. Contrat CORE -> à traiter avec
  CORE-005 / MCP-004.

périmètre non touché
  Aucun redesign du contrat provider (consigne de suspension respectée).
  Aucun fichier CORE hors PHASE3/slice/{pipeline,adapters,policy}.py déjà livrés
  par les 5 commits repris. Ce lot n'ajoute que 2 signatures de doubles de test
  + documentation. Aucune UI, aucun manifest, aucune règle OPA, aucun sandbox.

confiance
  HAUTE sur les 104 cas MCP et sur la réparation de la garde adversariale
  (contrôle de référence exécuté sur 4433af6 en worktree détaché).
  MOYENNE sur test_utilisation.py : alignement préventif NON EXERCÉ (OPA absent).
  NULLE sur toute évaluation OPA réelle dans cet environnement.
=== END AGNT HANDOFF ===
```
