# Intégration MCP — statut de validation

Date de la vérification : **2026-08-30 UTC**.

## Verdict par fonctionnalité

| Fonctionnalité | Statut | Preuve / limite |
|---|---|---|
| Contrat `capability ↔ provider ↔ transport ↔ backend` | **IMPLEMENTED + VERIFIED** | `test_mcp_contract.py` : 16/16 |
| Binding registre ↔ capability ↔ serveur ↔ outil | **IMPLEMENTED + VERIFIED** | chargement validé sans découverte réseau ; outil absent refusé |
| Sélection, plan, policy input et cible typée | **IMPLEMENTED + PARTIALLY VERIFIED** | plan/policy input testé ; évaluation OPA bloquée sans binaire |
| Garde policy/egress avant transport | **IMPLEMENTED + VERIFIED** | `test_mcp_policy_gate.py` : 3/3 avec double ; moteur OPA réel bloqué par environnement |
| Validation locale de schéma et d'arguments | **IMPLEMENTED + VERIFIED** | `test_mcp.py` : refus avant construction du transport |
| Handshake, découverte et appel JSON-RPC | **IMPLEMENTED + VERIFIED** | faux transport + HTTP/stdio/Streamable HTTP locaux ; aucun serveur tiers |
| Transport stdio sans shell + transport HTTP/Streamable HTTP | **IMPLEMENTED + VERIFIED** | chaque mode exercé par serveur/processus local contrôlé ; tiers non exercés |
| Timeout | **IMPLEMENTED + VERIFIED** | HTTP et stdio réels + doubles : `timed_out`, couverture `not_scanned`, ledger |
| Annulation et fermeture de session | **IMPLEMENTED + PARTIALLY VERIFIED** | annulation/fermeture stdio réelles ; annulation HTTP réelle non prouvée |
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

`test_mcp_policy_gate.py` utilise un double de la frontière policy et prouve que le refus policy,
la policy indisponible et l'egress fermé n'atteignent pas le transport.

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
| résultat commun, normalisation, ledger et rapport | **VÉRIFIÉ DANS LE PIPELINE EXISTANT** | passe HTTP réelle dans `test_mcp_e2e.py` |
| découverte distante comme information seulement | **VÉRIFIÉ** | `tools/list` ne modifie jamais `argument_schema` ni `approved_tool` |
| absence de fallback local | **VÉRIFIÉ** | transport non enregistré = erreur ; aucun appel CLI/`sandbox_cli` dans le chemin MCP |

**Action requise lors du merge CORE :** comparer les signatures et exceptions du registre canonique,
brancher `mcp_bootstrap` sur son instance/API réelle, supprimer le raccord local si le CORE expose
ces primitives, puis relancer les tests MCP ciblés. Aucun commit de ce checkout ne peut prétendre
avoir compilé contre le CORE absent.

## Blocages explicites

- OPA n'est pas installé dans l'environnement (`/home/user/.cache/arena_secops/bin/opa` absent) :
  `test_manifest.py` et `test_fanout.py` restent bloqués, et la policy MCP est **IMPLEMENTED +
  NOT EXERCISED** côté moteur OPA.
- Les serveurs/processus MCP des tests sont réels mais exclusivement contrôlés et locaux ; aucune
  compatibilité avec un serveur tiers, un proxy ou une variante de framing non testée n'est
  revendiquée.
- MCP-003 reste ouvert : l'annulation HTTP pendant un appel bloquant n'est pas démontrée. Le
  timeout ferme la session côté client ; l'arrêt du handler serveur n'est pas une annulation
  protocolaire MCP. Une vraie annulation devra utiliser le mécanisme de cancellation MCP/HTTP
  retenu par le CORE, avec preuve d'un serveur qui l'observe.
- Les échecs historiques liés à des exécutables/cache locaux absents ne sont pas comptés comme
  validation MCP.
