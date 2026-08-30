# Intégration MCP — statut de validation

Date de la vérification : **2026-08-30 UTC**.

## Verdict par fonctionnalité

| Fonctionnalité | Statut | Preuve / limite |
|---|---|---|
| Contrat `capability ↔ provider ↔ transport ↔ backend` | **IMPLEMENTED + VERIFIED** | `test_mcp_contract.py` : 11/11 |
| Binding registre ↔ capability ↔ serveur ↔ outil | **IMPLEMENTED + VERIFIED** | chargement validé sans découverte réseau ; outil absent refusé |
| Sélection, plan, policy input et cible typée | **IMPLEMENTED + PARTIALLY VERIFIED** | plan/policy input testé ; évaluation OPA bloquée sans binaire |
| Validation locale de schéma et d'arguments | **IMPLEMENTED + VERIFIED** | `test_mcp.py` : refus avant construction du transport |
| Handshake, découverte et appel JSON-RPC simulés | **IMPLEMENTED + VERIFIED** | faux transport en mémoire ; aucun serveur tiers réel |
| Transport stdio sans shell + transport HTTP/Streamable HTTP | **IMPLEMENTED + PARTIALLY VERIFIED** | compilation/contrat ; aucun endpoint ou serveur réel exercé |
| Timeout | **IMPLEMENTED + VERIFIED** | transport simulé : `timed_out`, couverture `not_scanned`, ledger explicite |
| Annulation et fermeture de session | **IMPLEMENTED + VERIFIED** | transport simulé ; nouvelle session et `close()` par invocation |
| Erreurs serveur / outil / réponse non conforme | **IMPLEMENTED + VERIFIED** | `unavailable`, `failed` et `invalid` testés séparément |
| Secrets et sorties distantes non fiables | **IMPLEMENTED + VERIFIED** | réponse et message d'erreur masqués avant `ProviderResult`/brut |
| Sandbox / frontière de confiance serveur distant | **IMPLEMENTED + PARTIALLY VERIFIED** | MCP n'est pas présenté comme sandbox local ; exécution réelle non exercée |
| Findings, normalisation et provenance | **IMPLEMENTED + VERIFIED** | sortie simulée passée par `findings.normaliser` |
| Ledger, couverture, corrélation et reporting UI/SARIF | **IMPLEMENTED + VERIFIED** | chemin `_vague` testé ; brut, ledger et identité conservés |

## Test d'intégration simulée

```text
PYTHONPATH=PHASE3/slice /tmp/agnt-venv/bin/python PHASE3/test_mcp.py
23/23 cas passent
```

Le transport de ce test joue `initialize`, `tools/list` et `tools/call` en mémoire. Le test ne
prouve donc ni un handshake réseau réel, ni la compatibilité avec une implémentation MCP tierce,
ni la disponibilité d'un credential.

## Blocages explicites

- OPA n'est pas installé dans l'environnement (`/home/user/.cache/arena_secops/bin/opa` absent) :
  `test_manifest.py` et `test_fanout.py` restent bloqués, et la policy MCP est **IMPLEMENTED +
  NOT EXERCISED** côté moteur OPA.
- Aucun serveur MCP réel n'a été contacté : HTTP, Streamable HTTP, stdio et annulation réseau
  réelle restent **PARTIALLY VERIFIED**, pas « intégration réelle validée ».
- Les échecs historiques liés à des exécutables/cache locaux absents ne sont pas comptés comme
  validation MCP.
