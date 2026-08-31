# GATE-002 — captures contrôlées du gate Product/API

Référence rejouable pour le gate `docs/coordination/api-conformance-gate/product_api_gate.py`
(contrats `agnt.history.v1`, `agnt.timeline.v1`, `agnt.execution-status.v1`).

## Ce que c'est

**17 réponses HTTP réelles de l'API CORE**, capturées sur 11 missions contrôlées.
Aucune réponse n'est écrite à la main : chaque octet est sorti de `PHASE3/interface/api.py`
+ `PHASE3/slice/mission_history.py`, servis en process par le producteur.

Le gate en mode `--require-full-coverage` exige les 16 cas de `FULL_COVERAGE` — ce qu'aucun
environnement réel ne contient naturellement (le README du gate le dit). Ces captures sont
donc le jeu de données de référence pour les prochains rejoueurs.

## Rejouer

```sh
# 1. régénérer les captures (API réelle, missions contrôlées, hors réseau)
python3 PHASE3/produire_captures_product.py

# 2. jouer le gate en couverture complète
python3 docs/coordination/api-conformance-gate/product_api_gate.py \
  --capture docs/coordination/captures/gate-002-product-api/capture-manifest.json \
  --require-full-coverage
```

Résultat mesuré le 2026-08-31 (Python 3.11.2) : **1467 PASS · 0 FAIL · 0 SKIP · exit 0**,
couverture **16/16**.

`--fixture-mode` n'est **pas** utilisé : ce sont des réponses d'API, pas des données de
contrat. La régénération produit des corps identiques ; seul `submission_id` du manifeste
change (format réel de `POST /api/runs` : `uuid4().hex[:12]`), c'est attendu.

## Matrice — quelle mission prouve quel cas

| Mission | Cas du gate | Fait exercé |
|---|---|---|
| `m-…120005Z-00000001` | `zero` | terminée, 0 finding **prouvé** (`rien_trouve` + 3 cibles analysées) |
| `m-…120004Z-00000002` | `findings` | terminée, 2 findings normalisés + 1 cluster |
| `m-…120003Z-00000003` | `refused` | refus de politique pré-Run → `non_autorise`, jamais zéro |
| `m-…120002Z-00000004` | `unavailable` | binaire absent → `unavailable`, détection `non_evalue` |
| `m-…120001Z-00000005` | `failed` | code retour 1 → `echoue`, jamais zéro |
| `m-…120000Z-00000006` | `timeout` | deadline dépassée → `timed_out` |
| `m-…115959Z-00000007` | `cancelled` | mission close pendant l'exécution → `cancelled` |
| `m-…115958Z-00000008` | `non_applicable` | cible `url`, provider écarté à l'applicabilité |
| `m-…115957Z-00000009` | `incomplete` | artefacts absents → `partial`/`missing_artifacts`, rien de fabriqué |
| `m-…115956Z-0000000a` | `unknown` | type d'événement inconnu du lecteur → `unknown_event_recorded`, payload jamais publié |
| `m-…115955Z-0000000b` | `mcp` | provenance **consignée** projetée en allowlist (voir ci-dessous) |
| (toutes) | `list`, `detail`, `timeline` | listing paginé, détail, projection du journal |
| `?status=en_file` | `empty_list` | liste réellement vide : HTTP 200 + `items: []` |
| manifeste | `submission_distinct` | id transitoire de file ≠ tout `mission_id`, ne singe pas `m-*` |

## Portée exacte du cas `mcp` — à lire avant de s'y fier

Le cas `mcp` exerce la **projection** CORE d'un fait de provenance consigné
(`slice/mission_history.py::_provenance`) : allowlist des champs, grammaire des
identifiants, `provider_kind` jamais deviné, et rejet des champs hostiles ajoutés
exprès à la fixture (`endpoint`, `token`, `argv`, `server_id_brut`).

**Aucun serveur MCP réel n'a été contacté** et aucun transport MCP n'est enregistré dans
cet arbre. Le *producteur* de ce fait est le raccord MCP-004 (transport enregistré +
faits transport/protocole détenus par MCP). Dit autrement : la projection est vérifiée,
l'acquisition du fait ne l'est pas encore ici.

## Invariants visibles dans ces captures

- Aucune absence ne devient zéro : `unavailable` / `echoue` / `timed_out` / `cancelled` /
  `non_autorise` portent `detection: non_evalue` **sans** `findings_count`.
- Zéro finding seulement avec preuve complète (`rien_trouve`, cibles analysées, `complete`).
- Artefact manquant → `missing_artifacts` logique, et la donnée correspondante est absente
  de `data` (jamais fabriquée).
- Aucun interdit publié : chemin absolu, argv, credential, Bearer, private key, stack trace,
  endpoint brut.
- `data.timeline` (journal, `seq` = ordre + identité) et `data.events` (legacy) restent
  indépendants ; aucun compteur fusionné.
