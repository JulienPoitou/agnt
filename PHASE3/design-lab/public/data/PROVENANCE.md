# Provenance des données du design-lab

## Source

- **Provenance des captures :** branche `main`, dossier `docs/coordination/captures/gate-002-product-api/`
  (jeu `gate-002-product-api`, base d'intégration `5f5e09d6`).
- Contenu : 17 corps de réponses HTTP **réelles** de l'API CORE (11 détails + 6 côté liste),
  servis en process par `PHASE3/produire_captures_product.py` sur 11 missions contrôlées.
  Aucune réponse n'est écrite à la main.
- Manifeste : `capture-manifest.json` (rôle + path + statut HTTP de chaque corps).
- Contrats exercés : `agnt.history.v1`, `agnt.timeline.v1`, `agnt.execution-status.v1`.
- Rejeu du gate mesuré par CORE le 2026-08-31 : **1467 PASS · 0 FAIL · 0 SKIP**, couverture
  **16/16** (voir le README du dossier de captures).

## Règle de copie

`public/data/gate-002-product-api/` est la **seule** copie de ces JSON côté front. Elle doit rester
**octet pour octet identique** à la source dans `docs/coordination/`. Ne jamais éditer une copie
locale ; régénérer depuis la source. Vérification :

```sh
diff -r docs/coordination/captures/gate-002-product-api \
        PHASE3/design-lab/public/data/gate-002-product-api --exclude='README.md'
```

## Ce qui ne vit PAS ici

- Le gate produit `product_api_gate.py` (+ son test, son README, ses fixtures `examples/`)
  vit dans `docs/coordination/api-conformance-gate/` — chez PRODUCT, pas dans un front.
  Vérifié le 2026-08-31 : ce dossier existe sur `arena/01a05425-agnt @ 3f96e25` et n'est
  pas encore mergé dans `main`. Les copies qui traînaient dans `PHASE3/design-lab/data/`
  ont été supprimées de ce front (erreur de catégorie : un validateur Python de contrat
  n'a rien à faire dans une app Next).
- Les fixtures de contrat `examples/anonymized-capture/` : idem, leur maison est le dossier
  du gate côté docs, pas ce front. Le lab n'affiche **que** les captures réelles gate-002.

## Serment du front

Le front n2019affiche que ce qui est présent dans ces fichiers. Une absence n'est jamais un zéro :
un champ absent s'affiche « inconnu / non consigné ». `refusé`, `échoué`, `non exécuté`,
`indisponible`, `annulé`, `expiré`, `non applicable` restent des états distincts, conformes aux
invariants documentés dans le README des captures.
