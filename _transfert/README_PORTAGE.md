# PORTAGE — session bundle → workspace source (2026-08-28)

## Contenu

| Fichier | Rôle |
|---|---|
| `projet_2026-08-28.patch` | patch unifié des 6 fichiers modifiés (base : bundle du 2026-08-28) |
| `testrepo_iac/` | fixture IaC complète (5 fichiers, dont `ATTENDUS.yaml` extrait d'exécution) |
| `APPLIQUER.sh` | dry-run → application → vérifications ; s'arrête au premier échec |

## Application

```bash
bash APPLIQUER.sh <racine_du_projet>
```

Puis, dans l'ordre : `bash PHASE3/bootstrap.sh` (exit 0 attendu, OPA 1.20.0 conforme,
javascript.yaml téléchargé), `python3 PHASE3/test_securite.py`, puis les batteries.

## Si le dry-run échoue

Le patch est calculé contre le bundle régénéré le 2026-08-28. Si le workspace source a
divergé, des hunks échoueront — **ne pas forcer** (`--force`). Les changements sont
documentés hunk par hunk dans `PATCHES_A_PORTER.md` (rév. 2) à la racine du bundle :
ils peuvent être appliqués à la main. Les deux cellules du CSV (nuclei/nikto
`api` → `cli`) se corrigent en 10 secondes à la main.

## Échecs de batteries attendus — et que faire

1. **test_manifest** : le compte de manifests testés augmente (checkov ajouté). Si le
   test attend un nombre fixe, étendre l'attente — c'est le motif « attentes extensibles »
   déjà appliqué en Phase 5A.
2. **test_slice** : une demande générique (« scan de sécurité complet ») résout désormais
   IAC_SCAN en plus des trois capacités de base ; le plan gagne un step checkov. Même
   traitement : attentes extensibles, pas de retour arrière sur les MOTIFS.
3. **test_independant / pyyaml** : si les 2 échecs persistent après le correctif
   javascript.yaml, la cause est mesurée : la règle `avoid-pyyaml-load` des packs épinglés
   ne matche plus `yaml.load(f)` nu (seulement `unsafe_load` / `Loader=yaml.Loader`…).
   Vérifier le motif réel dans `cible_independante` avant de toucher au test : si le code
   cible utilise `yaml.load` nu, c'est l'attente du test qui est obsolète, pas le moteur.

## Décision embarquée (réversible)

Le patch épingle **OPA 1.20.0** (URL versionnée) — le manifeste actuel redevient vrai.
Alternative non appliquée : épingler 1.20.1 et mettre l'empreinte à jour
(`0b3f152e61be276b70396cfbca49e39fc9d0c5089e0a8574e8f6a30f41a9187f`, mesurée par les
deux sessions). Changer d'avis = 2 lignes (URL + sha256 du manifeste).

## Vérifications déjà faites (session bundle)

- Patch appliqué sur extraction vierge du bundle : dry-run + application + vérifications
  statiques OK (c'est le test que rejoue `APPLIQUER.sh`).
- Semgrep 3 configs : exit 0, 0 erreur, règles JS déclenchées.
- checkov 3.3.15 : 38 findings, identiques avec/sans réseau (bwrap `--unshare-net`),
  aucune fuite du faux secret, extraction 15/15, `valider()` OK, intent OK.
- Bootstrap complet : exit 0, idempotent.
