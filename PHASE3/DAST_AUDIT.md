# Audit DAST backend — findings (session 2026-09-02)

## Chemin cartographié

```
requete → intent (mots-clés → capacités) → choisir_providers (PASSIF seulement)
        → filtrer_applicabilite (target_types ↔ type de cible) → conditions (egress)
        → OPA (risque ACTIVE ⇒ refus si profil non durci) → sandbox
        → adapters.executer → generique_cli (argv manifest, {URL}) → ResultatBrut
        → findings.normaliser (depuis_manifest via extraction.champs) → Finding
        → clusterer.regrouper → rapport/findings.json/raw_*/brut_*
```

## Trous identifiés (état du dépôt 0f75d1b)

1. **Sélection** : `intent.choisir_providers` ne retient QUE les providers `risque == "PASSIVE"` —
   les providers DAST actifs (nuclei, ffuf, nmap, demain zap) sont inatteignables par `executer()`,
   même sur demande explicite.
2. **Intent** : aucune capacité WEB/RECON n'a de mots-clés — une demande « scan de vulnérabilités
   web » ne résout jamais `WEB_VULN_SCAN_ACTIVE`.
3. **Cible URL** : `pipeline` bloque les cibles non locales — `_vague._un` ne construit que des
   `Target("repository"|"filesystem")`, l'étape 4 (garde de chemin) lève PipelineError si la cible
   n'a pas de chemin, `RUN.digest_cible` exige un Path. Le `Sandbox` exige et monte `racine_scan`.
4. **Adaptateur** : `generique_cli` lit `sbx.racine_scan` sans ménagement → AttributeError sur les
   doubles de sandbox documentés (4 batteries rouges au baseline : test_conditions_outils,
   test_catalogue_outils, test_plugins, test_vague_parallele). La garde de conditions passe APRÈS
   la résolution de l'exécutable (ordre divergent de `_lance`). La couverture d'une cible distante
   est indexée sur `M_SCAN` (un chemin de dépôt… qui n'existe pas) et un scan vide légitime est
   lu « ÉCHEC D'EXÉCUTION ».
5. **Normalisation** : le manifest `nuclei` ne déclare AUCUN `champs` → findings creux, TOUS de
   même empreinte (collision d'identité). `ffuf` et `nmap` idem (nmap : chaque élément XML devient
   un item vide). `zap` absent (pool : « prévue »).
6. **Corrélation** : le clusterer ne connaît que paquet/fichier+ligne — les coordonnées url/hote/
   image/ressource (vocabulaire COORDONNÉES du finding, déjà là) ne produisent AUCUN regroupement ;
   deux outils d'un même constat sur une même URL restent deux singletons.
7. **Modèle** : pas d'alias pour la preuve brute ni pour l'identifiant-source du finding (exigés par
   la mission) — les créneaux existent (evidence, identity) mais la voie déclarative ne les remplit pas.
8. **Tests obsolètes** : `test_catalogue_outils` affirme encore « RECON et WEB n'ont AUCUNE capacité »
   — contredit le registre en service (déclaration Groupe B appliquée le 01/09). `test_escalade`
   dépend de binaires présents. `test_outil_hadolint`/`shellcheck` : `types.CompletedProcess` (n'existe
   pas) au lieu de `subprocess.CompletedProcess` → crash là où un « non évalué » était prévu.

## Décision d'architecture retenue

- Aucune nouvelle classe : le Finding existant (source/identity/location/severity/evidence) suffit ;
  deux alias déclaratifs de plus (`preuve` → evidence, `source_id` → identity.source_finding_id),
  dans la lignée de `remediation`/`confiance` (« déclarés par le manifest, jamais déduits »).
- ZAP = second niveau de la promesse : parser NOMMÉ (`parsers_zap.py`), manifest déclaratif,
  format `custom`. Aucun changement du cœur pour le comprendre.
- Nuclei/ffuf/nmap = première niveau : champs déclarés dans capabilities.yaml, zéro code.
- Cibles URL : le descripteur `cible.Cible` (déjà là, déjà branché à OPA via `cible_descr`) devient
  la source du `Target` typé ; `Sandbox` gagne un mode « cible distante » (pas de montage de scan,
  `--chdir` M_OUT) ; réseau toujours jugé par la commande construite (conditions.py, inchangé).
- Sélection : un provider ACTIVE n'entre dans le plan QUE si la capacité a été demandée
  explicitement (motif ≠ « demande générique ») — et la politique OPA garde la main (verrou
  `sandbox_non_durci_outil_actif` : non levé, hors de mon périmètre).
- Oracle : le DAST reste une OBSERVATION. `cycle.verified` n'est jamais posé par la normalisation ;
  `vue_unifiee` expose la projection « observe »/« verifie » dérivée du cycle — rien de plus.
