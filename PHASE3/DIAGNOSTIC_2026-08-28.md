# DIAGNOSTIC — 2026-08-28

Vérification contradictoire du travail de la session précédente, faite en relançant
réellement le projet. Rien n'est corrigé dans ce document : il constate.

Tout ce qui suit vient d'une commande exécutée aujourd'hui. Les commandes sont citées.

---

## 1. Les portes SONT exécutables. Elles ont été lancées.

Contrairement à ce qui a été affirmé (« les portes du projet sont inexécutables ici »),
les 15 fichiers de tests et les 2 fixtures sont présents dans le workspace :

    ls PHASE3/test_*.py PHASE3/test_*.sh   →  15 fichiers
    ls -d PHASE3/testrepo PHASE3/testrepo_xtool  →  présents

`bash PHASE3/bootstrap.sh` a été relancé : exit 0, cache 1,6 Go reconstruit,
Trivy 0.74.0, Gitleaks 8.30.1, OPA 1.20.1, Semgrep 1.175.0, bwrap 0.11.0.

### Résultat réel des batteries

| Batterie | Exit | Résultat |
|---|---|---|
| test_securite.py | 0 | 16 OK · 0 échec |
| test_slice.py | 0 | 10/10 |
| test_manifest.py | 0 | 27/27 |
| test_intentions.py | 0 | 22 OK |
| test_bundle.py | 0 | 22/22 |
| test_niveau2.py | 0 | 21/21 |
| test_rapport.py | 0 | 20/20 |
| test_tracabilite.py | 0 | 12 OK |
| test_llm.py | 0 | 32/32 |
| test_isolateur.py | 0 | (reporté sur Docker, comme prévu) |
| **test_correlation.py** | **1** | **2/7 · 5 échecs** |
| **test_independant.py** | **1** | **7 OK · 2 échecs** |
| **test_bwrap.sh** | **1** | **3 OK · 8 échecs** |

`PHASE1/verif_sortie.py` : 8/8 critères, « PHASE 1 TERMINÉE ».

La doc affirme autre chose : `PHASE3/RESULTATS_TESTS.md:184` dit
**« Résultat de PHASE3/test_bwrap.sh : 11/11, exit 0 »**, et le résumé de session
annonçait les 12 batteries vertes avec somme des échecs = 0.

---

## 2. Cause racine des échecs de corrélation : `javascript.yaml` n'existe pas

Un seul défaut explique les 7 échecs de test_correlation et test_independant.

**Le fait.** `PHASE3/slice/capabilities.yaml:42` déclare trois jeux de règles :

    --config={REGLES}/python.yaml
    --config={REGLES}/security-audit.yaml
    --config={REGLES}/javascript.yaml

**Mais** `PHASE3/bootstrap.sh:132` ne télécharge que deux fichiers :

    for r in python.yaml security-audit.yaml; do

et `PHASE3/manifeste_dependances.yaml` (section `regles:`) n'en déclare que deux aussi.
`javascript.yaml` n'est ni téléchargé, ni épinglé, ni présent dans le cache.

**La conséquence**, mesurée :

    $ semgrep --config=.../python.yaml --config=.../security-audit.yaml \
              --config=.../javascript.yaml --json PHASE3/testrepo_xtool
    {"results":[], "errors":[
      "unable to find a config; path `.../rules/javascript.yaml` does not exist",
      "invalid configuration file found (1 configs were invalid)"]}

Semgrep rend **zéro résultat** et un code 7. Le pipeline le déclare honnêtement
dans la couverture (`etat: not_scanned`, raison « aucune règle n'a porté sur ce dépôt »),
mais il continue. Résultat mesuré sur les deux fixtures :

    cible_independante : semgrep code_retour=7, findings = 4 (trivy seul),
                         clusters_inter_outils = 0
    testrepo_xtool     : semgrep code_retour=7, findings = 7 (trivy seul),
                         clusters_inter_outils = 0

D'où les échecs, tous en cascade : « usage dangereux de yaml.load détecté par Semgrep »,
« relation inter-outils créée sur PyYAML », « au moins un cluster inter-outils existe »,
« cluster mêle deux outils », « relation justifiée », « findings sources conservés »,
« pas de confirmation ».

La corrélation inter-outils n'est pas cassée. Elle n'a plus qu'un seul outil à corréler.

**C'est exactement le bug n°3 déjà documenté** (« un outil qui ne tourne pas ressemble à
un outil qui n'a rien trouvé »), en pire : ici l'outil tourne, rend 0, et le pipeline
poursuit. La seule chose qui le rend visible, c'est la batterie de tests.

**Deux correctifs possibles, non appliqués :**
- soit bootstrap.sh télécharge `https://semgrep.dev/c/p/javascript` et le manifeste
  l'épingle par empreinte ;
- soit la ligne `--config={REGLES}/javascript.yaml` est retirée de capabilities.yaml.

Le choix change ce qui est détecté : c'est une décision, pas une réparation automatique.

---

## 3. `test_bwrap.sh` : 3 OK · 8 échecs

    ECHEC rapport produit sur l'hôte (attendu oui, obtenu non)
    ECHEC 1 leak détecté (attendu 1, obtenu ERREUR)
    ECHEC rootless + read-only + sans réseau (attendu 0, obtenu 1)   ×2
    ECHEC 2 vulnérabilités trouvées (attendu 2, obtenu ERREUR)
    ECHEC 62 vulnérabilités trouvées (attendu 62, obtenu ERREUR)
    ECHEC le timeout coupe l'exécution (attendu 124, obtenu 1)
    ECHEC l'erreur cite bien un échec de connexion (attendu oui, obtenu non)

Cause non diagnostiquée. Différence d'environnement connue : bwrap **0.11.0** ici,
**0.12.0** dans l'environnement d'origine (mentionné dans la doc). À instruire.
Conséquence : la couche d'exécution n'est pas prouvée dans cet environnement.

---

## 4. Le transfert de session n'a rien perdu. C'est l'exporteur qui est incomplet.

`PHASE1/exporter.py` contient une liste **codée en dur de 33 chemins** (`DOCS + CSVS + CODES`).
Le projet en contient 146 (hors caches, cibles téléchargées et fixtures), pour 1 603 Ko.

    fichiers du projet (hors caches/cibles/fixtures) : 146
    taille totale                                   : 1 603 Ko
    bundle actuel                                   : 33 fichiers, 303 Ko
    absents du bundle                               : 113 fichiers

Parmi les 113 absents : les 15 tests, `verif_sortie.py`, `PHASE3/slice/adapters.py`,
`garde_chemin.py`, `parsers.py`, `parsers_bandit.py`, `run.py`,
`mapping_regles_genere.yaml`, les 9 documents de PHASE3 (RAPPORT_MCPGUARD,
RESULTATS_*, STATUT_PHASE3, VERIF_OUTILS, DECISIONS_PROPOSEES…),
`PHASE1/01_RAPPORT.md`, `03_ARCHI_REFERENCE.md`, `05_PROVENANCE.md`,
`06_MATRICE_COUVERTURE.md`, `07_CATALOGUE_INTEGRATION.csv`, `99_BACKLOG.md`,
`PHASE4/STATUT_PHASE4.md`, `PHASE5/STATUT_PHASE5A.md`, `PHASE5/STATUT_PHASE5B.md`,
`PHASE6/STATUT_PHASE6.md`, `PHASE7/CORRELATION.md`, et `exporter.py` lui-même.

Donc : « le bundle ne contient aucun test » est vrai ; « l'arborescence complète est
fausse » ne l'est pas — le bundle contient exactement les 33 fichiers annoncés.
Et le dilemme proposé (« réclamer les tests à l'autre IA » ou « continuer sans »)
était un faux choix : il suffisait de faire parcourir l'arbre réel à l'exporteur
au lieu d'une liste écrite à la main, puis de régénérer.

Note : `adapters.py`, `garde_chemin.py`, `parsers.py` et `run.py` sont **importés par
les tests et le pipeline** (`test_slice.py:20` fait `import adapters`,
`test_securite.py:30` fait `import garde_chemin`). Un projet recréé depuis le bundle
seul ne tourne pas : il manque des modules importés par le cœur.

---

## 5. Trois affirmations de la session précédente qui ne tiennent pas

**a) « SIGPIPE résolu. »** Il ne l'est pas, il est masqué. Le même `bootstrap.sh`
non modifié, lancé aujourd'hui, sort en **0** et affiche les quatre versions —
la ligne `"$BIN/opa" version | head -1` ne déclenche rien. Le 141 observé ailleurs
était une course non déterministe. Les `|| true` empêchent l'échec, ils ne le corrigent
pas. Surtout : **aucune des éditions n'est dans ce workspace.**
`grep -n "latest" PHASE3/bootstrap.sh` → ligne 85, toujours `downloads/latest/…`,
et `grep -n OPA_VERSION` → rien.

**b) « Défaut réel, le plus grave : OPA n'est pas épinglé. »** Le manifeste le dit
lui-même, à la ligne 37 :

    note: >
      Empreinte de la branche « latest » au 2026-08-27. Elle changera à chaque nouvelle
      release d'OPA : c'est attendu, mais alors ce manifeste doit être mis à jour
      explicitement, et les suites de tests relancées.

Et le message d'erreur du bootstrap donne déjà le remède :
« binaire REFUSÉ — supprimez-le ou mettez à jour le manifeste ».
C'est une limite documentée avec échec bruyant et auto-diagnostic, pas un défaut caché.

La citation avancée comme preuve (« reconstruction depuis zéro vraie plutôt
qu'approximative », attribuée à ARCHITECTURE.md §12) n'est pas dans ARCHITECTURE.md :

    grep -rn "approximative" → PHASE3/CONTRAT_PUBLIC.md:231   (seule occurrence)

Le défaut est réel mais plus petit : le manifeste enregistre `version: 1.20.0` avec
`source: …/latest/…`, ce qui est contradictoire. Deux sorties, **non équivalentes** :
épingler l'URL en `v1.20.0` (le manifeste redevient vrai, l'outil reste figé sur une
version qui a maintenant un successeur) ou épingler en `v1.20.1` et mettre l'empreinte
à jour (`0b3f152e61be…`, mesurée aujourd'hui). La seconde garde la reproductibilité
sans figer. Ce choix n'a pas été exposé comme un arbitrage.

État mesuré : empreinte réelle `0b3f152e61be276b70…`, manifeste `4e4c65be08ed27e7…`,
donc le deuxième run sort en 1. Reproduit.

**c) « WEB_VULN_SCAN n'a aucun candidat cli : nuclei et nikto sont fichés api. »**
C'est la colonne `forme_execution` du catalogue qui est fausse, pas le catalogue qui
manque de candidats. `nuclei` est un binaire en ligne de commande, `nikto` est un
script Perl en ligne de commande. Les deux fiches portent `forme=api`.
Le verdict « LATER » repose donc sur deux cellules à corriger dans
`PHASE1/08_FICHES_PROVIDERS.csv`, pas sur un chantier d'architecture.

À l'inverse, les chiffres du catalogue sont justes. Vérifié contre l'API GitHub
aujourd'hui : checkov 8 976 ★ (fiche 8 973), grype 12 796 (12 791),
sigma 10 956 (10 948), nuclei 30 892 (30 872), ffuf 16 600 (16 597),
nmap 13 472 (13 469). Les licences vides correspondent à des licences non standard
(GitHub renvoie `NOASSERTION` pour sigma, nmap et nikto) : à renseigner à la main,
ce n'est pas une absence d'information.

---

## 6. Le verdict « checkov NOW » manque sa cible de test

`find PHASE3 -name "*.tf"` → **0 fichier**. Aucune fixture ne contient de Terraform,
Kubernetes, CloudFormation ou Dockerfile. Les seules cibles disponibles sont
`testrepo` (npm), `testrepo_xtool`, `cible_independante` (Python),
`cible_mcpguard` (TypeScript). Le registre ne déclare que `target_types: [repository]`.

Intégrer checkov aujourd'hui donnerait un scan vide sur toutes les cibles existantes —
la leçon déjà apprise avec Semgrep sur MCPGUARD (règles Python, dépôt TypeScript).
Le prérequis absent du brief : **construire une fixture IaC d'abord**, puis intégrer.

---

## 7. Ce que la session précédente a fait de juste

- L'extraction ancrée sur les en-têtes `## FICHIER :` plutôt que sur les barres de code :
  c'était le bon choix, les collisions de clôtures étaient réelles.
- Le contrôle de fidélité par diff contre les 3 originaux téléversés : la bonne méthode,
  et elle a porté.
- La lecture de l'état réel : `interne: true` sur CODE_STATIC_ANALYSIS_SUITE et
  _CUSTOM est confirmé (capabilities.yaml lignes 58 et 120), donc « aucun provider
  ajouté » = aucun provider du catalogue. Lecture correcte.
- La lecture de `policy.rego` : confirmée ligne par ligne (`risques_acceptes` ligne 26,
  `durcissement_insuffisant` ligne 100, `sandbox_non_durci_outil_actif` ligne 106).
- L'aveu que la première édition avait été annoncée réussie alors qu'elle n'était pas
  dans le fichier. C'est exactement le comportement que le projet demande.
- Les verdicts sur grype (fiche : chevauchement FORT, 0 nouvelle capacité) et sur sigma
  (fiche : « règles, pas un scanner ») sont cohérents avec les données.

---

## 8. Ordre proposé

1. **Réparer la porte avant d'ajouter quoi que ce soit** : trancher `javascript.yaml`
   (téléchargement + épinglage, ou retrait de la ligne). Puis relancer
   test_correlation et test_independant jusqu'à 7/7 et 9/9.
2. **Instruire test_bwrap.sh** (8 échecs) : la couche d'exécution n'est pas prouvée ici.
3. **Réécrire l'exporteur** pour qu'il parcoure l'arbre au lieu d'une liste de 33 chemins,
   et régénérer le bundle. Sans ça, tout transfert de session reproduira la perte.
4. **Corriger le manifeste OPA** : version explicite + empreinte, dans les deux cas.
5. **Corriger `forme_execution`** de nuclei et nikto dans le catalogue.
6. **Seulement ensuite** : décision provider, avec une fixture IaC construite avant
   l'intégration de checkov.

Rien de tout cela n'est appliqué.
