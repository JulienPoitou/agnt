# Dogfooding — étape 5 : observations sur cibles réelles (2026-08-29)

**Méthode.** Quatre dépôts publics clonés en shallow, commit figé
(`TARGETS.yaml`), analysés par le pipeline EXISTANT (`lancer.py` : aucune
logique nouvelle), en sandbox sans réseau. Preuves dans `rapports/<cible>/`
(raw, plan, rapport, clusters, METRIQUES.yaml, RAPPORT.md). Une anomalie
n'est pas une feature : ce document sépare ce qui a été **corrigé** (mesures
fausses) de ce qui est **observé** (laissé tel quel, délibérément).

## Cibles et résultats bruts

| Cible | Commit | Profil | Durée | Findings | Clusters inter-outils |
|---|---|---|---|---|---|
| gorilla/mux | db9d1d0 | Go, go.mod sans go.sum | 121 s | 5 (checkov 1, kics 4) | 0 (honnête : fichiers disjoints) |
| terraform-aws-vpc | cf0e3ca | 77 .tf + workflows GH | 137 s | 112 (checkov 39, kics 73) | **10** |
| psf/requests | 5460f46 | Python 37 .py | 56 s | 14 (semgrep 9, gitleaks 4, checkov 1) | 0 (honnête : sujets disjoints) |
| mochajs/mocha | e6b9ee7 | JS 243 .js + package-lock | 38 s | 38 (trivy 16, grype 16, kics 4, checkov 2) | **12** |

Aucune erreur d'exécution, aucun OOM (MemAvailable stable ~1 Go sur machine à
2 Go), 38-137 s par cible, 6 providers par mission.

## Corrigé pendant l'étape (2 mesures fausses — garde-fou n°2)

**C1. codes de succès kics incomplets.** Le manifest déclarait `[0, 60]`
d'après UNE observation (CRITICAL sur testrepo_iac). gorilla/mux (détections
LOW) a produit **30** — hors ensemble déclaré, provider marqué en échec à tort.
Corrigé en échelle complète `[0, 20, 30, 40, 50, 60]` (INFO/LOW/MEDIUM/HIGH/
CRITICAL), mesurée sur deux cibles et confirmée par la documentation kics.
Test modifié avec justification (test_grype_kics 1e).

**C2. cwd de la sandbox non déterministe → corrélation inter-outils aveugle.**
Sans `--chdir`, bwrap hérite du cwd du processus parent ; kics relativise ses
chemins par rapport au cwd — les MÊMES fichiers portaient des identifiants
différents selon le point de lancement (« PHASE3/mt-scan/main.tf » vs
« mt-scan/main.tf ») et ne matchaient ni entre eux, ni avec checkov
(« /main.tf »). Fix : `--chdir {M_SCAN}` (racine de scan, lecture seule).
Mesure avant/après sur terraform-aws-vpc : clusters inter-outils **0 → 10**.
ATTENDUS de testrepo_iac régénérés par le harnais ; 30/30 + régression verte.

**C3. affichage humain : basenames indiscernables.** Le RAPPORT.md affichait
« Fichiers : `package-lock.json`, `package-lock.json` » — en réalité
`docs/package-lock.json` ET `package-lock.json`, deux fichiers RÉELS de mocha
que le raccourci `split('/')[-1]` rendait indiscernables (un affichage qui fait
mentir une distinction). Corrigé : chemins complets. Vérifié en régénérant le
rapport mocha ; test_rapport_humain 18/18.

## Observé, non corrigé (volontairement)

**O1. « not_scanned » quand un outil scanne et ne trouve rien.** semgrep sur
mux (Go) et semgrep_go sur requests (Python) ressortent `not_scanned` : le
mécanisme declare_fichiers ne voit aucun fichier déclaré quand il n'y a aucun
finding. La sortie semgrep liste pourtant les chemins examinés (`paths.scanned`)
— piste d'honnêteté pour plus tard, PAS une urgence : l'état actuel est
prudent (sous-déclare la couverture, ne sur-déclare jamais).

**O2. codes de sortie kics non totalement prévisibles.** terraform-aws-vpc :
73 détections (dont HIGH) → code 0 ; mux : mêmes détections LOW → 30 au run 1,
0 au run 2. L'échelle déclarée couvre tous les cas observés ; la sémantique
exacte reste floue — documentée ici plutôt que devinée.

**O3. les providers IaC couvrent GitHub Actions.** checkov (CKV2_GHA_1) et
kics (requêtes CICD) détectent légitimement dans `.github/workflows/*.yml` —
les 5 findings « IaC » de mux sont des findings CI. Pas un faux positif :
une couverture réelle à nommer comme telle dans les rapports.

**O4. divergence de couverture trivy/grype sur requirements-dev.txt.** trivy
lit `requirements*.txt` ; le glob grype déclaré (`*requirements.txt`) ne matche
pas `requirements-dev.txt` mais matche `docs/requirements.txt` (fnmatch `*`
traverse `/` — connu étape 3). Sur requests : les deux tournent, 0 finding
chacun (dépendances dev à jour). Divergence potentielle enregistrée ; aucun
changement de glob sans occurrence mesurée qui le justifie.

**O5. gitleaks sur du vrai monde : 4 clés privées de fixtures de tests**
(`tests/certs/**` de requests, certificats expirés/de test). --redact a joué
(aucune valeur stockée). Le triage « vraie clé vs fixture » est une
responsabilité de rapport humain, pas du moteur — le RAPPORT.md montre fichier
+ règle, l'humain décide.

**O6. semgrep (python) tourne sur toutes les cibles** (provider legacy sans
applicabilité déclarable — dette déjà notée à l'étape 4) : ~15-30 s perdus sur
mux/terraform-aws-vpc. Coût mesuré, dette confirmée, pas de feature ajoutée.

**O7. convergence SCA en conditions réelles (mocha) : 11/11 paquets communs,
décomptes par paquet IDENTIQUES (16 = 16), namespaces distincts (CVE vs GHSA),
12 clusters cross_tool à raisons explicites** (`cross_tool, same_package,
related_dependency, tools:grype+trivy`). Le fan-out prouvé en étape 4 sur
fixture se confirme sur un vrai lockfile de production.

**O8. applicabilité honnête dans les deux sens** : grype écarté de mux (pas de
go.sum) et de terraform-aws-vpc (aucun lockfile) avec motif tracé dans le plan ;
semgrep_go écarté des cibles sans .go. Aucune exclusion silencieuse observée.

## Effets de bord vérifiés

pool.yaml régénéré (empreinte du registre changée par C1). Régression complète
après C1+C2 : voir PROJET_ETAT.md (entrée étape 5).
