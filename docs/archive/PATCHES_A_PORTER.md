# PATCHES À PORTER VERS LE WORKSPACE SOURCE — 2026-08-28 (rév. 2)
> **⚠️ Artefact daté (2026-08-28), non maintenu depuis.** Trois commits de chantier ont
> suivi (`f400fe6`, `59d987f`, `6298dae`) : ce qui est décrit ici comme « à porter » est en
> partie porté, et `_transfert/` n'existe plus. État réel : `PROJET_ETAT.md`.


> **Artefact exécutable prêt** : le dossier `_transfert/` contient le patch unifié,
> la fixture et `APPLIQUER.sh` (testé sur extraction vierge : exit 0). Ce document
> reste la référence lisible hunk par hunk, en secours si le dry-run du patch échoue.

Établi par la session bundle. Tout ce qui est marqué « vérifié ici » a été prouvé par
exécution dans ce workspace. Les tests du projet (batteries) n'existent pas ici : les
suites marquées « à relancer côté source » sont le juge final.

## A. Réparation de la porte — javascript.yaml (vérifié ici)

Cause des échecs `test_correlation` 2/7 et `test_independant` 7/9 : `capabilities.yaml`
déclare `--config={REGLES}/javascript.yaml`, jamais téléchargé ni épinglé → Semgrep
sort en code 7 avec zéro finding.

1. `PHASE3/bootstrap.sh` — boucle de règles :
   ```diff
   -for r in python security-audit; do
   +for r in python security-audit javascript; do
   ```
   et boucle de signalisation de divergence :
   ```diff
   -  for r in python.yaml security-audit.yaml; do
   +  for r in python.yaml security-audit.yaml javascript.yaml; do
   ```
2. `PHASE3/manifeste_dependances.yaml` — section `regles:`, ajouter :
   ```yaml
   javascript.yaml:
     source: https://semgrep.dev/c/p/javascript
     sha256: e65e8449157ef5d587f2c2a0c17ed388910ca90336e514d27941ccd25543cf4e
   ```
3. Vérifié ici : Semgrep avec les trois configs → **exit 0, 0 erreur**, règles JS
   déclenchées sur fichier de test. À relancer côté source : `test_correlation`,
   `test_independant`.
4. **Note mesurée** : la règle `avoid-pyyaml-load` des packs épinglés ne matche que les
   formes réellement dangereuses (`unsafe_load`, `Loader=yaml.Loader`…) — `yaml.load(f)`
   nu ne matche plus. Si `test_independant` attend un finding sur du `yaml.load` nu,
   l'attente ou la fixture doivent être revues — c'est le jeu de règles qui a évolué.

## B. bootstrap.sh — OPA épinglé + affichages sans tube (vérifié ici : exit 0)

```diff
 GITLEAKS_VERSION=8.30.1
+OPA_VERSION=1.20.0
```
```diff
 [ -x "$BIN/opa" ] || {
-  log "opa"
-  curl -sL -o "$BIN/opa" "https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static"
+  log "opa $OPA_VERSION"
+  curl -sL -o "$BIN/opa" "https://openpolicyagent.org/downloads/v$OPA_VERSION/opa_linux_amd64_static"
 }
```
```diff
-"$BIN/trivy" --version | head -1
-"$BIN/gitleaks" version
-"$BIN/opa" version | head -1
-semgrep --version | tail -1
+# Affichages : capture complète puis extraction — aucun tube, donc aucune course
+# SIGPIPE avec pipefail (le 141 intermittent, que `|| true` ne ferait que masquer).
+_v=$("$BIN/trivy" --version 2>/dev/null) && printf '%s\n' "${_v%%$'\n'*}" || true
+"$BIN/gitleaks" version || true
+_v=$("$BIN/opa" version 2>/dev/null) && printf '%s\n' "${_v%%$'\n'*}" || true
+_v=$(semgrep --version 2>/dev/null) && printf '%s\n' "${_v##*$'\n'}" || true
```
**Arbitrage ouvert** : 1.20.0 figé (choix validé ici, manifeste vrai) vs 1.20.1 +
empreinte mise à jour (`0b3f152e61be…`, mesurée par les deux sessions).

## C. Intégration checkov — IAC_SCAN, niveau 1 (vérifié ici sauf pipeline complet)

Fichiers modifiés/ajoutés ici, à porter tels quels :

| Fichier | Changement |
|---|---|
| `PHASE3/slice/capabilities.yaml` | capacité `IAC_SCAN` + provider `checkov` (manifest niveau 1) |
| `PHASE3/slice/provider_manifest.py` | `BINAIRES_AUTORISES` : `+ "checkov"` (seule ligne de cœur touchée — liste blanche assumée) |
| `PHASE3/slice/intent.py` | `MOTIFS["IAC_SCAN"]` : infrastructure, terraform, iac, cloudformation, mauvaise(s) configuration(s), checkov |
| `PHASE3/bootstrap.sh` | `command -v checkov || pip install --quiet checkov` |
| `PHASE3/manifeste_dependances.yaml` | entrée `checkov` (pip, distribution_hash `5173f1f5…`) |
| `PHASE3/testrepo_iac/` | fixture IaC (main.tf, k8s.yaml, Dockerfile, README, **ATTENDUS.yaml extrait d'exécution**) |

**Vérifié ici par exécution** :
- checkov 3.3.15 sur la fixture : 38 findings, **résultats identiques avec et sans
  réseau** (bwrap `--unshare-net`) — fonctionnement hors ligne prouvé ;
- le faux secret de la fixture n'apparaît dans aucune sortie (leçon #1) ;
- `severity` est **null en sortie OSS** (0/15) → gravité « indéterminée », jamais
  inventée (leçon #4) ; `description`/`short_description` null aussi → `message` mappé
  sur `check_name` ;
- `provider_manifest.valider()` : OK après ajout à la liste blanche (sans lui : refus
  « binaire non autorisé » — le contrôle de Phase 5A fonctionne) ;
- extraction déclarée : 15/15 items terraform projetés (regle, nom_regle, fichier,
  ligne via `file_line_range[0]`, message, severite, reference) ;
- intent (registre duck-typé, `parsers.py` absent du bundle) : « mauvaises
  configurations de mon IaC » → IAC_SCAN seul ; « Vérifie les dépendances » →
  DEPENDENCY_ANALYSIS seul (pas de fuite) ; INTERDIT intact.

**À relancer côté source** : `test_intentions` (nouveaux MOTIFS), `test_manifest`
(un manifest de plus — attentes extensibles), `test_slice` (une demande générique
inclut désormais IAC_SCAN : la composition du plan change), et un run `analyser.py`
complet sur `testrepo_iac` (le pipeline sandboxé ne peut pas tourner ici).

**Limites déclarées dans le manifest** : framework terraform uniquement (racine JSON
en liste avec plusieurs frameworks, illisible en modèle plat) ; kubernetes/dockerfile
non couverts par cette déclaration (déclaration sœur possible sans toucher au cœur).

## D. Catalogue — deux cellules corrigées (fait ici)

`PHASE1/08_FICHES_PROVIDERS.csv` : nuclei et nikto `forme_execution` **api → cli**
(binaire Go CLI / script Perl CLI). Conséquence : WEB_VULN_SCAN a des candidats cli.

## E. Exporteur — à réécrire côté source (rappel rév. 1)

Parcourir l'arbre réel (~146 fichiers) au lieu de 33 chemins codés en dur ; inclure
tests, fixtures, `adapters.py`, `garde_chemin.py`, `parsers.py`, `run.py` — sans eux le
bundle ne s'importe même pas (`import pipeline` → `ModuleNotFoundError: adapters`,
mesuré ici). Ajouter en en-tête du bundle : compte de fichiers + empreinte globale.

## F. Fichiers de la session bundle à porter

- `PHASE5/DECISION_PROVIDERS_PROPOSEE.md` — brief providers corrigé + addendum.
- `_extraire.py` — extraction ancrée sur les en-têtes (utilitaire de réception).
