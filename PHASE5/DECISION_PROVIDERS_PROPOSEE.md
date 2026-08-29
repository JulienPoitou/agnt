# DÉCISION PROVIDERS — PROPOSÉE, NON APPLIQUÉE

_Date : 2026-08-28 · Statut : en attente de validation humaine · Rien n'est codé._

Ce document croise la recommandation de `PROJET_ETAT.md` §REPRISE (Groupes A/B) avec le
catalogue `PHASE1/08_FICHES_PROVIDERS.csv` (69 fiches, vérifiées cette session), la matrice
`PHASE1/09_MATRICE_COUVERTURE_PROVIDERS.csv` (17 capacités), les gates de `PHASE1/CRITERES.md`
et le code réel du bundle (`policy.rego`, `capabilities.yaml`, `provider_manifest.py`).

## 0. État réel vérifié dans le code (avant toute décision)

Le registre (`PHASE3/slice/capabilities.yaml`) contient :

| Capacité | Provider | Nature |
|---|---|---|
| CODE_STATIC_ANALYSIS | semgrep | réel, PASSIVE, cli |
| DEPENDENCY_ANALYSIS | trivy | réel, PASSIVE, cli |
| SECRET_DETECTION | gitleaks | réel, PASSIVE, cli |
| CODE_STATIC_ANALYSIS_SUITE | bandit | **interne** — preuve de test du manifest |
| CODE_STATIC_ANALYSIS_CUSTOM | bandit_custom | **interne** — preuve niveau 2 |

« Aucun provider ajouté » (REPRISE) se lit donc : aucun provider **du catalogue** ajouté.
Bandit/bandit_custom sont des véhicules de test marqués `interne: true`, invisibles du LLM.

**Écart déclaré** : la matrice marque 5 capacités « OUI » mais le registre n'en expose que 3.
CLOUD_POSTURE et CONTAINER_SCAN sont « OUI » au sens écosystème (Trivy sait le faire), pas au
sens registre (aucun provider ne le fait ici). À trancher quand un provider les couvrira.

## 1. Verdicts par candidat (preuves = fiches du catalogue)

### checkov — OUI, après une fixture IaC (corrigé le 2026-08-28)

| Critère | Valeur (fiche) |
|---|---|
| Licence | **Apache-2.0** |
| Forme | cli · passif · actif au 2026-08-27 · maturité élevée |
| Capacité | IAC_SCAN — **« NON » dans la matrice**, fiche : « IaC, capacité où on a RIEN » |
| Nouvelles capacités | 1 · chevauchement « partiel avec trivy » |

Seul candidat du Groupe A qui remplit un vrai trou avec une licence permissive, la forme
`cli` déjà supportée et un risque PASSIVE accepté par la politique courante. Intégration
attendue au **niveau 1** (manifest déclaratif, format json + spécification d'extraction),
comme bandit l'a prouvé — mais sur une capacité réelle, pas de test.

**Prérequis manquant (ajouté après contre-vérification du 2026-08-28)** : aucune cible IaC
n'existe dans le corpus — 0 fichier `.tf`, pas de Kubernetes/CloudFormation/Dockerfile dans
les fixtures (mesuré côté workspace source). Intégrer checkov sans fixture produirait un
scan vide et ne prouverait rien : c'est la leçon Semgrep/MCPGUARD exactement (règles
Python, dépôt TypeScript). La construction d'une fixture IaC minimale (Terraform + une
mauvaise configuration connue, avec identifiants de checks attendus) doit précéder
l'intégration.

À vérifier à l'intégration (non vérifié à ce jour) : fonctionnement hors ligne avec les
checks embarqués ; absence d'écho de valeurs sensibles dans la sortie (leçon #1 — Bandit) ;
échelle de sévérité à traduire (leçon #4) ; déclaration de couverture si l'outil est absent
(leçon #2) ; épinglage de la version dans `manifeste_dependances.yaml`.

### sigma — ATTENDRE une décision de cadrage

La fiche du catalogue dit elle-même : **« règles, pas un scanner : produit des requêtes »**.
Deux obstacles avant intégration :

1. **La sortie n'est pas un finding.** Le pipeline actuel normalise des findings ; sigma-cli
   produit des requêtes converties. Soit on décide d'un type de sortie « artifact », soit on
   n'intègre pas. C'est une décision de modèle de données, pas d'ajout de provider.
2. **Licence non renseignée dans la fiche** (colonne vide). Pour un usage CLI, la gate G2 ne
   bloque pas (CRITERES §2.1 : outil externe = non applicable), mais la redistribution des
   règles dans notre cache doit être traitée comme les règles Semgrep (téléchargement +
   épinglage par empreinte).

De plus, la valeur de sigma s'exprime sur des **logs** — un type de cible que le workflow
actuel (analyse de dépôt) ne manipule pas. Recommandation : reporter jusqu'à la décision de
cadrage, et réévaluer quand un workflow LOG_ANALYSIS existera.

### grype — REPORTER (décision SBOM déjà enregistrée : « à trancher plus tard »)

La fiche est sans ambiguïté : **chevauchement « FORT avec trivy », nouvelles capacités : 0**.
La justification « SBOM » de la REPISE ne correspond à aucune ligne de la matrice (vérifié :
17 capacités, pas de SBOM) et n'est pas comptée comme nouvelle capacité par le catalogue.
Un deuxième scanner CVE redondant ne prouve rien de plus que ce que bandit a déjà prouvé.
Si le SBOM devient un besoin : noter d'abord la capacité dans la matrice, puis choisir le
provider (trivy sait déjà exporter du SBOM — connaissance générale, non vérifiée ici).

### Groupe B (nmap, ffuf, zap) — REPORTÉ (décision déjà enregistrée), avec trois faits nouveaux

1. **Le verrou est réel et vérifié dans le code** : `policy.rego` refuse tout step
   ACTIVE/INTRUSIVE/DESTRUCTIVE quand `profil_sandbox.durci` est faux
   (motif nommé `sandbox_non_durci_outil_actif`). L'isolateur OCI n'ayant jamais été
   éprouvé (`test_oci.sh` non exécuté), le Groupe B est bloqué par construction.
2. **zap n'a AUCUNE fiche dans le catalogue des 69.** Il n'apparaît que dans la colonne
   « chevauchement » de nuclei et nikto. La recommandation Groupe B cite un outil que le
   catalogue ne connaît pas : fiche à créer avant toute discussion.
3. **Corrigé le 2026-08-28** : j'avais écrit « WEB_VULN_SCAN n'a aucun candidat cli »
   d'après le catalogue, qui fiche nuclei et nikto en `forme=api`. Les deux cellules sont
   fausses — nuclei est un binaire CLI en Go, nikto un script Perl en CLI. Une fois
   corrigées, la capacité a des candidats cli et aucun chantier sur la forme d'exécution
   n'est requis pour elle. Le verdict LATER ne change pas : il repose sur la couche
   d'autorisation (points 1 et 2). À retenir : le catalogue prévenait que le classifieur
   contient des erreurs — j'ai cité l'avertissement, puis fait confiance aux cellules.
4. Licences non renseignées dans les fiches nmap et zap (absent) : à compléter à la main
   (rappel : « le classifieur automatique contient des erreurs »).

## 2. Recommandation consolidée

```
NOW*   checkov   — IAC_SCAN, le seul vrai trou couvrable (1 provider,
                   boucle catalogue → manifest sur une capacité réelle)
                   *prérequis : fixture IaC minimale d'abord — aucun .tf nulle part, mesuré
NEXT   sigma     — après décision de cadrage « artifact vs finding » + licence
LATER  grype     — si et quand SBOM entre dans la matrice (décision déjà enregistrée)
LATER  Groupe B  — après couche d'autorisation + OCI éprouvé (décision déjà enregistrée)
                   + fiche zap à créer + forme api à trancher pour WEB_VULN_SCAN
```

Cohérent avec la leçon #7 (« ce qui compte c'est la capacité à en ajouter, pas le nombre ») :
un provider réel validé de bout en bout vaut mieux que trois à moitié fondés.

## 3. Ce qui a été vérifié pour produire ce document

- Extraction 33/33 du bundle, fidélité confirmée par diff contre les 3 originaux téléversés.
- Bootstrap reconstruit : exit 0, OPA épinglé 1.20.0 conforme au manifeste (correctif
  appliqué ce jour : URL épinglée + affichages de version protégés du SIGPIPE).
- Fiches catalogue lues directement (checkov, sigma, grype, nmap, ffuf, nuclei, nikto,
  trufflehog, bandit, trivy, gitleaks, semgrep, tfsec, kics).
- `policy.rego` lu : garde ACTIVE confirmée. `capabilities.yaml` lu : 5 capacités, dont
  2 internes. `provider_manifest.py` lu : formats json/sarif/custom, niveau 1/2.

**Non vérifié** (déclaré comme tel) : comportement réel de checkov hors ligne et contenu
exact de sa sortie JSON ; licence exacte du corpus Sigma ; export SBOM de trivy ; tout ce
qui dépend des batteries de tests, absentes du bundle (décision 2026-08-28 : continuer
sans — les portes du projet sont inexécutables dans cet environnement).

---

## 4. Addendum — contre-vérification du 2026-08-28

Les tests, absents du bundle, ont été exécutés dans le workspace source :
`test_correlation` **2/7**, `test_independant` **7/9**, `test_bwrap.sh` **3/11** (les
autres vertes). Cause racine unique : `capabilities.yaml:42` déclare
`--config={REGLES}/javascript.yaml`, que le bootstrap ne télécharge pas et que le
manifeste n'épingle pas — Semgrep sort en code 7 avec zéro finding, et la corrélation
inter-outils perd un de ses deux outils.

**Cette incohérence était visible statiquement dans le bundle reçu** (revérifié depuis :
`javascript.yaml` n'apparaît que dans `capabilities.yaml`, nulle part ailleurs), et le
cœur reçu n'est même pas importable (`import pipeline` → `ModuleNotFoundError:
adapters`). Un croisement références/téléchargements et un test d'import auraient suffi
— aucun test n'était nécessaire pour les voir. C'est le trou de vérification de la
session bundle ; `py_compile` seul ne prouve rien.

Conséquences actées :

1. La décision providers est **gelée** jusqu'à : arbitrage javascript.yaml (téléchargement
   + épinglage, ou retrait de la ligne — décision qui change ce qui est détecté), portes
   de nouveau vertes, fixture IaC construite.
2. L'exporteur doit parcourir l'arbre réel au lieu d'une liste de 33 chemins : 113
   fichiers manquaient, dont des modules importés par le cœur (`adapters.py`,
   `garde_chemin.py`, `parsers.py`, `run.py`). Le dilemme « réclamer les tests /
   continuer sans » était un faux choix.
3. Les corrections du présent document sont marquées en place (prérequis checkov,
   nuclei/nikto). Le manifeste OPA documentait déjà la dérive de `latest` (note, lignes
   37-40) avec échec bruyant et remède : le qualificatif « défaut caché le plus grave »
   était excessif ; la contradiction réelle était `version: 1.20.0` + `source: …/latest/…`,
   résolue par l'épinglage (arbitrage 1.20.0 figé vs 1.20.1 + empreinte mise à jour :
   non équivalents, à trancher).
