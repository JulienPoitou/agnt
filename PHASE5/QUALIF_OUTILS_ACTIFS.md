# Qualification des outils actifs — nmap, nuclei, ffuf (Groupe B)

**Statut : PROPOSITION — épingle mesurée, déclaration NON appliquée.**
Date : 2026-09-01. Suite de `DECISION_PROVIDERS_PROPOSEE.md` (Groupe B = LATER
« après couche d'autorisation + OCI éprouvé »). Chantier `qualif/outils-actifs`.

## 1. Ce que ce dossier est — et ce qu'il n'est pas

**Est** : l'armement vérifié des trois premiers outils actifs de pentest, prêt à
passer le harnais dès que ses prérequis sont levés. Les binaires sont
téléchargés, leurs empreintes mesurées, l'exécution vérifiée, les blocs de
déclaration rédigés.

**N'est pas** : une activation. Rien n'est déclaré dans `capabilities.yaml` :
aucun provider `nmap`/`nuclei`/`ffuf` n'existe dans le registre tant que les
prérequis de la section 5 ne sont pas levés. C'est la règle du projet — « le
proposer serait le déclarer sans l'avoir vu » — appliquée aux outils actifs,
où une fausse déclaration coûte plus cher qu'en analyse statique : un scan
actif contre une cible n'est pas une lecture, c'est un contact.

Trois verrous indépendants protègent l'activation, et aucun n'est levé ce jour :

| Verrou | Où | État |
|---|---|---|
| Isolateur OCI éprouvé (`test_oci.sh` 10/10) | `PHASE3/test_oci.sh` | **Jamais exécuté** — chantier `oci/epreuve-isolation` en cours |
| D9 : jeton `{URL}` (cibles non-chemins) | `PHASE3/DECISIONS_PROPOSEES.md` | En attente d'arbitrage |
| Profil durci (`profil_sandbox.durci`) | `slice/profils.py` + `policy.rego` | Faux — `policy.rego` refuse tout step ACTIVE (`sandbox_non_durci_outil_actif`) |

## 2. État dans le pool (PHASE1)

| Outil | Fiche | Triage | Verdict phase1 | Licence |
|---|---|---|---|---|
| nmap | `08_FICHES_PROVIDERS.csv:8` — NETWORK_DISCOVERY | TRIAGE-HAUTE, 🔴 Offensive | A_NOTER | NPSL — « licence inconnue » au triage, identifiée depuis : à arbitrer |
| nuclei | `08_FICHES_PROVIDERS.csv:20` — WEB_VULN_SCAN | SHORTLIST | INTEGRATE | MIT |
| ffuf | `08_FICHES_PROVIDERS.csv:22` — WEB_ENDPOINT_DISCOVERY | TRIAGE-MINIMAL | A_NOTER | MIT |

Correction déjà enregistrée dans la décision Groupe B : nuclei est une **CLI**,
pas une « api » (le champ `forme_execution` de la fiche était faux).

## 3. Épinglage mesuré le 2026-09-01

Les empreintes sont dans `PHASE3/manifeste_dependances.yaml` (section
`binaires`, rôle `outil-actif`). Régime d'attestation :

- **nuclei 3.11.1** — archive `nuclei_3.11.1_linux_amd64.zip` : SHA-256 mesuré
  localement **ET** publié par l'API GitHub (`assets[].digest`), les deux
  coïncident (`ea63d4ae…`). Binaire extrait : `c4958814…`. Exécution vérifiée
  sous WSL Ubuntu 24.04 : `nuclei -version` → v3.11.1.
- **ffuf 2.2.1** — archive `ffuf_2.2.1_linux_amd64.tar.gz` : même double
  attestation (`86307885…`). Binaire extrait : `6325a181…`. Exécution vérifiée :
  `ffuf -V` → 2.2.1.
- **nmap 7.98** — pas de binaire Linux autonome publié en amont : le tarball
  source `nmap-7.98.tar.bz2` est épinglé (`ce847313…`), le régime binaire est
  « note » (comme detect-secrets) : empreinte dépendante de la chaîne de build.
  La construction exige la toolchain dans l'isolateur — même chantier que gosec.

Les binaires extraits sont déposés dans `~/.cache/arena_secops/bin` (cible WSL)
où `bootstrap.sh` les vérifiera contre le manifeste au moment de l'armement.

## 4. Forme de déclaration proposée (à coller dans `capabilities.yaml` UNIQUEMENT à l'activation)

Nouvelles capacités (identifiants du pool, matrice `09_MATRICE_COUVERTURE_PROVIDERS.csv`) :

```yaml
  - id: NETWORK_DISCOVERY
    description: >
      Découverte d'hôtes, de ports et de services sur une cible réseau — ACTIVE,
      exige un profil durci (isolateur OCI éprouvé) et une cible explicitement
      autorisée (jeton {URL}, décision D9).
    domaines: [reseau, offensive]
    entree: [cible]
    sortie: finding/host-service
    providers:
      - id: nmap
        kind: tool
        mode: CLI
        risque: ACTIVE
        cout: eleve
        priorite: 100
        commande: ["{BIN}/nmap", "-oX", "{sortie}"]
        # args réels à figer par exécution mesurée (harnais), pas à deviner :
        # -Pn/-sT/-sV selon profil, --datadir épinglé, -oX obligatoire (parsing).
        target_types: [host, network, url]

  - id: WEB_VULN_SCAN_ACTIVE
    description: >
      Scan de vulnérabilités web par modèles (nuclei) — ACTIVE, mêmes verrous.
    domaines: [webapp, offensive]
    entree: [cible]
    sortie: finding/web-vuln
    providers:
      - id: nuclei
        kind: tool
        mode: CLI
        risque: ACTIVE
        cout: moyen
        priorite: 110
        commande: ["{BIN}/nuclei"]
        manifest:
          id: nuclei
          kind: tool
          mode: cli
          binaire: nuclei
          tool_id: nuclei
          argv: ["{BIN}", "-target", "{TARGET}", "-jsonl", "-o", "{sortie}",
                 "-templates", "{REGLES}/nuclei-templates", "-silent"]
          output: { format: jsonl }
          extraction: { modele: plat, items_from: "<à mesurer sur sortie réelle>",
                        parser: "à écrire + harnais" }
          risk: ACTIVE
          target_types: [url]
          code_succes: [0]        # à confirmer par mesure (nuclei sort 0 même avec findings ?)
          conditions:
            base_fichiers: ["nuclei-templates"]   # même discipline que {DB}/trivy

  - id: WEB_ENDPOINT_DISCOVERY_ACTIVE
    description: >
      Découverte de chemins/paramètres web par fuzzing de liste de mots (ffuf) —
      ACTIVE, mêmes verrous.
    domaines: [webapp, offensive]
    entree: [cible]
    sortie: finding/web-endpoint
    providers:
      - id: ffuf
        kind: tool
        mode: CLI
        risque: ACTIVE
        cout: moyen
        priorite: 120
        commande: ["{BIN}/ffuf"]
        manifest:
          id: ffuf
          kind: tool
          mode: cli
          binaire: ffuf
          tool_id: ffuf
          argv: ["{BIN}", "-u", "{TARGET}/FUZZ", "-w", "{REGLES}/wordlists/<épinglée>",
                 "-of", "json", "-o", "{sortie}", "-s"]
          output: { format: json }
          extraction: { modele: plat, items_from: "<à mesurer>" }
          risk: ACTIVE
          target_types: [url]
          code_succes: [0]
```

Les champs marqués « à mesurer » sont précisément le travail de qualification
restant : ils se remplissent par exécution réelle sur une cible de contrôle
locale (section 6), jamais en copiant la documentation.

## 5. Prérequis d'activation (checklist, tout doit être vrai)

1. `bash PHASE3/test_oci.sh` → **10/10, 0 échec** sur la machine d'exécution.
2. **D9 passée** (jeton `{URL}` + `cible_autorisee` — le correctif F2 du même
   domaine n'est pas bloquant mais traite le même fichier).
3. Profil `durci: true` disponible (`profils.py`) et arbitrage **NPSL nmap** par
   le propriétaire (usage interne vs redistribution).
4. **Autorisation des cibles externes** : un scan actif ne se lance que contre
   une cible que le propriétaire a le droit de tester. Le registre des cibles
   admises (`AGNT_CIBLES`) doit distinguer un dépôt local d'une URL autorisée —
   c'est D9, pas un détail d'interface.
5. Épingle des données tierces : `nuclei-templates` (commit + empreinte, comme
   les règles semgrep) et la wordlist ffuf (fichier épinglé).
6. Cibles de test locales : une fixture `testrepo_url` servie par un serveur
   HTTP local (le scan se fait contre `127.0.0.1`, jamais contre un tiers).

## 6. Plan de harnais (après levée des prérequis)

Sur le modèle de `test_outil_detect_secrets.py` (le contrat d'extension) :

1. exécution réelle de l'outil contre la cible de contrôle **hors isolateur**,
2. parsing de la sortie brute → findings normalisés (modèle plat, blocs
   source/location/severity/evidence),
3. idem **sous l'isolateur durci** (OCI) — le résultat doit être identique,
4. cas d'entrée sale : sans templates épinglés (nuclei), sans wordlist (ffuf),
   sans `-oX` (nmap) → refus ou sortie vide assumée, jamais un faux « 0 constat »,
5. `code_succes` réels mesurés (et pas supposés),
6. statuts par outil (indisponible/inapplicable/écarté) conformes à
   `test_statuts_outils.py`.

## 7. Ce qui est déjà vérifiable sans les prérequis

`PHASE3/test_qualif_outils_actifs.py` (nouvelle suite, verte aujourd'hui) fixe
les invariants fail-closed du chantier : aucun provider actif déclaré dans le
registre tant que l'OCI n'est pas éprouvé, aucun profil durci, binaires
présents conformes au manifeste si armés, et empreintes du manifeste
re-calculées à la volée. Si quelqu'un déclare ces outils avant l'épreuve, la
suite tombe — c'est son rôle.
