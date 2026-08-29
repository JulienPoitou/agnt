# CONTEXTE PROJET — à lire avant de toucher à quoi que ce soit

Ce fichier transmet l'essentiel du projet à une IA qui le reprend. Il complète
`MASTER_PROMPT.md` (vision d'origine) et `PROJET_ETAT.md` (journal détaillé,
fait foi en cas de doute). État au 2026-08-29, étapes 0 à 6 closes.

## 1. Ce que c'est

Agent de sécurité **polyvalent et passif** : l'utilisateur formule une mission en
langage naturel + une cible (dépôt local) → compréhension (intent) → capacités →
sélection dans un pool d'outils open source → exécution **sandboxée** (bwrap) →
corrélation inter-outils → rapport fiable et reproductible.

Modèle gelé : **Source → Tool → Provider → Execution**.
Le runtime ne lit QUE `capabilities.yaml`. `pool.yaml` est une antichambre
(candidats) et ne devient **jamais** une seconde source de vérité du runtime.

Ce n'est PAS un outil offensif : aucun scan d'attaque, whitelist active et
approbation ACTIF ne s'automatisent **jamais**.

## 2. Contraintes utilisateur — NON NÉGOCIABLES

- **Un seul chantier concret à la fois.** Pas de nouvelle matrice, pas de
  grande revue d'architecture. On construit, on mesure.
- **Pas de feature sans occurrence observée** (dogfooding d'abord). Ne pas
  transformer chaque anomalie en nouvelle feature : c'est de la dette, on la note.
- **Aucun nouveau provider/outil sans besoin mesuré + harnais.**
- **Le LLM ne choisit QUE dans le catalogue déclaré** (capacités du registre).
  Jamais de commande libre, jamais de nom d'outil transmis au LLM. Sa sortie est
  validée contre le registre ; tout échec retombe sur le déterministe et le repli
  est tracé (`moteur = "deterministe(repli:<cause>)"`).
- **L'agent n'élargit jamais son propre périmètre** ; le scope est versionné, immuable.
- **Aucune intégration de provider ne modifie le cœur** (extraction à 3 niveaux).
- Le proxy d'egress est un mécanisme pur, jamais une pseudo-policy.
- Mission/Dossier = objet de première classe, **append-only** ; propositions LLM
  enregistrées comme données.
- Ne pas inventer de gravité : UNKNOWN ≠ LOW ≠ MEDIUM.
- `pool.yaml` jamais source de vérité runtime. Whitelist binaires + approbation
  actif jamais automatisées.
- **Langue de travail : français.** L'utilisateur invite à la contradiction
  (« dis-moi si tu réfutes ») — contredire avec des faits est attendu.
- Test modifié = justification écrite obligatoire. Aucun enjolivement.
- Avant de CRÉER un fichier : vérifier s'il existe déjà. (Incident réel : étape 6,
  `analyser.py` écrasé puis restauré par fusion.)

## 3. Architecture — où vivent les choses

```
PHASE3/slice/            le cœur (NE PAS réarchitecturer)
  intent.py              moteur d'intention déterministe (mots-clés, mot entier)
  intent_llm.py          contrat de sortie LLM + validation registre + repli
  fournisseurs_llm.py    MockLLM / Groq / OpenAICompatible (stdlib uniquement)
  registre.py            lit capabilities.yaml (source de vérité runtime)
  plan.py                plan canonique, applicabilité, requete_canonique
  pipeline.py            executer() : intent → plan → sandbox → extraction → corrélation
  sandbox.py             bwrap, CACHE_BIN/CACHE_DB/CACHE_REGLES, --chdir ancré
  extraction*.py         extraction à 3 niveaux par outil
  clustering / correlation   regroupement inter-outils
  rapport.py, rapport_humain.py, assainissement.py
PHASE3/analyser.py       POINT D'ENTRÉE : `python3 PHASE3/analyser.py <cible> ["requête"] [--moteur auto|deterministe|llm]`
                         (cible D'ABORD, requête optionnelle = audit complet)
                         produit bundle artifacts/<digest>/<plan>/<run>/ (SARIF, manifeste)
                         + archive mission artifacts/missions/<id>/sortie/ (RAPPORT.md)
PHASE3/capabilities.yaml capacités + providers + fan_out + globs d'applicabilité
PHASE3/pool.yaml         antichambre — régénérer EN DERNIER (empreinte du registre)
PHASE3/test_*.py         22 batteries autonomes (PAS pytest — scripts avec main())
PHASE3/bootstrap.sh      installe les outils épinglés (~3,7 Go hors workspace)
PHASE3/reconstruire_fixtures.sh  reconstruit les cibles de test
PHASE3/dogfooding/       cibles réelles (axios, requests, tf-aws-s3...), OBSERVATIONS, UTILISABILITE.md
Racine : MASTER_PROMPT.md (vision) · PROJET_ETAT.md (journal, fait foi) · README.md · README_USAGE.md
```

Outils intégrés (passifs, épinglés par sha) : semgrep, trivy, gitleaks, bandit,
checkov, grype, kics (+ gosec qualifié mais inutilisable sans toolchain Go).
**Cœur Python = stdlib uniquement, zéro dépendance tierce** (vérifié par grep des
imports). Pas de pyproject/Poetry : ce n'est pas un package, c'est un système exécutable.

## 4. État actuel

> Instantané, tenu à jour à la fin de chaque chantier — pas un journal. L'historique
> détaillé et daté est dans `PROJET_ETAT.md` ; ce qui est Acté §7, les dettes §6.

- Étapes 0-5 closes (cœur, sandbox, extraction, corrélation, fan-out, dogfooding).
- Étape 6 close + quatre chantiers depuis : **6bis** confiance de cible armée sur le
  chemin utilisateur · **6ter** identité canonique de fichier (`same_file` débloqué,
  148 findings réels → 5 clusters inter-outils, `clusterer.py` jamais touché) ·
  **6quater** couverture Go du mapping (le générateur apprenait 0 Go par construction) ·
  **Clarification LLM** (« testé » ≠ « validé en production »).
- Registre : **9 providers** (semgrep, bandit, bandit_custom, semgrep_go, trivy, grype,
  gitleaks, checkov, kics) ; `pool.yaml` à jour (empreinte `0a95593b8ceaa09b` vérifiée
  le 2026-08-30).
- **23 batteries** autonomes. Sur la machine de dev d'origine : 21/22 passaient. Dans
  un sandbox sans outils épinglés : 7/23, et les 16 rouges ont toutes une cause
  environnementale vérifiée (`opa` ×10, cache de règles, mission préalable, clé Groq) —
  aucune n'est une régression. Les lancer APRÈS `bootstrap.sh`, sinon le rouge ne veut
  rien dire.
- Git : 3 commits de chantier (`f400fe6`, `59d987f`, `6298dae`) sur la branche de session,
  poussés sur **github.com/JulienPoitou/agnt**.
- Machine : **2 Go de RAM** — lire les gros fichiers par blocs, pas de modèle LLM local.

## 5. Comment travailler ici

```bash
bash PHASE3/bootstrap.sh                # une fois : outils épinglés + recrée PHASE3/mt-*
bash PHASE3/reconstruire_fixtures.sh    # une fois : cibles de test
python3 PHASE3/test_intentions.py       # exemple de batterie (toutes autonomes)
python3 PHASE3/analyser.py PHASE3/testrepo "Analyse mon code Terraform"
```

Après TOUTE modification du cœur : lancer la régression complète
(les 22 `test_*.py`) — pas seulement le test qu'on vient d'écrire.
Pièges connus : `cmd | tail` masque le code de sortie ; `e.findings` = dicts ;
`rapport.json["findings"]` = compteur entier (détails dans `raw_*.json`) ;
les snapshots ne conservent pas les répertoires vides (`PHASE3/mt-*` recréés
par bootstrap.sh) ; gitleaks peut être hors PATH (`find / -name gitleaks`).

## 6. Dettes et observés (NOTER, pas corriger à chaud)

- O1-O8 (dogfooding) : not_scanned vs vide, codes kics, globs GitHub Actions,
  divergence trivy/grype requirements-dev, secrets fixtures masqués, semgrep
  legacy sur toutes cibles (~15-30 s), etc. → `dogfooding/OBSERVATIONS_dogfooding.md`.
- F5 : formulations non-expertes (plafond du matching mots-clés) — rôle du LLM réel.
- Accents : `intent.py` ne normalise pas, `plan.requete_canonique` oui →
  « vérifie les dependances » (sans accent) → needs_clarification. Vérifié. À traiter avec F5.
- `Sandbox.M_SCAN` est un chemin d'hôte en dur (`/home/user/PHASE3/mt-scan`) : la
  canonicisation en connaît une forme, mais la portabilité demande un montage dynamique.
- `cadre` checkov : dette de modèle, ne pas refaire maintenant.
- `pool.yaml` : régénérer en dernier si le registre bouge. Vérifié le 2026-08-30 :
  l'empreinte déclarée (`0a95593b8ceaa09b`) est bien celle de `slice/capabilities.yaml`
  — la ligne « STALE » qui figurait ici datait de l'ajout de la capacité Go, corrigée.
- **CRASH TEST SÉCURITÉ, relevé n°1 (ouvert, non corrigé à dessein).** Une sortie LLM qui
  nomme une capacité `interne: true` passe `intent_llm.valider()` : la garde compare au
  catalogue COMPLET (`registre.capabilities()`), alors que `descr()` et `publiques()`
  n'exposent que les 5 capacités publiques. Le plan se construit avec le provider interne
  (`bandit_custom`, donc `bandit` sur la cible) et `policy.rego` ne le refuse pas :
  `capability_ids` et `providers` transmis à OPA sont le catalogue complet, l'ensemble
  `couples` contient le couple interne. Impact mesuré : élargissement du périmètre
  (un outil que le contrat ne propose pas s'exécute), PAS exécution d'une commande
  forgée — l'argv vient du manifeste et `commande_suspecte` tient. Grave surtout parce
  que le pool annonce des outils ACTIFS à l'étape 7.
- `cible_autorisee` (pipeline.py:82) vaut `True` par défaut et n'est posé à `False`
  par aucun appelant : la CLI n'a pas de notion d'autorisation de cible. La garde
  `input.cible.autorisee == true` de `policy.rego` n'est donc armée qu'en test. À
  traiter avec l'approbation ACTIF de l'étape 7 (même nature de décision), pas à chaud.
- Sigma / providers Groupe B : backlog, pas maintenant.

## 7. Direction actée (pas à rediscuter)

- **Étape 7** : mode ACTIF, sur son propre labo uniquement (VMs boot-to-root
  récentes, GOAD, DetectionLab), egress contrôlé, outils actifs qualifiés par le harnais.
- **Étape 8** : benchmarks — scoring (atteinte, chemin, temps, plante/plante pas)
  d'abord labo local, puis plateformes dédiées (OffSec Proving Grounds, Vulnlab,
  HTB selon leurs règles) et benchmarks publiés (Cybench, CVE-Bench).
  **Scénarios réalistes exigés — pas de CVE de 2000.** Référence : XBOW (HackerOne 2025).

## 8. Réflexes à adopter

- Ne pas deviner : lire le fichier/la fonction avant d'affirmer.
- Mesure avant déclaration : une convention déduite d'un seul échantillon est
  une mesure fausse (incident kics : échelle de codes de sortie complète).
- Si un test casse après une modif : c'est la modif qui est suspecte en premier ;
  si c'est le test qui était faux, justification écrite.
- Contradire l'utilisateur sans fait = faute ; contredire AVEC fait = service rendu.
