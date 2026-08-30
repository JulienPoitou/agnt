# Dogfooding — bilan de la première campagne (2026-08-28)

**Règle de la campagne : mesurer, ne rien coder.** Aucune ligne de code n'a été
modifiée pendant cette campagne. Chaque anomalie est un fait observé, avec sa
fréquence, son impact et une action PROPOSÉE — les décisions appartiennent à
l'utilisateur.

## Protocole

5 dépôts réels, une seule requête canonique (« Analyse la sécurité de mon dépôt »),
moteur déterministe, pipeline complet (intent → plan → policy → sandbox → findings
→ clustering → rapports).

| Cible | Nature | Taille | Temps | Résultat |
|---|---|---|---|---|
| `cible_independante` (Config-Portal) | Python/Flask (base de référence) | 5 fichiers | 26 s | 11 findings, 2 clusters, **2 inter-outils** |
| `dogfooding/axios` | JS, **avec** package-lock.json | 466 fichiers | 36 s | **CRASH — 0 finding persisté** (anomalie n°1) |
| `dogfooding/express` | JS, **sans** lockfile | 213 fichiers | 25 s | 41 findings (100 % dans `examples/`), 1 cluster |
| `dogfooding/mux` | Go | 27 fichiers | 21 s | 1 finding (checkov/GitHub Actions), semgrep honnêtement `not_scanned` |
| `dogfooding/terraform-aws-s3-bucket` | Terraform réel (module populaire) | 124 fichiers | 54 s | 135 findings (134 checkov + 1 gitleaks/historique) |

Aucun problème de performance à cette échelle (≤ 54 s par dépôt).

## Les anomalies, dans l'ordre d'impact

| # | Problème | Fréquence | Impact | Action proposée |
|---|---|---|---|---|
| 1 | **Le garde-fou anti-fuite tue l'analyse entière sur un faux positif** : le motif « 40 caractères base64 » inclut `/` dans sa classe et matche les URL d'advisories GitHub (`…/security/advisories/GHSA` = exactement 40 caractères). Sur axios : `PipelineError`, **tous** les résultats de **tous** les outils perdus. | 1/5 dépôts, mais structurel : toute CVE npm avec référence GHSA (la quasi-totalité) | **CRITIQUE** — le moteur est inutilisable sur l'écosystème npm | Corriger le motif (contexte URL exclu ou `/` retiré de la classe) + test dédié sur URL d'advisory. Le principe « arrêt bruyant plutôt que fuite » reste juste — c'est le motif qui est faux. |
| 2 | **La corrélation JS/npm reste non mesurable** : express n'a pas de lockfile (Trivy aveugle — déclaré honnêtement en couverture), axios a crashé (n°1) avant la corrélation. | 2/2 dépôts JS | ÉLEVÉ — la question « le mapping npm est-il nécessaire ? » n'a toujours pas de réponse | Re-mesurer APRÈS la correction n°1. Ne pas coder le mapping JS avant : l'hypothèse n'est ni confirmée ni infirmée. |
| 3 | **Findings concentrés dans le code d'exemple** : express, 41/41 dans `examples/` (cookies de session, secrets en dur d'exemple). Techniquement vrais, décisionnellement du bruit. | 1/5 (seul dépôt JS analysé jusqu'au bout) | MOYEN — noie le signal | Étiqueter ou filtrer par chemin (`examples/`, `test/`, `docs/`) — à décider avec plus de données. |
| 4 | **Sur-regroupement** : 41 findings, 8 règles différentes, 2 fichiers → UN cluster (`same_package`). Le rapport humain dit « 1 point secondaire » pour 41 observations. | 1/5 | MOYEN — sous-estimation visible dans le rapport | Examiner le critère `same_package` (attribution de paquet trop grossière en JS). |
| 5 | **Liste de couverture illisible** : « `index.js`, `index.js`, `index.js`, `index.js`, `index.js` » (fichiers distincts, même basename). | observé sur express | FAIBLE — lisibilité | Afficher des chemins relatifs distinguables. |
| 6 | **Go : pas de SAST** — semgrep sans règles Go (`not_scanned`, déclaré). Compensé partiellement : trivy lit `go.mod` (0 vuln ici), checkov couvre les GitHub Actions. | 1/5 | MOYEN — trou de couverture mesuré | Candidat légitime à la décision « provider par trou » — pas d'urgence. |
| 7 | **Densité de bruit checkov sur module réel** : 134 findings (≈ 17 ressources × 8 règles), 129 dans `main.tf`. Le clusterer regroupe (10 clusters) mais le ratio signal/bruit est faible sur un module pourtant bien tenu. | 1/5 | MOYEN | Rien pour l'instant — mesurer sur d'autres dépôts IaC. |
| 8 | **Finding historique non qualifiable à froid** : gitleaks signale `generic-api-key` (main.tf:515, commit passé) ; la valeur est masquée à la source (leçon #1) donc le faux positif ne peut pas être tranché depuis le bundle. | 1/5 | FAIBLE | Documenter la procédure de vérification manuelle (aller au commit). Le moteur ne stockera jamais la valeur — c'est voulu. |

## Ce qui a tenu (à ne pas réparer)

- **Sélection, plan, policy, sandbox, traçabilité** : 4 runs de bout en bout sans
  incident ; `plan.json` porte la sélection motivée ; les états de couverture ont
  dit la vérité partout (semgrep Go `not_scanned`, trivy express « manifeste npm
  présent mais AUCUN lockfile » — la limite était écrite dans le registre, elle a
  servi).
- **Corrélation Python** : 2 clusters inter-outils sur la cible de référence —
  le cœur de l'idée fonctionne sur du réel.
- **Checkov multi-framework en conditions réelles** : il a détecté
  **github_actions** (4e framework, sans aucun changement de déclaration) et
  produit un finding VRAI et utile sur le dépôt Go (`CKV2_GHA_1` — permissions
  `write-all` dans un workflow). L'extension de la Phase 5A est validée par le réel.
- **Le garde-fou secrets a fait son travail** : sur axios il a refusé de persister.
  Le comportement « échouer plutôt que fuir » est le bon — seul le motif est en cause.
- **Gravités honnêtes** : aucune gravité inventée sur les 5 runs ; le rapport
  express dit « gravité moyenne » (WARNING semgrep traduit), pas autre chose.

## Roadmap dictée par les données (proposition — décisions utilisateur)

1. **Corriger l'anomalie n°1** (bug, pas feature : le motif, pas le principe) +
   test sur URL d'advisory. Sans ça, tout l'écosystème npm est inaccessible.
2. **Relancer la campagne JS** (axios + un dépôt avec lockfile vulnérable) pour
   MESURER enfin la corrélation npm → seulement alors décider du mapping JS.
3. Bruit (n°3, n°4, n°5) : attendre 2–3 dépôts de plus avant de trancher.
4. Go SAST (n°6) : seul trou de couverture candidat à un nouveau provider —
   après 1–3, et jamais « pour voir ».

Artefacts : runs dans `PHASE3/artifacts/` (cible `23aad3e5…`, mux `a75f42bc…`,
tfs3 `ed8eeabb…`, express `99d3aeed…`) ; journaux dans `PHASE3/dogfooding/logs/` ;
sortie trivy axios reproduite hors pipeline dans `/tmp/trivy_axios.json` (non
persistant — la rejouer si besoin : 4 vulnérabilités npm dont vite 5.4.21
CVE-2026-53571 HIGH).

---

# Addendum — campagne 2 : correction n°1 + relance JS (2026-08-28)

## La correction (point 1 validé par l'utilisateur — rien d'autre n'a été touché)

**Bug** : le motif heuristique « 40 caractères base64 » du jeu LARGE matchait des
contextes infrastructure, pas des secrets. Trois itérations, toutes pilotées par
les tests (24 cas dans la porte bloquante `test_securite.py`) :

1. Reproduit d'abord : l'URL GHSA d'axios fait échouer la porte (3 échecs).
2. Premier correctif (chiffre exigé + `{40,}`) : répare GHSA mais **révèle deux
   trous/faux positifs cachés** — clé de 41+ caractères qui ne matchait nulle part
   (trou), et sitôt `{40,}` activé : URL Fedora (identifiants de fil 40+) et
   chemins d'artefacts du projet se mettent à matcher (régressions bundle/rapport).
3. Correctif final, de principe : **les motifs stricts restent évalués sur le texte
   intégral ; l'heuristique 40 caractères ne s'applique qu'hors contexte
   infrastructure** (URL, chemins à 3 segments et plus). Perte assumée et
   documentée : un blob base64 nu caché DANS une URL échappe à l'heuristique
   (pas aux motifs stricts — `ghp_` dans une URL est toujours pris, testé).

Vérifié : porte de sécurité 24 cas (dont : GHSA passe, Fedora passe, chemin
d'artefact passe, clé nue 40 ET 42 caractères bloque, `ghp_` dans URL bloque,
garde-fou bout-en-bout dans les deux sens) ; bundle 24/24 ; rapport 20/20 ;
12 autres batteries + bwrap 11/11.

## Relance JS — la mesure attendue

| Dépôt | Exit | Findings | Inter-outils | Trivy npm | Semgrep package |
|---|---|---|---|---|---|
| axios | **0** (crash résolu) | 11 (semgrep 1, trivy 4, gitleaks 5, checkov 1) | 0 | nanoid, vite (2 paquets, 4 CVE) | `None` (mapping `inconnu`) |
| express | 0 | 41 (semgrep) | 0 | — (pas de lockfile, déclaré) | `express` (métadonnée de règle) |
| eslint | 0 | 76 (semgrep 72, gitleaks 1, checkov 3) | 0 | — (pas de lockfile) | `None` ×26, métadonnées ×46 (dont **`flask`**) |

**Verdict sur la cécité npm — mesuré, pas supposé :**

- **Aveuglement mécanique : CONFIRMÉ.** Les findings semgrep JS n'ont aucune clé
  de paquet utilisable (`None`, ou le nom du dépôt/framework venu des métadonnées
  de règle — jusqu'à `flask` attribué à un template Jekyll). Trivy, lui, nomme le
  vrai paquet (`vite`, `nanoid`). Aucune clé commune → la corrélation par paquet
  est structurellement impossible en JS (alors qu'elle produit 2 clusters
  inter-outils sur la cible Python).
- **Occasions manquées observées : AUCUNE (0/3 dépôts).** `vite` est importé par
  100 fichiers d'axios, mais l'unique finding semgrep d'axios n'en touche aucun.
  Sur ces 3 dépôts, la cécité n'a fait perdre AUCUN cluster.
- **Second aveuglement mesuré au passage (plus large que npm)** : les chemins ne
  sont pas normalisés entre outils — semgrep remonte des chemins absolus du
  montage sandbox (`…/mt-scan/…`), checkov des chemins de module (`/main.tf`),
  trivy des chemins relatifs. Le critère `same_file` ne peut donc JAMAIS matcher
  entre outils non plus. La corrélation Python ne tient que par `same_dependency_usage`.

**Décision proposée par les données** : NE PAS coder le mapping npm maintenant.
La cécité est réelle mais sans impact observé ; le chantier le plus rentable
serait la **normalisation des chemins** (elle débloquerait `same_file` pour tous
les langages, pas seulement JS) — mais c'est une décision utilisateur, pas une
évidence de campagne. Prochaine mesure d'impact possible à coût faible : un dépôt
sonde où un outil signale l'usage d'une dépendance que l'autre signale vulnérable.

## Autres observations de la campagne 2

- **gitleaks sur du réel** : axios 5 findings (2× `private-key` dans `test/key.pem`
  — clé de test commitée, classique ; 3× `generic-api-key` dans axios.js — à
  qualifier à la main), eslint 1 (`.travis.yml`, vraisemblablement clé chiffrée
  Travis). Aucune valeur stockée, conformément à la leçon #1.
- **checkov utile sur les dépôts JS aussi** : 4 findings GitHub Actions réels sur
  axios + eslint (`CKV_GHA_7` action non épinglée, `CKV2_GHA_1` permissions) —
  confirmation supplémentaire du multi-framework.
- **eslint** : pas de lockfile non plus — les grands dépôts JS ne commettent pas
  tous leur lockfile ; la limite trivy (déclarée) s'applique souvent en pratique.

---

## Suivi de roadmap (2026-08-29, relu le 2026-08-30)

**Complément 2026-08-30 — l'« autre aveuglement » est fermé.** La relativisation aux
racines connues ne couvrait ni `./x`, ni `a/../b`, ni le dépôt nommé depuis le répertoire
du run (`/PHASE3/testrepo_iac/k8s.yaml`, 20 findings checkov réels). Ces trois formes sont
canonisées depuis le 2026-08-30 dans `findings.normalise_chemin` (le clusterer n'a pas été
touché : il compare des identités, il ne les devine pas). Mesuré sur les captures de la
fixture iac : 148 findings → 5 clusters inter-outils dont `k8s.yaml` (checkov × kics),
et 0 cluster mêlant deux fichiers. Le mapping npm reste NON codé, pour les mêmes raisons
qu'au 2026-08-29 : impact toujours non démontré. Détail : `PROJET_ETAT.md`, étape 6ter.

**Suites du 2026-08-30 — chantiers C (couverture Go du mapping) et D (clarification LLM).**
C n'a pas consisté à régénérer le mapping : mesuré, l'ancien générateur produisait **0 entrée
Go même avec un `golang.yaml` portant des chemins de module** — la couverture était nulle par
construction, pas par oubli. S'ensuivent quatre corrections de `extraire_mapping.py` (liste
d'autorité = manifeste épinglé, `lues`/`mappées` par jeu, refus tracé des paquets Go en nom
court, tables incohérentes = génération refusée) et une batterie `test_mapping_go.py`
(17/17, 1 non évalué) dont les deux cas qui comptent sont les **négatifs** : sur les captures
réelles de `testrepo_go`, `technology: [go]` est un langage et ne nomme aucune dépendance →
0 paquet, 0 cluster, et c'est la réponse correcte. **Le dogfood de C reste à faire sur la
machine source** (`semgrep.dev` injoignable ici) : `python3 PHASE3/extraire_mapping.py` puis
lire « golang.yaml : N lues · M mappées ». `M = 0` ⇒ pas de corrélation Go codable, verdict
identique au mapping npm. D : « testé avec Groq » ne vaut pas « validé en production » —
l'ambiguïté est levée dans `PROJET_ETAT.md` par une clarification datée plutôt qu'en effaçant
les états successifs.

Chantier « normalisation des chemins » FAIT (décision utilisateur) : chemins
relativisés aux racines connues avant calcul des fingerprints ; batterie
`test_chemins.py` 9/9 sur artefacts capturés ; 17 portes vertes ; e2e : 0 chemin
absolu dans les findings et les clés de cluster, corrélations Python préservées
(2/2). Le mapping npm reste NON codé — cécité confirmée, impact toujours non
démontré.
