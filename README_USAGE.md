# Utiliser le système — une page

## Prérequis (une fois)

```bash
bash PHASE3/bootstrap.sh              # outils épinglés + empreintes (~3,7 Go hors workspace)
bash PHASE3/reconstruire_fixtures.sh  # uniquement pour lancer les batteries de tests
```

Le bootstrap pose **cinq binaires autonomes** (trivy 0.74.0, gitleaks 8.30.1, opa 1.20.0, grype
0.118.0, kics 2.1.20) et **quatre outils pip** (semgrep, bandit, checkov, et detect-secrets
depuis le 2026-08-30). Un outil pip qui manque n'est pas une panne du système : le registre le
marque `non_disponible`, et le refus le nomme — mesuré le 30/08/2026, la ligne rendue est
« exécutable introuvable (detect-secrets) : ni au cache épinglé, ni au PATH — lancer
bootstrap.sh ». Aucun scan n'est lancé pour rattraper l'absence.

## Analyser une cible

```bash
python3 PHASE3/analyser.py /chemin/du/depot ["Analyse la sécurité de mon dépôt"]
python3 PHASE3/analyser.py /chemin/du/depot "Analyse mon code Terraform" --moteur deterministe
```

- **La cible vient en premier**, la demande ensuite — et elle est optionnelle :
  sans elle, la demande par défaut est un audit complet du dépôt.
- La mission est en **langage naturel** : « Vérifie mes dépendances »,
  « Cherche des secrets exposés », « Analyse mon code Terraform »…
- Le moteur d'intention est **déterministe** par défaut. Avec une clé
  `GROQ_API_KEY` dans l'environnement (ou `--moteur llm`), un LLM comprend la
  demande — **dans le catalogue des capacités uniquement** : sa sortie est
  validée contre le registre, tout échec retombe sur le déterministe et le
  repli est tracé dans le champ `moteur`. `--moteur auto` (défaut) choisit le
  LLM si une clé est présente, sinon le déterministe — et le dit à l'écran. Le contrat a
  été exercé contre un vrai modèle (Groq) : c'est une preuve d'intégration, **pas** une
  validation en production — limites de débit, file d'attente et relances restent à
  concevoir (`PROJET_ETAT.md`, « Clarification — LLM réel testé ≠ LLM réel validé »).
- **La confiance de cible se déclare** : `--confiance untrusted` dit « ce dépôt n'est
  pas fiable ». La politique OPA refuse alors tout plan tant que la mémoire n'est pas
  bornée (il faut cgroups v2 ou un runtime OCI) — refus rendu **avant** exécution,
  avec le motif `memoire_non_bornee_cible_non_fiable`. Défaut : `controlled`, et il est
  affiché, jamais silencieux. Une valeur inconnue est une **erreur** (`1`), pas un repli.
- **L'autorisation de la cible se déclare aussi** : `--cible-autorisee=true` autorise
  explicitement la cible de cette mission (la politique exige `input.cible.autorisee ==
  true`). Absent ou `false` = refus `cible_non_autorisee` avant toute exécution — un oubli
  d'opérateur ne vaut jamais une autorisation. La valeur est **exigée** (pas de forme
  « `--cible-autorisee` seul »), et l'état est affiché au lancement.
- Codes de sortie : `0` analyse complète · `2` rien n'a été exécuté (une
  clarification est demandée, la demande est refusée, ou aucun provider ne
  s'applique) · `1` erreur technique.

## Depuis l'interface web

```bash
python3 PHASE3/interface/api.py --host 0.0.0.0 --port 8141    # puis ouvrir http://localhost:8141/
python3 PHASE3/interface/api.py --ouvert                     # la liste des cibles admises, et rien d'autre
```

- L'interface n'ajoute **aucun moteur** : elle appelle `analyser.lancer()`, les mêmes chemins,
  la même politique, les mêmes artefacts qu'en ligne de commande. Un RUN est une file à un seul
  occupant (`202` + `position`), suivi d'un `GET /api/runs/<id>` toutes les ~0,9-1,3 s.
- **Les cibles forment une liste fermée** — par défaut `testrepo`, `cible_independante`,
  `labo_securite` et `dogfooding` sous `PHASE3/`, étendue par `AGNT_CIBLES=/chemin/un:autre/deux`
  (variable lue par `api.cibles_admises()`). Une cible hors liste est refusée avec la liste en
  réponse — jamais corrigée, jamais ouverte d'elle-même. À savoir avant d'en ajouter une : la
  politique ne juge **pas le chemin** de la cible, elle juge capacités, confiance et
  `cible_autorisee` — depuis le 2026-08-30, l'autorisation n'est jamais implicite : la CLI la
  pose avec `--cible-autorisee true|false` (absent = refus `cible_non_autorisee`), et
  l'interface la dérive de sa liste d'admission (le corps de la requête est ignoré). La garde
  d'admission de l'interface borne donc l'accès, avec le garde-chemin et l'isolateur. Idem pour une question au-dessus de `TAILLE_MAX_REQUETE` :
  c'est un `400` chiffré, pas une troncature.
- Sur une machine où `bootstrap.sh` n'a pas été lancé, le RUN se termine en **refus nommé**
  (« PolicyError : binaire OPA introuvable : ~/.cache/arena_secops/bin/opa ») et cette cause est
  consignée dans le journal de mission. Un rapport vide ou une « erreur interne » serait un
  mensonge ; un refus qui dit pourquoi est un résultat.
- Les montages de l'isolateur sont cherchés sous `<dépôt>/PHASE3/mt-*`, c'est-à-dire la racine
  que `bootstrap.sh` crée (`ARENA_SECOPS_MONTEURS` pour les déplacer, `ARENA_SECOPS_CACHE` pour
  les binaires). Les deux se résolvent à partir du dépôt : ils ne dépendent plus du home de
  l'auteur (corrigé le 2026-08-30 — auparavant le premier lancement sur une autre machine
  échouait avec « lancer bootstrap.sh » après un bootstrap réussi).
- Un RUN interrompu par une exception laisse `mission.json` et `journal.jsonl`, **sans** bundle
  `sortie/` : le bundle s'écrit quand une exécution a eu lieu.
- La page s'ouvre en **maquette** tant que l'API ne répond pas, bandeau compris ; branchée, le
  bandeau se masque et tout ce qui s'affiche vient des artefacts. Ordre de lecture : demande,
  décision, **couverture avant le nombre de constats**, argv des outils, findings, clusters,
  rapport.

## Sur Windows / WSL

Le produit tourne dans le Linux de WSL, pas dans Windows. La séquence complète, avec le pré-vol :

```bash
cd ~ && git clone <dépôt> agnt && cd agnt          # le dépôt côté LINUX, pas sous /mnt/c
wsl.exe -l -v                                       # (depuis Windows) VERSION doit valoir 2
python3 -c "import yaml" 2>/dev/null || sudo apt-get install -y python3-yaml   # requis
bash PHASE3/bootstrap.sh                            # outils épinglés + PHASE3/mt-*
bash PHASE3/test_bwrap.sh                            # 0 = l'isolateur marche sur CETTE machine
python3 PHASE3/interface/api.py --host 0.0.0.0 --port 8141
```

- **PyYAML n'est pas décoratif** : `bootstrap.sh` lit `manifeste_dependances.yaml` avec. Depuis
  le 2026-08-30, un manifeste qui ne se parse pas fait **refuser** l'installation
  (« manifeste illisible · sudo apt-get install -y python3-yaml ») au lieu de la laisser
  annoncer « environnement prêt » sans avoir contrôlé un seul empreinte de binaire (mesuré :
  c'était le comportement précédent — `python3` échouait, `2>/dev/null` avalait, le contrôle
  concluait « aucune exigence épinglée »). Les quatre faces sont jugées par
  `bash PHASE3/test_bootstrap.sh` (divergent · conforme · absent · illisible), sans réseau.
- **`test_bwrap.sh` avant le premier scan** : il reprend exactement les flags de
  `Sandbox.commande()` (`--unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts`,
  racine en lecture seule) et rend 0 (passé), 1 (échec) ou **77 (rien n'a pu être mesuré)** —
  77 n'est pas un succès, c'est le code qui empêche un test d'environnement de verdir tout seul.
- **Le piège le plus probable est AppArmor, pas AGNT.** Ubuntu 23.10+ réserve la création de
  namespaces non privilégiés, et l'isolateur a justement besoin de `--unshare-net`. Le symptôme
  n'est pas une erreur du produit mais `bwrap: setting up uid map: Permission denied`, ou
  `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. À vérifier :
  `sysctl kernel.apparmor_restrict_unprivileged_userns` (1 = restreint) et
  `cat /proc/sys/kernel/unprivileged_userns_clone` (doit être 1). Le correctif que le script
  affiche — un profil AppArmor limité à `/usr/bin/bwrap` — est préféré au sysctl global, qui
  rouvrirait les namespaces à tous les processus de la machine. **Ne pas retirer
  `--unshare-net` pour « faire passer » le test** : la coupure réseau est la garde, pas un ornement.
- **Un checkout Windows peut casser les scripts eux-mêmes.** Avec `core.autocrlf` actif, un
  `.sh` arrive en CRLF et meurt ligne 13 (`set: pipefail\r: invalid option name`) après avoir
  commencé à s'exécuter — et son sha256 ne correspond plus à aucune empreinte épinglée.
  `.gitattributes` force LF depuis le 2026-08-30 ; sur un clone déjà là :
  `git add --renormalize . && git status` doit rendre une liste vide — mesuré sur ce dépôt :
  0 fichier modifié, la seule ligne CR suivie (`PHASE1/NOTES.csv`) étant marquée `-text`.
- **WSL1 ne suffit pas** : bubblewrap demande un vrai noyau (user namespaces). `uname -r` doit
  contenir `WSL2`.
- Les cibles sous `/mnt/c/...` sont déconseillées (performances et sémantique de permissions
  sur le filesystem Windows) — *recommandation d'expérience, non mesurée dans ce dépôt* ; ce qui
  y est mesuré, c'est que `bootstrap.sh` pose les points de montage sous `$(dirname $0)` et que
  `sandbox.py` les relit au même endroit depuis le 2026-08-30 (avant, il cherchait
  `/home/user/PHASE3/mt-*`, un répertoire qui n'existe nulle part).
- Depuis le navigateur Windows, `http://localhost:8141/` fonctionne sur WSL2 (forwarding
  automatique). Sinon : `ip addr show eth0` côté WSL, puis `http://<ip>:8141/`, ou
  `--host 127.0.0.1` avec un navigateur côté Linux.

## Ajouter un outil

Il y a deux chemins, et le premier suffit presque toujours. **Depuis le 30/08/2026, ajouter un
outil public ne touche plus le cœur : un fichier dans `PHASE3/plugins/` et une épingle dans
`PHASE3/manifeste_dependances.yaml`.** Mesuré sur deux outils réels (`radon`, `pip-audit`) par
`PHASE3/test_plugins.py` (92 cas) : zéro ligne dans `capabilities.yaml`, zéro `parsers_*.py`,
zéro ajout dans `BINAIRES_AUTORISES`.

### Chemin 1 — un fichier de plugin (le défaut)

```yaml
# PHASE3/plugins/<outil>.yaml
id: mon_outil                     # [a-z0-9_], et il n'existe pas déjà au registre
capacites: [CODE_STATIC_ANALYSIS] # capacités visées ; une capacité INCONNUE doit être déclarée
entrees: [repository]             #   juste en dessous par `capacite:` (une seule à la fois)
binaire: mon-outil                # le programme à lancer : la whiteliste du cœur OU une épingle
outillage: mon-outil              # l'id épinglé dans manifeste_dependances.yaml — LA porte
version_min: "1.2.3"              # optionnel : refus au chargement si l'épingle est plus ancienne
risque: PASSIVE                   # OBLIGATOIRE : PASSIVE | ACTIVE | EXPLOIT. Aucun défaut.
licence: MIT                      # doit correspondre à la licence de l'épingle
priorite: 100                     # un RANG : `choisir_providers` trie croissant, le plus petit gagne
fichiers_requis: ["*.py"]         # applicabilité (globs sur la cible) — pas `base_fichiers`
execution:
  args: ["--json", "{TARGET}"]    # liste de chaînes ; jamais une chaîne shell
  code_succes: [0, 1]            # beaucoup de scanners sortent 1 quand ils trouvent
sortie:
  format: json                    # json | jsonl | sarif | csv | xml | custom
lecture:
  modele: plat                    # plat | imbriqué | lignes_json | csv | xml | custom
  items_from: results
  champs: {regle: check_id, fichier: path, ligne: start.line, message: extra.message}
requirements:
  reseau: false                   # true = l'outil sort : REFUSÉ tant que l'export n'est pas accordé
  timeout_s: 600                  # ne peut qu'abaisser le plafond du profil
  sandbox: true                   # `false` est refusé — ce n'est pas une préférence d'exécution
```

puis l'épingle (version, source, licence, et pour un outil pip une `note` disant ce qui n'est pas
vérifiable par SHA-256) et une ligne d'installation dans `PHASE3/bootstrap.sh`. Trois touches, dont
aucune n'est du code.

**Ce que « aucune touche n'est du code » veut dire, et ne veut pas dire.** C'est vrai tant que la
*forme* de la sortie de l'outil entre dans ce que `lecture:` sait déjà décrire. Deux plugins ont
quand même demandé une touche de cœur, chaque fois d'un bloc **générique** et daté, jamais d'un
parser au cas par cas : la liste de blocs par fichier du JSON de radon, puis la valeur-**dict**
autorisée pour `nested_key: "*"` (npm audit). Un septième outil qui invente une troisième forme de
sortie se heurtera à la même règle — soit la grammaire l'absorbe, soit l'outil attend un adaptateur,
et le dire est plus utile que de compter des fichiers.

**`lecture.champs` n'accepte que des alias que le cœur LIT.** Un nom de champ inventé à droite est
une donnée perdue en silence, pas un champ « pour plus tard ». Mesuré le 31/08/2026 en écrivant la
garde : `correction: fix_versions` figurait dans `plugins/pip_audit.yaml` depuis sa première
version, `complexite: complexity` dans `plugins/radon.yaml`, et le modèle de finding ne consomme que
`regle, nom_regle, fichier, ligne, message, severite, reference, remediation, confiance, cwe, paquet`
plus les quatre coordonnées — la valeur de correctif n'était donc **jamais** remontée, et le nombre
de complexité de radon n'apparaissait nulle part dans le finding (vérifié sur `to_dict()`).
`correction` est devenu `remediation` (le correctif de `lodash`, `4.18.1`, se lit maintenant dans le
finding), `complexite`/`aliases`/`version` ont été **retirés** : ces valeurs restent dans l'artefact
brut de l'outil, qui est conservé à côté du JSON re-construit. Un cas de
`PHASE3/test_catalogue_outils.py` refuse désormais tout alias hors de cette liste, et la liste est
**extraite du code de `findings.depuis_manifest`**, pas recopiée dans le test — sinon c'est le
garde-fou qui aurait dérivé en premier.

Le fichier se relit à chaque chargement du registre, et il est soumis **aux mêmes validations**
qu'une entrée écrite à la main dans `capabilities.yaml` (`provider_manifest.valider`). Ce qui est
refusé, avec un motif qui nomme le fichier : une clé inconnue (une faute de frappe sur une clé de
sécurité ne devient pas un silence), un provider déjà défini, un `binaire` non épinglé, une licence
qui ne correspond pas à l'épingle, `sandbox: false`, une paire format↔modèle que le cœur ne sait
pas lire (`xml` + `modele: plat`), `custom` sans `parser` nommé, un `risque` absent, une capacité
inconnue sans `capacite:` ou sans `mots_cles`. Les plugins ne sont appliqués **qu'au registre de la
plateforme** : un registre variante (celui d'une batterie de tests) n'en hérite pas, sinon déposer
un fichier ajouterait des capacités à un test qui n'a rien demandé.

Diagnostic, en lecture seule : `python3 PHASE3/inventaire_plateforme.py` écrit dans chaque
proposition le **verdict du chargeur** recalculé (`# verdict du chargeur de plugins :`), et
`GET /api/capacites` répond `plugins: {fichiers, empreinte}` — la console dit quels fichiers
d'extension sont chargés sur *cette* machine, ce qui n'est pas la même question que « ce que la
plateforme sait faire ».

### Cinq modèles de lecture, et ce qu'ils signifient

`plat` (bandit, semgrep : une liste sous une clé), `imbriqué` (trivy, kics, checkov, radon :
conteneurs puis items — `nested_key: "*"` quand le conteneur *est* la liste, et `contexte` sur
`"*"` pour lire la clé du conteneur comme champ), `lignes_json` (un objet par ligne : nuclei,
httpx), `csv` (nikto, ffuf — entête et valeurs bordées à la lecture, `separateur` déclaré, jamais
deviné), `xml` (nmap : grammaire `@attr`, `balise@attr`, `sous/balise`). Chacun correspond à un
format **réellement rendu** par un outil de la file, et la dispatch se fait sur le modèle déclaré,
jamais sur une inspection du contenu — deviner à partir de la charge fait croire à un scan vide le
jour où le format bouge. Un format qui ne rentre dans aucun modèle : `sortie.format: custom` + un
`parser` nommé (chemin 2).

### Chemin 2 — un parser nommé, quand le format est propre à l'outil

`PHASE3/slice/parsers_<outil>.py`, enregistré par `@enregistrer("nom")`, désigné dans le manifest.
Contrat : `parse(texte) -> list[dict]`, valeurs déjà masquées, `[]` sur entrée inattendue — jamais
d'exception, et le parser est **l'autorité** sur les items (le normaliseur ne relit pas la sortie
par-dessus lui : défaut trouvé à l'intégration de `detect-secrets`, qui rendait 0 finding en
silence). Le cœur n'est pas modifié pour autant.

Ce que le cœur garde, que le plugin le veuille ou non : la liste des programmes exécutables (l'épingle
l'étend, le PATH ne l'étend pas), les jetons autorisés dans `argv`, les fragments interdits
(`;`, `|`, `$(`, redirections), le plafond de timeout, l'interdiction d'éléver des privilèges, la
coupure réseau par défaut, et la décision d'autorisation (OPA). Un manifest ne décide de rien : il
décrit.

### Ce que la conservation des sorties est devenue

À côté de `raw_<provider>.json` (ce que le cœur a compris), la mission conserve
`brut_<provider><extension>` : les octets que l'outil a écrits, lui — le fichier de sortie s'il
existe, sinon ce qu'il a rendu sur stdout, y compris pour les formats que le cœur ne parse pas
(`jsonl`, `csv`, `xml`). Les deux doivent rester comparables : c'est la seule façon de distinguer
« l'outil n'a rien trouvé » de « le cœur n'a rien compris à sa sortie ». Les deux passent par le
même examen avant de sortir du dépôt (`analyser.py` : copie si sûr, sinon `*.redacted` +
empreinte + compte d'occurrences) — une fenêtre ouverte sur `brut_*` sans cet examen aurait été une
fuite créée par nous-mêmes, exactement le défaut déjà constaté sur `raw_bandit.json`.

Trois règles apprises en écrivant ce chemin, toutes mesurées :

- `0 finding` ne veut pas dire « propre ». Un outil qui ne lit aucun fichier rend la même sortie
  qu'un dépôt sans problème — d'où `--all-files` pour `detect-secrets` (mesuré : 0 sans, 4 avec),
  la `limite` recopiée dans la couverture, et le refus d'un outil réseau dont le résultat vide
  serait lu comme une conclusion.
- Un outil qui ne classe pas n'est pas classé à sa place. Les findings `radon` portent `rank` dans
  la règle et `severity: UNKNOWN` : écrire « HIGH » parce qu'un rang F ressemble à une alerte
  serait inventer un avis de sécurité.
- Disponibilité jugée **une seule fois, avec une seule règle** (`resoudre_exe`) : le répertoire des
  outils et le PATH. Deux règles différentes faisaient annoncer « outil absent » à un outil
  exécutable.

## Élargir la cage, mener les outils de front (31/08/2026)

**Le réseau.** Chaque outil est lancé dans une cage bubblewrap privée de réseau
(`--unshare-net`), et les variables `HTTP_PROXY`/`HTTPS_PROXY` pointent sur un port mort en
double ceinture. Ce n'est pas un réglage de confort : le dépôt analysé est une entrée non
fiable. Jusqu'au 31/08/2026, un outil dont la fiche demandait le réseau (`requirements.reseau:
true`) était écarté à la sélection et, s'il y survivait, refusé à l'exécution par une cage
invariablement coupée : le champ `reseau_autorise` des profils ne servait à rien. Il agit
désormais aux deux endroits — et vaut `false` dans les deux profils livrés, ce qui se vérifie
(`test_qualite_plateforme.py`, cas 1 à 7).

Pour une mission, l'opérateur peut accorder la sortie :

```bash
python3 PHASE3/analyser.py PHASE3/testrepo "Analyse les dépendances du dépôt" --egress=true
```

· `--egress=true` — la cage est ouverte pour **cette mission seule** ; un `true` explicite est
  exigé, le drapeau nu est refusé (un drapeau de sécurité n'a pas de valeur par défaut muette).
· `--egress=false` — refus explicite, y compris sur un profil qui autorisait la sortie.
· absent — le profil fait foi.

« Non demandé », « accordé », « refusé » restent trois faits distincts partout où ils se
lisent : `rapport.json` et `run.json` (clé `egress`), le journal de mission (`type: egress`,
avec celui qui a posé la demande), l'archive relue par l'interface. L'état de la cage entre
aussi dans l'empreinte de contexte, donc dans le `run_id` : un run mené cage ouverte ne peut
pas se confondre avec un run fermé (cas 8 à 10).

L'interface web expose la même chose par une case, à gauche de « moteur d'intention ». Son
libellé est lu dans `/api/capacites` : il nomme le profil actif et la liste (vide) des profils
ouvrant la sortie. Décochée, elle n'envoie **rien** — cocher élargit, ne pas cocher ne
fabricote pas un refus explicite.

**Les outils de front.** Une vague mène jusqu'à quatre outils en parallèle, réglable et borné :

```bash
AGNT_VAGUE_PARALLELE=1 python3 PHASE3/analyser.py …   # la suite exacte, le chemin historique
AGNT_VAGUE_PARALLELE=8 …                               # plafond dur : 99 ne veut pas dire « tout »
```

Une valeur illisible retombe sur 1. Ce qui est garanti et mesuré (`test_vague_parallele.py`,
46 cas) : les artefacts sont fusionnés **dans l'ordre du plan**, jamais dans l'ordre
d'achèvement ; un outil parallèle passe par le même corps d'exécution et écrit les mêmes
gardes ; la première exception **au sens du plan** interrompt la vague, et un outil non encore
démarré ne démarre pas. Ce qui n'est **pas** mesuré ici : le gain de temps — la valeur 4 est un
choix assumé, pas un réglage évalué (aucun outil réseau installable, `bwrap` absent).

**L'état de la mission pendant qu'elle tourne.** Le ledger des six étapes est consigné à chaque
démarrage d'outil dans `journal.jsonl`. La console relit la dernière de ces lignes
(`/api/runs/<id>` → champ `vivante`) et l'affiche sous le bandeau d'état, avec les mêmes
pastilles que le bilan final. Aucun état intermédiaire n'est inventé pour l'écran : si aucune
mission ne correspond à ce run, le bloc reste vide plutôt que de montrer l'avancement d'une
autre.

## Le catalogue d'outils : ce qui entre, ce qui attend (31/08/2026)

Le registre lit six familles d'outils de sécurité. Trois entrées de plus sont passées par la voie
plugin ce jour (`ruff`, `eslint`, `npm audit`), sans retoucher le cœur ; le reste du catalogue est
ou bien déjà provider, ou bien **bloqué par un fait nommé** — et non par une impression. Le
chargement porte 6 plugins retenus et 0 refusé ; le registre compte 16 providers et 11 capacités
(comptés sur `Registry()` vivant, pas recopiés d'un état antérieur du dossier).

| Famille | Dans AGNT aujourd'hui | État mesuré sur cette machine |
|---|---|---|
| SAST | `semgrep`, `bandit` (+ variante custom, + Go), `radon_cc`, **`ruff_lint`**, **`eslint_js`** | ruff et bandit tournent ; semgrep a son binaire (1.175.0) mais **pas son jeu de règles** (`semgrep.dev` répond 000, les 4 packs épinglés sont irrécupérables ici) |
| SECRETS | `gitleaks`, `detect_secrets`, **`trufflehog3`** | detect-secrets et trufflehog3 tournent ; gitleaks est un asset GitHub injoignable |
| SCA | `trivy`, `grype`, `pip_audit`, **`npm_audit`** | pip-audit tourne et **demande** le réseau (donc refusé tant que la sortie n'est pas autorisée) ; `npm audit` tourne pareil, et c'est sur lui que la garde d'export a été mesurée des deux côtés : cage fermée → refus, `egress_autorise: true` → 2 findings lus puis projetés ; trivy/grype idem gitleaks |
| INFRA / CLOUD | `checkov`, `kics` | **checkov tourne** : 38 non-conformités sur `PHASE3/testrepo_iac`, hors réseau, depuis la correction `--skip-download` |
| RECON / WEB | aucun provider | ni capacité, ni binaire installable ; et un `{URL}` n'existe pas comme jeton (voir plus bas) |

**`ruff` (SAST, Python).** `plugins/ruff.yaml`. Sa commande porte `--isolated` et `--no-cache`, et
ces deux drapeaux ne sont pas une préférence de style : mesuré sur une copie de dépôt contenant un
`.ruff.toml` **invalide écrit par la cible**, `ruff check --select S,E,F` sort en `rc=2` avec zéro
résultat — la cible a supprimé son propre scan ; avec `--isolated`, mêmes findings. `--no-cache`
empêche ruff d'écrire `.ruff_cache/` dans une cible montée en lecture seule. Codes admis : `0`
(rien) et `1` (findings) — pas `2`.

**`trufflehog3` (SECRETS).** `plugins/trufflehog3.yaml`. Nommé ainsi parce que ce n'est **pas**
TruffleHog v3 (Go, GitHub Releases, injoignable) : un projet Python distinct, épinglé sous son nom.
Il sort `2` quand il trouve des secrets — donc `code_succes: [0, 2]`, sinon un scan productif est
registré comme une panne. Deux champs ne sont pas mappés, `secret` et `context` : l'outil y met la
valeur en clair, mesuré. La projection du finding n'en contient aucune ; **l'artefact brut de
l'outil, si** — limitation écrite dans le plugin et dans la batterie, pas gommée.

**`npm audit` (SCA, JavaScript).** `plugins/npm_audit.yaml`, 7ᵉ plugin du dossier, et premier
dont l'exécution **a besoin** de sortir. Déclaration : `npm audit --prefix {TARGET} --json`,
`code_succes: [0, 1]` (1 = des vulnérabilités trouvées, pas une panne), `reseau: true`, capacité
`DEPENDENCY_ANALYSIS_JS` **créée par le plugin** — pas posée sous `DEPENDENCY_ANALYSIS` : cette
capacité est en `max_providers: 2` avec Trivy (rang 100) et Grype (110) devant, donc un plugin
branché là serait chargé, validé, et **jamais planifié** (leçon D10). `nested_key: "*"` accepte
désormais les deux formes que rend npm : une liste, ou **un dict unique** (chaque clé = un paquet,
valeur = sa fiche) — extension de `slice/extraction.py` de même nature que le bloc radon, pas un
parser écrit à la main. `--prefix` rend l'outil indépendant du répertoire courant, ce qu'ESLint ne
sait pas faire : c'est pourquoi `eslint` attend encore la décision D8 et pas celui-ci. Mesuré sur
`PHASE3/testrepo` : `lodash` et `minimist` en `CRITICAL`, `cible.paquet` renseigné,
`remediation: 4.18.1` et `1.2.8`, `reference` sur l'avis GHSA et `cwe` sur `CWE-471`/`CWE-1321` (par
`via[0].url` et `via[0].cwe[0]` — la *première* entrée du tableau, pas « celle qui a une URL »).
`cve` ressort `None` et le finding **le nomme** dans son vecteur `absents` : npm loge la CVE dans
`via[].cves`, vide ici, et ne rend pas le score CVSS. Trois choses restent volontairement non
mappées et sont écrites dans le fichier : le reste du `via[]` mixte, `fixAvailable: false` qui ne
veut pas dire « inconnu », et le fait que l'audit **fait confiance au lockfile** tel qu'il a été
édité à la main.

**`--egress` change ce que ces outils peuvent dire.** Un outil qui appelle un service externe
(checkov le faisait) rend deux résultats différents selon la cage. C'est la raison pour laquelle la
correction vaut pour le registre, pas seulement pour ce plugin ou ce test.

**Ce que la grammaire ne sait pas dire (RECON/WEB).** Elle **admet** un plugin qui déclare
`entrees: [hote, url]` et `requirements.reseau: true` — vérifié : le chargeur dirait
« chargerait », et le refus de `plugins/propositions/nmap.yaml` porte sur le binaire non épinglé,
jamais sur le réseau. Le modèle de finding sait déjà loger une URL, un hôte, une image, une
ressource (et masque `user:***@` dans les URLs d'outils). Ce qui manque est un **septième jeton** :
les seules variables d'un manifest sont `{BIN} {TARGET} {OUT} {OUT_DIR} {REGLES} {DB}`, et
`{TARGET}` est un chemin monté. Un scanner réseau n'a donc nulle part où recevoir sa cible —
décision D9, avec ce qu'elle implique sur la politique d'export.

**Gitleaks (secrets).** Depuis le 2026-08-30 (SEC-G6a/F7) la grille de détection des secrets
est **fournie par AGNT, jamais par le dépôt analysé** : `--config={REGLES}/gitleaks.toml` est
porté par le registre, le fichier (`PHASE3/regles/gitleaks.toml`, jeu par défaut + aucune
allowlist) est copié par `bootstrap.sh`, épinglé par SHA-256 dans `manifeste_dependances.yaml`
et monté en lecture seule. Une grille absente ou divergente est un **refus**, pas un repli vers
la configuration par défaut ni vers un `.gitleaks.toml` que la cible contiendrait.

**ESLint (JavaScript).** `plugins/eslint.yaml`, capacité `CODE_STATIC_ANALYSIS_JS`. Ce plugin a
failli ne pas exister pour une raison fausse — « la cage ne fixe pas le répertoire courant », alors
que `Sandbox.commande()` émet bien un `--chdir` sur le montage de la cible (mesuré dans
`test_catalogue_outils.py`). Ce qui compte est ailleurs : la commande porte `--no-config-lookup`, et
mesuré sur une cible qui s'auto-exclut (`eslint.config.mjs` avec `ignores: ["**"]`), sans ce drapeau
ESLint déclare « all of the files … are ignored » et ne rend rien, avec il rend les mêmes findings.
Le jeu de règles est **dans l'argv** (`--rule '{…}'`), pas dans un fichier que le dépôt analysé
pourrait remplacer, et il ne contient qu'une demi-douzaine de règles fondamentales : aucun plugin,
aucune extension npm de sécurité n'est installé. Un « 0 finding » d'ESLint ici ne veut pas dire
« pas de faille JavaScript ». `code_succes: [0, 1]` — le code 2 (aucun fichier retenu) reste une
panne.

À relancer après installation complète du pool : `python3 PHASE3/test_catalogue_outils.py`
(84 cas ; deux se concluent par « NON ÉVALUÉ » quand la machine ne permet pas, et c'est écrit avec
leur cause).

## Lire le résultat

Les chemins de `findings.json` (et les clés de cluster) sont **relatifs à la cible**,
quelle que soit la forme rendue par l'outil : `/…/mt-scan/docs/x.py`, `./x.py`,
`docs\\x.py`, `/PHASE3/mon_depot/x.py` deviennent tous `docs/x.py` ou `x.py`. C'est ce qui
rend `same_file` possible entre outils — et un chemin qui remonterait hors de la cible
(`../x`) n'est jamais aplati : il reste distinct de `x`.

Deux vues des mêmes preuves :

```
PHASE3/artifacts/missions/<id>/sortie/     ← « qu'a produit CETTE mission ? »
├── RAPPORT.md      ← commencer ici : ce qu'il faut regarder, en clair
├── findings.json   · clusters.json   · rapport.json
├── plan.json       ← qui a été choisi, qui a été écarté, et POURQUOI
├── raw_*.json      ← ce que le cœur a compris de chaque outil
├── brut_*          ← les octets que l'outil a écrits (fichier, sinon stdout)
└── run.json        ← empreintes (versions outils, bases, policy, cible)

PHASE3/artifacts/<digest>/<plan_id>/<run_id>/   ← vue technique, indexée par cible
├── rapport_humain.md  · rapport.md  · rapport.sarif   ← export SIEM/IDE
└── manifeste.json     ← identifiants, digests, couverture, conservation des sorties
```

Le dossier de mission contient aussi le **journal append-only** (décisions,
arrêts, propositions LLM enregistrées comme données).

Quand rien n'a tourné, ce n'est pas une ligne d'erreur mais un état. Le CLI (depuis le
30/08/2026) et l'interface rendent le même bloc : la cause, le compte des outils par état, ce que
les conditions d'exécution ont écarté, le plan refusé, et le chemin du journal.

```
REFUS D'EXÉCUTION · PolicyError : binaire OPA introuvable : ~/.cache/arena_secops/bin/opa
outils : non_disponible 5 · non_applicable 1 · non_autorise 2
conditions refusées : trivy — base déclarée absente : …/trivy/db/metadata.json (lancer bootstrap.sh)
plan dfc88bd69ba80b1c · providers : semgrep, gitleaks, detect_secrets, checkov
  – checkov            non_disponible   exécutable introuvable (checkov) : ni au cache épinglé, ni au PATH
  – detect_secrets     non_autorise     décision : moteur de décision injoignable : …
  – semgrep_go         non_applicable   aucun fichier ne correspond aux globs déclarés ['*.go']
```

Code de sortie **2** : un refus reste un échec, il ne devient pas un succès parce qu'il est bien
expliqué. Et une panne qui n'est pas un refus garde son traceback complet.

## Ce que le système ne fait pas

- Il n'exécute que des outils **passifs** intégrés et qualifiés (8 à ce jour) —
  aucun scan offensif, aucun outil non qualifié, aucune commande libre.
- Il ne sort sur le réseau que si on le lui demande, pour une mission, à la main : aucun
  outil n'hérite d'une sortie par défaut, la demande est consignée avec son auteur, et
  l'état de la cage change l'empreinte du run.
- Il n'élargit jamais son périmètre : ce qui est refusé ou écarté est dit, avec
  un motif, dans `plan.json`.
- Une gravité inconnue reste « indéterminée » — jamais inventée.
