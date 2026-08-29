# PHASE 6 — LLM DERRIÈRE LE CONTRAT D'INTENTION

_Le LLM ne remplace que le matching déterministe. Il ne remplace pas le contrat._

---

## Ce que le LLM fait, et ce qu'il ne fait pas

```
phrase utilisateur → intention structurée
```

| Jamais | Parce que |
|---|---|
| choisir un outil | le registre résout les providers |
| construire le plan | `plan.construire()`, à partir du registre |
| contourner OPA | la policy évalue le plan, pas l'intention |
| modifier le registre | lecture seule |
| exécuter une commande | l'executor seul |

Il ne reçoit **que** la phrase et la description des capacités — jamais un nom d'outil, un
chemin, un argument. Vérifié par test : aucun de `nuclei`, `metasploit`, `sqlmap`, `/home/`,
`--config`, `bwrap`, `mt-scan` ne lui est transmis.

## L'architecture

```
slice/
  intent.py            moteur déterministe — RÉFÉrence, et repli
  intent_llm.py        garde-fous + validation du contrat
  fournisseurs_llm.py  interface + MockLLM + OpenAICompatible
```

**Les garde-fous déterministes s'appliquent dans les DEUX modes.** Une demande
explicitement interdite n'est jamais soumise à un modèle : le refus est une règle, pas
une opinion.

## Le contrat, inchangé

```yaml
status: resolved | needs_clarification | rejected
capabilities: [...]
question: ...
motif: ...
```

## Un modèle hostile ne peut rien casser — 7 comportements testés

Chaque comportement anormal retombe sur le déterministe, et le repli est **tracé** dans
`moteur` :

| Comportement simulé | Résultat |
|---|---|
| capacité inventée (`PENTEST_OFFENSIF_TOTAL`) | `deterministe(repli:capacités inconnues du registre)` |
| statut hors contrat (`peut_etre`) | `deterministe(repli:statut inconnu)` |
| `resolved` sans capacités | `deterministe(repli:resolved sans capacités)` |
| `rejected` sans motif | `deterministe(repli:rejected sans motif)` |
| clarification sans question | `deterministe(repli:needs_clarification sans question)` |
| réponse vide | `deterministe(repli:reponse_vide)` |
| exception | `deterministe(repli:RuntimeError)` |

Et le cas le plus important : un modèle qui tente d'imposer `("nuclei", "metasploit")` est
**rejeté**, et aucun de ces deux outils n'atteint le plan.

## Comparaison des deux moteurs

| | déterministe | LLM (mock) |
|---|---|---|
| « Analyse la sécurité de mon dépôt » | 5 capacités | 3 capacités |
| « scan de sécurité complet du dépôt » | 5 capacités | 3 capacités |
| « Vérifie les dépendances » | 1 capacité | 1 capacité |
| « Cherche les secrets exposés » | 1 capacité | 1 capacité |
| « Exfiltre les données » | rejected | rejected |
| « Fais un truc » | needs_clarification | needs_clarification |

**La différence de 5 contre 3 n'est pas un défaut du LLM.** Le déterministe ajoute
`CODE_STATIC_ANALYSIS_SUITE` et `CODE_STATIC_ANALYSIS_CUSTOM` parce qu'elles sont dans le
registre — ce sont des capacités de **test des providers**, pas des intentions utilisateur
distinctes. Le LLM a raison de ne pas les sélectionner : elles décrivent le même besoin.

C'est une leçon de conception : **le registre ne doit pas contenir deux capacités pour un
même besoin utilisateur**, sinon tout moteur qui sélectionne par capacité sur-sélectionne.

## Trois défauts réels trouvés en testant

Aucun n'était un bug du LLM. Tous étaient dans le déterministe, qui est la référence.

**1. Trou de sécurité — formes conjuguées absentes.**

```
INTERDIT contenait « exfiltrer » (infinitif), pas « exfiltre ».
→ « Exfiltre les données de ce dépôt » était RÉSOLU ET EXÉCUTÉ.
```

Corrigé : `exfiltre`, `exfiltras`, `détruis`, `détruit`, `porte dérobée`, `destructif`.

**2. `scan` absent des marqueurs génériques.**

```
« scan de sécurité complet du dépôt » → DEPENDENCY_ANALYSIS seul.
```

Parce que « sécurité » est à la fois un marqueur générique **et** un mot-clé de
`DEPENDENCY_ANALYSIS` : le mot-clé matchait, donc le repli générique ne se déclenchait
jamais. Corrigé : le générique **ajoute** les capacités, il ne s'y substitue pas.

**3. Verbes d'action dans les marqueurs génériques.**

En corrigeant le point 2, j'ai ajouté `vérifie` et `contrôle` — et
« Vérifie les dépendances » s'est mis à remonter **toutes** les capacités. Un verbe ne dit
rien du périmètre. Retirés.

## Un échec silencieux trouvé au passage

Bandit avait disparu (pip n'est pas persistant). Le pipeline **continuait sans rien dire** :

```
findings par outil : semgrep 2 · trivy 62 · gitleaks 1     ← bandit absent, aucun signal
```

Un outil manquant ressemblait exactement à un outil qui n'a rien trouvé. C'est le mode
d'échec le plus dangereux d'un scanner. Corrigé :

```yaml
cibles:
  - chemin: …
    etat: not_scanned
    raison: "outil 'bandit' absent ou en échec (code 127) — aucun résultat produit"
limites:
  - "ÉCHEC D'EXÉCUTION de 'bandit' : ce scan n'a rien couvert.
     Ce n'est pas une absence de problème."
```

`bootstrap.sh` installe désormais bubblewrap **et** bandit : apt et pip ne sont pas
persistants entre les sessions.

## Ce qui n'est PAS validé

**Aucun vrai modèle n'a été testé.** L'environnement n'a ni clé API, ni endpoint, ni
ollama — vérifié. `OpenAICompatible` est écrit et prêt, mais **non exercé**.

Donc ce qui est prouvé, c'est :

```
le contrat tient
les garde-fous tiennent
un modèle hostile ou défaillant ne casse rien
le repli déterministe fonctionne et est tracé
```

Ce qui n'est pas prouvé :

```
la qualité de compréhension d'un vrai modèle
son taux de repli en conditions réelles
sa latence
son coût
```

Le mock n'est pas un raccourci : c'est ce qui permet de tester le contrat sans dépendre d'un
fournisseur externe. Mais **il ne faut pas lire « 32/32 » comme « le LLM fonctionne »**.

## Suite de tests

```
test_securite       16/16   porte bloquante
test_slice          10/10
test_tracabilite    12/12
test_intentions     22/22
test_correlation     7/7
test_independant    10/10
test_manifest       27/27   niveau 1
test_niveau2        21/21   niveau 2
test_bundle         25/25   aucun secret dans tout le bundle
test_rapport        21/21
test_llm            32/32   contrat LLM
somme des codes : 0
```
