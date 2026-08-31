# Interface — surcouche réelle sur le moteur

`PHASE3/interface/` n'est pas une maquette : `api.py` sert la page et six routes, le
bouton RUN appelle le vrai point d'entrée (`analyser.lancer`), et l'historique relit
l'archive des missions par le lecteur canonique (`slice/mission_history.py`). Le moteur
de décision n'est pas dupliqué ici — l'API transmet et relit ce que le moteur écrit dans
son archive de mission.

## Le parcours, d'un seul tenant

1. **choisir une cible** — le sélecteur ne liste que les dépôts que le cœur accepte ;
2. **écrire la mission** — la question, telle qu'elle partira au moteur ;
3. **lancer** — RUN met la mission en file (un consommateur : la position s'affiche) ;
4. **suivre** — la ligne d'état pulse et compte les secondes ; le journal vivant montre
   les six étapes de chaque outil au fil de l'exécution ;
5. **lire le résultat** — ou un refus honnête avec son motif ;
6. **revoir l'historique** — les dernières missions, cliquables, relues dans l'archive.

L'historique est en bas de page : chaque ligne porte le statut réel (dérivé du journal,
jamais saisi), la date, la question, la cible, et un compte de constats **seulement si un
`findings.json` a réellement été lu** — sinon la ligne dit « constats non produits », pas
« 0 ». Cliquer une mission relit sa projection (`agnt.history.v1`) : bandeau, ce qui a
tourné (contrat `execution-status.v1`), constats, regroupement, rapport, et le journal
qui dit pourquoi celles qui se sont arrêtées se sont arrêtées. La liste se rafraîchit
seule après chaque run — un refus entre dans l'archive comme un résultat.

## Lancer

```sh
python3 PHASE3/interface/api.py --host 0.0.0.0 --port 8141
# http://localhost:8141/
```

`--ouvert` affiche les cibles admises et quitte. Sans `api.py`, la page reste lisible :
elle retombe sur `donnees_exemple.json` (mêmes clés, valeurs inventées) **en l'affichant**
— un bandeau « MAQUETTE » se retire tout seul dès que l'API répond, et l'historique dit
« indisponible » plutôt que de simuler une liste vide. Un écran de démo qui se prend pour
un écran de résultat est le défaut qu'on veut éviter, pas celui qu'on veut offrir.

## Routes

| | |
|---|---|
| `GET /` | la page |
| `GET /api/cibles` | les dépôts que le cœur accepte de scanner (mêmes règles que la CLI) |
| `GET /api/capacites` | le catalogue publié, pour remplir le sélecteur |
| `POST /api/runs` | `{cible: CHEMIN absolu (pas le nom), question, modele, confiance, moteur}` → `{run_id, statut}` |
| `GET /api/runs/<id>` | l'état, puis les artefacts de la mission quand elle est terminée |
| `GET /api/missions` | l'historique paginé (délégation à `mission_history.lister`) |
| `GET /api/missions/<id>` | le détail projeté d'une mission (délégation à `mission_history.projeter`) |

Une **file à un consommateur** : les montages de `Sandbox` partagent `PHASE3/run`, donc deux
RUN en parallèle se marcheraient dessus. Le parallélisme est un choix à faire, pas un réglage.

## Ce que le RUN est réellement

`analyser.lancer(question, cible, moteur="auto", fournisseur=None, confiance="controlled")` →
`(0 \| 2, résumé)`. Le numéro de mission affiché est le **dossier d'archive**
(`artifacts/missions/<id>/sortie/{plan,findings,clusters,rapport,intent,run}.json + RAPPORT.md`),
qui n'est pas le `run_id` consigné dans `run.json` — les deux sont affichés parce que les
confondre coûte des minutes quand on cherche une trace.

Sur une machine où `opa` et les binaires d'outils manquent, un RUN aboutit à
`statut: "refuse"` avec le motif (`aucun outil exécutable dans ces conditions : aucun
outil disponible sur cette machine`). C'est le comportement attendu et c'est ce que
l'écran montre : un refus **nommé**, pas un spinner éternel ni un rapport vide. Et parce
que le refus peut venir d'un RETOUR du moteur (code 2) comme d'une exception, les motifs
de la section politique partent de `resume.motif` — la parole du moteur — avant tout
détail technique : afficher « undefined : » à la place d'un motif absent était un défaut
réel, mesuré en E2E.

## Règle de rendu, non négociable

`textContent` partout, **jamais** `innerHTML`. Le dépôt scanné peut glisser un lien ou un
titre de section dans un `message` d'outil : la campagne adverse l'a mesuré trois fois
(C1, C2, C6). L'échappement ne vit pas dans l'interface mais dans `rapport_humain.sur()`,
importée par `rapport.py` — les deux rendeurs du projet partagent la même politique,
sinon elle diverge. La couverture, elle, est lue dans la commande passée
(`adapters._drapeau`) et non plus écrite à côté : un écran qui affiche « 2 scanners »
quand 3 jeux de règles sont chargés est un mensonge de mise en page.

L'historique ajoute une conséquence à cette règle : la projection `agnt.history.v1`
échappe `<` et `>` en `&lt;`/`&gt;` parce qu'elle ne sait pas qui la lira. Cette page ne
rendant jamais de markup, elle **défait** cet échappement à l'affichage pour restituer le
texte vrai (un extrait « if (a < b) » se relit tel quel) — sûr uniquement parce qu'aucun
chemin de cette page ne traverse du HTML.

## Aucun faux zéro

Trois états se ressemblent sur un écran naïf et seul le libellé les distingue :

- **0 prouvé** — un outil a tourné sur des cibles analysées et n'a rien trouvé :
  « 0 observation sur des cibles analysées » ;
- **non produit** — la mission s'est arrêtée (refus, erreur, aucun outil) : le bandeau
  écrit « non produits » en toutes lettres, jamais « 0 » en grand chiffre — le résumé du
  moteur porte pourtant `findings: 0` dans ce cas, mesuré en E2E réel ;
- **non lu** — l'artefact est absent ou illisible : « ? », et le détail d'historique
  nomme les artefacts manquants.

## Ce que l'interface ne fournit pas

Pas d'authentification, pas de multi-tenant, pas d'annulation d'un RUN lancé, pas
d'édition de politique. Le modèle de menace retenu est l'usage local par l'opérateur ;
ce qui reste non négociable, c'est que **l'entrée** (le dépôt) est hostile et que **la
sortie** (le rapport) est vue par un humain qui la copiera ailleurs.

## Vérifier le rendu sans navigateur

```sh
PYTHONPATH=… node PHASE3/interface/_domtest.mjs [projet]   # défaut : mocha
```

Le harnais juge `app.js` sur les bundles réels de dogfooding, y compris l'historique
(liste, détail, retour, mission introuvable) et les cas limites : serveur qui meurt,
API redémarrée, refus, résultats absents, charge adverse. `PHASE3/test_interface.py`
juge le contrat HTTP de l'autre côté.
