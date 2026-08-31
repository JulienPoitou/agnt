# Interface — surcouche réelle sur le moteur

`PHASE3/interface/` n'est plus une maquette : `api.py` sert la page et quatre routes, et le
bouton RUN appelle le vrai point d'entrée (`analyser.lancer`). Le moteur de décision, lui,
n'est pas dupliqué ici — l'API transmet et relit ce que le moteur écrit dans son archive de
mission.

## Lancer

```sh
python3 PHASE3/interface/api.py --host 0.0.0.0 --port 8141
# http://localhost:8141/
```

`--ouvert` ouvre le navigateur. Sans `api.py`, la page reste lisible : elle retombe sur
`donnees_exemple.json` (mêmes clés, valeurs inventées) **en l'affichant** — un bandeau
« MAQUETTE » se retire tout seul dès que l'API répond. Un écran de démo qui se prend pour un
écran de résultat est le défaut qu'on veut éviter, pas celui qu'on veut offrir.

## Routes

| | |
|---|---|
| `GET /` | la page |
| `GET /api/cibles` | les dépôts que le cœur accepte de scanner (mêmes règles que la CLI) |
| `GET /api/capacites` | le catalogue publié, pour remplir le sélecteur |
| `POST /api/runs` | `{cible: CHEMIN absolu (pas le nom), question, modele, confiance, moteur}` → `{run_id, statut}` |
| `GET /api/runs/<id>` | l'état, puis les artefacts de la mission quand elle est terminée |

Une **file à un consommateur** : les montages de `Sandbox` partagent `PHASE3/run`, donc deux
RUN en parallèle se marcheraient dessus. Le parallélisme est un choix à faire, pas un réglage.

## Ce que le RUN est réellement

`analyser.lancer(question, cible, moteur="auto", fournisseur=None, confiance="controlled")` →
`(0 \| 2, résumé)`. Le numéro de mission affiché est le **dossier d'archive**
(`artifacts/missions/<id>/sortie/{plan,findings,clusters,rapport,intent,run}.json + RAPPORT.md`),
qui n'est pas le `run_id` consigné dans `run.json` — les deux sont affichés parce que les
confondre coûte des minutes quand on cherche une trace.

Sur une machine où `opa` et les binaires d'outils manquent, un RUN aboutit à
`statut: "refuse"` avec le motif (`PolicyError : binaire OPA introuvable`). C'est le
comportement attendu et c'est ce que l'écran doit montrer : un refus **nommé**, pas un spinner
éternel ni un rapport vide.

## Règle de rendu, non négociable

`textContent` partout, **jamais** `innerHTML`. Le dépôt scanné peut glisser un lien ou un titre
de section dans un `message` d'outil : la campagne adverse l'a mesuré trois fois (C1, C2, C6).
L'échappement ne vit pas dans l'interface mais dans `rapport_humain.sur()`, importée par
`rapport.py` — les deux rendeurs du projet partagent la même politique, sinon elle diverge.
La couverture, elle, est lue dans la commande passée (`adapters._drapeau`) et non plus écrite à
côté : un écran qui affiche « 2 scanners » quand 3 jeux de règles sont chargés est un mensonge
de mise en page.

## Ce que l'interface ne fournit pas

Pas d'authentification, pas de multi-tenant, pas d'annulation d'un RUN lancé, pas d'édition de
politique. Le modèle de menace retenu est l'usage local par l'opérateur ; ce qui reste non
négociable, c'est que **l'entrée** (le dépôt) est hostile et que **la sortie** (le rapport) est
vue par un humain qui la copiera ailleurs.
