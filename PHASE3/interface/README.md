# Interface — maquette d'affichage (non branchée)

Ce dossier contient **la maquette visuelle** du futur écran AGNT, pas une interface utilisable.
Le moteur n'est pas appelé : `app.js` lit `donnees_exemple.json`.

## Voir

```sh
python3 -m http.server 8141 --bind 0.0.0.0 --directory PHASE3/interface
# http://localhost:8141/
```

(Pas d'ouverture en `file://` : `fetch()` y est bloqué par le navigateur.)

## Ce qui est réel et ce qui est inventé

| | |
|---|---|
| **noms de champs** | réels — `analyser.lancer()` (resume), `analyser._archiver_mission()` (`run.json`), `pipeline._rapport()`, `findings.Finding.to_dict()`, `clusterer.regrouper()`, `run.Contexte.to_dict()` |
| **valeurs** | inventées. Elles ressemblent à un résultat plausible ; elles ne viennent d'aucune exécution |
| **ordre des blocs** | délibéré : *ce qui a tourné* avant *les constats*, pour qu'un « 0 constat » se lise avec ses limites |

Le jour du branchement, chaque champ doit être recalé sur un `run.json` **sorti d'une vraie
exécution** (machine outillée : `bwrap`, `opa`, binaires d'outils). Une maquette qui affiche un
champ que le moteur ne produit pas est un écran vide déguisé en fonctionnalité.

## Une règle de code, non négociable ici

`textContent` partout, **jamais** `innerHTML`. Le contenu affiché vient d'outils qui ont lu un
dépôt non fiable ; ce dépôt peut glisser un lien ou un titre de section dans un `message`
(FAIL C1/C2/C6 du relevé de crash test, `PROJET_ETAT.md`). En attendant F4, le rapport est donc
un bloc de texte brut, avec un bouton *copier* plutôt qu'un rendu markdown.

## Branchement prévu (une fois la maquette validée)

```text
POST /api/runs {cible, question, modele}
  → une file à un job (les montages partagent PHASE3/run : parallelisme = plus tard)
  → analyser.lancer(mission, cible, moteur="auto", confiance=…)
  → lit l'archive de mission déjà écrite : artifacts/missions/<id>/sortie/{plan,findings,clusters,rapport,intent,run}.json + RAPPORT.md
  → GET /api/runs/<id> renvoie exactement l'objet de donnees_exemple.json
```

Deux corrections du relevé conditionnent l'exposition à quelqu'un d'autre : **F4** (assainir au
rendu) et **F8** (déclarer les `--config` réellement passés, pas une liste écrite en dur).
