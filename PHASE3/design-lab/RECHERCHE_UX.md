# AGNT — Recherche UX/UI

## Objet

Ce document accompagne l'exploration visuelle isolée du design lab. Il ne décrit pas une implémentation produit et ne modifie pas le contrat de l'interface réelle.

## 20 directions

1. **Trusted Evidence** — système forensic : faits, décisions, exécutions, preuves, limites.
2. **Case File** — dossier de mission éditorial et navigable.
3. **Investigation Workbench** — IDE d'investigation avec liste, canvas et inspector.
4. **Scientific Lab** — hypothèse, configuration, expérience, observations, conclusion.
5. **Trace Explorer** — mission comme arbre/timeline d'exécution.
6. **Knowledge Map** — relations réelles entre mission, target, provider, finding et evidence.
7. **Archive Room** — archives professionnelles, index, versions et pièces justificatives.
8. **Console Minimale** — entrée d'intention et complexité progressive.
9. **Operations Ledger** — registre précis des événements et décisions.
10. **Mission Timeline** — mission comprise par son déroulement temporel.
11. **Data Table First** — findings comme surface de travail principale.
12. **Observatory** — requêtes, filtres, distributions et corrélations actionnables.
13. **Code Review Security** — findings attachés aux fichiers et lignes de code.
14. **Control Desk** — policy, capabilities, providers, décisions et refus.
15. **Field Notebook** — carnet de recherche structuré avec références croisées.
16. **Graph Paper** — cartographie technique des relations réelles.
17. **Quiet Professional** — produit B2B premium, calme et sans décoration.
18. **Split Investigation** — signals, investigation et inspector persistants.
19. **Editorial Report** — analyse destinée à être lue et partagée.
20. **Unexpected / Controlled Experiment** — chaîne de garde documentaire autour de la preuve.

## Patterns à conserver

- Contexte global → objet → détail → preuve.
- Provenance navigable à chaque niveau.
- Distinction stricte entre demandé, autorisé, sélectionné, exécuté, échoué, non disponible, non applicable et inconnu.
- Progressive disclosure.
- Tables pour les volumes importants.
- Timeline pour le ledger.
- Graphe seulement pour des relations réelles.
- Command palette comme accélérateur, pas comme remplacement de la navigation.

## Patterns à éviter

- Dark navy + néon comme identité automatique.
- Gradients et glow décoratifs.
- Cartes KPI en mosaïque.
- Fake terminal.
- AI sparkle et avatars d'agent.
- Graphes sans relation explicable.
- Animations permanentes.
- Badges comme substitut à une structure de données.
- Score global magique.
- Confusion entre résultat vide et donnée inconnue.

## Comparaison

| Direction | Lisibilité | Identité | Scalabilité | Investigation | Compatibilité actuelle |
|---|---:|---:|---:|---:|---:|
| Trusted Evidence | 10 | 10 | 9 | 9 | 10 |
| Case File | 9 | 9 | 8 | 8 | 10 |
| Workbench | 8 | 9 | 9 | 10 | 9 |
| Scientific Lab | 9 | 9 | 8 | 8 | 8 |
| Trace Explorer | 8 | 8 | 9 | 9 | 9 |
| Knowledge Map | 7 | 10 | 7 | 10 | 6 |
| Archive Room | 9 | 9 | 8 | 8 | 9 |
| Console Minimale | 8 | 8 | 8 | 8 | 8 |
| Operations Ledger | 8 | 8 | 10 | 8 | 10 |
| Mission Timeline | 9 | 8 | 8 | 8 | 9 |
| Data Table First | 8 | 7 | 10 | 8 | 9 |
| Observatory | 7 | 7 | 9 | 8 | 7 |
| Code Review Security | 9 | 8 | 8 | 9 | 8 |
| Control Desk | 8 | 8 | 9 | 8 | 10 |
| Field Notebook | 8 | 10 | 7 | 9 | 7 |
| Graph Paper | 7 | 10 | 7 | 10 | 6 |
| Quiet Professional | 10 | 8 | 8 | 8 | 9 |
| Split Investigation | 8 | 9 | 9 | 10 | 9 |
| Editorial Report | 10 | 9 | 6 | 7 | 9 |
| Unexpected | 10 | 10 | 9 | 9 | 10 |

## Recommandation

Top 5 : Trusted Evidence, Case File, Investigation Workbench, Trace Explorer, Scientific Lab.

Recommandation de recherche : **Trusted Evidence** comme identité, **Case File** comme architecture, avec des interactions de Workbench et une lecture d'exécution de type Trace Explorer.

Cette combinaison correspond aux objets réellement disponibles : Mission, Target, Capability, Provider, Execution, Finding, Evidence, Correlation, Report, Policy et Ledger. Les agents autonomes, scores magiques, cartes d'attaque et workflows de remédiation automatique restent des hypothèses futures et ne doivent pas être présentés comme existants.
