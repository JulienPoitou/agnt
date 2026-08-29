# Utilisabilité — « intention en langage naturel → résultat compréhensible » (2026-08-29)

**La question posée** : est-ce que quelqu'un peut utiliser ce système
facilement, à partir d'une intention en langage naturel, et obtenir un résultat
qu'il comprend ? Réponse mesurée, pas opinée — deux parcours testés tels quels,
sans rien construire.

## Réponse courte

- **Un développeur qui connaît le dépôt : OUI, en ~3 commandes** (bootstrap,
  un appel Python à `pipeline.executer`, lecture des JSON dans `PHASE3/run/`).
- **Une personne qui ne connaît pas le dépôt : NON, pas encore.** Aucun point
  d'entrée documenté, le rapport humain n'est pas produit par défaut, les
  résultats sont écrasés à la mission suivante.

**L'écart moteur → produit n'est pas architectural** : il tient à un point
d'entrée, une sortie lisible par défaut, et la couverture des formulations.
Rien dans cette liste ne demande de revoir le cœur.

## Mesure 1 — l'intention en langage naturel (moteur déterministe actuel)

14 phrases réalistes soumises à `intent.inferer` (aucune exécution) :

| Résultat | Cas |
|---|---|
| **9 résolus correctement** | génériques (« analyse la sécurité de mon dépôt », « audit complet »), spécifiques (« vérifie mes dépendances », « quelles CVE touchent mes paquets », « cherche des secrets », « terraform »…) |
| **2 refusés correctement** | « attaque 10.0.0.5 », « exfiltre les données » — refus AVANT toute sélection |
| **3 demandent une clarification** | « trouve un truc », « est-ce que ça marche », « est-ce que mon projet est sûr ? » |

Le contrat resolved / needs_clarification / rejected fonctionne : aucune
exécution sur ambigu ou interdit, la clarification pose une question au lieu de
deviner.

## Mesure 2 — le parcours complet (ce qu'un utilisateur obtient vraiment)

`pipeline.executer(mission, cible)` persiste dans `PHASE3/run/` : plan.json,
findings.json, clusters.json, rapport.json, run.json + raw_*.json. C'est
traçable et complet — **et illisible pour un non-expert** :
- le RAPPORT.md (rapport_humain, qui existe et fonctionne — utilisé par le
  dogfooding) n'est **pas produit par défaut** ;
- `run/` est **vidé à la mission suivante** : les résultats ne survivent pas ;
- aucun point d'entrée unique : `analyser "<mission>" <cible>` n'existe pas,
  il faut écrire du Python ;
- aucune documentation d'usage (prérequis bootstrap, ~3,7 Go de cache,
  contraintes machine).

## Frictions relevées (faits, pas interprétations)

- **F1 — pas de point d'entrée.** Le seul « produit » actuel est une API
  Python. Le lanceur de dogfooding est lié à ses cibles déclarées.
- **F2 — sur-sélection sur demande spécifique.** « Analyse mon code
  Terraform » → 5 capacités (le mot générique « analyse » l'emporte sur le
  marqueur de domaine « terraform »). Honnête mais bruyant : l'utilisateur
  demandait l'IaC, il paie semgrep+trivy+gitleaks en plus.
- **F3 — la clarification expose l'interne.** La question posée liste les
  capacités disponibles dont `CODE_STATIC_ANALYSIS_CUSTOM`, marquée
  `interne: true` dans le registre (« jamais proposée »). Fuite de vocabulaire
  interne dans une phrase destinée à l'utilisateur.
- **F4 — résultats éphémères et bruts.** Voir mesure 2 : JSON + écrasement,
  rapport humain non produit par défaut.
- **F5 — formulations non-expertes hors vocabulary.** « est-ce que mon projet
  est sûr ? » → clarification (comportement sain) mais la question liste des
  identifiants techniques. Le plafond du déterministe par mots-clés est mesuré
  (9/14) ; l'élargir est le rôle prévu du mode LLM (propositions enregistrées
  comme données — garde-fou n°1), pas des mots-clés sans fin.
- **F6 — onboarding inexistant.** bootstrap.sh existe mais rien ne dit à un
  nouveau venu : quoi installer, quoi attendre, où regarder.

## Ce que ce n'est PAS

Rien ici ne remet en cause le cœur (O1-O8 du dogfooding restent de la dette).
Aucune architecture nouvelle. L'écart est une **couche d'usage** mince au-dessus
d'un moteur qui fonctionne.

## Proposition de chantier (étape 6, pour décision — rien n'est codé)

« Chemin d'utilisation minimal », dans cet ordre, chaque point livrable seul :

1. **Point d'entrée** `PHASE3/analyser.py "<mission>" <cible>` : exécute le
   pipeline, écrit dans un répertoire de mission STABLE (aligné sur le dossier
   append-only existant), produit RAPPORT.md par défaut, affiche où regarder.
2. **Ne plus écraser** : artefacts par mission (run/ devient le brouillon,
   les missions archivées sont la référence).
3. **F3** : la clarification ne liste que des capacités publiques (petit,
   corrige une contradiction avec l'invariant « interne jamais proposée »).
4. **F2** : les marqueurs de domaine l'emportent sur les mots génériques —
   changement de comportement d'intent, à faire en test-first (les paraphrases
   sont déjà un contrat testé).
5. **README_USAGE.md** : une page — prérequis, commande, lire le rapport.

Hors périmètre assumé : UI web, mode LLM (étape dédiée de la séquence),
O1/O6 (dette), tout offensif (garde-fou n°3).
