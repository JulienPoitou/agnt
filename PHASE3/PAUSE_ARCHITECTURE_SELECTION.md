# Pause architecture — la sélection des providers

_Date : 2026-08-28. Toutes les affirmations ci-dessous ont été revérifiées dans le
code du jour (le workspace a été restructuré : aucun souvenir des sessions
précédentes n'a été recopié sans relecture)._

## 1. État vérifié

- **La sélection** : `intent.py:187-199` (`choisir_providers`) — pour chaque
  capacité, filtre les providers PASSIF puis prend `passifs[0]`, c'est-à-dire
  **l'ordre du YAML**. Un seul appel : `pipeline.py:101`.
- **Le plan sait déjà exécuter plusieurs providers** : `plan.py:127` (`construire`)
  accepte une liste. C'est le *choisisseur* qui est mono, pas le moteur.
- **Aucune capacité n'a aujourd'hui deux providers** (vérifié sur le registre le
  jour même) : semgrep, bandit, bandit_custom sont trois capacités distinctes ;
  trivy, gitleaks, checkov sont seuls. Donc `passifs[0]` **ne décide rien
  aujourd'hui** — le problème est anticipé, pas actuel.
- Le cas « bandit vs semgrep » a été résolu en scindant les capacités
  (`CODE_STATIC_ANALYSIS_SUITE` / `_CUSTOM`, marquées internes pour ne pas fausser
  la sélection). C'est un contournement de la règle mono-provider, pas de
  l'orchestration.
- **`plan.json` trace le quoi, jamais le pourquoi** : les steps disent
  `capability → provider`, aucun champ n'explique pourquoi celui-là.
- Données disponibles par provider : `risque`, `cout` (faible/moyen),
  `preconditions` (cibles, langues, `lockfile_requis_pour`, `historique_git`),
  `cibles`, `declares_files`, `limite`. **Les `preconditions` ne sont évaluées
  par aucun code** (vérifié par grep) — c'est de la documentation déclarative.
- **Corrélation inter-outils** (`clusters_inter_outils`) : exige ≥ 2 outils sur le
  même actif. Elle fonctionne donc ENTRE capacités (semgrep + trivy sur une même
  dépendance), jamais AU SEIN d'une capacité (un seul provider y contribue).

## 2. Deux problèmes distincts — ne pas les mélanger

**A. Arbitrer** : choisir UN provider parmi N. Critère dominant : coût/temps.
   Besoin réel : **nul aujourd'hui** (aucun N ≥ 2).

**B. Convergence** : exécuter N providers et croiser leurs résultats. C'est
   l'idée fondatrice du projet (« deux outils indépendants convergent → probable »).
   Le moteur sait déjà le faire entre capacités ; il en est structurellement
   empêché au sein d'une capacité par `passifs[0]`.

La question « Pourquoi Trivy plutôt que Grype ? » est mal posée pour un système
de sécurité : la vraie question sera **« Trivy ET Grype, ou un seul faute de
budget ? »**. La convergence de deux outils indépendants vaut plus qu'une
préférence ; le critère de repli sur un seul est le coût, pas le goût.

## 3. Les options, de la plus petite à la plus grande

1. **Priorité explicite + motif traçable** (petit) : `priorite:` déclaré par
   provider ; `choisir_providers` trie au lieu de subir l'ordre YAML ; `plan.json`
   gagne `selection: {choisi, ecartes, motif}`. ~30 lignes + tests. Aucune
   refonte : le « pourquoi » devient auditable.
2. **Sélecteurs déclaratifs** (moyen) : conditions `quand:` évaluées sur les
   preconditions existantes (langue de la cible, présence d'un lockfile…) ;
   premier provider éligible dans l'ordre de priorité gagne. Exige un évaluateur
   de preconditions qui n'existe pas encore.
3. **Fan-out intra-capacité** (grand) : plusieurs providers par capacité au plan,
   corrélation trivy-vs-grype réelle. Touche plan, pipeline, couverture, rapport,
   tests — c'est la boucle de refonte que le projet s'est interdit d'ouvrir sans
   besoin démontré.

## 4. Recommandation

- **Maintenant : option 1, et rien d'autre.** Rendre explicite et traçable un
  choix qui est aujourd'hui arbitraire et silencieux. C'est de l'honnêteté
  (leçon #4 appliquée à l'orchestration), pas de l'architecture spéculative.
- **Ne pas construire l'option 3 avant qu'un second provider existe vraiment.**
  Sans deuxième provider, un fan-out ne produit aucun cas divergent à tester :
  ce serait construire un orchestrateur sur des hypothèses — exactement
  « l'architecture théoriquement parfaite avant de construire » que le projet a
  rejeté.
- **Quand le second provider arrivera** (Grype ou autre, décidé par trous de
  couverture) : la bonne question sera le budget de convergence, pas la
  préférence. L'option 1 aura déjà posé les rails (priorité + motif), l'option 3
  deviendra un incrément testable sur un cas réel.
- Désaccord enregistré et maintenu : les prochaines données utiles viennent du
  **dogfooding sur des dépôts réels** et de la **corrélation JS** (mapping npm
  aveugle aujourd'hui), pas du catalogue d'outils.

## 5. Lignes rouges (rappel)

- Aucun nom d'outil dans le cœur — la sélection lit le registre, rien d'autre.
- Toute sélection est traçable dans `plan.json` (reproductibilité, Phase 3.1).
- Clustering et modèle de findings : figés.
- Pas de nouvelle étude comparative de providers ; pas de nouveau provider
  ajouté « pour voir ».

---

## Décisions actées (2026-08-28, utilisateur)

1. **Option 1 implémentée le jour même** : `priorite:` déclaré par provider
   (registre.py, défaut 100, entier obligatoire) ; `choisir_providers` trie par
   priorité (égalités → ordre de déclaration) ; `plan.json` trace
   `selection: {choisis, ecartes, motif}` par capacité, hors empreinte du plan
   (le motif se déduit du registre, déjà empreinté — rejeu intact). Le motif ne
   ment jamais : un choix imposé hors ordre de priorité est dit « imposée par
   l'appelant ». Vérifié : `PHASE3/test_selection.py` 13/13 (dont un arbitrage
   réel à deux providers sur registre temporaire — première fois que le
   mécanisme est exercé en situation), 16 portes vertes, exécution réelle :
   `plan.json` porte « seul provider PASSIF déclaré pour cette capacité
   (priorité 100) ».
2. **Chantier suivant : dogfooding sur dépôts réels** ; la corrélation JS
   (mapping npm) viendra SI le dogfooding confirme la cécité en pratique.
   Aucun nouveau provider, aucune étude comparative.
