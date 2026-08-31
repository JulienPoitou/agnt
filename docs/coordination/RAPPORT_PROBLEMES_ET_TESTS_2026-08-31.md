# RAPPORT — Problèmes rencontrés, tests et résultats (vague V0)

> Rédigé par l'orchestrateur (session `arena/01a05944-agnt`), le 2026-08-31 au soir.
> Objet : documenter complètement les incidents de coordination de la journée, les tests menés et leurs résultats — pour ne plus les revivre.

## 0. Réponse à la question : « 3 agents sur 1 session, est-ce grave ? »

- **Aujourd'hui : aucun dégât.** Les trois mini-checks (QA-DOGFOOD, API-BFF, WEB-CONSOLE) étaient en lecture seule : aucun fichier modifié, aucun commit, aucun push de travail.
- **Dès l'envoi des missions : dégât garanti.** Une seule session recevrait plusieurs missions et entasserait plusieurs chantiers sur une seule branche → collision Git (l'incident historique du projet), intégration impossible proprement.
- Conclusion : pas d'urgence, mais **bloquant pour la suite**. Remède : 3 sessions réellement distinctes.

## 1. Le problème central, en une phrase

Plusieurs onglets du navigateur peuvent afficher **la même session Arena** ; l'interface ne le signale pas ; le seul témoin objectif est le **nom de branche courante** renvoyé par l'agent (`git branch --show-current`) : même nom = même session.

## 2. Problème n°1 — Faux « la branche produit n'existe pas » (piège refspec)

- **Symptôme** : 4 agents (CORE, API-BFF, WEB-CONSOLE, QA-DOGFOOD) ont déclaré `origin/<branche produit>` « inexistante ». Certains en ont conclu BLOCKED alors que leur session était correcte.
- **Cause** : le clone d'une session Arena ne suit que `main` (refspec `+refs/heads/main:refs/remotes/origin/main`). `git log origin/<branche>` cherche une référence locale absente → « unknown revision », interprété à tort comme « absente de GitHub ».
- **Test** : `git ls-remote --heads origin` (question posée directement à GitHub) → les 5 branches produit existent toutes à `89bd3b1`. Vérifié deux fois dans la journée.
- **Correctif livré** : mini-check réécrit — `git fetch origin <branche>` puis lecture de `FETCH_HEAD`, `git merge-base --is-ancestor`, et déclaration par l'agent de la branche produit choisie à la création de sa session.
- **Résultat** : faux négatif devenu impossible. Preuve : les 4 checks de la 2e vague ont tous affiché le bon SHA (`89bd3b1`) et BASE OK.

## 3. Problème n°2 — Trois agents, une seule session (onglets ≠ sessions)

- **Symptôme** : les checks de QA-DOGFOOD, API-BFF et WEB-CONSOLE (2e vague) annoncent tous la même branche courante `arena/01a0595c-agnt`, tout en déclarant trois branches produit différentes (qa-gate-v0, api-bff-v0, web-console-v0).
- **Impossibilité a priori** : un nom de branche de session est unique — une seule session au monde peut le porter.
- **Tests menés** :
  1. **Comparaison des rapports** → 3 fois le même nom, 3 produits contradictoires.
  2. **Recherche Internet + doc officielle Arena** (https://help.arena.ai/articles/5432423882-how-to-use-agent-mode) → chaque session Agent Mode travaille dans sa propre copie du dépôt, sur sa propre branche de travail (architecture confirmée) ; rien de public sur le nommage interne ; aucun signalement de doublon.
  3. **Historique du dépôt** → plus de vingt sessions Arena ayant poussé, autant de noms de branches uniques, jamais un doublon.
  4. **Test décisif — arbitrage par GitHub** : chaque onglet reçoit `git push origin HEAD`. Résultats : `arena/01a0595c-agnt` poussée une fois (« new branch ») puis deux fois « Everything up-to-date » → les trois onglets partagent le même état Git → même session. Par ailleurs : `arena/01a0595b-agnt` (DEVOPS) poussée comme nouvelle branche, et `arena/01a0593c-agnt` (session du 1er essai) poussée depuis un ancien onglet.
- **Résultat** : confirmé noir sur blanc — les trois checks ont été répondus par une seule session. Aucune casse (lecture seule).
- **Leçon** : un onglet ≠ une session. Test fiable à faire soi-même : les noms `BRANCHE COURANTE` des sessions doivent être **tous différents**.

## 4. Problème n°3 (ouvert) — Chantier UI non identifié

- Branche `session-01a05933-87ad-7631-a57f-b2740bc9164d` apparue le 31/08 à 21h45 (Paris) : 1 commit « Add local AGNT UI preview variants », 4 fichiers dans `PHASE3/design-lab/` (préviews UI), base `89bd3b1` (main).
- Identité inconnue (session design parallèle ? travail local ?). Non bloquant. À identifier pour l'hygiène de coordination ; à parquer en P1 (polish) le cas échéant.

## 5. Ce qui est sain (à ne pas toucher)

- **DEVOPS-LAUNCH** : session dédiée `arena/01a0595b-agnt`, branch-check OK, mission longue en cours, branche poussée.
- **CORE-HAPPY-PATH** : livré et vérifié (`dd0ebe6` sur `arena/01a05923-agnt`), handoff enregistré.
- **Branches produit** : les 5 existent, toutes à `89bd3b1` ; aucun merge/rebase/force-push sauvage.
- **Branches du diagnostic** (`01a0595c`, `01a0593c`) : pointeurs inertes à `89bd3b1`, sans danger, à nettoyer à l'intégration.

## 6. Reste à faire (la sortie)

1. Créer 3 sessions réellement neuves (chat vide avant collage), une par agent : API-BFF (`api-bff-v0`), WEB-CONSOLE (`web-console-v0`), QA-DOGFOOD (`qa-gate-v0`).
2. Coller le mini-check correspondant (n°2, n°3, n°4 — playbook §5).
3. Vérifier : 3 noms de branche jamais vus.
4. Transmettre les réponses à l'orchestrateur → missions longues immédiates (API-BFF et WEB-CONSOLE d'abord, QA-DOGFOOD en dernier).
5. Identifier la branche mystère si possible.
